import {
  D, WError, parseBytes, jstr, verifyDetached, b64uDecode,
  schema, HTTP_STATUS,
} from "@latticeag/weather-core";
import type * as T from "@latticeag/weather-core";
import type { Fleet } from "./fleet.js";

/**
 * Request pipeline (§6.1), exact check order: byte/depth limits, strict
 * parsing, version/schema, signature + fleet authentication, current
 * revocation, role authorization, idempotency, first-seen freshness, then
 * method validation inside the serialized mutation.
 */

const MAX_REQUEST_BYTES = 1048576;
const FRESHNESS_MS = 60000n;

const READ_METHODS = new Set<T.Method>([
  "fleet.get", "alert.list", "alert.get", "audit.read", "audit.checkpoint",
  "bundle.export", "metrics.get", "subscription.read",
]);

interface Bucket { tokens: number; last: number }
class TokenBucket {
  private m = new Map<string, Bucket>();
  constructor(private ratePerSec: number, private burst: number) {}
  take(key: string, nowMs: number): boolean {
    const b = this.m.get(key) ?? { tokens: this.burst, last: nowMs };
    b.tokens = Math.min(this.burst, b.tokens + ((nowMs - b.last) / 1000) * this.ratePerSec);
    b.last = nowMs;
    if (b.tokens < 1) { this.m.set(key, b); return false; }
    b.tokens -= 1;
    this.m.set(key, b);
    return true;
  }
}

export class Rpc {
  private principalBuckets = new TokenBucket(32, 64);
  private fleetBucket = new TokenBucket(100, 200);
  /** Reserved read/operator capacity: ingest and vote traffic cannot consume it. */
  private inFlightHeavy = 0;

  constructor(private fleet: Fleet) {}

  /** Handle one POST /v1/rpc body; returns the response object to serialize. */
  handle(raw: Uint8Array, wallMs: bigint): { status: number; body: unknown } {
    const bare = (code: T.Code) => ({ status: HTTP_STATUS[code], body: { error: { code } } });

    if (raw.length > MAX_REQUEST_BYTES) return bare("INVALID_INPUT");
    let env: T.RequestEnvelope;
    try {
      env = schema.vRequestEnvelope(parseBytes(raw));
    } catch (e) {
      if (e instanceof WError && e.code === "UNSUPPORTED_VERSION") return bare("UNSUPPORTED_VERSION");
      return bare("INVALID_INPUT");
    }
    const b = env.body;
    if (b.fleet !== this.fleet.fleetId) return bare("UNAUTHORIZED");
    const reqHash = D("WEATHER-REQUEST/1", b);
    if (reqHash !== env.hash) {
      return { status: HTTP_STATUS.HASH_MISMATCH, body: errBody(b.id, "HASH_MISMATCH") };
    }
    const bound = this.fleet.boundKey(b.key_id);
    if (!bound) return bare("UNAUTHORIZED");
    let sigOk = false;
    try {
      sigOk = verifyDetached(b64uDecode(bound.publicKey, 32, "pub"), "WEATHER-REQUEST-SIGN/1", reqHash, b64uDecode(env.sig, 64, "sig"));
    } catch { sigOk = false; }
    if (!sigOk) return bare("UNAUTHORIZED");
    if (this.fleet.revoked.has(b.key_id)) {
      return { status: HTTP_STATUS.KEY_REVOKED, body: errBody(b.id, "KEY_REVOKED") };
    }

    // Role authorization.
    const method = b.method;
    if (!this.roleOk(method, bound.roles, bound.isRoot)) {
      return { status: HTTP_STATUS.FORBIDDEN, body: errBody(b.id, "FORBIDDEN") };
    }

    // Rate limits: 32/s+64 per principal key, 100/s+200 per fleet; ingest/vote
    // traffic never consumes the 16 reserved read/operator slots.
    const now = Number(wallMs);
    if (!READ_METHODS.has(method) && this.inFlightHeavy >= 184) {
      return { status: HTTP_STATUS.CAPACITY, body: errBody(b.id, "CAPACITY", true) };
    }
    if (!this.principalBuckets.take(b.key_id, now) || !this.fleetBucket.take(this.fleet.fleetId, now)) {
      return { status: HTTP_STATUS.CAPACITY, body: errBody(b.id, "CAPACITY", true) };
    }

    // Idempotency precedes freshness: stored exact hits replay forever for 24h,
    // tombstones answer REPLAY_EXPIRED without re-execution.
    const idem = this.fleet.lookupIdempotent(b.key_id, b.id, reqHash);
    if (idem.hit === "conflict") {
      return { status: HTTP_STATUS.IDEMPOTENCY_CONFLICT, body: errBody(b.id, "IDEMPOTENCY_CONFLICT") };
    }
    if (idem.hit === "expired") {
      return { status: HTTP_STATUS.REPLAY_EXPIRED, body: errBody(b.id, "REPLAY_EXPIRED") };
    }
    if (idem.hit === "replay") {
      return { status: 200, body: JSON.parse(idem.result!) };
    }

    // First-seen freshness: |sent_ms - logical_now| <= 60000. The fleet's
    // logical clock is wall-driven, so logical_now at request evaluation is
    // max(last_logical, sampled_wall).
    const logicalNow = this.fleet.logical > wallMs ? this.fleet.logical : wallMs;
    const sent = BigInt(b.sent_ms);
    const diff = sent > logicalNow ? sent - logicalNow : logicalNow - sent;
    if (diff > FRESHNESS_MS) {
      return { status: HTTP_STATUS.STALE_REQUEST, body: errBody(b.id, "STALE_REQUEST") };
    }

    const heavy = !READ_METHODS.has(method);
    if (heavy) this.inFlightHeavy++;
    try {
      const result = this.dispatch(b, wallMs);
      const body = { v: 1, id: b.id, ok: true, result };
      this.fleet.recordIdempotent(b.key_id, b.id, reqHash, jstr(body), wallMs > this.fleet.logical ? wallMs : this.fleet.logical);
      return { status: 200, body };
    } catch (e) {
      const code = e instanceof WError ? e.code : "INVALID_INPUT";
      const retryable = e instanceof WError ? e.retryable : false;
      const body = { v: 1, id: b.id, ok: false, error: { code, retryable } };
      // BUSY/CAPACITY do not consume the request ID before mutation.
      if (code !== "BUSY" && code !== "CAPACITY") {
        try {
          this.fleet.recordIdempotent(b.key_id, b.id, reqHash, jstr(body), wallMs > this.fleet.logical ? wallMs : this.fleet.logical);
        } catch { /* ignore */ }
      }
      return { status: HTTP_STATUS[code] ?? 400, body };
    } finally {
      if (heavy) this.inFlightHeavy--;
    }
  }

  private roleOk(method: T.Method, roles: T.Role[], isRoot: boolean): boolean {
    if (isRoot) {
      // Bootstrap root: config install and whole-fleet reads only.
      return method === "config.put" || READ_METHODS.has(method) ||
        method === "alert.list" || method === "alert.get";
    }
    switch (method) {
      case "fleet.get": case "alert.list": case "alert.get": case "audit.read":
      case "audit.checkpoint": case "bundle.export": case "metrics.get":
        return roles.includes("reader") || roles.includes("operator") || roles.includes("watcher");
      case "config.put": return false; // non-root cannot install configs
      case "source.append": return roles.includes("producer");
      case "subscription.open": case "subscription.read": case "subscription.ack": case "subscription.set":
      case "vote.submit": return roles.includes("watcher");
      case "alert.act": return roles.includes("operator");
      default: return false;
    }
  }

  private dispatch(b: T.RequestBody, wall: bigint): unknown {
    const f = this.fleet;
    const p = (b as { params: Record<string, unknown> }).params;
    switch (b.method) {
      case "fleet.get": return f.fleetGet();
      case "config.put": return f.configPut((p as { config: T.ConfigEnvelope }).config, wall);
      case "source.append": return f.sourceAppend(b.key_id, (p as { entries: T.SourceEntry[] }).entries, wall);
      case "subscription.open": {
        const q = p as { watcher: string; after_seq: string };
        return f.subscriptionOpen(b.key_id, q.watcher, q.after_seq, wall);
      }
      case "subscription.read": {
        const q = p as { subscription: string; after_seq: string; limit: number };
        return f.subscriptionRead(b.key_id, q.subscription, q.after_seq, q.limit, wall);
      }
      case "subscription.ack": {
        const q = p as { subscription: string; through_seq: string };
        return f.subscriptionAck(b.key_id, q.subscription, q.through_seq, wall);
      }
      case "subscription.set": {
        const q = p as { subscription: string; action: "pause" | "resume" | "close"; expected_revision: string };
        return f.subscriptionSet(b.key_id, q.subscription, q.action, q.expected_revision, wall);
      }
      case "vote.submit": return f.voteSubmit(b.key_id, (p as { vote: T.Vote }).vote, wall);
      case "alert.list": {
        const q = p as { state: T.AlertState | null; after: string | null; limit: number };
        return f.alertList(q.state, q.after, q.limit);
      }
      case "alert.get": return f.alertGet((p as { alert: string }).alert);
      case "alert.act": {
        const q = p as { alert: string; action: "ack" | "close"; expected_revision: string; note_hash: string | null };
        return f.alertAct(b.key_id, q.alert, q.action, q.expected_revision, q.note_hash, wall);
      }
      case "audit.read": {
        const q = p as { after_seq: string; through: T.Head | null; limit: number };
        return f.auditRead(q.after_seq, q.through, q.limit);
      }
      case "audit.checkpoint": return f.checkpoint();
      case "bundle.export": {
        const q = p as { after_seq: string; checkpoint: T.Checkpoint; limit: number };
        return f.bundleExport(q.after_seq, q.checkpoint, q.limit);
      }
      case "metrics.get": return f.metricsGet();
      default: throw new WError("INVALID_INPUT", "unknown method");
    }
  }
}

function errBody(id: string, code: string, retryable = false): unknown {
  return { v: 1, id, ok: false, error: { code, retryable } };
}
