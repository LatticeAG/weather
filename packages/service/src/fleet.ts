import { DatabaseSync } from "node:sqlite";
import {
  D, ZERO, J, jstr, WError, err, newId, uBig, isHash,
  signDetached, verifyDetached, b64uDecode,
  evaluateResults, manifestOf, usagePayloadHash,
} from "@latticeag/weather-core";
import type * as T from "@latticeag/weather-core";
import { openFleetDb, metaGet, metaSet, metaJson } from "./db.js";

/**
 * The serialized fleet actor (FleetDO semantics, §4–§5, §8). All mutations run
 * inside one IMMEDIATE SQLite transaction; audit signatures are computed
 * before commit and released only on commit. Logical time is
 * max(last_logical_ms, sampled_wall_ms); every mutation carries its t.
 */

const DAY_MS = 86400000n;
const LEASE_MS = 300000n;
const DELIVERY_LEASE_MS = 30000n;
const WINDOW_MS = 60000n;
const MAX_CATCHUP_WINDOWS = 60;
const HARD_BYTES = 8589934592n;
const RESERVE_BYTES = 67108864n;

const RETRY_DELAYS = [1000n, 2000n, 4000n, 8000n, 16000n, 32000n, 60000n];

interface SourceRow {
  id: string; state: T.SourceState; seq: number; hash: string;
  activated_ms: number; last_ms: number | null; last_input: string | null;
  complete: number;
}

export interface FleetOpts {
  dataDir: string;
  fleet: string;
  root: T.Pin;
  audit: T.Pin;
  auditSeed: Uint8Array;
  packDigest: string;
  readOnly?: boolean;
  /** Bootstrap primary notification URL (https:443 fixed path); null disables delivery. */
  primaryUrl?: string | null;
}

export class Fleet {
  readonly db: DatabaseSync;
  readonly fleetId: string;
  readonly root: T.Pin;
  readonly auditPin: T.Pin;
  private auditSeed: Uint8Array;
  readonly packDigest: string;
  readonly primaryUrl: string | null;
  catchingUp = false;
  private lockedError = false;

  constructor(o: FleetOpts) {
    this.db = openFleetDb(o.dataDir, o.fleet);
    this.fleetId = o.fleet;
    this.root = o.root;
    this.auditPin = o.audit;
    this.auditSeed = o.auditSeed;
    this.packDigest = o.packDigest;
    this.primaryUrl = o.primaryUrl ?? null;
    if (metaGet(this.db, "storage_version") === null) {
      metaSet(this.db, "storage_version", "1");
      metaSet(this.db, "phase", o.readOnly ? "READ_ONLY" : "RUNNING");
      metaSet(this.db, "logical_ms", "0");
      metaSet(this.db, "next_input_index", "1");
      metaSet(this.db, "audit_head", JSON.stringify({ seq: "0", hash: ZERO }));
      metaSet(this.db, "active_config", "null");
      metaSet(this.db, "pending_config", "null");
      metaSet(this.db, "revoked_keys", "[]");
      metaSet(this.db, "byte_accounting", "0");
      metaSet(this.db, "last_checkpoint", "null");
    }
    if (o.readOnly && this.phase === "RUNNING") metaSet(this.db, "phase", "READ_ONLY");
  }

  // ---- meta accessors -------------------------------------------------
  get phase(): T.Phase { return metaGet(this.db, "phase") as T.Phase; }
  get logical(): bigint { return BigInt(metaGet(this.db, "logical_ms")!); }
  get auditHead(): T.Head { return metaJson<T.Head>(this.db, "audit_head")!; }
  get nextIndex(): bigint { return BigInt(metaGet(this.db, "next_input_index")!); }
  get revoked(): Set<string> { return new Set(metaJson<string[]>(this.db, "revoked_keys")!); }
  get byteAccounting(): bigint { return BigInt(metaGet(this.db, "byte_accounting")!); }

  activeHash(): string | null { return metaJson<string | null>(this.db, "active_config"); }
  pendingHash(): string | null { return metaJson<string | null>(this.db, "pending_config"); }

  object<TV>(kind: string, hash: string): TV | null {
    const r = this.db.prepare("SELECT canonical FROM objects WHERE kind=? AND hash=?").get(kind, hash) as { canonical: Uint8Array } | undefined;
    return r ? (JSON.parse(Buffer.from(r.canonical).toString("utf8")) as TV) : null;
  }

  activeConfig(): T.ConfigEnvelope | null {
    const h = this.activeHash();
    return h === null ? null : this.object<T.ConfigEnvelope>("config", h);
  }
  pendingConfig(): T.ConfigEnvelope | null {
    const h = this.pendingHash();
    return h === null ? null : this.object<T.ConfigEnvelope>("config", h);
  }
  configByHash(h: string): T.ConfigEnvelope | null { return this.object("config", h); }

  // ---- audit ----------------------------------------------------------
  private appendAudit(kind: T.AuditKind, data: unknown, t: bigint): T.Audit {
    const head = this.auditHead;
    const seq = uBig(head.seq) + 1n;
    const body = {
      v: 1, fleet: this.fleetId, event_id: newId("wev"), seq: seq.toString(),
      prev: head.hash, at_ms: t.toString(), key_id: this.auditPin.key_id,
      kind, data,
    } as T.AuditBody;
    const hash = D("WEATHER-AUDIT/1", body);
    let sig: Uint8Array;
    try {
      sig = signDetached(this.auditSeed, "WEATHER-AUDIT-SIGN/1", hash);
    } catch {
      this.lockedError = true;
      throw new WError("AUDIT_UNAVAILABLE", "audit signer failed");
    }
    const bodyBytes = Buffer.from(jstr(body), "utf8");
    this.db.prepare("INSERT INTO audit(seq,hash,prev,at_ms,body,sig) VALUES(?,?,?,?,?,?)")
      .run(Number(seq), hash, head.hash, Number(t), bodyBytes, Buffer.from(sig).toString("base64url"));
    metaSet(this.db, "audit_head", JSON.stringify({ seq: seq.toString(), hash }));
    this.putObjectFirstRefs(seq, body);
    this.accountBytes(BigInt(bodyBytes.length + 88));
    return { body, hash, sig: Buffer.from(sig).toString("base64url") };
  }

  private accountBytes(n: bigint): void {
    const v = this.byteAccounting + n;
    metaSet(this.db, "byte_accounting", v.toString());
  }

  /** ≥80% warns (capacity_warning getter); ≥90% switches to READ_ONLY. */
  get capacityWarning(): boolean {
    return this.byteAccounting * 10n >= HARD_BYTES * 8n;
  }

  private checkCapacity(): void {
    const used = this.byteAccounting;
    if (used * 10n >= HARD_BYTES * 9n && this.phase === "RUNNING") {
      throw new WError("CAPACITY", "storage high-water");
    }
    void RESERVE_BYTES;
  }

  // ---- time / scheduled work ------------------------------------------
  /**
   * Advance logical time to t (a Tick when t advances), then run scheduled
   * work in spec order: expired windows ascending, ConfigActivated, alert
   * expiries ascending, subscription expiries ascending.
   */
  private advance(t: bigint): void {
    if (t < 0n) throw new WError("INVALID_INPUT", "negative time");
    if (t > this.logical) {
      this.appendAudit("Tick", { logical_ms: t.toString() }, t);
      metaSet(this.db, "logical_ms", t.toString());
      this.sweepIdempotency(t);
    }
    let finalized = 0;
    for (;;) {
      const active = this.activeConfig();
      if (active === null) break;
      const nextEnd = this.nextWindowEnd(active);
      if (nextEnd === null || nextEnd > t) break;
      if (finalized >= MAX_CATCHUP_WINDOWS) { this.catchingUp = true; return; }
      this.finalizeWindow(active, nextEnd - WINDOW_MS, nextEnd, t);
      finalized++;
      const pending = this.pendingConfig();
      if (pending !== null && uBig(pending.body.effective_ms) === nextEnd) this.activatePending(t);
    }
    this.catchingUp = false;
    const pending = this.pendingConfig();
    if (pending !== null && uBig(pending.body.effective_ms) <= t) this.activatePending(t);
    this.expireAlerts(t);
    this.expireSubscriptions(t);
  }

  /** Next window end under the active config; null when active is null. */
  private nextWindowEnd(active: T.ConfigEnvelope): bigint | null {
    const row = this.db.prepare("SELECT MAX(start_ms) AS m FROM windows WHERE config_hash=?")
      .get(active.hash) as { m: number | null };
    if (row.m === null) return uBig(active.body.effective_ms) + WINDOW_MS;
    return BigInt(row.m) + 2n * WINDOW_MS;
  }

  private sweepIdempotency(t: bigint): void {
    this.db.prepare("UPDATE requests SET result=NULL WHERE result IS NOT NULL AND expires_ms<?").run(Number(t));
  }

  private activatePending(t: bigint): void {
    const pending = this.pendingConfig()!;
    const prev = this.activeConfig();
    // Retire sources absent/disabled in the new epoch; create rows for newly
    // enabled sources. History windows reset (same-epoch rule).
    const inCfg = new Map(pending.body.sources.map((s) => [s.id, s]));
    for (const s of this.db.prepare("SELECT * FROM sources").all() as unknown as SourceRow[]) {
      const nc = inCfg.get(s.id);
      if ((!nc || !nc.enabled) && s.state !== "RETIRED") {
        this.db.prepare("UPDATE sources SET state='RETIRED' WHERE id=?").run(s.id);
      }
    }
    for (const sc of pending.body.sources) {
      if (!sc.enabled) continue;
      const have = this.db.prepare("SELECT id FROM sources WHERE id=?").get(sc.id);
      if (!have) {
        this.db.prepare("INSERT INTO sources(id,state,seq,hash,activated_ms,last_ms,last_input,complete) VALUES(?,?,?,?,?,NULL,NULL,1)")
          .run(sc.id, "EMPTY", 0, ZERO, Number(uBig(pending.body.effective_ms)));
      }
    }
    this.db.prepare("UPDATE configs SET state='RETIRED' WHERE state='ACTIVE'").run();
    this.db.prepare("UPDATE configs SET state='ACTIVE' WHERE hash=?").run(pending.hash);
    metaSet(this.db, "active_config", JSON.stringify(pending.hash));
    metaSet(this.db, "pending_config", "null");
    this.appendAudit("ConfigActivated", { config: pending.hash }, t);
    void prev;
  }

  private expireAlerts(t: bigint): void {
    const rows = this.db.prepare("SELECT id, view FROM alerts WHERE state='CANDIDATE' AND expires_ms<=? ORDER BY id")
      .all(Number(t)) as unknown as { id: string; view: Uint8Array }[];
    for (const r of rows) {
      const view = JSON.parse(Buffer.from(r.view).toString("utf8")) as T.AlertView;
      const rev = (uBig(view.revision) + 1n).toString();
      this.setAlertView({ ...view, state: "EXPIRED", revision: rev });
      this.appendAudit("AlertChanged", {
        alert: r.id, from: "CANDIDATE", to: "EXPIRED", actor: null, note_hash: null, revision: rev,
      }, t);
    }
  }

  private expireSubscriptions(t: bigint): void {
    const rows = this.db.prepare("SELECT id FROM subscriptions WHERE state IN ('ACTIVE','PAUSED') AND lease_ms<=? ORDER BY id")
      .all(Number(t)) as unknown as { id: string }[];
    for (const r of rows) {
      const s = this.getSub(r.id)!;
      const next = { ...s, state: "EXPIRED" as const, revision: (uBig(s.revision) + 1n).toString() };
      this.putSub(next);
      this.appendAudit("SubscriptionChanged", { subscription: next, event: "EXPIRE" }, t);
    }
  }

  // ---- window finalization --------------------------------------------
  private finalizeWindow(active: T.ConfigEnvelope, start: bigint, end: bigint, t: bigint): void {
    const wacc = (this.db.prepare(
      "SELECT a.input_index, a.received_ms, a.late, a.counted, s.entry FROM accepted a JOIN source_slots s ON s.source=a.source AND s.seq=a.seq AND s.hash=a.hash WHERE a.received_ms>=? AND a.received_ms<? ORDER BY a.input_index",
    ).all(Number(start), Number(end)) as unknown as { input_index: number; received_ms: number; late: number; counted: number; entry: Uint8Array }[])
      .map((r): T.Accepted => ({
        index: r.input_index.toString(),
        received_ms: r.received_ms.toString(),
        late: r.late === 1,
        counted: r.counted === 1,
        entry: JSON.parse(Buffer.from(r.entry).toString("utf8")) as T.SourceEntry,
      }));

    const closes: { source: string; headSeq: string; headHash: string; state: T.SourceState; activated_ms: string; last_received_ms: string | null; last_input: string | null; complete: boolean; pending: number; revoked: boolean }[] = [];
    for (const sc of active.body.sources.filter((s) => s.enabled).sort((a, b) => (a.id < b.id ? -1 : 1))) {
      const st = this.db.prepare("SELECT * FROM sources WHERE id=?").get(sc.id) as unknown as SourceRow;
      const pend = this.db.prepare("SELECT COUNT(*) AS n FROM pending WHERE source=?").get(sc.id) as { n: number };
      closes.push({
        source: sc.id, headSeq: st.seq.toString(), headHash: st.hash, state: st.state,
        activated_ms: st.activated_ms.toString(),
        last_received_ms: st.last_ms === null ? null : st.last_ms.toString(),
        last_input: st.last_input, complete: st.complete === 1,
        pending: Number(pend.n), revoked: this.revoked.has(sc.pin.key_id),
      });
    }

    const historyRows = this.db.prepare("SELECT manifest_hash FROM windows WHERE config_hash=? ORDER BY start_ms DESC LIMIT 5")
      .all(active.hash) as unknown as { manifest_hash: string }[];
    const history = historyRows.map((r) => r.manifest_hash).reverse();
    const historyWindows = history
      .map((h) => {
        const m = this.object<T.Manifest>("manifest", h)!;
        const acc = this.windowAccepted(m);
        return { manifest: m, accepted: acc };
      });

    const w: T.WindowInput = {
      fleet: this.fleetId, configHash: active.hash, config: active.body,
      start_ms: start.toString(), end_ms: end.toString(),
      through_index: (this.nextIndex - 1n).toString(),
      accepted: wacc, history, historyWindows, closes,
      revoked_keys: this.revoked,
    };
    const { manifest, hash: mh } = manifestOf(w);
    this.putObject("manifest", mh, manifest);
    this.db.prepare("INSERT INTO windows(config_hash,start_ms,manifest_hash) VALUES(?,?,?)")
      .run(active.hash, Number(start), mh);

    const results = evaluateResults(w, manifest, mh);
    this.appendAudit("WindowFinalized", { manifest: mh, result_count: results.length }, t);
    for (const r of results) {
      this.putObject("result", r.hash, r);
      this.db.prepare("INSERT INTO results(hash,manifest_hash,detector,target) VALUES(?,?,?,?)")
        .run(r.hash, mh, r.body.detector, r.body.target);
      this.appendAudit("ResultFinalized", { result: r.hash }, t);
      this.bumpMetric(r.body.decision.status === "HIT" ? "detector_hit_total" : r.body.decision.status === "UNKNOWN" ? "detector_unknown_total" : null);
    }
    for (const r of results) {
      if (r.body.decision.status !== "HIT") continue;
      const alert: T.AlertView = {
        id: newId("wal"), result: r.hash, state: "CANDIDATE", assurance: "VALID",
        domains: [], votes: [], expires_ms: (end + 180000n).toString(),
        delivery: "NONE", revision: "1",
      };
      this.db.prepare("INSERT INTO alerts(id,result_hash,state,assurance,revision,expires_ms,view) VALUES(?,?,?,?,?,?,?)")
        .run(alert.id, r.hash, alert.state, alert.assurance, 1, Number(uBig(alert.expires_ms)), Buffer.from(jstr(alert), "utf8"));
      this.appendAudit("AlertCreated", { alert }, t);
    }
  }

  private windowAccepted(m: T.Manifest): T.Accepted[] {
    return (this.db.prepare(
      "SELECT a.input_index, a.received_ms, a.late, a.counted, s.entry FROM accepted a JOIN source_slots s ON s.source=a.source AND s.seq=a.seq AND s.hash=a.hash WHERE a.received_ms>=? AND a.received_ms<? ORDER BY a.input_index",
    ).all(Number(uBig(m.start_ms)), Number(uBig(m.end_ms))) as unknown as { input_index: number; received_ms: number; late: number; counted: number; entry: Uint8Array }[])
      .map((r): T.Accepted => ({
        index: r.input_index.toString(), received_ms: r.received_ms.toString(),
        late: r.late === 1, counted: r.counted === 1,
        entry: JSON.parse(Buffer.from(r.entry).toString("utf8")) as T.SourceEntry,
      }));
  }

  private putObject(kind: string, hash: string, value: unknown): void {
    const bytes = Buffer.from(jstr(value), "utf8");
    this.db.prepare("INSERT INTO objects(kind,hash,canonical) VALUES(?,?,?) ON CONFLICT(kind,hash) DO NOTHING")
      .run(kind, hash, bytes);
    this.accountBytes(BigInt(bytes.length));
  }

  private putObjectFirstRefs(entrySeq: bigint, body: T.AuditBody): void {
    // Objects are attached at their first referencing audit position.
    const d = body.data as Record<string, unknown>;
    const refs: [string, string][] = [];
    switch (body.kind) {
      case "ConfigScheduled": case "ConfigActivated": case "KeysRevoked":
        refs.push(["config", d["config"] as string]); break;
      case "WindowFinalized": {
        refs.push(["manifest", d["manifest"] as string]);
        const cfgHash = this.activeHash();
        if (cfgHash) refs.push(["config", cfgHash]);
        break;
      }
      case "ResultFinalized": refs.push(["result", d["result"] as string]); break;
      case "DeliveryChanged": {
        const p = d["page"] as string | null;
        if (p) refs.push(["page", p]);
        break;
      }
      default: break;
    }
    for (const [kind, hash] of refs) {
      this.db.prepare("INSERT OR IGNORE INTO objects_introduced(kind,hash,seq) VALUES(?,?,?)")
        .run(kind, hash, Number(entrySeq));
    }
  }

  // ---- mutations (each runs in its own IMMEDIATE tx) -------------------
  private tx<R>(t: bigint, fn: () => R): R {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.advance(t);
      if (this.catchingUp) { this.db.exec("ROLLBACK"); throw new WError("BUSY", "catching up", true); }
      this.checkCapacity();
      const r = fn();
      if (this.lockedError) { this.db.exec("ROLLBACK"); throw new WError("AUDIT_UNAVAILABLE", "signer failure"); }
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      try { this.db.exec("ROLLBACK"); } catch { /* already rolled back */ }
      if (e instanceof WError && e.code === "CAPACITY" && this.phase === "RUNNING" && !this.lockedError) {
        this.enterReadOnly(t);
      }
      throw e;
    }
  }

  private enterReadOnly(t: bigint): void {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      if (this.phase === "RUNNING") {
        metaSet(this.db, "phase", "READ_ONLY");
        this.appendAudit("FleetChanged", { from: "RUNNING", to: "READ_ONLY", reason: "CAPACITY" }, t);
      }
      this.db.exec("COMMIT");
    } catch { this.db.exec("ROLLBACK"); }
  }

  private requireRunning(): void {
    if (this.phase === "LOCKED") throw new WError("AUDIT_UNAVAILABLE", "fleet locked");
    if (this.phase === "READ_ONLY") throw new WError("CAPACITY", "fleet read-only");
  }

  /** config.put — root only (role checked by the RPC layer). */
  configPut(env: T.ConfigEnvelope, wall: bigint): { hash: string; state: "PENDING"; effective_ms: string } {
    const t0 = this.logical;
    const t = t0 > wall ? t0 : wall;
    return this.tx(t, () => {
      this.requireRunning();
      if (env.hash !== D("WEATHER-CONFIG/1", env.body)) throw new WError("HASH_MISMATCH", "config hash");
      if (env.key_id !== this.root.key_id) throw new WError("SIGNATURE_INVALID", "config not root-signed");
      if (!verifyDetached(b64uDecode(this.root.public_key, 32, "root"), "WEATHER-CONFIG-SIGN/1", env.hash, b64uDecode(env.sig, 64, "sig"))) {
        throw new WError("SIGNATURE_INVALID", "config signature");
      }
      const c = env.body;
      if (c.fleet !== this.fleetId) throw new WError("INVALID_INPUT", "config fleet mismatch");
      if (c.pack_digest !== this.packDigest) throw new WError("PACK_UNAVAILABLE", `pack ${c.pack_digest} not installed`);
      const active = this.activeConfig();
      const scheduled = this.lastConfig();
      if (scheduled === null) {
        if (c.epoch !== "1" || c.predecessor !== ZERO) throw new WError("CHAIN_INVALID", "first epoch must be 1/ZERO");
      } else {
        if (uBig(c.epoch) !== uBig(scheduled.body.epoch) + 1n || c.predecessor !== scheduled.hash) {
          throw new WError("CHAIN_INVALID", "epoch/predecessor mismatch");
        }
        if (this.pendingConfig() !== null) throw new WError("STATE_CONFLICT", "a pending config exists");
        this.checkSuccessorInvariants(scheduled.body, c);
      }
      const logicalNow = this.logical;
      const want = (logicalNow / WINDOW_MS) * WINDOW_MS + WINDOW_MS;
      if (uBig(c.effective_ms) !== want) throw new WError("INVALID_INPUT", `effective_ms must be ${want}`);
      // Revocation overlay applies immediately at admission.
      const cur = this.revoked;
      const newKeys = c.revoked_keys.filter((k) => !cur.has(k));
      for (const k of c.revoked_keys) cur.add(k);
      if (cur.has(this.root.key_id) || cur.has(this.auditPin.key_id)) {
        throw new WError("INVALID_INPUT", "cannot revoke root or audit key");
      }
      metaSet(this.db, "revoked_keys", JSON.stringify([...cur].sort()));
      this.db.prepare("INSERT INTO configs(epoch,hash,effective_ms,state) VALUES(?,?,?,'PENDING')")
        .run(Number(uBig(c.epoch)), env.hash, Number(uBig(c.effective_ms)));
      this.putObject("config", env.hash, env);
      metaSet(this.db, "pending_config", JSON.stringify(env.hash));
      this.appendAudit("ConfigScheduled", { config: env.hash }, t);
      if (newKeys.length > 0) {
        this.appendAudit("KeysRevoked", { config: env.hash, keys: newKeys.sort() }, t);
        this.degradeForKeys(newKeys, t);
      }
      return { hash: env.hash, state: "PENDING", effective_ms: c.effective_ms };
    });
  }

  private lastConfig(): T.ConfigEnvelope | null {
    const row = this.db.prepare("SELECT hash FROM configs ORDER BY epoch DESC LIMIT 1").get() as { hash: string } | undefined;
    return row ? this.configByHash(row.hash) : null;
  }

  private checkSuccessorInvariants(prev: T.Config, next: T.Config): void {
    const oldSources = new Map(prev.sources.map((s) => [s.id, s]));
    const principals = new Map(next.principals.map((p) => [p.id, p]));
    const prevPrincipals = new Map(prev.principals.map((p) => [p.id, p]));
    const subjects = new Set(next.subjects.map((s) => s.id));
    for (const s of next.sources) {
      const o = oldSources.get(s.id);
      if (o && (o.principal !== s.principal || o.pin.key_id !== s.pin.key_id ||
        o.pin.public_key !== s.pin.public_key || o.profile !== s.profile ||
        o.meter !== s.meter || o.subjects.join(",") !== s.subjects.join(","))) {
        throw new WError("INVALID_INPUT", "retained source changed bound fields");
      }
      const pr = principals.get(s.principal);
      const pp = prevPrincipals.get(s.principal);
      if (o && pp && (!pr || pr.pin.key_id !== pp.pin.key_id || pr.pin.public_key !== pp.pin.public_key)) {
        throw new WError("INVALID_INPUT", "retained source's principal changed");
      }
      for (const sub of s.subjects) {
        if (!subjects.has(sub)) throw new WError("INVALID_INPUT", "retained source lists removed subject");
      }
    }
    const oldWatchers = new Map(prev.watchers.map((w) => [w.id, w]));
    for (const w of next.watchers) {
      const o = oldWatchers.get(w.id);
      if (o) {
        const pr = principals.get(w.principal);
        const pp = prevPrincipals.get(w.principal);
        if (pp && (!pr || pr.pin.key_id !== pp.pin.key_id || pr.pin.public_key !== pp.pin.public_key)) {
          throw new WError("INVALID_INPUT", "retained watcher's principal changed");
        }
      }
    }
  }

  /** source.append — producer role. */
  sourceAppend(keyId: string, entries: T.SourceEntry[], wall: bigint): { items: T.IngestItem[]; source: T.SourceView } {
    const t0 = this.logical;
    const t = t0 > wall ? t0 : wall;
    return this.tx(t, () => {
      this.requireRunning();
      const cfg = this.activeConfig();
      if (!cfg) throw new WError("FORBIDDEN", "no committed config");
      const principal = cfg.body.principals.find((p) => p.pin.key_id === keyId);
      const src = principal ? cfg.body.sources.find((s) => s.principal === principal.id && s.enabled) : undefined;
      if (!principal || !src) throw new WError("FORBIDDEN", "key is not a bound producer");
      const st = this.sourceRow(src.id);
      if (!st) throw new WError("FORBIDDEN", "source not installed");
      if (this.revoked.has(src.pin.key_id)) throw new WError("KEY_REVOKED", "source key revoked");

      // Batch shape: sorted by seq, unique seq (INVALID_INPUT rejects all).
      let prevSeq = -1n;
      for (const e of entries) {
        const s = uBig(e.body.seq);
        if (s <= prevSeq) throw new WError("INVALID_INPUT", "entries not sorted-unique by seq");
        prevSeq = s;
      }

      // Verify every envelope before any mutation (§4.1 step 2).
      for (const e of entries) {
        if (e.hash !== D("WEATHER-SOURCE/1", e.body)) throw new WError("HASH_MISMATCH", "entry hash");
        if (e.body.fleet !== this.fleetId || e.body.source !== src.id) {
          throw new WError("FORBIDDEN", "entry binds another fleet/source");
        }
        if (e.body.key_id !== src.pin.key_id) throw new WError("SIGNATURE_INVALID", "entry key binding");
        if (!verifyDetached(b64uDecode(src.pin.public_key, 32, "pub"), "WEATHER-SOURCE-SIGN/1", e.hash, b64uDecode(e.sig, 64, "sig"))) {
          throw new WError("SIGNATURE_INVALID", "entry signature");
        }
        if (e.body.native.profile !== src.profile) throw new WError("FORBIDDEN", "profile mismatch");
        const obs = e.body.observation;
        if ("subject" in obs && !src.subjects.includes(obs.subject)) throw new WError("FORBIDDEN", "subject not authorized");
        if (obs.kind === "spend" && !src.meter) throw new WError("FORBIDDEN", "spend from non-meter source");
        if ((obs.kind === "scope" || obs.kind === "replication") && src.meter) throw new WError("FORBIDDEN", "scope/replication from meter source");
        if (uBig(e.body.observed_ms) > t + 60000n) throw new WError("FUTURE_TIMESTAMP", "observed_ms too far ahead");
      }

      const items: T.IngestItem[] = entries.map((e) => ({ seq: e.body.seq, status: "NOT_APPLIED", index: null, counted: false }));

      // Slot lookup: known retained hash → DUPLICATE; different → fork.
      const forkIdx: number[] = [];
      for (let i = 0; i < entries.length; i++) {
        const e = entries[i]!;
        const rows = this.db.prepare("SELECT hash, entry FROM source_slots WHERE source=? AND seq=?")
          .all(src.id, Number(uBig(e.body.seq))) as unknown as { hash: string; entry: Uint8Array }[];
        if (rows.some((r) => r.hash === e.hash)) {
          const acc = this.db.prepare("SELECT input_index FROM accepted WHERE source=? AND seq=?")
            .get(src.id, Number(uBig(e.body.seq))) as { input_index: number } | undefined;
          items[i] = { seq: e.body.seq, status: "DUPLICATE", index: acc ? acc.input_index.toString() : null, counted: false };
          this.bumpMetric("inputs_duplicate_total");
          continue;
        }
        if (rows.length > 0) forkIdx.push(i);
      }

      if (st.state === "FORKED") {
        if (items.every((it) => it.status === "DUPLICATE")) return { items, source: this.sourceView(src.id) };
        throw new WError("SOURCE_FORKED", "source is forked");
      }
      if (st.state === "TERMINAL" || st.state === "RETIRED") {
        if (items.every((it) => it.status === "DUPLICATE")) return { items, source: this.sourceView(src.id) };
        throw new WError("SOURCE_TERMINAL", "source is terminal/retired");
      }

      if (forkIdx.length > 0) {
        // Commit only fork evidence; ordinary entries are not applied.
        for (const i of forkIdx) {
          const e = entries[i]!;
          const existing = this.db.prepare("SELECT entry FROM source_slots WHERE source=? AND seq=? LIMIT 1")
            .get(src.id, Number(uBig(e.body.seq))) as { entry: Uint8Array };
          this.db.prepare("INSERT OR IGNORE INTO source_slots(source,seq,hash,entry) VALUES(?,?,?,?)")
            .run(src.id, Number(uBig(e.body.seq)), e.hash, Buffer.from(jstr(e), "utf8"));
          this.db.prepare("UPDATE sources SET state='FORKED' WHERE id=?").run(src.id);
          this.appendAudit("SourceForkObserved", {
            source: src.id,
            left: JSON.parse(Buffer.from(existing.entry).toString("utf8")),
            right: e, reason: "SLOT_FORK",
          }, t);
          items[i] = { seq: e.body.seq, status: "FORK", index: null, counted: false };
          this.bumpMetric("source_forks_total");
        }
        this.degradeForSource(src.id, null, t);
        return { items, source: this.sourceView(src.id) };
      }

      // Ordinary processing in seq order.
      let head = { seq: BigInt(st.seq), hash: st.hash };
      for (let i = 0; i < entries.length; i++) {
        const e = entries[i]!;
        if (items[i]!.status === "DUPLICATE") continue;
        const seq = uBig(e.body.seq);
        if (seq <= head.seq) throw new WError("CHAIN_INVALID", "unseen slot at/below head");
        if (seq > head.seq + 256n) throw new WError("GAP_LIMIT", "sequence gap beyond 256");
        if (seq === head.seq + 1n) {
          if (e.body.prev !== head.hash) {
            // Durable evidence buffer + GAPPED; the call still reports CHAIN_INVALID.
            this.bufferEntry(src.id, e, t);
            this.db.exec("COMMIT");
            this.db.exec("BEGIN IMMEDIATE");
            throw new WError("CHAIN_INVALID", "contiguous predecessor mismatch");
          }
          // Terminal with pending suffix → terminal/suffix fork; batch's new
          // entries are not applied beyond this point.
          const beyond = this.db.prepare("SELECT s.entry FROM pending p JOIN source_slots s ON s.source=p.source AND s.seq=p.seq AND s.hash=p.hash WHERE p.source=? AND p.seq>? ORDER BY p.seq LIMIT 1")
            .get(src.id, Number(seq)) as { entry: Uint8Array } | undefined;
          if (e.body.observation.kind === "terminal" && beyond) {
            this.db.prepare("INSERT OR IGNORE INTO source_slots(source,seq,hash,entry) VALUES(?,?,?,?)")
              .run(src.id, Number(seq), e.hash, Buffer.from(jstr(e), "utf8"));
            this.db.prepare("UPDATE sources SET state='FORKED' WHERE id=?").run(src.id);
            this.appendAudit("SourceForkObserved", {
              source: src.id, left: e,
              right: JSON.parse(Buffer.from(beyond.entry).toString("utf8")),
              reason: "TERMINAL_SUFFIX",
            }, t);
            items[i] = { seq: e.body.seq, status: "FORK", index: null, counted: false };
            this.bumpMetric("source_forks_total");
            this.degradeForSource(src.id, null, t);
            return { items, source: this.sourceView(src.id) };
          }
          this.acceptEntry(src, st, e, t, items, i);
          head = { seq, hash: e.hash };
          // Drain buffered successors.
          for (;;) {
            const row = this.db.prepare("SELECT p.hash, s.entry FROM pending p JOIN source_slots s ON s.source=p.source AND s.seq=p.seq AND s.hash=p.hash WHERE p.source=? AND p.seq=?")
              .get(src.id, Number(head.seq + 1n)) as { hash: string; entry: Uint8Array } | undefined;
            if (!row) break;
            const pe = JSON.parse(Buffer.from(row.entry).toString("utf8")) as T.SourceEntry;
            if (pe.body.prev !== head.hash) break; // retained as GAPPED evidence
            const more = this.db.prepare("SELECT s.entry FROM pending p JOIN source_slots s ON s.source=p.source AND s.seq=p.seq AND s.hash=p.hash WHERE p.source=? AND p.seq>? ORDER BY p.seq LIMIT 1")
              .get(src.id, Number(head.seq + 1n)) as { entry: Uint8Array } | undefined;
            if (pe.body.observation.kind === "terminal" && more) {
              this.db.prepare("UPDATE sources SET state='FORKED' WHERE id=?").run(src.id);
              this.appendAudit("SourceForkObserved", {
                source: src.id, left: pe,
                right: JSON.parse(Buffer.from(more.entry).toString("utf8")),
                reason: "TERMINAL_SUFFIX",
              }, t);
              this.bumpMetric("source_forks_total");
              this.degradeForSource(src.id, null, t);
              return { items, source: this.sourceView(src.id) };
            }
            this.db.prepare("DELETE FROM pending WHERE source=? AND seq=?").run(src.id, Number(head.seq + 1n));
            const idx = this.applyAccepted(src, pe, t);
            head = { seq: head.seq + 1n, hash: pe.hash };
            void idx;
          }
        } else {
          this.bufferEntry(src.id, e, t);
          items[i] = { seq: e.body.seq, status: "BUFFERED", index: null, counted: false };
        }
      }
      const pend = this.db.prepare("SELECT COUNT(*) AS n FROM pending WHERE source=?").get(src.id) as { n: number };
      const cur = this.sourceRow(src.id)!;
      if (cur.state !== "FORKED" && cur.state !== "TERMINAL") {
        this.db.prepare("UPDATE sources SET state=? WHERE id=?").run(Number(pend.n) > 0 ? "GAPPED" : "ACTIVE", src.id);
      }
      return { items, source: this.sourceView(src.id) };
    });
  }

  private sourceRow(id: string): SourceRow | null {
    return (this.db.prepare("SELECT * FROM sources WHERE id=?").get(id) as unknown as SourceRow | undefined) ?? null;
  }

  private bufferEntry(source: string, e: T.SourceEntry, t: bigint): void {
    const n = this.db.prepare("SELECT COUNT(*) AS n FROM pending WHERE source=?").get(source) as { n: number };
    if (Number(n.n) >= 256) throw new WError("GAP_LIMIT", "pending capacity");
    this.db.prepare("INSERT OR IGNORE INTO source_slots(source,seq,hash,entry) VALUES(?,?,?,?)")
      .run(source, Number(uBig(e.body.seq)), e.hash, Buffer.from(jstr(e), "utf8"));
    this.db.prepare("INSERT OR IGNORE INTO pending(source,seq,hash) VALUES(?,?,?)")
      .run(source, Number(uBig(e.body.seq)), e.hash);
    this.db.prepare("UPDATE sources SET state='GAPPED' WHERE id=?").run(source);
    this.appendAudit("SourceBuffered", { entry: e }, t);
  }

  private acceptEntry(src: T.SourceConfig, st: SourceRow, e: T.SourceEntry, t: bigint, items: T.IngestItem[], i: number): void {
    const index = this.applyAccepted(src, e, t);
    items[i] = { seq: e.body.seq, status: "ACCEPTED", index: index.toString(), counted: true };
    const acc = this.db.prepare("SELECT counted FROM accepted WHERE input_index=?").get(Number(index)) as { counted: number };
    items[i]!.counted = acc.counted === 1;
  }

  private applyAccepted(src: T.SourceConfig, e: T.SourceEntry, t: bigint): bigint {
    const obs = e.body.observation;
    let counted = true;
    if (obs.kind === "spend") {
      const ph = usagePayloadHash(obs.subject, obs.delta, obs.unit);
      const prev = this.db.prepare("SELECT payload_hash FROM usage_ids WHERE source=? AND usage_id=?")
        .get(src.id, obs.usage_id) as { payload_hash: string } | undefined;
      if (prev) {
        if (prev.payload_hash !== ph) throw new WError("USAGE_CONFLICT", "usage_id reused with different payload");
        counted = false;
      } else {
        this.db.prepare("INSERT INTO usage_ids(source,usage_id,payload_hash,first_index) VALUES(?,?,?,?)")
          .run(src.id, obs.usage_id, ph, Number(this.nextIndex));
      }
    }
    const late = uBig(e.body.observed_ms) < t - 120000n;
    const index = this.nextIndex;
    this.db.prepare("INSERT INTO accepted(input_index,source,seq,hash,received_ms,counted,late) VALUES(?,?,?,?,?,?,?)")
      .run(Number(index), src.id, Number(uBig(e.body.seq)), e.hash, Number(t), counted ? 1 : 0, late ? 1 : 0);
    this.db.prepare("INSERT OR IGNORE INTO source_slots(source,seq,hash,entry) VALUES(?,?,?,?)")
      .run(src.id, Number(uBig(e.body.seq)), e.hash, Buffer.from(jstr(e), "utf8"));
    metaSet(this.db, "next_input_index", (index + 1n).toString());
    const st = this.sourceRow(src.id)!;
    const nonsignal = obs.kind !== "signal";
    const newLastMs = nonsignal ? Number(t) : st.last_ms;
    const newLastInput = nonsignal ? e.hash : st.last_input;
    const complete = obs.kind === "coverage" ? (obs.complete ? 1 : 0) : st.complete;
    const newState = obs.kind === "terminal" ? "TERMINAL" : "ACTIVE";
    this.db.prepare("UPDATE sources SET seq=?, hash=?, last_ms=?, last_input=?, complete=?, state=? WHERE id=?")
      .run(Number(uBig(e.body.seq)), e.hash, newLastMs, newLastInput, complete, newState, src.id);
    const accepted: T.Accepted = {
      index: index.toString(), received_ms: t.toString(), entry: e, late, counted,
    };
    this.appendAudit("SourceAccepted", { accepted }, t);
    this.bumpMetric("inputs_accepted_total");
    if (late) this.bumpMetric("inputs_late_total");
    return index;
  }

  private sourceView(id: string): T.SourceView {
    const st = this.sourceRow(id)!;
    const pend = this.db.prepare("SELECT COUNT(*) AS n FROM pending WHERE source=?").get(id) as { n: number };
    return {
      source: id, state: st.state,
      head: { seq: st.seq.toString(), hash: st.hash },
      last_received_ms: st.last_ms === null ? null : st.last_ms.toString(),
      complete: st.complete === 1, pending: Number(pend.n),
    };
  }

  // ---- subscriptions ----------------------------------------------------
  private getSub(id: string): T.Subscription | null {
    const r = this.db.prepare("SELECT * FROM subscriptions WHERE id=?").get(id) as
      { id: string; watcher: string; state: string; ack: number; delivered: number; lease_ms: number; revision: number } | undefined;
    if (!r) return null;
    return {
      id: r.id, watcher: r.watcher, state: r.state as T.SubscriptionState,
      ack: r.ack.toString(), delivered: r.delivered.toString(),
      lease_until_ms: r.lease_ms.toString(), revision: r.revision.toString(),
    };
  }

  private putSub(s: T.Subscription): void {
    this.db.prepare("UPDATE subscriptions SET state=?, ack=?, delivered=?, lease_ms=?, revision=? WHERE id=?")
      .run(s.state, Number(uBig(s.ack)), Number(uBig(s.delivered)), Number(uBig(s.lease_until_ms)), Number(uBig(s.revision)), s.id);
  }

  private callerWatcher(cfg: T.Config, keyId: string): T.WatcherConfig {
    const principal = cfg.principals.find((p) => p.pin.key_id === keyId);
    const w = principal ? cfg.watchers.find((x) => x.principal === principal.id) : undefined;
    if (!principal || !w) throw new WError("FORBIDDEN", "key is not a bound watcher");
    return w;
  }

  subscriptionOpen(keyId: string, watcher: string, afterSeq: string, wall: bigint): T.Subscription {
    const t = this.logical > wall ? this.logical : wall;
    return this.tx(t, () => {
      this.requireRunning();
      const cfg = this.activeConfig();
      if (!cfg) throw new WError("FORBIDDEN", "no committed config");
      const w = this.callerWatcher(cfg.body, keyId);
      if (w.id !== watcher) throw new WError("FORBIDDEN", "subscription owned by another watcher");
      const live = this.db.prepare("SELECT id FROM subscriptions WHERE watcher=? AND state IN ('ACTIVE','PAUSED')").get(watcher);
      if (live) throw new WError("STATE_CONFLICT", "watcher already has a live subscription");
      if (uBig(afterSeq) > uBig(this.auditHead.seq)) throw new WError("CURSOR_INVALID", "after_seq beyond head");
      const sub: T.Subscription = {
        id: newId("wss"), watcher, state: "ACTIVE",
        ack: afterSeq, delivered: afterSeq,
        lease_until_ms: (t + LEASE_MS).toString(), revision: "1",
      };
      this.db.prepare("INSERT INTO subscriptions(id,watcher,state,ack,delivered,lease_ms,revision) VALUES(?,?,?,?,?,?,?)")
        .run(sub.id, watcher, "ACTIVE", Number(uBig(afterSeq)), Number(uBig(afterSeq)), Number(t + LEASE_MS), 1);
      this.appendAudit("SubscriptionChanged", { subscription: sub, event: "OPEN" }, t);
      return sub;
    });
  }

  /** Objects first-referenced in (afterSeq, nextSeq], sorted by (kind,hash). */
  private pageObjects(afterSeq: bigint, nextSeq: bigint): T.ObjectRecord[] {
    const rows = this.db.prepare(
      "SELECT o.kind, o.hash, o.canonical FROM objects_introduced i JOIN objects o ON o.kind=i.kind AND o.hash=i.hash WHERE i.seq>? AND i.seq<=? ORDER BY o.kind, o.hash",
    ).all(Number(afterSeq), Number(nextSeq)) as unknown as { kind: string; hash: string; canonical: Uint8Array }[];
    return rows.map((r) => ({
      kind: r.kind as T.ObjectRecord["kind"], hash: r.hash,
      value: JSON.parse(Buffer.from(r.canonical).toString("utf8")),
    }));
  }

  private frame(afterSeq: bigint, through: T.Head, limit: number): T.FramePage {
    const rows = this.db.prepare("SELECT seq, body, sig, hash FROM audit WHERE seq>? AND seq<=? ORDER BY seq LIMIT ?")
      .all(Number(afterSeq), Number(uBig(through.seq)), limit + 1) as unknown as
      { seq: number; body: Uint8Array; sig: string; hash: string }[];
    // 1 MiB page budget including referenced objects; never split an entry.
    const entries: T.Audit[] = [];
    let bytes = 0n;
    for (const r of rows.slice(0, limit)) {
      const sz = BigInt(r.body.length + 128);
      if (entries.length > 0 && bytes + sz > 1048576n) break;
      entries.push({ body: JSON.parse(Buffer.from(r.body).toString("utf8")), hash: r.hash, sig: r.sig });
      bytes += sz;
    }
    let nextSeq = entries.length > 0 ? uBig(entries[entries.length - 1]!.body.seq) : afterSeq;
    const objects = this.pageObjects(afterSeq, nextSeq);
    // Keep the whole page (entries + object closure) under 1 MiB by trimming
    // the tail entries when the closure would overflow.
    while (entries.length > 0) {
      const total = bytes + objects.reduce((n, o) => n + BigInt(jstr(o.value).length + 96), 0n);
      if (total <= 1048576n) break;
      const removed = entries.pop()!;
      bytes -= BigInt(jstr(removed.body).length + 128);
      nextSeq = uBig(entries[entries.length - 1]!.body.seq);
      objects.length = 0;
      objects.push(...this.pageObjects(afterSeq, nextSeq));
    }
    return {
      entries, objects, through,
      next_seq: nextSeq.toString(),
      more: uBig(through.seq) > nextSeq,
    };
  }

  subscriptionRead(keyId: string, sub: string, afterSeq: string, limit: number, wall: bigint): T.FramePage {
    const t = this.logical > wall ? this.logical : wall;
    return this.tx(t, () => {
      const s = this.getSub(sub);
      if (!s) throw new WError("NOT_FOUND", "subscription");
      const cfg = this.activeConfig();
      if (!cfg) throw new WError("FORBIDDEN", "no committed config");
      const w = this.callerWatcher(cfg.body, keyId);
      if (s.watcher !== w.id) throw new WError("FORBIDDEN", "subscription owned by another watcher");
      if (s.state !== "ACTIVE") throw new WError("STATE_CONFLICT", `subscription ${s.state}`);
      if (uBig(afterSeq) < uBig(s.ack) || uBig(afterSeq) > uBig(s.delivered)) {
        throw new WError("CURSOR_INVALID", "after_seq outside [ack,delivered]");
      }
      const through = this.auditHead;
      const page = this.frame(uBig(afterSeq), through, limit);
      const nd = { ...s, delivered: page.next_seq, lease_until_ms: (t + LEASE_MS).toString() };
      this.putSub(nd);
      return page;
    });
  }

  subscriptionAck(keyId: string, sub: string, throughSeq: string, wall: bigint): T.Subscription {
    const t = this.logical > wall ? this.logical : wall;
    return this.tx(t, () => {
      const s = this.getSub(sub);
      if (!s) throw new WError("NOT_FOUND", "subscription");
      const cfg = this.activeConfig();
      if (!cfg) throw new WError("FORBIDDEN", "no committed config");
      const w = this.callerWatcher(cfg.body, keyId);
      if (s.watcher !== w.id) throw new WError("FORBIDDEN", "subscription owned by another watcher");
      if (s.state !== "ACTIVE") throw new WError("STATE_CONFLICT", `subscription ${s.state}`);
      if (uBig(throughSeq) > uBig(s.delivered) || uBig(throughSeq) < uBig(s.ack)) {
        throw new WError("CURSOR_INVALID", "ack outside [ack,delivered]");
      }
      const advancing = uBig(throughSeq) > uBig(s.ack);
      const next: T.Subscription = {
        ...s, ack: throughSeq,
        lease_until_ms: (t + LEASE_MS).toString(),
        revision: advancing ? (uBig(s.revision) + 1n).toString() : s.revision,
      };
      this.putSub(next);
      return next;
    });
  }

  subscriptionSet(keyId: string, sub: string, action: "pause" | "resume" | "close", expected: string, wall: bigint): T.Subscription {
    const t = this.logical > wall ? this.logical : wall;
    return this.tx(t, () => {
      this.requireRunning();
      const s = this.getSub(sub);
      if (!s) throw new WError("NOT_FOUND", "subscription");
      const cfg = this.activeConfig();
      if (!cfg) throw new WError("FORBIDDEN", "no committed config");
      const w = this.callerWatcher(cfg.body, keyId);
      if (s.watcher !== w.id) throw new WError("FORBIDDEN", "subscription owned by another watcher");
      if (s.revision !== expected) throw new WError("REVISION_CONFLICT", "expected_revision mismatch");
      const legal =
        (action === "pause" && s.state === "ACTIVE") ||
        (action === "resume" && s.state === "PAUSED") ||
        (action === "close" && (s.state === "ACTIVE" || s.state === "PAUSED"));
      if (!legal) throw new WError("STATE_CONFLICT", `cannot ${action} ${s.state}`);
      const next: T.Subscription = {
        ...s,
        state: action === "pause" ? "PAUSED" : action === "resume" ? "ACTIVE" : "CLOSED",
        lease_until_ms: action === "close" ? s.lease_until_ms : (t + LEASE_MS).toString(),
        revision: (uBig(s.revision) + 1n).toString(),
      };
      this.putSub(next);
      this.appendAudit("SubscriptionChanged", {
        subscription: next,
        event: action === "pause" ? "PAUSE" : action === "resume" ? "RESUME" : "CLOSE",
      }, t);
      return next;
    });
  }

  // ---- votes / alerts ---------------------------------------------------
  voteSubmit(keyId: string, vote: T.Vote, wall: bigint): { accepted: true; alert: T.AlertView } {
    const t = this.logical > wall ? this.logical : wall;
    return this.tx(t, () => {
      this.requireRunning();
      const cfg = this.activeConfig();
      if (!cfg) throw new WError("FORBIDDEN", "no committed config");
      if (vote.hash !== D("WEATHER-VOTE/1", vote.body)) throw new WError("HASH_MISMATCH", "vote hash");
      const w = this.callerWatcher(cfg.body, keyId);
      if (vote.body.watcher !== w.id) throw new WError("FORBIDDEN", "vote names another watcher");
      if (vote.body.key_id !== w.pin.key_id) throw new WError("SIGNATURE_INVALID", "vote key binding");
      if (!verifyDetached(b64uDecode(w.pin.public_key, 32, "pub"), "WEATHER-VOTE-SIGN/1", vote.hash, b64uDecode(vote.sig, 64, "sig"))) {
        throw new WError("SIGNATURE_INVALID", "vote signature");
      }
      const alertRow = this.db.prepare("SELECT * FROM alerts WHERE result_hash=?").get(vote.body.result) as
        { id: string; view: Uint8Array; state: string; expires_ms: number } | undefined;
      if (!alertRow) throw new WError("NOT_FOUND", "result names no committed alert");
      const result = this.object<T.Result>("result", vote.body.result)!;
      // Frozen roster: the watcher must be enabled in the result's config epoch.
      const rcfg = this.configByHash(result.body.config);
      if (!rcfg) throw new WError("RESULT_MISMATCH", "result config missing");
      const frozen = rcfg.body.watchers.find((x) => x.id === vote.body.watcher);
      if (!frozen || !frozen.enabled) throw new WError("FORBIDDEN", "watcher outside frozen roster");
      if (vote.body.fleet !== this.fleetId || vote.body.config !== result.body.config || vote.body.manifest !== result.body.manifest) {
        this.bumpMetric("vote_rejected_total");
        throw new WError("RESULT_MISMATCH", "vote binding mismatch");
      }
      const alert = JSON.parse(Buffer.from(alertRow.view).toString("utf8")) as T.AlertView;
      if (t >= uBig(alert.expires_ms)) {
        this.bumpMetric("vote_rejected_total");
        throw new WError("VOTE_EXPIRED", "vote past expiry");
      }
      if (alert.state === "CLOSED") {
        this.bumpMetric("vote_rejected_total");
        throw new WError("STATE_CONFLICT", "alert closed");
      }
      const existing = this.db.prepare("SELECT vote_hash FROM votes WHERE result_hash=? AND watcher=?")
        .get(vote.body.result, w.id) as { vote_hash: string } | undefined;
      if (existing) {
        if (existing.vote_hash !== vote.hash) {
          this.bumpMetric("vote_rejected_total");
          throw new WError("RESULT_MISMATCH", "conflicting vote from same watcher");
        }
        return { accepted: true, alert };
      }
      this.db.prepare("INSERT INTO votes(result_hash,watcher,vote_hash,vote) VALUES(?,?,?,?)")
        .run(vote.body.result, w.id, vote.hash, Buffer.from(jstr(vote), "utf8"));
      this.appendAudit("VoteAccepted", { alert: alert.id, vote }, t);
      const revokedNow = this.revoked;
      const voteRows = this.db.prepare("SELECT watcher, vote_hash FROM votes WHERE result_hash=?")
        .all(vote.body.result) as unknown as { watcher: string; vote_hash: string }[];
      const domains = new Set<string>();
      for (const vr of voteRows) {
        const wc = rcfg.body.watchers.find((x) => x.id === vr.watcher)!;
        const v = JSON.parse(Buffer.from(
          (this.db.prepare("SELECT vote FROM votes WHERE vote_hash=?").get(vr.vote_hash) as { vote: Uint8Array }).vote,
        ).toString("utf8")) as T.Vote;
        if (!revokedNow.has(v.body.key_id)) domains.add(wc.domain);
      }
      const votesList = voteRows.map((v) => v.vote_hash).sort();
      const rev = (uBig(alert.revision) + 1n).toString();
      let next: T.AlertView = { ...alert, votes: votesList, domains: [...domains].sort(), revision: rev };
      this.setAlertView(next);
      if (next.state === "CANDIDATE" && domains.size >= rcfg.body.quorum_domains && next.assurance === "VALID") {
        const rev2 = (uBig(rev) + 1n).toString();
        next = { ...next, state: "CORROBORATED", revision: rev2 };
        this.setAlertView(next);
        this.appendAudit("AlertChanged", {
          alert: alert.id, from: "CANDIDATE", to: "CORROBORATED",
          actor: null, note_hash: null, revision: rev2,
        }, t);
        next = this.queuePage(next, t);
      }
      return { accepted: true, alert: next };
    });
  }

  private setAlertView(a: T.AlertView): void {
    this.db.prepare("UPDATE alerts SET state=?, assurance=?, revision=?, view=? WHERE id=?")
      .run(a.state, a.assurance, Number(uBig(a.revision)), Buffer.from(jstr(a), "utf8"), a.id);
  }

  /** Create the immutable Page and QUEUED outbox row after CORROBORATED. */
  private queuePage(alert: T.AlertView, t: bigint): T.AlertView {
    const cfg = this.activeConfig()!;
    // null primary_url disables delivery, not corroboration (§6.3).
    if (cfg.body.notification_target !== "primary" || this.primaryUrl === null) return alert;
    const corrHead = this.auditHead; // the just-committed AlertChanged position
    const result = this.object<T.Result>("result", alert.result)!;
    const body: T.PageBody = {
      v: 1, fleet: this.fleetId, alert: alert.id, result: alert.result,
      config: result.body.config, manifest: result.body.manifest,
      corroborated: corrHead, semantics: "ADVISORY_ONLY", key_id: this.auditPin.key_id,
    };
    const hash = D("WEATHER-PAGE/1", body);
    const sig = Buffer.from(signDetached(this.auditSeed, "WEATHER-PAGE-SIGN/1", hash)).toString("base64url");
    const page: T.Page = { body, hash, sig };
    this.putObject("page", hash, page);
    this.db.prepare("INSERT INTO outbox(alert,page_hash,state,attempts,due_ms,lease_ms,last_status,cancel_pending) VALUES(?,?,?,0,?,NULL,NULL,0)")
      .run(alert.id, hash, "QUEUED", Number(t));
    const delivery: T.Delivery = {
      alert: alert.id, state: "QUEUED", attempts: 0,
      due_ms: t.toString(), lease_until_ms: null, last_status: null,
    };
    this.appendAudit("DeliveryChanged", { delivery, page: hash, cancel_pending: false }, t);
    const rev = (uBig(alert.revision) + 1n).toString();
    const next = { ...alert, delivery: "QUEUED" as const, revision: rev };
    this.setAlertView(next);
    return next;
  }

  alertAct(keyId: string, alertId: string, action: "ack" | "close", expected: string, noteHash: string | null, wall: bigint): T.AlertView {
    const t = this.logical > wall ? this.logical : wall;
    return this.tx(t, () => {
      this.requireRunning();
      const cfg = this.activeConfig();
      if (!cfg) throw new WError("FORBIDDEN", "no committed config");
      const principal = cfg.body.principals.find((p) => p.pin.key_id === keyId);
      if (!principal || !principal.roles.includes("operator")) throw new WError("FORBIDDEN", "key is not an operator");
      const row = this.db.prepare("SELECT view FROM alerts WHERE id=?").get(alertId) as { view: Uint8Array } | undefined;
      if (!row) throw new WError("NOT_FOUND", "alert");
      const alert = JSON.parse(Buffer.from(row.view).toString("utf8")) as T.AlertView;
      if (alert.revision !== expected) throw new WError("REVISION_CONFLICT", "expected_revision mismatch");
      const legal =
        (action === "ack" && alert.state === "CORROBORATED") ||
        (action === "close" && (alert.state === "CANDIDATE" || alert.state === "CORROBORATED" || alert.state === "ACKNOWLEDGED"));
      if (!legal) throw new WError("STATE_CONFLICT", `cannot ${action} ${alert.state}`);
      const rev = (uBig(alert.revision) + 1n).toString();
      const next: T.AlertView = { ...alert, state: action === "ack" ? "ACKNOWLEDGED" : "CLOSED", revision: rev };
      this.setAlertView(next);
      this.appendAudit("AlertChanged", {
        alert: alertId, from: alert.state, to: next.state,
        actor: principal.id, note_hash: noteHash, revision: rev,
      }, t);
      this.cancelPendingDelivery(alertId, next, t);
      return this.getAlert(alertId)!;
    });
  }

  private cancelPendingDelivery(alertId: string, alert: T.AlertView, t: bigint): void {
    const ob = this.db.prepare("SELECT * FROM outbox WHERE alert=?").get(alertId) as
      { page_hash: string; state: string; attempts: number; due_ms: number | null; lease_ms: number | null; last_status: number | null; cancel_pending: number } | undefined;
    if (!ob) return;
    if (ob.state === "QUEUED" || ob.state === "RETRY") {
      this.db.prepare("UPDATE outbox SET state='CANCELLED' WHERE alert=?").run(alertId);
      const delivery: T.Delivery = {
        alert: alertId, state: "CANCELLED", attempts: ob.attempts,
        due_ms: ob.due_ms === null ? null : ob.due_ms.toString(),
        lease_until_ms: ob.lease_ms === null ? null : ob.lease_ms.toString(),
        last_status: ob.last_status,
      };
      this.appendAudit("DeliveryChanged", { delivery, page: null, cancel_pending: false }, t);
      const rev = (uBig(alert.revision) + 1n).toString();
      this.setAlertView({ ...alert, delivery: "CANCELLED", revision: rev });
    } else if (ob.state === "IN_FLIGHT") {
      this.db.prepare("UPDATE outbox SET cancel_pending=1 WHERE alert=?").run(alertId);
    }
  }

  /** Relevant-source/key degradation (§5.1). */
  private degradeForSource(source: string | null, key: string | null, t: bigint): void {
    const alertRows = this.db.prepare("SELECT id, result_hash, view FROM alerts WHERE assurance='VALID'")
      .all() as unknown as { id: string; result_hash: string; view: Uint8Array }[];
    for (const r of alertRows) {
      const result = this.object<T.Result>("result", r.result_hash);
      if (!result) continue;
      let relevant = false;
      if (source !== null) {
        const manifest = this.object<T.Manifest>("manifest", result.body.manifest);
        const srcEntries = new Set(
          (this.db.prepare("SELECT hash FROM accepted WHERE source=?").all(source) as unknown as { hash: string }[]).map((x) => x.hash),
        );
        relevant = result.body.evidence.some((h) => srcEntries.has(h)) ||
          (manifest?.cuts.some((c) => c.source === source) ?? false);
      }
      if (!relevant && key !== null) {
        const votesRows = this.db.prepare("SELECT watcher, vote FROM votes WHERE result_hash=?")
          .all(r.result_hash) as unknown as { watcher: string; vote: Uint8Array }[];
        for (const vr of votesRows) {
          const v = JSON.parse(Buffer.from(vr.vote).toString("utf8")) as T.Vote;
          if (v.body.key_id === key) { relevant = true; break; }
        }
        if (!relevant) {
          const rcfg = this.configByHash(result.body.config);
          const manifest = this.object<T.Manifest>("manifest", result.body.manifest);
          if (rcfg && manifest) {
            const voterWatchers = new Set(votesRows.map((vr) => vr.watcher));
            relevant = rcfg.body.watchers.some((w) => w.pin.key_id === key && voterWatchers.has(w.id)) ||
              rcfg.body.sources.some((s) => {
                if (s.pin.key_id !== key) return false;
                if (manifest.cuts.some((c) => c.source === s.id)) return true;
                const srcHashes = new Set(
                  (this.db.prepare("SELECT hash FROM accepted WHERE source=?").all(s.id) as unknown as { hash: string }[]).map((x) => x.hash),
                );
                return result.body.evidence.some((h) => srcHashes.has(h));
              });
          }
        }
      }
      if (!relevant) continue;
      const alert = JSON.parse(Buffer.from(r.view).toString("utf8")) as T.AlertView;
      const rev = (uBig(alert.revision) + 1n).toString();
      const next = { ...alert, assurance: "DEGRADED" as const, revision: rev };
      this.setAlertView(next);
      this.appendAudit("AlertDegraded", { alert: r.id, source, key, revision: rev }, t);
      this.cancelPendingDelivery(r.id, next, t);
    }
  }

  private degradeForKeys(keys: string[], t: bigint): void {
    for (const k of keys) this.degradeForSource(null, k, t);
  }

  // ---- deliveries -------------------------------------------------------
  /** Drive due outbox items; sender performs the actual POST. */
  runDeliveries(wall: bigint, sender: (page: T.Page, idem: string) => Promise<{ status: number } | null>): void {
    const t = this.logical > wall ? this.logical : wall;
    const due = this.db.prepare(
      "SELECT alert, page_hash FROM outbox WHERE state IN ('QUEUED','RETRY') AND due_ms IS NOT NULL AND due_ms<=?",
    ).all(Number(t)) as unknown as { alert: string; page_hash: string }[];
    for (const d of due) {
      const alert = this.getAlert(d.alert)!;
      if (alert.state === "CLOSED" || alert.state === "EXPIRED" || alert.assurance === "DEGRADED") {
        this.tx(t, () => this.cancelPendingDelivery(d.alert, alert, t));
        continue;
      }
      this.tx(t, () => {
        this.db.prepare("UPDATE outbox SET state='IN_FLIGHT', attempts=attempts+1, lease_ms=? WHERE alert=?")
          .run(Number(t + DELIVERY_LEASE_MS), d.alert);
        const ob = this.db.prepare("SELECT * FROM outbox WHERE alert=?").get(d.alert) as { attempts: number };
        const delivery: T.Delivery = {
          alert: d.alert, state: "IN_FLIGHT", attempts: ob.attempts,
          due_ms: null, lease_until_ms: (t + DELIVERY_LEASE_MS).toString(), last_status: null,
        };
        this.appendAudit("DeliveryChanged", { delivery, page: d.page_hash, cancel_pending: false }, t);
      });
      const page = this.object<T.Page>("page", d.page_hash)!;
      void sender(page, d.page_hash).then((r) => this.completeDelivery(d.alert, d.page_hash, r ? r.status : null));
    }
  }

  completeDelivery(alertId: string, pageHash: string, status: number | null): void {
    const t = this.logical; // completion recorded at current logical time
    this.tx(t === 0n ? 1n : t, () => {
      const ob = this.db.prepare("SELECT * FROM outbox WHERE alert=? AND page_hash=?").get(alertId, pageHash) as
        { state: string; attempts: number; cancel_pending: number } | undefined;
      if (!ob || ob.state !== "IN_FLIGHT") return; // stale/duplicate completion
      const alert = this.getAlert(alertId)!;
      const cancel = ob.cancel_pending === 1 || alert.state === "CLOSED" || alert.assurance === "DEGRADED";
      if (status !== null && status >= 200 && status < 300 && !cancel) {
        this.db.prepare("UPDATE outbox SET state='DELIVERED', last_status=? WHERE alert=?").run(status, alertId);
        this.deliveryEvent(alertId, "DELIVERED", ob.attempts, status, t);
        const rev = (uBig(alert.revision) + 1n).toString();
        this.setAlertView({ ...alert, delivery: "DELIVERED", revision: rev });
        return;
      }
      const retryable = status === null || status === 429 || status >= 500;
      if (!retryable || ob.attempts >= 8 || cancel) {
        const fin = cancel && !(status !== null && status >= 200 && status < 300) ? "CANCELLED" :
          (status !== null && status >= 200 && status < 300) ? "DELIVERED" : "FAILED";
        this.db.prepare("UPDATE outbox SET state=?, last_status=? WHERE alert=?").run(fin, status, alertId);
        this.deliveryEvent(alertId, fin, ob.attempts, status, t);
        const rev = (uBig(alert.revision) + 1n).toString();
        this.setAlertView({ ...alert, delivery: fin as T.DeliveryState, revision: rev });
        if (fin === "FAILED") this.bumpMetric("page_failed_total");
        return;
      }
      const delay = RETRY_DELAYS[ob.attempts - 1]!;
      this.db.prepare("UPDATE outbox SET state='RETRY', due_ms=?, lease_ms=NULL, last_status=? WHERE alert=?")
        .run(Number(t + delay), status, alertId);
      this.deliveryEvent(alertId, "RETRY", ob.attempts, status, t);
      const rev = (uBig(alert.revision) + 1n).toString();
      this.setAlertView({ ...alert, delivery: "RETRY", revision: rev });
    });
  }

  private deliveryEvent(alertId: string, state: T.DeliveryState, attempts: number, status: number | null, t: bigint): void {
    const ob = this.db.prepare("SELECT due_ms, lease_ms FROM outbox WHERE alert=?").get(alertId) as
      { due_ms: number | null; lease_ms: number | null };
    const delivery: T.Delivery = {
      alert: alertId, state, attempts,
      due_ms: ob.due_ms === null ? null : ob.due_ms.toString(),
      lease_until_ms: ob.lease_ms === null ? null : ob.lease_ms.toString(),
      last_status: status,
    };
    this.appendAudit("DeliveryChanged", { delivery, page: null, cancel_pending: false }, t);
    if (state === "IN_FLIGHT" || state === "RETRY" || state === "FAILED") this.bumpMetric("page_attempt_total");
  }

  // ---- reads --------------------------------------------------------------
  getAlert(id: string): T.AlertView | null {
    const r = this.db.prepare("SELECT view FROM alerts WHERE id=?").get(id) as { view: Uint8Array } | undefined;
    return r ? (JSON.parse(Buffer.from(r.view).toString("utf8")) as T.AlertView) : null;
  }

  alertList(state: T.AlertState | null, after: string | null, limit: number): { alerts: T.AlertView[]; next: string | null } {
    const rows = state === null
      ? this.db.prepare("SELECT id, view FROM alerts WHERE id>? ORDER BY id LIMIT ?").all(after ?? "", limit + 1)
      : this.db.prepare("SELECT id, view FROM alerts WHERE state=? AND id>? ORDER BY id LIMIT ?").all(state, after ?? "", limit + 1);
    const list = (rows as unknown as { id: string; view: Uint8Array }[]).slice(0, limit);
    return {
      alerts: list.map((r) => JSON.parse(Buffer.from(r.view).toString("utf8")) as T.AlertView),
      next: (rows as unknown as { id: string }[]).length > limit ? list[list.length - 1]!.id : null,
    };
  }

  alertGet(id: string): { alert: T.AlertView; result: T.Result; manifest: T.Manifest } {
    const alert = this.getAlert(id);
    if (!alert) throw new WError("NOT_FOUND", "alert");
    const result = this.object<T.Result>("result", alert.result);
    const manifest = result ? this.object<T.Manifest>("manifest", result.body.manifest) : null;
    if (!result || !manifest) throw new WError("AUDIT_UNAVAILABLE", "missing objects");
    return { alert, result, manifest };
  }

  auditRead(afterSeq: string, through: T.Head | null, limit: number): T.FramePage {
    const head = this.auditHead;
    const pinned = through ?? head;
    if (through !== null) {
      const genesis = through.seq === "0" && through.hash === ZERO;
      const row = this.db.prepare("SELECT hash FROM audit WHERE seq=?").get(Number(uBig(through.seq))) as { hash: string } | undefined;
      if (!genesis && (!row || row.hash !== through.hash)) throw new WError("CURSOR_INVALID", "through is not a committed position");
      if (uBig(through.seq) > uBig(head.seq)) throw new WError("CURSOR_INVALID", "through beyond head");
    }
    if (uBig(afterSeq) > uBig(pinned.seq)) throw new WError("CURSOR_INVALID", "after_seq exceeds through");
    return this.frame(uBig(afterSeq), pinned, limit);
  }

  checkpoint(): T.Checkpoint {
    const head = this.auditHead;
    const cached = metaJson<T.Checkpoint>(this.db, "last_checkpoint");
    if (cached && cached.body.head.seq === head.seq && cached.body.head.hash === head.hash) return cached;
    const body: T.CheckpointBody = {
      v: 1, fleet: this.fleetId, head,
      through_index: (this.nextIndex - 1n).toString(),
      logical_ms: this.logical.toString(),
      config: this.activeHash(),
      key_id: this.auditPin.key_id,
    };
    const hash = D("WEATHER-CHECKPOINT/1", body);
    const cp: T.Checkpoint = {
      body, hash,
      sig: Buffer.from(signDetached(this.auditSeed, "WEATHER-CHECKPOINT-SIGN/1", hash)).toString("base64url"),
    };
    metaSet(this.db, "last_checkpoint", jstr(cp));
    return cp;
  }

  bundleExport(afterSeq: string, checkpoint: T.Checkpoint, limit: number): T.BundlePage {
    if (checkpoint.hash !== D("WEATHER-CHECKPOINT/1", checkpoint.body)) throw new WError("HASH_MISMATCH", "checkpoint hash");
    if (checkpoint.body.fleet !== this.fleetId || checkpoint.body.key_id !== this.auditPin.key_id) {
      throw new WError("SIGNATURE_INVALID", "checkpoint binding");
    }
    if (!verifyDetached(b64uDecode(this.auditPin.public_key, 32, "audit"), "WEATHER-CHECKPOINT-SIGN/1", checkpoint.hash, b64uDecode(checkpoint.sig, 64, "sig"))) {
      throw new WError("SIGNATURE_INVALID", "checkpoint signature");
    }
    const head = this.auditHead;
    const cpSeq = uBig(checkpoint.body.head.seq);
    if (cpSeq > uBig(head.seq)) throw new WError("CURSOR_INVALID", "checkpoint beyond head");
    const genesis = checkpoint.body.head.seq === "0" && checkpoint.body.head.hash === ZERO;
    const row = this.db.prepare("SELECT hash FROM audit WHERE seq=?").get(Number(cpSeq)) as { hash: string } | undefined;
    if (!genesis && (!row || row.hash !== checkpoint.body.head.hash)) throw new WError("CURSOR_INVALID", "checkpoint not a committed position");
    if (uBig(afterSeq) > cpSeq) throw new WError("CURSOR_INVALID", "after_seq exceeds checkpoint head");
    const page = this.frame(uBig(afterSeq), checkpoint.body.head, limit);
    return {
      v: 1, format: "weather-evidence/1", checkpoint,
      after_seq: afterSeq, entries: page.entries, objects: page.objects,
      next_seq: page.next_seq, more: uBig(checkpoint.body.head.seq) > uBig(page.next_seq),
      native_disclosure: "COMMITMENTS_ONLY",
    };
  }

  fleetGet(): T.FleetView {
    const counts = { candidate: 0, corroborated: 0, acknowledged: 0, closed: 0, expired: 0 };
    for (const r of this.db.prepare("SELECT state, COUNT(*) AS n FROM alerts GROUP BY state").all() as unknown as { state: string; n: number }[]) {
      const k = r.state.toLowerCase() as keyof typeof counts;
      counts[k] = Number(r.n);
    }
    const cfg = this.activeConfig();
    const sources: T.SourceView[] = cfg
      ? cfg.body.sources.filter((s) => s.enabled).map((s) => this.sourceView(s.id)).sort((a, b) => (a.source < b.source ? -1 : 1))
      : [];
    const enabledDomains = new Set(cfg ? cfg.body.watchers.filter((w) => w.enabled).map((w) => w.domain) : []);
    const paging = cfg && cfg.body.notification_target === "primary" && enabledDomains.size >= 2 && this.primaryUrl !== null
      ? "AVAILABLE" as const : "PAGING_UNAVAILABLE" as const;
    return {
      fleet: this.fleetId, phase: this.phase, logical_ms: this.logical.toString(),
      config: cfg, pending: this.pendingConfig(),
      head: this.auditHead, through_index: (this.nextIndex - 1n).toString(),
      sources, alerts: counts, paging, catching_up: this.catchingUp,
    };
  }

  metricsGet(): { fleet: string; samples: T.Metric[] } {
    const counters = metaJson<Record<string, string>>(this.db, "counters") ?? {};
    const names: T.MetricName[] = [
      "inputs_accepted_total", "inputs_duplicate_total", "inputs_late_total",
      "source_forks_total", "detector_hit_total", "detector_unknown_total",
      "vote_rejected_total", "page_attempt_total", "page_failed_total",
    ];
    const samples: T.Metric[] = names.map((n) => ({ name: n, value: counters[n] ?? "0" }));
    samples.push({ name: "audit_bytes", value: this.byteAccounting.toString() });
    const domains = new Set<string>();
    const cfg = this.activeConfig();
    if (cfg) {
      for (const r of this.db.prepare("SELECT watcher FROM votes").all() as unknown as { watcher: string }[]) {
        const w = cfg.body.watchers.find((x) => x.id === r.watcher);
        if (w) domains.add(w.domain);
      }
    }
    samples.push({ name: "active_domains", value: domains.size.toString() });
    samples.push({ name: "logical_lag_ms", value: "0" });
    return { fleet: this.fleetId, samples };
  }

  private bumpMetric(name: T.MetricName | null): void {
    if (!name) return;
    const c = metaJson<Record<string, string>>(this.db, "counters") ?? {};
    c[name] = (BigInt(c[name] ?? "0") + 1n).toString();
    metaSet(this.db, "counters", JSON.stringify(c));
  }

  /** Called inside the request's tx by the RPC layer after method dispatch. */
  recordIdempotent(keyId: string, requestId: string, requestHash: string, resultJson: string, t: bigint): void {
    this.db.prepare("INSERT OR REPLACE INTO requests(key_id,request_id,request_hash,result,expires_ms) VALUES(?,?,?,?,?)")
      .run(keyId, requestId, requestHash, Buffer.from(resultJson, "utf8"), Number(t + DAY_MS));
  }

  lookupIdempotent(keyId: string, requestId: string, requestHash: string): { hit: "replay" | "conflict" | "expired" | "none"; result?: string } {
    const r = this.db.prepare("SELECT request_hash, result FROM requests WHERE key_id=? AND request_id=?")
      .get(keyId, requestId) as { request_hash: string; result: Uint8Array | null } | undefined;
    if (!r) return { hit: "none" };
    if (r.request_hash !== requestHash) return { hit: "conflict" };
    if (r.result === null) return { hit: "expired" };
    return { hit: "replay", result: Buffer.from(r.result).toString("utf8") };
  }

  /** Keys currently bound: bootstrap root plus principals of committed (active or scheduled) configs. */
  boundKey(keyId: string): { publicKey: string; roles: T.Role[]; isRoot: boolean } | null {
    if (keyId === this.root.key_id) return { publicKey: this.root.public_key, roles: ["operator"], isRoot: true };
    for (const cfg of [this.activeConfig(), this.pendingConfig()]) {
      if (!cfg) continue;
      const p = cfg.body.principals.find((x) => x.pin.key_id === keyId);
      if (p) return { publicKey: p.pin.public_key, roles: p.roles, isRoot: false };
    }
    return null;
  }
}

export { openFleetDb, isHash };
