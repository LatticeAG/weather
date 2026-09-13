import { createHash, verify as nVerify, createPublicKey } from "node:crypto";
import { WError } from "./errors.js";
import { J, jstr } from "./jcs.js";
import { D, isHash } from "./hash.js";
import { isId, type IdPrefix } from "./ids.js";
import { isU, uBig } from "./schema.js";
import {
  spendKernel, spendSum, scopeKernel, replicationKernel, silenceKernel,
  signalAnnotation, checkedSum,
} from "./detectors.js";
import type { Decision, SourceState } from "./types.js";
import { canonicalPoint, canonicalSignature } from "./ed25519.js";

/**
 * §13 kernel ops: compact pure units isolating parser/predicate/transition
 * logic. Each op maps its literal input object to the literal expected object
 * (or {error: CODE}).
 */

const KERR = (code: string) => ({ error: code });

function needU(x: unknown, w: string): string {
  if (!isU(x)) throw new WError("INVALID_INPUT", w);
  return x;
}

// ---- sequence kernel state model -------------------------------------
// head: last contiguous seq; pending: sorted buffered seqs; known:
// NONE|SAME|DIFFERENT describes slot (seq) retention; sig_valid gates
// attribution; prev_matches describes the new entry's prev vs head hash.
function opSequence(i: Record<string, unknown>): unknown {
  if (i["sig_valid"] !== true) return KERR("SIGNATURE_INVALID");
  const head = BigInt(needU(i["head"], "head"));
  const pending = (i["pending"] as string[]).map((p) => BigInt(needU(p, "pending")));
  const seq = BigInt(needU(i["seq"], "seq"));
  const known = i["known"] as "NONE" | "SAME" | "DIFFERENT";
  const prevMatches = i["prev_matches"] === true;

  if (known === "SAME") {
    return { status: "DUPLICATE", state: "ACTIVE", head: head.toString(), pending: pending.map(String), drained: [] };
  }
  if (known === "DIFFERENT") {
    return { status: "FORK", state: "FORKED", head: head.toString(), pending: pending.map(String), drained: [] };
  }
  // known === NONE
  if (seq <= head) return KERR("CHAIN_INVALID"); // unseen slot at/below head: prev cannot chain
  if (seq > head + 256n) return KERR("GAP_LIMIT");
  const pend = new Set(pending);
  const drained: bigint[] = [];
  let h = head;
  let status: string;
  if (seq === h + 1n) {
    if (!prevMatches) {
      // contiguous predecessor mismatch: durably buffered as evidence, GAPPED
      pend.add(seq);
      return KERR("CHAIN_INVALID");
    }
    drained.push(seq);
    h = seq;
    status = "ACCEPTED";
    // drain contiguous pending
    while (pend.has(h + 1n)) {
      h = h + 1n;
      drained.push(h);
      pend.delete(h);
    }
  } else {
    pend.add(seq);
    status = "BUFFERED";
  }
  const ps = [...pend].sort((a, b) => (a < b ? -1 : 1)).map(String);
  return {
    status,
    state: pend.size === 0 ? "ACTIVE" : "GAPPED",
    head: h.toString(),
    pending: ps,
    drained: drained.map(String),
  };
}

const RETRY_DELAYS = [1000n, 2000n, 4000n, 8000n, 16000n, 32000n, 60000n];

export function runKernel(input: Record<string, unknown>): unknown {
  const op = input["op"];
  switch (op) {
    case "canonical": {
      const utf8 = jstr(input["value"]);
      return { utf8, sha256: createHash("sha256").update(utf8, "utf8").digest("hex") };
    }
    case "digest":
      return { hash: D(String(input["tag"]), input["value"]) };
    case "ed25519": {
      const pub = Buffer.from(String(input["public_hex"]), "hex");
      const msg = Buffer.from(String(input["message_hex"]), "hex");
      const sig = Buffer.from(String(input["signature_hex"]), "hex");
      if (pub.length !== 32 || sig.length !== 64) return { valid: false };
      if (!canonicalPoint(pub) || !canonicalSignature(sig)) return { valid: false };
      const spki = createPublicKey({
        key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub]),
        format: "der", type: "spki",
      });
      return { valid: nVerify(null, msg, spki, sig) };
    }
    case "parse": {
      try {
        const { parseText } = jsonMod();
        parseText(String(input["raw"]));
        return {};
      } catch (e) {
        if (e instanceof WError) return KERR(e.code);
        throw e;
      }
    }
    case "canonical_equal": {
      const l = J(input["left"]);
      const r = J(input["right"]);
      return { equal: Buffer.compare(l, r) === 0 };
    }
    case "id":
      return { valid: isId(input["value"], input["prefix"] as IdPrefix) };
    case "uint": {
      if (!isU(input["value"])) return KERR("INVALID_INPUT");
      return {};
    }
    case "spend":
      return spendKernel(input["prior"] as string[], needU(input["current"], "current"), input["quality"] as never);
    case "spend_sum":
      return spendSum(input["deltas"] as string[]);
    case "scope":
      return scopeKernel(
        input["policies"] as string[], input["scopes"] as string[],
        input["policy"] as string | null, input["scope"] as string | null,
        input["reported_violation"] === true,
      );
    case "replication":
      return replicationKernel(
        input["processes"] as string | null, input["threads"] as string | null,
        input["declared_processes"] as string | null,
        needU(input["max_processes"], "max_processes"), needU(input["max_threads"], "max_threads"),
      );
    case "silence":
      return silenceKernel(input["state"] as SourceState, needU(input["last_ms"], "last_ms"), needU(input["end_ms"], "end_ms"));
    case "receive_time": {
      const last = uBig(needU(input["last_logical_ms"], "last_logical_ms"));
      const wall = uBig(needU(input["wall_ms"], "wall_ms"));
      const obs = uBig(needU(input["observed_ms"], "observed_ms"));
      const t = last > wall ? last : wall;
      if (obs > t + 60000n) return KERR("FUTURE_TIMESTAMP");
      const late = obs < t - 120000n;
      const wstart = (t / 60000n) * 60000n;
      return { logical_ms: t.toString(), window_start_ms: wstart.toString(), late };
    }
    case "sequence":
      return opSequence(input);
    case "usage": {
      const stored = input["stored"] as { subject: string; delta: string; unit: string } | null;
      const inc = input["incoming"] as { subject: string; delta: string; unit: string };
      const ph = (x: { subject: string; delta: string; unit: string }) =>
        D("WEATHER-USAGE/1", { delta: x.delta, subject: x.subject, unit: x.unit });
      if (stored === null) return { counted: true };
      if (ph(stored) !== ph(inc)) return KERR("USAGE_CONFLICT");
      return { counted: false };
    }
    case "lattice": {
      const votes = input["votes"] as { watcher: string; domain: string; eligible: boolean }[];
      const seen = new Set<string>();
      const domains = new Set<string>();
      for (const v of votes) {
        if (seen.has(v.watcher)) continue;
        seen.add(v.watcher);
        if (v.eligible) domains.add(v.domain);
      }
      const ds = [...domains].sort();
      return { domains: ds, corroborated: ds.length >= 2 };
    }
    case "vote_gate": {
      const same = input["same_result"] === true;
      const now = uBig(needU(input["now_ms"], "now_ms"));
      const exp = uBig(needU(input["expires_ms"], "expires_ms"));
      if (!same) return KERR("RESULT_MISMATCH");
      if (now >= exp) return KERR("VOTE_EXPIRED");
      return { accepted: true };
    }
    case "alert_action": {
      const state = input["state"] as string;
      const action = input["action"] as string;
      const expected = needU(input["expected_revision"], "expected_revision");
      const actual = needU(input["actual_revision"], "actual_revision");
      if (expected !== actual) return KERR("REVISION_CONFLICT");
      if (action === "ack" && state === "CORROBORATED") return { state: "ACKNOWLEDGED" };
      if (action === "close" && (state === "CANDIDATE" || state === "CORROBORATED" || state === "ACKNOWLEDGED")) {
        return { state: "CLOSED" };
      }
      return KERR("STATE_CONFLICT");
    }
    case "delivery_failure": {
      const attempts = Number(input["attempts"]);
      const status = input["status"] as number | null;
      const retryable = status === null || status === 429 || status >= 500;
      if (!retryable) return { state: "FAILED", delay_ms: null };
      if (attempts >= 8) return { state: "FAILED", delay_ms: null };
      return { state: "RETRY", delay_ms: RETRY_DELAYS[attempts - 1]!.toString() };
    }
    case "page_dedup": {
      const existing = new Set(input["existing_results"] as string[]);
      let inserted = 0;
      for (const r of input["corroborated_results"] as string[]) {
        if (!existing.has(r)) { existing.add(r); inserted++; }
      }
      return { outbox_results: [...existing], inserted };
    }
    case "degrade": {
      const delivery = input["delivery"] as string;
      const d = delivery === "QUEUED" || delivery === "RETRY" ? "CANCELLED" : delivery;
      return { state: input["state"], assurance: "DEGRADED", delivery: d };
    }
    case "audit_positions": {
      const seqs = (input["seqs"] as string[]).map((s) => uBig(needU(s, "seqs")));
      for (let k = 1; k < seqs.length; k++) {
        if (seqs[k] !== seqs[k - 1]! + 1n) return KERR("CHAIN_INVALID");
      }
      return {};
    }
    case "export_complete": {
      const ok = input["header"] === true && input["trailer"] === true && input["expected_entries"] === input["actual_entries"];
      return ok ? { complete: true } : { complete: false, reason: "INCOMPLETE" };
    }
    case "rates": {
      const g = (k: string) => uBig(needU(input[k], k));
      const tp = g("tp"), fp = g("fp"), fn = g("fn"), tn = g("tn"), up = g("unknown_positive"), un = g("unknown_negative");
      const frac = (n: bigint, d: bigint) => (d === 0n ? null : { n: n.toString(), d: d.toString() });
      const N = tp + fp + fn + tn + up + un;
      return {
        precision: frac(tp, tp + fp),
        recall: frac(tp, tp + fn + up),
        false_positive_rate: frac(fp, fp + tn + un),
        coverage: frac(tp + fp + fn + tn, N),
      };
    }
    case "signal": {
      if (!isHash(input["artifact"])) throw new WError("INVALID_INPUT", "artifact");
      return signalAnnotation();
    }
    default:
      throw new WError("INVALID_INPUT", `unknown op ${String(op)}`);
  }
}

import { parseText } from "./json.js";
function jsonMod() {
  return { parseText };
}

export { checkedSum };
export type { Decision };
