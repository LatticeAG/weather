import { D } from "./hash.js";
import { uBig } from "./schema.js";
import {
  spendKernel, scopeKernel, replicationKernel, silenceKernel,
  aggregateScope, aggregateReplication, checkedSum,
} from "./detectors.js";
import type {
  Accepted, Config, Decision, Hash, Manifest, Quality, Result, ResultBody,
  SourceCut, SourceID, SubjectID, U,
} from "./types.js";

/**
 * Deterministic window evaluation (§4.2–4.3): builds the Manifest fields a
 * fleet computes at closure and the full ordered result set. Pure: the caller
 * supplies committed inputs and cut state; nothing here touches a clock, the
 * network, a filesystem, or a random source.
 */

export interface SourceClose {
  source: SourceID;
  headSeq: U;
  headHash: Hash;
  state: SourceCut["state"];
  activated_ms: U;
  last_received_ms: U | null;
  last_input: Hash | null;
  complete: boolean;
  pending: number;
  revoked: boolean;
}

export interface WindowInput {
  fleet: string;
  configHash: Hash;
  config: Config;
  start_ms: U;
  end_ms: U;
  through_index: U;
  /** Accepted records whose received_ms falls in [start,end), index order. */
  accepted: Accepted[];
  /** Prior same-epoch manifest hashes, chronological (≤5). */
  history: Hash[];
  /** Prior same-epoch windows (≤5), chronological, for spend history. */
  historyWindows: { manifest: Manifest; accepted: Accepted[] }[];
  /** Closure-time cuts for every enabled source, sorted by source id. */
  closes: SourceClose[];
  /** Effective revocation overlay at closure (monotonic union). */
  revoked_keys: Set<string>;
}

const dec = (status: Decision["status"], reason: Decision["reason"], value: string | null = null, limit: string | null = null): Decision =>
  ({ status, reason, value, limit });

export function computeCuts(closes: SourceClose[]): SourceCut[] {
  return closes.map((c) => ({
    source: c.source,
    head: { seq: c.headSeq, hash: c.headHash },
    state: c.state,
    activated_ms: c.activated_ms,
    last_received_ms: c.last_received_ms,
    last_input: c.last_input,
    complete: c.complete,
  }));
}

export function computeQuality(closes: SourceClose[], accepted: Accepted[], revoked: Set<string>): Quality {
  for (const c of closes) {
    if (c.state === "FORKED" || revoked.has(c.source)) return "DEGRADED";
  }
  const anyLate = accepted.some((a) => a.late && a.entry.body.observation.kind !== "signal");
  for (const c of closes) {
    if (c.state === "GAPPED" || c.pending > 0 || !c.complete) return "INCOMPLETE";
  }
  if (anyLate) return "INCOMPLETE";
  return "COMPLETE";
}

export function manifestOf(w: WindowInput): { manifest: Manifest; hash: Hash } {
  const manifest: Manifest = {
    v: 1,
    fleet: w.fleet,
    config: w.configHash,
    start_ms: w.start_ms,
    end_ms: w.end_ms,
    through_index: w.through_index,
    inputs: w.accepted.map((a) => a.entry.hash),
    history: w.history.slice(-5),
    cuts: computeCuts(w.closes),
    quality: computeQuality(w.closes, w.accepted, effectiveRevoked(w)),
  };
  return { manifest, hash: D("WEATHER-MANIFEST/1", manifest) };
}

function effectiveRevoked(w: WindowInput): Set<string> {
  // Quality degrades when a source's *registered key* is revoked (§4.2); the
  // caller's revoked set carries key_ids, so translate through the config.
  const srcKeys = new Map<string, string>();
  for (const s of w.config.sources) srcKeys.set(s.pin.key_id, s.id);
  const out = new Set<string>();
  for (const k of w.revoked_keys) {
    const src = srcKeys.get(k);
    if (src) out.add(src);
  }
  return out;
}

/** Per-source coverage failure used by scope/replication (§4.3): FORKED,
 * revoked key, false coverage flag, or pending entries at closure. The GAPPED
 * state implies pending>0 (a source becomes GAPPED exactly when a forward
 * sequence is buffered), which keeps offline replay equivalent. */
function sourceCoverageFails(c: SourceClose, revokedKeyIds: Set<string>, keyId: string): boolean {
  return c.state === "FORKED" || c.state === "GAPPED" || revokedKeyIds.has(keyId) || !c.complete || c.pending > 0;
}

/** True when a source contributed a contiguous nonsignal observation in the window. */
function hasNonsignal(accepted: Accepted[], source: SourceID): boolean {
  return accepted.some((a) => a.entry.body.source === source && a.entry.body.observation.kind !== "signal");
}

/** Recompute a history window's spend decision status for the history rule. */
function priorSpendStatus(hw: { manifest: Manifest; accepted: Accepted[] }, config: Config, revokedKeyIds: Set<string>): "HIT_CLEAR" | "UNKNOWN" {
  const meters = config.sources.filter((s) => s.enabled && s.meter);
  if (meters.length === 0) return "UNKNOWN"; // EVIDENCE_MISSING
  for (const m of meters) {
    const cut = hw.manifest.cuts.find((c) => c.source === m.id);
    if (!cut) return "UNKNOWN";
    const fails =
      cut.state === "FORKED" ||
      revokedKeyIds.has(m.pin.key_id) ||
      !cut.complete ||
      !hw.accepted.some((a) => a.entry.body.source === m.id && a.entry.body.observation.kind !== "signal");
    if (fails) return "UNKNOWN";
  }
  const sum = checkedSum(
    hw.accepted
      .filter((a) => a.counted && a.entry.body.observation.kind === "spend")
      .map((a) => (a.entry.body.observation as { delta: string }).delta),
  );
  if (sum === null) return "UNKNOWN"; // ARITHMETIC_OVERFLOW
  if (hw.manifest.history.length < 5) return "UNKNOWN"; // BASELINE_WARMUP
  return "HIT_CLEAR";
}

function priorSpendTotal(hw: { manifest: Manifest; accepted: Accepted[] }): bigint {
  const s = checkedSum(
    hw.accepted
      .filter((a) => a.counted && a.entry.body.observation.kind === "spend")
      .map((a) => (a.entry.body.observation as { delta: string }).delta),
  );
  return s ?? 0n;
}

export interface WindowResult {
  manifest: Manifest;
  manifestHash: Hash;
  results: Result[];
  hitResults: Result[];
}

/** Full deterministic window evaluation: manifest + ordered results. */
export function evaluateWindow(w: WindowInput): WindowResult {
  const { manifest, hash: manifestHash } = manifestOf(w);
  const results = evaluateResults(w, manifest, manifestHash);
  return { manifest, manifestHash, results, hitResults: results.filter((r) => r.body.decision.status === "HIT") };
}

/** The ordered result set for an already-built manifest (also used by replay). */
export function evaluateResults(w: WindowInput, manifest: Manifest, manifestHash: Hash): Result[] {
  const cfg = w.config;
  const revokedKeyIds = w.revoked_keys;
  const cutBySource = new Map(manifest.cuts.map((c) => [c.source, c]));
  const closeBySource = new Map(w.closes.map((c) => [c.source, c]));
  const out: Result[] = [];

  const mk = (detector: ResultBody["detector"], target: string, decision: Decision, evidence: Hash[]): Result => {
    const body: ResultBody = {
      v: 1, fleet: w.fleet, config: w.configHash, manifest: manifestHash,
      detector, target, decision, evidence: [...new Set(evidence)].sort(),
    };
    return { body, hash: D("WEATHER-RESULT/1", body) };
  };

  // ---- spend_spike/1 → fleet target ------------------------------------
  {
    const meters = cfg.sources.filter((s) => s.enabled && s.meter);
    let d: Decision;
    let evidence: Hash[] = [];
    const spendEntries = w.accepted.filter((a) => a.entry.body.observation.kind === "spend" && a.counted);
    evidence = spendEntries.map((a) => a.entry.hash);
    const deltas = spendEntries.map((a) => (a.entry.body.observation as { delta: string }).delta);
    const sum = checkedSum(deltas);
    if (meters.length === 0) {
      d = dec("UNKNOWN", "EVIDENCE_MISSING");
      evidence = [];
    } else {
      const cRep = sum === null ? null : sum.toString();
      let covFail = false;
      for (const m of meters) {
        const cut = cutBySource.get(m.id);
        const cutState = cut?.state ?? "EMPTY";
        const complete = cut?.complete ?? true;
        if (
          cutState === "FORKED" || revokedKeyIds.has(m.pin.key_id) || !complete ||
          !hasNonsignal(w.accepted, m.id)
        ) covFail = true;
      }
      if (covFail) {
        d = dec("UNKNOWN", "COVERAGE_INCOMPLETE", cRep, null);
      } else if (sum === null) {
        d = dec("UNKNOWN", "ARITHMETIC_OVERFLOW", null, null);
      } else if (w.historyWindows.length < 5) {
        d = dec("UNKNOWN", "BASELINE_WARMUP", cRep, null);
      } else if (w.historyWindows.some((hw) => priorSpendStatus(hw, cfg, revokedKeyIds) === "UNKNOWN")) {
        d = dec("UNKNOWN", "COVERAGE_INCOMPLETE", cRep, null);
      } else {
        const priors = w.historyWindows.map(priorSpendTotal);
        const sorted = [...priors].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
        const m = sorted[2]!;
        const b = m > 100000n ? m : 100000n;
        const t0 = 3n * b;
        const t = t0 > 1000000n ? t0 : 1000000n;
        const limit = t > uBig("9223372036854775807") ? null : t.toString();
        d = sum >= t
          ? dec("HIT", "SPEND_SPIKE", cRep, limit)
          : dec("CLEAR", "BELOW_THRESHOLD", cRep, limit);
      }
    }
    out.push(mk("spend_spike/1", w.fleet, d, evidence));
  }

  // ---- scope_drift/1 and replication_anomaly/1 → per subject ------------
  const subjectsWithScope = new Map<SubjectID, { d: Decision; index: bigint; hash: Hash }[]>();
  const subjectsWithRep = new Map<SubjectID, { d: Decision; index: bigint; hash: Hash }[]>();
  const subjCfg = new Map(cfg.subjects.map((s) => [s.id, s]));
  const subjectSources = (sub: SubjectID) =>
    cfg.sources.filter((s) => s.enabled && s.subjects.includes(sub));

  for (const a of w.accepted) {
    const obs = a.entry.body.observation;
    if (obs.kind === "scope") {
      const sc = subjCfg.get(obs.subject);
      if (!sc) continue;
      const d = scopeKernel(sc.policies, sc.scopes, obs.policy_hash, obs.scope_hash, obs.reported_violation);
      const l = subjectsWithScope.get(obs.subject) ?? [];
      l.push({ d, index: uBig(a.index), hash: a.entry.hash });
      subjectsWithScope.set(obs.subject, l);
    } else if (obs.kind === "replication") {
      const sc = subjCfg.get(obs.subject);
      if (!sc) continue;
      const d = replicationKernel(obs.processes, obs.threads, obs.declared_processes, sc.max_processes, sc.max_threads);
      const l = subjectsWithRep.get(obs.subject) ?? [];
      l.push({ d, index: uBig(a.index), hash: a.entry.hash });
      subjectsWithRep.set(obs.subject, l);
    }
  }

  const relevantCoverageFails = (sub: SubjectID): boolean =>
    subjectSources(sub).some((s) => {
      const close = closeBySource.get(s.id);
      const cut = cutBySource.get(s.id);
      return sourceCoverageFails(
        close ?? { source: s.id, headSeq: "0", headHash: "0".repeat(64), state: cut?.state ?? "EMPTY", activated_ms: cut?.activated_ms ?? cfg.effective_ms, last_received_ms: null, last_input: null, complete: cut?.complete ?? true, pending: 0, revoked: false },
        revokedKeyIds,
        s.pin.key_id,
      );
    });

  for (const [sub, ds] of subjectsWithScope) {
    let d: Decision;
    if (relevantCoverageFails(sub)) {
      d = dec("UNKNOWN", "COVERAGE_INCOMPLETE");
    } else {
      d = aggregateScope(ds.map((x) => ({ d: x.d, index: x.index })));
    }
    out.push(mk("scope_drift/1", sub, d, ds.map((x) => x.hash)));
  }
  for (const [sub, ds] of subjectsWithRep) {
    let d: Decision;
    if (relevantCoverageFails(sub)) {
      d = dec("UNKNOWN", "COVERAGE_INCOMPLETE");
    } else {
      d = aggregateReplication(ds.map((x) => ({ d: x.d, index: x.index })));
    }
    out.push(mk("replication_anomaly/1", sub, d, ds.map((x) => x.hash)));
  }

  // ---- stream_silence/1 → per enabled source ----------------------------
  for (const cut of manifest.cuts) {
    const srcCfg = cfg.sources.find((s) => s.id === cut.source);
    const revoked = srcCfg ? revokedKeyIds.has(srcCfg.pin.key_id) : false;
    let d: Decision;
    if (revoked) {
      d = dec("UNKNOWN", "COVERAGE_INCOMPLETE");
    } else {
      const basis = cut.last_received_ms ?? cut.activated_ms;
      d = silenceKernel(cut.state, basis, manifest.end_ms);
    }
    // The liveness witness is the cut's last_input hash (§4.2).
    const ev = cut.last_input !== null ? [cut.last_input] : [];
    out.push(mk("stream_silence/1", cut.source, d, ev));
  }

  out.sort((a, b) => {
    if (a.body.detector !== b.body.detector) return a.body.detector < b.body.detector ? -1 : 1;
    return a.body.target < b.body.target ? -1 : a.body.target > b.body.target ? 1 : 0;
  });
  return out;
}
