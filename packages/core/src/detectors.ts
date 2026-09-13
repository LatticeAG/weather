import type { Decision, Quality, SourceState } from "./types.js";
import { uBig } from "./schema.js";

/**
 * The four deterministic detectors, §4.3. All arithmetic on U values is
 * checked via BigInt; threshold multiplication uses wider intermediates.
 */

export const U_MAX = 9223372036854775807n;
const BASELINE_FLOOR = 100000n;
const SPEND_MIN = 1000000n;
const SPEND_MULT = 3n;
const SILENCE_MS = 120000n;

const dec = (status: Decision["status"], reason: Decision["reason"], value: string | null, limit: string | null): Decision =>
  ({ status, reason, value, limit });

/** Checked sum; null when the running total exceeds U (§4.1). */
export function checkedSum(deltas: string[]): bigint | null {
  let s = 0n;
  for (const d of deltas) {
    s += uBig(d);
    if (s > U_MAX) return null;
  }
  return s;
}

/**
 * spend_spike/1 kernel (§4.3, §13 op "spend"): the kernel's `quality`
 * argument collapses current coverage and prior-window completeness into one
 * flag; the service computes each separately.
 */
export function spendKernel(prior: string[], current: string, quality: Quality): Decision {
  const c = uBig(current);
  if (quality !== "COMPLETE") return dec("UNKNOWN", "COVERAGE_INCOMPLETE", current, null);
  if (prior.length < 5) return dec("UNKNOWN", "BASELINE_WARMUP", current, null);
  const sorted = prior.map(uBig).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const m = sorted[2]!;
  const b = m > BASELINE_FLOOR ? m : BASELINE_FLOOR;
  const t0 = SPEND_MULT * b;
  const t = t0 > SPEND_MIN ? t0 : SPEND_MIN;
  const limit = t > U_MAX ? null : t.toString();
  if (c >= t) return dec("HIT", "SPEND_SPIKE", current, limit);
  return dec("CLEAR", "BELOW_THRESHOLD", current, limit);
}

/** spend_sum kernel: checked aggregation only (TV-W--15). */
export function spendSum(deltas: string[]): Decision {
  const s = checkedSum(deltas);
  if (s === null) return dec("UNKNOWN", "ARITHMETIC_OVERFLOW", null, null);
  return dec("CLEAR", "BELOW_THRESHOLD", s.toString(), null);
}

/** scope_drift/1 kernel over one observation (§4.3). */
export function scopeKernel(
  policies: string[],
  scopes: string[],
  policy: string | null,
  scope: string | null,
  reported_violation: boolean,
): Decision {
  if (reported_violation) return dec("HIT", "DRIFT_REPORTED", null, null);
  if (policy !== null && !policies.includes(policy)) return dec("HIT", "POLICY_DRIFT", null, null);
  if (scope !== null && !scopes.includes(scope)) return dec("HIT", "SCOPE_DRIFT", null, null);
  if (policy !== null || scope !== null) return dec("CLEAR", "SCOPE_MATCH", null, null);
  return dec("UNKNOWN", "EVIDENCE_MISSING", null, null);
}

const STATUS_RANK: Record<Decision["status"], number> = { HIT: 0, UNKNOWN: 1, CLEAR: 2, SIGNAL: 3 };
const SCOPE_HIT_RANK: Partial<Record<Decision["reason"], number>> = { DRIFT_REPORTED: 0, POLICY_DRIFT: 1, SCOPE_DRIFT: 2 };
const REP_HIT_RANK: Partial<Record<Decision["reason"], number>> = { PROCESS_EXCESS: 0, THREAD_EXCESS: 1, DECLARED_MISMATCH: 2 };

/** Aggregate a subject's scope decisions: HIT before UNKNOWN before CLEAR; HIT reason priority §4.3. */
export function aggregateScope(ds: { d: Decision; index: bigint }[]): Decision {
  let best = ds[0]!;
  for (const c of ds.slice(1)) {
    const r = STATUS_RANK[c.d.status] - STATUS_RANK[best.d.status];
    if (r < 0) { best = c; continue; }
    if (r > 0) continue;
    if (c.d.status === "HIT") {
      const pr = (SCOPE_HIT_RANK[c.d.reason] ?? 9) - (SCOPE_HIT_RANK[best.d.reason] ?? 9);
      if (pr < 0 || (pr === 0 && c.index < best.index)) best = c;
    } else if (c.index < best.index) best = c;
  }
  return best.d;
}

/** Aggregate a subject's replication decisions: status, then reason priority, then lowest input index. */
export function aggregateReplication(ds: { d: Decision; index: bigint }[]): Decision {
  let best = ds[0]!;
  for (const c of ds.slice(1)) {
    const r = STATUS_RANK[c.d.status] - STATUS_RANK[best.d.status];
    if (r < 0) { best = c; continue; }
    if (r > 0) continue;
    if (c.d.status === "HIT") {
      const pr = (REP_HIT_RANK[c.d.reason] ?? 9) - (REP_HIT_RANK[best.d.reason] ?? 9);
      if (pr < 0 || (pr === 0 && c.index < best.index)) best = c;
    } else if (c.index < best.index) best = c;
  }
  return best.d;
}

/** replication_anomaly/1 kernel over one observation (§4.3). */
export function replicationKernel(
  processes: string | null,
  threads: string | null,
  declared_processes: string | null,
  max_processes: string,
  max_threads: string,
): Decision {
  if (processes !== null && uBig(processes) > uBig(max_processes)) {
    return dec("HIT", "PROCESS_EXCESS", processes, max_processes);
  }
  if (threads !== null && uBig(threads) > uBig(max_threads)) {
    return dec("HIT", "THREAD_EXCESS", threads, max_threads);
  }
  if (declared_processes !== null && processes !== null && uBig(declared_processes) !== uBig(processes)) {
    return dec("HIT", "DECLARED_MISMATCH", processes, declared_processes);
  }
  if (processes === null && threads === null) return dec("UNKNOWN", "EVIDENCE_MISSING", null, null);
  if (declared_processes !== null && processes === null) return dec("UNKNOWN", "EVIDENCE_MISSING", null, null);
  return dec(
    "CLEAR", "INVENTORY_MATCH",
    processes !== null ? processes : threads,
    processes !== null ? max_processes : max_threads,
  );
}

/**
 * stream_silence/1 kernel (§4.3). `basis_ms` is the source cut's
 * last_received_ms, or activated_ms when null; `state` is the cut's state.
 * FORKED (or service-side revoked-key overlay) yields
 * UNKNOWN/COVERAGE_INCOMPLETE; TERMINAL/RETIRED yields CLEAR/SOURCE_TERMINAL.
 */
export function silenceKernel(state: SourceState, basis_ms: string, end_ms: string): Decision {
  if (state === "TERMINAL" || state === "RETIRED") return dec("CLEAR", "SOURCE_TERMINAL", null, null);
  if (state === "FORKED") return dec("UNKNOWN", "COVERAGE_INCOMPLETE", null, null);
  const age = uBig(end_ms) - uBig(basis_ms);
  if (age >= SILENCE_MS) return dec("HIT", "STREAM_SILENT", age.toString(), SILENCE_MS.toString());
  return dec("CLEAR", "STREAM_RECENT", age.toString(), SILENCE_MS.toString());
}

/** On-demand signal annotation (§4.3): never persisted, never pages. */
export function signalAnnotation(): Decision {
  return dec("SIGNAL", "SIGNAL_ONLY", null, null);
}
