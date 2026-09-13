import { runKernel } from "./kernels.js";
import { WError } from "./errors.js";
import { isU } from "./schema.js";
import type { EvalConfig, EvalReport, EvalSuite, EvalRate, Fraction, Interval, LabeledUnit } from "./types.js";

/**
 * §12 evaluation math: exact rational rates and 95% Wilson intervals with
 * z=1.959963984540054, clamped to [0,1], half-even six-decimal presentation.
 */

const Z = 1.959963984540054;

/** Round half-even to six decimals; returns the fixed-decimal string. */
export function round6(x: number): string {
  const scaled = x * 1e6;
  const fl = Math.floor(scaled);
  const diff = scaled - fl;
  let n: number;
  if (diff > 0.5) n = fl + 1;
  else if (diff < 0.5) n = fl;
  else n = fl % 2 === 0 ? fl : fl + 1;
  return (n / 1e6).toFixed(6);
}

export function wilson95(k: bigint, n: bigint): Interval {
  if (n === 0n) return null;
  const kd = Number(k);
  const nd = Number(n);
  const p = kd / nd;
  const z2 = Z * Z;
  const denom = 1 + z2 / nd;
  const center = (p + z2 / (2 * nd)) / denom;
  const half = (Z * Math.sqrt((p * (1 - p)) / nd + z2 / (4 * nd * nd))) / denom;
  const clamp = (x: number) => Math.min(1, Math.max(0, x));
  return { low: round6(clamp(center - half)), high: round6(clamp(center + half)) };
}

export function fracRate(n: bigint, d: bigint): EvalRate {
  if (d === 0n) return { fraction: null, wilson95: null };
  return { fraction: { n: n.toString(), d: d.toString() }, wilson95: wilson95(n, d) };
}

export interface VectorDef {
  id: string;
  input: Record<string, unknown>;
  expected: unknown;
}

export interface Counts9 {
  tp: bigint; fp: bigint; fn: bigint; tn: bigint;
  unknown_positive: bigint; unknown_negative: bigint;
  signals: bigint; corroborated: bigint; delivered: bigint;
}

const zeroCounts = (): Counts9 => ({
  tp: 0n, fp: 0n, fn: 0n, tn: 0n, unknown_positive: 0n, unknown_negative: 0n,
  signals: 0n, corroborated: 0n, delivered: 0n,
});

function classify(decisionStatus: string, positive: boolean, c: Counts9): void {
  if (decisionStatus === "HIT") { if (positive) c.tp++; else c.fp++; }
  else if (decisionStatus === "CLEAR") { if (positive) c.fn++; else c.tn++; }
  else if (decisionStatus === "UNKNOWN") { if (positive) c.unknown_positive++; else c.unknown_negative++; }
  else if (decisionStatus === "SIGNAL") c.signals++;
}

function deepEqual(a: unknown, b: unknown): boolean {
  return canonicalEq(a, b);
}

function canonicalEq(a: unknown, b: unknown): boolean {
  // structural equality over parsed JSON values
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => canonicalEq(x, b[i]));
  }
  if (typeof a === "object") {
    const ka = Object.keys(a), kb = Object.keys(b as object);
    if (ka.length !== kb.length) return false;
    return ka.every((k) =>
      Object.prototype.hasOwnProperty.call(b, k) &&
      canonicalEq((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
  }
  return false;
}

const LIMITATIONS = ["SYNTHETIC_SCOPE_ONLY", "SOURCE_ASSERTIONS_NOT_TRUTH", "COT_NOT_PROOF"] as const;

/**
 * eval.run (§12): runs the fixed 60-vector suite per implementation plus any
 * labeled units drawn from the pinned corpus, then emits one EvalReport per
 * implementation. Offline only; never uploads anything.
 */
export function evalRun(
  cfg: EvalConfig,
  vectors: VectorDef[],
  suite: EvalSuite | null,
  impl: "typescript" | "python",
  unitDecisions?: Map<string, { status: string }>,
): EvalReport {
  let passed = 0;
  for (const v of vectors) {
    const out = runKernel(v.input);
    if (deepEqual(out, v.expected)) passed++;
  }
  const counts = zeroCounts();
  if (suite) {
    if (suite.config.corpus_digest !== cfg.corpus_digest) {
      throw new WError("INVALID_INPUT", "suite corpus_digest != eval config corpus_digest");
    }
    for (const un of suite.units) {
      applyUnit(un, counts, vectors, unitDecisions);
    }
  }
  const N = counts.tp + counts.fp + counts.fn + counts.tn + counts.unknown_positive + counts.unknown_negative;
  return {
    v: 1,
    suite: "weather-conformance/1",
    corpus_digest: cfg.corpus_digest,
    pack_digest: cfg.pack_digest,
    seed: cfg.seed,
    implementation: impl,
    vectors: vectors.length,
    passed,
    counts: {
      tp: counts.tp.toString(), fp: counts.fp.toString(), fn: counts.fn.toString(),
      tn: counts.tn.toString(), unknown_positive: counts.unknown_positive.toString(),
      unknown_negative: counts.unknown_negative.toString(), signals: counts.signals.toString(),
      corroborated: counts.corroborated.toString(), delivered: counts.delivered.toString(),
    },
    precision: fracRate(counts.tp, counts.tp + counts.fp),
    recall: fracRate(counts.tp, counts.tp + counts.fn + counts.unknown_positive),
    false_positive_rate: fracRate(counts.fp, counts.fp + counts.tn + counts.unknown_negative),
    coverage: fracRate(counts.tp + counts.fp + counts.fn + counts.tn, N),
    limitations: [...LIMITATIONS],
  };
}

/**
 * Labeled units reference corpus scenarios by name: a unit naming a fixed
 * vector (e.g. "TV-W--09") evaluates that vector's kernel decision against the
 * unit's detector and label. UNKNOWN and SIGNAL are counted honestly and stay
 * in denominators.
 */
function applyUnit(
  un: LabeledUnit,
  counts: Counts9,
  vectors: VectorDef[],
  unitDecisions?: Map<string, { status: string }>,
): void {
  const ext = unitDecisions?.get(un.unit);
  if (ext) { classify(ext.status, un.positive, counts); return; }
  const vec = vectors.find((v) => v.id === un.unit);
  if (!vec) throw new WError("INVALID_INPUT", `eval unit ${un.unit} not in pinned corpus`);
  const out = runKernel(vec.input) as { status?: string };
  classify(typeof out.status === "string" ? out.status : "UNKNOWN", un.positive, counts);
}
