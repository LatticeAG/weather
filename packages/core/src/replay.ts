import { WError } from "./errors.js";
import { D } from "./hash.js";
import { uBig } from "./schema.js";
import { evaluateResults, type WindowInput, type SourceClose } from "./window.js";
import type { ReplayInput, ReplayOutput, Manifest } from "./types.js";

/**
 * core.replay (§6.3): pure predicate replay over a committed window. Validates
 * that supplied inputs equal the manifest's committed sets, recomputes prior
 * totals/coverage rather than trusting aggregates, and returns the manifest
 * hash plus the recomputed result set.
 */

function bad(msg: string): never {
  throw new WError("INVALID_INPUT", `replay: ${msg}`);
}

export function replay(input: ReplayInput): ReplayOutput {
  const m = input.manifest;
  const cfg = input.config.body;

  // manifest ↔ config binding
  if (input.config.hash !== m.config) bad("manifest.config != supplied config hash");
  if (cfg.fleet !== m.fleet) bad("config fleet != manifest fleet");
  if (cfg.pack !== "weather-core/1.0.0") throw new WError("PACK_UNAVAILABLE", `unsupported pack ${cfg.pack}`);

  // accepted == manifest.inputs, in order
  if (input.accepted.length !== m.inputs.length) bad("accepted length != manifest.inputs");
  const seenIdx = new Set<string>();
  let prevIdx: bigint | null = null;
  for (let i = 0; i < input.accepted.length; i++) {
    const a = input.accepted[i]!;
    if (a.entry.hash !== m.inputs[i]) bad(`accepted[${i}] hash != manifest.inputs[${i}]`);
    const idx = uBig(a.index);
    if (seenIdx.has(a.index)) bad("duplicate input index");
    seenIdx.add(a.index);
    if (prevIdx !== null && idx <= prevIdx) bad("accepted indexes not increasing");
    prevIdx = idx;
    const r = uBig(a.received_ms);
    if (r < uBig(m.start_ms) || r >= uBig(m.end_ms)) bad("accepted record outside window");
    if (uBig(a.index) > uBig(m.through_index)) bad("accepted index beyond through_index");
  }

  // history windows: contiguous, same-epoch, end at current start, ≤5
  if (input.history.length > 5) bad("more than five history windows");
  if (input.history.length !== m.history.length) bad("history window count != manifest.history");
  for (let i = 0; i < input.history.length; i++) {
    const hw = input.history[i]!;
    const hh = D("WEATHER-MANIFEST/1", hw.manifest);
    if (hh !== m.history[i]) bad(`history[${i}] hash mismatch`);
    if (hw.manifest.config !== m.config) bad("history window not same-epoch");
    if (hw.manifest.fleet !== m.fleet) bad("history window fleet mismatch");
    if (hw.accepted.length !== hw.manifest.inputs.length) bad("history accepted length mismatch");
    for (let j = 0; j < hw.accepted.length; j++) {
      if (hw.accepted[j]!.entry.hash !== hw.manifest.inputs[j]) bad("history accepted != its manifest.inputs");
      const r = uBig(hw.accepted[j]!.received_ms);
      if (r < uBig(hw.manifest.start_ms) || r >= uBig(hw.manifest.end_ms)) bad("history accepted outside its window");
    }
    if (i > 0 && uBig(hw.manifest.start_ms) !== uBig(input.history[i - 1]!.manifest.end_ms)) {
      bad("history windows not contiguous");
    }
  }
  if (input.history.length > 0) {
    const last = input.history[input.history.length - 1]!.manifest;
    if (uBig(last.end_ms) !== uBig(m.start_ms)) bad("history does not end at current start");
  }

  // last_inputs: exactly each nonnull cut.last_input, sorted by source;
  // source/hash/received_ms must match the cut; signal entries invalid.
  const cutsSorted = [...m.cuts].sort((a, b) => (a.source < b.source ? -1 : a.source > b.source ? 1 : 0));
  const expect: { source: string; hash: string; ms: string }[] = [];
  for (const c of cutsSorted) {
    if (c.last_input !== null) expect.push({ source: c.source, hash: c.last_input, ms: c.last_received_ms! });
  }
  const liSorted = [...input.last_inputs].sort((a, b) => {
    const s = a.entry.body.source < b.entry.body.source ? -1 : a.entry.body.source > b.entry.body.source ? 1 : 0;
    return s;
  });
  if (liSorted.length !== expect.length) bad("last_inputs length mismatch");
  for (let i = 0; i < expect.length; i++) {
    const a = liSorted[i]!;
    const e = expect[i]!;
    if (a.entry.body.source !== e.source) bad("last_inputs source mismatch");
    if (a.entry.hash !== e.hash) bad("last_inputs hash mismatch");
    if (a.received_ms !== e.ms) bad("last_inputs received_ms mismatch");
    if (a.entry.body.observation.kind === "signal") bad("signal entry as liveness witness");
  }

  // Reconstruct closure-time source state from the cuts.
  const pendingBySource = new Map<string, number>();
  const closes: SourceClose[] = m.cuts.map((c) => ({
    source: c.source,
    headSeq: c.head.seq,
    headHash: c.head.hash,
    state: c.state,
    activated_ms: c.activated_ms,
    last_received_ms: c.last_received_ms,
    last_input: c.last_input,
    complete: c.complete,
    pending: pendingBySource.get(c.source) ?? 0,
    revoked: false,
  }));

  const w: WindowInput = {
    fleet: m.fleet,
    configHash: m.config,
    config: cfg,
    start_ms: m.start_ms,
    end_ms: m.end_ms,
    through_index: m.through_index,
    accepted: input.accepted,
    history: m.history,
    historyWindows: input.history,
    closes,
    revoked_keys: new Set(cfg.revoked_keys),
  };

  const results = evaluateResults(w, m, D("WEATHER-MANIFEST/1", m));
  return { manifest: D("WEATHER-MANIFEST/1", m), results };
}

export type { Manifest };
