import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  D, ZERO, jstr, parseText, b64uEncode, signDetached,
} from "@latticeag/weather-core";
import type {
  CollectorCursor, Hash, Head, Pin, PrivateKeyFile, SourceEntry, SourceID,
  SubjectID, Observation, FleetID,
} from "@latticeag/weather-core";

/**
 * Local collector adapters (§2.2). They read *files* produced by the native
 * system — a `trellis-export/1` NDJSON stream or a `vislineage-bundle/1`
 * object — verify what can be verified locally, project each retained native
 * record deterministically, sign the resulting SourceEntry chain under the
 * operator's producer key, and return NDJSON plus an updated durable cursor.
 * No live provider API access exists here by design.
 */

export interface CollectorPins {
  fleet: FleetID;
  source: SourceID;
  key: PrivateKeyFile; // producer key; key_id must equal the source pin key_id
  /** Trellis: agent_id → Weather subject. VisLineage: "workspace|source|ns|subject" → subject. */
  subject_map: Record<string, SubjectID>;
}

interface TrellisCheckpoint {
  body: {
    v: 1; checkpoint_id: string; host_id: string; run_id: string;
    key_id: string; head: Head; state: string;
    audit: "COMPLETE_PREFIX" | "GAP"; wall_time: string;
  };
  hash: Hash; sig: string;
}

interface TrellisEvent {
  body: {
    v: 1; run_id: string; seq: string; prev: Hash; kind: string; data: unknown;
  };
  hash: Hash; sig: string;
}

const sha = (b: Uint8Array | string) =>
  createHash("sha256").update(typeof b === "string" ? Buffer.from(b, "utf8") : b).digest("hex");

function nativeRef(parts: (string | number | bigint)[]): string {
  return parts.join("/");
}

function emitEntry(
  pins: CollectorPins, cursor: CollectorCursor, ordinal: number,
  ref: string, artifact: Hash, verification: "VERIFIED_AT_PIN" | "ASSERTED",
  profile: "trellis-export/1" | "vislineage-export/1",
  obs: Observation, observedMs: bigint,
): SourceEntry {
  const seq = (BigInt(cursor.head.seq) + 1n).toString();
  const body = {
    v: 1 as const, fleet: pins.fleet, source: pins.source, seq,
    prev: cursor.head.hash, observed_ms: observedMs.toString(),
    native: { profile, native_ref: ref, native_artifact: artifact, verification },
    observation: obs, key_id: pins.key.key_id,
  };
  const hash = D("WEATHER-SOURCE/1", body);
  const sig = b64uEncode(signDetached(Buffer.from(pins.key.seed, "base64url"), "WEATHER-SOURCE-SIGN/1", hash));
  const entry: SourceEntry = { body, hash, sig };
  cursor.head = { seq, hash };
  cursor.pending_entries.push(entry);
  void ordinal;
  return entry;
}

function subjectFor(pins: CollectorPins, key: string): SubjectID | null {
  return pins.subject_map[key] ?? null;
}

/**
 * collect_trellis(export_path, pins, cursor): consume a trellis-export/1
 * NDJSON file — `{record:"header",checkpoint,policy}` then
 * `{record:"entry",entry}` lines — validate the checkpoint pin and the
 * chain prefix, then project §2.2: RunCreated→scope, InventoryObserved→
 * replication, StopLatched(SCOPE_MISMATCH|REPLICATION_MISMATCH)→reported
 * violation scope, RunStopped/RunRejected→terminal, native GAP→coverage
 * false, other retained entries→pulse.
 */
export function collect_trellis(
  exportPath: string, pins: CollectorPins, cursor: CollectorCursor,
): { ndjson: string; cursor: CollectorCursor } {
  const text = readFileSync(exportPath, "utf8");
  const lines = text.split("\n").filter((l) => l.length > 0);
  if (lines.length === 0) throw new Error("trellis export: empty file");
  const header = parseText(lines[0]!) as { record: string; v: number; format: string; checkpoint: TrellisCheckpoint; policy?: unknown };
  if (header.record !== "header" || header.format !== "trellis-export/1") {
    throw new Error("trellis export: bad header");
  }
  const cp = header.checkpoint;
  const cpHash = D("TRELLIS-CHECKPOINT/1", cp.body);
  const checkpointOk = cpHash === cp.hash && cp.body.audit === "COMPLETE_PREFIX";
  const headSeq = BigInt(cp.body.head.seq);

  const entries: { raw: string; entry: TrellisEvent }[] = [];
  let prev = ZERO;
  let ok = checkpointOk;
  for (let i = 1; i < lines.length; i++) {
    const rec = parseText(lines[i]!) as { record: string; entry: TrellisEvent };
    if (rec.record !== "entry") throw new Error(`trellis export: bad record at line ${i + 1}`);
    const e = rec.entry;
    const h = D("TRELLIS-ENTRY/1", e.body);
    if (h !== e.hash || e.body.prev !== prev || BigInt(e.body.seq) !== BigInt(i)) ok = false;
    if (BigInt(e.body.seq) > headSeq) ok = false;
    prev = e.hash;
    entries.push({ raw: lines[i]!, entry: e });
  }
  const lastHash = entries.length > 0 ? entries[entries.length - 1]!.entry.hash : ZERO;
  if (BigInt(entries.length) < headSeq || lastHash !== cp.body.head.hash) ok = false;

  const verification = ok ? "VERIFIED_AT_PIN" as const : "ASSERTED" as const;
  const runId = cp.body.run_id;
  const hostId = cp.body.host_id;
  if (!ok) {
    // Unverifiable upstream data is preserved only as a coverage=false record
    // on the first new ordinal; native bytes are never silently trusted.
    emitEntry(pins, cursor, 0, nativeRef([hostId, runId, "gap"]), sha(lines[0]!), "ASSERTED", "trellis-export/1",
      { kind: "coverage", complete: false }, BigInt(Date.now()));
    return { ndjson: cursor.pending_entries.map((e) => jstr(e)).join("\n") + "\n", cursor };
  }

  let ordinal = Number(cursor.native_frontier === "" ? 0 : cursor.native_frontier);
  const now = BigInt(Date.now());
  for (const { raw, entry } of entries) {
    ordinal++;
    const e = entry.body;
    const artifact = sha(raw);
    const ref = nativeRef([hostId, runId, e.seq]);
    const data = e.data as Record<string, unknown>;
    const agent = (data["agent_id"] as string | undefined) ?? runId;
    const subject = subjectFor(pins, agent);
    switch (e.kind) {
      case "RunCreated":
        if (subject) {
          emitEntry(pins, cursor, ordinal, ref, artifact, verification, "trellis-export/1",
            { kind: "scope", subject, policy_hash: data["policy_hash"] as Hash, scope_hash: null, reported_violation: false }, now);
        } else {
          emitEntry(pins, cursor, ordinal, ref, artifact, verification, "trellis-export/1", { kind: "pulse" }, now);
        }
        break;
      case "InventoryObserved": {
        const inv = data["inventory"] as { tgid?: unknown[]; threads?: string } | undefined;
        if (subject) {
          emitEntry(pins, cursor, ordinal, ref, artifact, verification, "trellis-export/1",
            {
              kind: "replication", subject,
              processes: String(inv?.tgid ? new Set(inv.tgid).size : 0),
              threads: String(inv?.threads ?? "0"),
              declared_processes: null,
            }, now);
        } else {
          emitEntry(pins, cursor, ordinal, ref, artifact, verification, "trellis-export/1", { kind: "pulse" }, now);
        }
        break;
      }
      case "StopLatched": {
        const reason = data["reason"] as string;
        if (reason === "SCOPE_MISMATCH" && subject) {
          emitEntry(pins, cursor, ordinal, ref, artifact, verification, "trellis-export/1",
            { kind: "scope", subject, policy_hash: null, scope_hash: null, reported_violation: true }, now);
        } else if (reason === "REPLICATION_MISMATCH" && subject) {
          emitEntry(pins, cursor, ordinal, ref, artifact, verification, "trellis-export/1",
            { kind: "scope", subject, policy_hash: null, scope_hash: null, reported_violation: true }, now);
        } else {
          emitEntry(pins, cursor, ordinal, ref, artifact, verification, "trellis-export/1", { kind: "pulse" }, now);
        }
        break;
      }
      case "RunStopped": case "RunRejected":
        emitEntry(pins, cursor, ordinal, ref, artifact, verification, "trellis-export/1",
          { kind: "terminal" }, now);
        break;
      case "Gap":
        emitEntry(pins, cursor, ordinal, ref, artifact, verification, "trellis-export/1",
          { kind: "coverage", complete: false }, now);
        break;
      default:
        emitEntry(pins, cursor, ordinal, ref, artifact, verification, "trellis-export/1", { kind: "pulse" }, now);
    }
  }
  cursor.native_frontier = String(ordinal);
  return { ndjson: cursor.pending_entries.map((e) => jstr(e)).join("\n") + "\n", cursor };
}

/** vislineage-bundle/1 structural + inventory verification (§2.2). */
export function collect_vislineage(
  bundlePath: string, pins: CollectorPins, cursor: CollectorCursor,
): { ndjson: string; cursor: CollectorCursor } {
  const raw = readFileSync(bundlePath, "utf8");
  const bundle = parseText(raw) as {
    body: {
      v: 1; format: string; workspace: string; trace: string; revision: string;
      inventory: { kind: string; digest: Hash; bytes: string }[];
      [k: string]: unknown;
    };
    hash: Hash;
    steps?: { body: Record<string, unknown>; hash: Hash }[];
    origins?: { body: Record<string, unknown>; hash: Hash }[];
    audit?: { body: Record<string, unknown>; hash: Hash }[];
    attachments?: unknown[];
  };
  if (bundle.body.format !== "vislineage-bundle/1" || bundle.body.v !== 1) {
    throw new Error("vislineage bundle: bad format");
  }
  const bundleOk = D("VL-BUNDLE/1", bundle.body) === bundle.hash;
  // Inventory: every supplied object exactly once, sorted by (kind,digest),
  // digest = H(J(envelope)), bytes = J(envelope).length.
  const objects: { kind: string; digest: Hash; bytes: bigint }[] = [];
  for (const [kind, arr] of [["step", bundle.steps ?? []], ["origin", bundle.origins ?? []], ["audit", bundle.audit ?? []]] as const) {
    for (const env of arr) {
      const j = jstr(env);
      objects.push({ kind, digest: sha(j), bytes: BigInt(j.length) });
    }
  }
  const inventoryOk =
    bundleOk &&
    objects.length === bundle.body.inventory.length &&
    objects.every((o, i) => {
      const inv = bundle.body.inventory[i]!;
      return inv.kind === o.kind && inv.digest === o.digest && inv.bytes === o.bytes.toString();
    });
  const verification = inventoryOk ? "VERIFIED_AT_PIN" as const : "ASSERTED" as const;

  let ordinal = Number(cursor.native_frontier === "" ? 0 : cursor.native_frontier);
  const now = BigInt(Date.now());
  if (!inventoryOk) {
    emitEntry(pins, cursor, ordinal, `vislineage/${bundle.body.workspace}/${bundle.body.trace}/${bundle.body.revision}`,
      bundle.hash, "ASSERTED", "vislineage-export/1",
      { kind: "coverage", complete: false }, now);
    return { ndjson: cursor.pending_entries.map((e) => jstr(e)).join("\n") + "\n", cursor };
  }

  for (const step of bundle.steps ?? []) {
    ordinal++;
    const b = step.body;
    const agent = b["agent"] as { namespace?: string; subject?: string } | null;
    const subject = agent
      ? subjectFor(pins, `${bundle.body.workspace}|${b["source"]}|${agent.namespace ?? ""}|${agent.subject ?? ""}`)
      : null;
    const ref = `vislineage/${bundle.body.workspace}/${bundle.body.trace}/${bundle.body.revision}/${step.hash}`;
    if (!subject) {
      emitEntry(pins, cursor, ordinal, ref, sha(jstr(step)), verification, "vislineage-export/1", { kind: "pulse" }, now);
      continue;
    }
    const policy = (b["policy"] as Hash | null) ?? null;
    const offers = (b["offers"] as { scope?: Hash }[] | undefined) ?? [];
    const accept = (b["accept"] as { scope?: Hash } | null | undefined) ?? null;
    if (policy !== null) {
      emitEntry(pins, cursor, ordinal, ref, sha(jstr(step)), verification, "vislineage-export/1",
        { kind: "scope", subject, policy_hash: policy, scope_hash: null, reported_violation: false }, now);
    }
    for (const o of offers) {
      if (o.scope) {
        emitEntry(pins, cursor, ordinal, ref, sha(jstr(step)), verification, "vislineage-export/1",
          { kind: "scope", subject, policy_hash: null, scope_hash: o.scope, reported_violation: false }, now);
      }
    }
    if (accept?.scope) {
      emitEntry(pins, cursor, ordinal, ref, sha(jstr(step)), verification, "vislineage-export/1",
        { kind: "scope", subject, policy_hash: null, scope_hash: accept.scope, reported_violation: false }, now);
    }
    if (policy === null && offers.every((o) => !o.scope) && !accept?.scope) {
      emitEntry(pins, cursor, ordinal, ref, sha(jstr(step)), verification, "vislineage-export/1", { kind: "pulse" }, now);
    }
  }
  cursor.native_frontier = String(ordinal);
  return { ndjson: cursor.pending_entries.map((e) => jstr(e)).join("\n") + "\n", cursor };
}

export function newCursor(fleet: FleetID, source: SourceID): CollectorCursor {
  return { v: 1, fleet, source, native_frontier: "", head: { seq: "0", hash: ZERO }, pending_entries: [] };
}
