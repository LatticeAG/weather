// Collector adapter tests: synthetic trellis-export/1 and vislineage-bundle/1
// fixtures → signed SourceEntry NDJSON, cursor continuity, honest degradation.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CORE = new URL("../packages/core/dist/index.js", import.meta.url).pathname;
const COLL = new URL("../packages/collectors/dist/index.js", import.meta.url).pathname;
const { D, ZERO, jstr, b64uDecode, b64uEncode, verifyDetached, schema, generateSeed, privateKeyFromSeed, publicKeyOf } =
  await import(CORE);
const { collect_trellis, collect_vislineage, newCursor } = await import(COLL);

const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const F = "wfl_" + "L".repeat(21), S = "wso_" + "M".repeat(21), U = "wsu_" + "N".repeat(21);
const prodSeed = generateSeed();
const prod = { v: 1, key_id: "wky_" + "P".repeat(21), seed: prodSeed };
const prodPub = b64uEncode(publicKeyOf(privateKeyFromSeed(prodSeed)));
const pins = { fleet: F, source: S, key: prod, subject_map: { "agent-1": U } };
const dir = mkdtempSync(join(tmpdir(), "wcoll-"));

function trellisEvent(run, seq, prev, kind, data) {
  const body = { v: 1, run_id: run, seq: String(seq), prev, kind, data };
  return { body, hash: D("TRELLIS-ENTRY/1", body), sig: "native-sig" };
}

function trellisExport(hostId, runId, events, audit = "COMPLETE_PREFIX") {
  const last = events[events.length - 1];
  const cp = {
    body: {
      v: 1, checkpoint_id: "tcp_1", host_id: hostId, run_id: runId, key_id: "tky_1",
      head: { seq: String(events.length), hash: last.hash }, state: "RUNNING",
      audit, wall_time: "1789275000000",
    },
    hash: "", sig: "native-sig",
  };
  cp.hash = D("TRELLIS-CHECKPOINT/1", cp.body);
  const lines = [jstr({ record: "header", v: 1, format: "trellis-export/1", checkpoint: cp, policy: null })];
  for (const e of events) lines.push(jstr({ record: "entry", entry: e }));
  const p = join(dir, `tre-${Math.random().toString(36).slice(2)}.ndjson`);
  writeFileSync(p, lines.join("\n") + "\n");
  return p;
}

function checkEntries(ndjson, expect) {
  const entries = ndjson.trim().split("\n").map((l) => schema.vSourceEntry(JSON.parse(l)));
  assert.equal(entries.length, expect.length);
  let prev = ZERO;
  entries.forEach((e, i) => {
    assert.equal(e.body.seq, String(i + 1));
    assert.equal(e.body.prev, prev);
    assert.equal(e.hash, D("WEATHER-SOURCE/1", e.body));
    assert.ok(verifyDetached(b64uDecode(prodPub, 32, "pub"), "WEATHER-SOURCE-SIGN/1", e.hash, b64uDecode(e.sig, 64, "sig")));
    prev = e.hash;
    assert.equal(e.body.observation.kind, expect[i]);
  });
  return entries;
}

test("trellis export projects events to a signed source chain", () => {
  const run = "run-9", host = "host-1";
  const e1 = trellisEvent(run, 1, ZERO, "RunCreated", { agent_id: "agent-1", policy_hash: "a".repeat(64) });
  const e2 = trellisEvent(run, 2, e1.hash, "InventoryObserved", { agent_id: "agent-1", inventory: { tgid: [1, 2, 3], threads: "10" } });
  const e3 = trellisEvent(run, 3, e2.hash, "Heartbeat", {});
  const e4 = trellisEvent(run, 4, e3.hash, "RunStopped", {});
  const p = trellisExport(host, run, [e1, e2, e3, e4]);
  const cursor = newCursor(F, S);
  const { ndjson, cursor: cur } = collect_trellis(p, pins, cursor);
  const entries = checkEntries(ndjson, ["scope", "replication", "pulse", "terminal"]);
  assert.equal(entries[0].body.native.verification, "VERIFIED_AT_PIN");
  assert.equal(entries[1].body.observation.processes, "3");
  assert.equal(cur.native_frontier, "4");
  assert.equal(cur.head.seq, "4");
});

test("trellis gap/broken chain emits coverage=false ASSERTED only", () => {
  const run = "run-g", host = "host-1";
  const e1 = trellisEvent(run, 1, ZERO, "Heartbeat", {});
  const bad = trellisEvent(run, 2, "f".repeat(64), "Heartbeat", {}); // broken prev
  const p = trellisExport(host, run, [e1, bad]);
  const cursor = newCursor(F, S);
  const { ndjson } = collect_trellis(p, pins, cursor);
  const entries = checkEntries(ndjson, ["coverage"]);
  assert.equal(entries[0].body.observation.complete, false);
  assert.equal(entries[0].body.native.verification, "ASSERTED");
});

test("vislineage bundle projects steps and verifies inventory", () => {
  const mkStep = (body) => ({ body, hash: D("VL-STEP/1", body) });
  const step = mkStep({
    agent: { namespace: "ns", subject: "subj" }, source: "src",
    policy: "c".repeat(64), offers: [{ scope: "d".repeat(64) }], accept: { scope: "e".repeat(64) },
  });
  const objects = [{ kind: "step", env: step }];
  const inventory = objects.map((o) => ({ kind: o.kind, digest: sha(jstr(o.env)), bytes: String(jstr(o.env).length) }));
  const bundleBody = {
    v: 1, format: "vislineage-bundle/1", workspace: "ws", trace: "tr", revision: "1",
    inventory,
  };
  const bundle = { body: bundleBody, hash: "", steps: [step], origins: [], audit: [] };
  bundle.hash = D("VL-BUNDLE/1", bundleBody);
  const p = join(dir, "vl.json");
  writeFileSync(p, jstr(bundle) + "\n");
  const pins2 = { ...pins, subject_map: { "ws|src|ns|subj": U } };
  const cursor = newCursor(F, S);
  const { ndjson } = collect_vislineage(p, pins2, cursor);
  const entries = checkEntries(ndjson, ["scope", "scope", "scope"]);
  assert.equal(entries[0].body.native.verification, "VERIFIED_AT_PIN");
  assert.equal(entries[0].body.observation.policy_hash, "c".repeat(64));
  assert.equal(entries[1].body.observation.scope_hash, "d".repeat(64));
  assert.equal(entries[2].body.observation.scope_hash, "e".repeat(64));
});

test("vislineage inventory mismatch degrades to coverage=false", () => {
  const bundleBody = {
    v: 1, format: "vislineage-bundle/1", workspace: "ws", trace: "tr", revision: "1",
    inventory: [{ kind: "step", digest: "0".repeat(64), bytes: "1" }],
  };
  const bundle = { body: bundleBody, hash: D("VL-BUNDLE/1", bundleBody), steps: [], origins: [], audit: [] };
  const p = join(dir, "vl-bad.json");
  writeFileSync(p, jstr(bundle) + "\n");
  const cursor = newCursor(F, S);
  const { ndjson } = collect_vislineage(p, pins, cursor);
  const entries = checkEntries(ndjson, ["coverage"]);
  assert.equal(entries[0].body.observation.complete, false);
});
