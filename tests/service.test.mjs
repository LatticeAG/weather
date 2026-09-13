import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  D, ZERO, jstr, privateKeyFromSeed, publicKeyOf, b64uEncode, signDetached,
  verify, parseText,
} from "../packages/core/dist/index.js";
import { Fleet } from "../packages/service/dist/index.js";
import { Rpc } from "../packages/service/dist/rpc.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dir = mkdtempSync(join(tmpdir(), "weather-svc-"));
after(() => rmSync(dir, { recursive: true, force: true }));

const H = (s) => createHash("sha256").update(s).digest("hex");
const KEYS = Object.fromEntries(Array.from({ length: 6 }, (_, i) => {
  const seed = Buffer.alloc(32, i + 1);
  return [i + 1, { seed, pub: b64uEncode(publicKeyOf(privateKeyFromSeed(seed))) }];
}));
const pin = (n) => ({ key_id: `wky_${String(n).repeat(21)}`, public_key: KEYS[n].pub });
const F = `wfl_${"F".repeat(21)}`;
const S = `wso_${"S".repeat(21)}`;
const U = `wsu_${"U".repeat(21)}`;
const W1 = `wwa_${"A".repeat(21)}`, W2 = `wwa_${"B".repeat(21)}`;
const D1 = `wdo_${"A".repeat(21)}`, D2 = `wdo_${"B".repeat(21)}`;
const P = (n) => `wpr_${String(n).repeat(21)}`;
const I = (p, c) => `${p}_${c.repeat(21)}`;

// Regenerate §6.2 fixtures to reuse their exact signed objects (CE, E, V, V2).
const fixtureLines = execFileSync("python3", [join(root, "fixtures/generate_rpc_fixtures.py")], { encoding: "utf8" })
  .trim().split("\n").map((l) => JSON.parse(l));
const byMethod = Object.fromEntries(fixtureLines.map((x) => [x.request.body.method, x]));
const CE = byMethod["config.put"].request.body.params.config;
const E = byMethod["source.append"].request.body.params.entries[0];
const V = byMethod["vote.submit"].request.body.params.vote;
const CP0 = byMethod["audit.checkpoint"].response.result;

const MH = D("WEATHER-MANIFEST/1", {
  v: 1, fleet: F, config: CE.hash, start_ms: "60000", end_ms: "120000",
  through_index: "1", inputs: [E.hash], history: [],
  cuts: [{
    source: S, head: { seq: "1", hash: E.hash }, state: "ACTIVE",
    activated_ms: "60000", last_received_ms: "65000", last_input: E.hash, complete: true,
  }],
  quality: "COMPLETE",
});
const RB = {
  v: 1, fleet: F, config: CE.hash, manifest: MH, detector: "scope_drift/1",
  target: U, decision: { status: "HIT", reason: "POLICY_DRIFT", value: null, limit: null },
  evidence: [E.hash],
};
const R_HASH = D("WEATHER-RESULT/1", RB);

function signBody(body, kind, n) {
  const hash = D(`WEATHER-${kind}/1`, body);
  const sig = b64uEncode(signDetached(KEYS[n].seed, `WEATHER-${kind}-SIGN/1`, hash));
  return { body, hash, sig };
}

let reqN = 0;
function request(method, params, n, sentMs) {
  const body = {
    v: 1, fleet: F, id: `wrq_t${String(++reqN).padStart(20, "0")}`.slice(0, 25),
    key_id: pin(n).key_id, sent_ms: String(sentMs), method, params,
  };
  const hash = D("WEATHER-REQUEST/1", body);
  return Buffer.from(jstr({
    body, hash,
    sig: b64uEncode(signDetached(KEYS[n].seed, "WEATHER-REQUEST-SIGN/1", hash)),
  }), "utf8");
}

let fleet, rpc;
before(() => {
  fleet = new Fleet({
    dataDir: dir, fleet: F, root: pin(1), audit: pin(2),
    auditSeed: KEYS[2].seed, packDigest: H("weather-test-pack"),
  });
  rpc = new Rpc(fleet);
});

const call = (method, params, n, sentMs) => {
  const r = rpc.handle(request(method, params, n, sentMs), BigInt(sentMs));
  return r.body;
};
const ok = (method, params, n, sentMs) => {
  const r = call(method, params, n, sentMs);
  assert.equal(r.ok, true, JSON.stringify(r));
  return r.result;
};
const bad = (method, params, n, sentMs, code) => {
  const r = call(method, params, n, sentMs);
  assert.equal(r.ok, false, JSON.stringify(r));
  assert.equal(r.error.code, code, JSON.stringify(r));
  return r;
};

test("fleet.get on empty fleet matches §6.2", () => {
  assert.deepEqual(ok("fleet.get", {}, 1, 0), {
    fleet: F, phase: "RUNNING", logical_ms: "0", config: null, pending: null,
    head: { seq: "0", hash: ZERO }, through_index: "0", sources: [],
    alerts: { candidate: 0, corroborated: 0, acknowledged: 0, closed: 0, expired: 0 },
    paging: "PAGING_UNAVAILABLE", catching_up: false,
  });
});

test("audit.checkpoint/audit.read/bundle.export on empty fleet match §6.2", () => {
  const cp = ok("audit.checkpoint", {}, 1, 0);
  assert.equal(cp.body.head.seq, "0");
  assert.equal(cp.body.head.hash, ZERO);
  assert.equal(cp.body.key_id, pin(2).key_id);
  const page = ok("audit.read", { after_seq: "0", through: { seq: "0", hash: ZERO }, limit: 128 }, 1, 0);
  assert.deepEqual(page, { entries: [], objects: [], through: { seq: "0", hash: ZERO }, next_seq: "0", more: false });
  const bundle = ok("bundle.export", { after_seq: "0", checkpoint: cp, limit: 128 }, 1, 0);
  assert.equal(bundle.format, "weather-evidence/1");
  assert.equal(bundle.native_disclosure, "COMMITMENTS_ONLY");
});

test("config.put schedules epoch 1; wrong signer rejected", () => {
  const r = ok("config.put", { config: CE }, 1, 0);
  assert.deepEqual(r, { hash: CE.hash, state: "PENDING", effective_ms: "60000" });
  // a key bound only by the scheduled config is authenticated but lacks the role
  bad("config.put", { config: CE }, 3, 0, "FORBIDDEN");
  // a key bound by nothing at all is UNAUTHORIZED
  const unbound = { v: 1, fleet: F, id: `wrq_u${"0".repeat(20)}`, key_id: `wky_${"9".repeat(21)}`, sent_ms: "0", method: "fleet.get", params: {} };
  const uh = D("WEATHER-REQUEST/1", unbound);
  const ue = { body: unbound, hash: uh, sig: b64uEncode(signDetached(KEYS[6].seed, "WEATHER-REQUEST-SIGN/1", uh)) };
  const ur = rpc.handle(Buffer.from(jstr(ue), "utf8"), 0n).body;
  assert.equal(ur.error.code, "UNAUTHORIZED");
});

test("source.append accepts seq 1; window finalizes at 120000", () => {
  const r = ok("source.append", { entries: [E] }, 3, 65000);
  assert.deepEqual(r.items, [{ seq: "1", status: "ACCEPTED", index: "1", counted: true }]);
  assert.equal(r.source.state, "ACTIVE");
  assert.equal(r.source.head.hash, E.hash);
  // duplicate replay: same body again → DUPLICATE
  const d = ok("source.append", { entries: [E] }, 3, 66000);
  assert.equal(d.items[0].status, "DUPLICATE");
  assert.equal(d.items[0].index, "1");
});

let _subId = null, _subAck = "0";
test("subscription lifecycle", () => {
  const sub = ok("subscription.open", { watcher: W1, after_seq: "2" }, 4, 66000);
  _subId = sub.id;
  assert.equal(sub.state, "ACTIVE");
  assert.equal(sub.watcher, W1);
  assert.equal(sub.lease_until_ms, "366000");
  assert.equal(sub.revision, "1");
  const page = ok("subscription.read", { subscription: sub.id, after_seq: sub.delivered, limit: 128 }, 4, 66000);
  assert.equal(page.through.seq, String(fleet.auditHead.seq));
  const acked = ok("subscription.ack", { subscription: sub.id, through_seq: page.next_seq }, 4, 66000);
  assert.equal(acked.ack, page.next_seq);
  _subAck = acked.ack;
  const paused = ok("subscription.set", { subscription: sub.id, action: "pause", expected_revision: acked.revision }, 4, 66000);
  assert.equal(paused.state, "PAUSED");
  ok("subscription.set", { subscription: sub.id, action: "resume", expected_revision: paused.revision }, 4, 66000);
  // second live subscription for same watcher → STATE_CONFLICT
  bad("subscription.open", { watcher: W1, after_seq: "0" }, 4, 66000, "STATE_CONFLICT");
});

test("window close creates HIT alert; votes corroborate; outbox empty (null target)", () => {
  // Trigger finalization: a read at t=120001.
  ok("subscription.read", { subscription: subId(), after_seq: _subAck, limit: 1 }, 4, 120001);
  const list = ok("alert.list", { state: "CANDIDATE", after: null, limit: 128 }, 6, 120001);
  assert.equal(list.alerts.length, 1);
  const a = list.alerts[0];
  assert.equal(a.result, R_HASH);
  assert.equal(a.state, "CANDIDATE");
  assert.equal(a.expires_ms, "300000");
  assert.equal(a.revision, "1");
  // vote 1 (watcher1, domain A)
  const v1 = ok("vote.submit", { vote: V }, 4, 120001);
  assert.equal(v1.accepted, true);
  assert.deepEqual(v1.alert.domains, [D1]);
  assert.deepEqual(v1.alert.votes, [V.hash]);
  assert.equal(v1.alert.revision, "2");
  // same vote again → idempotent, no change
  const v1b = ok("vote.submit", { vote: V }, 4, 120002);
  assert.deepEqual(v1b.alert.votes, [V.hash]);
  // vote 2 (watcher2, domain B) → CORROBORATED; notification_target null → no outbox
  const V2 = signBody({ ...V.body, watcher: W2, key_id: pin(5).key_id }, "VOTE", 5);
  const v2 = ok("vote.submit", { vote: V2 }, 5, 120003);
  assert.equal(v2.alert.state, "CORROBORATED");
  assert.deepEqual(v2.alert.domains, [D1, D2]);
  assert.equal(v2.alert.delivery, "NONE");
  // vote from a non-roster key → FORBIDDEN (operator key has no watcher)
  const VX = signBody({ ...V.body, watcher: W2, key_id: pin(6).key_id }, "VOTE", 6);
  bad("vote.submit", { vote: VX }, 6, 120004, "FORBIDDEN");
});

function subId() {
  return _subId;
}

test("alert.act close + revision CAS", () => {
  const list = ok("alert.list", { state: null, after: null, limit: 128 }, 6, 120005);
  const a = list.alerts[0];
  assert.equal(a.state, "CORROBORATED");
  // wrong revision → REVISION_CONFLICT
  bad("alert.act", { alert: a.id, action: "ack", expected_revision: "1", note_hash: null }, 6, 120005, "REVISION_CONFLICT");
  const cur = ok("alert.get", { alert: a.id }, 6, 120005);
  const acked = ok("alert.act", { alert: a.id, action: "ack", expected_revision: cur.alert.revision, note_hash: null }, 6, 120005);
  assert.equal(acked.state, "ACKNOWLEDGED");
  const closed = ok("alert.act", { alert: a.id, action: "close", expected_revision: acked.revision, note_hash: null }, 6, 120006);
  assert.equal(closed.state, "CLOSED");
  // closed alert rejects further votes with STATE_CONFLICT (identical replay
  // of V2 has the same hash and would otherwise be idempotent)
  bad("vote.submit", { vote: V2dup() }, 5, 120006, "STATE_CONFLICT");
});

function V2dup() {
  return signBody({ ...V.body, watcher: W2, key_id: pin(5).key_id }, "VOTE", 5);
}

test("idempotency: same id+body replays; different body conflicts", () => {
  const req = request("fleet.get", {}, 1, 130000);
  const r1 = rpc.handle(req, 130000n).body;
  const r2 = rpc.handle(req, 140000n).body;
  assert.deepEqual(r1, r2);
  // re-sign with same id but different body → IDEMPOTENCY_CONFLICT
  const b = JSON.parse(req.toString());
  b.body.sent_ms = "140000";
  b.hash = D("WEATHER-REQUEST/1", b.body);
  b.sig = b64uEncode(signDetached(KEYS[1].seed, "WEATHER-REQUEST-SIGN/1", b.hash));
  const r3 = rpc.handle(Buffer.from(jstr(b), "utf8"), 140000n).body;
  assert.equal(r3.error.code, "IDEMPOTENCY_CONFLICT");
});

test("stale and future requests rejected", () => {
  // sent_ms 70s behind current wall/logical → STALE_REQUEST
  const stale = request("fleet.get", {}, 1, 70000);
  const r = rpc.handle(stale, 140001n).body;
  assert.equal(r.error.code, "STALE_REQUEST");
});

test("audit chain verifies end-to-end via offline verify()", () => {
  const cp = ok("audit.checkpoint", {}, 1, 140001);
  const pages = [];
  let after = "0";
  for (;;) {
    const p = ok("bundle.export", { after_seq: after, checkpoint: cp, limit: 4 }, 1, 140001);
    pages.push(p);
    if (!p.more) break;
    after = p.next_seq;
  }
  const res = verify({ pages, root: pin(1), audit: pin(2), expected_head: cp.body.head });
  assert.equal(res.integrity, "VALID", res.reasons.join(","));
  assert.equal(res.replay, "MATCH", res.reasons.join(","));
  assert.equal(res.completeness, "AT_PIN");
  assert.equal(res.native_truth, "NOT_ATTESTED");
});

test("metrics.get reports counters", () => {
  const m = ok("metrics.get", {}, 1, 140002);
  const names = Object.fromEntries(m.samples.map((s) => [s.name, s.value]));
  assert.equal(names.inputs_accepted_total, "1");
  assert.equal(names.detector_hit_total, "1");
});
