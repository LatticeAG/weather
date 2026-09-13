// Outbox delivery path: corroborated alert → signed Page → POST attempts with
// exact retry schedule, receiver 204 → DELIVERED; 5xx → RETRY; cancel-on-close.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  D, ZERO, jstr, privateKeyFromSeed, publicKeyOf, b64uEncode, b64uDecode,
  signDetached, verifyDetached,
} from "../packages/core/dist/index.js";
import { Fleet } from "../packages/service/dist/index.js";
import { Rpc } from "../packages/service/dist/rpc.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const H = (s) => createHash("sha256").update(s).digest("hex");
const KEYS = Object.fromEntries(Array.from({ length: 6 }, (_, i) => {
  const seed = Buffer.alloc(32, i + 1);
  return [i + 1, { seed, pub: b64uEncode(publicKeyOf(privateKeyFromSeed(seed))) }];
}));
const pin = (n) => ({ key_id: `wky_${String(n).repeat(21)}`, public_key: KEYS[n].pub });
const F = `wfl_${"F".repeat(21)}`, S = `wso_${"S".repeat(21)}`, U = `wsu_${"U".repeat(21)}`;
const W1 = `wwa_${"A".repeat(21)}`, W2 = `wwa_${"B".repeat(21)}`;
const D1 = `wdo_${"A".repeat(21)}`, D2 = `wdo_${"B".repeat(21)}`;

const fixtureLines = execFileSync("python3", [join(root, "fixtures/generate_rpc_fixtures.py")], { encoding: "utf8" })
  .trim().split("\n").map((l) => JSON.parse(l));
const byMethod = Object.fromEntries(fixtureLines.map((x) => [x.request.body.method, x]));
const CE = byMethod["config.put"].request.body.params.config;
const E = byMethod["source.append"].request.body.params.entries[0];

// Same fleet shape as §6.2 but with paging enabled and a primary URL bound.
const CB = { ...CE.body, notification_target: "primary" };
const CE2 = {
  body: CB, hash: D("WEATHER-CONFIG/1", CB), key_id: pin(1).key_id,
  sig: b64uEncode(signDetached(KEYS[1].seed, "WEATHER-CONFIG-SIGN/1", D("WEATHER-CONFIG/1", CB))),
};
const MH2 = D("WEATHER-MANIFEST/1", {
  v: 1, fleet: F, config: CE2.hash, start_ms: "60000", end_ms: "120000",
  through_index: "1", inputs: [E.hash], history: [],
  cuts: [{
    source: S, head: { seq: "1", hash: E.hash }, state: "ACTIVE",
    activated_ms: "60000", last_received_ms: "65000", last_input: E.hash, complete: true,
  }],
  quality: "COMPLETE",
});
const R2 = D("WEATHER-RESULT/1", {
  v: 1, fleet: F, config: CE2.hash, manifest: MH2, detector: "scope_drift/1",
  target: U, decision: { status: "HIT", reason: "POLICY_DRIFT", value: null, limit: null },
  evidence: [E.hash],
});

const dir = mkdtempSync(join(tmpdir(), "weather-outbox-"));
const fleet = new Fleet({
  dataDir: dir, fleet: F, root: pin(1), audit: pin(2),
  auditSeed: KEYS[2].seed, packDigest: H("weather-test-pack"),
  primaryUrl: "https://pager.example.com/weather-hook",
});
const rpc = new Rpc(fleet);

function req(method, params, n, sentMs) {
  const body = {
    v: 1, fleet: F, id: `wrq_${Math.random().toString(36).slice(2, 10).padEnd(8, "x")}`.slice(0, 25).padEnd(25, "x").replace(/^wrq_/, "wrq_"),
    key_id: pin(n).key_id, sent_ms: String(sentMs), method, params,
  };
  body.id = `wrq_${(Math.random().toString(36) + "x".repeat(30)).replace(/[^A-Za-z0-9_-]/g, "x").slice(0, 21)}`;
  const hash = D("WEATHER-REQUEST/1", body);
  return Buffer.from(jstr({ body, hash, sig: b64uEncode(signDetached(KEYS[n].seed, "WEATHER-REQUEST-SIGN/1", hash)) }), "utf8");
}
const ok = (method, params, n, sentMs) => {
  const r = rpc.handle(req(method, params, n, sentMs), BigInt(sentMs));
  assert.equal(r.body.ok, true, JSON.stringify(r.body));
  return r.body.result;
};
const vote = (watcher, keyId, n) => {
  const body = { v: 1, fleet: F, watcher, config: CE2.hash, result: R2, manifest: MH2, key_id: keyId };
  const hash = D("WEATHER-VOTE/1", body);
  return { body, hash, sig: b64uEncode(signDetached(KEYS[n].seed, "WEATHER-VOTE-SIGN/1", hash)) };
};
const settle = () => new Promise((r) => setImmediate(r));

let alertId;
before(() => {
  ok("config.put", { config: CE2 }, 1, 0);
  ok("source.append", { entries: [E] }, 3, 65000);
  ok("subscription.open", { watcher: W1, after_seq: "0" }, 4, 120001); // mutating request finalizes window → CANDIDATE
  const list = ok("alert.list", { state: "CANDIDATE", after: null, limit: 128 }, 6, 120001);
  assert.equal(list.alerts.length, 1);
  alertId = list.alerts[0].id;
});

test("corroboration queues a signed Page; 503 retries on schedule; 204 delivers", async () => {
  const v1 = ok("vote.submit", { vote: vote(W1, pin(4).key_id, 4) }, 4, 120002);
  assert.equal(v1.alert.delivery, "NONE");
  const v2 = ok("vote.submit", { vote: vote(W2, pin(5).key_id, 5) }, 5, 120003);
  assert.equal(v2.alert.state, "CORROBORATED");
  assert.equal(v2.alert.delivery, "QUEUED");

  const posts = [];
  const sender503 = async (page, idem) => {
    posts.push({ page, idem });
    // receiver contract: Idempotency-Key = Page.hash, body = Page (§6.3)
    assert.equal(idem, page.hash);
    assert.equal(page.body.alert, alertId);
    assert.equal(page.body.semantics, "ADVISORY_ONLY");
    assert.equal(page.hash, D("WEATHER-PAGE/1", page.body));
    assert.ok(verifyDetached(b64uDecode(pin(2).public_key, 32, "audit"), "WEATHER-PAGE-SIGN/1", page.hash, b64uDecode(page.sig, 64, "sig")));
    return { status: 503 };
  };
  fleet.runDeliveries(120004n, sender503);
  await settle();
  let a = fleet.getAlert(alertId);
  assert.equal(a.delivery, "RETRY");

  // Not yet due: delay after attempt 1 is exactly 1000 ms.
  fleet.runDeliveries(120500n, sender503);
  await settle();
  assert.equal(posts.length, 1);

  fleet.runDeliveries(121004n, sender503); // due → attempt 2 → 503 → RETRY (+2000)
  await settle();
  assert.equal(posts.length, 2);
  a = fleet.getAlert(alertId);
  assert.equal(a.delivery, "RETRY");

  const sender204 = async (page, idem) => ({ status: 204 });
  fleet.runDeliveries(123004n, sender204); // due after +2000
  await settle();
  a = fleet.getAlert(alertId);
  assert.equal(a.delivery, "DELIVERED");
});

test("queuePage skipped when primary_url absent even with target=primary", () => {
  const dir2 = mkdtempSync(join(tmpdir(), "weather-outbox2-"));
  const f2 = new Fleet({
    dataDir: dir2, fleet: F, root: pin(1), audit: pin(2),
    auditSeed: KEYS[2].seed, packDigest: H("weather-test-pack"), primaryUrl: null,
  });
  const rpc2 = new Rpc(f2);
  const ok2 = (m, p, n, s) => {
    const r = rpc2.handle(req(m, p, n, s), BigInt(s));
    assert.equal(r.body.ok, true, JSON.stringify(r.body));
    return r.body.result;
  };
  ok2("config.put", { config: CE2 }, 1, 0);
  ok2("source.append", { entries: [E] }, 3, 65000);
  ok2("subscription.open", { watcher: W1, after_seq: "0" }, 4, 120001);
  ok2("vote.submit", { vote: vote(W1, pin(4).key_id, 4) }, 4, 120002);
  const v2 = ok2("vote.submit", { vote: vote(W2, pin(5).key_id, 5) }, 5, 120003);
  assert.equal(v2.alert.state, "CORROBORATED");
  assert.equal(v2.alert.delivery, "NONE"); // corroborated, never queued
});
