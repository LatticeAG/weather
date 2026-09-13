import { D, ZERO, EMPTY_HEAD } from "./hash.js";
import { J } from "./jcs.js";
import { uBig } from "./schema.js";
import { verifyDetached } from "./ed25519.js";
import { evaluateResults, type WindowInput, type SourceClose } from "./window.js";
import { usagePayloadHash } from "./usage.js";
import type {
  Accepted, AlertView, Audit, AuditBody, BundlePage, Checkpoint, ConfigEnvelope,
  Delivery, Hash, Head, Manifest, Result, SourceEntry, SourceID, Subscription,
  U, VerifyInput, VerifyResult, Vote,
} from "./types.js";

/**
 * evidence.verify (§5.3, §6.3): offline bundle verification. Checks, in
 * order: parsing (done by the caller's strict parse), external role pins, all
 * object hashes, all signatures, source continuity/forks, journal
 * transitions, config epochs, manifests, detector replay, votes, and page
 * eligibility. Never fetches native_artifact; returns explicit limitations.
 */

type Reason =
  | "NO_PAGES" | "PARSE_INVALID" | "HASH_MISMATCH" | "SIGNATURE_INVALID"
  | "CHAIN_INVALID" | "TRANSITION_INVALID" | "OBJECT_MISSING" | "OBJECT_CONFLICT"
  | "REPLAY_MISMATCH" | "PACK_UNAVAILABLE" | "HEAD_MISMATCH" | "INCOMPLETE";

interface SrcState {
  id: SourceID;
  state: "EMPTY" | "ACTIVE" | "GAPPED" | "FORKED" | "TERMINAL" | "RETIRED";
  seq: bigint;
  hash: Hash;
  activated_ms: U;
  last_ms: U | null;
  last_input: Hash | null;
  complete: boolean;
  pending: Map<bigint, SourceEntry>;
}

interface AlertSt {
  view: AlertView;
  votes: Map<string, Hash>; // watcher -> vote hash
  domains: Set<string>;
  degradedCauses: Set<string>;
}

class Verifier {
  reasons = new Set<Reason>();
  integrityBad = false;
  replayBad = false;
  incomplete = false;
  packUnavailable = false;

  logical = 0n;
  fleet = "";
  configs = new Map<Hash, ConfigEnvelope>();
  active: ConfigEnvelope | null = null;
  pendingCfg: ConfigEnvelope | null = null;
  revoked = new Set<string>();
  sources = new Map<SourceID, SrcState>();
  acceptedList: Accepted[] = [];
  usageIds = new Map<string, Map<string, Hash>>();
  windows: { manifest: Manifest; accepted: Accepted[] }[] = [];
  results = new Map<Hash, Result>();
  alerts = new Map<string, AlertSt>();
  subs = new Map<string, Subscription>();
  outbox = new Map<string, Delivery>();
  throughIdx = 0n;
  objects = new Map<string, unknown>();
  referenced = new Set<string>();
  positions = new Map<bigint, Hash>(); // audit seq -> hash (ancestry checks)
  sawConfigScheduled = false;
  auditKeyId = "";

  // WindowFinalized → ResultFinalized* → AlertCreated* event-group tracking
  pw: { manifest: Manifest; expect: number; got: number; results: Result[] } | null = null;

  fail(r: Reason): void {
    this.reasons.add(r);
    if (r === "REPLAY_MISMATCH") this.replayBad = true;
    else if (r === "PACK_UNAVAILABLE") { this.packUnavailable = true; this.incomplete = true; }
    else if (r === "INCOMPLETE" || r === "HEAD_MISMATCH") this.incomplete = true;
    else this.integrityBad = true;
  }

  sig(env: { hash: string; sig: string }, tag: string, publicKeyB64: string): boolean {
    try {
      return verifyDetached(
        new Uint8Array(Buffer.from(publicKeyB64, "base64url")), tag, env.hash,
        new Uint8Array(Buffer.from(env.sig, "base64url")),
      );
    } catch {
      return false;
    }
  }

  event(b: AuditBody): void {
    const at = uBig(b.at_ms);
    // A declared result group must complete before any other event kind.
    if (this.pw && b.kind !== "ResultFinalized" && b.kind !== "AlertCreated") {
      if (this.pw.got !== this.pw.expect) this.fail("TRANSITION_INVALID");
      this.pw = null;
    }
    switch (b.kind) {
      case "Tick": this.onTick(b.data.logical_ms, at); break;
      case "ConfigScheduled": this.onConfigScheduled(b.data.config); break;
      case "ConfigActivated": this.onConfigActivated(b.data.config, at); break;
      case "KeysRevoked": this.onKeysRevoked(b.data.keys); break;
      case "SourceAccepted": this.onSourceAccepted(b.data.accepted, at); break;
      case "SourceBuffered": this.onSourceBuffered(b.data.entry); break;
      case "SourceForkObserved": this.onFork(b.data.source, b.data.left, b.data.right, b.data.reason); break;
      case "WindowFinalized": this.onWindowFinalized(b.data.manifest, b.data.result_count); break;
      case "ResultFinalized": this.onResultFinalized(b.data.result); break;
      case "AlertCreated": this.onAlertCreated(b.data.alert); break;
      case "VoteAccepted": this.onVoteAccepted(b.data.alert, b.data.vote, at); break;
      case "AlertChanged": this.onAlertChanged(b.data.alert, b.data.from, b.data.to, b.data.actor, b.data.revision, at); break;
      case "AlertDegraded": this.onAlertDegraded(b.data.alert, b.data.source, b.data.key, b.data.revision); break;
      case "SubscriptionChanged": this.onSubChanged(b.data.subscription, b.data.event); break;
      case "DeliveryChanged": this.onDeliveryChanged(b.data.delivery, b.data.page); break;
      case "FleetChanged": break;
    }
  }

  onTick(logical: string, at: bigint): void {
    const l = uBig(logical);
    if (l !== at || l <= this.logical) this.fail("TRANSITION_INVALID");
    else this.logical = l;
  }

  onConfigScheduled(configHash: Hash): void {
    const rec = this.objects.get(`config:${configHash}`) as ConfigEnvelope | undefined;
    if (!rec) { this.fail("OBJECT_MISSING"); return; }
    if (rec.key_id !== this.auditRootKey || !this.sig(rec, "WEATHER-CONFIG-SIGN/1", this.rootPub)) {
      this.fail("SIGNATURE_INVALID"); return;
    }
    const c = rec.body;
    if (c.fleet !== this.fleet) { this.fail("TRANSITION_INVALID"); return; }
    if (!this.sawConfigScheduled) {
      if (c.epoch !== "1" || c.predecessor !== ZERO) { this.fail("TRANSITION_INVALID"); return; }
    } else {
      const prev = this.active?.body ?? null;
      const prevHash = this.active?.hash ?? this.lastScheduledHash();
      if (!prev || !prevHash) { this.fail("TRANSITION_INVALID"); return; }
      if (uBig(c.epoch) !== uBig(prev.epoch) + 1n || c.predecessor !== prevHash) { this.fail("CHAIN_INVALID"); return; }
      if (this.pendingCfg) { this.fail("TRANSITION_INVALID"); return; }
      const oldSources = new Map(prev.sources.map((s) => [s.id, s]));
      for (const s of c.sources) {
        const o = oldSources.get(s.id);
        if (o && (o.principal !== s.principal || o.pin.key_id !== s.pin.key_id ||
          o.pin.public_key !== s.pin.public_key || o.profile !== s.profile ||
          o.meter !== s.meter || o.subjects.join(",") !== s.subjects.join(","))) {
          this.fail("TRANSITION_INVALID"); return;
        }
      }
    }
    if (c.pack !== "weather-core/1.0.0") this.fail("PACK_UNAVAILABLE");
    this.configs.set(configHash, rec);
    this.pendingCfg = rec;
    this.sawConfigScheduled = true;
    this.lastScheduled = rec;
    for (const k of c.revoked_keys) this.revoked.add(k);
  }

  lastScheduled: ConfigEnvelope | null = null;
  auditRootKey = "";
  rootPub = "";

  private lastScheduledHash(): Hash | null {
    return this.lastScheduled?.hash ?? null;
  }

  onConfigActivated(configHash: Hash, at: bigint): void {
    if (!this.pendingCfg || this.pendingCfg.hash !== configHash) { this.fail("TRANSITION_INVALID"); return; }
    if (uBig(this.pendingCfg.body.effective_ms) > at) { this.fail("TRANSITION_INVALID"); return; }
    const c = this.pendingCfg.body;
    const inCfg = new Map(c.sources.map((s) => [s.id, s]));
    for (const st of this.sources.values()) {
      const nc = inCfg.get(st.id);
      if ((!nc || !nc.enabled) && st.state !== "RETIRED") st.state = "RETIRED";
    }
    for (const sc of c.sources) {
      if (!sc.enabled) continue;
      if (!this.sources.has(sc.id)) {
        this.sources.set(sc.id, {
          id: sc.id, state: "EMPTY", seq: 0n, hash: ZERO, activated_ms: c.effective_ms,
          last_ms: null, last_input: null, complete: true, pending: new Map(),
        });
      }
    }
    this.active = this.pendingCfg;
    this.pendingCfg = null;
    this.windows = [];
  }

  onKeysRevoked(keys: string[]): void {
    for (const k of keys) this.revoked.add(k);
  }

  private srcCfg(source: SourceID) {
    return this.active?.body.sources.find((s) => s.id === source) ?? null;
  }

  entrySigOk(e: SourceEntry): boolean {
    if (e.hash !== D("WEATHER-SOURCE/1", e.body)) { this.fail("HASH_MISMATCH"); return false; }
    if (e.body.fleet !== this.fleet) { this.fail("TRANSITION_INVALID"); return false; }
    const sc = this.srcCfg(e.body.source);
    if (!sc) { this.fail("TRANSITION_INVALID"); return false; }
    if (sc.pin.key_id !== e.body.key_id) { this.fail("SIGNATURE_INVALID"); return false; }
    if (!verifyDetached(
      new Uint8Array(Buffer.from(sc.pin.public_key, "base64url")),
      "WEATHER-SOURCE-SIGN/1", e.hash,
      new Uint8Array(Buffer.from(e.sig, "base64url")),
    )) return false;
    // profile binding + subject authorization (§4.1 step 2)
    if (sc.profile !== e.body.native.profile) { this.fail("TRANSITION_INVALID"); return false; }
    const obs = e.body.observation;
    if ("subject" in obs && !sc.subjects.includes(obs.subject)) { this.fail("TRANSITION_INVALID"); return false; }
    if (obs.kind === "spend" && !sc.meter) { this.fail("TRANSITION_INVALID"); return false; }
    if ((obs.kind === "scope" || obs.kind === "replication") && sc.meter) { this.fail("TRANSITION_INVALID"); return false; }
    return true;
  }

  onSourceAccepted(a: Accepted, at: bigint): void {
    const st = this.sources.get(a.entry.body.source);
    if (!this.entrySigOk(a.entry)) return;
    if (!st || st.state === "RETIRED" || st.state === "TERMINAL" || st.state === "FORKED") {
      this.fail("TRANSITION_INVALID"); return;
    }
    const e = a.entry;
    const seq = uBig(e.body.seq);
    if (seq !== st.seq + 1n) { this.fail("CHAIN_INVALID"); return; }
    if (st.seq === 0n ? e.body.prev !== ZERO : e.body.prev !== st.hash) { this.fail("CHAIN_INVALID"); return; }
    if (uBig(a.received_ms) !== at) { this.fail("TRANSITION_INVALID"); return; }
    if (uBig(a.index) !== this.throughIdx + 1n) { this.fail("CHAIN_INVALID"); return; }
    const maxLate = this.active ? BigInt(this.active.body.max_late_ms) : 120000n;
    const late = uBig(e.body.observed_ms) < at - maxLate;
    if (a.late !== late) { this.fail("TRANSITION_INVALID"); return; }
    const obs = e.body.observation;
    let counted = true;
    if (obs.kind === "spend") {
      const ph = usagePayloadHash(obs.subject, obs.delta, obs.unit);
      const smap = this.usageIds.get(st.id) ?? new Map<string, Hash>();
      const prevP = smap.get(obs.usage_id);
      if (prevP !== undefined) {
        if (prevP !== ph) { this.fail("TRANSITION_INVALID"); return; }
        counted = false;
      } else smap.set(obs.usage_id, ph);
      this.usageIds.set(st.id, smap);
    }
    if (a.counted !== counted) { this.fail("TRANSITION_INVALID"); return; }
    if (obs.kind === "terminal" && st.pending.size > 0) { this.fail("TRANSITION_INVALID"); return; }
    st.seq = seq;
    st.hash = e.hash;
    if (obs.kind !== "signal") { st.last_ms = a.received_ms; st.last_input = e.hash; }
    if (obs.kind === "coverage") st.complete = obs.complete;
    st.state = obs.kind === "terminal" ? "TERMINAL" : st.pending.size > 0 ? "GAPPED" : "ACTIVE";
    this.throughIdx += 1n;
    this.acceptedList.push(a);
  }

  onSourceBuffered(e: SourceEntry): void {
    const st = this.sources.get(e.body.source);
    if (!this.entrySigOk(e)) return;
    if (!st || st.state === "RETIRED" || st.state === "TERMINAL" || st.state === "FORKED") {
      this.fail("TRANSITION_INVALID"); return;
    }
    const seq = uBig(e.body.seq);
    if (seq <= st.seq || st.pending.has(seq)) { this.fail("TRANSITION_INVALID"); return; }
    st.pending.set(seq, e);
    st.state = "GAPPED";
  }

  onFork(source: SourceID, left: SourceEntry, right: SourceEntry, reason: "SLOT_FORK" | "TERMINAL_SUFFIX"): void {
    const st = this.sources.get(source);
    if (!st) { this.fail("TRANSITION_INVALID"); return; }
    for (const e of [left, right]) {
      if (e.body.source !== source) { this.fail("TRANSITION_INVALID"); return; }
      if (!this.entrySigOk(e)) return;
    }
    if (reason === "SLOT_FORK") {
      if (uBig(left.body.seq) !== uBig(right.body.seq) || left.hash === right.hash) {
        this.fail("TRANSITION_INVALID"); return;
      }
    } else {
      const terms = [left, right].filter((e) => e.body.observation.kind === "terminal");
      if (terms.length !== 1) { this.fail("TRANSITION_INVALID"); return; }
    }
    st.state = "FORKED";
  }

  onWindowFinalized(manifestHash: Hash, resultCount: number): void {
    const m = this.objects.get(`manifest:${manifestHash}`) as Manifest | undefined;
    if (!m || !this.active) { this.fail(m ? "TRANSITION_INVALID" : "OBJECT_MISSING"); return; }
    const wacc = this.acceptedList.filter((a) => {
      const r = uBig(a.received_ms);
      return r >= uBig(m.start_ms) && r < uBig(m.end_ms);
    });
    const closes: SourceClose[] = this.active.body.sources
      .filter((s) => s.enabled)
      .map((s) => {
        const st = this.sources.get(s.id)!;
        return {
          source: s.id, headSeq: st.seq.toString(), headHash: st.hash, state: st.state,
          activated_ms: st.activated_ms, last_received_ms: st.last_ms, last_input: st.last_input,
          complete: st.complete, pending: st.pending.size, revoked: this.revoked.has(s.pin.key_id),
        };
      })
      .sort((a, b) => (a.source < b.source ? -1 : 1));
    const recomputed: Manifest = {
      v: 1, fleet: m.fleet, config: m.config, start_ms: m.start_ms, end_ms: m.end_ms,
      through_index: this.throughIdx.toString(),
      inputs: wacc.map((a) => a.entry.hash),
      history: this.windows.slice(-5).map((w) => D("WEATHER-MANIFEST/1", w.manifest)),
      cuts: closes.map((c) => ({
        source: c.source, head: { seq: c.headSeq, hash: c.headHash }, state: c.state,
        activated_ms: c.activated_ms, last_received_ms: c.last_received_ms,
        last_input: c.last_input, complete: c.complete,
      })),
      quality: qualityOf(closes, wacc),
    };
    if (D("WEATHER-MANIFEST/1", recomputed) !== manifestHash) this.fail("REPLAY_MISMATCH");
    const win: WindowInput = {
      fleet: m.fleet, configHash: m.config, config: this.active.body,
      start_ms: m.start_ms, end_ms: m.end_ms, through_index: this.throughIdx.toString(),
      accepted: wacc, history: recomputed.history, historyWindows: this.windows.slice(-5),
      closes, revoked_keys: new Set(this.revoked),
    };
    const results = evaluateResults(win, recomputed, manifestHash);
    if (results.length !== resultCount) { this.fail("REPLAY_MISMATCH"); return; }
    this.pw = { manifest: recomputed, expect: resultCount, got: 0, results };
    this.windows.push({ manifest: recomputed, accepted: wacc });
    if (this.windows.length > 5) this.windows.shift();
  }

  onResultFinalized(resultHash: Hash): void {
    const pw = this.pw;
    if (!pw) { this.fail("TRANSITION_INVALID"); return; }
    const rec = this.objects.get(`result:${resultHash}`) as Result | undefined;
    if (!rec) { this.fail("OBJECT_MISSING"); return; }
    const exp = pw.results[pw.got];
    if (!exp || rec.hash !== exp.hash) this.fail("REPLAY_MISMATCH");
    this.results.set(resultHash, rec);
    pw.got++;
  }

  onAlertCreated(alert: AlertView): void {
    const pw = this.pw;
    if (!pw) { this.fail("TRANSITION_INVALID"); return; }
    if (alert.state !== "CANDIDATE" || alert.revision !== "1" || alert.domains.length !== 0 ||
        alert.votes.length !== 0 || alert.delivery !== "NONE" || alert.assurance !== "VALID") {
      this.fail("TRANSITION_INVALID"); return;
    }
    const hit = pw.results.find((r) => r.hash === alert.result);
    if (!hit || hit.body.decision.status !== "HIT") { this.fail("TRANSITION_INVALID"); return; }
    const expectExp = uBig(pw.manifest.end_ms) + BigInt(this.active!.body.vote_ttl_ms);
    if (uBig(alert.expires_ms) !== expectExp) { this.fail("TRANSITION_INVALID"); return; }
    this.alerts.set(alert.id, { view: alert, votes: new Map(), domains: new Set(), degradedCauses: new Set() });
  }

  onVoteAccepted(alertId: string, vote: Vote, at: bigint): void {
    const al = this.alerts.get(alertId);
    if (!al) { this.fail("TRANSITION_INVALID"); return; }
    if (vote.hash !== D("WEATHER-VOTE/1", vote.body)) { this.fail("HASH_MISMATCH"); return; }
    const res = this.results.get(vote.body.result);
    if (!res || res.hash !== al.view.result) { this.fail("TRANSITION_INVALID"); return; }
    if (vote.body.fleet !== this.fleet || vote.body.config !== res.body.config || vote.body.manifest !== res.body.manifest) {
      this.fail("TRANSITION_INVALID"); return;
    }
    const rcfg = this.configs.get(res.body.config)?.body;
    if (!rcfg) { this.fail("OBJECT_MISSING"); return; }
    const wc = rcfg.watchers.find((w) => w.id === vote.body.watcher);
    if (!wc || !wc.enabled) { this.fail("TRANSITION_INVALID"); return; }
    if (wc.pin.key_id !== vote.body.key_id) { this.fail("SIGNATURE_INVALID"); return; }
    if (!this.sig(vote, "WEATHER-VOTE-SIGN/1", wc.pin.public_key)) { this.fail("SIGNATURE_INVALID"); return; }
    if (at >= uBig(al.view.expires_ms)) { this.fail("TRANSITION_INVALID"); return; }
    if (al.view.state === "CLOSED" || al.view.state === "EXPIRED") { this.fail("TRANSITION_INVALID"); return; }
    if (al.votes.has(vote.body.watcher)) { this.fail("TRANSITION_INVALID"); return; }
    al.votes.set(vote.body.watcher, vote.hash);
    if (!this.revoked.has(vote.body.key_id)) al.domains.add(wc.domain);
    al.view = { ...al.view, votes: [...al.votes.values()].sort(), domains: [...al.domains].sort(), revision: (uBig(al.view.revision) + 1n).toString() };
  }

  onAlertChanged(alertId: string, from: string, to: string, actor: string | null, revision: string, at: bigint): void {
    const al = this.alerts.get(alertId);
    if (!al) { this.fail("TRANSITION_INVALID"); return; }
    if (al.view.state !== from || uBig(revision) !== uBig(al.view.revision) + 1n) {
      this.fail("TRANSITION_INVALID"); return;
    }
    const ok =
      (from === "CANDIDATE" && to === "CORROBORATED" && actor === null && al.domains.size >= 2 && al.view.assurance === "VALID") ||
      (from === "CANDIDATE" && to === "EXPIRED" && actor === null && at >= uBig(al.view.expires_ms)) ||
      (from === "CORROBORATED" && to === "ACKNOWLEDGED" && actor !== null) ||
      ((from === "CANDIDATE" || from === "CORROBORATED" || from === "ACKNOWLEDGED") && to === "CLOSED" && actor !== null);
    if (!ok) { this.fail("TRANSITION_INVALID"); return; }
    al.view = { ...al.view, state: to as AlertView["state"], revision };
  }

  onAlertDegraded(alertId: string, source: string | null, key: string | null, revision: string): void {
    const al = this.alerts.get(alertId);
    if (!al || al.view.assurance !== "VALID") { this.fail("TRANSITION_INVALID"); return; }
    if (uBig(revision) !== uBig(al.view.revision) + 1n) { this.fail("TRANSITION_INVALID"); return; }
    const cause = `${source ?? "-"}:${key ?? "-"}`;
    if (al.degradedCauses.has(cause)) { this.fail("TRANSITION_INVALID"); return; }
    al.degradedCauses.add(cause);
    al.view = { ...al.view, assurance: "DEGRADED", revision };
  }

  onSubChanged(sub: Subscription, ev: "OPEN" | "PAUSE" | "RESUME" | "EXPIRE" | "CLOSE"): void {
    const cur = this.subs.get(sub.id);
    const legal =
      (ev === "OPEN" && !cur && sub.state === "ACTIVE") ||
      (ev === "PAUSE" && cur?.state === "ACTIVE" && sub.state === "PAUSED") ||
      (ev === "RESUME" && cur?.state === "PAUSED" && sub.state === "ACTIVE") ||
      (ev === "EXPIRE" && (cur?.state === "ACTIVE" || cur?.state === "PAUSED") && sub.state === "EXPIRED") ||
      (ev === "CLOSE" && (cur?.state === "ACTIVE" || cur?.state === "PAUSED") && sub.state === "CLOSED");
    if (!legal) { this.fail("TRANSITION_INVALID"); return; }
    this.subs.set(sub.id, sub);
  }

  onDeliveryChanged(d: Delivery, page: Hash | null): void {
    if (page !== null && !this.objects.has(`page:${page}`)) { this.fail("OBJECT_MISSING"); return; }
    const cur = this.outbox.get(d.alert);
    const s = cur?.state ?? "NONE";
    const legal =
      (s === "NONE" && d.state === "QUEUED" && d.attempts === 0) ||
      ((s === "QUEUED" || s === "RETRY") && (d.state === "IN_FLIGHT" || d.state === "CANCELLED")) ||
      (s === "IN_FLIGHT" && (d.state === "DELIVERED" || d.state === "RETRY" || d.state === "FAILED" || d.state === "CANCELLED"));
    if (!legal) { this.fail("TRANSITION_INVALID"); return; }
    this.outbox.set(d.alert, d);
  }
}

function qualityOf(closes: SourceClose[], accepted: Accepted[]): "COMPLETE" | "INCOMPLETE" | "DEGRADED" {
  for (const c of closes) if (c.state === "FORKED" || c.revoked) return "DEGRADED";
  const anyLate = accepted.some((a) => a.late && a.entry.body.observation.kind !== "signal");
  for (const c of closes) if (c.state === "GAPPED" || c.pending > 0 || !c.complete) return "INCOMPLETE";
  if (anyLate) return "INCOMPLETE";
  return "COMPLETE";
}

function canonBytes(v: unknown): string {
  return J(v).toString("hex");
}

export function verify(input: VerifyInput): VerifyResult {
  const V = new Verifier();
  const head0: Head = { seq: "0", hash: ZERO };

  if (input.pages.length === 0) {
    return { integrity: "INVALID", replay: "INCOMPLETE", completeness: "INCOMPLETE", native_truth: "NOT_ATTESTED", head: head0, reasons: ["NO_PAGES"] };
  }

  V.rootPub = input.root.public_key;
  V.auditKeyId = input.audit.key_id;
  V.auditRootKey = input.root.key_id;
  const auditPub = input.audit.public_key;

  // --- identical signed checkpoint on every page ---------------------------
  let cp: Checkpoint | null = null;
  for (const p of input.pages) {
    if (cp === null) cp = p.checkpoint;
    else if (canonBytes(p.checkpoint) !== canonBytes(cp)) { V.fail("HASH_MISMATCH"); break; }
    const c = p.checkpoint;
    if (c.body.key_id !== input.audit.key_id || c.hash !== D("WEATHER-CHECKPOINT/1", c.body) ||
        !V.sig(c, "WEATHER-CHECKPOINT-SIGN/1", auditPub)) {
      V.fail(c.hash === D("WEATHER-CHECKPOINT/1", c.body) ? "SIGNATURE_INVALID" : "HASH_MISMATCH");
      break;
    }
  }
  if (V.integrityBad) return finish(V, head0, input.expected_head);
  const cpb = cp!.body;
  V.fleet = cpb.fleet;

  // --- object table ----------------------------------------------------------
  for (const p of input.pages) {
    for (const o of p.objects) {
      const key = `${o.kind}:${o.hash}`;
      const prior = V.objects.get(key);
      if (prior !== undefined) {
        if (canonBytes(prior) !== canonBytes(o.value)) V.fail("OBJECT_CONFLICT");
        continue;
      }
      const bodyOf = (v: unknown) => (v as { body: unknown }).body;
      const want =
        o.kind === "config" ? D("WEATHER-CONFIG/1", bodyOf(o.value)) :
        o.kind === "manifest" ? D("WEATHER-MANIFEST/1", o.value) :
        o.kind === "result" ? D("WEATHER-RESULT/1", bodyOf(o.value)) :
        D("WEATHER-PAGE/1", bodyOf(o.value));
      const declared = o.kind === "manifest" ? o.hash : (o.value as { hash: string }).hash;
      if (o.hash !== want || declared !== o.hash) { V.fail("HASH_MISMATCH"); continue; }
      V.objects.set(key, o.value);
    }
  }

  // --- audit chain: contiguity, links, monotone time, signatures -------------
  const entries: Audit[] = [];
  for (let i = 0; i < input.pages.length; i++) {
    const p = input.pages[i]!;
    if (uBig(p.after_seq) !== (i === 0 ? 0n : uBig(input.pages[i - 1]!.next_seq))) {
      V.fail("CHAIN_INVALID");
      break;
    }
    let expect = uBig(p.after_seq) + 1n;
    for (const e of p.entries) {
      if (uBig(e.body.seq) !== expect) { V.fail("CHAIN_INVALID"); break; }
      expect++;
      entries.push(e);
    }
    const lastSeq = p.entries.length > 0 ? uBig(p.entries[p.entries.length - 1]!.body.seq) : uBig(p.after_seq);
    if (uBig(p.next_seq) !== lastSeq) { V.fail("CHAIN_INVALID"); break; }
  }

  let prev = ZERO;
  let seq = 0n;
  let lastAt = -1n;
  for (const e of entries) {
    if (V.integrityBad) break;
    if (e.hash !== D("WEATHER-AUDIT/1", e.body)) { V.fail("HASH_MISMATCH"); break; }
    if (e.body.key_id !== V.auditKeyId || !V.sig(e, "WEATHER-AUDIT-SIGN/1", auditPub)) {
      V.fail("SIGNATURE_INVALID"); break;
    }
    if (e.body.fleet !== V.fleet) { V.fail("TRANSITION_INVALID"); break; }
    if (uBig(e.body.seq) !== seq + 1n || e.body.prev !== prev) { V.fail("CHAIN_INVALID"); break; }
    const at = uBig(e.body.at_ms);
    if (at < lastAt) { V.fail("CHAIN_INVALID"); break; }
    lastAt = at;
    seq++;
    prev = e.hash;
    V.positions.set(seq, e.hash);
    V.event(e.body);
  }
  if (V.pw && V.pw.got !== V.pw.expect) { V.fail("TRANSITION_INVALID"); V.pw = null; }
  const verifiedHead: Head = { seq: seq.toString(), hash: prev };

  if (!V.integrityBad && (verifiedHead.seq !== cpb.head.seq || verifiedHead.hash !== cpb.head.hash)) {
    V.fail("INCOMPLETE");
  }

  collectRefs(entries, V);
  for (const key of V.objects.keys()) {
    if (!V.referenced.has(key)) V.fail("OBJECT_CONFLICT");
  }

  return finish(V, verifiedHead, input.expected_head);
}

function collectRefs(entries: Audit[], V: Verifier): void {
  for (const e of entries) {
    const d = e.body.data as Record<string, unknown>;
    switch (e.body.kind) {
      case "ConfigScheduled":
      case "ConfigActivated":
      case "KeysRevoked":
        V.referenced.add(`config:${d["config"]}`);
        break;
      case "WindowFinalized": {
        V.referenced.add(`manifest:${d["manifest"]}`);
        const m = V.objects.get(`manifest:${d["manifest"]}`) as Manifest | undefined;
        if (m) V.referenced.add(`config:${m.config}`);
        break;
      }
      case "ResultFinalized": {
        V.referenced.add(`result:${d["result"]}`);
        const r = V.objects.get(`result:${d["result"]}`) as Result | undefined;
        if (r) { V.referenced.add(`manifest:${r.body.manifest}`); V.referenced.add(`config:${r.body.config}`); }
        break;
      }
      case "DeliveryChanged": {
        const p = (d as { page: string | null }).page;
        if (p) {
          V.referenced.add(`page:${p}`);
          const pg = V.objects.get(`page:${p}`) as { body: { config: string; manifest: string; result: string } } | undefined;
          if (pg) {
            V.referenced.add(`config:${pg.body.config}`);
            V.referenced.add(`manifest:${pg.body.manifest}`);
            V.referenced.add(`result:${pg.body.result}`);
          }
        }
        break;
      }
      default:
        break;
    }
  }
}

function finish(V: Verifier, head: Head, expected: Head | null): VerifyResult {
  const reasons = [...V.reasons];
  if (V.integrityBad) {
    return { integrity: "INVALID", replay: "INCOMPLETE", completeness: "INCOMPLETE", native_truth: "NOT_ATTESTED", head, reasons };
  }
  const replay: VerifyResult["replay"] = V.replayBad ? "MISMATCH" : (V.incomplete ? "INCOMPLETE" : "MATCH");
  let completeness: VerifyResult["completeness"];
  if (expected === null) {
    completeness = "UNPINNED_PREFIX";
  } else if (uBig(expected.seq) <= uBig(head.seq) && V.positions.get(uBig(expected.seq)) === expected.hash) {
    completeness = "AT_PIN";
  } else {
    completeness = "INCOMPLETE";
    reasons.push("HEAD_MISMATCH");
  }
  return { integrity: "VALID", replay, completeness, native_truth: "NOT_ATTESTED", head, reasons };
}

export { EMPTY_HEAD };
