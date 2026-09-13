import { WError } from "./errors.js";
import { isHash, ZERO } from "./hash.js";
import { isId, type IdPrefix } from "./ids.js";
import { isPub, isSig } from "./base64.js";
import type * as T from "./types.js";

/**
 * Closed-object, all-fields-required validators for the §3.1 IDL. Field-level
 * bounds apply the 256-element default plus the explicit §3.1 exceptions
 * (subjects 512; manifest inputs / result evidence 4096).
 */

const U_MAX = 9223372036854775807n;
const U_RE = /^(0|[1-9][0-9]{0,18})$/;

export function isU(x: unknown): x is T.U {
  return typeof x === "string" && U_RE.test(x) && BigInt(x) <= U_MAX;
}
export function u(x: unknown, what: string): T.U {
  if (!isU(x)) throw new WError("INVALID_INPUT", `${what}: not a U decimal string`);
  return x;
}
export function uBig(x: T.U): bigint {
  return BigInt(x);
}

export function isText(x: unknown): x is T.Text {
  if (typeof x !== "string") return false;
  // Unicode scalar values: JS strings may hold surrogate pairs; reject lone
  // surrogates, count code points, cap UTF-8 bytes.
  let scalars = 0;
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const c2 = x.charCodeAt(i + 1);
      if (!(c2 >= 0xdc00 && c2 <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
    else if (c < 0x20 || c === 0x7f) return false;
    scalars++;
  }
  if (scalars < 1 || scalars > 256) return false;
  return Buffer.byteLength(x, "utf8") <= 1024;
}

function bad(what: string, why: string): never {
  throw new WError("INVALID_INPUT", `${what}: ${why}`);
}

function isObj(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function closed(x: unknown, keys: readonly string[], what: string): Record<string, unknown> {
  if (!isObj(x)) bad(what, "not an object");
  const ks = Object.keys(x);
  if (ks.length !== keys.length) bad(what, `expected exactly ${keys.length} members`);
  const want = new Set(keys);
  for (const k of ks) if (!want.has(k)) bad(what, `unknown member ${k}`);
  return x;
}

function bool(x: unknown, what: string): boolean {
  if (typeof x !== "boolean") bad(what, "not boolean");
  return x;
}

function hash(x: unknown, what: string): T.Hash {
  if (!isHash(x)) bad(what, "not a 64-hex Hash");
  return x;
}

function hashOrNull(x: unknown, what: string): T.Hash | null {
  if (x === null) return null;
  return hash(x, what);
}

function text(x: unknown, what: string): T.Text {
  if (!isText(x)) bad(what, "not Text (1-256 scalars, <=1024 UTF-8 bytes, no C0/DEL)");
  return x;
}

function id(x: unknown, p: IdPrefix, what: string): string {
  if (!isId(x, p)) bad(what, `not a ${p}_ ID`);
  return x;
}

function pub(x: unknown, what: string): T.Pub {
  if (!isPub(x)) bad(what, "not a canonical 32-byte base64url public key");
  return x;
}

function sig(x: unknown, what: string): T.Sig {
  if (!isSig(x)) bad(what, "not a canonical 64-byte base64url signature");
  return x;
}

function arr(x: unknown, max: number, what: string): unknown[] {
  if (!Array.isArray(x)) bad(what, "not an array");
  if (x.length > max) bad(what, `more than ${max} elements`);
  return x;
}

function intN(x: unknown, min: number, max: number, what: string): number {
  if (typeof x !== "number" || !Number.isSafeInteger(x) || x < min || x > max) bad(what, `not an integer in [${min},${max}]`);
  return x;
}

function litV(x: unknown, v: number, what: string): void {
  if (x !== v) bad(what, `v must be ${v}`);
}

function oneOf<S extends string>(x: unknown, set: readonly S[], what: string): S {
  if (typeof x !== "string" || !(set as readonly string[]).includes(x)) bad(what, `not one of ${set.join("|")}`);
  return x as S;
}

function sortedUniqueStr(xs: string[]): boolean {
  for (let i = 1; i < xs.length; i++) if (xs[i - 1]! >= xs[i]!) return false;
  return true;
}

// ---------------------------------------------------------------- basics

export function vHead(x: unknown, what = "head"): T.Head {
  const o = closed(x, ["seq", "hash"], what);
  return { seq: u(o["seq"], what + ".seq"), hash: hash(o["hash"], what + ".hash") };
}

export function vPin(x: unknown, what = "pin"): T.Pin {
  const o = closed(x, ["key_id", "public_key"], what);
  return { key_id: id(o["key_id"], "wky", what + ".key_id"), public_key: pub(o["public_key"], what + ".public_key") };
}

const ROLES: readonly T.Role[] = ["operator", "producer", "reader", "watcher"];

export function vPrincipal(x: unknown, what = "principal"): T.Principal {
  const o = closed(x, ["id", "pin", "roles"], what);
  const roles = arr(o["roles"], 4, what + ".roles").map((r, i) => oneOf(r, ROLES, `${what}.roles[${i}]`));
  if (!sortedUniqueStr(roles)) bad(what, "roles not sorted-unique");
  return { id: id(o["id"], "wpr", what + ".id"), pin: vPin(o["pin"], what + ".pin"), roles };
}

const PROFILES: readonly T.NativeProfile[] = ["trellis-export/1", "vislineage-export/1", "weather-meter/1"];

export function vNative(x: unknown, what = "native"): T.Native {
  const o = closed(x, ["profile", "native_ref", "native_artifact", "verification"], what);
  return {
    profile: oneOf(o["profile"], PROFILES, what + ".profile"),
    native_ref: text(o["native_ref"], what + ".native_ref"),
    native_artifact: hash(o["native_artifact"], what + ".native_artifact"),
    verification: oneOf(o["verification"], ["VERIFIED_AT_PIN", "ASSERTED"] as const, what + ".verification"),
  };
}

export function vObservation(x: unknown, what = "observation"): T.Observation {
  if (!isObj(x)) bad(what, "not an object");
  const kind = x["kind"];
  switch (kind) {
    case "spend": {
      const o = closed(x, ["kind", "subject", "delta", "unit", "usage_id"], what);
      if (o["unit"] !== "usd_micro") bad(what, "unit must be usd_micro");
      return {
        kind: "spend",
        subject: id(o["subject"], "wsu", what + ".subject"),
        delta: u(o["delta"], what + ".delta"),
        unit: "usd_micro",
        usage_id: text(o["usage_id"], what + ".usage_id"),
      };
    }
    case "scope": {
      const o = closed(x, ["kind", "subject", "policy_hash", "scope_hash", "reported_violation"], what);
      return {
        kind: "scope",
        subject: id(o["subject"], "wsu", what + ".subject"),
        policy_hash: hashOrNull(o["policy_hash"], what + ".policy_hash"),
        scope_hash: hashOrNull(o["scope_hash"], what + ".scope_hash"),
        reported_violation: bool(o["reported_violation"], what + ".reported_violation"),
      };
    }
    case "replication": {
      const o = closed(x, ["kind", "subject", "processes", "threads", "declared_processes"], what);
      const nu = (v: unknown, w: string) => (v === null ? null : u(v, w));
      return {
        kind: "replication",
        subject: id(o["subject"], "wsu", what + ".subject"),
        processes: nu(o["processes"], what + ".processes"),
        threads: nu(o["threads"], what + ".threads"),
        declared_processes: nu(o["declared_processes"], what + ".declared_processes"),
      };
    }
    case "pulse":
      closed(x, ["kind"], what);
      return { kind: "pulse" };
    case "terminal":
      closed(x, ["kind"], what);
      return { kind: "terminal" };
    case "coverage": {
      const o = closed(x, ["kind", "complete"], what);
      return { kind: "coverage", complete: bool(o["complete"], what + ".complete") };
    }
    case "signal": {
      const o = closed(x, ["kind", "subject", "artifact"], what);
      return {
        kind: "signal",
        subject: id(o["subject"], "wsu", what + ".subject"),
        artifact: hash(o["artifact"], what + ".artifact"),
      };
    }
    default:
      bad(what, `unknown kind ${String(kind)}`);
  }
}

export function vSourceBody(x: unknown, what = "source_body"): T.SourceBody {
  const o = closed(x, ["v", "fleet", "source", "seq", "prev", "observed_ms", "native", "observation", "key_id"], what);
  litV(o["v"], 1, what + ".v");
  const seq = u(o["seq"], what + ".seq");
  if (seq === "0") bad(what + ".seq", "sequence starts at 1");
  return {
    v: 1,
    fleet: id(o["fleet"], "wfl", what + ".fleet"),
    source: id(o["source"], "wso", what + ".source"),
    seq,
    prev: hash(o["prev"], what + ".prev"),
    observed_ms: u(o["observed_ms"], what + ".observed_ms"),
    native: vNative(o["native"], what + ".native"),
    observation: vObservation(o["observation"], what + ".observation"),
    key_id: id(o["key_id"], "wky", what + ".key_id"),
  };
}

export function vSourceEntry(x: unknown, what = "source_entry"): T.SourceEntry {
  const o = closed(x, ["body", "hash", "sig"], what);
  return { body: vSourceBody(o["body"], what + ".body"), hash: hash(o["hash"], what + ".hash"), sig: sig(o["sig"], what + ".sig") };
}

export function vAccepted(x: unknown, what = "accepted"): T.Accepted {
  const o = closed(x, ["index", "received_ms", "entry", "late", "counted"], what);
  return {
    index: u(o["index"], what + ".index"),
    received_ms: u(o["received_ms"], what + ".received_ms"),
    entry: vSourceEntry(o["entry"], what + ".entry"),
    late: bool(o["late"], what + ".late"),
    counted: bool(o["counted"], what + ".counted"),
  };
}

const SOURCE_STATES: readonly T.SourceState[] = ["EMPTY", "ACTIVE", "GAPPED", "FORKED", "TERMINAL", "RETIRED"];

export function vSourceView(x: unknown, what = "source_view"): T.SourceView {
  const o = closed(x, ["source", "state", "head", "last_received_ms", "complete", "pending"], what);
  return {
    source: id(o["source"], "wso", what + ".source"),
    state: oneOf(o["state"], SOURCE_STATES, what + ".state"),
    head: vHead(o["head"], what + ".head"),
    last_received_ms: o["last_received_ms"] === null ? null : u(o["last_received_ms"], what + ".last_received_ms"),
    complete: bool(o["complete"], what + ".complete"),
    pending: intN(o["pending"], 0, 256, what + ".pending"),
  };
}

// ---------------------------------------------------------------- config

export function vSourceConfig(x: unknown, what = "source_config"): T.SourceConfig {
  const o = closed(x, ["id", "principal", "pin", "profile", "subjects", "meter", "enabled"], what);
  const subjects = arr(o["subjects"], 512, what + ".subjects").map((s, i) => id(s, "wsu", `${what}.subjects[${i}]`));
  if (!sortedUniqueStr(subjects)) bad(what, "subjects not sorted-unique");
  return {
    id: id(o["id"], "wso", what + ".id"),
    principal: id(o["principal"], "wpr", what + ".principal"),
    pin: vPin(o["pin"], what + ".pin"),
    profile: oneOf(o["profile"], PROFILES, what + ".profile"),
    subjects,
    meter: bool(o["meter"], what + ".meter"),
    enabled: bool(o["enabled"], what + ".enabled"),
  };
}

export function vSubjectConfig(x: unknown, what = "subject_config"): T.SubjectConfig {
  const o = closed(x, ["id", "policies", "scopes", "max_processes", "max_threads"], what);
  const policies = arr(o["policies"], 32, what + ".policies").map((p, i) => hash(p, `${what}.policies[${i}]`));
  const scopes = arr(o["scopes"], 32, what + ".scopes").map((p, i) => hash(p, `${what}.scopes[${i}]`));
  if (!sortedUniqueStr(policies)) bad(what, "policies not sorted-unique");
  if (!sortedUniqueStr(scopes)) bad(what, "scopes not sorted-unique");
  const mp = u(o["max_processes"], what + ".max_processes");
  const mt = u(o["max_threads"], what + ".max_threads");
  if (uBig(mp) < 1n || uBig(mp) > 4096n) bad(what, "max_processes out of 1..4096");
  if (uBig(mt) < 1n || uBig(mt) > 65536n) bad(what, "max_threads out of 1..65536");
  return { id: id(o["id"], "wsu", what + ".id"), policies, scopes, max_processes: mp, max_threads: mt };
}

export function vWatcherConfig(x: unknown, what = "watcher_config"): T.WatcherConfig {
  const o = closed(x, ["id", "principal", "pin", "domain", "enabled"], what);
  return {
    id: id(o["id"], "wwa", what + ".id"),
    principal: id(o["principal"], "wpr", what + ".principal"),
    pin: vPin(o["pin"], what + ".pin"),
    domain: id(o["domain"], "wdo", what + ".domain"),
    enabled: bool(o["enabled"], what + ".enabled"),
  };
}

export function vConfig(x: unknown, what = "config"): T.Config {
  const o = closed(x, [
    "v", "fleet", "epoch", "predecessor", "effective_ms", "pack", "pack_digest",
    "window_ms", "history_windows", "baseline_floor", "spend_min", "spend_multiplier",
    "silence_ms", "max_late_ms", "vote_ttl_ms", "quorum_domains",
    "sources", "subjects", "watchers", "principals", "revoked_keys", "notification_target",
  ], what);
  litV(o["v"], 1, what + ".v");
  if (o["pack"] !== "weather-core/1.0.0") bad(what, "pack must be weather-core/1.0.0");
  if (o["window_ms"] !== 60000) bad(what, "window_ms must be 60000");
  if (o["history_windows"] !== 5) bad(what, "history_windows must be 5");
  if (o["baseline_floor"] !== "100000") bad(what, "baseline_floor must be \"100000\"");
  if (o["spend_min"] !== "1000000") bad(what, "spend_min must be \"1000000\"");
  if (o["spend_multiplier"] !== 3) bad(what, "spend_multiplier must be 3");
  if (o["silence_ms"] !== 120000) bad(what, "silence_ms must be 120000");
  if (o["max_late_ms"] !== 120000) bad(what, "max_late_ms must be 120000");
  if (o["vote_ttl_ms"] !== 180000) bad(what, "vote_ttl_ms must be 180000");
  if (o["quorum_domains"] !== 2) bad(what, "quorum_domains must be 2");
  const epoch = u(o["epoch"], what + ".epoch");
  if (epoch === "0") bad(what + ".epoch", "epoch starts at 1");
  const sources = arr(o["sources"], 64, what + ".sources").map((s, i) => vSourceConfig(s, `${what}.sources[${i}]`));
  const subjects = arr(o["subjects"], 512, what + ".subjects").map((s, i) => vSubjectConfig(s, `${what}.subjects[${i}]`));
  const watchers = arr(o["watchers"], 16, what + ".watchers").map((w, i) => vWatcherConfig(w, `${what}.watchers[${i}]`));
  const principals = arr(o["principals"], 64, what + ".principals").map((p, i) => vPrincipal(p, `${what}.principals[${i}]`));
  const revoked = arr(o["revoked_keys"], 256, what + ".revoked_keys").map((k, i) => id(k, "wky", `${what}.revoked_keys[${i}]`));
  if (!sortedUniqueStr(sources.map((s) => s.id))) bad(what, "sources not sorted-unique by id");
  if (!sortedUniqueStr(subjects.map((s) => s.id))) bad(what, "subjects not sorted-unique by id");
  if (!sortedUniqueStr(watchers.map((w) => w.id))) bad(what, "watchers not sorted-unique by id");
  if (!sortedUniqueStr(principals.map((p) => p.id))) bad(what, "principals not sorted-unique by id");
  if (!sortedUniqueStr(revoked)) bad(what, "revoked_keys not sorted-unique");
  let subjSum = 0;
  for (const s of sources) subjSum += s.subjects.length;
  if (subjSum > 512) bad(what, "sum of sources' subjects exceeds 512");
  let polSum = 0;
  for (const s of subjects) polSum += s.policies.length + s.scopes.length;
  if (polSum > 256) bad(what, "sum of subjects' policies+scopes exceeds 256");
  if (o["notification_target"] !== null && o["notification_target"] !== "primary") {
    bad(what, "notification_target must be \"primary\" or null");
  }
  return {
    v: 1,
    fleet: id(o["fleet"], "wfl", what + ".fleet"),
    epoch,
    predecessor: hash(o["predecessor"], what + ".predecessor"),
    effective_ms: u(o["effective_ms"], what + ".effective_ms"),
    pack: "weather-core/1.0.0",
    pack_digest: hash(o["pack_digest"], what + ".pack_digest"),
    window_ms: 60000,
    history_windows: 5,
    baseline_floor: "100000",
    spend_min: "1000000",
    spend_multiplier: 3,
    silence_ms: 120000,
    max_late_ms: 120000,
    vote_ttl_ms: 180000,
    quorum_domains: 2,
    sources, subjects, watchers, principals,
    revoked_keys: revoked,
    notification_target: o["notification_target"] as "primary" | null,
  };
}

export function vConfigEnvelope(x: unknown, what = "config_envelope"): T.ConfigEnvelope {
  const o = closed(x, ["body", "hash", "key_id", "sig"], what);
  return {
    body: vConfig(o["body"], what + ".body"),
    hash: hash(o["hash"], what + ".hash"),
    key_id: id(o["key_id"], "wky", what + ".key_id"),
    sig: sig(o["sig"], what + ".sig"),
  };
}

// ---------------------------------------------------------------- manifest/result/vote

export function vSourceCut(x: unknown, what = "source_cut"): T.SourceCut {
  const o = closed(x, ["source", "head", "state", "activated_ms", "last_received_ms", "last_input", "complete"], what);
  const lastMs = o["last_received_ms"] === null ? null : u(o["last_received_ms"], what + ".last_received_ms");
  const lastIn = hashOrNull(o["last_input"], what + ".last_input");
  if ((lastMs === null) !== (lastIn === null)) bad(what, "last_received_ms/last_input must be null together");
  return {
    source: id(o["source"], "wso", what + ".source"),
    head: vHead(o["head"], what + ".head"),
    state: oneOf(o["state"], SOURCE_STATES, what + ".state"),
    activated_ms: u(o["activated_ms"], what + ".activated_ms"),
    last_received_ms: lastMs,
    last_input: lastIn,
    complete: bool(o["complete"], what + ".complete"),
  };
}

const QUALITIES: readonly T.Quality[] = ["COMPLETE", "INCOMPLETE", "DEGRADED"];

export function vManifest(x: unknown, what = "manifest"): T.Manifest {
  const o = closed(x, ["v", "fleet", "config", "start_ms", "end_ms", "through_index", "inputs", "history", "cuts", "quality"], what);
  litV(o["v"], 1, what + ".v");
  const inputs = arr(o["inputs"], 4096, what + ".inputs").map((h, i) => hash(h, `${what}.inputs[${i}]`));
  const history = arr(o["history"], 5, what + ".history").map((h, i) => hash(h, `${what}.history[${i}]`));
  const cuts = arr(o["cuts"], 64, what + ".cuts").map((c, i) => vSourceCut(c, `${what}.cuts[${i}]`));
  if (!sortedUniqueStr(cuts.map((c) => c.source))) bad(what, "cuts not sorted by source");
  return {
    v: 1,
    fleet: id(o["fleet"], "wfl", what + ".fleet"),
    config: hash(o["config"], what + ".config"),
    start_ms: u(o["start_ms"], what + ".start_ms"),
    end_ms: u(o["end_ms"], what + ".end_ms"),
    through_index: u(o["through_index"], what + ".through_index"),
    inputs, history, cuts,
    quality: oneOf(o["quality"], QUALITIES, what + ".quality"),
  };
}

const DETECTORS: readonly T.Detector[] = ["replication_anomaly/1", "scope_drift/1", "spend_spike/1", "stream_silence/1"];
const STATUSES: readonly T.DecisionStatus[] = ["HIT", "CLEAR", "UNKNOWN", "SIGNAL"];
const REASONS: readonly T.Reason[] = [
  "ARITHMETIC_OVERFLOW", "BASELINE_WARMUP", "BELOW_THRESHOLD", "COVERAGE_INCOMPLETE",
  "DECLARED_MISMATCH", "DRIFT_REPORTED", "EVIDENCE_MISSING", "INVENTORY_MATCH",
  "POLICY_DRIFT", "PROCESS_EXCESS", "SCOPE_DRIFT", "SCOPE_MATCH", "SIGNAL_ONLY",
  "SOURCE_TERMINAL", "SPEND_SPIKE", "STREAM_RECENT", "STREAM_SILENT", "THREAD_EXCESS",
];

export function vDecision(x: unknown, what = "decision"): T.Decision {
  const o = closed(x, ["status", "reason", "value", "limit"], what);
  return {
    status: oneOf(o["status"], STATUSES, what + ".status"),
    reason: oneOf(o["reason"], REASONS, what + ".reason"),
    value: o["value"] === null ? null : u(o["value"], what + ".value"),
    limit: o["limit"] === null ? null : u(o["limit"], what + ".limit"),
  };
}

export function vResultBody(x: unknown, what = "result_body"): T.ResultBody {
  const o = closed(x, ["v", "fleet", "config", "manifest", "detector", "target", "decision", "evidence"], what);
  litV(o["v"], 1, what + ".v");
  const target = o["target"];
  if (typeof target !== "string") bad(what, "target not a string");
  const evidence = arr(o["evidence"], 4096, what + ".evidence").map((h, i) => hash(h, `${what}.evidence[${i}]`));
  if (!sortedUniqueStr(evidence)) bad(what, "evidence not sorted-unique");
  return {
    v: 1,
    fleet: id(o["fleet"], "wfl", what + ".fleet"),
    config: hash(o["config"], what + ".config"),
    manifest: hash(o["manifest"], what + ".manifest"),
    detector: oneOf(o["detector"], DETECTORS, what + ".detector"),
    target,
    decision: vDecision(o["decision"], what + ".decision"),
    evidence,
  };
}

export function vResult(x: unknown, what = "result"): T.Result {
  const o = closed(x, ["body", "hash"], what);
  return { body: vResultBody(o["body"], what + ".body"), hash: hash(o["hash"], what + ".hash") };
}

export function vVoteBody(x: unknown, what = "vote_body"): T.VoteBody {
  const o = closed(x, ["v", "fleet", "watcher", "config", "result", "manifest", "key_id"], what);
  litV(o["v"], 1, what + ".v");
  return {
    v: 1,
    fleet: id(o["fleet"], "wfl", what + ".fleet"),
    watcher: id(o["watcher"], "wwa", what + ".watcher"),
    config: hash(o["config"], what + ".config"),
    result: hash(o["result"], what + ".result"),
    manifest: hash(o["manifest"], what + ".manifest"),
    key_id: id(o["key_id"], "wky", what + ".key_id"),
  };
}

export function vVote(x: unknown, what = "vote"): T.Vote {
  const o = closed(x, ["body", "hash", "sig"], what);
  return { body: vVoteBody(o["body"], what + ".body"), hash: hash(o["hash"], what + ".hash"), sig: sig(o["sig"], what + ".sig") };
}

// ---------------------------------------------------------------- alert/subscription/delivery

const ALERT_STATES: readonly T.AlertState[] = ["ACKNOWLEDGED", "CANDIDATE", "CLOSED", "CORROBORATED", "EXPIRED"];
const SUB_STATES: readonly T.SubscriptionState[] = ["ACTIVE", "PAUSED", "EXPIRED", "CLOSED"];
const DELIVERY_STATES: readonly T.DeliveryState[] = ["NONE", "QUEUED", "IN_FLIGHT", "RETRY", "DELIVERED", "FAILED", "CANCELLED"];

export function vAlertView(x: unknown, what = "alert_view"): T.AlertView {
  const o = closed(x, ["id", "result", "state", "assurance", "domains", "votes", "expires_ms", "delivery", "revision"], what);
  const domains = arr(o["domains"], 16, what + ".domains").map((d, i) => id(d, "wdo", `${what}.domains[${i}]`));
  const votes = arr(o["votes"], 16, what + ".votes").map((v, i) => hash(v, `${what}.votes[${i}]`));
  if (!sortedUniqueStr(domains)) bad(what, "domains not sorted-unique");
  if (!sortedUniqueStr(votes)) bad(what, "votes not sorted-unique");
  return {
    id: id(o["id"], "wal", what + ".id"),
    result: hash(o["result"], what + ".result"),
    state: oneOf(o["state"], ALERT_STATES, what + ".state"),
    assurance: oneOf(o["assurance"], ["VALID", "DEGRADED"] as const, what + ".assurance"),
    domains, votes,
    expires_ms: u(o["expires_ms"], what + ".expires_ms"),
    delivery: oneOf(o["delivery"], DELIVERY_STATES, what + ".delivery"),
    revision: u(o["revision"], what + ".revision"),
  };
}

export function vSubscription(x: unknown, what = "subscription"): T.Subscription {
  const o = closed(x, ["id", "watcher", "state", "ack", "delivered", "lease_until_ms", "revision"], what);
  const ack = u(o["ack"], what + ".ack");
  const delivered = u(o["delivered"], what + ".delivered");
  if (uBig(ack) > uBig(delivered)) bad(what, "ack > delivered");
  return {
    id: id(o["id"], "wss", what + ".id"),
    watcher: id(o["watcher"], "wwa", what + ".watcher"),
    state: oneOf(o["state"], SUB_STATES, what + ".state"),
    ack, delivered,
    lease_until_ms: u(o["lease_until_ms"], what + ".lease_until_ms"),
    revision: u(o["revision"], what + ".revision"),
  };
}

export function vPageBody(x: unknown, what = "page_body"): T.PageBody {
  const o = closed(x, ["v", "fleet", "alert", "result", "config", "manifest", "corroborated", "semantics", "key_id"], what);
  litV(o["v"], 1, what + ".v");
  if (o["semantics"] !== "ADVISORY_ONLY") bad(what, "semantics must be ADVISORY_ONLY");
  return {
    v: 1,
    fleet: id(o["fleet"], "wfl", what + ".fleet"),
    alert: id(o["alert"], "wal", what + ".alert"),
    result: hash(o["result"], what + ".result"),
    config: hash(o["config"], what + ".config"),
    manifest: hash(o["manifest"], what + ".manifest"),
    corroborated: vHead(o["corroborated"], what + ".corroborated"),
    semantics: "ADVISORY_ONLY",
    key_id: id(o["key_id"], "wky", what + ".key_id"),
  };
}

export function vPage(x: unknown, what = "page"): T.Page {
  const o = closed(x, ["body", "hash", "sig"], what);
  return { body: vPageBody(o["body"], what + ".body"), hash: hash(o["hash"], what + ".hash"), sig: sig(o["sig"], what + ".sig") };
}

export function vDelivery(x: unknown, what = "delivery"): T.Delivery {
  const o = closed(x, ["alert", "state", "attempts", "due_ms", "lease_until_ms", "last_status"], what);
  return {
    alert: id(o["alert"], "wal", what + ".alert"),
    state: oneOf(o["state"], DELIVERY_STATES, what + ".state"),
    attempts: intN(o["attempts"], 0, 8, what + ".attempts"),
    due_ms: o["due_ms"] === null ? null : u(o["due_ms"], what + ".due_ms"),
    lease_until_ms: o["lease_until_ms"] === null ? null : u(o["lease_until_ms"], what + ".lease_until_ms"),
    last_status: o["last_status"] === null ? null : intN(o["last_status"], 100, 599, what + ".last_status"),
  };
}

// ---------------------------------------------------------------- audit/checkpoint/bundle

const AUDIT_KINDS: readonly T.AuditKind[] = [
  "ConfigScheduled", "ConfigActivated", "KeysRevoked", "Tick", "SourceAccepted",
  "SourceBuffered", "SourceForkObserved", "WindowFinalized", "ResultFinalized",
  "AlertCreated", "VoteAccepted", "AlertChanged", "AlertDegraded",
  "SubscriptionChanged", "DeliveryChanged", "FleetChanged",
];

function vAuditData(kind: T.AuditKind, x: unknown, what: string): AuditDataOf<T.AuditKind> {
  switch (kind) {
    case "ConfigScheduled":
    case "ConfigActivated": {
      const o = closed(x, ["config"], what);
      return { config: hash(o["config"], what + ".config") } as AuditDataOf<T.AuditKind>;
    }
    case "KeysRevoked": {
      const o = closed(x, ["config", "keys"], what);
      const keys = arr(o["keys"], 256, what + ".keys").map((k, i) => id(k, "wky", `${what}.keys[${i}]`));
      if (!sortedUniqueStr(keys)) bad(what, "keys not sorted-unique");
      return { config: hash(o["config"], what + ".config"), keys } as AuditDataOf<T.AuditKind>;
    }
    case "Tick": {
      const o = closed(x, ["logical_ms"], what);
      return { logical_ms: u(o["logical_ms"], what + ".logical_ms") } as AuditDataOf<T.AuditKind>;
    }
    case "SourceAccepted": {
      const o = closed(x, ["accepted"], what);
      return { accepted: vAccepted(o["accepted"], what + ".accepted") } as AuditDataOf<T.AuditKind>;
    }
    case "SourceBuffered": {
      const o = closed(x, ["entry"], what);
      return { entry: vSourceEntry(o["entry"], what + ".entry") } as AuditDataOf<T.AuditKind>;
    }
    case "SourceForkObserved": {
      const o = closed(x, ["source", "left", "right", "reason"], what);
      return {
        source: id(o["source"], "wso", what + ".source"),
        left: vSourceEntry(o["left"], what + ".left"),
        right: vSourceEntry(o["right"], what + ".right"),
        reason: oneOf(o["reason"], ["SLOT_FORK", "TERMINAL_SUFFIX"] as const, what + ".reason"),
      } as AuditDataOf<T.AuditKind>;
    }
    case "WindowFinalized": {
      const o = closed(x, ["manifest", "result_count"], what);
      return { manifest: hash(o["manifest"], what + ".manifest"), result_count: intN(o["result_count"], 1, 1089, what + ".result_count") } as AuditDataOf<T.AuditKind>;
    }
    case "ResultFinalized": {
      const o = closed(x, ["result"], what);
      return { result: hash(o["result"], what + ".result") } as AuditDataOf<T.AuditKind>;
    }
    case "AlertCreated": {
      const o = closed(x, ["alert"], what);
      return { alert: vAlertView(o["alert"], what + ".alert") } as AuditDataOf<T.AuditKind>;
    }
    case "VoteAccepted": {
      const o = closed(x, ["alert", "vote"], what);
      return { alert: id(o["alert"], "wal", what + ".alert"), vote: vVote(o["vote"], what + ".vote") } as AuditDataOf<T.AuditKind>;
    }
    case "AlertChanged": {
      const o = closed(x, ["alert", "from", "to", "actor", "note_hash", "revision"], what);
      return {
        alert: id(o["alert"], "wal", what + ".alert"),
        from: oneOf(o["from"], ALERT_STATES, what + ".from"),
        to: oneOf(o["to"], ALERT_STATES, what + ".to"),
        actor: o["actor"] === null ? null : id(o["actor"], "wpr", what + ".actor"),
        note_hash: hashOrNull(o["note_hash"], what + ".note_hash"),
        revision: u(o["revision"], what + ".revision"),
      } as AuditDataOf<T.AuditKind>;
    }
    case "AlertDegraded": {
      const o = closed(x, ["alert", "source", "key", "revision"], what);
      return {
        alert: id(o["alert"], "wal", what + ".alert"),
        source: o["source"] === null ? null : id(o["source"], "wso", what + ".source"),
        key: o["key"] === null ? null : id(o["key"], "wky", what + ".key"),
        revision: u(o["revision"], what + ".revision"),
      } as AuditDataOf<T.AuditKind>;
    }
    case "SubscriptionChanged": {
      const o = closed(x, ["subscription", "event"], what);
      return {
        subscription: vSubscription(o["subscription"], what + ".subscription"),
        event: oneOf(o["event"], ["OPEN", "PAUSE", "RESUME", "EXPIRE", "CLOSE"] as const, what + ".event"),
      } as AuditDataOf<T.AuditKind>;
    }
    case "DeliveryChanged": {
      const o = closed(x, ["delivery", "page", "cancel_pending"], what);
      return {
        delivery: vDelivery(o["delivery"], what + ".delivery"),
        page: hashOrNull(o["page"], what + ".page"),
        cancel_pending: bool(o["cancel_pending"], what + ".cancel_pending"),
      } as AuditDataOf<T.AuditKind>;
    }
    case "FleetChanged": {
      const o = closed(x, ["from", "to", "reason"], what);
      return {
        from: oneOf(o["from"], ["RUNNING", "READ_ONLY", "LOCKED"] as const, what + ".from"),
        to: oneOf(o["to"], ["RUNNING", "READ_ONLY", "LOCKED"] as const, what + ".to"),
        reason: oneOf(o["reason"], ["CAPACITY", "OPERATOR"] as const, what + ".reason"),
      } as AuditDataOf<T.AuditKind>;
    }
  }
}

type AuditDataOf<K extends T.AuditKind> = T.AuditData[K];

export function vAuditBody(x: unknown, what = "audit_body"): T.AuditBody {
  if (!isObj(x)) bad(what, "not an object");
  const base = closed(x, ["v", "fleet", "event_id", "seq", "prev", "at_ms", "key_id", "kind", "data"], what);
  litV(base["v"], 1, what + ".v");
  const kind = oneOf(base["kind"], AUDIT_KINDS, what + ".kind");
  const body = {
    v: 1 as const,
    fleet: id(base["fleet"], "wfl", what + ".fleet"),
    event_id: id(base["event_id"], "wev", what + ".event_id"),
    seq: u(base["seq"], what + ".seq"),
    prev: hash(base["prev"], what + ".prev"),
    at_ms: u(base["at_ms"], what + ".at_ms"),
    key_id: id(base["key_id"], "wky", what + ".key_id"),
    kind,
    data: vAuditData(kind, base["data"], what + ".data"),
  };
  return body as T.AuditBody;
}

export function vAudit(x: unknown, what = "audit"): T.Audit {
  const o = closed(x, ["body", "hash", "sig"], what);
  return { body: vAuditBody(o["body"], what + ".body"), hash: hash(o["hash"], what + ".hash"), sig: sig(o["sig"], what + ".sig") };
}

export function vCheckpointBody(x: unknown, what = "checkpoint_body"): T.CheckpointBody {
  const o = closed(x, ["v", "fleet", "head", "through_index", "logical_ms", "config", "key_id"], what);
  litV(o["v"], 1, what + ".v");
  return {
    v: 1,
    fleet: id(o["fleet"], "wfl", what + ".fleet"),
    head: vHead(o["head"], what + ".head"),
    through_index: u(o["through_index"], what + ".through_index"),
    logical_ms: u(o["logical_ms"], what + ".logical_ms"),
    config: hashOrNull(o["config"], what + ".config"),
    key_id: id(o["key_id"], "wky", what + ".key_id"),
  };
}

export function vCheckpoint(x: unknown, what = "checkpoint"): T.Checkpoint {
  const o = closed(x, ["body", "hash", "sig"], what);
  return { body: vCheckpointBody(o["body"], what + ".body"), hash: hash(o["hash"], what + ".hash"), sig: sig(o["sig"], what + ".sig") };
}

export function vObjectRecord(x: unknown, what = "object_record"): T.ObjectRecord {
  const o = closed(x, ["kind", "hash", "value"], what);
  const kind = oneOf(o["kind"], ["config", "manifest", "result", "page"] as const, what + ".kind");
  const h = hash(o["hash"], what + ".hash");
  let value: T.ObjectRecord["value"];
  switch (kind) {
    case "config": value = vConfigEnvelope(o["value"], what + ".value"); break;
    case "manifest": value = vManifest(o["value"], what + ".value"); break;
    case "result": value = vResult(o["value"], what + ".value"); break;
    case "page": value = vPage(o["value"], what + ".value"); break;
  }
  return { kind, hash: h, value };
}

export function vBundlePage(x: unknown, what = "bundle_page"): T.BundlePage {
  const o = closed(x, ["v", "format", "checkpoint", "after_seq", "entries", "objects", "next_seq", "more", "native_disclosure"], what);
  litV(o["v"], 1, what + ".v");
  if (o["format"] !== "weather-evidence/1") bad(what, "format must be weather-evidence/1");
  if (o["native_disclosure"] !== "COMMITMENTS_ONLY") bad(what, "native_disclosure must be COMMITMENTS_ONLY");
  const entries = arr(o["entries"], 128, what + ".entries").map((e, i) => vAudit(e, `${what}.entries[${i}]`));
  const objects = arr(o["objects"], 512, what + ".objects").map((r, i) => vObjectRecord(r, `${what}.objects[${i}]`));
  return {
    v: 1, format: "weather-evidence/1",
    checkpoint: vCheckpoint(o["checkpoint"], what + ".checkpoint"),
    after_seq: u(o["after_seq"], what + ".after_seq"),
    entries, objects,
    next_seq: u(o["next_seq"], what + ".next_seq"),
    more: bool(o["more"], what + ".more"),
    native_disclosure: "COMMITMENTS_ONLY",
  };
}

// ---------------------------------------------------------------- RPC

const METHODS: readonly T.Method[] = [
  "fleet.get", "config.put", "source.append", "subscription.open", "subscription.read",
  "subscription.ack", "subscription.set", "vote.submit", "alert.list", "alert.get",
  "alert.act", "audit.read", "audit.checkpoint", "bundle.export", "metrics.get",
];

function vParams(method: T.Method, x: unknown, what: string): Calls_Input<T.Method> {
  switch (method) {
    case "fleet.get":
    case "audit.checkpoint":
    case "metrics.get":
      closed(x, [], what);
      return {} as Calls_Input<T.Method>;
    case "config.put": {
      const o = closed(x, ["config"], what);
      return { config: vConfigEnvelope(o["config"], what + ".config") } as Calls_Input<T.Method>;
    }
    case "source.append": {
      const o = closed(x, ["entries"], what);
      const entries = arr(o["entries"], 64, what + ".entries");
      if (entries.length < 1) bad(what, "entries must have 1..64");
      return { entries: entries.map((e, i) => vSourceEntry(e, `${what}.entries[${i}]`)) } as Calls_Input<T.Method>;
    }
    case "subscription.open": {
      const o = closed(x, ["watcher", "after_seq"], what);
      return { watcher: id(o["watcher"], "wwa", what + ".watcher"), after_seq: u(o["after_seq"], what + ".after_seq") } as Calls_Input<T.Method>;
    }
    case "subscription.read": {
      const o = closed(x, ["subscription", "after_seq", "limit"], what);
      return {
        subscription: id(o["subscription"], "wss", what + ".subscription"),
        after_seq: u(o["after_seq"], what + ".after_seq"),
        limit: intN(o["limit"], 1, 128, what + ".limit"),
      } as Calls_Input<T.Method>;
    }
    case "subscription.ack": {
      const o = closed(x, ["subscription", "through_seq"], what);
      return { subscription: id(o["subscription"], "wss", what + ".subscription"), through_seq: u(o["through_seq"], what + ".through_seq") } as Calls_Input<T.Method>;
    }
    case "subscription.set": {
      const o = closed(x, ["subscription", "action", "expected_revision"], what);
      return {
        subscription: id(o["subscription"], "wss", what + ".subscription"),
        action: oneOf(o["action"], ["pause", "resume", "close"] as const, what + ".action"),
        expected_revision: u(o["expected_revision"], what + ".expected_revision"),
      } as Calls_Input<T.Method>;
    }
    case "vote.submit": {
      const o = closed(x, ["vote"], what);
      return { vote: vVote(o["vote"], what + ".vote") } as Calls_Input<T.Method>;
    }
    case "alert.list": {
      const o = closed(x, ["state", "after", "limit"], what);
      return {
        state: o["state"] === null ? null : oneOf(o["state"], ALERT_STATES, what + ".state"),
        after: o["after"] === null ? null : id(o["after"], "wal", what + ".after"),
        limit: intN(o["limit"], 1, 128, what + ".limit"),
      } as Calls_Input<T.Method>;
    }
    case "alert.get": {
      const o = closed(x, ["alert"], what);
      return { alert: id(o["alert"], "wal", what + ".alert") } as Calls_Input<T.Method>;
    }
    case "alert.act": {
      const o = closed(x, ["alert", "action", "expected_revision", "note_hash"], what);
      return {
        alert: id(o["alert"], "wal", what + ".alert"),
        action: oneOf(o["action"], ["ack", "close"] as const, what + ".action"),
        expected_revision: u(o["expected_revision"], what + ".expected_revision"),
        note_hash: hashOrNull(o["note_hash"], what + ".note_hash"),
      } as Calls_Input<T.Method>;
    }
    case "audit.read": {
      const o = closed(x, ["after_seq", "through", "limit"], what);
      return {
        after_seq: u(o["after_seq"], what + ".after_seq"),
        through: o["through"] === null ? null : vHead(o["through"], what + ".through"),
        limit: intN(o["limit"], 1, 128, what + ".limit"),
      } as Calls_Input<T.Method>;
    }
    case "bundle.export": {
      const o = closed(x, ["after_seq", "checkpoint", "limit"], what);
      return {
        after_seq: u(o["after_seq"], what + ".after_seq"),
        checkpoint: vCheckpoint(o["checkpoint"], what + ".checkpoint"),
        limit: intN(o["limit"], 1, 128, what + ".limit"),
      } as Calls_Input<T.Method>;
    }
  }
}

type Calls_Input<M extends T.Method> = T.Calls[M]["input"];

export function vRequestBody(x: unknown, what = "request_body"): T.RequestBody {
  if (!isObj(x)) bad(what, "not an object");
  const o = closed(x, ["v", "fleet", "id", "key_id", "sent_ms", "method", "params"], what);
  litV(o["v"], 1, what + ".v");
  const method = oneOf(o["method"], METHODS, what + ".method");
  const body = {
    v: 1 as const,
    fleet: id(o["fleet"], "wfl", what + ".fleet"),
    id: id(o["id"], "wrq", what + ".id"),
    key_id: id(o["key_id"], "wky", what + ".key_id"),
    sent_ms: u(o["sent_ms"], what + ".sent_ms"),
    method,
    params: vParams(method, o["params"], what + ".params"),
  };
  return body as T.RequestBody;
}

export function vRequestEnvelope(x: unknown, what = "request_envelope"): T.RequestEnvelope {
  const o = closed(x, ["body", "hash", "sig"], what);
  return {
    body: vRequestBody(o["body"], what + ".body"),
    hash: hash(o["hash"], what + ".hash"),
    sig: sig(o["sig"], what + ".sig"),
  };
}

// ---------------------------------------------------------------- local file formats

export function vClientConfig(x: unknown, what = "client_config"): T.ClientConfig {
  const o = closed(x, ["v", "endpoint", "fleet", "principal_key_file", "trust_file", "timeout_ms"], what);
  litV(o["v"], 1, what + ".v");
  const endpoint = o["endpoint"];
  if (typeof endpoint !== "string" || endpoint.length < 1 || endpoint.length > 1024) bad(what, "endpoint not a string");
  const timeout = intN(o["timeout_ms"], 100, 60000, what + ".timeout_ms");
  return {
    v: 1, endpoint: endpoint as string,
    fleet: id(o["fleet"], "wfl", what + ".fleet"),
    principal_key_file: text(o["principal_key_file"], what + ".principal_key_file"),
    trust_file: text(o["trust_file"], what + ".trust_file"),
    timeout_ms: timeout,
  };
}

export function vTrustFile(x: unknown, what = "trust_file"): T.TrustFile {
  const o = closed(x, ["v", "fleet", "root", "audit", "minimum_head"], what);
  litV(o["v"], 1, what + ".v");
  return {
    v: 1,
    fleet: id(o["fleet"], "wfl", what + ".fleet"),
    root: vPin(o["root"], what + ".root"),
    audit: vPin(o["audit"], what + ".audit"),
    minimum_head: o["minimum_head"] === null ? null : vHead(o["minimum_head"], what + ".minimum_head"),
  };
}

export function vPrivateKeyFile(x: unknown, what = "private_key_file"): T.PrivateKeyFile {
  const o = closed(x, ["v", "key_id", "public_key", "seed"], what);
  litV(o["v"], 1, what + ".v");
  const seed = o["seed"];
  if (typeof seed !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(seed)) bad(what, "seed must be canonical base64url of 32 bytes");
  return {
    v: 1,
    key_id: id(o["key_id"], "wky", what + ".key_id"),
    public_key: pub(o["public_key"], what + ".public_key"),
    seed: seed as string,
  };
}

export function vBootstrap(x: unknown, what = "bootstrap"): T.Bootstrap {
  const o = closed(x, ["v", "fleets", "hard_bytes_per_fleet", "reserve_bytes", "storage_version"], what);
  litV(o["v"], 1, what + ".v");
  const fleets = arr(o["fleets"], 16, what + ".fleets").map((f, i) => {
    const fo = closed(f, ["fleet", "root", "audit", "allowed_view_origin", "primary_url"], `${what}.fleets[${i}]`);
    const avo = fo["allowed_view_origin"];
    const pu = fo["primary_url"];
    if (avo !== null && (typeof avo !== "string" || avo.length > 1024)) bad(what, "allowed_view_origin");
    if (pu !== null) {
      if (typeof pu !== "string" || pu.length > 1024) bad(what, "primary_url");
      try {
        const u = new URL(pu as string);
        if (u.protocol !== "https:" || (u.port !== "" && u.port !== "443") ||
          u.username !== "" || u.password !== "" || u.search !== "" || u.hash !== "") {
          bad(what, "primary_url must be https:443 with a fixed path, no query/fragment/credentials");
        }
      } catch (e) {
        if (e instanceof WError) throw e;
        bad(what, "primary_url must be https:443 with a fixed path, no query/fragment/credentials");
      }
    }
    return {
      fleet: id(fo["fleet"], "wfl", `${what}.fleets[${i}].fleet`),
      root: vPin(fo["root"], `${what}.fleets[${i}].root`),
      audit: vPin(fo["audit"], `${what}.fleets[${i}].audit`),
      allowed_view_origin: avo as string | null,
      primary_url: pu as string | null,
    };
  });
  if (!sortedUniqueStr(fleets.map((f) => f.fleet))) bad(what, "fleets not sorted by fleet id");
  if (o["hard_bytes_per_fleet"] !== "8589934592") bad(what, "hard_bytes_per_fleet must be \"8589934592\"");
  if (o["reserve_bytes"] !== "67108864") bad(what, "reserve_bytes must be \"67108864\"");
  if (o["storage_version"] !== 1) bad(what, "storage_version must be 1");
  return { v: 1, fleets, hard_bytes_per_fleet: "8589934592", reserve_bytes: "67108864", storage_version: 1 };
}

export function vWatcherCursor(x: unknown, what = "watcher_cursor"): T.WatcherCursor {
  const o = closed(x, ["v", "fleet", "watcher", "subscription", "ack", "head", "config", "pending_votes"], what);
  litV(o["v"], 1, what + ".v");
  const pv = arr(o["pending_votes"], 256, what + ".pending_votes").map((v, i) => vVote(v, `${what}.pending_votes[${i}]`));
  return {
    v: 1,
    fleet: id(o["fleet"], "wfl", what + ".fleet"),
    watcher: id(o["watcher"], "wwa", what + ".watcher"),
    subscription: o["subscription"] === null ? null : id(o["subscription"], "wss", what + ".subscription"),
    ack: u(o["ack"], what + ".ack"),
    head: vHead(o["head"], what + ".head"),
    config: hashOrNull(o["config"], what + ".config"),
    pending_votes: pv,
  };
}

export function vCollectorCursor(x: unknown, what = "collector_cursor"): T.CollectorCursor {
  const o = closed(x, ["v", "fleet", "source", "native_frontier", "head", "pending_entries"], what);
  litV(o["v"], 1, what + ".v");
  const pe = arr(o["pending_entries"], 256, what + ".pending_entries").map((e, i) => vSourceEntry(e, `${what}.pending_entries[${i}]`));
  return {
    v: 1,
    fleet: id(o["fleet"], "wfl", what + ".fleet"),
    source: id(o["source"], "wso", what + ".source"),
    native_frontier: text(o["native_frontier"], what + ".native_frontier"),
    head: vHead(o["head"], what + ".head"),
    pending_entries: pe,
  };
}

// ---------------------------------------------------------------- eval

export function vEvalConfig(x: unknown, what = "eval_config"): T.EvalConfig {
  const o = closed(x, ["v", "suite", "pack_digest", "seed", "allow_seed_override", "corpus_digest", "implementations"], what);
  litV(o["v"], 1, what + ".v");
  if (o["suite"] !== "weather-conformance/1") bad(what, "suite must be weather-conformance/1");
  const impls = arr(o["implementations"], 2, what + ".implementations").map((i, k) => oneOf(i, ["python", "typescript"] as const, `${what}.implementations[${k}]`));
  if (!sortedUniqueStr(impls)) bad(what, "implementations not sorted-unique");
  return {
    v: 1, suite: "weather-conformance/1",
    pack_digest: hash(o["pack_digest"], what + ".pack_digest"),
    seed: u(o["seed"], what + ".seed"),
    allow_seed_override: bool(o["allow_seed_override"], what + ".allow_seed_override"),
    corpus_digest: hash(o["corpus_digest"], what + ".corpus_digest"),
    implementations: impls,
  };
}

export function vEvalSuite(x: unknown, what = "eval_suite"): T.EvalSuite {
  const o = closed(x, ["v", "suite", "config", "units"], what);
  litV(o["v"], 1, what + ".v");
  if (o["suite"] !== "weather-conformance/1") bad(what, "suite must be weather-conformance/1");
  const units = arr(o["units"], 4096, what + ".units").map((un, i) => {
    const uo = closed(un, ["unit", "detector", "positive"], `${what}.units[${i}]`);
    return {
      unit: text(uo["unit"], `${what}.units[${i}].unit`),
      detector: oneOf(uo["detector"], DETECTORS, `${what}.units[${i}].detector`),
      positive: bool(uo["positive"], `${what}.units[${i}].positive`),
    };
  });
  return { v: 1, suite: "weather-conformance/1", config: vEvalConfig(o["config"], what + ".config"), units };
}

export function vReplayInput(x: unknown, what = "replay_input"): T.ReplayInput {
  const o = closed(x, ["config", "manifest", "accepted", "history", "last_inputs"], what);
  const accepted = arr(o["accepted"], 4096, what + ".accepted").map((a, i) => vAccepted(a, `${what}.accepted[${i}]`));
  const history = arr(o["history"], 5, what + ".history").map((h, i) => {
    const ho = closed(h, ["manifest", "accepted"], `${what}.history[${i}]`);
    return {
      manifest: vManifest(ho["manifest"], `${what}.history[${i}].manifest`),
      accepted: arr(ho["accepted"], 4096, `${what}.history[${i}].accepted`).map((a, j) => vAccepted(a, `${what}.history[${i}].accepted[${j}]`)),
    };
  });
  const lastInputs = arr(o["last_inputs"], 64, what + ".last_inputs").map((a, i) => vAccepted(a, `${what}.last_inputs[${i}]`));
  return {
    config: vConfigEnvelope(o["config"], what + ".config"),
    manifest: vManifest(o["manifest"], what + ".manifest"),
    accepted, history, last_inputs: lastInputs,
  };
}

export function vPackManifest(x: unknown, what = "pack_manifest"): T.PackManifest {
  const o = closed(x, ["v", "pack", "schema_major", "semantics", "corpus_digest", "implementations"], what);
  litV(o["v"], 1, what + ".v");
  if (o["pack"] !== "weather-core/1.0.0") bad(what, "pack must be weather-core/1.0.0");
  if (o["schema_major"] !== 1) bad(what, "schema_major must be 1");
  if (o["semantics"] !== "WEATHER-SPEC-2026-09-12/4.3") bad(what, "semantics mismatch");
  const impls = arr(o["implementations"], 2, what + ".implementations").map((im, i) => {
    const io = closed(im, ["language", "artifact_digest"], `${what}.implementations[${i}]`);
    return {
      language: oneOf(io["language"], ["python", "typescript"] as const, `${what}.implementations[${i}].language`),
      artifact_digest: hash(io["artifact_digest"], `${what}.implementations[${i}].artifact_digest`),
    };
  });
  if (!sortedUniqueStr(impls.map((i) => i.language))) bad(what, "implementations not sorted by language");
  if (impls.length !== 2) bad(what, "implementations must contain exactly python and typescript");
  return {
    v: 1, pack: "weather-core/1.0.0", schema_major: 1,
    semantics: "WEATHER-SPEC-2026-09-12/4.3",
    corpus_digest: hash(o["corpus_digest"], what + ".corpus_digest"),
    implementations: impls,
  };
}

export function vMigration(x: unknown, what = "migration"): T.Migration {
  const o = closed(x, ["v", "fleet", "from_storage", "to_storage", "tool_digest", "input_head", "backup_digest", "expected_projection"], what);
  litV(o["v"], 1, what + ".v");
  return {
    v: 1,
    fleet: id(o["fleet"], "wfl", what + ".fleet"),
    from_storage: intN(o["from_storage"], 1, 1024, what + ".from_storage"),
    to_storage: intN(o["to_storage"], 1, 1024, what + ".to_storage"),
    tool_digest: hash(o["tool_digest"], what + ".tool_digest"),
    input_head: vHead(o["input_head"], what + ".input_head"),
    backup_digest: hash(o["backup_digest"], what + ".backup_digest"),
    expected_projection: hash(o["expected_projection"], what + ".expected_projection"),
  };
}

export { ZERO };
