"""Wire-shape validators (§3.1), raising SchemaError("INVALID_INPUT") on failure.

Independent Python port of the §3.x object grammar: closed objects, U decimal
strings, canonical base64url, locked ID grammar, sorted-unique sets, and all
stated bounds.
"""

import re

from .canon import is_hash

_U_MAX = 9223372036854775807
_U_RE = re.compile(r"^(0|[1-9][0-9]{0,18})$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_ID_ALPHABET = set("_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


class SchemaError(ValueError):
    def __init__(self, msg):
        super().__init__(msg)
        self.code = "INVALID_INPUT"


def _bad(what, why):
    raise SchemaError(f"{what}: {why}")


def is_u(x) -> bool:
    return isinstance(x, str) and bool(_U_RE.match(x)) and int(x) <= _U_MAX


def u(x, what):
    if not is_u(x):
        _bad(what, "not a U decimal string")
    return x


def u_big(x):
    return int(x)


def is_text(x) -> bool:
    if not isinstance(x, str):
        return False
    scalars = 0
    i = 0
    while i < len(x):
        c = ord(x[i])
        if 0xD800 <= c <= 0xDBFF:
            if i + 1 >= len(x) or not (0xDC00 <= ord(x[i + 1]) <= 0xDFFF):
                return False
            i += 1
        elif 0xDC00 <= c <= 0xDFFF:
            return False
        elif c < 0x20 or c == 0x7F:
            return False
        scalars += 1
        i += 1
    return 1 <= scalars <= 256 and len(x.encode("utf-8")) <= 1024


def is_id(x, prefix) -> bool:
    if not isinstance(x, str) or not x.startswith(prefix + "_"):
        return False
    body = x[len(prefix) + 1:]
    return len(body) == 21 and all(c in _ID_ALPHABET for c in body)


def is_pub(s) -> bool:
    import base64
    if not isinstance(s, str) or not _B64URL.match(s):
        return False
    try:
        b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return False
    return len(b) == 32 and base64.urlsafe_b64encode(b).decode().rstrip("=") == s


def is_sig(s) -> bool:
    import base64
    if not isinstance(s, str) or not _B64URL.match(s):
        return False
    try:
        b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return False
    return len(b) == 64 and base64.urlsafe_b64encode(b).decode().rstrip("=") == s


def _closed(x, keys, what):
    if not isinstance(x, dict):
        _bad(what, "not an object")
    if len(x) != len(keys):
        _bad(what, f"expected exactly {len(keys)} members")
    want = set(keys)
    for k in x:
        if k not in want:
            _bad(what, f"unknown member {k}")
    return x


def _bool(x, what):
    if not isinstance(x, bool):
        _bad(what, "not boolean")
    return x


def _hash(x, what):
    if not is_hash(x):
        _bad(what, "not a 64-hex Hash")
    return x


def _hash_or_null(x, what):
    return None if x is None else _hash(x, what)


def _text(x, what):
    if not is_text(x):
        _bad(what, "not Text (1-256 scalars, <=1024 UTF-8 bytes, no C0/DEL)")
    return x


def _id(x, p, what):
    if not is_id(x, p):
        _bad(what, f"not a {p}_ ID")
    return x


def _pub(x, what):
    if not is_pub(x):
        _bad(what, "not a canonical 32-byte base64url public key")
    return x


def _sig(x, what):
    if not is_sig(x):
        _bad(what, "not a canonical 64-byte base64url signature")
    return x


def _arr(x, mx, what):
    if not isinstance(x, list):
        _bad(what, "not an array")
    if len(x) > mx:
        _bad(what, f"more than {mx} elements")
    return x


def _int_n(x, lo, hi, what):
    if not isinstance(x, int) or isinstance(x, bool) or x < lo or x > hi:
        _bad(what, f"not an integer in [{lo},{hi}]")
    return x


def _lit_v(x, v, what):
    if x != v:
        _bad(what, f"v must be {v}")


def _one_of(x, opts, what):
    if x not in opts:
        _bad(what, f"not one of {'|'.join(opts)}")
    return x


def _sorted_unique(xs):
    return all(xs[i - 1] < xs[i] for i in range(1, len(xs)))


# ------------------------------------------------------------------ basics

def v_head(x, what="head"):
    o = _closed(x, ["seq", "hash"], what)
    return {"seq": u(o["seq"], what + ".seq"), "hash": _hash(o["hash"], what + ".hash")}


def v_pin(x, what="pin"):
    o = _closed(x, ["key_id", "public_key"], what)
    return {"key_id": _id(o["key_id"], "wky", what + ".key_id"),
            "public_key": _pub(o["public_key"], what + ".public_key")}


_ROLES = ["operator", "producer", "reader", "watcher"]


def v_principal(x, what="principal"):
    o = _closed(x, ["id", "pin", "roles"], what)
    roles = [_one_of(r, _ROLES, f"{what}.roles[{i}]") for i, r in enumerate(_arr(o["roles"], 4, what + ".roles"))]
    if not _sorted_unique(roles):
        _bad(what, "roles not sorted-unique")
    return {"id": _id(o["id"], "wpr", what + ".id"), "pin": v_pin(o["pin"], what + ".pin"), "roles": roles}


_PROFILES = ["trellis-export/1", "vislineage-export/1", "weather-meter/1"]


def v_native(x, what="native"):
    o = _closed(x, ["profile", "native_ref", "native_artifact", "verification"], what)
    return {
        "profile": _one_of(o["profile"], _PROFILES, what + ".profile"),
        "native_ref": _text(o["native_ref"], what + ".native_ref"),
        "native_artifact": _hash(o["native_artifact"], what + ".native_artifact"),
        "verification": _one_of(o["verification"], ["VERIFIED_AT_PIN", "ASSERTED"], what + ".verification"),
    }


def v_observation(x, what="observation"):
    if not isinstance(x, dict):
        _bad(what, "not an object")
    kind = x.get("kind")
    if kind == "spend":
        o = _closed(x, ["kind", "subject", "delta", "unit", "usage_id"], what)
        if o["unit"] != "usd_micro":
            _bad(what, "unit must be usd_micro")
        return {"kind": "spend", "subject": _id(o["subject"], "wsu", what + ".subject"),
                "delta": u(o["delta"], what + ".delta"), "unit": "usd_micro",
                "usage_id": _text(o["usage_id"], what + ".usage_id")}
    if kind == "scope":
        o = _closed(x, ["kind", "subject", "policy_hash", "scope_hash", "reported_violation"], what)
        return {"kind": "scope", "subject": _id(o["subject"], "wsu", what + ".subject"),
                "policy_hash": _hash_or_null(o["policy_hash"], what + ".policy_hash"),
                "scope_hash": _hash_or_null(o["scope_hash"], what + ".scope_hash"),
                "reported_violation": _bool(o["reported_violation"], what + ".reported_violation")}
    if kind == "replication":
        o = _closed(x, ["kind", "subject", "processes", "threads", "declared_processes"], what)
        nu = lambda v, w: None if v is None else u(v, w)
        return {"kind": "replication", "subject": _id(o["subject"], "wsu", what + ".subject"),
                "processes": nu(o["processes"], what + ".processes"),
                "threads": nu(o["threads"], what + ".threads"),
                "declared_processes": nu(o["declared_processes"], what + ".declared_processes")}
    if kind == "pulse":
        _closed(x, ["kind"], what)
        return {"kind": "pulse"}
    if kind == "terminal":
        _closed(x, ["kind"], what)
        return {"kind": "terminal"}
    if kind == "coverage":
        o = _closed(x, ["kind", "complete"], what)
        return {"kind": "coverage", "complete": _bool(o["complete"], what + ".complete")}
    if kind == "signal":
        o = _closed(x, ["kind", "subject", "artifact"], what)
        return {"kind": "signal", "subject": _id(o["subject"], "wsu", what + ".subject"),
                "artifact": _hash(o["artifact"], what + ".artifact")}
    _bad(what, f"unknown kind {kind}")


def v_source_body(x, what="source_body"):
    o = _closed(x, ["v", "fleet", "source", "seq", "prev", "observed_ms", "native", "observation", "key_id"], what)
    _lit_v(o["v"], 1, what + ".v")
    seq = u(o["seq"], what + ".seq")
    if seq == "0":
        _bad(what + ".seq", "sequence starts at 1")
    return {
        "v": 1,
        "fleet": _id(o["fleet"], "wfl", what + ".fleet"),
        "source": _id(o["source"], "wso", what + ".source"),
        "seq": seq,
        "prev": _hash(o["prev"], what + ".prev"),
        "observed_ms": u(o["observed_ms"], what + ".observed_ms"),
        "native": v_native(o["native"], what + ".native"),
        "observation": v_observation(o["observation"], what + ".observation"),
        "key_id": _id(o["key_id"], "wky", what + ".key_id"),
    }


def v_source_entry(x, what="source_entry"):
    o = _closed(x, ["body", "hash", "sig"], what)
    return {"body": v_source_body(o["body"], what + ".body"),
            "hash": _hash(o["hash"], what + ".hash"),
            "sig": _sig(o["sig"], what + ".sig")}


def v_accepted(x, what="accepted"):
    o = _closed(x, ["index", "received_ms", "entry", "late", "counted"], what)
    return {"index": u(o["index"], what + ".index"),
            "received_ms": u(o["received_ms"], what + ".received_ms"),
            "entry": v_source_entry(o["entry"], what + ".entry"),
            "late": _bool(o["late"], what + ".late"),
            "counted": _bool(o["counted"], what + ".counted")}


_SOURCE_STATES = ["EMPTY", "ACTIVE", "GAPPED", "FORKED", "TERMINAL", "RETIRED"]


def v_source_view(x, what="source_view"):
    o = _closed(x, ["source", "state", "head", "last_received_ms", "complete", "pending"], what)
    return {
        "source": _id(o["source"], "wso", what + ".source"),
        "state": _one_of(o["state"], _SOURCE_STATES, what + ".state"),
        "head": v_head(o["head"], what + ".head"),
        "last_received_ms": None if o["last_received_ms"] is None else u(o["last_received_ms"], what + ".last_received_ms"),
        "complete": _bool(o["complete"], what + ".complete"),
        "pending": _int_n(o["pending"], 0, 256, what + ".pending"),
    }


# ------------------------------------------------------------------ config

def v_source_config(x, what="source_config"):
    o = _closed(x, ["id", "principal", "pin", "profile", "subjects", "meter", "enabled"], what)
    subjects = [_id(s, "wsu", f"{what}.subjects[{i}]") for i, s in enumerate(_arr(o["subjects"], 512, what + ".subjects"))]
    if not _sorted_unique(subjects):
        _bad(what, "subjects not sorted-unique")
    return {
        "id": _id(o["id"], "wso", what + ".id"),
        "principal": _id(o["principal"], "wpr", what + ".principal"),
        "pin": v_pin(o["pin"], what + ".pin"),
        "profile": _one_of(o["profile"], _PROFILES, what + ".profile"),
        "subjects": subjects,
        "meter": _bool(o["meter"], what + ".meter"),
        "enabled": _bool(o["enabled"], what + ".enabled"),
    }


def v_subject_config(x, what="subject_config"):
    o = _closed(x, ["id", "policies", "scopes", "max_processes", "max_threads"], what)
    policies = [_hash(p, f"{what}.policies[{i}]") for i, p in enumerate(_arr(o["policies"], 32, what + ".policies"))]
    scopes = [_hash(s, f"{what}.scopes[{i}]") for i, s in enumerate(_arr(o["scopes"], 32, what + ".scopes"))]
    if not _sorted_unique(policies):
        _bad(what, "policies not sorted-unique")
    if not _sorted_unique(scopes):
        _bad(what, "scopes not sorted-unique")
    mp = int(u(o["max_processes"], what + ".max_processes"))
    mt = int(u(o["max_threads"], what + ".max_threads"))
    if not 1 <= mp <= 4096:
        _bad(what, "max_processes out of 1..4096")
    if not 1 <= mt <= 65536:
        _bad(what, "max_threads out of 1..65536")
    return {"id": _id(o["id"], "wsu", what + ".id"), "policies": policies, "scopes": scopes,
            "max_processes": str(mp), "max_threads": str(mt)}


def v_watcher_config(x, what="watcher_config"):
    o = _closed(x, ["id", "principal", "pin", "domain", "enabled"], what)
    return {
        "id": _id(o["id"], "wwa", what + ".id"),
        "principal": _id(o["principal"], "wpr", what + ".principal"),
        "pin": v_pin(o["pin"], what + ".pin"),
        "domain": _id(o["domain"], "wdo", what + ".domain"),
        "enabled": _bool(o["enabled"], what + ".enabled"),
    }


def v_config(x, what="config"):
    o = _closed(x, [
        "v", "fleet", "epoch", "predecessor", "effective_ms", "pack", "pack_digest",
        "window_ms", "history_windows", "baseline_floor", "spend_min", "spend_multiplier",
        "silence_ms", "max_late_ms", "vote_ttl_ms", "quorum_domains",
        "sources", "subjects", "watchers", "principals", "revoked_keys", "notification_target",
    ], what)
    _lit_v(o["v"], 1, what + ".v")
    if o["pack"] != "weather-core/1.0.0":
        _bad(what, "pack must be weather-core/1.0.0")
    if o["window_ms"] != 60000:
        _bad(what, "window_ms must be 60000")
    if o["history_windows"] != 5:
        _bad(what, "history_windows must be 5")
    if o["baseline_floor"] != "100000":
        _bad(what, 'baseline_floor must be "100000"')
    if o["spend_min"] != "1000000":
        _bad(what, 'spend_min must be "1000000"')
    if o["spend_multiplier"] != 3:
        _bad(what, "spend_multiplier must be 3")
    if o["silence_ms"] != 120000:
        _bad(what, "silence_ms must be 120000")
    if o["max_late_ms"] != 120000:
        _bad(what, "max_late_ms must be 120000")
    if o["vote_ttl_ms"] != 180000:
        _bad(what, "vote_ttl_ms must be 180000")
    if o["quorum_domains"] != 2:
        _bad(what, "quorum_domains must be 2")
    epoch = u(o["epoch"], what + ".epoch")
    if epoch == "0":
        _bad(what + ".epoch", "epoch starts at 1")
    sources = [v_source_config(s, f"{what}.sources[{i}]") for i, s in enumerate(_arr(o["sources"], 64, what + ".sources"))]
    subjects = [v_subject_config(s, f"{what}.subjects[{i}]") for i, s in enumerate(_arr(o["subjects"], 512, what + ".subjects"))]
    watchers = [v_watcher_config(w, f"{what}.watchers[{i}]") for i, w in enumerate(_arr(o["watchers"], 16, what + ".watchers"))]
    principals = [v_principal(p, f"{what}.principals[{i}]") for i, p in enumerate(_arr(o["principals"], 64, what + ".principals"))]
    revoked = [_id(k, "wky", f"{what}.revoked_keys[{i}]") for i, k in enumerate(_arr(o["revoked_keys"], 256, what + ".revoked_keys"))]
    if not _sorted_unique([s["id"] for s in sources]):
        _bad(what, "sources not sorted-unique by id")
    if not _sorted_unique([s["id"] for s in subjects]):
        _bad(what, "subjects not sorted-unique by id")
    if not _sorted_unique([w["id"] for w in watchers]):
        _bad(what, "watchers not sorted-unique by id")
    if not _sorted_unique([p["id"] for p in principals]):
        _bad(what, "principals not sorted-unique by id")
    if not _sorted_unique(revoked):
        _bad(what, "revoked_keys not sorted-unique")
    if sum(len(s["subjects"]) for s in sources) > 512:
        _bad(what, "sum of sources' subjects exceeds 512")
    if sum(len(s["policies"]) + len(s["scopes"]) for s in subjects) > 256:
        _bad(what, "sum of subjects' policies+scopes exceeds 256")
    if o["notification_target"] not in (None, "primary"):
        _bad(what, 'notification_target must be "primary" or null')
    return {
        "v": 1,
        "fleet": _id(o["fleet"], "wfl", what + ".fleet"),
        "epoch": epoch,
        "predecessor": _hash(o["predecessor"], what + ".predecessor"),
        "effective_ms": u(o["effective_ms"], what + ".effective_ms"),
        "pack": "weather-core/1.0.0",
        "pack_digest": _hash(o["pack_digest"], what + ".pack_digest"),
        "window_ms": 60000,
        "history_windows": 5,
        "baseline_floor": "100000",
        "spend_min": "1000000",
        "spend_multiplier": 3,
        "silence_ms": 120000,
        "max_late_ms": 120000,
        "vote_ttl_ms": 180000,
        "quorum_domains": 2,
        "sources": sources, "subjects": subjects, "watchers": watchers, "principals": principals,
        "revoked_keys": revoked,
        "notification_target": o["notification_target"],
    }


def v_config_envelope(x, what="config_envelope"):
    o = _closed(x, ["body", "hash", "key_id", "sig"], what)
    return {"body": v_config(o["body"], what + ".body"),
            "hash": _hash(o["hash"], what + ".hash"),
            "key_id": _id(o["key_id"], "wky", what + ".key_id"),
            "sig": _sig(o["sig"], what + ".sig")}


# ------------------------------------------------------------------ manifest/result/vote

def v_source_cut(x, what="source_cut"):
    o = _closed(x, ["source", "head", "state", "activated_ms", "last_received_ms", "last_input", "complete"], what)
    last_ms = None if o["last_received_ms"] is None else u(o["last_received_ms"], what + ".last_received_ms")
    last_in = _hash_or_null(o["last_input"], what + ".last_input")
    if (last_ms is None) != (last_in is None):
        _bad(what, "last_received_ms/last_input must be null together")
    return {
        "source": _id(o["source"], "wso", what + ".source"),
        "head": v_head(o["head"], what + ".head"),
        "state": _one_of(o["state"], _SOURCE_STATES, what + ".state"),
        "activated_ms": u(o["activated_ms"], what + ".activated_ms"),
        "last_received_ms": last_ms,
        "last_input": last_in,
        "complete": _bool(o["complete"], what + ".complete"),
    }


_QUALITIES = ["COMPLETE", "INCOMPLETE", "DEGRADED"]


def v_manifest(x, what="manifest"):
    o = _closed(x, ["v", "fleet", "config", "start_ms", "end_ms", "through_index", "inputs", "history", "cuts", "quality"], what)
    _lit_v(o["v"], 1, what + ".v")
    inputs = [_hash(h, f"{what}.inputs[{i}]") for i, h in enumerate(_arr(o["inputs"], 4096, what + ".inputs"))]
    history = [_hash(h, f"{what}.history[{i}]") for i, h in enumerate(_arr(o["history"], 5, what + ".history"))]
    cuts = [v_source_cut(c, f"{what}.cuts[{i}]") for i, c in enumerate(_arr(o["cuts"], 64, what + ".cuts"))]
    if not _sorted_unique([c["source"] for c in cuts]):
        _bad(what, "cuts not sorted by source")
    return {
        "v": 1,
        "fleet": _id(o["fleet"], "wfl", what + ".fleet"),
        "config": _hash(o["config"], what + ".config"),
        "start_ms": u(o["start_ms"], what + ".start_ms"),
        "end_ms": u(o["end_ms"], what + ".end_ms"),
        "through_index": u(o["through_index"], what + ".through_index"),
        "inputs": inputs, "history": history, "cuts": cuts,
        "quality": _one_of(o["quality"], _QUALITIES, what + ".quality"),
    }


_DETECTORS = ["replication_anomaly/1", "scope_drift/1", "spend_spike/1", "stream_silence/1"]
_STATUSES = ["HIT", "CLEAR", "UNKNOWN", "SIGNAL"]
_REASONS = [
    "ARITHMETIC_OVERFLOW", "BASELINE_WARMUP", "BELOW_THRESHOLD", "COVERAGE_INCOMPLETE",
    "DECLARED_MISMATCH", "DRIFT_REPORTED", "EVIDENCE_MISSING", "INVENTORY_MATCH",
    "POLICY_DRIFT", "PROCESS_EXCESS", "SCOPE_DRIFT", "SCOPE_MATCH", "SIGNAL_ONLY",
    "SOURCE_TERMINAL", "SPEND_SPIKE", "STREAM_RECENT", "STREAM_SILENT", "THREAD_EXCESS",
]


def v_decision(x, what="decision"):
    o = _closed(x, ["status", "reason", "value", "limit"], what)
    return {
        "status": _one_of(o["status"], _STATUSES, what + ".status"),
        "reason": _one_of(o["reason"], _REASONS, what + ".reason"),
        "value": None if o["value"] is None else u(o["value"], what + ".value"),
        "limit": None if o["limit"] is None else u(o["limit"], what + ".limit"),
    }


def v_result_body(x, what="result_body"):
    o = _closed(x, ["v", "fleet", "config", "manifest", "detector", "target", "decision", "evidence"], what)
    _lit_v(o["v"], 1, what + ".v")
    if not isinstance(o["target"], str):
        _bad(what, "target not a string")
    evidence = [_hash(h, f"{what}.evidence[{i}]") for i, h in enumerate(_arr(o["evidence"], 4096, what + ".evidence"))]
    if not _sorted_unique(evidence):
        _bad(what, "evidence not sorted-unique")
    return {
        "v": 1,
        "fleet": _id(o["fleet"], "wfl", what + ".fleet"),
        "config": _hash(o["config"], what + ".config"),
        "manifest": _hash(o["manifest"], what + ".manifest"),
        "detector": _one_of(o["detector"], _DETECTORS, what + ".detector"),
        "target": o["target"],
        "decision": v_decision(o["decision"], what + ".decision"),
        "evidence": evidence,
    }


def v_result(x, what="result"):
    o = _closed(x, ["body", "hash"], what)
    return {"body": v_result_body(o["body"], what + ".body"), "hash": _hash(o["hash"], what + ".hash")}


def v_vote_body(x, what="vote_body"):
    o = _closed(x, ["v", "fleet", "watcher", "config", "result", "manifest", "key_id"], what)
    _lit_v(o["v"], 1, what + ".v")
    return {
        "v": 1,
        "fleet": _id(o["fleet"], "wfl", what + ".fleet"),
        "watcher": _id(o["watcher"], "wwa", what + ".watcher"),
        "config": _hash(o["config"], what + ".config"),
        "result": _hash(o["result"], what + ".result"),
        "manifest": _hash(o["manifest"], what + ".manifest"),
        "key_id": _id(o["key_id"], "wky", what + ".key_id"),
    }


def v_vote(x, what="vote"):
    o = _closed(x, ["body", "hash", "sig"], what)
    return {"body": v_vote_body(o["body"], what + ".body"),
            "hash": _hash(o["hash"], what + ".hash"),
            "sig": _sig(o["sig"], what + ".sig")}


# ------------------------------------------------------------------ alert/subscription/delivery

_ALERT_STATES = ["ACKNOWLEDGED", "CANDIDATE", "CLOSED", "CORROBORATED", "EXPIRED"]
_SUB_STATES = ["ACTIVE", "PAUSED", "EXPIRED", "CLOSED"]
_DELIVERY_STATES = ["NONE", "QUEUED", "IN_FLIGHT", "RETRY", "DELIVERED", "FAILED", "CANCELLED"]


def v_alert_view(x, what="alert_view"):
    o = _closed(x, ["id", "result", "state", "assurance", "domains", "votes", "expires_ms", "delivery", "revision"], what)
    domains = [_id(d, "wdo", f"{what}.domains[{i}]") for i, d in enumerate(_arr(o["domains"], 16, what + ".domains"))]
    votes = [_hash(v, f"{what}.votes[{i}]") for i, v in enumerate(_arr(o["votes"], 16, what + ".votes"))]
    if not _sorted_unique(domains):
        _bad(what, "domains not sorted-unique")
    if not _sorted_unique(votes):
        _bad(what, "votes not sorted-unique")
    return {
        "id": _id(o["id"], "wal", what + ".id"),
        "result": _hash(o["result"], what + ".result"),
        "state": _one_of(o["state"], _ALERT_STATES, what + ".state"),
        "assurance": _one_of(o["assurance"], ["VALID", "DEGRADED"], what + ".assurance"),
        "domains": domains, "votes": votes,
        "expires_ms": u(o["expires_ms"], what + ".expires_ms"),
        "delivery": _one_of(o["delivery"], _DELIVERY_STATES, what + ".delivery"),
        "revision": u(o["revision"], what + ".revision"),
    }


def v_subscription(x, what="subscription"):
    o = _closed(x, ["id", "watcher", "state", "ack", "delivered", "lease_until_ms", "revision"], what)
    ack = u(o["ack"], what + ".ack")
    delivered = u(o["delivered"], what + ".delivered")
    if int(ack) > int(delivered):
        _bad(what, "ack > delivered")
    return {
        "id": _id(o["id"], "wss", what + ".id"),
        "watcher": _id(o["watcher"], "wwa", what + ".watcher"),
        "state": _one_of(o["state"], _SUB_STATES, what + ".state"),
        "ack": ack, "delivered": delivered,
        "lease_until_ms": u(o["lease_until_ms"], what + ".lease_until_ms"),
        "revision": u(o["revision"], what + ".revision"),
    }


def v_page_body(x, what="page_body"):
    o = _closed(x, ["v", "fleet", "alert", "result", "config", "manifest", "corroborated", "semantics", "key_id"], what)
    _lit_v(o["v"], 1, what + ".v")
    if o["semantics"] != "ADVISORY_ONLY":
        _bad(what, "semantics must be ADVISORY_ONLY")
    return {
        "v": 1,
        "fleet": _id(o["fleet"], "wfl", what + ".fleet"),
        "alert": _id(o["alert"], "wal", what + ".alert"),
        "result": _hash(o["result"], what + ".result"),
        "config": _hash(o["config"], what + ".config"),
        "manifest": _hash(o["manifest"], what + ".manifest"),
        "corroborated": v_head(o["corroborated"], what + ".corroborated"),
        "semantics": "ADVISORY_ONLY",
        "key_id": _id(o["key_id"], "wky", what + ".key_id"),
    }


def v_page(x, what="page"):
    o = _closed(x, ["body", "hash", "sig"], what)
    return {"body": v_page_body(o["body"], what + ".body"),
            "hash": _hash(o["hash"], what + ".hash"),
            "sig": _sig(o["sig"], what + ".sig")}


def v_delivery(x, what="delivery"):
    o = _closed(x, ["alert", "state", "attempts", "due_ms", "lease_until_ms", "last_status"], what)
    return {
        "alert": _id(o["alert"], "wal", what + ".alert"),
        "state": _one_of(o["state"], _DELIVERY_STATES, what + ".state"),
        "attempts": _int_n(o["attempts"], 0, 8, what + ".attempts"),
        "due_ms": None if o["due_ms"] is None else u(o["due_ms"], what + ".due_ms"),
        "lease_until_ms": None if o["lease_until_ms"] is None else u(o["lease_until_ms"], what + ".lease_until_ms"),
        "last_status": None if o["last_status"] is None else _int_n(o["last_status"], 100, 599, what + ".last_status"),
    }


# ------------------------------------------------------------------ audit/checkpoint/bundle

_AUDIT_KINDS = [
    "ConfigScheduled", "ConfigActivated", "KeysRevoked", "Tick", "SourceAccepted",
    "SourceBuffered", "SourceForkObserved", "WindowFinalized", "ResultFinalized",
    "AlertCreated", "VoteAccepted", "AlertChanged", "AlertDegraded",
    "SubscriptionChanged", "DeliveryChanged", "FleetChanged",
]


def _v_audit_data(kind, x, what):
    if kind in ("ConfigScheduled", "ConfigActivated"):
        o = _closed(x, ["config"], what)
        return {"config": _hash(o["config"], what + ".config")}
    if kind == "KeysRevoked":
        o = _closed(x, ["config", "keys"], what)
        keys = [_id(k, "wky", f"{what}.keys[{i}]") for i, k in enumerate(_arr(o["keys"], 256, what + ".keys"))]
        if not _sorted_unique(keys):
            _bad(what, "keys not sorted-unique")
        return {"config": _hash(o["config"], what + ".config"), "keys": keys}
    if kind == "Tick":
        o = _closed(x, ["logical_ms"], what)
        return {"logical_ms": u(o["logical_ms"], what + ".logical_ms")}
    if kind == "SourceAccepted":
        o = _closed(x, ["accepted"], what)
        return {"accepted": v_accepted(o["accepted"], what + ".accepted")}
    if kind == "SourceBuffered":
        o = _closed(x, ["entry"], what)
        return {"entry": v_source_entry(o["entry"], what + ".entry")}
    if kind == "SourceForkObserved":
        o = _closed(x, ["source", "left", "right", "reason"], what)
        return {
            "source": _id(o["source"], "wso", what + ".source"),
            "left": v_source_entry(o["left"], what + ".left"),
            "right": v_source_entry(o["right"], what + ".right"),
            "reason": _one_of(o["reason"], ["SLOT_FORK", "TERMINAL_SUFFIX"], what + ".reason"),
        }
    if kind == "WindowFinalized":
        o = _closed(x, ["manifest", "result_count"], what)
        return {"manifest": _hash(o["manifest"], what + ".manifest"),
                "result_count": _int_n(o["result_count"], 1, 1089, what + ".result_count")}
    if kind == "ResultFinalized":
        o = _closed(x, ["result"], what)
        return {"result": _hash(o["result"], what + ".result")}
    if kind == "AlertCreated":
        o = _closed(x, ["alert"], what)
        return {"alert": v_alert_view(o["alert"], what + ".alert")}
    if kind == "VoteAccepted":
        o = _closed(x, ["alert", "vote"], what)
        return {"alert": _id(o["alert"], "wal", what + ".alert"), "vote": v_vote(o["vote"], what + ".vote")}
    if kind == "AlertChanged":
        o = _closed(x, ["alert", "from", "to", "actor", "note_hash", "revision"], what)
        return {
            "alert": _id(o["alert"], "wal", what + ".alert"),
            "from": _one_of(o["from"], _ALERT_STATES, what + ".from"),
            "to": _one_of(o["to"], _ALERT_STATES, what + ".to"),
            "actor": None if o["actor"] is None else _id(o["actor"], "wpr", what + ".actor"),
            "note_hash": _hash_or_null(o["note_hash"], what + ".note_hash"),
            "revision": u(o["revision"], what + ".revision"),
        }
    if kind == "AlertDegraded":
        o = _closed(x, ["alert", "source", "key", "revision"], what)
        return {
            "alert": _id(o["alert"], "wal", what + ".alert"),
            "source": None if o["source"] is None else _id(o["source"], "wso", what + ".source"),
            "key": None if o["key"] is None else _id(o["key"], "wky", what + ".key"),
            "revision": u(o["revision"], what + ".revision"),
        }
    if kind == "SubscriptionChanged":
        o = _closed(x, ["subscription", "event"], what)
        return {
            "subscription": v_subscription(o["subscription"], what + ".subscription"),
            "event": _one_of(o["event"], ["OPEN", "PAUSE", "RESUME", "EXPIRE", "CLOSE"], what + ".event"),
        }
    if kind == "DeliveryChanged":
        o = _closed(x, ["delivery", "page", "cancel_pending"], what)
        return {
            "delivery": v_delivery(o["delivery"], what + ".delivery"),
            "page": _hash_or_null(o["page"], what + ".page"),
            "cancel_pending": _bool(o["cancel_pending"], what + ".cancel_pending"),
        }
    if kind == "FleetChanged":
        o = _closed(x, ["from", "to", "reason"], what)
        return {
            "from": _one_of(o["from"], ["RUNNING", "READ_ONLY", "LOCKED"], what + ".from"),
            "to": _one_of(o["to"], ["RUNNING", "READ_ONLY", "LOCKED"], what + ".to"),
            "reason": _one_of(o["reason"], ["CAPACITY", "OPERATOR"], what + ".reason"),
        }
    _bad(what, f"unknown kind {kind}")


def v_audit_body(x, what="audit_body"):
    if not isinstance(x, dict):
        _bad(what, "not an object")
    base = _closed(x, ["v", "fleet", "event_id", "seq", "prev", "at_ms", "key_id", "kind", "data"], what)
    _lit_v(base["v"], 1, what + ".v")
    kind = _one_of(base["kind"], _AUDIT_KINDS, what + ".kind")
    return {
        "v": 1,
        "fleet": _id(base["fleet"], "wfl", what + ".fleet"),
        "event_id": _id(base["event_id"], "wev", what + ".event_id"),
        "seq": u(base["seq"], what + ".seq"),
        "prev": _hash(base["prev"], what + ".prev"),
        "at_ms": u(base["at_ms"], what + ".at_ms"),
        "key_id": _id(base["key_id"], "wky", what + ".key_id"),
        "kind": kind,
        "data": _v_audit_data(kind, base["data"], what + ".data"),
    }


def v_audit(x, what="audit"):
    o = _closed(x, ["body", "hash", "sig"], what)
    return {"body": v_audit_body(o["body"], what + ".body"),
            "hash": _hash(o["hash"], what + ".hash"),
            "sig": _sig(o["sig"], what + ".sig")}


def v_checkpoint_body(x, what="checkpoint_body"):
    o = _closed(x, ["v", "fleet", "head", "through_index", "logical_ms", "config", "key_id"], what)
    _lit_v(o["v"], 1, what + ".v")
    return {
        "v": 1,
        "fleet": _id(o["fleet"], "wfl", what + ".fleet"),
        "head": v_head(o["head"], what + ".head"),
        "through_index": u(o["through_index"], what + ".through_index"),
        "logical_ms": u(o["logical_ms"], what + ".logical_ms"),
        "config": _hash_or_null(o["config"], what + ".config"),
        "key_id": _id(o["key_id"], "wky", what + ".key_id"),
    }


def v_checkpoint(x, what="checkpoint"):
    o = _closed(x, ["body", "hash", "sig"], what)
    return {"body": v_checkpoint_body(o["body"], what + ".body"),
            "hash": _hash(o["hash"], what + ".hash"),
            "sig": _sig(o["sig"], what + ".sig")}


def v_object_record(x, what="object_record"):
    o = _closed(x, ["kind", "hash", "value"], what)
    kind = _one_of(o["kind"], ["config", "manifest", "result", "page"], what + ".kind")
    h = _hash(o["hash"], what + ".hash")
    value = {
        "config": v_config_envelope,
        "manifest": v_manifest,
        "result": v_result,
        "page": v_page,
    }[kind](o["value"], what + ".value")
    return {"kind": kind, "hash": h, "value": value}


def v_bundle_page(x, what="bundle_page"):
    o = _closed(x, ["v", "format", "checkpoint", "after_seq", "entries", "objects", "next_seq", "more", "native_disclosure"], what)
    _lit_v(o["v"], 1, what + ".v")
    if o["format"] != "weather-evidence/1":
        _bad(what, "format must be weather-evidence/1")
    if o["native_disclosure"] != "COMMITMENTS_ONLY":
        _bad(what, "native_disclosure must be COMMITMENTS_ONLY")
    entries = [v_audit(e, f"{what}.entries[{i}]") for i, e in enumerate(_arr(o["entries"], 128, what + ".entries"))]
    objects = [v_object_record(r, f"{what}.objects[{i}]") for i, r in enumerate(_arr(o["objects"], 512, what + ".objects"))]
    return {
        "v": 1, "format": "weather-evidence/1",
        "checkpoint": v_checkpoint(o["checkpoint"], what + ".checkpoint"),
        "after_seq": u(o["after_seq"], what + ".after_seq"),
        "entries": entries, "objects": objects,
        "next_seq": u(o["next_seq"], what + ".next_seq"),
        "more": _bool(o["more"], what + ".more"),
        "native_disclosure": "COMMITMENTS_ONLY",
    }


# ------------------------------------------------------------------ RPC

_METHODS = [
    "fleet.get", "config.put", "source.append", "subscription.open", "subscription.read",
    "subscription.ack", "subscription.set", "vote.submit", "alert.list", "alert.get",
    "alert.act", "audit.read", "audit.checkpoint", "bundle.export", "metrics.get",
]


def _v_params(method, x, what):
    if method in ("fleet.get", "audit.checkpoint", "metrics.get"):
        _closed(x, [], what)
        return {}
    if method == "config.put":
        o = _closed(x, ["config"], what)
        return {"config": v_config_envelope(o["config"], what + ".config")}
    if method == "source.append":
        o = _closed(x, ["entries"], what)
        entries = _arr(o["entries"], 64, what + ".entries")
        if len(entries) < 1:
            _bad(what, "entries must have 1..64")
        return {"entries": [v_source_entry(e, f"{what}.entries[{i}]") for i, e in enumerate(entries)]}
    if method == "subscription.open":
        o = _closed(x, ["watcher", "after_seq"], what)
        return {"watcher": _id(o["watcher"], "wwa", what + ".watcher"),
                "after_seq": u(o["after_seq"], what + ".after_seq")}
    if method == "subscription.read":
        o = _closed(x, ["subscription", "after_seq", "limit"], what)
        return {"subscription": _id(o["subscription"], "wss", what + ".subscription"),
                "after_seq": u(o["after_seq"], what + ".after_seq"),
                "limit": _int_n(o["limit"], 1, 128, what + ".limit")}
    if method == "subscription.ack":
        o = _closed(x, ["subscription", "through_seq"], what)
        return {"subscription": _id(o["subscription"], "wss", what + ".subscription"),
                "through_seq": u(o["through_seq"], what + ".through_seq")}
    if method == "subscription.set":
        o = _closed(x, ["subscription", "action", "expected_revision"], what)
        return {"subscription": _id(o["subscription"], "wss", what + ".subscription"),
                "action": _one_of(o["action"], ["pause", "resume", "close"], what + ".action"),
                "expected_revision": u(o["expected_revision"], what + ".expected_revision")}
    if method == "vote.submit":
        o = _closed(x, ["vote"], what)
        return {"vote": v_vote(o["vote"], what + ".vote")}
    if method == "alert.list":
        o = _closed(x, ["state", "after", "limit"], what)
        return {
            "state": None if o["state"] is None else _one_of(o["state"], _ALERT_STATES, what + ".state"),
            "after": None if o["after"] is None else _id(o["after"], "wal", what + ".after"),
            "limit": _int_n(o["limit"], 1, 128, what + ".limit"),
        }
    if method == "alert.get":
        o = _closed(x, ["alert"], what)
        return {"alert": _id(o["alert"], "wal", what + ".alert")}
    if method == "alert.act":
        o = _closed(x, ["alert", "action", "expected_revision", "note_hash"], what)
        return {
            "alert": _id(o["alert"], "wal", what + ".alert"),
            "action": _one_of(o["action"], ["ack", "close"], what + ".action"),
            "expected_revision": u(o["expected_revision"], what + ".expected_revision"),
            "note_hash": _hash_or_null(o["note_hash"], what + ".note_hash"),
        }
    if method == "audit.read":
        o = _closed(x, ["after_seq", "through", "limit"], what)
        return {"after_seq": u(o["after_seq"], what + ".after_seq"),
                "through": None if o["through"] is None else v_head(o["through"], what + ".through"),
                "limit": _int_n(o["limit"], 1, 128, what + ".limit")}
    if method == "bundle.export":
        o = _closed(x, ["after_seq", "checkpoint", "limit"], what)
        return {"after_seq": u(o["after_seq"], what + ".after_seq"),
                "checkpoint": v_checkpoint(o["checkpoint"], what + ".checkpoint"),
                "limit": _int_n(o["limit"], 1, 128, what + ".limit")}
    _bad(what, f"unknown method {method}")


def v_request_body(x, what="request_body"):
    if not isinstance(x, dict):
        _bad(what, "not an object")
    o = _closed(x, ["v", "fleet", "id", "key_id", "sent_ms", "method", "params"], what)
    _lit_v(o["v"], 1, what + ".v")
    method = _one_of(o["method"], _METHODS, what + ".method")
    return {
        "v": 1,
        "fleet": _id(o["fleet"], "wfl", what + ".fleet"),
        "id": _id(o["id"], "wrq", what + ".id"),
        "key_id": _id(o["key_id"], "wky", what + ".key_id"),
        "sent_ms": u(o["sent_ms"], what + ".sent_ms"),
        "method": method,
        "params": _v_params(method, o["params"], what + ".params"),
    }


def v_request_envelope(x, what="request_envelope"):
    o = _closed(x, ["body", "hash", "sig"], what)
    return {"body": v_request_body(o["body"], what + ".body"),
            "hash": _hash(o["hash"], what + ".hash"),
            "sig": _sig(o["sig"], what + ".sig")}


# ------------------------------------------------------------------ local file formats

def v_client_config(x, what="client_config"):
    o = _closed(x, ["v", "endpoint", "fleet", "principal_key_file", "trust_file", "timeout_ms"], what)
    _lit_v(o["v"], 1, what + ".v")
    if not isinstance(o["endpoint"], str) or not 1 <= len(o["endpoint"]) <= 1024:
        _bad(what, "endpoint not a string")
    return {
        "v": 1, "endpoint": o["endpoint"],
        "fleet": _id(o["fleet"], "wfl", what + ".fleet"),
        "principal_key_file": _text(o["principal_key_file"], what + ".principal_key_file"),
        "trust_file": _text(o["trust_file"], what + ".trust_file"),
        "timeout_ms": _int_n(o["timeout_ms"], 100, 60000, what + ".timeout_ms"),
    }


def v_trust_file(x, what="trust_file"):
    o = _closed(x, ["v", "fleet", "root", "audit", "minimum_head"], what)
    _lit_v(o["v"], 1, what + ".v")
    return {
        "v": 1,
        "fleet": _id(o["fleet"], "wfl", what + ".fleet"),
        "root": v_pin(o["root"], what + ".root"),
        "audit": v_pin(o["audit"], what + ".audit"),
        "minimum_head": None if o["minimum_head"] is None else v_head(o["minimum_head"], what + ".minimum_head"),
    }


def v_private_key_file(x, what="private_key_file"):
    o = _closed(x, ["v", "key_id", "public_key", "seed"], what)
    _lit_v(o["v"], 1, what + ".v")
    seed = o["seed"]
    if not isinstance(seed, str) or not re.match(r"^[A-Za-z0-9_-]{43}$", seed):
        _bad(what, "seed must be canonical base64url of 32 bytes")
    return {"v": 1, "key_id": _id(o["key_id"], "wky", what + ".key_id"),
            "public_key": _pub(o["public_key"], what + ".public_key"), "seed": seed}


def v_bootstrap(x, what="bootstrap"):
    o = _closed(x, ["v", "fleets", "hard_bytes_per_fleet", "reserve_bytes", "storage_version"], what)
    _lit_v(o["v"], 1, what + ".v")
    fleets = []
    for i, f in enumerate(_arr(o["fleets"], 16, what + ".fleets")):
        fo = _closed(f, ["fleet", "root", "audit", "allowed_view_origin", "primary_url"], f"{what}.fleets[{i}]")
        avo, pu = fo["allowed_view_origin"], fo["primary_url"]
        if avo is not None and (not isinstance(avo, str) or len(avo) > 1024):
            _bad(what, "allowed_view_origin")
        if pu is not None and (not isinstance(pu, str) or len(pu) > 1024):
            _bad(what, "primary_url")
        fleets.append({
            "fleet": _id(fo["fleet"], "wfl", f"{what}.fleets[{i}].fleet"),
            "root": v_pin(fo["root"], f"{what}.fleets[{i}].root"),
            "audit": v_pin(fo["audit"], f"{what}.fleets[{i}].audit"),
            "allowed_view_origin": avo,
            "primary_url": pu,
        })
    if not _sorted_unique([f["fleet"] for f in fleets]):
        _bad(what, "fleets not sorted by fleet id")
    if o["hard_bytes_per_fleet"] != "8589934592":
        _bad(what, 'hard_bytes_per_fleet must be "8589934592"')
    if o["reserve_bytes"] != "67108864":
        _bad(what, 'reserve_bytes must be "67108864"')
    if o["storage_version"] != 1:
        _bad(what, "storage_version must be 1")
    return {"v": 1, "fleets": fleets, "hard_bytes_per_fleet": "8589934592",
            "reserve_bytes": "67108864", "storage_version": 1}


def v_watcher_cursor(x, what="watcher_cursor"):
    o = _closed(x, ["v", "fleet", "watcher", "subscription", "ack", "head", "config", "pending_votes"], what)
    _lit_v(o["v"], 1, what + ".v")
    pv = [v_vote(v, f"{what}.pending_votes[{i}]") for i, v in enumerate(_arr(o["pending_votes"], 256, what + ".pending_votes"))]
    return {
        "v": 1,
        "fleet": _id(o["fleet"], "wfl", what + ".fleet"),
        "watcher": _id(o["watcher"], "wwa", what + ".watcher"),
        "subscription": None if o["subscription"] is None else _id(o["subscription"], "wss", what + ".subscription"),
        "ack": u(o["ack"], what + ".ack"),
        "head": v_head(o["head"], what + ".head"),
        "config": _hash_or_null(o["config"], what + ".config"),
        "pending_votes": pv,
    }


def v_collector_cursor(x, what="collector_cursor"):
    o = _closed(x, ["v", "fleet", "source", "native_frontier", "head", "pending_entries"], what)
    _lit_v(o["v"], 1, what + ".v")
    pe = [v_source_entry(e, f"{what}.pending_entries[{i}]") for i, e in enumerate(_arr(o["pending_entries"], 256, what + ".pending_entries"))]
    return {
        "v": 1,
        "fleet": _id(o["fleet"], "wfl", what + ".fleet"),
        "source": _id(o["source"], "wso", what + ".source"),
        "native_frontier": _text(o["native_frontier"], what + ".native_frontier"),
        "head": v_head(o["head"], what + ".head"),
        "pending_entries": pe,
    }


# ------------------------------------------------------------------ eval

def v_eval_config(x, what="eval_config"):
    o = _closed(x, ["v", "suite", "pack_digest", "seed", "allow_seed_override", "corpus_digest", "implementations"], what)
    _lit_v(o["v"], 1, what + ".v")
    if o["suite"] != "weather-conformance/1":
        _bad(what, "suite must be weather-conformance/1")
    impls = [_one_of(i, ["python", "typescript"], f"{what}.implementations[{k}]")
             for k, i in enumerate(_arr(o["implementations"], 2, what + ".implementations"))]
    if not _sorted_unique(impls):
        _bad(what, "implementations not sorted-unique")
    return {
        "v": 1, "suite": "weather-conformance/1",
        "pack_digest": _hash(o["pack_digest"], what + ".pack_digest"),
        "seed": u(o["seed"], what + ".seed"),
        "allow_seed_override": _bool(o["allow_seed_override"], what + ".allow_seed_override"),
        "corpus_digest": _hash(o["corpus_digest"], what + ".corpus_digest"),
        "implementations": impls,
    }


def v_eval_suite(x, what="eval_suite"):
    o = _closed(x, ["v", "suite", "config", "units"], what)
    _lit_v(o["v"], 1, what + ".v")
    if o["suite"] != "weather-conformance/1":
        _bad(what, "suite must be weather-conformance/1")
    units = []
    for i, un in enumerate(_arr(o["units"], 4096, what + ".units")):
        uo = _closed(un, ["unit", "detector", "positive"], f"{what}.units[{i}]")
        units.append({
            "unit": _text(uo["unit"], f"{what}.units[{i}].unit"),
            "detector": _one_of(uo["detector"], _DETECTORS, f"{what}.units[{i}].detector"),
            "positive": _bool(uo["positive"], f"{what}.units[{i}].positive"),
        })
    return {"v": 1, "suite": "weather-conformance/1",
            "config": v_eval_config(o["config"], what + ".config"), "units": units}


def v_replay_input(x, what="replay_input"):
    o = _closed(x, ["config", "manifest", "accepted", "history", "last_inputs"], what)
    accepted = [v_accepted(a, f"{what}.accepted[{i}]") for i, a in enumerate(_arr(o["accepted"], 4096, what + ".accepted"))]
    history = []
    for i, h in enumerate(_arr(o["history"], 5, what + ".history")):
        ho = _closed(h, ["manifest", "accepted"], f"{what}.history[{i}]")
        history.append({
            "manifest": v_manifest(ho["manifest"], f"{what}.history[{i}].manifest"),
            "accepted": [v_accepted(a, f"{what}.history[{i}].accepted[{j}]")
                         for j, a in enumerate(_arr(ho["accepted"], 4096, f"{what}.history[{i}].accepted"))],
        })
    last_inputs = [v_accepted(a, f"{what}.last_inputs[{i}]") for i, a in enumerate(_arr(o["last_inputs"], 64, what + ".last_inputs"))]
    return {
        "config": v_config_envelope(o["config"], what + ".config"),
        "manifest": v_manifest(o["manifest"], what + ".manifest"),
        "accepted": accepted, "history": history, "last_inputs": last_inputs,
    }


def v_pack_manifest(x, what="pack_manifest"):
    o = _closed(x, ["v", "pack", "schema_major", "semantics", "corpus_digest", "implementations"], what)
    _lit_v(o["v"], 1, what + ".v")
    if o["pack"] != "weather-core/1.0.0":
        _bad(what, "pack must be weather-core/1.0.0")
    if o["schema_major"] != 1:
        _bad(what, "schema_major must be 1")
    if o["semantics"] != "WEATHER-SPEC-2026-09-12/4.3":
        _bad(what, "semantics mismatch")
    impls = []
    for i, im in enumerate(_arr(o["implementations"], 2, what + ".implementations")):
        io = _closed(im, ["language", "artifact_digest"], f"{what}.implementations[{i}]")
        impls.append({
            "language": _one_of(io["language"], ["python", "typescript"], f"{what}.implementations[{i}].language"),
            "artifact_digest": _hash(io["artifact_digest"], f"{what}.implementations[{i}].artifact_digest"),
        })
    if not _sorted_unique([i["language"] for i in impls]):
        _bad(what, "implementations not sorted by language")
    if len(impls) != 2:
        _bad(what, "implementations must contain exactly python and typescript")
    return {
        "v": 1, "pack": "weather-core/1.0.0", "schema_major": 1,
        "semantics": "WEATHER-SPEC-2026-09-12/4.3",
        "corpus_digest": _hash(o["corpus_digest"], what + ".corpus_digest"),
        "implementations": impls,
    }


def v_migration(x, what="migration"):
    o = _closed(x, ["v", "fleet", "from_storage", "to_storage", "tool_digest", "input_head", "backup_digest", "expected_projection"], what)
    _lit_v(o["v"], 1, what + ".v")
    return {
        "v": 1,
        "fleet": _id(o["fleet"], "wfl", what + ".fleet"),
        "from_storage": _int_n(o["from_storage"], 1, 1024, what + ".from_storage"),
        "to_storage": _int_n(o["to_storage"], 1, 1024, what + ".to_storage"),
        "tool_digest": _hash(o["tool_digest"], what + ".tool_digest"),
        "input_head": v_head(o["input_head"], what + ".input_head"),
        "backup_digest": _hash(o["backup_digest"], what + ".backup_digest"),
        "expected_projection": _hash(o["expected_projection"], what + ".expected_projection"),
    }
