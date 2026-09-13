#!/usr/bin/env python3
"""weather/1 §6.2 RPC request/response fixture generator.

Emits the fifteen canonical signed request/response pairs defined by the
WEATHER specification, one canonical JSON object per line on stdout.
Deliberately public deterministic test keys bytes([n])*32 — forbidden in real
deployments. Python 3.12+, requires the pinned `cryptography` dependency.
"""
import base64
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def J(x):
    return json.dumps(x, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def H(b):
    return hashlib.sha256(b).hexdigest()


def D(tag, x):
    return H(tag.encode() + b"\0" + J(x))


def B(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def I(prefix, char):
    return prefix + "_" + char * 21


KEYS = {n: Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32) for n in range(1, 7)}


def pin(n):
    return {"key_id": I("wky", str(n)), "public_key": B(KEYS[n].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))}


def signed(body, kind, n):
    h = D("WEATHER-" + kind + "/1", body)
    sig = B(KEYS[n].sign(("WEATHER-" + kind + "-SIGN/1").encode() + b"\0" + bytes.fromhex(h)))
    return {"body": body, "hash": h, "sig": sig}


F, S, U = I("wfl", "F"), I("wso", "S"), I("wsu", "U")
W1, W2, D1, D2 = I("wwa", "A"), I("wwa", "B"), I("wdo", "A"), I("wdo", "B")
P3, P4, P5, P6 = [I("wpr", str(n)) for n in range(3, 7)]
Z, H1, H2 = "0" * 64, H(b"observed-policy"), H(b"allowed-policy")
EMPTY = {"seq": "0", "hash": Z}
C = {"v": 1, "fleet": F, "epoch": "1", "predecessor": Z, "effective_ms": "60000", "pack": "weather-core/1.0.0", "pack_digest": H(b"weather-test-pack"), "window_ms": 60000, "history_windows": 5, "baseline_floor": "100000", "spend_min": "1000000", "spend_multiplier": 3, "silence_ms": 120000, "max_late_ms": 120000, "vote_ttl_ms": 180000, "quorum_domains": 2,
     "sources": [{"id": S, "principal": P3, "pin": pin(3), "profile": "trellis-export/1", "subjects": [U], "meter": False, "enabled": True}],
     "subjects": [{"id": U, "policies": [H2], "scopes": [], "max_processes": "1", "max_threads": "8"}],
     "watchers": [{"id": W1, "principal": P4, "pin": pin(4), "domain": D1, "enabled": True}, {"id": W2, "principal": P5, "pin": pin(5), "domain": D2, "enabled": True}],
     "principals": [{"id": P3, "pin": pin(3), "roles": ["producer"]}, {"id": P4, "pin": pin(4), "roles": ["watcher"]}, {"id": P5, "pin": pin(5), "roles": ["watcher"]}, {"id": P6, "pin": pin(6), "roles": ["operator", "reader"]}], "revoked_keys": [], "notification_target": None}
CE = signed(C, "CONFIG", 1)
CE["key_id"] = pin(1)["key_id"]
E = signed({"v": 1, "fleet": F, "source": S, "seq": "1", "prev": Z, "observed_ms": "65000", "native": {"profile": "trellis-export/1", "native_ref": "fixture/run/1/scope/0", "native_artifact": H(b"native-fixture"), "verification": "VERIFIED_AT_PIN"}, "observation": {"kind": "scope", "subject": U, "policy_hash": H1, "scope_hash": None, "reported_violation": False}, "key_id": pin(3)["key_id"]}, "SOURCE", 3)
SV = {"source": S, "state": "ACTIVE", "head": {"seq": "1", "hash": E["hash"]}, "last_received_ms": "65000", "complete": True, "pending": 0}
M = {"v": 1, "fleet": F, "config": CE["hash"], "start_ms": "60000", "end_ms": "120000", "through_index": "1", "inputs": [E["hash"]], "history": [], "cuts": [dict({k: SV[k] for k in ("source", "head", "state", "last_received_ms", "complete")}, activated_ms="60000", last_input=E["hash"])], "quality": "COMPLETE"}
MH = D("WEATHER-MANIFEST/1", M)
RB = {"v": 1, "fleet": F, "config": CE["hash"], "manifest": MH, "detector": "scope_drift/1", "target": U, "decision": {"status": "HIT", "reason": "POLICY_DRIFT", "value": None, "limit": None}, "evidence": [E["hash"]]}
R = {"body": RB, "hash": D("WEATHER-RESULT/1", RB)}
V = signed({"v": 1, "fleet": F, "watcher": W1, "config": CE["hash"], "result": R["hash"], "manifest": MH, "key_id": pin(4)["key_id"]}, "VOTE", 4)
A = {"id": I("wal", "A"), "result": R["hash"], "state": "CANDIDATE", "assurance": "VALID", "domains": [], "votes": [], "expires_ms": "300000", "delivery": "NONE", "revision": "1"}
CP0 = signed({"v": 1, "fleet": F, "head": EMPTY, "through_index": "0", "logical_ms": "0", "config": None, "key_id": pin(2)["key_id"]}, "CHECKPOINT", 2)
SUB = {"id": I("wss", "S"), "watcher": W1, "state": "ACTIVE", "ack": "2", "delivered": "2", "lease_until_ms": "365000", "revision": "1"}


def audit(seq, prev, at, kind, data):
    body = {"v": 1, "fleet": F, "event_id": I("wev", chr(64 + seq)), "seq": str(seq), "prev": prev, "at_ms": at, "key_id": pin(2)["key_id"], "kind": kind, "data": data}
    return signed(body, "AUDIT", 2)


AU1 = audit(1, Z, "0", "ConfigScheduled", {"config": CE["hash"]})
AU2 = audit(2, AU1["hash"], "60000", "Tick", {"logical_ms": "60000"})
AU3 = audit(3, AU2["hash"], "60000", "ConfigActivated", {"config": CE["hash"]})
AU4 = audit(4, AU3["hash"], "65000", "Tick", {"logical_ms": "65000"})
AU5 = audit(5, AU4["hash"], "65000", "SubscriptionChanged", {"subscription": SUB, "event": "OPEN"})
HEAD5 = {"seq": "5", "hash": AU5["hash"]}


def result(detector, target, decision, evidence):
    body = dict(RB, detector=detector, target=target, decision=decision, evidence=evidence)
    return {"body": body, "hash": D("WEATHER-RESULT/1", body)}


SP = result("spend_spike/1", F, {"status": "UNKNOWN", "reason": "EVIDENCE_MISSING", "value": None, "limit": None}, [])
SI = result("stream_silence/1", S, {"status": "CLEAR", "reason": "STREAM_RECENT", "value": "55000", "limit": "120000"}, [E["hash"]])
V2 = signed(dict(V["body"], watcher=W2, key_id=pin(5)["key_id"]), "VOTE", 5)
PAGE_LOG = [AU1, AU2, AU3, AU4, AU5]
for at, kind, data in [("65000", "SourceAccepted", {"accepted": {"index": "1", "received_ms": "65000", "entry": E, "late": False, "counted": True}}), ("120000", "Tick", {"logical_ms": "120000"}), ("120000", "WindowFinalized", {"manifest": MH, "result_count": 3}), ("120000", "ResultFinalized", {"result": R["hash"]}), ("120000", "ResultFinalized", {"result": SP["hash"]}), ("120000", "ResultFinalized", {"result": SI["hash"]}), ("120000", "AlertCreated", {"alert": A}), ("120001", "Tick", {"logical_ms": "120001"}), ("120001", "VoteAccepted", {"alert": A["id"], "vote": V}), ("120001", "VoteAccepted", {"alert": A["id"], "vote": V2}), ("120001", "AlertChanged", {"alert": A["id"], "from": "CANDIDATE", "to": "CORROBORATED", "actor": None, "note_hash": None, "revision": "4"})]:
    PAGE_LOG.append(audit(len(PAGE_LOG) + 1, PAGE_LOG[-1]["hash"], at, kind, data))
CORROBORATED_HEAD = {"seq": str(len(PAGE_LOG)), "hash": PAGE_LOG[-1]["hash"]}
PAGE = signed({"v": 1, "fleet": F, "alert": A["id"], "result": R["hash"], "config": CE["hash"], "manifest": MH, "corroborated": CORROBORATED_HEAD, "semantics": "ADVISORY_ONLY", "key_id": pin(2)["key_id"]}, "PAGE", 2)
EMPTY_PAGE = {"entries": [], "objects": [], "through": EMPTY, "next_seq": "0", "more": False}
COUNTS = {"candidate": 0, "corroborated": 0, "acknowledged": 0, "closed": 0, "expired": 0}
EXAMPLES = []


def pair(method, params, result, n=6, now="65000"):
    body = {"v": 1, "fleet": F, "id": I("wrq", "Q"), "key_id": pin(n)["key_id"], "sent_ms": now, "method": method, "params": params}
    EXAMPLES.append({"request": signed(body, "REQUEST", n), "response": {"v": 1, "id": body["id"], "ok": True, "result": result}})


pair("fleet.get", {}, {"fleet": F, "phase": "RUNNING", "logical_ms": "0", "config": None, "pending": None, "head": EMPTY, "through_index": "0", "sources": [], "alerts": COUNTS, "paging": "PAGING_UNAVAILABLE", "catching_up": False}, 1, "0")
pair("config.put", {"config": CE}, {"hash": CE["hash"], "state": "PENDING", "effective_ms": "60000"}, 1, "0")
pair("source.append", {"entries": [E]}, {"items": [{"seq": "1", "status": "ACCEPTED", "index": "1", "counted": True}], "source": SV}, 3)
pair("subscription.open", {"watcher": W1, "after_seq": "2"}, SUB, 4)
pair("subscription.read", {"subscription": SUB["id"], "after_seq": "5", "limit": 128}, {"entries": [], "objects": [], "through": HEAD5, "next_seq": "5", "more": False}, 4)
pair("subscription.ack", {"subscription": SUB["id"], "through_seq": "5"}, dict(SUB, ack="5", delivered="5", revision="2"), 4)
pair("subscription.set", {"subscription": SUB["id"], "action": "pause", "expected_revision": "2"}, dict(SUB, state="PAUSED", ack="5", delivered="5", revision="3"), 4)
pair("vote.submit", {"vote": V}, {"accepted": True, "alert": dict(A, domains=[D1], votes=[V["hash"]], revision="2")}, 4, "120001")
pair("alert.list", {"state": "CANDIDATE", "after": None, "limit": 128}, {"alerts": [A], "next": None}, 6, "120001")
pair("alert.get", {"alert": A["id"]}, {"alert": A, "result": R, "manifest": M}, 6, "120001")
pair("alert.act", {"alert": A["id"], "action": "close", "expected_revision": "1", "note_hash": None}, dict(A, state="CLOSED", revision="2"), 6, "120001")
pair("audit.read", {"after_seq": "0", "through": EMPTY, "limit": 128}, EMPTY_PAGE, 1, "0")
pair("audit.checkpoint", {}, CP0, 1, "0")
pair("bundle.export", {"after_seq": "0", "checkpoint": CP0, "limit": 128}, {"v": 1, "format": "weather-evidence/1", "checkpoint": CP0, "after_seq": "0", "entries": [], "objects": [], "next_seq": "0", "more": False, "native_disclosure": "COMMITMENTS_ONLY"}, 1, "0")
pair("metrics.get", {}, {"fleet": F, "samples": []}, 1, "0")
for example in EXAMPLES:
    print(J(example).decode())
