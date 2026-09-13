"""§13 kernel ops — compact pure units for the conformance vectors."""

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canon import J, H, D, is_hash
from .crypto import canonical_point, canonical_signature, is_id
from .detectors import spend, spend_sum, scope, replication, silence, signal_decision
from .schema import is_u
from .strictjson import parse_text, StrictError


def _kerr(code):
    return {"error": code}


def _need_u(x, name):
    if not is_u(x):
        raise ValueError(name)
    return int(x)


_RETRY_DELAYS = [1000, 2000, 4000, 8000, 16000, 32000, 60000]


def _op_sequence(i):
    if i.get("sig_valid") is not True:
        return _kerr("SIGNATURE_INVALID")
    head = _need_u(i.get("head"), "head")
    pending = [_need_u(p, "pending") for p in i.get("pending", [])]
    seq = _need_u(i.get("seq"), "seq")
    known = i.get("known")
    prev_matches = i.get("prev_matches") is True

    base = {"state": "ACTIVE", "head": str(head), "pending": [str(p) for p in pending], "drained": []}
    if known == "SAME":
        return {"status": "DUPLICATE", **base}
    if known == "DIFFERENT":
        return {"status": "FORK", "state": "FORKED", "head": str(head),
                "pending": [str(p) for p in pending], "drained": []}
    if seq <= head:
        return _kerr("CHAIN_INVALID")
    if seq > head + 256:
        return _kerr("GAP_LIMIT")
    pend = set(pending)
    drained = []
    h = head
    if seq == h + 1:
        if not prev_matches:
            return _kerr("CHAIN_INVALID")
        drained.append(seq)
        h = seq
        status = "ACCEPTED"
        while h + 1 in pend:
            h += 1
            drained.append(h)
            pend.discard(h)
    else:
        pend.add(seq)
        status = "BUFFERED"
    return {
        "status": status,
        "state": "ACTIVE" if not pend else "GAPPED",
        "head": str(h),
        "pending": [str(p) for p in sorted(pend)],
        "drained": [str(d) for d in drained],
    }


def run_kernel(inp):
    op = inp.get("op")
    if op == "canonical":
        utf8 = J(inp["value"]).decode("utf-8")
        return {"utf8": utf8, "sha256": H(utf8.encode("utf-8"))}
    if op == "digest":
        return {"hash": D(str(inp["tag"]), inp["value"])}
    if op == "ed25519":
        pub = bytes.fromhex(str(inp["public_hex"]))
        msg = bytes.fromhex(str(inp["message_hex"]))
        sig = bytes.fromhex(str(inp["signature_hex"]))
        if len(pub) != 32 or len(sig) != 64:
            return {"valid": False}
        if not canonical_point(pub) or not canonical_signature(sig):
            return {"valid": False}
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
            return {"valid": True}
        except Exception:
            return {"valid": False}
    if op == "parse":
        try:
            parse_text(str(inp["raw"]))
            return {}
        except StrictError as e:
            return _kerr(e.code)
    if op == "canonical_equal":
        return {"equal": J(inp["left"]) == J(inp["right"])}
    if op == "id":
        return {"valid": is_id(inp.get("value"), str(inp.get("prefix")))}
    if op == "uint":
        if not is_u(inp.get("value")):
            return _kerr("INVALID_INPUT")
        return {}
    if op == "spend":
        return spend(inp["prior"], _need_u(inp.get("current"), "current"), inp.get("quality"))
    if op == "spend_sum":
        return spend_sum(inp["deltas"])
    if op == "scope":
        return scope(inp["policies"], inp["scopes"], inp.get("policy"), inp.get("scope"),
                     inp.get("reported_violation") is True)
    if op == "replication":
        return replication(inp.get("processes"), inp.get("threads"), inp.get("declared_processes"),
                           _need_u(inp.get("max_processes"), "max_processes"),
                           _need_u(inp.get("max_threads"), "max_threads"))
    if op == "silence":
        return silence(inp.get("state"), _need_u(inp.get("last_ms"), "last_ms"),
                       _need_u(inp.get("end_ms"), "end_ms"))
    if op == "receive_time":
        last = _need_u(inp.get("last_logical_ms"), "last_logical_ms")
        wall = _need_u(inp.get("wall_ms"), "wall_ms")
        obs = _need_u(inp.get("observed_ms"), "observed_ms")
        t = max(last, wall)
        if obs > t + 60000:
            return _kerr("FUTURE_TIMESTAMP")
        return {"logical_ms": str(t), "window_start_ms": str((t // 60000) * 60000),
                "late": obs < t - 120000}
    if op == "sequence":
        return _op_sequence(inp)
    if op == "usage":
        stored = inp.get("stored")
        inc = inp["incoming"]

        def ph(x):
            return D("WEATHER-USAGE/1", {"delta": x["delta"], "subject": x["subject"], "unit": x["unit"]})

        if stored is None:
            return {"counted": True}
        if ph(stored) != ph(inc):
            return _kerr("USAGE_CONFLICT")
        return {"counted": False}
    if op == "lattice":
        seen = set()
        domains = set()
        for v in inp["votes"]:
            if v["watcher"] in seen:
                continue
            seen.add(v["watcher"])
            if v["eligible"]:
                domains.add(v["domain"])
        ds = sorted(domains)
        return {"domains": ds, "corroborated": len(ds) >= 2}
    if op == "vote_gate":
        if inp.get("same_result") is not True:
            return _kerr("RESULT_MISMATCH")
        if _need_u(inp.get("now_ms"), "now_ms") >= _need_u(inp.get("expires_ms"), "expires_ms"):
            return _kerr("VOTE_EXPIRED")
        return {"accepted": True}
    if op == "alert_action":
        state = inp.get("state")
        action = inp.get("action")
        if _need_u(inp.get("expected_revision"), "expected_revision") != _need_u(inp.get("actual_revision"), "actual_revision"):
            return _kerr("REVISION_CONFLICT")
        if action == "ack" and state == "CORROBORATED":
            return {"state": "ACKNOWLEDGED"}
        if action == "close" and state in ("CANDIDATE", "CORROBORATED", "ACKNOWLEDGED"):
            return {"state": "CLOSED"}
        return _kerr("STATE_CONFLICT")
    if op == "delivery_failure":
        attempts = int(inp["attempts"])
        status = inp.get("status")
        retryable = status is None or status == 429 or status >= 500
        if not retryable or attempts >= 8:
            return {"state": "FAILED", "delay_ms": None}
        return {"state": "RETRY", "delay_ms": str(_RETRY_DELAYS[attempts - 1])}
    if op == "page_dedup":
        existing = list(inp["existing_results"])
        es = set(existing)
        inserted = 0
        for r in inp["corroborated_results"]:
            if r not in es:
                es.add(r)
                existing.append(r)
                inserted += 1
        return {"outbox_results": existing, "inserted": inserted}
    if op == "degrade":
        d = inp["delivery"]
        d = "CANCELLED" if d in ("QUEUED", "RETRY") else d
        return {"state": inp["state"], "assurance": "DEGRADED", "delivery": d}
    if op == "audit_positions":
        seqs = [_need_u(s, "seqs") for s in inp["seqs"]]
        for k in range(1, len(seqs)):
            if seqs[k] != seqs[k - 1] + 1:
                return _kerr("CHAIN_INVALID")
        return {}
    if op == "export_complete":
        ok = inp.get("header") is True and inp.get("trailer") is True \
            and inp.get("expected_entries") == inp.get("actual_entries")
        return {"complete": True} if ok else {"complete": False, "reason": "INCOMPLETE"}
    if op == "rates":
        tp, fp, fn, tn = (_need_u(inp[k], k) for k in ("tp", "fp", "fn", "tn"))
        up, un = (_need_u(inp[k], k) for k in ("unknown_positive", "unknown_negative"))

        def frac(n, d):
            return None if d == 0 else {"n": str(n), "d": str(d)}

        total = tp + fp + fn + tn + up + un
        return {
            "precision": frac(tp, tp + fp),
            "recall": frac(tp, tp + fn + up),
            "false_positive_rate": frac(fp, fp + tn + un),
            "coverage": frac(tp + fp + fn + tn, total),
        }
    if op == "signal":
        if not is_hash(inp.get("artifact")):
            raise ValueError("artifact")
        return signal_decision()
    raise ValueError(f"unknown op {op}")
