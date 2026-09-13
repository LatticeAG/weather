"""The four deterministic detectors (§4.3), independent implementation.

U values are Python ints (unbounded); checks compare against U_MAX directly.
"""

U_MAX = 9223372036854775807
_BASELINE_FLOOR = 100000
_SPEND_MIN = 1000000
_SPEND_MULT = 3
_SILENCE_MS = 120000


def _dec(status, reason, value=None, limit=None):
    return {"status": status, "reason": reason, "value": value, "limit": limit}


def checked_sum(deltas):
    s = 0
    for d in deltas:
        s += int(d)
        if s > U_MAX:
            return None
    return s


def spend(prior, current, quality):
    c = int(current)
    if quality != "COMPLETE":
        return _dec("UNKNOWN", "COVERAGE_INCOMPLETE", str(current), None)
    if len(prior) < 5:
        return _dec("UNKNOWN", "BASELINE_WARMUP", str(current), None)
    m = sorted(int(p) for p in prior)[2]
    b = max(m, _BASELINE_FLOOR)
    t = max(_SPEND_MULT * b, _SPEND_MIN)
    limit = str(t) if t <= U_MAX else None
    if c >= t:
        return _dec("HIT", "SPEND_SPIKE", str(current), limit)
    return _dec("CLEAR", "BELOW_THRESHOLD", str(current), limit)


def spend_sum(deltas):
    s = checked_sum(deltas)
    if s is None:
        return _dec("UNKNOWN", "ARITHMETIC_OVERFLOW")
    return _dec("CLEAR", "BELOW_THRESHOLD", str(s))


def scope(policies, scopes, policy, scope_v, reported_violation):
    if reported_violation:
        return _dec("HIT", "DRIFT_REPORTED")
    if policy is not None and policy not in policies:
        return _dec("HIT", "POLICY_DRIFT")
    if scope_v is not None and scope_v not in scopes:
        return _dec("HIT", "SCOPE_DRIFT")
    if policy is not None or scope_v is not None:
        return _dec("CLEAR", "SCOPE_MATCH")
    return _dec("UNKNOWN", "EVIDENCE_MISSING")


_STATUS_RANK = {"HIT": 0, "UNKNOWN": 1, "CLEAR": 2, "SIGNAL": 3}
_SCOPE_HIT = {"DRIFT_REPORTED": 0, "POLICY_DRIFT": 1, "SCOPE_DRIFT": 2}
_REP_HIT = {"PROCESS_EXCESS": 0, "THREAD_EXCESS": 1, "DECLARED_MISMATCH": 2}


def _aggregate(ds, hit_rank):
    best = ds[0]
    for c in ds[1:]:
        r = _STATUS_RANK[c["d"]["status"]] - _STATUS_RANK[best["d"]["status"]]
        if r < 0:
            best = c
            continue
        if r > 0:
            continue
        if c["d"]["status"] == "HIT":
            pr = hit_rank.get(c["d"]["reason"], 9) - hit_rank.get(best["d"]["reason"], 9)
            if pr < 0 or (pr == 0 and c["index"] < best["index"]):
                best = c
        elif c["index"] < best["index"]:
            best = c
    return best["d"]


def aggregate_scope(ds):
    return _aggregate(ds, _SCOPE_HIT)


def aggregate_replication(ds):
    return _aggregate(ds, _REP_HIT)


def replication(processes, threads, declared_processes, max_processes, max_threads):
    if processes is not None and int(processes) > int(max_processes):
        return _dec("HIT", "PROCESS_EXCESS", str(processes), str(max_processes))
    if threads is not None and int(threads) > int(max_threads):
        return _dec("HIT", "THREAD_EXCESS", str(threads), str(max_threads))
    if declared_processes is not None and processes is not None and int(declared_processes) != int(processes):
        return _dec("HIT", "DECLARED_MISMATCH", str(processes), str(declared_processes))
    if processes is None and threads is None:
        return _dec("UNKNOWN", "EVIDENCE_MISSING")
    if declared_processes is not None and processes is None:
        return _dec("UNKNOWN", "EVIDENCE_MISSING")
    return _dec(
        "CLEAR", "INVENTORY_MATCH",
        str(processes) if processes is not None else str(threads),
        str(max_processes) if processes is not None else str(max_threads),
    )


def silence(state, basis_ms, end_ms):
    if state in ("TERMINAL", "RETIRED"):
        return _dec("CLEAR", "SOURCE_TERMINAL")
    if state == "FORKED":
        return _dec("UNKNOWN", "COVERAGE_INCOMPLETE")
    age = int(end_ms) - int(basis_ms)
    if age >= _SILENCE_MS:
        return _dec("HIT", "STREAM_SILENT", str(age), str(_SILENCE_MS))
    return _dec("CLEAR", "STREAM_RECENT", str(age), str(_SILENCE_MS))


def signal_decision():
    return _dec("SIGNAL", "SIGNAL_ONLY")
