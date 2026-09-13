"""Deterministic window evaluation (§4.2–4.3), Python reducer."""

from .canon import D, ZERO
from .detectors import (
    spend as _spend_kernel, scope as _scope_kernel, replication as _rep_kernel,
    silence as _sil_kernel, aggregate_scope, aggregate_replication, checked_sum,
)


def _dec(status, reason, value=None, limit=None):
    return {"status": status, "reason": reason, "value": value, "limit": limit}


def compute_cuts(closes):
    return [{
        "source": c["source"], "head": {"seq": c["head_seq"], "hash": c["head_hash"]},
        "state": c["state"], "activated_ms": c["activated_ms"],
        "last_received_ms": c["last_received_ms"], "last_input": c["last_input"],
        "complete": c["complete"],
    } for c in closes]


def _effective_revoked(w):
    src_keys = {s["pin"]["key_id"]: s["id"] for s in w["config"]["sources"]}
    return {src_keys[k] for k in w["revoked_keys"] if k in src_keys}


def compute_quality(closes, accepted, revoked_sources):
    for c in closes:
        if c["state"] == "FORKED" or c["source"] in revoked_sources:
            return "DEGRADED"
    any_late = any(a["late"] and a["entry"]["body"]["observation"]["kind"] != "signal" for a in accepted)
    for c in closes:
        if c["state"] == "GAPPED" or c["pending"] > 0 or not c["complete"]:
            return "INCOMPLETE"
    return "INCOMPLETE" if any_late else "COMPLETE"


def manifest_of(w):
    manifest = {
        "v": 1, "fleet": w["fleet"], "config": w["config_hash"],
        "start_ms": w["start_ms"], "end_ms": w["end_ms"],
        "through_index": w["through_index"],
        "inputs": [a["entry"]["hash"] for a in w["accepted"]],
        "history": w["history"][-5:],
        "cuts": compute_cuts(w["closes"]),
        "quality": compute_quality(w["closes"], w["accepted"], _effective_revoked(w)),
    }
    return manifest, D("WEATHER-MANIFEST/1", manifest)


def _coverage_fails(c, revoked_key_ids, key_id):
    return (c["state"] in ("FORKED", "GAPPED") or key_id in revoked_key_ids
            or not c["complete"] or c["pending"] > 0)


def _has_nonsignal(accepted, source):
    return any(a["entry"]["body"]["source"] == source
               and a["entry"]["body"]["observation"]["kind"] != "signal" for a in accepted)


def _prior_spend_status(hw, config, revoked_key_ids):
    meters = [s for s in config["sources"] if s["enabled"] and s["meter"]]
    if not meters:
        return "UNKNOWN"
    for m in meters:
        cut = next((c for c in hw["manifest"]["cuts"] if c["source"] == m["id"]), None)
        if cut is None:
            return "UNKNOWN"
        if (cut["state"] == "FORKED" or m["pin"]["key_id"] in revoked_key_ids
                or not cut["complete"]
                or not _has_nonsignal(hw["accepted"], m["id"])):
            return "UNKNOWN"
    s = checked_sum([a["entry"]["body"]["observation"]["delta"]
                     for a in hw["accepted"]
                     if a["counted"] and a["entry"]["body"]["observation"]["kind"] == "spend"])
    if s is None:
        return "UNKNOWN"
    if len(hw["manifest"]["history"]) < 5:
        return "UNKNOWN"
    return "HIT_CLEAR"


def _prior_spend_total(hw):
    s = checked_sum([a["entry"]["body"]["observation"]["delta"]
                     for a in hw["accepted"]
                     if a["counted"] and a["entry"]["body"]["observation"]["kind"] == "spend"])
    return s if s is not None else 0


def evaluate_window(w):
    manifest, mh = manifest_of(w)
    results = evaluate_results(w, manifest, mh)
    return {"manifest": manifest, "manifest_hash": mh, "results": results,
            "hit_results": [r for r in results if r["body"]["decision"]["status"] == "HIT"]}


def evaluate_results(w, manifest, manifest_hash):
    cfg = w["config"]
    revoked_key_ids = w["revoked_keys"]
    cut_by_source = {c["source"]: c for c in manifest["cuts"]}
    close_by_source = {c["source"]: c for c in w["closes"]}
    out = []

    def mk(detector, target, decision, evidence):
        body = {
            "v": 1, "fleet": w["fleet"], "config": w["config_hash"],
            "manifest": manifest_hash, "detector": detector, "target": target,
            "decision": decision, "evidence": sorted(set(evidence)),
        }
        return {"body": body, "hash": D("WEATHER-RESULT/1", body)}

    # spend_spike/1 → fleet
    meters = [s for s in cfg["sources"] if s["enabled"] and s["meter"]]
    spend_entries = [a for a in w["accepted"]
                     if a["entry"]["body"]["observation"]["kind"] == "spend" and a["counted"]]
    evidence = [a["entry"]["hash"] for a in spend_entries]
    deltas = [a["entry"]["body"]["observation"]["delta"] for a in spend_entries]
    total = checked_sum(deltas)
    if not meters:
        d = _dec("UNKNOWN", "EVIDENCE_MISSING")
        evidence = []
    else:
        c_rep = str(total) if total is not None else None
        cov_fail = False
        for m in meters:
            cut = cut_by_source.get(m["id"])
            cut_state = cut["state"] if cut else "EMPTY"
            complete = cut["complete"] if cut else True
            if (cut_state == "FORKED" or m["pin"]["key_id"] in revoked_key_ids
                    or not complete or not _has_nonsignal(w["accepted"], m["id"])):
                cov_fail = True
        if cov_fail:
            d = _dec("UNKNOWN", "COVERAGE_INCOMPLETE", c_rep)
        elif total is None:
            d = _dec("UNKNOWN", "ARITHMETIC_OVERFLOW")
        elif len(w["history_windows"]) < 5:
            d = _dec("UNKNOWN", "BASELINE_WARMUP", c_rep)
        elif any(_prior_spend_status(hw, cfg, revoked_key_ids) == "UNKNOWN"
                 for hw in w["history_windows"]):
            d = _dec("UNKNOWN", "COVERAGE_INCOMPLETE", c_rep)
        else:
            priors = sorted(_prior_spend_total(hw) for hw in w["history_windows"])
            m = priors[2]
            b = max(m, 100000)
            t = max(3 * b, 1000000)
            limit = str(t) if t <= 9223372036854775807 else None
            d = (_dec("HIT", "SPEND_SPIKE", c_rep, limit) if total >= t
                 else _dec("CLEAR", "BELOW_THRESHOLD", c_rep, limit))
    out.append(mk("spend_spike/1", w["fleet"], d, evidence))

    # scope_drift/1 and replication_anomaly/1 → per subject
    subjects_scope = {}
    subjects_rep = {}
    subj_cfg = {s["id"]: s for s in cfg["subjects"]}

    def subject_sources(sub):
        return [s for s in cfg["sources"] if s["enabled"] and sub in s["subjects"]]

    for a in w["accepted"]:
        obs = a["entry"]["body"]["observation"]
        if obs["kind"] == "scope":
            sc = subj_cfg.get(obs["subject"])
            if not sc:
                continue
            d = _scope_kernel(sc["policies"], sc["scopes"], obs["policy_hash"],
                              obs["scope_hash"], obs["reported_violation"])
            subjects_scope.setdefault(obs["subject"], []).append(
                {"d": d, "index": int(a["index"]), "hash": a["entry"]["hash"]})
        elif obs["kind"] == "replication":
            sc = subj_cfg.get(obs["subject"])
            if not sc:
                continue
            d = _rep_kernel(obs["processes"], obs["threads"], obs["declared_processes"],
                            sc["max_processes"], sc["max_threads"])
            subjects_rep.setdefault(obs["subject"], []).append(
                {"d": d, "index": int(a["index"]), "hash": a["entry"]["hash"]})

    def relevant_cov_fails(sub):
        for s in subject_sources(sub):
            close = close_by_source.get(s["id"])
            cut = cut_by_source.get(s["id"])
            c = close or {
                "source": s["id"], "head_seq": "0", "head_hash": ZERO,
                "state": cut["state"] if cut else "EMPTY",
                "activated_ms": cut["activated_ms"] if cut else cfg["effective_ms"],
                "last_received_ms": None, "last_input": None,
                "complete": cut["complete"] if cut else True,
                "pending": 0, "revoked": False,
            }
            if _coverage_fails(c, revoked_key_ids, s["pin"]["key_id"]):
                return True
        return False

    for sub, ds in subjects_scope.items():
        d = (_dec("UNKNOWN", "COVERAGE_INCOMPLETE") if relevant_cov_fails(sub)
             else aggregate_scope(ds))
        out.append(mk("scope_drift/1", sub, d, [x["hash"] for x in ds]))
    for sub, ds in subjects_rep.items():
        d = (_dec("UNKNOWN", "COVERAGE_INCOMPLETE") if relevant_cov_fails(sub)
             else aggregate_replication(ds))
        out.append(mk("replication_anomaly/1", sub, d, [x["hash"] for x in ds]))

    # stream_silence/1 → per enabled source
    for cut in manifest["cuts"]:
        src_cfg = next((s for s in cfg["sources"] if s["id"] == cut["source"]), None)
        if src_cfg and src_cfg["pin"]["key_id"] in revoked_key_ids:
            d = _dec("UNKNOWN", "COVERAGE_INCOMPLETE")
        else:
            basis = cut["last_received_ms"] if cut["last_received_ms"] is not None else cut["activated_ms"]
            d = _sil_kernel(cut["state"], basis, manifest["end_ms"])
        ev = [cut["last_input"]] if cut["last_input"] is not None else []
        out.append(mk("stream_silence/1", cut["source"], d, ev))

    out.sort(key=lambda r: (r["body"]["detector"], r["body"]["target"]))
    return out
