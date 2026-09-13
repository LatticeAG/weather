"""core.replay (§6.3): pure predicate replay over a committed window."""


class ReplayError(ValueError):
    def __init__(self, msg, code="INVALID_INPUT"):
        super().__init__(msg)
        self.code = code


def replay(inp):
    from .canon import D
    from .window import evaluate_results

    m = inp["manifest"]
    cfg = inp["config"]["body"]

    if inp["config"]["hash"] != m["config"]:
        raise ReplayError("manifest.config != supplied config hash")
    if cfg["fleet"] != m["fleet"]:
        raise ReplayError("config fleet != manifest fleet")
    if cfg["pack"] != "weather-core/1.0.0":
        raise ReplayError(f"unsupported pack {cfg['pack']}", "PACK_UNAVAILABLE")

    if len(inp["accepted"]) != len(m["inputs"]):
        raise ReplayError("accepted length != manifest.inputs")
    seen_idx = set()
    prev_idx = None
    for i, a in enumerate(inp["accepted"]):
        if a["entry"]["hash"] != m["inputs"][i]:
            raise ReplayError(f"accepted[{i}] hash != manifest.inputs[{i}]")
        idx = int(a["index"])
        if a["index"] in seen_idx:
            raise ReplayError("duplicate input index")
        seen_idx.add(a["index"])
        if prev_idx is not None and idx <= prev_idx:
            raise ReplayError("accepted indexes not increasing")
        prev_idx = idx
        r = int(a["received_ms"])
        if r < int(m["start_ms"]) or r >= int(m["end_ms"]):
            raise ReplayError("accepted record outside window")
        if idx > int(m["through_index"]):
            raise ReplayError("accepted index beyond through_index")

    if len(inp["history"]) > 5:
        raise ReplayError("more than five history windows")
    if len(inp["history"]) != len(m["history"]):
        raise ReplayError("history window count != manifest.history")
    for i, hw in enumerate(inp["history"]):
        if D("WEATHER-MANIFEST/1", hw["manifest"]) != m["history"][i]:
            raise ReplayError(f"history[{i}] hash mismatch")
        if hw["manifest"]["config"] != m["config"]:
            raise ReplayError("history window not same-epoch")
        if hw["manifest"]["fleet"] != m["fleet"]:
            raise ReplayError("history window fleet mismatch")
        if len(hw["accepted"]) != len(hw["manifest"]["inputs"]):
            raise ReplayError("history accepted length mismatch")
        for j, a in enumerate(hw["accepted"]):
            if a["entry"]["hash"] != hw["manifest"]["inputs"][j]:
                raise ReplayError("history accepted != its manifest.inputs")
            r = int(a["received_ms"])
            if r < int(hw["manifest"]["start_ms"]) or r >= int(hw["manifest"]["end_ms"]):
                raise ReplayError("history accepted outside its window")
        if i > 0 and int(hw["manifest"]["start_ms"]) != int(inp["history"][i - 1]["manifest"]["end_ms"]):
            raise ReplayError("history windows not contiguous")
    if inp["history"]:
        last = inp["history"][-1]["manifest"]
        if int(last["end_ms"]) != int(m["start_ms"]):
            raise ReplayError("history does not end at current start")

    cuts_sorted = sorted(m["cuts"], key=lambda c: c["source"])
    expect = [{"source": c["source"], "hash": c["last_input"], "ms": c["last_received_ms"]}
              for c in cuts_sorted if c["last_input"] is not None]
    li_sorted = sorted(inp["last_inputs"], key=lambda a: a["entry"]["body"]["source"])
    if len(li_sorted) != len(expect):
        raise ReplayError("last_inputs length mismatch")
    for a, e in zip(li_sorted, expect):
        if a["entry"]["body"]["source"] != e["source"]:
            raise ReplayError("last_inputs source mismatch")
        if a["entry"]["hash"] != e["hash"]:
            raise ReplayError("last_inputs hash mismatch")
        if a["received_ms"] != e["ms"]:
            raise ReplayError("last_inputs received_ms mismatch")
        if a["entry"]["body"]["observation"]["kind"] == "signal":
            raise ReplayError("signal entry as liveness witness")

    pending_by_source = {}
    closes = [{
        "source": c["source"], "head_seq": c["head"]["seq"], "head_hash": c["head"]["hash"],
        "state": c["state"], "activated_ms": c["activated_ms"],
        "last_received_ms": c["last_received_ms"], "last_input": c["last_input"],
        "complete": c["complete"], "pending": pending_by_source.get(c["source"], 0),
        "revoked": False,
    } for c in m["cuts"]]

    w = {
        "fleet": m["fleet"], "config_hash": m["config"], "config": cfg,
        "start_ms": m["start_ms"], "end_ms": m["end_ms"],
        "through_index": m["through_index"], "accepted": inp["accepted"],
        "history": m["history"], "history_windows": inp["history"],
        "closes": closes, "revoked_keys": set(cfg["revoked_keys"]),
    }
    mh = D("WEATHER-MANIFEST/1", m)
    results = evaluate_results(w, m, mh)
    return {"manifest": mh, "results": results}
