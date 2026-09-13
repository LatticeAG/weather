"""§12 evaluation math: exact rational rates and 95% Wilson intervals."""

import math
from decimal import Decimal, ROUND_HALF_EVEN

_Z = 1.959963984540054
_LIMITATIONS = ["SYNTHETIC_SCOPE_ONLY", "SOURCE_ASSERTIONS_NOT_TRUTH", "COT_NOT_PROOF"]


def round6(x: float) -> str:
    q = Decimal(str(x)).quantize(Decimal("0.000001"), rounding=ROUND_HALF_EVEN)
    return f"{q:.6f}"


def wilson95(k: int, n: int):
    if n == 0:
        return None
    p = k / n
    z2 = _Z * _Z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (_Z * math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom
    clamp = lambda x: min(1.0, max(0.0, x))
    return {"low": round6(clamp(center - half)), "high": round6(clamp(center + half))}


def frac_rate(n: int, d: int):
    if d == 0:
        return {"fraction": None, "wilson95": None}
    return {"fraction": {"n": str(n), "d": str(d)}, "wilson95": wilson95(n, d)}


def rates(tp, fp, fn, tn, unknown_positive, unknown_negative):
    total = tp + fp + fn + tn + unknown_positive + unknown_negative

    def frac(n, d):
        return None if d == 0 else {"n": str(n), "d": str(d)}

    return {
        "precision": frac(tp, tp + fp),
        "recall": frac(tp, tp + fn + unknown_positive),
        "false_positive_rate": frac(fp, fp + tn + unknown_negative),
        "coverage": frac(tp + fp + fn + tn, total),
    }


def _classify(status, positive, c):
    if status == "HIT":
        c["tp" if positive else "fp"] += 1
    elif status == "CLEAR":
        c["fn" if positive else "tn"] += 1
    elif status == "UNKNOWN":
        c["unknown_positive" if positive else "unknown_negative"] += 1
    elif status == "SIGNAL":
        c["signals"] += 1


def _eq(a, b):
    if type(a) != type(b):
        if a is None or b is None:
            return a is b
        return a == b if not isinstance(a, (dict, list)) else False
    if isinstance(a, list):
        return len(a) == len(b) and all(_eq(x, y) for x, y in zip(a, b))
    if isinstance(a, dict):
        return set(a) == set(b) and all(_eq(a[k], b[k]) for k in a)
    return a == b


def eval_run(cfg, vectors, suite, impl, unit_decisions=None):
    from .kernels import run_kernel

    passed = sum(1 for v in vectors if _eq(run_kernel(v["input"]), v["expected"]))
    counts = {k: 0 for k in ("tp", "fp", "fn", "tn", "unknown_positive",
                             "unknown_negative", "signals", "corroborated", "delivered")}
    if suite:
        if suite["config"]["corpus_digest"] != cfg["corpus_digest"]:
            raise ValueError("suite corpus_digest != eval config corpus_digest")
        for un in suite["units"]:
            ext = (unit_decisions or {}).get(un["unit"])
            if ext:
                _classify(ext["status"], un["positive"], counts)
                continue
            vec = next((v for v in vectors if v["id"] == un["unit"]), None)
            if not vec:
                raise ValueError(f"eval unit {un['unit']} not in pinned corpus")
            out = run_kernel(vec["input"])
            _classify(out.get("status", "UNKNOWN") if isinstance(out, dict) else "UNKNOWN",
                      un["positive"], counts)

    n = sum(counts[k] for k in ("tp", "fp", "fn", "tn", "unknown_positive", "unknown_negative"))
    return {
        "v": 1,
        "suite": "weather-conformance/1",
        "corpus_digest": cfg["corpus_digest"],
        "pack_digest": cfg["pack_digest"],
        "seed": cfg["seed"],
        "implementation": impl,
        "vectors": len(vectors),
        "passed": passed,
        "counts": {k: str(v) for k, v in counts.items()},
        "precision": frac_rate(counts["tp"], counts["tp"] + counts["fp"]),
        "recall": frac_rate(counts["tp"], counts["tp"] + counts["fn"] + counts["unknown_positive"]),
        "false_positive_rate": frac_rate(counts["fp"], counts["fp"] + counts["tn"] + counts["unknown_negative"]),
        "coverage": frac_rate(counts["tp"] + counts["fp"] + counts["fn"] + counts["tn"], n),
        "limitations": list(_LIMITATIONS),
    }
