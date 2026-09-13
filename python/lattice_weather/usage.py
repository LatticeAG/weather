"""usage_ids.payload_hash = D("WEATHER-USAGE/1", {delta, subject, unit}) (§3.3)."""

from .canon import D


def usage_payload_hash(subject: str, delta: str, unit: str) -> str:
    return D("WEATHER-USAGE/1", {"delta": delta, "subject": subject, "unit": unit})
