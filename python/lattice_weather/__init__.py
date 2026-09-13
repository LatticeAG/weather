"""lattice_weather — independent Python implementation of weather/1.

Supplies the deterministic reducers, signed-object helpers, offline evidence
verifier, replay entry point, and eval math. It is deliberately a second
implementation: arithmetic and reduction paths are written independently of
the TypeScript core.
"""

from .canon import J, H, D, ZERO, EMPTY_HEAD
from .strictjson import parse_bytes, parse_text, StrictError
from .crypto import (
    new_seed, pin_of_seed, sign_detached, verify_detached, nanoid, new_id,
    public_key_b64,
)
from .detectors import (
    spend, spend_sum, scope, replication, silence, signal_decision, checked_sum,
)
from .replay import replay
from .verify import verify
from .evaluate import eval_run, wilson95, rates

__all__ = [
    "J", "H", "D", "ZERO", "EMPTY_HEAD",
    "parse_bytes", "parse_text", "StrictError",
    "new_seed", "pin_of_seed", "sign_detached", "verify_detached", "nanoid",
    "new_id", "public_key_b64",
    "spend", "spend_sum", "scope", "replication", "silence", "signal_decision",
    "checked_sum", "replay", "verify", "eval_run", "wilson95", "rates",
]
