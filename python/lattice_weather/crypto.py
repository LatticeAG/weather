"""Ed25519 + nanoid helpers (§3.1, §3.3).

Ordinary Ed25519 (RFC 8032) via `cryptography`; explicit canonicality gates
(S < L, canonical point encodings, small-order rejection) are applied before
library verification.
"""

import base64
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_L = (1 << 252) + 27742317777372353535851937790883648493
_P = (1 << 255) - 19

_SMALL_ORDER = {
    bytes.fromhex(h) for h in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac637a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    )
}


def _le(b: bytes) -> int:
    return int.from_bytes(b, "little")


def canonical_point(b: bytes) -> bool:
    if len(b) != 32:
        return False
    if (_le(b) & ((1 << 255) - 1)) >= _P:
        return False
    return b not in _SMALL_ORDER


def canonical_signature(sig: bytes) -> bool:
    return len(sig) == 64 and canonical_point(sig[:32]) and _le(sig[32:]) < _L


def sign_message(sign_tag: str, hash_hex: str) -> bytes:
    return sign_tag.encode("utf-8") + b"\x00" + bytes.fromhex(hash_hex)


def sign_detached(seed: bytes, sign_tag: str, hash_hex: str) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(sign_message(sign_tag, hash_hex))


def verify_detached(pub_raw: bytes, sign_tag: str, hash_hex: str, sig: bytes) -> bool:
    try:
        if not canonical_point(pub_raw) or not canonical_signature(sig):
            return False
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, sign_message(sign_tag, hash_hex))
        return True
    except Exception:
        return False


def public_key_b64(seed: bytes) -> str:
    raw = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def pin_of_seed(key_id: str, seed: bytes) -> dict:
    return {"key_id": key_id, "public_key": public_key_b64(seed)}


def new_seed() -> bytes:
    return secrets.token_bytes(32)


_ALPHABET = "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def nanoid() -> str:
    out = []
    while len(out) < 21:
        for x in secrets.token_bytes(32):
            if x < 256:
                out.append(_ALPHABET[x & 63])
                if len(out) == 21:
                    break
    return "".join(out)


def new_id(prefix: str) -> str:
    return f"{prefix}_{nanoid()}"


def is_id(x, prefix: str) -> bool:
    if not isinstance(x, str) or not x.startswith(prefix + "_"):
        return False
    body = x[len(prefix) + 1 :]
    return len(body) == 21 and all(c in _ALPHABET for c in body)
