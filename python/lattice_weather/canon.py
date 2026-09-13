"""RFC 8785 canonicalization J(x) and domain-separated hashing (§3.3).

Member ordering uses the UTF-16 code-unit order (Python sorts by code point,
so keys are ordered by their UTF-16BE encoding to match ECMAScript). Numbers
are restricted to the protocol's nonnegative safe-integer domain and emit as
ECMAScript shortest decimal digits. No Unicode normalization is performed.
"""

import hashlib

ZERO = "0" * 64
EMPTY_HEAD = {"seq": "0", "hash": ZERO}

_SAFE_INT_MAX = 9007199254740991


def _esc(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif 0xD800 <= o <= 0xDFFF:
            raise ValueError("lone surrogate in J")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _ser(v, out):
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):
        if v < 0 or v > _SAFE_INT_MAX:
            raise ValueError("non-protocol number in J")
        out.append(str(v))
    elif isinstance(v, str):
        out.append(_esc(v))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _ser(item, out)
        out.append("]")
    elif isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        out.append("{")
        for i, k in enumerate(keys):
            if i:
                out.append(",")
            out.append(_esc(k))
            out.append(":")
            _ser(v[k], out)
        out.append("}")
    else:
        raise ValueError("unserializable value in J")


def J(x) -> bytes:
    out = []
    _ser(x, out)
    return "".join(out).encode("utf-8")


def H(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def D(tag: str, x) -> str:
    return H(tag.encode("utf-8") + b"\x00" + J(x))


def is_hash(x) -> bool:
    return (
        isinstance(x, str)
        and len(x) == 64
        and all(c in "0123456789abcdef" for c in x)
    )
