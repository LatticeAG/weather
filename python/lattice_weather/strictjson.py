"""Strict protocol JSON parser (§3.1).

UTF-8 without BOM; duplicate members rejected before materialization; lone
surrogates, trailing data, invalid UTF-8, fractions, exponent tokens,
negative zero, and integers above 9007199254740991 rejected. Generic
structural caps: depth 24, 256 members/object, 4096 elements/array (the
largest explicit exception); per-field bounds are schema-level.
"""


class StrictError(ValueError):
    def __init__(self, msg):
        super().__init__(msg)
        self.code = "INVALID_INPUT"


MAX_DEPTH = 24
MAX_MEMBERS = 256
MAX_ELEMENTS = 4096


def parse_bytes(buf: bytes):
    if buf[:3] == b"\xef\xbb\xbf":
        raise StrictError("UTF-8 BOM")
    try:
        text = buf.decode("utf-8")
    except UnicodeDecodeError as e:
        raise StrictError("invalid UTF-8") from e
    return parse_text(text)


def parse_text(text: str):
    p = _P(text)
    return p.run()


class _P:
    def __init__(self, t: str):
        self.t = t
        self.i = 0

    def bad(self, msg):
        raise StrictError(msg)

    def run(self):
        self.ws()
        v = self.value(1)
        self.ws()
        if self.i != len(self.t):
            self.bad("trailing data")
        return v

    def ws(self):
        t = self.t
        while self.i < len(t) and t[self.i] in " \t\n\r":
            self.i += 1

    def value(self, depth):
        if depth > MAX_DEPTH:
            self.bad("depth cap exceeded")
        if self.i >= len(self.t):
            self.bad("unexpected end")
        c = self.t[self.i]
        if c == "{":
            return self.obj(depth)
        if c == "[":
            return self.arr(depth)
        if c == '"':
            return self.string()
        if c == "t":
            return self.lit("true", True)
        if c == "f":
            return self.lit("false", False)
        if c == "n":
            return self.lit("null", None)
        if "0" <= c <= "9":
            return self.number()
        self.bad("unexpected token")

    def lit(self, s, v):
        if self.t.startswith(s, self.i):
            self.i += len(s)
            return v
        self.bad("bad literal")

    def number(self):
        t = self.t
        start = self.i
        if t[self.i] == "0":
            self.i += 1
        else:
            while self.i < len(t) and "0" <= t[self.i] <= "9":
                self.i += 1
        if self.i == start:
            self.bad("bad number")
        if self.i < len(t) and t[self.i] in ".eE":
            self.bad("non-integer number token")
        n = int(t[start:self.i])
        if n > 9007199254740991:
            self.bad("unsafe integer")
        return n

    def string(self):
        t = self.t
        self.i += 1
        out = []
        while self.i < len(t):
            c = t[self.i]
            o = ord(c)
            if c == '"':
                self.i += 1
                return "".join(out)
            if c == "\\":
                self.i += 1
                if self.i >= len(t):
                    self.bad("bad escape")
                e = t[self.i]
                simple = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
                if e in simple:
                    out.append(simple[e])
                    self.i += 1
                elif e == "u":
                    if self.i + 4 >= len(t) + 1:
                        self.bad("bad \\u escape")
                    h = t[self.i + 1 : self.i + 5]
                    if len(h) != 4 or any(ch not in "0123456789abcdefABCDEF" for ch in h):
                        self.bad("bad \\u escape")
                    cp = int(h, 16)
                    out.append(chr(cp))
                    self.i += 5
                else:
                    self.bad("bad escape")
            else:
                if o < 0x20:
                    self.bad("unescaped control")
                if 0xD800 <= o <= 0xDBFF:
                    o2 = ord(t[self.i + 1]) if self.i + 1 < len(t) else 0
                    if not (0xDC00 <= o2 <= 0xDFFF):
                        self.bad("lone surrogate")
                    out.append(t[self.i])
                    out.append(t[self.i + 1])
                    self.i += 2
                elif 0xDC00 <= o <= 0xDFFF:
                    self.bad("lone surrogate")
                else:
                    out.append(c)
                    self.i += 1
        self.bad("unterminated string")

    def obj(self, depth):
        self.i += 1
        o = {}
        self.ws()
        if self.i < len(self.t) and self.t[self.i] == "}":
            self.i += 1
            return o
        n = 0
        while True:
            self.ws()
            if self.i >= len(self.t) or self.t[self.i] != '"':
                self.bad("expected member string")
            k = self.string()
            n += 1
            if n > MAX_MEMBERS:
                self.bad("member cap exceeded")
            if k in o:
                self.bad("duplicate member")
            self.ws()
            if self.i >= len(self.t) or self.t[self.i] != ":":
                self.bad("expected colon")
            self.i += 1
            self.ws()
            o[k] = self.value(depth + 1)
            self.ws()
            if self.i >= len(self.t):
                self.bad("unexpected end in object")
            c = self.t[self.i]
            if c == ",":
                self.i += 1
                continue
            if c == "}":
                self.i += 1
                return o
            self.bad("expected comma or brace")

    def arr(self, depth):
        self.i += 1
        a = []
        self.ws()
        if self.i < len(self.t) and self.t[self.i] == "]":
            self.i += 1
            return a
        while True:
            if len(a) >= MAX_ELEMENTS:
                self.bad("element cap exceeded")
            self.ws()
            a.append(self.value(depth + 1))
            self.ws()
            if self.i >= len(self.t):
                self.bad("unexpected end in array")
            c = self.t[self.i]
            if c == ",":
                self.i += 1
                continue
            if c == "]":
                self.i += 1
                return a
            self.bad("expected comma or bracket")
