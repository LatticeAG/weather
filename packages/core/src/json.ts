import { WError } from "./errors.js";

/**
 * Strict protocol JSON parser (§3.1): UTF-8 without BOM, duplicate member
 * rejection before materialization, lone-surrogate rejection, trailing-data
 * rejection, nonnegative safe-integer number tokens only (no fractions,
 * exponents, or negative zero), plus depth/member/element caps.
 */

export interface ParseCaps {
  maxDepth: number;      // default 24
  maxMembers: number;    // default 256 per object
  maxElements: number;   // default 256 per array
}

/**
 * Generic structural caps (§3.1): depth 24, 256 members/object. The generic
 * element cap is 4096 — the largest explicit exception (Manifest.inputs and
 * ResultBody.evidence); every field's exact bound is enforced by schema
 * validation, which applies the 256-element default and the §3.1 exceptions.
 */
export const DEFAULT_CAPS: ParseCaps = { maxDepth: 24, maxMembers: 256, maxElements: 4096 };

const decoder = new TextDecoder("utf-8", { fatal: true });

function bad(msg: string): never {
  throw new WError("INVALID_INPUT", `JSON: ${msg}`);
}

export function parseBytes(buf: Uint8Array, caps: ParseCaps = DEFAULT_CAPS): unknown {
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) bad("UTF-8 BOM");
  let text: string;
  try {
    text = decoder.decode(buf);
  } catch {
    bad("invalid UTF-8");
  }
  return parseText(text, caps);
}

export function parseText(text: string, caps: ParseCaps = DEFAULT_CAPS): unknown {
  return new P(text, caps).run();
}

const HEX = "0123456789abcdefABCDEF".split("").reduce((s, c) => ((s[c.charCodeAt(0)] = 1), s), new Uint8Array(256));

class P {
  i = 0;
  constructor(private t: string, private caps: ParseCaps) {}
  run(): unknown {
    this.ws();
    const v = this.value(1);
    this.ws();
    if (this.i !== this.t.length) bad("trailing data");
    return v;
  }
  private ws(): void {
    const t = this.t;
    while (this.i < t.length) {
      const c = t.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }
  private value(depth: number): unknown {
    if (depth > this.caps.maxDepth) bad("depth cap exceeded");
    if (this.i >= this.t.length) bad("unexpected end");
    const c = this.t.charCodeAt(this.i);
    if (c === 0x7b) return this.object(depth);
    if (c === 0x5b) return this.array(depth);
    if (c === 0x22) return this.string();
    if (c === 0x74) return this.lit("true", true);
    if (c === 0x66) return this.lit("false", false);
    if (c === 0x6e) return this.lit("null", null);
    if (c >= 0x30 && c <= 0x39) return this.number();
    bad("unexpected token");
  }
  private lit(s: string, v: unknown): unknown {
    if (this.t.startsWith(s, this.i)) { this.i += s.length; return v; }
    bad("bad literal");
  }
  private number(): number {
    const t = this.t;
    const start = this.i;
    if (t.charCodeAt(this.i) === 0x30) this.i++;
    else while (this.i < t.length && t.charCodeAt(this.i) >= 0x30 && t.charCodeAt(this.i) <= 0x39) this.i++;
    if (this.i === start) bad("bad number");
    if (this.i < t.length) {
      const c = t.charCodeAt(this.i);
      if (c === 0x2e || c === 0x65 || c === 0x45) bad("non-integer number token");
    }
    const n = Number(t.slice(start, this.i));
    if (!Number.isSafeInteger(n) || n > 9007199254740991) bad("unsafe integer");
    return n;
  }
  private string(): string {
    const t = this.t;
    this.i++; // opening quote
    const out: string[] = [];
    while (this.i < t.length) {
      const c = t.charCodeAt(this.i);
      if (c === 0x22) { this.i++; return out.join(""); }
      if (c === 0x5c) {
        this.i++;
        if (this.i >= t.length) bad("bad escape");
        const e = t.charCodeAt(this.i);
        switch (e) {
          case 0x22: out.push('"'); this.i++; break;
          case 0x5c: out.push("\\"); this.i++; break;
          case 0x2f: out.push("/"); this.i++; break;
          case 0x62: out.push("\b"); this.i++; break;
          case 0x66: out.push("\f"); this.i++; break;
          case 0x6e: out.push("\n"); this.i++; break;
          case 0x72: out.push("\r"); this.i++; break;
          case 0x74: out.push("\t"); this.i++; break;
          case 0x75: {
            const cp = this.hex4();
            out.push(String.fromCharCode(cp));
            break;
          }
          default: bad("bad escape");
        }
      } else {
        if (c < 0x20) bad("unescaped control");
        if (c >= 0xd800 && c <= 0xdbff) {
          const c2 = t.charCodeAt(this.i + 1);
          if (!(c2 >= 0xdc00 && c2 <= 0xdfff)) bad("lone surrogate");
          out.push(t[this.i]!, t[this.i + 1]!);
          this.i += 2;
        } else if (c >= 0xdc00 && c <= 0xdfff) {
          bad("lone surrogate");
        } else {
          out.push(t[this.i]!);
          this.i++;
        }
      }
    }
    bad("unterminated string");
  }
  private hex4(): number {
    const t = this.t;
    if (this.i + 4 >= t.length + 1) bad("bad \\u escape");
    let v = 0;
    for (let k = 0; k < 4; k++) {
      const c = t.charCodeAt(this.i + 1 + k);
      if (!HEX[c]) bad("bad \\u escape");
      v = v * 16 + parseInt(t[this.i + 1 + k]!, 16);
    }
    this.i += 5;
    return v;
  }
  private object(depth: number): Record<string, unknown> {
    this.i++;
    const o: Record<string, unknown> = Object.create(null);
    this.ws();
    if (this.t.charCodeAt(this.i) === 0x7d) { this.i++; return o; }
    let n = 0;
    for (;;) {
      this.ws();
      if (this.t.charCodeAt(this.i) !== 0x22) bad("expected member string");
      const k = this.string();
      if (++n > this.caps.maxMembers) bad("member cap exceeded");
      if (Object.prototype.hasOwnProperty.call(o, k)) bad("duplicate member");
      this.ws();
      if (this.t.charCodeAt(this.i) !== 0x3a) bad("expected colon");
      this.i++;
      this.ws();
      o[k] = this.value(depth + 1);
      this.ws();
      const c = this.t.charCodeAt(this.i);
      if (c === 0x2c) { this.i++; continue; }
      if (c === 0x7d) { this.i++; return o; }
      bad("expected comma or brace");
    }
  }
  private array(depth: number): unknown[] {
    this.i++;
    const a: unknown[] = [];
    this.ws();
    if (this.t.charCodeAt(this.i) === 0x5d) { this.i++; return a; }
    for (;;) {
      if (a.length >= this.caps.maxElements) bad("element cap exceeded");
      this.ws();
      a.push(this.value(depth + 1));
      this.ws();
      const c = this.t.charCodeAt(this.i);
      if (c === 0x2c) { this.i++; continue; }
      if (c === 0x5d) { this.i++; return a; }
      bad("expected comma or bracket");
    }
  }
}
