import { WError } from "./errors.js";

/**
 * J(x): RFC 8785 canonical JSON bytes (§3.1). UTF-16 member ordering is the
 * ECMAScript default string order; number serialization is ECMAScript
 * Number::toString restricted to the protocol's safe-integer domain; strings
 * are emitted without Unicode normalization using the JSON escape set.
 */

function esc(s: string, out: string[]): void {
  out.push('"');
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out.push('\\"');
    else if (c === 0x5c) out.push("\\\\");
    else if (c === 0x08) out.push("\\b");
    else if (c === 0x09) out.push("\\t");
    else if (c === 0x0a) out.push("\\n");
    else if (c === 0x0c) out.push("\\f");
    else if (c === 0x0d) out.push("\\r");
    else if (c < 0x20) out.push("\\u", c.toString(16).padStart(4, "0"));
    else if (c >= 0xd800 && c <= 0xdbff) {
      const c2 = s.charCodeAt(i + 1);
      if (!(c2 >= 0xdc00 && c2 <= 0xdfff)) {
        throw new WError("INVALID_INPUT", "lone surrogate in J");
      }
      out.push(s[i]!, s[i + 1]!);
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new WError("INVALID_INPUT", "lone surrogate in J");
    } else {
      out.push(s[i]!);
    }
  }
  out.push('"');
}

function ser(v: unknown, out: string[]): void {
  if (v === null) { out.push("null"); return; }
  if (v === true) { out.push("true"); return; }
  if (v === false) { out.push("false"); return; }
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || v < 0 || v > 9007199254740991) {
      throw new WError("INVALID_INPUT", "non-protocol number in J");
    }
    out.push(String(v));
    return;
  }
  if (typeof v === "string") { esc(v, out); return; }
  if (Array.isArray(v)) {
    out.push("[");
    for (let i = 0; i < v.length; i++) {
      if (i) out.push(",");
      ser(v[i], out);
    }
    out.push("]");
    return;
  }
  if (typeof v === "object") {
    const keys = Object.keys(v as Record<string, unknown>).sort();
    out.push("{");
    for (let i = 0; i < keys.length; i++) {
      if (i) out.push(",");
      esc(keys[i]!, out);
      out.push(":");
      ser((v as Record<string, unknown>)[keys[i]!], out);
    }
    out.push("}");
    return;
  }
  throw new WError("INVALID_INPUT", "unserializable value in J");
}

export function J(x: unknown): Buffer {
  const out: string[] = [];
  ser(x, out);
  return Buffer.from(out.join(""), "utf8");
}

export function jstr(x: unknown): string {
  const out: string[] = [];
  ser(x, out);
  return out.join("");
}
