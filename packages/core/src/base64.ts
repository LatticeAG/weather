import { WError } from "./errors.js";

/** Canonical unpadded base64url (§3.1): exactly the RFC 4648 alphabet, no padding. */
const B64URL = /^[A-Za-z0-9_-]+$/;

export function b64uEncode(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

export function b64uDecode(s: string, expectedLen: number, what: string): Uint8Array {
  if (typeof s !== "string" || !B64URL.test(s)) throw new WError("INVALID_INPUT", `${what}: noncanonical base64url`);
  const b = Buffer.from(s, "base64url");
  if (b.length !== expectedLen) throw new WError("INVALID_INPUT", `${what}: wrong length`);
  if (b.toString("base64url") !== s) throw new WError("INVALID_INPUT", `${what}: noncanonical encoding`);
  return new Uint8Array(b);
}

export function isPub(s: unknown): s is string {
  if (typeof s !== "string" || !B64URL.test(s)) return false;
  const b = Buffer.from(s, "base64url");
  return b.length === 32 && b.toString("base64url") === s;
}

export function isSig(s: unknown): s is string {
  if (typeof s !== "string" || !B64URL.test(s)) return false;
  const b = Buffer.from(s, "base64url");
  return b.length === 64 && b.toString("base64url") === s;
}
