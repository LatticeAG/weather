import { createHash } from "node:crypto";
import { J } from "./jcs.js";

/** H(bytes) = lowercase_hex(SHA-256(bytes)) (§3.3). */
export function H(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** D(tag,x) = H(UTF8(tag) || 0x00 || J(x)) (§3.3). */
export function D(tag: string, x: unknown): string {
  return createHash("sha256").update(tag, "utf8").update(Buffer.from([0])).update(J(x)).digest("hex");
}

export const ZERO = "0".repeat(64);
export const EMPTY_HEAD = { seq: "0", hash: ZERO } as const;

export function isHash(x: unknown): x is string {
  return typeof x === "string" && /^[0-9a-f]{64}$/.test(x);
}
