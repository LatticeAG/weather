import { createPrivateKey, createPublicKey, sign as nSign, verify as nVerify, randomBytes, type KeyObject } from "node:crypto";
import { WError } from "./errors.js";

/**
 * Ordinary Ed25519 (RFC 8032), with explicit canonicality gates per §3.1:
 * signature scalar S < L, canonical point encodings for R and the public key
 * (y < p), and rejection of the eight small-order encodings.
 */

const L_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;
const P_FIELD = (1n << 255n) - 19n;

const SMALL_ORDER = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac637a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
]);

function leInt(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
  return v;
}

/** Canonical point encoding: y < p (top bit is the x sign). */
export function canonicalPoint(b: Uint8Array): boolean {
  if (b.length !== 32) return false;
  const y = leInt(b) & ((1n << 255n) - 1n);
  if (y >= P_FIELD) return false;
  return !SMALL_ORDER.has(Buffer.from(b).toString("hex"));
}

export function canonicalSignature(sig: Uint8Array): boolean {
  if (sig.length !== 64) return false;
  if (!canonicalPoint(sig.subarray(0, 32))) return false;
  return leInt(sig.subarray(32, 64)) < L_ORDER;
}

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function privateKeyFromSeed(seed: Uint8Array): KeyObject {
  if (seed.length !== 32) throw new WError("INVALID_INPUT", "seed must be 32 bytes");
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]), format: "der", type: "pkcs8" });
}

export function publicKeyFromRaw(raw: Uint8Array): KeyObject {
  if (!canonicalPoint(raw)) throw new WError("INVALID_INPUT", "noncanonical public key");
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(raw)]), format: "der", type: "spki" });
}

export function publicKeyOf(priv: KeyObject): Uint8Array {
  const jwk = priv.export({ format: "jwk" }) as { x: string };
  return new Uint8Array(Buffer.from(jwk.x, "base64url"));
}

/** Signature input: UTF8(sign_tag) || 0x00 || hexdecode(hash) (§3.3). */
export function signMessage(signTag: string, hashHex: string): Buffer {
  return Buffer.concat([Buffer.from(signTag, "utf8"), Buffer.from([0]), Buffer.from(hashHex, "hex")]);
}

export function signDetached(seed: Uint8Array, signTag: string, hashHex: string): Uint8Array {
  const priv = privateKeyFromSeed(seed);
  return new Uint8Array(nSign(null, signMessage(signTag, hashHex), priv));
}

export function verifyDetached(pubRaw: Uint8Array, signTag: string, hashHex: string, sig: Uint8Array): boolean {
  try {
    if (!canonicalSignature(sig)) return false;
    const pub = publicKeyFromRaw(pubRaw);
    return nVerify(null, signMessage(signTag, hashHex), pub, Buffer.from(sig));
  } catch {
    return false;
  }
}

export function generateSeed(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}
