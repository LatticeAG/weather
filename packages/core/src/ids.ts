import { randomBytes } from "node:crypto";

/**
 * Locked ID grammar (§3.1): exact prefix, underscore, 21 characters from the
 * CSPRNG nanoid alphabet. IDs are opaque, immutable, case-sensitive, never
 * recycled, never derived from truncated hashes.
 */
export const ID_ALPHABET = "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
export const ID_BODY_LEN = 21;

export type IdPrefix =
  | "wfl" | "wso" | "wwa" | "wdo" | "wsu" | "wky" | "wrq" | "wss" | "wal" | "wev" | "wpr";

const PREFIXES = new Set<string>([
  "wfl", "wso", "wwa", "wdo", "wsu", "wky", "wrq", "wss", "wal", "wev", "wpr",
]);

const ALPHABET_SET = new Set(ID_ALPHABET.split(""));

export function nanoid(): string {
  // Rejection sampling over CSPRNG bytes (64-character alphabet).
  const out: string[] = [];
  while (out.length < ID_BODY_LEN) {
    const b = randomBytes(32);
    for (const x of b) {
      if (x < 64 * 4) {
        out.push(ID_ALPHABET[x & 63]!);
        if (out.length === ID_BODY_LEN) break;
      }
    }
  }
  return out.join("");
}

export function newId(prefix: IdPrefix): string {
  return `${prefix}_${nanoid()}`;
}

export function isId(x: unknown, prefix: IdPrefix): x is string {
  if (typeof x !== "string") return false;
  if (!x.startsWith(prefix + "_")) return false;
  const body = x.slice(prefix.length + 1);
  if (body.length !== ID_BODY_LEN) return false;
  for (const c of body) if (!ALPHABET_SET.has(c)) return false;
  return true;
}

export function idPrefixOf(x: string): string | null {
  const i = x.indexOf("_");
  if (i < 0) return null;
  const p = x.slice(0, i);
  return PREFIXES.has(p) ? p : null;
}
