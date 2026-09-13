import { openSync, readFileSync, writeFileSync, renameSync, statSync, lstatSync, mkdirSync, constants, fsyncSync, closeSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { D, ZERO, jstr, parseText, isId, isHash, publicKeyOf, privateKeyFromSeed, b64uEncode } from "@latticeag/weather-core";
import type { ClientConfig, TrustFile, PrivateKeyFile, Pin, Head } from "@latticeag/weather-core";

/** Strict local file IO: no-follow, owner-only private keys, exclusive create. */

export class CliError extends Error {
  constructor(readonly code: number, msg: string) { super(msg); this.name = "CliError"; }
}

export function loadJson<T>(path: string, what: string): T {
  let raw: string;
  try { raw = readFileSync(path, "utf8"); }
  catch { throw new CliError(2, `${what}: cannot read ${path}`); }
  try { return parseText(raw) as T; }
  catch (e) { throw new CliError(2, `${what}: ${(e as Error).message}`); }
}

export function writeExclusive(path: string, data: string, mode = 0o600): void {
  let fd: number;
  try { fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, mode); }
  catch { throw new CliError(2, `refusing to overwrite existing ${path}`); }
  try { writeFileSync(fd, data); fsyncSync(fd); } finally { closeSync(fd); }
}

/** Atomic replace: tmp file in same dir, fsync, rename. */
export function atomicWrite(path: string, data: string, mode = 0o600): void {
  const dir = join(path, "..");
  const tmp = join(dir, `.${path.split("/").pop()}.tmp-${process.pid}`);
  writeExclusive(tmp, data, mode);
  try { renameSync(tmp, path); }
  catch (e) { throw new CliError(1, `atomic write ${path}: ${(e as Error).message}`); }
}

export function noSymlink(path: string): void {
  try { if (lstatSync(path).isSymbolicLink()) throw new CliError(2, `refusing symlinked path ${path}`); }
  catch (e) { if (e instanceof CliError) throw e; /* ENOENT ok */ }
}

export function stateDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const st = statSync(path);
  if (!st.isDirectory()) throw new CliError(2, `${path} is not a directory`);
}

export function loadClientConfig(path?: string): ClientConfig {
  const p = path ?? process.env["WEATHER_CONFIG"] ?? join(homedir(), ".config", "weather", "client.json");
  const c = loadJson<ClientConfig>(p, "client config");
  if (c.v !== 1 || typeof c.endpoint !== "string" || !isId(c.fleet, "wfl") ||
    typeof c.principal_key_file !== "string" || typeof c.trust_file !== "string" ||
    typeof c.timeout_ms !== "number") {
    throw new CliError(2, "client config: invalid shape");
  }
  const u = new URL(c.endpoint);
  if (u.username || u.password || u.search || u.hash) throw new CliError(2, "endpoint must not carry credentials/query/fragment");
  const loopback = u.hostname === "127.0.0.1" || u.hostname === "::1" || u.hostname === "localhost";
  if (u.protocol === "http:" && !loopback) throw new CliError(2, "HTTP endpoint permitted only for literal loopback");
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new CliError(2, "endpoint must be HTTP(S)");
  return c;
}

export function loadTrust(path: string): TrustFile {
  const t = loadJson<TrustFile>(path, "trust file");
  if (t.v !== 1 || !isId(t.fleet, "wfl") || !isId(t.root.key_id, "wky") || !isId(t.audit.key_id, "wky")) {
    throw new CliError(2, "trust file: invalid shape");
  }
  if (t.minimum_head !== null && (!isHash(t.minimum_head.hash) || !/^\d+$/.test(t.minimum_head.seq))) {
    throw new CliError(2, "trust file: invalid minimum_head");
  }
  return t;
}

export function loadKey(path: string): PrivateKeyFile {
  noSymlink(path);
  const st = statSync(path);
  if (st.mode & 0o077) throw new CliError(2, `key file ${path} must be mode 0600 (owner-only)`);
  const k = loadJson<PrivateKeyFile>(path, "private key file");
  if (k.v !== 1 || !isId(k.key_id, "wky") || typeof k.seed !== "string") {
    throw new CliError(2, "key file: invalid shape");
  }
  const seed = Buffer.from(k.seed, "base64url");
  if (seed.length !== 32) throw new CliError(2, "key file: seed must decode to 32 bytes");
  const derived = b64uEncode(publicKeyOf(privateKeyFromSeed(seed)));
  if (derived !== k.public_key) throw new CliError(2, "key file: public_key does not match seed");
  return k;
}

export function keyFromSeed(seed: Uint8Array, keyId: string): PrivateKeyFile {
  return {
    v: 1, key_id: keyId as PrivateKeyFile["key_id"],
    public_key: b64uEncode(publicKeyOf(privateKeyFromSeed(seed))),
    seed: Buffer.from(seed).toString("base64url"),
  };
}

export function pinFromKey(k: PrivateKeyFile): Pin {
  return { key_id: k.key_id, public_key: k.public_key };
}

export function parseHead(s: string): Head {
  const i = s.indexOf(":");
  if (i < 0) throw new CliError(2, `expected SEQ:HASH, got ${s}`);
  const seq = s.slice(0, i), hash = s.slice(i + 1);
  if (!/^\d+$/.test(seq) || !isHash(hash)) throw new CliError(2, `invalid SEQ:HASH ${s}`);
  return { seq, hash };
}

export const GENESIS: Head = { seq: "0", hash: ZERO };
export { D };
