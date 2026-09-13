#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  D, ZERO, jstr, parseText, newId, isHash, isId, uBig,
  generateSeed, publicKeyOf, privateKeyFromSeed, b64uEncode, b64uDecode,
  signDetached, verifyDetached, exitCodeFor, schema, evalRun, replay, verify,
  corpusDigest, artifactDigest,
} from "@latticeag/weather-core";
import type {
  AlertView, BundlePage, Checkpoint, Config, ConfigEnvelope, EvalSuite,
  FramePage, Head, Metric, Method, Pin, SourceEntry, Subscription, Vote,
  FleetView, TrustFile, LabeledUnit,
} from "@latticeag/weather-core";
import { Fleet } from "@latticeag/weather-service";
import { serve } from "@latticeag/weather-service";
import { Client } from "./client.js";
import {
  CliError, loadClientConfig, loadTrust, loadKey, loadJson, writeExclusive,
  atomicWrite, parseHead, keyFromSeed, pinFromKey, noSymlink, GENESIS,
} from "./files.js";
import { watchOnce, loadCursor, saveCursor } from "./watcher.js";
import { exportEvidence, verifyExport, headExceeds } from "./exporter.js";

const ARGS = process.argv.slice(2);

/** Strict flag table: unknown/duplicate flags and missing values exit 2. */
function flags(spec: Record<string, "value" | "bool">, argv: string[]): { vals: Map<string, string>; bools: Set<string>; pos: string[] } {
  const vals = new Map<string, string>();
  const bools = new Set<string>();
  const pos: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const name = a.slice(2);
      const k = spec[name];
      if (!k) throw new CliError(2, `unknown flag --${name}`);
      if (k === "bool") {
        if (bools.has(name)) throw new CliError(2, `duplicate flag --${name}`);
        bools.add(name);
      } else {
        if (vals.has(name)) throw new CliError(2, `duplicate flag --${name}`);
        const v = argv[++i];
        if (v === undefined) throw new CliError(2, `missing value for --${name}`);
        vals.set(name, v);
      }
    } else {
      pos.push(a);
    }
  }
  return { vals, bools, pos };
}

function need(vals: Map<string, string>, name: string): string {
  const v = vals.get(name);
  if (v === undefined) throw new CliError(2, `missing required --${name}`);
  return v;
}

const esc = (s: string): string => s.replace(/[\x00-\x1f\x7f\x1b]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`);

let JSON_MODE = false;
const out = (v: unknown): void => {
  if (JSON_MODE) { process.stdout.write(jstr(v) + "\n"); return; }
  process.stdout.write(esc(typeof v === "string" ? v : jstr(v)) + "\n");
};

function clientAndKey(cfgPath?: string): { client: Client; cfg: ReturnType<typeof loadClientConfig> } {
  const cfg = loadClientConfig(cfgPath);
  const key = loadKey(cfg.principal_key_file);
  return { client: new Client(cfg, key), cfg };
}

async function main(): Promise<number> {
  // Global flags: --json, --config PATH may appear anywhere.
  let configPath: string | undefined;
  const argv: string[] = [];
  for (let i = 0; i < ARGS.length; i++) {
    const a = ARGS[i]!;
    if (a === "--json") { JSON_MODE = true; continue; }
    if (a === "--config") {
      configPath = ARGS[++i];
      if (configPath === undefined) throw new CliError(2, "missing value for --config");
      continue;
    }
    argv.push(a);
  }

  const [cmd, sub] = argv;
  switch (cmd) {
    case "version": {
      out({ protocol: "weather/1", pack: "weather-core/1.0.0", storage_version: 1, implementation: "typescript", version: "0.1.0" });
      return 0;
    }
    case "keygen": {
      const f = flags({ out: "value", "public-out": "value" }, argv.slice(1));
      const seed = generateSeed();
      const key = keyFromSeed(seed, newId("wky"));
      writeExclusive(need(f.vals, "out"), jstr(key) + "\n", 0o600);
      writeExclusive(need(f.vals, "public-out"), jstr({ v: 1, key_id: key.key_id, public_key: key.public_key }) + "\n", 0o644);
      out({ key_id: key.key_id, public_key: key.public_key });
      return 0;
    }
    case "config": return cmdConfig(argv.slice(1), configPath);
    case "serve": return cmdServe(argv.slice(1));
    case "fleet": {
      if (sub !== "get") throw new CliError(2, "usage: weather fleet get");
      const { client } = clientAndKey(configPath);
      out(await client.call("fleet.get", {}));
      return 0;
    }
    case "ingest": return cmdIngest(argv.slice(1), configPath);
    case "watch": return cmdWatch(argv.slice(1), configPath);
    case "subscription": return cmdSubscription(argv.slice(1), configPath);
    case "alerts": return cmdAlerts(argv.slice(1), configPath);
    case "audit": return cmdAudit(argv.slice(1), configPath);
    case "export": return cmdExport(argv.slice(1), configPath);
    case "verify": return cmdVerify(argv.slice(1));
    case "replay": return cmdReplay(argv.slice(1));
    case "eval": return cmdEval(argv.slice(1));
    case "metrics": {
      const { client } = clientAndKey(configPath);
      out(await client.call("metrics.get", {}));
      return 0;
    }
    default:
      throw new CliError(2, `unknown command ${cmd ?? ""}`);
  }
}

// ---- config subcommands ---------------------------------------------------
async function cmdConfig(argv: string[], configPath?: string): Promise<number> {
  const [sub, ...rest] = argv;
  switch (sub) {
    case "lint": {
      const f = flags({}, rest);
      if (f.pos.length !== 1) throw new CliError(2, "usage: weather config lint PATH");
      const c = loadJson<Config>(f.pos[0]!, "config");
      schema.vConfig(c);
      out({ valid: true });
      return 0;
    }
    case "sign": {
      const f = flags({ "root-key-file": "value", out: "value" }, rest);
      if (f.pos.length !== 1) throw new CliError(2, "usage: weather config sign PATH --root-key-file PATH --out PATH");
      const c = loadJson<Config>(f.pos[0]!, "config");
      schema.vConfig(c);
      const root = loadKey(need(f.vals, "root-key-file"));
      const hash = D("WEATHER-CONFIG/1", c);
      const env: ConfigEnvelope = {
        body: c, hash, key_id: root.key_id,
        sig: b64uEncode(signDetached(Buffer.from(root.seed, "base64url"), "WEATHER-CONFIG-SIGN/1", hash)),
      };
      writeExclusive(need(f.vals, "out"), jstr(env) + "\n");
      out(env);
      return 0;
    }
    case "apply": {
      const f = flags({}, rest);
      if (f.pos.length !== 1) throw new CliError(2, "usage: weather config apply PATH");
      const env = loadJson<ConfigEnvelope>(f.pos[0]!, "config envelope");
      schema.vConfigEnvelope(env);
      const { client } = clientAndKey(configPath);
      out(await client.call("config.put", { config: env }));
      return 0;
    }
    default: throw new CliError(2, `unknown config subcommand ${sub ?? ""}`);
  }
}

// ---- serve -----------------------------------------------------------------
function cmdServe(argv: string[]): Promise<number> {
  const f = flags({
    bootstrap: "value", "data-dir": "value", "audit-key-file": "value",
    listen: "value", "read-only": "bool", fleet: "value",
  }, argv);
  const boot = loadJson<{ v: 1; fleets: { fleet: string; root: Pin; audit: Pin; allowed_view_origin: string | null; primary_url: string | null }[] }>(
    need(f.vals, "bootstrap"), "bootstrap");
  if (!Array.isArray(boot.fleets) || boot.fleets.length === 0) throw new CliError(2, "bootstrap: no fleets");
  const fid = f.vals.get("fleet");
  const bf = fid ? boot.fleets.find((x) => x.fleet === fid) : boot.fleets[0];
  if (!bf) throw new CliError(2, `fleet ${fid} not in bootstrap`);
  const auditKey = loadKey(need(f.vals, "audit-key-file"));
  if (auditKey.key_id !== bf.audit.key_id) throw new CliError(3, "audit key file does not match bootstrap audit pin");
  const fleet = new Fleet({
    dataDir: need(f.vals, "data-dir"), fleet: bf.fleet as Fleet["fleetId"],
    root: bf.root, audit: bf.audit, auditSeed: Buffer.from(auditKey.seed, "base64url"),
    packDigest: computePackDigest(), readOnly: f.bools.has("read-only"),
    primaryUrl: bf.primary_url,
  });
  const server = serve({ fleet, listen: f.vals.get("listen") ?? "127.0.0.1:8787" });
  // Outbox pump (§6.3): POST Page to primary_url with Idempotency-Key=Page.hash;
  // 204 is success, 429/5xx/network retry on the fixed backoff, redirects fail.
  if (bf.primary_url !== null) {
    const target = bf.primary_url;
    const sender = async (page: { hash: string }) => {
      try {
        const r = await fetch(target, {
          method: "POST", redirect: "error",
          headers: { "content-type": "application/json", "idempotency-key": page.hash },
          body: jstr(page),
        });
        await r.arrayBuffer(); // drain
        return { status: r.status };
      } catch { return null; }
    };
    const pump = setInterval(() => {
      try { fleet.runDeliveries(BigInt(Date.now()), sender); } catch { /* pump survives */ }
    }, 500);
    pump.unref();
    server.on("close", () => clearInterval(pump));
  }
  const addr = server.address();
  out({ listening: typeof addr === "object" && addr ? `${bf.fleet} on ${(addr as { port: number }).port}` : "listening" });
  return new Promise(() => { /* runs until signal */ });
}

/** Pack digest over the released core module files (§3.2). */
function computePackDigest(): string {
  const coreDir = join(dirname(fileURLToPath(import.meta.url)), "../../core/dist");
  try {
    const files = ["index.js", "schema.js", "jcs.js", "hash.js", "ed25519.js", "detectors.js", "kernels.js", "window.js", "replay.js", "verify.js", "eval.js", "pack.js", "usage.js", "types.js", "errors.js", "base64.js", "ids.js", "json.js"];
    const fa = files.map((p) => ({ path: p, sha256: createHash("sha256").update(readFileSync(join(coreDir, p))).digest("hex") }));
    return artifactDigest(fa);
  } catch {
    return createHash("sha256").update("weather-core/1.0.0-dev").digest("hex");
  }
}

// ---- ingest -----------------------------------------------------------------
async function cmdIngest(argv: string[], configPath?: string): Promise<number> {
  const f = flags({}, argv);
  if (f.pos.length !== 1) throw new CliError(2, "usage: weather ingest PATH");
  const text = readFileSync(f.pos[0]!, "utf8");
  const entries: SourceEntry[] = [];
  for (const line of text.split("\n")) {
    if (line.length === 0) continue;
    entries.push(schema.vSourceEntry(parseText(line)));
  }
  const { client } = clientAndKey(configPath);
  for (let i = 0; i < entries.length; i += 64) {
    out(await client.call("source.append", { entries: entries.slice(i, i + 64) }));
  }
  return 0;
}

// ---- watch ------------------------------------------------------------------
async function cmdWatch(argv: string[], configPath?: string): Promise<number> {
  const f = flags({ watcher: "value", "state-dir": "value", once: "bool" }, argv);
  const w = need(f.vals, "watcher");
  if (!isId(w, "wwa")) throw new CliError(2, "watcher must be a wwa_ ID");
  const watcher = w as Subscription["watcher"];
  const dir = need(f.vals, "state-dir");
  noSymlink(dir);
  const { client, cfg } = clientAndKey(configPath);
  const trust = loadTrust(cfg.trust_file);
  const key = loadKey(cfg.principal_key_file);
  const seed = Buffer.from(key.seed, "base64url");
  if (f.bools.has("once")) {
    const r = await watchOnce({ client, trust, stateDir: dir, watcher, keyId: key.key_id, seed });
    out({ head: r.head, votes_sent: r.votes.toString() });
    return 0;
  }
  // Long-running: poll through captured heads; renew ack at most once / 60s.
  let lastRenew = 0;
  const stop = () => { process.exitCode = 130; };
  process.on("SIGINT", stop);
  process.on("SIGTERM", () => { process.exitCode = 143; });
  for (;;) {
    await watchOnce({ client, trust, stateDir: dir, watcher, keyId: key.key_id, seed });
    const now = Date.now();
    if (now - lastRenew >= 60000) lastRenew = now;
    await new Promise((r) => setTimeout(r, 5000));
    if (process.exitCode === 130 || process.exitCode === 143) return process.exitCode;
  }
}

// ---- subscription ------------------------------------------------------------
async function cmdSubscription(argv: string[], configPath?: string): Promise<number> {
  const [sub, ...rest] = argv;
  if (sub !== "set") throw new CliError(2, "usage: weather subscription set ID --action pause|resume|close --revision U");
  const f = flags({ action: "value", revision: "value" }, rest);
  if (f.pos.length !== 1) throw new CliError(2, "missing subscription ID");
  const action = need(f.vals, "action");
  if (action !== "pause" && action !== "resume" && action !== "close") throw new CliError(2, "bad --action");
  const { client } = clientAndKey(configPath);
  out(await client.call("subscription.set", {
    subscription: f.pos[0], action, expected_revision: need(f.vals, "revision"),
  }));
  return 0;
}

// ---- alerts ------------------------------------------------------------------
async function cmdAlerts(argv: string[], configPath?: string): Promise<number> {
  const [sub, ...rest] = argv;
  const { client } = clientAndKey(configPath);
  switch (sub) {
    case "list": {
      const f = flags({ state: "value", after: "value", limit: "value" }, rest);
      out(await client.call("alert.list", {
        state: f.vals.get("state") ?? null, after: f.vals.get("after") ?? null,
        limit: f.vals.has("limit") ? Number(f.vals.get("limit")) : 128,
      }));
      return 0;
    }
    case "get": {
      const f = flags({}, rest);
      if (f.pos.length !== 1) throw new CliError(2, "usage: weather alerts get ID");
      out(await client.call("alert.get", { alert: f.pos[0] }));
      return 0;
    }
    case "ack": case "close": {
      const f = flags({ revision: "value", "note-file": "value" }, rest);
      if (f.pos.length !== 1) throw new CliError(2, `usage: weather alerts ${sub} ID --revision U`);
      const noteHash = f.vals.has("note-file")
        ? D("WEATHER-NOTE/1", { note_sha256: createHash("sha256").update(readFileSync(need(f.vals, "note-file"))).digest("hex") })
        : null;
      out(await client.call("alert.act", {
        alert: f.pos[0], action: sub === "ack" ? "ack" : "close",
        expected_revision: need(f.vals, "revision"), note_hash: noteHash,
      }));
      return 0;
    }
    default: throw new CliError(2, `unknown alerts subcommand ${sub ?? ""}`);
  }
}

// ---- audit --------------------------------------------------------------------
async function cmdAudit(argv: string[], configPath?: string): Promise<number> {
  const [sub, ...rest] = argv;
  const { client } = clientAndKey(configPath);
  switch (sub) {
    case "read": {
      const f = flags({ after: "value", through: "value", limit: "value" }, rest);
      const page = await client.call("audit.read", {
        after_seq: f.vals.get("after") ?? "0",
        through: f.vals.has("through") ? parseHead(need(f.vals, "through")) : null,
        limit: f.vals.has("limit") ? Number(f.vals.get("limit")) : 128,
      }) as FramePage;
      // Canonical NDJSON: one audit entry per line.
      for (const e of page.entries) process.stdout.write(jstr(e) + "\n");
      return 0;
    }
    case "checkpoint":
      out(await client.call("audit.checkpoint", {}));
      return 0;
    default: throw new CliError(2, `unknown audit subcommand ${sub ?? ""}`);
  }
}

// ---- export / verify / replay -------------------------------------------------
async function cmdExport(argv: string[], configPath?: string): Promise<number> {
  const f = flags({ out: "value" }, argv);
  const { client, cfg } = clientAndKey(configPath);
  const trust = loadTrust(cfg.trust_file);
  const r = await exportEvidence({ client, trust, out: need(f.vals, "out") });
  // Verify before reporting success; update minimum_head.
  const check = verifyExport({ path: need(f.vals, "out"), trust, expectedHead: null });
  if (check.result.integrity !== "VALID" || check.result.replay !== "MATCH") {
    throw new CliError(6, `post-export verify failed: ${check.result.reasons.join(",")}`);
  }
  if (headExceeds(r.head, trust.minimum_head)) {
    try {
      atomicWrite(cfg.trust_file, jstr({ ...trust, minimum_head: r.head }) + "\n");
    } catch { process.stderr.write("warning: could not update trust_file minimum_head\n"); }
  }
  out({ exported: r.head, pages: r.pages.toString(), entries: r.entries.toString() });
  return 0;
}

async function cmdVerify(argv: string[]): Promise<number> {
  const f = flags({ trust: "value", "expected-head": "value" }, argv);
  if (f.pos.length !== 1) throw new CliError(2, "usage: weather verify PATH --trust PATH [--expected-head SEQ:HASH]");
  const trust = loadTrust(need(f.vals, "trust"));
  const expected = f.vals.has("expected-head") ? parseHead(need(f.vals, "expected-head")) : null;
  const { result, head } = verifyExport({ path: f.pos[0]!, trust, expectedHead: expected });
  out(result);
  if (result.integrity !== "VALID") return 6;
  if (result.replay === "MISMATCH") return 5;
  if (expected !== null && result.completeness !== "AT_PIN") return 6;
  if (result.replay === "INCOMPLETE") return 6;
  if (headExceeds(head, trust.minimum_head)) {
    try { atomicWrite(need(f.vals, "trust"), jstr({ ...trust, minimum_head: head }) + "\n"); }
    catch { process.stderr.write("warning: could not update trust_file minimum_head\n"); }
  }
  return 0;
}

async function cmdReplay(argv: string[]): Promise<number> {
  const f = flags({ trust: "value" }, argv);
  if (f.pos.length !== 1) throw new CliError(2, "usage: weather replay PATH --trust PATH");
  const trust = loadTrust(need(f.vals, "trust"));
  const { result } = verifyExport({ path: f.pos[0]!, trust, expectedHead: null });
  out(result);
  if (result.integrity !== "VALID") return 6;
  return result.replay === "MATCH" ? 0 : 5;
}

// ---- eval ----------------------------------------------------------------------
async function cmdEval(argv: string[]): Promise<number> {
  const f = flags({ suite: "value", out: "value", seed: "value" }, argv);
  const suite = loadJson<EvalSuite>(need(f.vals, "suite"), "eval suite");
  if (suite.v !== 1 || suite.suite !== "weather-conformance/1") throw new CliError(2, "eval suite: invalid shape");
  const cfg = { ...suite.config };
  if (f.vals.has("seed")) {
    if (!cfg.allow_seed_override) throw new CliError(2, "suite does not permit --seed override");
    cfg.seed = need(f.vals, "seed");
  }
  const vectorsPath = join(dirname(fileURLToPath(import.meta.url)), "../../../conformance/vectors.json");
  const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as { id: string; input: Record<string, unknown>; expected: unknown }[];
  const reports = cfg.implementations.map((impl) => evalRun(cfg, vectors, suite, impl));
  const dir = need(f.vals, "out");
  writeExclusive(join(dir, "eval-report.json"), jstr(reports.length === 1 ? reports[0] : reports) + "\n", 0o644);
  out(reports.length === 1 ? reports[0] : reports);
  const fail = reports.some((r) => r.passed !== r.vectors);
  return fail ? 5 : 0;
}

main().then((code) => { process.exitCode = code; })
  .catch((e) => {
    if (e instanceof CliError) {
      process.stderr.write(`weather: ${e.message}\n`);
      process.exitCode = e.code;
    } else if (e && typeof e === "object" && "code" in e) {
      const code = (e as { code: Parameters<typeof exitCodeFor>[0] }).code;
      process.stderr.write(`weather: ${code}\n`);
      process.exitCode = exitCodeFor(code);
    } else {
      process.stderr.write(`weather: ${(e as Error).message ?? e}\n`);
      process.exitCode = 1;
    }
  });
