import { createWriteStream, readFileSync, statSync, existsSync, renameSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  D, jstr, parseText, verifyDetached, b64uDecode, verify, uBig,
} from "@latticeag/weather-core";
import type { BundlePage, Checkpoint, Head, TrustFile, VerifyResult } from "@latticeag/weather-core";
import type { Client } from "./client.js";
import { CliError, GENESIS } from "./files.js";

const EXPORT_MAX_BYTES = 12n * 1024n * 1024n * 1024n;

/** Descends: candidate head seq >= minimum seq and equal ancestry at minimum. */
function headDescends(head: Head, minimum: Head | null): boolean {
  if (minimum === null) return true;
  return uBig(head.seq) >= uBig(minimum.seq);
}

/**
 * weather export: pin a fresh checkpoint (verify audit sig + ancestry vs
 * trust.minimum_head), page bundle.export to EOF, then atomically install the
 * NDJSON evidence file: header, one `page` record per BundlePage, trailer.
 */
export async function exportEvidence(opts: {
  client: Client; trust: TrustFile; out: string;
}): Promise<{ head: Head; pages: bigint; entries: bigint }> {
  const cp = await opts.client.call("audit.checkpoint", {}) as Checkpoint;
  if (cp.hash !== D("WEATHER-CHECKPOINT/1", cp.body)) throw new CliError(6, "checkpoint hash mismatch");
  if (cp.body.fleet !== opts.trust.fleet || cp.body.key_id !== opts.trust.audit.key_id) {
    throw new CliError(6, "checkpoint not bound to this fleet/audit pin");
  }
  if (!verifyDetached(b64uDecode(opts.trust.audit.public_key, 32, "audit"), "WEATHER-CHECKPOINT-SIGN/1", cp.hash, b64uDecode(cp.sig, 64, "sig"))) {
    throw new CliError(6, "checkpoint signature invalid");
  }
  if (!headDescends(cp.body.head, opts.trust.minimum_head)) {
    throw new CliError(6, "checkpoint head does not descend from minimum_head");
  }
  const tmp = `${opts.out}.tmp-${process.pid}`;
  if (existsSync(opts.out)) throw new CliError(2, `refusing to overwrite ${opts.out}`);
  const ws = createWriteStream(tmp, { flags: "wx", mode: 0o600 });
  let bytes = 0n;
  const write = (s: string) => {
    bytes += BigInt(Buffer.byteLength(s));
    if (bytes > EXPORT_MAX_BYTES) {
      ws.destroy(); rmSync(tmp, { force: true });
      throw new CliError(7, "export exceeds 12 GiB bound");
    }
    ws.write(s);
  };
  try {
    write(jstr({ record: "header", v: 1, format: "weather-evidence/1", checkpoint: cp }) + "\n");
    let after = "0";
    let pages = 0n, entries = 0n;
    for (;;) {
      const page = await opts.client.call("bundle.export", {
        after_seq: after, checkpoint: cp, limit: 128,
      }) as BundlePage;
      write(jstr({ record: "page", page }) + "\n");
      pages++;
      entries += BigInt(page.entries.length);
      if (!page.more) { after = page.next_seq; break; }
      after = page.next_seq;
    }
    write(jstr({ record: "trailer", pages: pages.toString(), entries: entries.toString(), head: cp.body.head }) + "\n");
    await new Promise<void>((res, rej) => { ws.end(() => res()); ws.on("error", rej); });
    renameSync(tmp, opts.out);
    return { head: cp.body.head, pages, entries };
  } catch (e) {
    try { ws.destroy(); rmSync(tmp, { force: true }); } catch { /* keep only our own tmp removal */ }
    throw e;
  }
}

export interface ParsedExport {
  checkpoint: Checkpoint;
  pages: BundlePage[];
  entries: { body: Record<string, unknown>; hash: string; sig: string }[];
  objects: { kind: string; hash: string; value: unknown }[];
  head: Head;
}

/** Parse an evidence file into checkpoint + deduplicated entries/objects. */
export function parseExport(path: string): ParsedExport {
  const text = readFileSync(path, "utf8");
  const lines = text.split("\n");
  if (lines.length === 0 || lines[lines.length - 1] !== "") throw new CliError(6, "export: missing trailing LF");
  let checkpoint: Checkpoint | null = null;
  const pages: BundlePage[] = [];
  const entries: ParsedExport["entries"] = [];
  const objects = new Map<string, { kind: string; hash: string; value: unknown }>();
  let trailer: { pages: string; entries: string; head: Head } | null = null;
  let seenPages = 0n, seenEntries = 0n;
  for (let i = 0; i < lines.length - 1; i++) {
    const rec = parseText(lines[i]!) as { record: string; [k: string]: unknown };
    if (i === 0) {
      if (rec.record !== "header" || rec["format"] !== "weather-evidence/1") throw new CliError(6, "export: bad header");
      checkpoint = rec["checkpoint"] as Checkpoint;
      continue;
    }
    if (rec.record === "page") {
      const page = rec["page"] as BundlePage;
      pages.push(page);
      for (const e of page.entries) entries.push(e);
      for (const o of page.objects) objects.set(`${o.kind}:${o.hash}`, o);
      seenPages++;
      seenEntries += BigInt(page.entries.length);
      continue;
    }
    if (rec.record === "trailer") {
      trailer = { pages: rec["pages"] as string, entries: rec["entries"] as string, head: rec["head"] as Head };
      continue;
    }
    throw new CliError(6, `export: unknown record at line ${i + 1}`);
  }
  if (!checkpoint || !trailer) throw new CliError(6, "export: missing header/trailer");
  if (BigInt(trailer.pages) !== seenPages || BigInt(trailer.entries) !== seenEntries) {
    throw new CliError(6, "export: trailer counts mismatch");
  }
  // Consecutive entries 1..head.seq with no gaps/dups.
  for (let i = 0; i < entries.length; i++) {
    if (uBig(entries[i]!.body["seq"] as string) !== BigInt(i + 1)) {
      throw new CliError(6, "export: audit entries not a contiguous prefix");
    }
  }
  return { checkpoint: checkpoint!, pages, entries, objects: [...objects.values()], head: trailer.head };
}

/**
 * weather verify: offline journal verification (§6.3). Returns the
 * VerifyResult; exit-code mapping happens in the caller.
 */
export function verifyExport(opts: {
  path: string; trust: TrustFile; expectedHead: Head | null;
}): { result: VerifyResult; head: Head } {
  const parsed = parseExport(opts.path);
  const result = verify({
    pages: parsed.pages,
    root: opts.trust.root, audit: opts.trust.audit,
    expected_head: opts.expectedHead,
  });
  // minimum_head ancestry: verified head must descend from the stored pin.
  if (result.integrity === "VALID" && opts.trust.minimum_head !== null &&
    !headDescends(result.head, opts.trust.minimum_head)) {
    throw new CliError(6, "verified head does not descend from trust minimum_head");
  }
  return { result, head: result.head };
}

/** True when `head` strictly exceeds `minimum`. */
export function headExceeds(head: Head, minimum: Head | null): boolean {
  return minimum === null || uBig(head.seq) > uBig(minimum.seq);
}

export function exportDigest(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}
