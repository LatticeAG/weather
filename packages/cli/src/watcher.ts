import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import {
  D, ZERO, jstr, parseText, verifyDetached, b64uDecode, b64uEncode,
  signDetached, replay, uBig,
} from "@latticeag/weather-core";
import type {
  Accepted, AlertView, Audit, ConfigEnvelope, FramePage, Head, Manifest,
  Result, SourceEntry, Subscription, TrustFile, Vote, WatcherCursor, WatcherID,
} from "@latticeag/weather-core";
import type { Client } from "./client.js";
import { CliError, atomicWrite, loadJson, stateDir, GENESIS } from "./files.js";

/**
 * weather watch (§7.1): open/read → verify frames → persist local batch →
 * replay → persist signed pending votes → send votes → ack consumed seq.
 * A crash retries identical persisted votes; nothing is fabricated locally.
 */

interface CursorFile extends WatcherCursor { }

function cursorPath(dir: string): string { return join(dir, "cursor.json"); }

export function loadCursor(dir: string, fleet: string, watcher: WatcherID): WatcherCursor {
  stateDir(dir);
  try {
    const c = loadJson<WatcherCursor>(cursorPath(dir), "watcher cursor");
    if (c.v !== 1 || c.fleet !== fleet || c.watcher !== watcher) throw new CliError(2, "cursor file mismatch");
    return c;
  } catch (e) {
    if (e instanceof CliError && e.message.includes("cannot read")) {
      return {
        v: 1, fleet: fleet as WatcherCursor["fleet"], watcher, subscription: null,
        ack: "0", head: GENESIS, config: null, pending_votes: [],
      };
    }
    throw e;
  }
}

export function saveCursor(dir: string, c: WatcherCursor): void {
  atomicWrite(cursorPath(dir), jstr(c) + "\n");
}

/** Local evidence accumulator: every seen Accepted record + object. */
export class ReplayStore {
  readonly db: DatabaseSync;
  constructor(dir: string) {
    this.db = new DatabaseSync(join(dir, "replay.sqlite"));
    this.db.exec(`
      PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS accepted (input_index INTEGER PRIMARY KEY, source TEXT NOT NULL, hash TEXT NOT NULL, received_ms INTEGER NOT NULL, counted INTEGER NOT NULL, late INTEGER NOT NULL, entry BLOB NOT NULL) STRICT;
      CREATE TABLE IF NOT EXISTS objects (kind TEXT NOT NULL, hash TEXT NOT NULL, canonical BLOB NOT NULL, PRIMARY KEY(kind,hash)) STRICT;
      CREATE TABLE IF NOT EXISTS manifests (hash TEXT PRIMARY KEY, start_ms INTEGER NOT NULL, end_ms INTEGER NOT NULL, config_hash TEXT NOT NULL) STRICT;
      CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, result_hash TEXT NOT NULL) STRICT;
    `);
  }
  putAccepted(a: Accepted): void {
    this.db.prepare("INSERT OR IGNORE INTO accepted VALUES(?,?,?,?,?,?,?)")
      .run(Number(uBig(a.index)), a.entry.body.source, a.entry.hash, Number(uBig(a.received_ms)), a.counted ? 1 : 0, a.late ? 1 : 0,
        Buffer.from(jstr(a.entry), "utf8"));
  }
  putObject(kind: string, hash: string, value: unknown): void {
    this.db.prepare("INSERT OR IGNORE INTO objects VALUES(?,?,?)").run(kind, hash, Buffer.from(jstr(value), "utf8"));
    if (kind === "manifest") {
      const m = value as Manifest;
      this.db.prepare("INSERT OR IGNORE INTO manifests VALUES(?,?,?,?)")
        .run(hash, Number(uBig(m.start_ms)), Number(uBig(m.end_ms)), m.config);
    }
  }
  getObject<T>(kind: string, hash: string): T | null {
    const r = this.db.prepare("SELECT canonical FROM objects WHERE kind=? AND hash=?").get(kind, hash) as { canonical: Uint8Array } | undefined;
    return r ? JSON.parse(Buffer.from(r.canonical).toString("utf8")) as T : null;
  }
  acceptedBetween(start: bigint, end: bigint): Accepted[] {
    return (this.db.prepare("SELECT input_index, received_ms, counted, late, entry FROM accepted WHERE received_ms>=? AND received_ms<? ORDER BY input_index")
      .all(Number(start), Number(end)) as unknown as { input_index: number; received_ms: number; counted: number; late: number; entry: Uint8Array }[])
      .map((r) => ({
        index: r.input_index.toString(), received_ms: r.received_ms.toString(),
        counted: r.counted === 1, late: r.late === 1,
        entry: JSON.parse(Buffer.from(r.entry).toString("utf8")) as SourceEntry,
      }));
  }
  acceptedByHash(hash: string): Accepted | null {
    const r = this.db.prepare("SELECT input_index, received_ms, counted, late, entry FROM accepted WHERE hash=?").get(hash) as
      { input_index: number; received_ms: number; counted: number; late: number; entry: Uint8Array } | undefined;
    return r ? {
      index: r.input_index.toString(), received_ms: r.received_ms.toString(),
      counted: r.counted === 1, late: r.late === 1,
      entry: JSON.parse(Buffer.from(r.entry).toString("utf8")) as SourceEntry,
    } : null;
  }
  manifestHashAt(start: bigint, configHash: string): string | null {
    const r = this.db.prepare("SELECT hash FROM manifests WHERE start_ms=? AND config_hash=?").get(Number(start), configHash) as { hash: string } | undefined;
    return r?.hash ?? null;
  }
  putAlert(id: string, resultHash: string): void {
    this.db.prepare("INSERT OR IGNORE INTO alerts VALUES(?,?)").run(id, resultHash);
  }
  alertForResult(h: string): string | null {
    const r = this.db.prepare("SELECT id FROM alerts WHERE result_hash=?").get(h) as { id: string } | undefined;
    return r?.id ?? null;
  }
  close(): void { this.db.close(); }
}

/** Verify an audit entry's hash+signature+chain against the trust audit pin. */
export function verifyAuditEntry(e: Audit, prevHash: string, auditPub: string): void {
  const recomputed = D("WEATHER-AUDIT/1", e.body);
  if (recomputed !== e.hash) throw new CliError(6, "audit hash mismatch");
  if (e.body.prev !== prevHash) throw new CliError(6, "audit chain break");
  if (e.body.key_id !== undefined && !verifyDetached(b64uDecode(auditPub, 32, "audit"), "WEATHER-AUDIT-SIGN/1", e.hash, b64uDecode(e.sig, 64, "sig"))) {
    throw new CliError(6, "audit signature invalid");
  }
}

/** One watch pass: read → verify → persist → replay → vote → ack. */
export async function watchOnce(opts: {
  client: Client; trust: TrustFile; stateDir: string; watcher: WatcherID;
  keyId: string; seed: Uint8Array;
  onEvent?: (msg: string) => void;
}): Promise<{ head: Head; votes: number }> {
  const store = new ReplayStore(opts.stateDir);
  try {
    const cursor = loadCursor(opts.stateDir, opts.trust.fleet, opts.watcher);
    if (cursor.subscription === null) {
      const sub = await opts.client.call("subscription.open", {
        watcher: opts.watcher, after_seq: cursor.ack,
      }) as Subscription;
      cursor.subscription = sub.id;
      saveCursor(opts.stateDir, cursor);
    }
    let votes = 0;
    let head = cursor.head;
    // Read pages through one captured head.
    for (;;) {
      const page = await opts.client.call("subscription.read", {
        subscription: cursor.subscription, after_seq: cursor.ack, limit: 128,
      }) as FramePage;
      // Verify chain from the cursor's last-verified head.
      let prev = cursor.head.seq === page.entries[0]?.body.seq
        ? cursor.head.hash
        : undefined;
      let prevHash = cursor.head.hash;
      for (const e of page.entries) {
        if (uBig(e.body.seq) <= uBig(cursor.ack)) { prevHash = e.hash; continue; }
        verifyAuditEntry(e, prevHash, opts.trust.audit.public_key);
        prevHash = e.hash;
      }
      void prev;
      // Persist objects and accepted records.
      for (const o of page.objects) store.putObject(o.kind, o.hash, o.value);
      const newResults: { manifest: Manifest; resultHash: string }[] = [];
      let pendingManifest: Manifest | null = null;
      for (const e of page.entries) {
        const d = e.body.data as Record<string, unknown>;
        switch (e.body.kind) {
          case "SourceAccepted": {
            const a = (d["accepted"] ?? d) as Accepted;
            store.putAccepted(a);
            break;
          }
          case "WindowFinalized":
            pendingManifest = store.getObject<Manifest>("manifest", d["manifest"] as string);
            break;
          case "ResultFinalized":
            if (pendingManifest) newResults.push({ manifest: pendingManifest, resultHash: d["result"] as string });
            break;
          case "ConfigScheduled": case "ConfigActivated": case "KeysRevoked": {
            const cfg = store.getObject<ConfigEnvelope>("config", d["config"] as string);
            if (cfg) cursor.config = cfg.hash;
            break;
          }
          case "AlertCreated": {
            const av = d["alert"] as AlertView;
            store.putAlert(av.id, av.result);
            break;
          }
          default: break;
        }
      }
      // Replay each finalized window; sign votes for recomputed HIT results.
      for (const { manifest, resultHash } of newResults) {
        const cfg = store.getObject<ConfigEnvelope>("config", manifest.config);
        if (!cfg) continue;
        const accepted = store.acceptedBetween(uBig(manifest.start_ms), uBig(manifest.end_ms));
        const history: { manifest: Manifest; accepted: Accepted[] }[] = [];
        for (const hh of manifest.history) {
          const hm = store.getObject<Manifest>("manifest", hh);
          if (!hm) break;
          history.push({ manifest: hm, accepted: store.acceptedBetween(uBig(hm.start_ms), uBig(hm.end_ms)) });
        }
        const last_inputs: Accepted[] = [];
        for (const c of manifest.cuts) {
          if (c.last_input !== null) {
            const a = store.acceptedByHash(c.last_input);
            if (a) last_inputs.push(a);
          }
        }
        let out;
        try {
          out = replay({ config: cfg, manifest, accepted, history, last_inputs });
        } catch { continue; } // incomplete local evidence: no vote
        const recomputed = out.results.find((r) => r.hash === resultHash);
        if (!recomputed) continue; // mismatch → abstain, never sign
        if (recomputed.body.decision.status !== "HIT") continue;
        const alertId = store.alertForResult(resultHash);
        if (!alertId) continue;
        if (cursor.pending_votes.some((v) => v.body.result === resultHash)) continue;
        const voteBody = {
          v: 1 as const, fleet: opts.trust.fleet, watcher: opts.watcher,
          config: manifest.config, result: resultHash, manifest: out.manifest,
          key_id: opts.keyId,
        };
        const vh = D("WEATHER-VOTE/1", voteBody);
        const vote: Vote = {
          body: voteBody, hash: vh,
          sig: b64uEncode(signDetached(opts.seed, "WEATHER-VOTE-SIGN/1", vh)),
        };
        cursor.pending_votes.push(vote);
      }
      head = page.through;
      if (!page.more) break;
    }
    // Send persisted votes, then acknowledge through the captured head.
    const remaining: Vote[] = [];
    for (const v of cursor.pending_votes) {
      try {
        await opts.client.call("vote.submit", { vote: v });
        votes++;
      } catch (e) {
        // Duplicate/expired/conflicting votes are final; transport errors keep
        // the identical signed vote queued for the next pass.
        if (e instanceof CliError && e.code === 7) { remaining.push(v); continue; }
        if (e instanceof CliError && (e.code === 3 || e.code === 4)) continue;
        remaining.push(v);
      }
    }
    cursor.pending_votes = remaining;
    await opts.client.call("subscription.ack", {
      subscription: cursor.subscription, through_seq: head.seq,
    });
    cursor.ack = head.seq;
    cursor.head = head;
    saveCursor(opts.stateDir, cursor);
    return { head, votes };
  } finally {
    store.close();
  }
}
