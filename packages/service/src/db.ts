import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

/**
 * Local fleet storage (§8.1): DATA/FLEET/state.sqlite with WAL,
 * synchronous=FULL, foreign_keys=ON, busy_timeout=5000. JSON/BLOB columns
 * hold canonical UTF-8 bytes of validated IDL values.
 */
export const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY CHECK(seq>0), hash TEXT NOT NULL UNIQUE, prev TEXT NOT NULL, at_ms INTEGER NOT NULL, body BLOB NOT NULL, sig TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS objects (kind TEXT NOT NULL, hash TEXT NOT NULL, canonical BLOB NOT NULL, PRIMARY KEY(kind,hash)) STRICT;
CREATE TABLE IF NOT EXISTS configs (epoch INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, effective_ms INTEGER NOT NULL, state TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY, state TEXT NOT NULL, seq INTEGER NOT NULL, hash TEXT NOT NULL, activated_ms INTEGER NOT NULL, last_ms INTEGER, last_input TEXT, complete INTEGER NOT NULL CHECK(complete IN (0,1)), CHECK((last_ms IS NULL)=(last_input IS NULL))) STRICT;
CREATE TABLE IF NOT EXISTS source_slots (source TEXT NOT NULL REFERENCES sources(id), seq INTEGER NOT NULL, hash TEXT NOT NULL, entry BLOB NOT NULL, PRIMARY KEY(source,seq,hash)) STRICT;
CREATE TABLE IF NOT EXISTS pending (source TEXT NOT NULL REFERENCES sources(id), seq INTEGER NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(source,seq)) STRICT;
CREATE TABLE IF NOT EXISTS accepted (input_index INTEGER PRIMARY KEY, source TEXT NOT NULL REFERENCES sources(id), seq INTEGER NOT NULL, hash TEXT NOT NULL, received_ms INTEGER NOT NULL, counted INTEGER NOT NULL CHECK(counted IN (0,1)), late INTEGER NOT NULL CHECK(late IN (0,1)), UNIQUE(source,seq)) STRICT;
CREATE TABLE IF NOT EXISTS usage_ids (source TEXT NOT NULL REFERENCES sources(id), usage_id TEXT NOT NULL, payload_hash TEXT NOT NULL, first_index INTEGER NOT NULL, PRIMARY KEY(source,usage_id)) STRICT;
CREATE TABLE IF NOT EXISTS windows (config_hash TEXT NOT NULL, start_ms INTEGER NOT NULL, manifest_hash TEXT NOT NULL UNIQUE, PRIMARY KEY(config_hash,start_ms)) STRICT;
CREATE TABLE IF NOT EXISTS results (hash TEXT PRIMARY KEY, manifest_hash TEXT NOT NULL REFERENCES windows(manifest_hash), detector TEXT NOT NULL, target TEXT NOT NULL, UNIQUE(manifest_hash,detector,target)) STRICT;
CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, result_hash TEXT NOT NULL UNIQUE REFERENCES results(hash), state TEXT NOT NULL, assurance TEXT NOT NULL, revision INTEGER NOT NULL, expires_ms INTEGER NOT NULL, view BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS votes (result_hash TEXT NOT NULL REFERENCES results(hash), watcher TEXT NOT NULL, vote_hash TEXT NOT NULL UNIQUE, vote BLOB NOT NULL, PRIMARY KEY(result_hash,watcher)) STRICT;
CREATE TABLE IF NOT EXISTS subscriptions (id TEXT PRIMARY KEY, watcher TEXT NOT NULL, state TEXT NOT NULL, ack INTEGER NOT NULL, delivered INTEGER NOT NULL, lease_ms INTEGER NOT NULL, revision INTEGER NOT NULL, CHECK(ack<=delivered)) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS one_live_subscription ON subscriptions(watcher) WHERE state IN ('ACTIVE','PAUSED');
CREATE TABLE IF NOT EXISTS outbox (alert TEXT PRIMARY KEY REFERENCES alerts(id), page_hash TEXT NOT NULL UNIQUE, state TEXT NOT NULL, attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 8), due_ms INTEGER, lease_ms INTEGER, last_status INTEGER, cancel_pending INTEGER NOT NULL CHECK(cancel_pending IN (0,1))) STRICT;
CREATE TABLE IF NOT EXISTS requests (key_id TEXT NOT NULL, request_id TEXT NOT NULL, request_hash TEXT NOT NULL, result BLOB, expires_ms INTEGER NOT NULL, PRIMARY KEY(key_id,request_id)) STRICT;
CREATE TABLE IF NOT EXISTS objects_introduced (kind TEXT NOT NULL, hash TEXT NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY(kind,hash)) STRICT;
CREATE INDEX IF NOT EXISTS accepted_by_time ON accepted(received_ms,input_index);
CREATE INDEX IF NOT EXISTS alerts_by_state ON alerts(state,id);
CREATE INDEX IF NOT EXISTS pending_by_source ON pending(source,seq);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(state,due_ms);
`;

export function openFleetDb(dataDir: string, fleet: string): DatabaseSync {
  const dir = join(dataDir, fleet);
  mkdirSync(dir, { recursive: true });
  mkdirSync(join(dir, "exports"), { recursive: true });
  const db = new DatabaseSync(join(dir, "state.sqlite"));
  db.exec("PRAGMA journal_mode=WAL");
  db.exec("PRAGMA synchronous=FULL");
  db.exec("PRAGMA foreign_keys=ON");
  db.exec("PRAGMA busy_timeout=5000");
  db.exec(SCHEMA);
  return db;
}

export function metaGet(db: DatabaseSync, key: string): string | null {
  const r = db.prepare("SELECT value FROM meta WHERE key=?").get(key) as { value: Uint8Array } | undefined;
  return r ? Buffer.from(r.value).toString("utf8") : null;
}

export function metaSet(db: DatabaseSync, key: string, value: string): void {
  db.prepare("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run(key, Buffer.from(value, "utf8"));
}

export function metaJson<T>(db: DatabaseSync, key: string): T | null {
  const v = metaGet(db, key);
  return v === null ? null : (JSON.parse(v) as T);
}
