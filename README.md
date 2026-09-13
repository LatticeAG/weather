# Weather

[![CI](https://github.com/LatticeAG/weather/actions/workflows/ci.yml/badge.svg)](https://github.com/LatticeAG/weather/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-22%2B-blue.svg)](package.json)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![Protocol](https://img.shields.io/badge/protocol-weather%2F1-blue.svg)](#layout)

**Weather** is the LatticeAG fleet-observation and advisory-alerting core:
signed, hash-chained source streams feed four deterministic detectors
(`spend_spike/1`, `scope_drift/1`, `replication_anomaly/1`, `stream_silence/1`),
and corroborated results page operators through a durable outbox. Everything
is local: the journal is one SQLite database per fleet, evidence is canonical
JSON under Ed25519, and offline verification is pure.

> Weather is **weather, not walls**. A result means exactly this: *"these
> signed observations were admitted under this configuration, replaying to
> these decisions."* It does not establish physical truth, does not create an
> authorization boundary, and does not act on anything by itself.
> `native_truth: "NOT_ATTESTED"` is carried on every verification, and every
> exported bundle states `native_disclosure: "COMMITMENTS_ONLY"`.

## Layout

- `packages/core` — strict JSON (RFC 8785 canonicalization, duplicate-key and
  exponent rejection), domain-separated digests, Ed25519 canonicality,
  locked-width IDs, the four detector kernels, window evaluation, replay,
  offline journal verification, eval math (exact fractions + Wilson95).
- `packages/service` — the serialized fleet actor over `node:sqlite` (WAL,
  `synchronous=FULL`, one writer): source admission with 256-deep sequence
  buffering and fork retention, usage dedup, window finalization, watcher
  votes and domain corroboration, subscriptions with durable ack cursors,
  the retrying outbox, audit chain + checkpoints + bounded export, and the
  `/v1/rpc` pipeline (limits → strict parse → version → signature/fleet →
  revocation → role → idempotency → freshness → method).
- `packages/cli` — the `weather` executable: `version`, `keygen`,
  `config lint|sign|apply`, `serve`, `fleet get`, `ingest`, `watch`,
  `subscription set`, `alerts list|get|ack|close`, `audit read|checkpoint`,
  `export`, `verify`, `replay`, `eval`, `metrics`. `--json` prints one
  canonical object; exit codes follow §7.1.
- `packages/collectors` — `collect_trellis(export_path, pins, cursor)` and
  `collect_vislineage(bundle_path, pins, cursor)`: file-based SDK adapters
  that project native evidence into signed `SourceEntry` NDJSON with honest
  `verification` attribution (`VERIFIED_AT_PIN` only when the local checks
  actually pass). No live provider access exists here.
- `packages/host` — honest `NotImplemented` stubs for the Cloudflare-hosted
  fleet view and paging transport, plus the pure validators for the hosted
  identity mapping and primary-URL policy.
- `python/lattice_weather` — independent Python implementation of the same
  kernels, replay, verify, and eval (`python -m lattice_weather replay|verify|eval`).
  Python supplies reducers and clients, not a second database writer.
- `conformance/vectors.json` — the fixed `TV-W--01 … TV-W--60` suite.
- `fixtures/generate_rpc_fixtures.py` — the §6.2 signed request/response
  fixture program (deterministic test keys `bytes([n])*32`, never for real
  deployments).

## Develop

```sh
npm ci && npm test                 # TypeScript build + 60 vectors + service suite
python3 -m pytest python/tests -q  # independent Python parity over the same vectors
python3 fixtures/generate_rpc_fixtures.py  # §6.2 canonical RPC examples
```

## Smoke sketch

```sh
weather keygen --out op-key.json --public-out op-pub.json
weather serve --bootstrap bootstrap.json --data-dir ./data --audit-key-file audit-key.json
weather config lint fleet-config.json && weather config sign fleet-config.json --root-key-file root-key.json --out signed-config.json
weather config apply signed-config.json          # schedules at the next minute boundary
weather ingest entries.ndjson                    # signed SourceEntry batch
weather watch --watcher wwa_… --state-dir ./w1 --once
weather alerts list --json
weather export --out evidence.ndjson             # checkpoint-pinned bundle
weather verify evidence.ndjson --trust trust.json --json
```
