#!/usr/bin/env node
// Local-only smoke: generated keys and state are removed on exit.
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { artifactDigest } from '../packages/core/dist/index.js';

const dir = mkdtempSync(resolve('.weather-smoke-'));
const cli = resolve('packages/cli/dist/main.js');
const port = process.env.WEATHER_SMOKE_PORT ?? '18787';
let server;
const run = (...args) => {
  const r = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`${args.join(' ')}: ${r.stderr}`);
  return r.stdout;
};
const file = (name) => join(dir, name);
const write = (name, value) => writeFileSync(file(name), JSON.stringify(value));
try {
  for (const name of ['root', 'audit', 'operator']) run('keygen', '--out', file(`${name}-key.json`), '--public-out', file(`${name}-pub.json`));
  const pin = name => { const { key_id, public_key } = JSON.parse(readFileSync(file(`${name}-pub.json`))); return { key_id, public_key }; };
  const fleet = 'wfl_FFFFFFFFFFFFFFFFFFFFF';
  write('bootstrap.json', { v: 1, fleets: [{ fleet, root: pin('root'), audit: pin('audit'), allowed_view_origin: null, primary_url: null }] });
  write('trust.json', { v: 1, fleet, root: pin('root'), audit: pin('audit'), minimum_head: null });
  write('client.json', { v: 1, endpoint: `http://127.0.0.1:${port}`, fleet, principal_key_file: file('root-key.json'), trust_file: file('trust.json'), timeout_ms: 2000 });
  const pairs = readFileSync('fixtures/rpc_pairs.jsonl', 'utf8').trim().split('\n').map(JSON.parse);
  const config = pairs.find(p => p.request.body.method === 'config.put').request.body.params.config.body;
  const files = ['index.js', 'schema.js', 'jcs.js', 'hash.js', 'ed25519.js', 'detectors.js', 'kernels.js', 'window.js', 'replay.js', 'verify.js', 'eval.js', 'pack.js', 'usage.js', 'types.js', 'errors.js', 'base64.js', 'ids.js', 'json.js'];
  config.pack_digest = artifactDigest(files.map(path => ({ path, sha256: createHash('sha256').update(readFileSync(`packages/core/dist/${path}`)).digest('hex') })));
  config.effective_ms = String((Math.floor(Date.now() / 60000) + 1) * 60000);
  config.sources = []; config.subjects = []; config.watchers = [];
  config.principals = [{ id: 'wpr_666666666666666666666', pin: pin('operator'), roles: ['operator', 'reader'] }];
  write('fleet-config.json', config);
  process.stdout.write(run('config', 'lint', file('fleet-config.json'), '--json'));
  run('config', 'sign', file('fleet-config.json'), '--root-key-file', file('root-key.json'), '--out', file('signed-config.json'));
  server = spawn(process.execPath, [cli, 'serve', '--bootstrap', file('bootstrap.json'), '--data-dir', file('data'), '--audit-key-file', file('audit-key.json'), '--listen', `127.0.0.1:${port}`], { stdio: 'ignore' });
  let ready = false;
  for (let i = 0; i < 50; i++) {
    try { const r = await fetch(`http://127.0.0.1:${port}/healthz`); if (r.ok) { ready = true; break; } } catch {}
    await new Promise(r => setTimeout(r, 100));
  }
  if (!ready || server.exitCode !== null) throw new Error('server failed to start');
  process.stdout.write(run('fleet', 'get', '--config', file('client.json'), '--json'));
  process.stdout.write(run('config', 'apply', file('signed-config.json'), '--config', file('client.json'), '--json'));
} finally {
  if (server) { server.kill(); await new Promise(r => server.once('exit', r)); }
  rmSync(dir, { recursive: true, force: true });
}
