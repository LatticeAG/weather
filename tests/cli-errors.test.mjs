import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../packages/cli/dist/client.js';
import { keyFromSeed } from '../packages/cli/dist/files.js';

for (const code of ['UNAUTHORIZED', 'FORBIDDEN']) {
  test(`RPC ${code} includes an actionable hint`, async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async () => new Response(JSON.stringify({ ok: false, error: { code } }), { status: 403 });
    try {
      const client = new Client({ fleet: 'wfl_FFFFFFFFFFFFFFFFFFFFF', endpoint: 'http://localhost', timeout_ms: 1000 }, keyFromSeed(Buffer.alloc(32, 1), 'wky_111111111111111111111'));
      await assert.rejects(client.call('fleet.get', {}), e => e.rpcCode === code && e.message.includes(code === 'UNAUTHORIZED' ? 'principal key binding' : 'required role'));
    } finally { globalThis.fetch = original; }
  });
}
