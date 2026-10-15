import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Store, digest, secret } from '../src/store.mjs';

test('credential records are encrypted, durable and bound to their lookup keys', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-store-')); const path = join(dir, 'state.sqlite');
  const key = randomBytes(32).toString('hex'); const value = { token: secret() };
  let store = new Store(path, key);
  try {
    store.put('grant', 'one', value, Date.now() + 60000);
    assert.deepEqual(store.get('grant', 'one'), value);
    assert.equal(readFileSync(path).includes(Buffer.from(value.token)), false);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    store.close(); store = new Store(path, key);
    assert.deepEqual(store.get('grant', 'one'), value);
    const sealed = store.db.prepare('SELECT value FROM records').get().value;
    assert.throws(() => store.open('grant', 'other', sealed));
  } finally { store.close(); rmSync(dir, { recursive: true }); }
});
test('expired values are rejected and transactions roll back', () => {
  const store = new Store(':memory:', randomBytes(32).toString('hex'));
  try {
    store.put('access', digest(secret()), {}, Date.now() - 1);
    assert.throws(() => store.transaction(() => { store.put('grant', 'x', {}, Date.now()+10000); throw new Error('rollback'); }));
    assert.equal(store.get('grant', 'x'), null);
    store.prune(); assert.equal(store.db.prepare('SELECT COUNT(*) AS count FROM records').get().count, 0);
  } finally { store.close(); }
});
test('storage key is mandatory', () => assert.throws(() => new Store(':memory:', ''), /MCP_STORAGE_KEY/));
