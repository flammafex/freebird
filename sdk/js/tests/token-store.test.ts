// SPDX-License-Identifier: Apache-2.0 OR MIT

import { afterEach, describe, expect, it } from 'vitest';
import {
  MemoryTokenStore,
  StorageTokenStore,
  deserializeGraphIssuanceRecoveryContext,
  serializeGraphIssuanceRecoveryContext,
} from '../src/index.js';
import type { FreebirdToken, GraphIssuanceRecoveryContext } from '../src/index.js';
import { GraphIssuanceError } from '../src/index.js';

function token(value: string, validUntil?: number): FreebirdToken {
  return { tokenValue: value, issuerId: 'issuer:test', valid_until: validUntil };
}

const future = Math.floor(Date.now() / 1000) + 3600;
const past = Math.floor(Date.now() / 1000) - 3600;

describe('MemoryTokenStore', () => {
  it('saves, loads, lists, and clears multiple tokens', async () => {
    const store = new MemoryTokenStore();
    await store.save(token('a'));
    await store.save(token('b'));
    await store.save(token('c'));

    expect(await store.list()).toHaveLength(3);
    expect((await store.load('b'))?.tokenValue).toBe('b');
    expect((await store.load('missing'))).toBeNull();

    // load() with no id returns the most recently saved token.
    expect((await store.load())?.tokenValue).toBe('c');

    await store.clear();
    expect(await store.list()).toHaveLength(0);
    expect(await store.load()).toBeNull();
  });

  it('replaces a token with the same id on save', async () => {
    const store = new MemoryTokenStore();
    await store.save(token('a', future));
    await store.save(token('a', future + 100));
    expect(await store.list()).toHaveLength(1);
    expect((await store.load('a'))?.valid_until).toBe(future + 100);
  });

  it('evicts expired tokens on load and list', async () => {
    const store = new MemoryTokenStore();
    await store.save(token('fresh', future));
    await store.save(token('stale', past));

    const listed = await store.list();
    expect(listed.map((t) => t.tokenValue)).toEqual(['fresh']);

    // The expired token is gone even when looked up by id.
    expect(await store.load('stale')).toBeNull();
    expect(await store.load('fresh')).not.toBeNull();
  });

  it('keeps tokens without a valid_until', async () => {
    const store = new MemoryTokenStore();
    await store.save(token('no-expiry'));
    expect(await store.list()).toHaveLength(1);
    expect((await store.load('no-expiry'))?.tokenValue).toBe('no-expiry');
  });
});

describe('StorageTokenStore (Node filesystem)', () => {
  const dir = '/tmp/freebird-sdk-token-store-test';
  const path = `${dir}/tokens.json`;

  afterEach(async () => {
    const fs = await import('node:fs');
    await fs.promises.rm(dir, { recursive: true, force: true });
  });

  it('persists tokens across store instances', async () => {
    const fs = await import('node:fs');
    await fs.promises.mkdir(dir, { recursive: true });

    const store = new StorageTokenStore({ key: path });
    await store.save(token('a', future));
    await store.save(token('b'));

    const reloaded = new StorageTokenStore({ key: path });
    expect(await reloaded.list()).toHaveLength(2);
    expect((await reloaded.load('a'))?.tokenValue).toBe('a');
  });

  it('evicts expired tokens on read', async () => {
    const fs = await import('node:fs');
    await fs.promises.mkdir(dir, { recursive: true });

    const store = new StorageTokenStore({ key: path });
    await store.save(token('fresh', future));
    await store.save(token('stale', past));

    const reloaded = new StorageTokenStore({ key: path });
    expect((await reloaded.list()).map((t) => t.tokenValue)).toEqual(['fresh']);
  });

  it('writes the token file with 0o600 permissions on Unix', async () => {
    const fs = await import('node:fs');
    await fs.promises.mkdir(dir, { recursive: true });

    const store = new StorageTokenStore({ key: path });
    await store.save(token('a'));

    const stat = await fs.promises.stat(path);
    // 0o600 & 0o777 === 0o600 on Unix.
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('clear removes the file', async () => {
    const fs = await import('node:fs');
    await fs.promises.mkdir(dir, { recursive: true });

    const store = new StorageTokenStore({ key: path });
    await store.save(token('a'));
    await store.clear();
    await expect(fs.promises.stat(path)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});

describe('GraphIssuanceRecoveryContext JSON round-trip', () => {
  const context: GraphIssuanceRecoveryContext = {
    request: {
      version: 2,
      public_operation_id: 'AAAAAAAAAAAAAAAAAAAAAA',
      issuance_policy_id: 'policy-1',
      graph_id: 'a'.repeat(64),
      keyset_id: 'b'.repeat(64),
      descriptor_id: 'c'.repeat(64),
      blinded_message: 'blinded',
      authorization: 'auth',
    },
    requestDigest: 'd'.repeat(43),
    publicOperationId: 'AAAAAAAAAAAAAAAAAAAAAA',
    issuancePolicyId: 'policy-1',
    graphId: 'a'.repeat(64),
    keysetId: 'b'.repeat(64),
    descriptorId: 'c'.repeat(64),
    statusCapability: 'e'.repeat(43),
    expectedTokenKeyId: 'f'.repeat(64),
    // JSON-safe opaque caller-owned blinding state.
    blindingState: { tag: 'opaque', nonce: 'abc' },
  };

  it('round-trips all fields including opaque blindingState', () => {
    const serialized = serializeGraphIssuanceRecoveryContext(context);
    const restored = deserializeGraphIssuanceRecoveryContext(serialized);
    expect(restored).toEqual(context);
    expect(restored.blindingState).toEqual({ tag: 'opaque', nonce: 'abc' });
  });

  it('produces a documented versioned envelope', () => {
    const parsed = JSON.parse(serializeGraphIssuanceRecoveryContext(context)) as {
      version: number;
      type: string;
      context: unknown;
    };
    expect(parsed.version).toBe(1);
    expect(parsed.type).toBe('graph_issuance_recovery_context');
    expect(parsed.context).toEqual(context);
  });

  it('rejects malformed serializations', () => {
    expect(() => deserializeGraphIssuanceRecoveryContext('not json'))
      .toThrow(GraphIssuanceError);
    expect(() => deserializeGraphIssuanceRecoveryContext(JSON.stringify({ version: 99 })))
      .toThrow(GraphIssuanceError);
    expect(() => deserializeGraphIssuanceRecoveryContext(JSON.stringify({
      version: 1,
      type: 'graph_issuance_recovery_context',
      context: { missing: 'fields' },
    }))).toThrow(GraphIssuanceError);
  });
});
