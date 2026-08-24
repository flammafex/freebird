// SPDX-License-Identifier: Apache-2.0 OR MIT

import { afterEach, describe, expect, it } from 'vitest';
import {
  MemoryTokenStore,
  StorageTokenStore,
} from '../src/index.js';
import type { FreebirdToken } from '../src/index.js';

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
  const dir = '/tmp/flammafex-freebird-token-store-test';
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
