// SPDX-License-Identifier: Apache-2.0 OR MIT

import type { FreebirdToken, TokenStore } from '../types.js';

/**
 * The stable id used to key tokens in a {@link TokenStore}: the redemption
 * token value, which is unique per issued token.
 */
export function tokenId(token: FreebirdToken): string {
  return token.tokenValue;
}

function isExpired(token: FreebirdToken, nowMs: number): boolean {
  if (token.valid_until === undefined) return false;
  // valid_until is a Unix timestamp in seconds (see PublicKeyInfo.valid_until).
  return token.valid_until * 1000 <= nowMs;
}

function isToken(value: unknown): value is FreebirdToken {
  return typeof value === 'object' && value !== null &&
    typeof (value as FreebirdToken).tokenValue === 'string' &&
    typeof (value as FreebirdToken).issuerId === 'string';
}

/**
 * An in-memory {@link TokenStore}. Useful for tests and short-lived sessions;
 * does not survive process restarts.
 */
export class MemoryTokenStore implements TokenStore {
  private readonly tokens = new Map<string, FreebirdToken>();

  async save(token: FreebirdToken): Promise<void> {
    this.tokens.set(tokenId(token), { ...token });
  }

  async load(id?: string): Promise<FreebirdToken | null> {
    this.evict();
    if (id !== undefined) {
      const token = this.tokens.get(id);
      return token ? { ...token } : null;
    }
    const entries = [...this.tokens.values()];
    return entries.length ? { ...entries[entries.length - 1] } : null;
  }

  async list(): Promise<FreebirdToken[]> {
    this.evict();
    return [...this.tokens.values()].map((token) => ({ ...token }));
  }

  async clear(): Promise<void> {
    this.tokens.clear();
  }

  private evict(): void {
    const now = Date.now();
    for (const [id, token] of this.tokens) {
      if (isExpired(token, now)) this.tokens.delete(id);
    }
  }
}

/** Options for {@link StorageTokenStore}. */
export interface StorageTokenStoreOptions {
  /**
   * The storage key. In a browser this is the `localStorage` key; in Node it
   * is the filesystem path of the token file.
   */
  key: string;
}

/**
 * A durable {@link TokenStore} backed by `localStorage` in the browser and by
 * the filesystem in Node.
 *
 * Node writes follow the repo's security hygiene: the file is written to a
 * temporary sibling, `fsync`ed, and atomically renamed into place, with mode
 * `0o600` on Unix so token material is not world-readable.
 */
export class StorageTokenStore implements TokenStore {
  private readonly key: string;
  private readonly useBrowser: boolean;

  constructor(options: StorageTokenStoreOptions) {
    this.key = options.key;
    this.useBrowser = isBrowserStorageAvailable();
  }

  async save(token: FreebirdToken): Promise<void> {
    const tokens = await this.readAll();
    const index = tokens.findIndex((candidate) => tokenId(candidate) === tokenId(token));
    if (index >= 0) tokens[index] = token;
    else tokens.push(token);
    await this.writeAll(tokens);
  }

  async load(id?: string): Promise<FreebirdToken | null> {
    const tokens = await this.readAll();
    if (id !== undefined) {
      const token = tokens.find((candidate) => tokenId(candidate) === id);
      return token ?? null;
    }
    return tokens.length ? tokens[tokens.length - 1] : null;
  }

  async list(): Promise<FreebirdToken[]> {
    return this.readAll();
  }

  async clear(): Promise<void> {
    if (this.useBrowser) {
      window.localStorage.removeItem(this.key);
      return;
    }
    const fs = await getFs();
    await fs.promises.rm(this.key, { force: true });
  }

  private async readAll(): Promise<FreebirdToken[]> {
    let raw: string | null;
    if (this.useBrowser) {
      raw = window.localStorage.getItem(this.key);
    } else {
      const fs = await getFs();
      try {
        raw = await fs.promises.readFile(this.key, 'utf8');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
        throw error;
      }
    }
    if (!raw) return [];
    try {
      const parsed: unknown = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      const now = Date.now();
      return parsed.filter((value): value is FreebirdToken =>
        isToken(value) && !isExpired(value, now));
    } catch {
      // Corrupt or unreadable storage is treated as empty rather than fatal.
      return [];
    }
  }

  private async writeAll(tokens: FreebirdToken[]): Promise<void> {
    const data = JSON.stringify(tokens);
    if (this.useBrowser) {
      window.localStorage.setItem(this.key, data);
      return;
    }
    await atomicWrite(this.key, data);
  }
}

function isBrowserStorageAvailable(): boolean {
  try {
    return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined';
  } catch {
    return false;
  }
}

let fsPromise: Promise<typeof import('node:fs')> | null = null;
function getFs(): Promise<typeof import('node:fs')> {
  if (!fsPromise) fsPromise = import('node:fs');
  return fsPromise;
}

/**
 * Atomic, restrictive-permission file write: write to a temp sibling, fsync,
 * then rename into place. On Unix the temp file is created with mode `0o600`.
 */
async function atomicWrite(path: string, data: string): Promise<void> {
  const fs = await getFs();
  const tmp = `${path}.tmp`;
  const isUnix = typeof process !== 'undefined' && process.platform !== 'win32';
  const mode = isUnix ? 0o600 : undefined;
  const handle = await fs.promises.open(tmp, 'w', mode);
  try {
    await handle.writeFile(data, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.promises.rename(tmp, path);
}
