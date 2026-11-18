// Resolve `@cloudflare/privacypass-ts` from the client package first so that the crypto tests use
// its copy when available. Otherwise, use the pinned copy in `demo/web/node_modules`.
// CI installs that copy with `npm ci --ignore-scripts` in `demo/web`.
//
// If neither copy is installed, the test runner reports why the crypto tests are skipped.
// The protocol tests run without the peer.
import { createRequire, register, registerHooks } from 'node:module';
import * as hook from './peer-hook.mjs';

const PEER = '@cloudflare/privacypass-ts';
const demoPackage = new URL('../../../demo/web/package.json', import.meta.url);

function tryResolve(base) {
  try {
    return createRequire(base).resolve(PEER);
  } catch {
    return undefined;
  }
}

/**
 * Resolve the peer so that the test runner can skip the signing and verification checks if it
 * is missing.
 *
 * @returns {Promise<{ available: boolean, source?: string }>} The result includes the source
 *   if the peer is available.
 */
export async function installPeer() {
  if (tryResolve(import.meta.url)) return { available: true, source: 'package' };
  const entry = tryResolve(demoPackage.href);
  if (!entry) return { available: false };
  if (typeof registerHooks === 'function') {
    hook.setPeerEntry(entry);
    registerHooks({ resolve: hook.resolve });
  } else {
    register(new URL('./peer-hook.mjs', import.meta.url), {
      parentURL: import.meta.url,
      data: { entry },
    });
  }
  return { available: true, source: 'demo/web' };
}
