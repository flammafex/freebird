// Test-only helper: makes `@cloudflare/privacypass-ts` resolvable for the crypto
// tests without installing anything into this package.
//
// Resolution order:
//   1. this package's own install (a consumer or future local install), if any;
//   2. the exact pinned copy in demo/web/node_modules, which CI installs with
//      `npm ci --ignore-scripts` for the browser demo.
// Otherwise the crypto tests are skipped with an explicit reason. The
// protocol tests never need the peer, so they always run.
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

/** @returns {Promise<{ available: boolean, source?: string }>} */
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
