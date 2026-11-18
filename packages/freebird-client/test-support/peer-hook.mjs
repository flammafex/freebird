// Test-only resolve hook. It maps the bare specifier `@cloudflare/privacypass-ts`
// to one explicit file path. Registered only by test/support/peer.mjs, and only
// when this package has no install of its own.
import { pathToFileURL } from 'node:url';

let peerEntry;

export function setPeerEntry(entry) {
  peerEntry = entry;
}

// Synchronous, so it also works with module.registerHooks(); for the older
// module.register() fallback, a plain return value is accepted too.
export function resolve(specifier, context, nextResolve) {
  if (specifier === '@cloudflare/privacypass-ts' && peerEntry) {
    return { url: pathToFileURL(peerEntry).href, shortCircuit: true };
  }
  return nextResolve(specifier, context);
}

// Used only by the module.register() fallback.
export function initialize(data) {
  peerEntry = data?.entry;
}
