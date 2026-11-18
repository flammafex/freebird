// If the client has no local install, `./peer.mjs` registers this hook so that
// `@cloudflare/privacypass-ts` resolves to the demo's copy.
import { pathToFileURL } from 'node:url';

let peerEntry;

export function setPeerEntry(entry) {
  peerEntry = entry;
}

// Return the result synchronously so that the hook works with both `module.registerHooks()`
// and `module.register()`.
export function resolve(specifier, context, nextResolve) {
  if (specifier === '@cloudflare/privacypass-ts' && peerEntry) {
    return { url: pathToFileURL(peerEntry).href, shortCircuit: true };
  }
  return nextResolve(specifier, context);
}

// Read the entry provided by `module.register()` so that its loader resolves the same copy of the peer.
export function initialize(data) {
  peerEntry = data?.entry;
}
