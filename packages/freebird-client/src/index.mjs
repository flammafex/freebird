// The browser client uses Privacy Pass tokens from a Freebird Issuer to access a protected Origin.
// Install `@cloudflare/privacypass-ts` at version `0.9.0` so that the browser bundle can resolve
// the peer dependency.
export { fetchWithToken, obtainToken, authorizationHeader } from './token.mjs';
export { admissionFromPow } from './admission.mjs';
export { FreebirdError } from './errors.mjs';
