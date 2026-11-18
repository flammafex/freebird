// Freebird browser client: Privacy Pass access to an Origin via a Freebird Issuer.
// Browser ESM, no bundled dependencies. The peer dependency
// @cloudflare/privacypass-ts (exact 0.9.0) must be installed by the consumer.
export { fetchWithToken, obtainToken, authorizationHeader } from './token.mjs';
export { admissionFromPow } from './admission.mjs';
export { FreebirdError } from './errors.mjs';
