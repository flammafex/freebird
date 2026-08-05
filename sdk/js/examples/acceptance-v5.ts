// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Acceptance example — V5 issue → verify.
//
// This demonstrates the "zero bespoke protocol code" bar for the V5 flow: a
// consumer issues a V5 public bearer pass and verifies it using ONLY the SDK's
// high-level methods. No hand-rolled RFC 9474 blinding/unblinding or wire-format
// code — `issuePublicToken` and `verifyPublicBearerPassLocally` wrap it all.
//
// PREREQUISITES: a running issuer (127.0.0.1:8081) and verifier
// (127.0.0.1:8082) configured with a V5 public bearer key. This example is
// intentionally NOT a unit test: it requires live services.
//
// Run:  npx tsx examples/acceptance-v5.ts
//   or:  npm run build && node dist/examples/acceptance-v5.js

import { FreebirdClient, crypto } from '../src/index.js';

const ISSUER_URL = 'http://127.0.0.1:8081';
const VERIFIER_URL = 'http://127.0.0.1:8082';
const ISSUER_ID = 'issuer:local:v4';

// Trivial base64url encoding of the already-produced pass bytes so it can be
// presented to the verifier. This is plain encoding, not protocol code.
function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function main(): Promise<void> {
  const client = new FreebirdClient({ issuerUrl: ISSUER_URL, verifierUrl: VERIFIER_URL });

  // 1. Resolve the active V5 public bearer key from discovery.
  const metadata = await client.getKeyDiscoveryMetadata();
  const key = metadata.public[0];
  if (!key) throw new Error('issuer publishes no V5 public bearer key');
  const tokenKeyId = key.token_key_id;

  // 2. Build the message to be blindly signed. This is the only "protocol"
  //    helper the consumer touches, and it is part of the SDK's crypto facade.
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const msg = crypto.buildPublicBearerMessage(nonce, crypto.tokenKeyIdFromHex(tokenKeyId), ISSUER_ID);

  // 3. Issue a complete V5 public bearer pass in one high-level call.
  const pass = await client.issuePublicToken(msg, { nonce, tokenKeyId, issuerId: ISSUER_ID });
  console.log('issued V5 public bearer pass:', pass.length, 'bytes');

  // 4. Verify the pass locally against the published key. NOTE: local
  //    verification checks only cryptographic validity — it does NOT check
  //    spend status. Only the verifier's /v1/verify enforces single-use.
  const locallyValid = await client.verifyPublicBearerPassLocally(pass, key);
  console.log('verifyPublicBearerPassLocally:', locallyValid);

  // 5. For spend-status enforcement, present the pass to the verifier. The
  //    SDK converts the pass into a FreebirdToken for the consuming verify.
  const token = { tokenValue: bytesToBase64Url(pass), issuerId: ISSUER_ID, version: 5 as const, tokenKeyId };
  const resp = await client.verifyToken(token);
  console.log('verifyToken ok:', resp.ok, 'at', resp.verified_at);
}

main().catch((err) => {
  console.error('V5 acceptance flow failed:', err);
  process.exitCode = 1;
});
