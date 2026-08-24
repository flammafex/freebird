// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Direct V7 native-bearer acceptance example.
//
// Prerequisites: a live issuer exposing direct V7 discovery and issuance, and
// a verifier configured for V4/V7 remote checks. Set FREEBIRD_SDK_ISSUER_URL
// and FREEBIRD_SDK_VERIFIER_URL before running this example.
//
// Run: npm run build && node --experimental-strip-types examples/acceptance-v7.ts

import { FreebirdClient, ReplayedTokenError } from '../src/index.js';

const issuerUrl = process.env.FREEBIRD_SDK_ISSUER_URL ?? 'http://127.0.0.1:8081';
const verifierUrl = process.env.FREEBIRD_SDK_VERIFIER_URL ?? 'http://127.0.0.1:8082';

async function main(): Promise<void> {
  const client = new FreebirdClient({ issuerUrl, verifierUrl });
  const discovery = await client.getV7KeyDiscoveryMetadata();
  console.log('direct V7 key:', discovery.native_bearer_v7.token_key_id);

  const ownerCommitment = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const token = await client.issueNativeBearerV7({ owner_commitment: ownerCommitment });
  console.log('issued V7 token:', token.tokenValue.length, 'base64url characters');

  const locallyValid = await client.verifyNativeBearerV7Locally(token.tokenValue);
  console.log('local V7 verification:', locallyValid);

  const checked = await client.checkToken(token);
  console.log('remote non-consuming check:', checked.ok);

  const verified = await client.verifyToken(token);
  console.log('remote consuming verification:', verified.ok, verified.verified_at);

  try {
    await client.verifyToken(token);
    throw new Error('replay was unexpectedly accepted');
  } catch (error) {
    if (!(error instanceof ReplayedTokenError)) throw error;
    console.log('remote replay rejection:', error instanceof Error ? error.name : 'unknown error');
  }
}

main().catch((error) => {
  console.error('V7 acceptance flow failed:', error);
  process.exitCode = 1;
});
