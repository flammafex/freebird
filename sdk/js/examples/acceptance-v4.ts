// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Acceptance example — V4 issue → verify.
//
// This demonstrates the "zero bespoke protocol code" bar for the V4 flow: a
// consumer issues an anonymous V4 token and verifies it using ONLY the SDK's
// high-level methods. No hand-rolled VOPRF, blinding, or wire-format code.
//
// PREREQUISITES: a running issuer (127.0.0.1:8081) and verifier
// (127.0.0.1:8082) — see the local V4 round-trip in AGENTS.md. This example is
// intentionally NOT a unit test: it requires live services.
//
// Run:  npx tsx examples/acceptance-v4.ts
//   or:  npm run build && node dist/examples/acceptance-v4.js

import { FreebirdClient } from '../src/index.js';

const ISSUER_URL = 'http://127.0.0.1:8081';
const VERIFIER_URL = 'http://127.0.0.1:8082';

async function main(): Promise<void> {
  // 1. Configure the client. The SDK handles discovery, blinding, issuance,
  //    and verification internally.
  const client = new FreebirdClient({ issuerUrl: ISSUER_URL, verifierUrl: VERIFIER_URL });

  // 2. Issue a V4 token. `issueToken` performs the full blind-issue-finalize
  //    round trip and returns a ready-to-use FreebirdToken.
  const token = await client.issueToken();
  console.log('issued V4 token:', token.tokenValue.slice(0, 24) + '…');

  // 3. Verify it against the verifier. `verifyToken` consumes the token and
  //    returns the full VerifyResp; `verifyTokenValid` is a boolean convenience.
  const resp = await client.verifyToken(token);
  console.log('verifyToken ok:', resp.ok, 'at', resp.verified_at);

  const stillValid = await client.verifyTokenValid(token);
  console.log('verifyTokenValid:', stillValid);

  // 4. A non-consuming validity check is available via `checkToken`.
  const checked = await client.checkToken(token);
  console.log('checkToken ok:', checked.ok);

  // 5. Batch issuance + batch verification are also high-level.
  const batch = await client.issueTokens([new Uint8Array(32), new Uint8Array(32)]);
  const batchResp = await client.verifyBatch(batch);
  console.log('batch verify: successful', batchResp.successful, 'failed', batchResp.failed);
}

main().catch((err) => {
  console.error('V4 acceptance flow failed:', err);
  process.exitCode = 1;
});
