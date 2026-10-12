// SPDX-License-Identifier: Apache-2.0 OR MIT

import { describe, expect, it } from 'vitest';
import { FreebirdClient, ReplayedTokenError } from '../src/index.js';

const issuerUrl = process.env.FREEBIRD_SDK_ISSUER_URL?.trim();
const verifierUrl = process.env.FREEBIRD_SDK_VERIFIER_URL?.trim();
const liveTest = issuerUrl && verifierUrl ? it : it.skip;

describe('live Freebird services', () => {
  liveTest('issues and verifies V4 against configured services', async () => {
    const client = new FreebirdClient({ issuerUrl: issuerUrl!, verifierUrl: verifierUrl! });

    const single = await client.issueToken();
    const singleVerification = await client.verifyToken(single);
    expect(singleVerification.ok).toBe(true);

    const batch = await client.issueTokens([
      new Uint8Array(32),
      new Uint8Array(32),
    ]);
    expect(batch).toHaveLength(2);
    const batchVerification = await client.verifyBatch(batch);
    expect(batchVerification.successful).toBe(2);
    expect(batchVerification.failed).toBe(0);

    const singleReplay = await client.issueToken();
    await expect(client.verifyToken(singleReplay)).resolves.toMatchObject({ ok: true });
    await expect(client.verifyToken(singleReplay)).rejects.toBeInstanceOf(ReplayedTokenError);
  });
});
