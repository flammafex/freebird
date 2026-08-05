// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Acceptance test — V4 issue → verify with zero bespoke protocol code.
//
// This is the CI-runnable counterpart to examples/acceptance-v4.ts. It drives
// the SDK's high-level methods (`issueToken` → `verifyToken` → `checkToken` →
// `verifyBatch`) against a mocked issuer/verifier, proving a consumer can
// complete the V4 flow using ONLY the SDK surface — no hand-rolled VOPRF,
// blinding, or wire-format code. The live-service examples cover V5 and V2.

import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/crypto/voprf.js', () => ({
  blind: vi.fn(() => ({ blinded: new Uint8Array([4, 5]), state: { r: 1n, p: {} } })),
  finalize: vi.fn(() => new Uint8Array([6, 7])),
  buildScopeDigest: vi.fn(() => new Uint8Array([1, 2, 3])),
  buildPrivateTokenInput: vi.fn(() => new Uint8Array([8])),
  buildRedemptionToken: vi.fn(() => new Uint8Array([9, 8, 7])),
  parseRedemptionToken: vi.fn(),
  tokenKeyIdFromSpki: vi.fn(),
  tokenKeyIdToHex: vi.fn(),
  tokenKeyIdFromHex: vi.fn(),
  buildPublicBearerMessage: vi.fn(),
  buildPublicBearerPass: vi.fn(),
  parsePublicBearerPass: vi.fn(),
}));

import { FreebirdClient, crypto } from '../src/index.js';
import type { FreebirdToken } from '../src/index.js';

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const issuerMetadata = {
  issuer_id: 'issuer:test',
  voprf: { suite: 'P256-SHA256', kid: 'kid-1', pubkey: 'public-key' },
};
const verifierMetadata = {
  verifier_id: 'verifier:test',
  audience: 'audience:test',
  scope_digest_b64: bytesToBase64Url(crypto.buildScopeDigest('verifier:test', 'audience:test')),
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function client(): FreebirdClient {
  return new FreebirdClient({
    issuerUrl: 'https://issuer.example',
    verifierUrl: 'https://verifier.example',
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
  vi.restoreAllMocks();
});

describe('V4 acceptance: issue → verify with zero bespoke protocol code', () => {
  it('issues a token and verifies it using only high-level SDK methods', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))                       // /.well-known/issuer
      .mockResolvedValueOnce(json(verifierMetadata))                     // /.well-known/verifier
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-1', issuer_id: 'issuer:test' })) // /v1/oprf/issue
      .mockResolvedValueOnce(json({ ok: true, verified_at: 123 }));      // /v1/verify
    vi.stubGlobal('fetch', fetchMock);

    const sdk = client();

    // Issue — one high-level call.
    const token: FreebirdToken = await sdk.issueToken();
    expect(token.tokenValue).toBeTruthy();
    expect(token.issuerId).toBe('issuer:test');

    // Verify — one high-level call.
    const resp = await sdk.verifyToken(token);
    expect(resp.ok).toBe(true);
    expect(resp.verified_at).toBe(123);

    // The consumer wrote no protocol code: the SDK made exactly the expected
    // discovery + issuance + verification requests.
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      'https://issuer.example/.well-known/issuer',
      'https://verifier.example/.well-known/verifier',
      'https://issuer.example/v1/oprf/issue',
      'https://verifier.example/v1/verify',
    ]);
  });

  it('supports the boolean convenience and non-consuming check', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-1', issuer_id: 'issuer:test' }))
      .mockResolvedValueOnce(json({ ok: true, verified_at: 1 }))   // verifyTokenValid
      .mockResolvedValueOnce(json({ ok: true, verified_at: 2 }));  // checkToken
    vi.stubGlobal('fetch', fetchMock);

    const sdk = client();
    const token = await sdk.issueToken();

    await expect(sdk.verifyTokenValid(token)).resolves.toBe(true);
    await expect(sdk.checkToken(token)).resolves.toMatchObject({ ok: true });
  });

  it('supports batch issuance and batch verification', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(json({
        results: [
          { status: 'success', token: 't1', kid: 'kid-1', issuer_id: 'issuer:test' },
          { status: 'success', token: 't2', kid: 'kid-1', issuer_id: 'issuer:test' },
        ],
        successful: 2,
        failed: 0,
        processing_time_ms: 1,
        throughput: 2,
      }))                                                             // /v1/oprf/issue/batch
      .mockResolvedValueOnce(json({
        results: [
          { status: 'success', verified_at: 1 },
          { status: 'success', verified_at: 2 },
        ],
        successful: 2,
        failed: 0,
        processing_time_ms: 1,
        throughput: 2,
      }));                                                            // /v1/verify/batch
    vi.stubGlobal('fetch', fetchMock);

    const sdk = client();
    const tokens = await sdk.issueTokens([new Uint8Array(32), new Uint8Array(32)]);
    expect(tokens).toHaveLength(2);

    const batchResp = await sdk.verifyBatch(tokens);
    expect(batchResp.successful).toBe(2);
    expect(batchResp.failed).toBe(0);
  });
});
