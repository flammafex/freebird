// SPDX-License-Identifier: Apache-2.0 OR MIT

import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/crypto/voprf.js', () => ({
  blind: vi.fn(() => ({ blinded: new Uint8Array([4, 5]), state: { r: 1n, p: {} } })),
  finalize: vi.fn(() => new Uint8Array([6, 7])),
  buildScopeDigest: vi.fn(() => new Uint8Array([1, 2, 3])),
  buildPrivateTokenInput: vi.fn(() => new Uint8Array([8])),
  buildRedemptionToken: vi.fn(() => new Uint8Array([9, 8, 7])),
  parseRedemptionToken: vi.fn(),
  tokenKeyIdFromHex: vi.fn(() => new Uint8Array(32)),
  buildPublicBearerPass: vi.fn(() => new Uint8Array([1, 2, 3])),
  parsePublicBearerPass: vi.fn(),
  tokenKeyIdFromSpki: vi.fn(),
  tokenKeyIdToHex: vi.fn(),
  buildPublicBearerMessage: vi.fn(),
}));

vi.mock('../src/crypto/rsa.js', () => ({
  rsaBlind: vi.fn(async () => ({
    blinded: new Uint8Array([1, 2]),
    state: { inv: new Uint8Array(), prepared: new Uint8Array(), publicKey: new Uint8Array() },
  })),
  rsaUnblind: vi.fn(async () => new Uint8Array([3, 4, 5])),
  rsaVerify: vi.fn(),
}));

import { FreebirdClient, BatchIssuanceError } from '../src/index.js';
import type { FreebirdToken } from '../src/index.js';

const issuerMetadata = {
  issuer_id: 'issuer:test',
  voprf: { suite: 'P256-SHA256', kid: 'kid-1', pubkey: 'public-key' },
};
const verifierMetadata = {
  verifier_id: 'verifier:test',
  audience: 'audience:test',
  scope_digest_b64: 'AQID',
};
const keyDiscoveryMetadata = {
  issuer_id: 'issuer:test',
  current_epoch: 1,
  valid_epochs: [1],
  epoch_duration_sec: 86_400,
  voprf: { suite: 'P256-SHA256', kid: 'kid-1', pubkey: 'public-key' },
  public: [{
    token_key_id: 'a'.repeat(64),
    token_type: 'public_bearer_pass',
    rfc9474_variant: 'RSABSSA-SHA384-PSS-Deterministic',
    modulus_bits: 2048,
    pubkey_spki_b64: 'AQID',
    issuer_id: 'issuer:test',
    valid_from: 1,
    valid_until: 2,
    spend_policy: 'single_use',
  }],
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function client(config: ConstructorParameters<typeof FreebirdClient>[0] = {
  issuerUrl: 'https://issuer.example',
  verifierUrl: 'https://verifier.example',
}): FreebirdClient {
  return new FreebirdClient(config);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
  vi.restoreAllMocks();
});

describe('issueTokens (V4 batch)', () => {
  it('blinds each message, posts the exact batch body, and finalizes each success', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(json({
        results: [
          { status: 'success', token: 'eval-1', kid: 'kid-1', issuer_id: 'issuer:test' },
          { status: 'success', token: 'eval-2', kid: 'kid-1', issuer_id: 'issuer:test' },
        ],
        successful: 2,
        failed: 0,
        processing_time_ms: 1,
        throughput: 2,
      }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();

    const tokens = await sdk.issueTokens([new Uint8Array(32), new Uint8Array(32)]);

    expect(tokens).toHaveLength(2);
    expect(tokens[0]).toMatchObject({ issuerId: 'issuer:test', version: 4, kid: 'kid-1' });
    expect(tokens[1]).toMatchObject({ issuerId: 'issuer:test', version: 4, kid: 'kid-1' });
    expect(tokens[0].tokenValue).toBeTruthy();

    const batchCall = fetchMock.mock.calls.find(([url]) => url === 'https://issuer.example/v1/oprf/issue/batch');
    expect(batchCall).toBeDefined();
    const body = JSON.parse(batchCall![1].body as string);
    expect(body.blinded_elements).toHaveLength(2);
    expect(body.blinded_elements[0]).toBeTruthy();
  });

  it('surfaces per-token errors via BatchIssuanceError instead of dropping them', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(json({
        results: [
          { status: 'success', token: 'eval-1', kid: 'kid-1', issuer_id: 'issuer:test' },
          { status: 'error', message: 'invalid base64', code: 'validation_failed' },
          { status: 'error', message: 'voprf failed', code: 'voprf_evaluation_failed' },
        ],
        successful: 1,
        failed: 2,
        processing_time_ms: 1,
        throughput: 1,
      }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();

    const err = await sdk.issueTokens([new Uint8Array(32), new Uint8Array(32), new Uint8Array(32)])
      .catch((e) => e);

    expect(err).toBeInstanceOf(BatchIssuanceError);
    expect((err as BatchIssuanceError).failed).toBe(2);
    // The successful token is still surfaced, not silently dropped.
    expect((err as BatchIssuanceError).tokens).toHaveLength(1);
    // The per-token error codes are surfaced.
    const codes = (err as BatchIssuanceError).results
      .filter((r) => r.status === 'error')
      .map((r) => (r.status === 'error' ? r.code : ''));
    expect(codes).toEqual(['validation_failed', 'voprf_evaluation_failed']);
  });

  it('chunks inputs above MAX_BATCH_SIZE (10_000) into multiple requests', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata));
    // 10_000 + 5 -> two chunks: 10_000 and 5.
    const chunkResp = (count: number) => json({
      results: Array.from({ length: count }, () => ({
        status: 'success', token: 'eval', kid: 'kid-1', issuer_id: 'issuer:test',
      })),
      successful: count,
      failed: 0,
      processing_time_ms: 1,
      throughput: count,
    });
    fetchMock
      .mockResolvedValueOnce(chunkResp(10_000))
      .mockResolvedValueOnce(chunkResp(5));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();

    const msgs = Array.from({ length: 10_005 }, () => new Uint8Array(32));
    const tokens = await sdk.issueTokens(msgs);

    expect(tokens).toHaveLength(10_005);
    const batchCalls = fetchMock.mock.calls.filter(([url]) => url === 'https://issuer.example/v1/oprf/issue/batch');
    expect(batchCalls).toHaveLength(2);
    const firstBody = JSON.parse(batchCalls[0][1].body as string);
    const secondBody = JSON.parse(batchCalls[1][1].body as string);
    expect(firstBody.blinded_elements).toHaveLength(10_000);
    expect(secondBody.blinded_elements).toHaveLength(5);
  });

  it('throws a generic error on a non-2xx batch response', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(new Response('down', { status: 503 }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();

    await expect(sdk.issueTokens([new Uint8Array(32)])).rejects.toThrow('Batch token issuance failed');
  });
});

describe('issuePublicTokens (V5 batch)', () => {
  it('blinds each message, posts the exact batch body, and unblinds each signature', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(keyDiscoveryMetadata))
      .mockResolvedValueOnce(json({
        blind_signatures: ['AQID', 'BAUG'],
        token_key_id: 'a'.repeat(64),
        issuer_id: 'issuer:test',
        successful: 2,
        failed: 0,
        processing_time_ms: 1,
        throughput: 2,
      }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example' });

    const passes = await sdk.issuePublicTokens(
      [new Uint8Array(48), new Uint8Array(48)],
      { tokenKeyId: 'a'.repeat(64), issuerId: 'issuer:test', nonces: [new Uint8Array(32), new Uint8Array(32)] },
    );

    expect(passes).toHaveLength(2);
    const batchCall = fetchMock.mock.calls.find(([url]) => url === 'https://issuer.example/v1/public/issue/batch');
    expect(batchCall).toBeDefined();
    const body = JSON.parse(batchCall![1].body as string);
    expect(body.blinded_msgs).toHaveLength(2);
    expect(body.token_key_id).toBe('a'.repeat(64));
  });

  it('chunks V5 inputs above MAX_BATCH_SIZE into multiple requests', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(json(keyDiscoveryMetadata));
    const chunkResp = (count: number) => json({
      blind_signatures: Array.from({ length: count }, () => 'sig'),
      token_key_id: 'a'.repeat(64),
      issuer_id: 'issuer:test',
      successful: count,
      failed: 0,
      processing_time_ms: 1,
      throughput: count,
    });
    fetchMock
      .mockResolvedValueOnce(chunkResp(10_000))
      .mockResolvedValueOnce(chunkResp(5));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example' });

    const msgs = Array.from({ length: 10_005 }, () => new Uint8Array(48));
    const nonces = Array.from({ length: 10_005 }, () => new Uint8Array(32));
    const passes = await sdk.issuePublicTokens(msgs, {
      tokenKeyId: 'a'.repeat(64),
      issuerId: 'issuer:test',
      nonces,
    });

    expect(passes).toHaveLength(10_005);
    const batchCalls = fetchMock.mock.calls.filter(([url]) => url === 'https://issuer.example/v1/public/issue/batch');
    expect(batchCalls).toHaveLength(2);
    const firstBody = JSON.parse(batchCalls[0][1].body as string);
    const secondBody = JSON.parse(batchCalls[1][1].body as string);
    expect(firstBody.blinded_msgs).toHaveLength(10_000);
    expect(secondBody.blinded_msgs).toHaveLength(5);
  });

  it('rejects when nonces do not match the number of messages', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const sdk = client({ issuerUrl: 'https://issuer.example' });

    await expect(sdk.issuePublicTokens(
      [new Uint8Array(48)],
      { tokenKeyId: 'a'.repeat(64), issuerId: 'issuer:test', nonces: [] },
    )).rejects.toThrow('Nonces must be provided for each message');
  });
});
