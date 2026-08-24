// SPDX-License-Identifier: Apache-2.0 OR MIT

import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/crypto/voprf.js', () => ({
  blind: vi.fn(() => ({ blinded: new Uint8Array([4, 5]), state: { r: 1n, p: {} } })),
  finalize: vi.fn(() => new Uint8Array([6, 7])),
  buildScopeDigest: vi.fn(() => new Uint8Array([1, 2, 3])),
  buildPrivateTokenInput: vi.fn(() => new Uint8Array([8])),
  buildRedemptionToken: vi.fn((nonce: Uint8Array) => nonce.slice()),
  parseRedemptionToken: vi.fn(),
  tokenKeyIdFromHex: vi.fn(() => new Uint8Array(32)),
  tokenKeyIdFromSpki: vi.fn(),
  tokenKeyIdToHex: vi.fn(),
}));

vi.mock('../src/crypto/rsa.js', () => ({
  rsaBlind: vi.fn(async () => ({
    blinded: new Uint8Array([1, 2]),
    state: { inv: new Uint8Array(), prepared: new Uint8Array(), publicKey: new Uint8Array() },
  })),
  rsaUnblind: vi.fn(async () => new Uint8Array([3, 4, 5])),
  rsaVerify: vi.fn(),
}));

import {
  FreebirdClient,
  BatchIssuanceError,
  BatchIssuanceInterruptedError,
  buildBatchBinding,
  DiscoveryError,
  FreebirdError,
} from '../src/index.js';
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

const BATCH_BODY_LIMIT = 60 * 1024;

function jsonBytes(body: unknown): number {
  return new TextEncoder().encode(JSON.stringify(body)).byteLength;
}

function requestBodies(fetchMock: ReturnType<typeof vi.fn>, path: string): { raw: string; body: any }[] {
  return fetchMock.mock.calls
    .filter(([url]) => url === `https://issuer.example${path}`)
    .map(([, init]) => {
      const raw = String((init as RequestInit).body);
      return { raw, body: JSON.parse(raw) };
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
  it('rejects a fixed proof before discovery when the batch needs multiple chunks', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();

    await expect(sdk.issueTokens(
      Array.from({ length: 10_001 }, () => new Uint8Array(32)),
      { sybilProof: { type: 'none' } },
    )).rejects.toBeInstanceOf(FreebirdError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects sybilProof and proofFactory together at runtime', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();
    const invalidOptions = {
      sybilProof: { type: 'none' as const },
      proofFactory: vi.fn(() => ({ type: 'none' as const })),
    };

    // @ts-expect-error proof and factory are mutually exclusive
    await expect(sdk.issueTokens([], invalidOptions)).rejects.toMatchObject({ code: 'issuance' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

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

  it('does not retry a V4 stale-key response with a fixed proof', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(json({
        results: [{ status: 'success', token: 'eval', kid: 'kid-2', issuer_id: 'issuer:test' }],
        successful: 1, failed: 0, processing_time_ms: 1, throughput: 1,
      }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(client().issueTokens(
      [new Uint8Array(32)],
      { sybilProof: { type: 'none' } },
    )).rejects.toMatchObject({ code: 'discovery' });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls.filter(([url]) => url.endsWith('/v1/oprf/issue/batch'))).toHaveLength(1);
  });

  it('retains completed chunks and calls a proof factory per chunk binding', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata));
    fetchMock.mockResolvedValueOnce(json({
      results: Array.from({ length: 10_000 }, () => ({
        status: 'success', token: 'eval', kid: 'kid-1', issuer_id: 'issuer:test',
      })),
      successful: 10_000, failed: 0, processing_time_ms: 1, throughput: 10_000,
    }));
    fetchMock.mockResolvedValueOnce(new Response('down', { status: 503 }));
    vi.stubGlobal('fetch', fetchMock);
    const bindings: string[] = [];
    const proofFactory = vi.fn(({ binding }: { binding: string }) => {
      bindings.push(binding);
      return { type: 'none' as const };
    });
    const sdk = client();

    const error = await sdk.issueTokens(
      Array.from({ length: 10_005 }, () => new Uint8Array(32)),
      { proofFactory },
    ).catch((cause) => cause);

    expect(error).toBeInstanceOf(BatchIssuanceInterruptedError);
    expect((error as BatchIssuanceInterruptedError<FreebirdToken>).completed).toHaveLength(10_000);
    expect(proofFactory).toHaveBeenCalledTimes(2);
    const posts = fetchMock.mock.calls.filter(([url]) => url.endsWith('/v1/oprf/issue/batch'));
    expect(posts).toHaveLength(2);
    const firstBody = JSON.parse(posts[0][1].body as string);
    const secondBody = JSON.parse(posts[1][1].body as string);
    expect(bindings).toEqual([
      buildBatchBinding('issue-batch', 'issuer:test', firstBody.blinded_elements),
      buildBatchBinding('issue-batch', 'issuer:test', secondBody.blinded_elements),
    ]);
  });
});

describe('exact UTF-8 batch body budgets', () => {
  it('greedily budgets V4 bodies including context and a multibyte Sybil proof', async () => {
    let nonceValue = 0;
    vi.stubGlobal('crypto', {
      getRandomValues: (bytes: Uint8Array) => {
        bytes.fill(nonceValue++);
        return bytes;
      },
    });
    const proof = { type: 'registered_user' as const, user_id: '参加者'.repeat(2_000) };
    const ctxB64 = 'é'.repeat(1_000);
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === 'https://issuer.example/.well-known/issuer') return json(issuerMetadata);
      if (url === 'https://verifier.example/.well-known/verifier') return json(verifierMetadata);
      if (url === 'https://issuer.example/v1/oprf/issue/batch') {
        const body = JSON.parse(String(init?.body)) as { blinded_elements: string[] };
        return json({
          results: body.blinded_elements.map((_, index) => ({
            status: 'success', token: `eval-${index}`, kid: 'kid-1', issuer_id: 'issuer:test',
          })),
          successful: body.blinded_elements.length,
          failed: 0,
          processing_time_ms: 1,
          throughput: body.blinded_elements.length,
        });
      }
      throw new Error(`unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const tokens = await client().issueTokens(
      Array.from({ length: 9_000 }, () => new Uint8Array(32)),
      { proofFactory: () => proof, ctxB64 },
    );
    const bodies = requestBodies(fetchMock, '/v1/oprf/issue/batch');

    expect(bodies.length).toBeGreaterThan(1);
    expect(tokens).toHaveLength(9_000);
    expect(bodies.reduce((sum, request) => sum + request.body.blinded_elements.length, 0)).toBe(9_000);
    expect(bodies.every(({ raw }) => new TextEncoder().encode(raw).byteLength <= BATCH_BODY_LIMIT)).toBe(true);
    for (let index = 0; index < bodies.length; index++) {
      const request = bodies[index];
      expect(request.body.ctx_b64).toBe(ctxB64);
      expect(request.body.sybil_proof).toEqual(proof);
      if (index < bodies.length - 1) {
        const larger = {
          ...request.body,
          blinded_elements: [...request.body.blinded_elements, 'BAU'],
        };
        expect(jsonBytes(larger)).toBeGreaterThan(BATCH_BODY_LIMIT);
      }
    }
    // The finalized V4 output is the nonce in this test double, proving that
    // greedy chunking does not reorder results across requests.
    expect(tokens.map((token) => token.tokenValue).slice(0, 4)).toEqual([
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE',
      'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI',
      'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM',
    ]);
  });

  it('rejects an oversized single fixed request without posting it', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata));
    vi.stubGlobal('fetch', fetchMock);
    const oversizedProof = { type: 'registered_user' as const, user_id: 'x'.repeat(BATCH_BODY_LIMIT) };

    await expect(client().issueTokens([new Uint8Array(32)], { sybilProof: oversizedProof }))
      .rejects.toThrow('single batch item exceeds');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fetchMock.mock.calls.filter(([url]) => url === 'https://issuer.example/v1/oprf/issue/batch')).toHaveLength(0);

  });
});
