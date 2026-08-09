// SPDX-License-Identifier: Apache-2.0 OR MIT

import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/crypto/voprf.js', () => ({
  blind: vi.fn(() => ({ blinded: new Uint8Array(33), state: { r: 1n, p: {} } })),
  finalize: vi.fn(() => new Uint8Array([6, 7])),
  buildScopeDigest: vi.fn(() => new Uint8Array([1, 2, 3])),
  buildPrivateTokenInput: vi.fn(() => new Uint8Array([8])),
  buildRedemptionToken: vi.fn((nonce: Uint8Array) => nonce.slice()),
  parseRedemptionToken: vi.fn(),
  tokenKeyIdFromHex: vi.fn(() => new Uint8Array(32)),
  buildPublicBearerPass: vi.fn((nonce: Uint8Array) => nonce.slice()),
  parsePublicBearerPass: vi.fn(),
  tokenKeyIdFromSpki: vi.fn(),
  tokenKeyIdToHex: vi.fn(),
  buildPublicBearerMessage: vi.fn(),
}));

vi.mock('../src/crypto/rsa.js', () => ({
  rsaBlind: vi.fn(async () => ({
    blinded: new Uint8Array(
      (globalThis as unknown as { __freebirdRsaModulusBytes?: number }).__freebirdRsaModulusBytes ?? 256,
    ),
    state: { inv: new Uint8Array(), prepared: new Uint8Array(), publicKey: new Uint8Array() },
  })),
  rsaUnblind: vi.fn(async () => new Uint8Array([3, 4, 5])),
  rsaVerify: vi.fn(async () => true),
}));

import { buildBatchBinding, FreebirdClient } from '../src/index.js';

const LIMIT = 60 * 1024;
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

function bodyOf(init: RequestInit | undefined): { raw: string; body: Record<string, unknown> } {
  const raw = String(init?.body);
  return { raw, body: JSON.parse(raw) as Record<string, unknown> };
}

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete (globalThis as unknown as { __freebirdRsaModulusBytes?: number }).__freebirdRsaModulusBytes;
  vi.clearAllMocks();
});

describe('protocol-sized 60 KiB batch budgets', () => {
  it('uses real encoded V4 element sizes, preserves order, and binds discarded candidates', async () => {
    let nonceValue = 0;
    const generatedNonces: Uint8Array[] = [];
    vi.stubGlobal('crypto', {
      getRandomValues: (bytes: Uint8Array) => {
        bytes.fill(nonceValue++);
        generatedNonces.push(bytes.slice());
        return bytes;
      },
    });
    const proof = { type: 'registered_user' as const, user_id: '用户'.repeat(300) };
    const bindings: string[] = [];
    const bodies: { raw: string; body: Record<string, unknown> }[] = [];
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === 'https://issuer.example/.well-known/issuer') return json(issuerMetadata);
      if (url === 'https://verifier.example/.well-known/verifier') return json(verifierMetadata);
      if (url === 'https://issuer.example/v1/oprf/issue/batch') {
        const request = bodyOf(init);
        bodies.push(request);
        const elements = request.body.blinded_elements as string[];
        return json({
          results: elements.map(() => ({
            status: 'success', token: 'evaluation', kid: 'kid-1', issuer_id: 'issuer:test',
          })),
          successful: elements.length, failed: 0, processing_time_ms: 1, throughput: elements.length,
        });
      }
      throw new Error(`unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const tokens = await new FreebirdClient({
      issuerUrl: 'https://issuer.example',
      verifierUrl: 'https://verifier.example',
    }).issueTokens(
      Array.from({ length: 2_000 }, () => new Uint8Array(32)),
      {
        ctxB64: 'é'.repeat(500),
        proofFactory: ({ binding }) => {
          bindings.push(binding);
          return proof;
        },
      },
    );

    expect(tokens).toHaveLength(2_000);
    expect(bodies.length).toBeGreaterThan(1);
    expect(bodies.reduce((sum, request) => sum + (request.body.blinded_elements as string[]).length, 0)).toBe(2_000);
    expect(bodies.every(({ raw }) => new TextEncoder().encode(raw).byteLength <= LIMIT)).toBe(true);
    expect((bodies[0].body.blinded_elements as string[])[0]).toHaveLength(44);
    expect(bodies.every(({ body }) => body.ctx_b64 === 'é'.repeat(500))).toBe(true);
    expect(bodies.every(({ body }) => body.sybil_proof !== undefined)).toBe(true);

    const emittedBindings = new Set(
      bodies.map(({ body }) => buildBatchBinding(
        'issue-batch',
        'issuer:test',
        body.blinded_elements as string[],
      )),
    );
    expect(bindings.every((binding) => binding.startsWith('freebird:issue-batch:v1:issuer:test:'))).toBe(true);
    expect(bindings.some((binding) => !emittedBindings.has(binding))).toBe(true);
    expect(tokens.map((token) => token.tokenValue))
      .toEqual(generatedNonces.slice(0, 2_000).map(base64Url));
  });

  it('uses real encoded V5 RSA sizes and preserves nonce alignment across byte chunks', async () => {
    (globalThis as unknown as { __freebirdRsaModulusBytes?: number }).__freebirdRsaModulusBytes = 256;
    const nonces = Array.from({ length: 2_000 }, (_, index) => {
      const nonce = new Uint8Array(32);
      nonce.fill(index);
      return nonce;
    });
    const proof = { type: 'registered_user' as const, user_id: '利用者'.repeat(200) };
    const bodies: { raw: string; body: Record<string, unknown> }[] = [];
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === 'https://issuer.example/.well-known/keys') return json(keyDiscoveryMetadata);
      if (url === 'https://issuer.example/v1/public/issue/batch') {
        const request = bodyOf(init);
        bodies.push(request);
        const messages = request.body.blinded_msgs as string[];
        return json({
          blind_signatures: messages.map(() => 'AQID'),
          token_key_id: 'a'.repeat(64), issuer_id: 'issuer:test',
          successful: messages.length, failed: 0, processing_time_ms: 1, throughput: messages.length,
        });
      }
      throw new Error(`unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const passes = await new FreebirdClient({ issuerUrl: 'https://issuer.example' }).issuePublicTokens(
      Array.from({ length: 2_000 }, () => new Uint8Array(48)),
      {
        tokenKeyId: 'a'.repeat(64), issuerId: 'issuer:test', nonces,
        proofFactory: () => proof,
      },
    );

    expect(passes).toHaveLength(2_000);
    expect(bodies.length).toBeGreaterThan(1);
    expect(bodies.reduce((sum, request) => sum + (request.body.blinded_msgs as string[]).length, 0)).toBe(2_000);
    expect(bodies.every(({ raw }) => new TextEncoder().encode(raw).byteLength <= LIMIT)).toBe(true);
    expect((bodies[0].body.blinded_msgs as string[])[0]).toHaveLength(342);
    expect(bodies.every(({ body }) => body.token_key_id === 'a'.repeat(64))).toBe(true);
    expect(passes.slice(0, 4)).toEqual(nonces.slice(0, 4));
  });

  it.each([
    [3072, 384, 512],
    [4096, 512, 683],
  ])('accepts announced %d-bit V5 keys with %d-byte blinded values', async (bits, bytes, encodedLength) => {
    (globalThis as unknown as { __freebirdRsaModulusBytes?: number }).__freebirdRsaModulusBytes = bytes;
    const metadata = {
      ...keyDiscoveryMetadata,
      public: [{ ...keyDiscoveryMetadata.public[0], modulus_bits: bits }],
    };
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === 'https://issuer.example/.well-known/keys') return json(metadata);
      if (url === 'https://issuer.example/v1/public/issue/batch') {
        const { body } = bodyOf(init);
        const messages = body.blinded_msgs as string[];
        return json({
          blind_signatures: messages.map(() => 'AQID'), token_key_id: 'a'.repeat(64), issuer_id: 'issuer:test',
          successful: messages.length, failed: 0, processing_time_ms: 1, throughput: messages.length,
        });
      }
      throw new Error(`unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const passes = await new FreebirdClient({ issuerUrl: 'https://issuer.example' }).issuePublicTokens(
      [new Uint8Array(48)],
      {
        tokenKeyId: 'a'.repeat(64), issuerId: 'issuer:test', nonces: [new Uint8Array(32)],
      },
    );
    expect(passes).toHaveLength(1);
    const post = fetchMock.mock.calls.find(([url]) => url === 'https://issuer.example/v1/public/issue/batch');
    expect(post).toBeDefined();
    expect((bodyOf(post![1] as RequestInit).body.blinded_msgs as string[])[0]).toHaveLength(encodedLength);
  });

  it('rebinds only the stale byte-sized V5 chunk and retries with fresh factory binding', async () => {
    const keyA = 'a'.repeat(64);
    const keyB = 'b'.repeat(64);
    const keyMetadata = (tokenKeyId: string) => ({
      ...keyDiscoveryMetadata,
      public: [{ ...keyDiscoveryMetadata.public[0], token_key_id: tokenKeyId }],
    });
    const nonces = Array.from({ length: 400 }, (_, index) => {
      const nonce = new Uint8Array(32);
      nonce.fill(index);
      return nonce;
    });
    const bodies: { raw: string; body: Record<string, unknown> }[] = [];
    const bindings: string[] = [];
    let keyFetches = 0;
    let batchPosts = 0;
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === 'https://issuer.example/.well-known/issuer') return json(issuerMetadata);
      if (url === 'https://issuer.example/.well-known/keys') {
        keyFetches++;
        return json(keyMetadata(keyFetches === 1 ? keyA : keyB));
      }
      if (url === 'https://issuer.example/v1/public/issue/batch') {
        const request = bodyOf(init);
        bodies.push(request);
        batchPosts++;
        const messages = request.body.blinded_msgs as string[];
        const responseKey = batchPosts === 1 ? keyB : keyB;
        return json({
          blind_signatures: messages.map(() => 'AQID'),
          token_key_id: responseKey,
          issuer_id: 'issuer:test',
          successful: messages.length, failed: 0, processing_time_ms: 1, throughput: messages.length,
        });
      }
      throw new Error(`unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const passes = await new FreebirdClient({ issuerUrl: 'https://issuer.example' })
      .issuePublicTokensForCurrentKey(nonces, {
        proofFactory: ({ binding }) => {
          bindings.push(binding);
          return { type: 'none' };
        },
      });

    expect(passes).toHaveLength(400);
    expect(bodies.length).toBeGreaterThan(2);
    expect((bodies[0].body.blinded_msgs as string[]).length)
      .toBe((bodies[1].body.blinded_msgs as string[]).length);
    expect(bodies.every(({ raw }) => new TextEncoder().encode(raw).byteLength <= LIMIT)).toBe(true);
    expect(bindings).toEqual(bodies.map(({ body }) => buildBatchBinding(
      'public-issue-batch',
      'issuer:test',
      body.blinded_msgs as string[],
    )));
    expect(passes.slice(0, 4)).toEqual(nonces.slice(0, 4));
  });

  it('re-chunks only the stale V4 tail when the retry proof grows', async () => {
    let nonceValue = 0;
    const generatedNonces: Uint8Array[] = [];
    vi.stubGlobal('crypto', {
      getRandomValues: (bytes: Uint8Array) => {
        bytes.fill(nonceValue++);
        generatedNonces.push(bytes.slice());
        return bytes;
      },
    });
    const largeProof = { type: 'registered_user' as const, user_id: 'retry-user'.repeat(2_000) };
    const bindings: string[] = [];
    const proofSizes: number[] = [];
    const bodies: { raw: string; body: Record<string, unknown> }[] = [];
    let keyFetches = 0;
    let batchPosts = 0;
    let generatedBeforeRetry = 0;
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === 'https://issuer.example/.well-known/issuer') return json(issuerMetadata);
      if (url === 'https://verifier.example/.well-known/verifier') return json(verifierMetadata);
      if (url === 'https://issuer.example/.well-known/keys') {
        keyFetches++;
        return json({
          ...keyDiscoveryMetadata,
          voprf: { ...keyDiscoveryMetadata.voprf, kid: keyFetches === 1 ? 'kid-2' : 'kid-2' },
        });
      }
      if (url === 'https://issuer.example/v1/oprf/issue/batch') {
        const request = bodyOf(init);
        bodies.push(request);
        batchPosts++;
        if (batchPosts === 2) generatedBeforeRetry = generatedNonces.length;
        const elements = request.body.blinded_elements as string[];
        const kid = batchPosts === 1 ? 'kid-1' : batchPosts === 2 ? 'kid-2' : 'kid-2';
        return json({
          results: elements.map(() => ({ status: 'success', token: 'evaluation', kid, issuer_id: 'issuer:test' })),
          successful: elements.length, failed: 0, processing_time_ms: 1, throughput: elements.length,
        });
      }
      throw new Error(`unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const tokens = await new FreebirdClient({
      issuerUrl: 'https://issuer.example', verifierUrl: 'https://verifier.example',
    }).issueTokens(
      Array.from({ length: 3_000 }, () => new Uint8Array(32)),
      {
        proofFactory: ({ binding }) => {
          bindings.push(binding);
          const proof = bindings.length <= 2 ? { type: 'none' as const } : largeProof;
          proofSizes.push(JSON.stringify(proof).length);
          return proof;
        },
      },
    );

    expect(tokens).toHaveLength(3_000);
    expect(bodies.length).toBeGreaterThan(3);
    expect((bodies[0].body.blinded_elements as string[]).length).toBeGreaterThan(0);
    expect(bodies[0].body.sybil_proof).toEqual({ type: 'none' });
    expect(bodies[1].body.sybil_proof).toEqual({ type: 'none' });
    expect(bodies[2].body.sybil_proof).toEqual(largeProof);
    expect((bodies[2].body.blinded_elements as string[]).length)
      .toBeLessThan((bodies[1].body.blinded_elements as string[]).length);
    expect(bodies.every(({ raw }) => new TextEncoder().encode(raw).byteLength <= LIMIT)).toBe(true);
    expect(bodies.slice(0, 1).concat(bodies.slice(2))
      .reduce((sum, request) => sum + (request.body.blinded_elements as string[]).length, 0)).toBe(3_000);
    const completedCount = (bodies[0].body.blinded_elements as string[]).length;
    const expectedOutputNonces = generatedNonces.slice(0, completedCount).concat(
      generatedNonces.slice(generatedBeforeRetry, generatedBeforeRetry + 3_000 - completedCount),
    );
    expect(tokens.map((token) => token.tokenValue)).toEqual(expectedOutputNonces.map(base64Url));
    expect(generatedBeforeRetry).toBeGreaterThan(completedCount);
    expect(bindings.length).toBeGreaterThan(bodies.length);
    expect(proofSizes.some((size) => size > 10_000)).toBe(true);
    for (const { body } of bodies) {
      expect(bindings).toContain(buildBatchBinding(
        'issue-batch', 'issuer:test', body.blinded_elements as string[],
      ));
    }
  });

  it('re-chunks a completed-tail V5 retry with larger proof bytes without replaying passes', async () => {
    const keyA = 'a'.repeat(64);
    const keyB = 'b'.repeat(64);
    const largeProof = { type: 'registered_user' as const, user_id: 'retry-v5'.repeat(2_000) };
    const keyMetadata = (tokenKeyId: string) => ({
      ...keyDiscoveryMetadata,
      public: [{ ...keyDiscoveryMetadata.public[0], token_key_id: tokenKeyId }],
    });
    const nonces = Array.from({ length: 500 }, (_, index) => {
      const nonce = new Uint8Array(32);
      nonce.fill(index);
      return nonce;
    });
    const bodies: { raw: string; body: Record<string, unknown> }[] = [];
    const bindings: string[] = [];
    let keyFetches = 0;
    let batchPosts = 0;
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === 'https://issuer.example/.well-known/issuer') return json(issuerMetadata);
      if (url === 'https://issuer.example/.well-known/keys') {
        keyFetches++;
        return json(keyMetadata(keyFetches === 1 ? keyA : keyB));
      }
      if (url === 'https://issuer.example/v1/public/issue/batch') {
        const request = bodyOf(init);
        bodies.push(request);
        batchPosts++;
        const messages = request.body.blinded_msgs as string[];
        const responseKey = batchPosts === 1 ? keyA : keyB;
        return json({
          blind_signatures: messages.map(() => 'AQID'), token_key_id: responseKey,
          issuer_id: 'issuer:test', successful: messages.length, failed: 0,
          processing_time_ms: 1, throughput: messages.length,
        });
      }
      throw new Error(`unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const passes = await new FreebirdClient({ issuerUrl: 'https://issuer.example' })
      .issuePublicTokensForCurrentKey(nonces, {
        proofFactory: ({ binding }) => {
          bindings.push(binding);
          return bindings.length <= 2 ? { type: 'none' } : largeProof;
        },
      });

    expect(passes).toHaveLength(500);
    expect(bodies.length).toBeGreaterThan(3);
    expect(bodies[0].body.token_key_id).toBe(keyA);
    expect(bodies[1].body.token_key_id).toBe(keyA);
    expect(bodies[2].body.token_key_id).toBe(keyB);
    expect(bodies[0].body.sybil_proof).toEqual({ type: 'none' });
    expect(bodies[1].body.sybil_proof).toEqual({ type: 'none' });
    expect(bodies[2].body.sybil_proof).toEqual(largeProof);
    expect((bodies[2].body.blinded_msgs as string[]).length)
      .toBeLessThan((bodies[1].body.blinded_msgs as string[]).length);
    expect(bodies.every(({ raw }) => new TextEncoder().encode(raw).byteLength <= LIMIT)).toBe(true);
    expect(bodies.slice(0, 1).concat(bodies.slice(2))
      .reduce((sum, request) => sum + (request.body.blinded_msgs as string[]).length, 0)).toBe(500);
    expect(bindings.length).toBeGreaterThan(bodies.length);
    for (const { body } of bodies) {
      expect(bindings).toContain(buildBatchBinding(
        'public-issue-batch', 'issuer:test', body.blinded_msgs as string[],
      ));
    }
    expect(passes).toEqual(nonces);
  });

  it('accepts exactly 60 KiB and excludes the next item for both V4 and V5', async () => {
    let nonceValue = 0;
    const generatedNonces: Uint8Array[] = [];
    vi.stubGlobal('crypto', {
      getRandomValues: (bytes: Uint8Array) => {
        bytes.fill(nonceValue++);
        generatedNonces.push(bytes.slice());
        return bytes;
      },
    });
    const v4Base = {
      blinded_elements: ['A'.repeat(44)],
      sybil_proof: undefined,
      ctx_b64: '',
    };
    const v4Context = 'x'.repeat(LIMIT - new TextEncoder().encode(JSON.stringify(v4Base)).byteLength);
    const v4Fetch = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === 'https://issuer.example/.well-known/issuer') return json(issuerMetadata);
      if (url === 'https://verifier.example/.well-known/verifier') return json(verifierMetadata);
      if (url === 'https://issuer.example/v1/oprf/issue/batch') {
        const { body } = bodyOf(init);
        const elements = body.blinded_elements as string[];
        return json({
          results: elements.map(() => ({ status: 'success', token: 'evaluation', kid: 'kid-1', issuer_id: 'issuer:test' })),
          successful: elements.length, failed: 0, processing_time_ms: 1, throughput: elements.length,
        });
      }
      throw new Error(`unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', v4Fetch);
    const v4Tokens = await new FreebirdClient({ issuerUrl: 'https://issuer.example', verifierUrl: 'https://verifier.example' })
      .issueTokens([new Uint8Array(32), new Uint8Array(32)], { ctxB64: v4Context });
    const v4Bodies = v4Fetch.mock.calls
      .filter(([url]) => url === 'https://issuer.example/v1/oprf/issue/batch')
      .map(([, init]) => bodyOf(init));
    expect(v4Bodies).toHaveLength(2);
    expect(v4Bodies.every(({ raw }) => new TextEncoder().encode(raw).byteLength === LIMIT)).toBe(true);
    expect(v4Bodies.map(({ body }) => (body.blinded_elements as string[]).length)).toEqual([1, 1]);
    expect(v4Tokens.map((token) => token.tokenValue)).toEqual(generatedNonces.map(base64Url));

    const v5BaseProof = { type: 'registered_user' as const, user_id: '' };
    const v5Base = {
      blinded_msgs: ['A'.repeat(342)],
      token_key_id: 'a'.repeat(64),
      sybil_proof: v5BaseProof,
    };
    const v5Proof = {
      type: 'registered_user' as const,
      user_id: 'x'.repeat(LIMIT - new TextEncoder().encode(JSON.stringify(v5Base)).byteLength),
    };
    const v5Fetch = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === 'https://issuer.example/.well-known/keys') return json(keyDiscoveryMetadata);
      if (url === 'https://issuer.example/v1/public/issue/batch') {
        const { body } = bodyOf(init);
        const messages = body.blinded_msgs as string[];
        return json({
          blind_signatures: messages.map(() => 'AQID'), token_key_id: 'a'.repeat(64), issuer_id: 'issuer:test',
          successful: messages.length, failed: 0, processing_time_ms: 1, throughput: messages.length,
        });
      }
      throw new Error(`unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', v5Fetch);
    await new FreebirdClient({ issuerUrl: 'https://issuer.example' }).issuePublicTokens(
      [new Uint8Array(48), new Uint8Array(48)],
      {
        tokenKeyId: 'a'.repeat(64), issuerId: 'issuer:test',
        nonces: [new Uint8Array(32), new Uint8Array(32)],
        proofFactory: () => v5Proof,
      },
    );
    const v5Bodies = v5Fetch.mock.calls
      .filter(([url]) => url === 'https://issuer.example/v1/public/issue/batch')
      .map(([, init]) => bodyOf(init));
    expect(v5Bodies).toHaveLength(2);
    expect(v5Bodies.every(({ raw }) => new TextEncoder().encode(raw).byteLength === LIMIT)).toBe(true);
    expect(v5Bodies.map(({ body }) => (body.blinded_msgs as string[]).length)).toEqual([1, 1]);
  });

  it('rejects limits above the SDK ceiling before any discovery or network I/O', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    await expect(new FreebirdClient({
      issuerUrl: 'https://issuer.example',
      batchBodyLimitBytes: LIMIT + 1,
    }).issueTokens([])).rejects.toThrow('cannot exceed 60 KiB');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('preflights protocol-sized elements and all static fields before discovery', async () => {
    const v4Fetch = vi.fn();
    vi.stubGlobal('fetch', v4Fetch);
    await expect(new FreebirdClient({
      issuerUrl: 'https://issuer.example',
      batchBodyLimitBytes: 60,
    }).issueTokens([new Uint8Array(32)])).rejects.toThrow('single batch item exceeds');
    expect(v4Fetch).not.toHaveBeenCalled();

    const v5Fetch = vi.fn();
    vi.stubGlobal('fetch', v5Fetch);
    await expect(new FreebirdClient({
      issuerUrl: 'https://issuer.example',
      batchBodyLimitBytes: 400,
    }).issuePublicTokens(
      [new Uint8Array(48)],
      {
        tokenKeyId: 'a'.repeat(64), issuerId: 'issuer:test', nonces: [new Uint8Array(32)],
      },
    )).rejects.toThrow('single batch item exceeds');
    expect(v5Fetch).not.toHaveBeenCalled();
  });
});
