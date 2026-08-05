// SPDX-License-Identifier: Apache-2.0 OR MIT

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

import { FreebirdClient, DiscoveryError } from '../src/index.js';

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
  public: [],
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
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
  vi.restoreAllMocks();
});

describe('key discovery cache TTL', () => {
  it('returns the cached metadata within the TTL without a second fetch', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(json(keyDiscoveryMetadata)));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example', keyCacheTtlMs: 1000 });

    const first = await sdk.getKeyDiscoveryMetadata();
    const second = await sdk.getKeyDiscoveryMetadata();

    expect(second).toBe(first);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('refetches once the TTL has elapsed', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(json(keyDiscoveryMetadata)));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example', keyCacheTtlMs: 1000 });

    await sdk.getKeyDiscoveryMetadata();
    vi.setSystemTime(new Date('2024-01-01T00:00:02Z')); // +2s, past the 1s TTL
    await sdk.getKeyDiscoveryMetadata();

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('derives the TTL from epoch_duration_sec when keyCacheTtlMs is unset', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(json(keyDiscoveryMetadata)));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example' });

    await sdk.getKeyDiscoveryMetadata();
    // epoch_duration_sec is 86_400 -> TTL 86_400_000ms; still fresh after 1s.
    vi.setSystemTime(new Date('2024-01-01T00:00:01Z'));
    await sdk.getKeyDiscoveryMetadata();

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('refreshKeyDiscoveryMetadata forces a fetch even when the cache is fresh', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(json(keyDiscoveryMetadata)));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example', keyCacheTtlMs: 1000 });

    await sdk.getKeyDiscoveryMetadata();
    await sdk.refreshKeyDiscoveryMetadata();

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe('auto-refresh-and-retry on key rotation', () => {
  it('refreshes discovery and retries successfully when the issuer rotates keys', async () => {
    const rotatedMetadata = {
      ...keyDiscoveryMetadata,
      voprf: { ...keyDiscoveryMetadata.voprf, kid: 'kid-2' },
    };
    // First issue returns kid-2 (rotated); refresh returns kid-2; retry succeeds.
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-2', issuer_id: 'issuer:test' }))
      .mockResolvedValueOnce(json(rotatedMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-2', issuer_id: 'issuer:test' }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();

    const token = await sdk.issueToken();

    expect(token.kid).toBe('kid-2');
    // issuer metadata, verifier metadata, first issue, refresh, retry issue
    expect(fetchMock).toHaveBeenCalledTimes(5);
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      'https://issuer.example/.well-known/issuer',
      'https://verifier.example/.well-known/verifier',
      'https://issuer.example/v1/oprf/issue',
      'https://issuer.example/.well-known/keys',
      'https://issuer.example/v1/oprf/issue',
    ]);
  });

  it('throws DiscoveryError when the mismatch persists after refresh', async () => {
    const rotatedMetadata = {
      ...keyDiscoveryMetadata,
      voprf: { ...keyDiscoveryMetadata.voprf, kid: 'kid-2' },
    };
    // First issue returns kid-2; refresh returns kid-2; retry still returns kid-3.
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-2', issuer_id: 'issuer:test' }))
      .mockResolvedValueOnce(json(rotatedMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-3', issuer_id: 'issuer:test' }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();

    await expect(sdk.issueToken()).rejects.toBeInstanceOf(DiscoveryError);
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });

  it('auto-refreshes and retries V5 public blind signature on token_key_id mismatch', async () => {
    const keyA = 'a'.repeat(64);
    const keyB = 'b'.repeat(64);
    const metadataWith = (tokenKeyId: string) => ({
      ...keyDiscoveryMetadata,
      public: [{
        token_key_id: tokenKeyId,
        token_type: 'public_bearer_pass',
        rfc9474_variant: 'RSABSSA-SHA384-PSS-Deterministic',
        modulus_bits: 2048,
        pubkey_spki_b64: 'spki',
        issuer_id: 'issuer:test',
        valid_from: 1,
        valid_until: 2,
        spend_policy: 'single_use',
      }],
    });
    // Cached discovery says key A; issuer has rotated to key B and returns it;
    // refresh returns key B; retry succeeds.
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(metadataWith(keyA)))
      .mockResolvedValueOnce(json({
        blind_signature_b64: 'sig', token_key_id: keyB, issuer_id: 'issuer:test',
      }))
      .mockResolvedValueOnce(json(metadataWith(keyB)))
      .mockResolvedValueOnce(json({
        blind_signature_b64: 'sig', token_key_id: keyB, issuer_id: 'issuer:test',
      }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example', verifierId: 'v', audience: 'a' });

    await expect(sdk.issuePublicBlindSignature('message'))
      .resolves.toMatchObject({ token_key_id: keyB });
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it('throws DiscoveryError on persistent V5 token_key_id mismatch', async () => {
    const keyA = 'a'.repeat(64);
    const keyB = 'b'.repeat(64);
    const keyC = 'c'.repeat(64);
    const metadataWith = (tokenKeyId: string) => ({
      ...keyDiscoveryMetadata,
      public: [{
        token_key_id: tokenKeyId,
        token_type: 'public_bearer_pass',
        rfc9474_variant: 'RSABSSA-SHA384-PSS-Deterministic',
        modulus_bits: 2048,
        pubkey_spki_b64: 'spki',
        issuer_id: 'issuer:test',
        valid_from: 1,
        valid_until: 2,
        spend_policy: 'single_use',
      }],
    });
    // Cached discovery says key A; issuer returns key C; refresh returns key B;
    // retry still returns key C -> persistent mismatch.
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(metadataWith(keyA)))
      .mockResolvedValueOnce(json({
        blind_signature_b64: 'sig', token_key_id: keyC, issuer_id: 'issuer:test',
      }))
      .mockResolvedValueOnce(json(metadataWith(keyB)))
      .mockResolvedValueOnce(json({
        blind_signature_b64: 'sig', token_key_id: keyC, issuer_id: 'issuer:test',
      }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example', verifierId: 'v', audience: 'a' });

    await expect(sdk.issuePublicBlindSignature('message')).rejects.toBeInstanceOf(DiscoveryError);
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });
});
