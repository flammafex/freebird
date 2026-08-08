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
  buildPublicBearerPass: vi.fn(() => new Uint8Array([9, 8, 7])),
  parsePublicBearerPass: vi.fn(),
}));

vi.mock('../src/crypto/rsa.js', () => ({
  rsaBlind: vi.fn(async () => ({
    blinded: new Uint8Array([1, 2]),
    state: { inv: new Uint8Array(), prepared: new Uint8Array(), publicKey: new Uint8Array() },
  })),
  rsaUnblind: vi.fn(async () => new Uint8Array([3, 4, 5])),
  rsaVerify: vi.fn(async () => true),
}));

import {
  buildIssueBinding,
  buildPublicIssueBinding,
  FreebirdClient,
  DiscoveryError,
  StalePublicKeyError,
} from '../src/index.js';
import * as rsa from '../src/crypto/rsa.js';
import type { SybilProofFactory } from '../src/index.js';
import { createClientState } from '../src/client/state.js';
import { issueToken } from '../src/client/issuance.js';

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
  function privateIssuanceState() {
    const state = createClientState({ issuerUrl: 'https://issuer.example' });
    state.metadata = { ...issuerMetadata, voprf: { ...issuerMetadata.voprf } };
    state.verifierMetadata = { ...verifierMetadata };
    return state;
  }

  it('does not retry V4 single issuance with a fixed proof after stale-key response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({
      token: 'evaluation', kid: 'kid-2', issuer_id: 'issuer:test',
    }));
    vi.stubGlobal('fetch', fetchMock);
    const state = privateIssuanceState();
    const rotatedMetadata = {
      ...keyDiscoveryMetadata,
      voprf: { ...keyDiscoveryMetadata.voprf, kid: 'kid-2' },
    };

    await expect(issueToken(
      state,
      { type: 'none' },
      async () => undefined,
      async () => rotatedMetadata,
    )).rejects.toBeInstanceOf(StalePublicKeyError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('refreshes V4 single issuance with a factory-bound proof on retry', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({
        token: 'evaluation', kid: 'kid-2', issuer_id: 'issuer:test',
      }))
      .mockResolvedValueOnce(json({
        token: 'evaluation', kid: 'kid-2', issuer_id: 'issuer:test',
      }));
    vi.stubGlobal('fetch', fetchMock);
    const state = privateIssuanceState();
    const rotatedMetadata = {
      ...keyDiscoveryMetadata,
      voprf: { ...keyDiscoveryMetadata.voprf, kid: 'kid-2' },
    };
    const bindings: string[] = [];
    const factory: SybilProofFactory = ({ binding }) => {
      bindings.push(binding);
      return { type: 'none' };
    };

    await issueToken(state, factory, async () => undefined, async () => rotatedMetadata);

    const posts = fetchMock.mock.calls.map(([, init]) => JSON.parse(init.body as string));
    expect(bindings).toEqual(posts.map((body) =>
      buildIssueBinding('issuer:test', body.blinded_element_b64)));
    expect(bindings).toHaveLength(2);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

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

  it('rejects low-level V5 key mismatch without replaying the blinded value', async () => {
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
    // Cached discovery says key A; issuer has rotated to key B and returns it.
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
      .rejects.toBeInstanceOf(StalePublicKeyError);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('throws StalePublicKeyError on a persistent low-level V5 mismatch', async () => {
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

    await expect(sdk.issuePublicBlindSignature('message')).rejects.toBeInstanceOf(StalePublicKeyError);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not replay a caller blinded value after token_key_not_active', async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve(json({ error: 'token_key_not_active' }, 400)));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example' });

    await expect(sdk.issuePublicBlindSignature('old-blinded', undefined, 'a'.repeat(64)))
      .rejects.toBeInstanceOf(StalePublicKeyError);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('reblinds once for the type-safe current-key V5 API', async () => {
    const keyA = 'a'.repeat(64);
    const keyB = 'b'.repeat(64);
    const metadataWith = (tokenKeyId: string) => ({
      issuer_id: 'issuer:test', current_epoch: 1, valid_epochs: [1],
      epoch_duration_sec: 3600,
      voprf: { suite: 'P256-SHA256', kid: 'kid', pubkey: 'pubkey' },
      public: [{
        token_key_id: tokenKeyId,
        token_type: 'public_bearer_pass',
        rfc9474_variant: 'RSABSSA-SHA384-PSS-Deterministic',
        modulus_bits: 2048,
        pubkey_spki_b64: 'spki',
        issuer_id: 'issuer:test', valid_from: 1, valid_until: 2,
        spend_policy: 'single_use',
      }],
    });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({
        issuer_id: 'issuer:test',
        voprf: { suite: 'P256-SHA256', kid: 'kid', pubkey: 'pubkey' },
      }))
      .mockResolvedValueOnce(json(metadataWith(keyA)))
      .mockResolvedValueOnce(json({ error: 'token_key_not_active' }, 400))
      .mockResolvedValueOnce(json({
        issuer_id: 'issuer:test',
        voprf: { suite: 'P256-SHA256', kid: 'kid', pubkey: 'pubkey' },
      }))
      .mockResolvedValueOnce(json(metadataWith(keyB)))
      .mockResolvedValueOnce(json({
        blind_signature_b64: 'sig', token_key_id: keyB, issuer_id: 'issuer:test',
      }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example' });
    const bindings: string[] = [];
    const proofFactory: SybilProofFactory = ({ binding }) => {
      bindings.push(binding);
      return { type: 'none' };
    };

    await expect(sdk.issuePublicTokenForCurrentKey({
      nonce: new Uint8Array(32), proofFactory,
    }))
      .resolves.toBeInstanceOf(Uint8Array);
    const posts = fetchMock.mock.calls.filter(([url]) => url.endsWith('/v1/public/issue'));
    expect(posts).toHaveLength(2);
    expect(rsa.rsaBlind).toHaveBeenCalledTimes(2);
    expect(bindings).toEqual(posts.map(([, init]) => {
      const body = JSON.parse(init.body as string);
      return buildPublicIssueBinding('issuer:test', body.blinded_msg_b64);
    }));
  });

  it('does not retry current-key V5 with a fixed proof after stale-key rejection', async () => {
    const keyA = 'a'.repeat(64);
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({
        issuer_id: 'issuer:test',
        voprf: { suite: 'P256-SHA256', kid: 'kid', pubkey: 'pubkey' },
      }))
      .mockResolvedValueOnce(json({
        ...keyDiscoveryMetadata,
        public: [{
          token_key_id: keyA,
          token_type: 'public_bearer_pass',
          rfc9474_variant: 'RSABSSA-SHA384-PSS-Deterministic',
          modulus_bits: 2048,
          pubkey_spki_b64: 'spki', issuer_id: 'issuer:test',
          valid_from: 1, valid_until: 2, spend_policy: 'single_use',
        }],
      }))
      .mockResolvedValueOnce(json({ error: 'token_key_not_active' }, 400));
    vi.stubGlobal('fetch', fetchMock);

    await expect(client({ issuerUrl: 'https://issuer.example' }).issuePublicTokenForCurrentKey({
      nonce: new Uint8Array(32), sybilProof: { type: 'none' },
    })).rejects.toBeInstanceOf(StalePublicKeyError);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls.filter(([url]) => url.endsWith('/v1/public/issue'))).toHaveLength(1);
  });
});
