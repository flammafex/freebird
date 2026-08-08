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

import { buildIssueBinding, FreebirdClient } from '../src/index.js';
import {
  DiscoveryError,
  VerifierNotConfiguredError,
} from '../src/index.js';
import * as voprf from '../src/crypto/voprf.js';
import type { SybilProofFactory } from '../src/index.js';

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
  vi.unstubAllGlobals();
  vi.clearAllMocks();
  vi.restoreAllMocks();
});

describe('issuer key discovery cache and initialization characterization', () => {
  it('keeps a live config reference and dispatches the public init hook', async () => {
    class InitProbe extends FreebirdClient {
      initCalls = 0;

      override async init(): Promise<void> {
        this.initCalls++;
        await super.init();
      }
    }
    const config = {
      issuerUrl: 'https://issuer.example',
      verifierUrl: 'https://verifier.example',
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-1', issuer_id: 'issuer:test' }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = new InitProbe(config);
    config.issuerUrl = 'https://issuer.changed';

    await sdk.issueToken();

    expect(sdk.initCalls).toBe(1);
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      'https://issuer.changed/.well-known/issuer',
      'https://verifier.example/.well-known/verifier',
      'https://issuer.changed/v1/oprf/issue',
    ]);
  });

  it('dispatches public discovery overrides for V5 and exchange selection', async () => {
    class DiscoveryProbe extends FreebirdClient {
      discoveryCalls = 0;

      override async getKeyDiscoveryMetadata() {
        this.discoveryCalls++;
        return keyDiscoveryMetadata;
      }
    }
    const v5Probe = new DiscoveryProbe({ issuerUrl: 'https://issuer.example' });
    const v5Fetch = vi.fn().mockResolvedValue(json({
      blind_signature_b64: 'signature', token_key_id: 'a'.repeat(64), issuer_id: 'issuer:test',
    }));
    vi.stubGlobal('fetch', v5Fetch);
    await expect(v5Probe.issuePublicBlindSignature('message', undefined, 'a'.repeat(64)))
      .resolves.toMatchObject({ blind_signature_b64: 'signature' });
    expect(v5Probe.discoveryCalls).toBe(0);

    const discoveryV5Probe = new DiscoveryProbe({ issuerUrl: 'https://issuer.example' });
    const discoveryV5Fetch = vi.fn().mockResolvedValue(json({
      blind_signature_b64: 'signature', token_key_id: 'a'.repeat(64), issuer_id: 'issuer:test',
    }));
    vi.stubGlobal('fetch', discoveryV5Fetch);
    await expect(discoveryV5Probe.issuePublicBlindSignature('message'))
      .rejects.toThrow('No V5 public bearer key is available');
    expect(discoveryV5Probe.discoveryCalls).toBe(1);

    const exchangeProbe = new DiscoveryProbe({ issuerUrl: 'https://issuer.example' });
    await expect(exchangeProbe.selectExchangeTransition('a'.repeat(64), 'b'.repeat(64)))
      .rejects.toThrow('Issuer does not publish V2 exchange discovery');
    expect(exchangeProbe.discoveryCalls).toBe(1);
  });

  it('caches validated discovery and returns the same object on later reads', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(keyDiscoveryMetadata));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example', verifierId: 'v', audience: 'a' });

    const first = await sdk.getKeyDiscoveryMetadata();
    const second = await sdk.getKeyDiscoveryMetadata();

    expect(second).toBe(first);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith('https://issuer.example/.well-known/keys');
  });

  it('does not cache a failed discovery fetch', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('unavailable', { status: 503 }))
      .mockResolvedValueOnce(json(keyDiscoveryMetadata));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example', verifierId: 'v', audience: 'a' });

    await expect(sdk.getKeyDiscoveryMetadata()).rejects.toBeInstanceOf(DiscoveryError);
    await expect(sdk.getKeyDiscoveryMetadata()).resolves.toEqual(keyDiscoveryMetadata);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not cache discovery that fails structural validation', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ ...keyDiscoveryMetadata, graph_issuance: {} }))
      .mockResolvedValueOnce(json(keyDiscoveryMetadata));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example', verifierId: 'v', audience: 'a' });

    await expect(sdk.getKeyDiscoveryMetadata()).rejects.toThrow(
      'Invalid graph issuance discovery metadata',
    );
    await expect(sdk.getKeyDiscoveryMetadata()).resolves.toEqual(keyDiscoveryMetadata);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not coalesce concurrent discovery fetches', async () => {
    const pending: Array<(response: Response) => void> = [];
    const fetchMock = vi.fn(() => new Promise<Response>((resolve) => pending.push(resolve)));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example', verifierId: 'v', audience: 'a' });

    const first = sdk.getKeyDiscoveryMetadata();
    const second = sdk.getKeyDiscoveryMetadata();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(pending).toHaveLength(2);

    pending[0](json(keyDiscoveryMetadata));
    pending[1](json(keyDiscoveryMetadata));
    await expect(first).resolves.toEqual(keyDiscoveryMetadata);
    await expect(second).resolves.toEqual(keyDiscoveryMetadata);
  });

  it('keeps successful issuer metadata across a failed verifier fetch', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(new Response('verifier down', { status: 503 }))
      .mockResolvedValueOnce(json(verifierMetadata));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();

    await expect(sdk.init()).rejects.toBeInstanceOf(DiscoveryError);
    await expect(sdk.init()).resolves.toBeUndefined();
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      'https://issuer.example/.well-known/issuer',
      'https://verifier.example/.well-known/verifier',
      'https://verifier.example/.well-known/verifier',
    ]);
  });

  it('does not re-enter init from issueToken after a verifier-only partial init', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(new Response('verifier down', { status: 503 }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();

    await expect(sdk.init()).rejects.toBeInstanceOf(DiscoveryError);
    await expect(sdk.issueToken()).rejects.toThrow();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('prefers verifierUrl over verifierId and audience during partial initialization', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(new Response('verifier down', { status: 503 }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({
      issuerUrl: 'https://issuer.example',
      verifierUrl: 'https://verifier.example',
      verifierId: 'fallback-verifier',
      audience: 'fallback-audience',
    });

    await expect(sdk.init()).rejects.toBeInstanceOf(DiscoveryError);
    expect(fetchMock.mock.calls[1][0]).toBe('https://verifier.example/.well-known/verifier');
  });

  it('derives verifier scope locally when verifierUrl is absent', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(issuerMetadata));
    vi.stubGlobal('fetch', fetchMock);
    await expect(client({
      issuerUrl: 'https://issuer.example',
      verifierId: 'verifier:test',
      audience: 'audience:test',
    }).init()).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe('V4 private issuance and verifier HTTP characterization', () => {
  it('orchestrates V4 with exact nonce, scope, context, arguments, and order', async () => {
    const nonce = new Uint8Array(32).fill(0x2a);
    const randomValues = vi.spyOn(globalThis.crypto, 'getRandomValues')
      .mockImplementation((array) => {
        (array as Uint8Array).set(nonce);
        return array;
      });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-1', issuer_id: 'issuer:test' }));
    vi.stubGlobal('fetch', fetchMock);

    await client().issueToken();

    const context = new TextEncoder().encode('freebird:v4');
    const scope = new Uint8Array([1, 2, 3]);
    const privateInputCall = vi.mocked(voprf.buildPrivateTokenInput).mock.calls[0];
    const blindCall = vi.mocked(voprf.blind).mock.calls[0];
    const finalizeCall = vi.mocked(voprf.finalize).mock.calls[0];
    const redemptionCall = vi.mocked(voprf.buildRedemptionToken).mock.calls[0];
    const scopeCall = vi.mocked(voprf.buildScopeDigest).mock.calls[0];
    expect(randomValues).toHaveBeenCalledTimes(1);
    const generatedNonce = randomValues.mock.calls[0][0] as Uint8Array;
    expect(generatedNonce).toEqual(nonce);
    expect(privateInputCall[0]).toBe('issuer:test');
    expect(privateInputCall[1]).toBe('kid-1');
    expect(privateInputCall[2]).toBe(generatedNonce);
    expect(privateInputCall[3]).toEqual(scope);
    expect(blindCall[0]).toEqual(new Uint8Array([8]));
    expect(scopeCall).toEqual(['verifier:test', 'audience:test']);
    expect(blindCall[1]).toEqual(context);
    expect(finalizeCall).toEqual([
      { r: 1n, p: {} },
      'evaluation',
      'public-key',
      blindCall[1],
    ]);
    expect(finalizeCall[3]).toBe(blindCall[1]);
    expect(redemptionCall).toEqual([
      generatedNonce,
      privateInputCall[3],
      'kid-1',
      'issuer:test',
      new Uint8Array([6, 7]),
    ]);
    expect(redemptionCall[1]).toBe(privateInputCall[3]);
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      'https://issuer.example/.well-known/issuer',
      'https://verifier.example/.well-known/verifier',
      'https://issuer.example/v1/oprf/issue',
    ]);
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toEqual({ blinded_element_b64: 'BAU' });
    const order = [
      vi.mocked(voprf.buildPrivateTokenInput).mock.invocationCallOrder[0],
      vi.mocked(voprf.blind).mock.invocationCallOrder[0],
      vi.mocked(voprf.finalize).mock.invocationCallOrder[0],
      vi.mocked(voprf.buildRedemptionToken).mock.invocationCallOrder[0],
    ];
    expect(order[0]).toBeLessThan(order[1]);
    expect(order[1]).toBeLessThan(order[2]);
    expect(order[2]).toBeLessThan(order[3]);
    expect(vi.mocked(voprf.buildScopeDigest).mock.invocationCallOrder[0])
      .toBeLessThan(order[0]);
  });

  it('rejects an inconsistent published scope before blind or issue POST', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json({ ...verifierMetadata, scope_digest_b64: 'AQIE' }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(client().issueToken()).rejects.toThrow('Verifier scope metadata is inconsistent');
    expect(vi.mocked(voprf.blind)).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1][0]).toBe('https://verifier.example/.well-known/verifier');
  });

  it('exposes a typed V4 proof factory across a stale-key retry', async () => {
    const rotatedMetadata = {
      ...keyDiscoveryMetadata,
      voprf: { ...keyDiscoveryMetadata.voprf, kid: 'kid-2' },
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-2', issuer_id: 'issuer:test' }))
      .mockResolvedValueOnce(json(rotatedMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-2', issuer_id: 'issuer:test' }));
    vi.stubGlobal('fetch', fetchMock);
    vi.mocked(voprf.blind)
      .mockImplementationOnce(() => ({
        blinded: new Uint8Array([4, 5]), state: { r: 1n, p: {} },
      }))
      .mockImplementationOnce(() => ({
        blinded: new Uint8Array([6, 7]), state: { r: 2n, p: {} },
      }));
    const bindings: string[] = [];
    const proofs: Array<{ type: 'proof_of_work'; input: string; nonce: number; timestamp: number }> = [];
    const proofFactory: SybilProofFactory = ({ binding }) => {
      bindings.push(binding);
      const proof = {
        type: 'proof_of_work' as const,
        input: binding,
        nonce: bindings.length,
        timestamp: 1_000 + bindings.length,
      };
      proofs.push(proof);
      return proof;
    };

    await client().issueTokenWithProofFactory(proofFactory);

    const posts = fetchMock.mock.calls.filter(([url]) => url.endsWith('/v1/oprf/issue'));
    expect(posts).toHaveLength(2);
    expect(bindings).toEqual(posts.map(([, init]) => {
      const body = JSON.parse(init.body as string);
      return buildIssueBinding('issuer:test', body.blinded_element_b64);
    }));
    expect(bindings[0]).not.toBe(bindings[1]);
    expect(proofs).toEqual([
      expect.objectContaining({ input: bindings[0] }),
      expect.objectContaining({ input: bindings[1] }),
    ]);
    expect(proofs[0]).not.toEqual(proofs[1]);
    expect(JSON.parse(posts[0][1].body as string).sybil_proof).toEqual(proofs[0]);
    expect(JSON.parse(posts[1][1].body as string).sybil_proof).toEqual(proofs[1]);
  });

  it('reports a missing verifier scope before blind or issue POST', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(json(issuerMetadata));
    vi.stubGlobal('fetch', fetchMock);

    await expect(client({ issuerUrl: 'https://issuer.example' }).issueToken())
      .rejects.toThrow('Verifier scope required: configure verifierUrl or verifierId+audience');
    expect(vi.mocked(voprf.blind)).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('https://issuer.example/.well-known/issuer');
  });

  it('serializes the V4 issue request and returns the V4 redemption-token facade', async () => {
    const proof = { type: 'invitation' as const, code: 'invite', signature: 'sig' };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-1', issuer_id: 'issuer:test' }));
    vi.stubGlobal('fetch', fetchMock);

    const token = await client().issueToken(proof);

    expect(token).toEqual({ tokenValue: 'CQgH', issuerId: 'issuer:test', version: 4, kid: 'kid-1' });
    expect(fetchMock.mock.calls[2][0]).toBe('https://issuer.example/v1/oprf/issue');
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toEqual({
      blinded_element_b64: 'BAU',
      sybil_proof: proof,
    });
  });

  it.each([400, 401, 403] as const)('maps issuer rejection HTTP %i to the rejection family', async (status) => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(new Response('rejected', { status }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(client().issueToken()).rejects.toMatchObject({ code: 'issuance' });
  });

  it('maps non-policy issuer failures separately and auto-refreshes on key rotation', async () => {
    const failedFetch = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(new Response('backend failure', { status: 500 }));
    vi.stubGlobal('fetch', failedFetch);
    await expect(client().issueToken()).rejects.toMatchObject({ code: 'issuance' });

    // First issue returns a rotated kid; the SDK refreshes discovery and
    // retries successfully with the new key.
    const rotatedMetadata = {
      ...keyDiscoveryMetadata,
      voprf: { ...keyDiscoveryMetadata.voprf, kid: 'kid-2' },
    };
    const rotatedFetch = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-2', issuer_id: 'issuer:test' }))
      .mockResolvedValueOnce(json(rotatedMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-2', issuer_id: 'issuer:test' }));
    vi.stubGlobal('fetch', rotatedFetch);
    const token = await client().issueToken();
    expect(token.kid).toBe('kid-2');

    // Persistent mismatch after refresh still throws DiscoveryError.
    const persistentFetch = vi.fn()
      .mockResolvedValueOnce(json(issuerMetadata))
      .mockResolvedValueOnce(json(verifierMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-2', issuer_id: 'issuer:test' }))
      .mockResolvedValueOnce(json(rotatedMetadata))
      .mockResolvedValueOnce(json({ token: 'evaluation', kid: 'kid-3', issuer_id: 'issuer:test' }));
    vi.stubGlobal('fetch', persistentFetch);
    await expect(client().issueToken()).rejects.toBeInstanceOf(DiscoveryError);
  });

  it('preserves verifier wire behavior for accepted, rejected, and unconfigured clients', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ ok: true, verified_at: 1 }))
      .mockResolvedValueOnce(new Response('invalid', { status: 400 }))
      .mockResolvedValueOnce(json({ ok: false, error: 'replay_detected', verified_at: 0 }, 401));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();
    const v5Token = {
      tokenValue: 'v5-wire-token',
      issuerId: 'issuer:test',
      version: 5 as const,
      tokenKeyId: 'a'.repeat(64),
    };

    await expect(sdk.verifyToken(v5Token)).resolves.toEqual({ ok: true, verified_at: 1 });
    await expect(sdk.verifyToken(v5Token)).rejects.toMatchObject({ code: 'invalid_token' });
    await expect(sdk.verifyToken(v5Token)).rejects.toMatchObject({ code: 'replayed_token' });
    expect(fetchMock).toHaveBeenNthCalledWith(1, 'https://verifier.example/v1/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token_b64: 'v5-wire-token' }),
    });

    const noVerifier = client({ issuerUrl: 'https://issuer.example' });
    await expect(noVerifier.verifyToken(v5Token)).rejects.toBeInstanceOf(VerifierNotConfiguredError);
  });

  it('classifies partial replay-shaped responses as invalid tokens', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      json({ ok: false, error: 'replay_detected' }, 401),
    ));
    await expect(client().verifyToken({
      tokenValue: 'v5-wire-token', issuerId: 'issuer:test', version: 5,
    })).rejects.toMatchObject({ code: 'invalid_token' });
  });
});

describe('V5 public bearer issuance HTTP characterization', () => {
  const v5Metadata = {
    ...keyDiscoveryMetadata,
    public: [{
      token_key_id: 'a'.repeat(64),
      token_type: 'public_bearer_pass',
      rfc9474_variant: 'RSABSSA-SHA384-PSS-Deterministic',
      modulus_bits: 2048,
      pubkey_spki_b64: 'spki',
      issuer_id: 'issuer:test',
      valid_from: 1,
      valid_until: 2,
      spend_policy: 'single_use',
    }],
  };

  it('discovers the single-use V5 key and accepts byte or string blinded messages', async () => {
    const proof = { type: 'none' as const };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(v5Metadata))
      .mockResolvedValueOnce(json({
        blind_signature_b64: 'signature',
        token_key_id: 'a'.repeat(64),
        issuer_id: 'issuer:test',
      }))
      .mockResolvedValueOnce(json({
        blind_signature_b64: 'signature-2',
        token_key_id: 'a'.repeat(64),
        issuer_id: 'issuer:test',
      }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client({ issuerUrl: 'https://issuer.example', verifierId: 'v', audience: 'a' });

    await expect(sdk.issuePublicBlindSignature(new Uint8Array([1, 2]), proof))
      .resolves.toMatchObject({ blind_signature_b64: 'signature' });
    await expect(sdk.issuePublicBlindSignature('already-base64url', proof))
      .resolves.toMatchObject({ blind_signature_b64: 'signature-2' });
    expect(fetchMock.mock.calls[1][1].body).toBe(JSON.stringify({
      blinded_msg_b64: 'AQI', token_key_id: 'a'.repeat(64), sybil_proof: proof,
    }));
    expect(fetchMock.mock.calls[2][1].body).toBe(JSON.stringify({
      blinded_msg_b64: 'already-base64url', token_key_id: 'a'.repeat(64), sybil_proof: proof,
    }));
  });

  it('selects the first eligible V5 key in published order', async () => {
    const firstEligible = 'c'.repeat(64);
    const secondEligible = 'd'.repeat(64);
    const metadata = {
      ...v5Metadata,
      public: [
        { ...v5Metadata.public[0], token_type: 'other', token_key_id: 'b'.repeat(64) },
        { ...v5Metadata.public[0], token_key_id: firstEligible },
        { ...v5Metadata.public[0], token_key_id: secondEligible },
      ],
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(metadata))
      .mockResolvedValueOnce(json({
        blind_signature_b64: 'signature', token_key_id: firstEligible, issuer_id: 'issuer:test',
      }));
    vi.stubGlobal('fetch', fetchMock);

    await client({ issuerUrl: 'https://issuer.example', verifierId: 'v', audience: 'a' })
      .issuePublicBlindSignature('message');
    expect(JSON.parse(fetchMock.mock.calls[1][1].body).token_key_id).toBe(firstEligible);
  });

  it('honors an explicit V5 key without discovery, rejects missing keys, and preserves errors', async () => {
    const directFetch = vi.fn().mockResolvedValue(json({
      blind_signature_b64: 'signature', token_key_id: 'b'.repeat(64), issuer_id: 'issuer:test',
    }));
    vi.stubGlobal('fetch', directFetch);
    await expect(client().issuePublicBlindSignature('message', undefined, 'b'.repeat(64)))
      .resolves.toMatchObject({ token_key_id: 'b'.repeat(64) });
    expect(directFetch).toHaveBeenCalledTimes(2);

    const missingFetch = vi.fn().mockResolvedValue(json(keyDiscoveryMetadata));
    vi.stubGlobal('fetch', missingFetch);
    await expect(client({ issuerUrl: 'https://issuer.example', verifierId: 'v', audience: 'a' })
      .issuePublicBlindSignature('message')).rejects.toThrow('No V5 public bearer key is available');
    expect(missingFetch).toHaveBeenCalledTimes(1);

    const errorFetch = vi.fn().mockResolvedValue(new Response('rejected', { status: 422 }));
    vi.stubGlobal('fetch', errorFetch);
    await expect(client().issuePublicBlindSignature('message', undefined, 'b'.repeat(64)))
      .rejects.toMatchObject({ code: 'issuance' });
  });
});
