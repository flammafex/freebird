// SPDX-License-Identifier: Apache-2.0 OR MIT

import { afterEach, describe, expect, it, vi } from 'vitest';
import type { V7DirectBinding, V7DirectKeyDiscovery, V7Token } from '../src/index.js';

const bindingOne = {
  identity: { issuer_id: 'issuer:v7', token_key_id: '1'.repeat(64) },
  public_key_spki: new Uint8Array(1), spki_fingerprint: 'fingerprint-one', asset_id: 'CASH',
  amount_minor: 1n, valid_from: 0n, valid_until: 9999999999n,
} as unknown as V7DirectBinding;
const bindingTwo = {
  identity: { issuer_id: 'issuer:v7', token_key_id: '2'.repeat(64) },
  public_key_spki: new Uint8Array(1), spki_fingerprint: 'fingerprint-two', asset_id: 'CASH',
  amount_minor: 1n, valid_from: 0n, valid_until: 9999999999n,
} as unknown as V7DirectBinding;
const discovery = (tokenKeyId: string): V7DirectKeyDiscovery => ({
  issuer_id: 'issuer:v7', current_epoch: 1, valid_epochs: [1], epoch_duration_sec: 3600n,
  voprf: { suite: 'unused', kid: 'unused', pubkey: 'unused' },
  native_bearer_v7: { issuer_id: 'issuer:v7', token_key_id: tokenKeyId },
  native_bearer_v7_retained: [],
}) as unknown as V7DirectKeyDiscovery;

let activeBinding = bindingOne;
let activeDiscovery = discovery(bindingOne.identity.token_key_id);
const fakeToken = { body: { identity: bindingOne.identity } } as unknown as V7Token;

vi.mock('../src/client/v7_discovery.js', () => ({
  getV7KeyDiscoveryMetadata: vi.fn(async () => activeDiscovery),
  refreshV7KeyDiscoveryMetadata: vi.fn(async () => activeDiscovery),
}));

vi.mock('../src/crypto/native_bearer_v7.js', () => ({
  bindingFromV7Discovery: vi.fn(() => activeBinding),
  buildV7Body: vi.fn((input: unknown) => input),
  blindV7: vi.fn(async () => ({ blinded: new Uint8Array(384), state: {} })),
  deriveV7Nullifier: vi.fn(),
  directBindingFromDiscovery: vi.fn(() => activeBinding),
  finalizeV7: vi.fn(async () => fakeToken),
  parseV7Body: vi.fn(),
  serializeV7Token: vi.fn(() => Uint8Array.of(7, 1)),
  parseV7Token: vi.fn(() => fakeToken),
  v7ApplicationDigest: vi.fn(),
  v7ArtifactDigest: vi.fn(),
  v7BodyTranscript: vi.fn(),
  verifyV7Token: vi.fn(async () => true),
}));

import { FreebirdClient } from '../src/index.js';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function blindSignature(): string {
  return Buffer.alloc(384).toString('base64url');
}

afterEach(() => {
  activeBinding = bindingOne;
  activeDiscovery = discovery(bindingOne.identity.token_key_id);
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('V7 direct acceptance flow', () => {
  it('discovers, issues, locally verifies, checks, verifies, and rejects replay', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ issuer_id: 'issuer:v7', token_key_id: bindingOne.identity.token_key_id, blind_signature_b64: blindSignature() }))
      .mockResolvedValueOnce(json({ ok: true, verified_at: 1 }))
      .mockResolvedValueOnce(json({ ok: true, verified_at: 2 }))
      .mockResolvedValueOnce(json({ ok: false, error: 'replay_detected', verified_at: 0 }, 401));
    vi.stubGlobal('fetch', fetchMock);
    const client = new FreebirdClient({ issuerUrl: 'https://issuer.example', verifierUrl: 'https://verifier.example' });

    const discovered = await client.getV7KeyDiscoveryMetadata();
    expect(discovered.native_bearer_v7.token_key_id).toBe(bindingOne.identity.token_key_id);
    expect('native_exchange_v7' in discovered).toBe(false);

    const token = await client.issueNativeBearerV7({ owner_commitment: new Uint8Array(32) });
    expect(token.version).toBe(7);
    await expect(client.verifyNativeBearerV7Locally(token.tokenValue)).resolves.toBe(true);
    await expect(client.checkToken(token)).resolves.toMatchObject({ ok: true, verified_at: 1 });
    await expect(client.verifyToken(token)).resolves.toMatchObject({ ok: true, verified_at: 2 });
    await expect(client.verifyToken(token)).rejects.toMatchObject({ code: 'replayed_token' });
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it('rebuilds V7 state and proof binding once after stale-key rejection', async () => {
    const requests: Record<string, unknown>[] = [];
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      requests.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      if (requests.length === 1) {
        activeBinding = bindingTwo;
        activeDiscovery = discovery(bindingTwo.identity.token_key_id);
        return new Response('token_key_not_active', { status: 400 });
      }
      return json({ issuer_id: 'issuer:v7', token_key_id: bindingTwo.identity.token_key_id, blind_signature_b64: blindSignature() });
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = new FreebirdClient({ issuerUrl: 'https://issuer.example' });
    const bindings: string[] = [];

    activeBinding = bindingOne;
    activeDiscovery = discovery(bindingOne.identity.token_key_id);
    const token = await client.issueNativeBearerV7({
      owner_commitment: new Uint8Array(32),
      proofFactory: ({ binding }) => {
        bindings.push(binding);
        return { type: 'proof_of_work', input: binding, nonce: 0, timestamp: 0 };
      },
    });

    expect(token.version).toBe(7);
    expect(bindings).toHaveLength(2);
    expect(bindings[0]).not.toBe(bindings[1]);
    expect((requests[0].sybil_proof as { input: string }).input).toBe(bindings[0]);
    expect((requests[1].sybil_proof as { input: string }).input).toBe(bindings[1]);
  });
});
