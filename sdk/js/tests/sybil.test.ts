// SPDX-License-Identifier: Apache-2.0 OR MIT

import { afterEach, describe, expect, it, vi } from 'vitest';
import { FreebirdClient } from '../src/index.js';
import type { SybilProof } from '../src/index.js';
import fixtureJson from '../../../common/test-fixtures/sybil-proofs.json' with { type: 'json' };

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

const typedVariants = [
  {
    type: 'proof_of_work',
    nonce: 9007199254740991,
    input: 'freebird:test:proof-of-work',
    timestamp: 1700000000,
  },
  {
    type: 'rate_limit',
    client_id: 'client:test',
    timestamp: 1700000001,
  },
  {
    type: 'invitation',
    code: 'invite-code-test',
    signature: 'invite-signature-test',
  },
  {
    type: 'registered_user',
    user_id: 'user:test',
  },
  {
    type: 'web_authn',
    subject_hash: 'subject-hash-test',
    auth_proof: 'auth-proof-test',
    timestamp: 1700000002,
  },
  {
    type: 'progressive_trust',
    user_id_hash: 'user-hash-progressive-test',
    first_seen: 1690000000,
    tokens_issued: 4294967295,
    last_issuance: 1700000003,
    hmac_proof: 'progressive-hmac-test',
  },
  {
    type: 'proof_of_diversity',
    user_id_hash: 'user-hash-diversity-test',
    diversity_score: 100,
    unique_networks: 4294967295,
    unique_devices: 4294967294,
    first_seen: 1690000001,
    hmac_proof: 'diversity-hmac-test',
  },
  {
    type: 'multi_party_vouching',
    vouchee_id_hash: 'vouchee-hash-test',
    vouches: [
      {
        voucher_id: 'voucher:test',
        vouchee_id: 'vouchee:test',
        timestamp: 1700000004,
        signature: 'vouch-signature-test',
        voucher_pubkey_b64: 'vouch-public-key-test',
      },
    ],
    hmac_proof: 'vouching-hmac-test',
    timestamp: 1700000005,
  },
  {
    type: 'social_graph',
    attestation: '{"contract_version":"sophia/v1","artifact_type":"cred.presentation","artifacts":[{"artifact":{"artifact_type":"social_graph.attestation"}}],"controller_public_key":"controller-key-test","presentation_signature":"presentation-signature-test"}',
    presentation: 'presentation-signature-hex-test',
  },
  {
    type: 'multi',
    proofs: [
      { type: 'none' },
      {
        type: 'rate_limit',
        client_id: 'nested-client:test',
        timestamp: 1700000006,
      },
    ],
  },
  { type: 'none' },
] satisfies readonly SybilProof[];

const fixture = { variants: typedVariants };

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function assertSafeIntegers(value: unknown): void {
  if (typeof value === 'number') {
    expect(Number.isSafeInteger(value)).toBe(true);
  } else if (Array.isArray(value)) {
    value.forEach(assertSafeIntegers);
  } else if (value !== null && typeof value === 'object') {
    Object.values(value).forEach(assertSafeIntegers);
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Sybil proof schema and serialization', () => {
  it('keeps the shared JSON fixture equal to the typed fixture', () => {
    expect(fixtureJson).toStrictEqual(fixture);
  });

  it('covers every Rust SybilProof variant with JSON-safe numbers', () => {
    expect(fixture.variants.map((proof) => proof.type)).toEqual([
      'proof_of_work',
      'rate_limit',
      'invitation',
      'registered_user',
      'web_authn',
      'progressive_trust',
      'proof_of_diversity',
      'multi_party_vouching',
      'social_graph',
      'multi',
      'none',
    ]);
    assertSafeIntegers(fixture);

    const webAuthn = fixture.variants.find((proof) => proof.type === 'web_authn');
    expect(webAuthn).toMatchObject({
      type: 'web_authn',
      subject_hash: 'subject-hash-test',
    });
    expect('username' in (webAuthn ?? {})).toBe(false);
  });

  it('preserves each fixture variant when the SDK serializes an issue request', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({
        issuer_id: 'issuer:test',
        voprf: { suite: 'P256-SHA256', kid: 'kid-1', pubkey: 'public-key' },
      }))
      .mockResolvedValueOnce(json({
        verifier_id: 'verifier:test',
        audience: 'audience:test',
        scope_digest_b64: 'AQID',
      }));
    for (const _proof of fixture.variants) {
      fetchMock.mockResolvedValueOnce(json({
        token: 'evaluation',
        kid: 'kid-1',
        issuer_id: 'issuer:test',
      }));
    }
    vi.stubGlobal('fetch', fetchMock);

    const client = new FreebirdClient({
      issuerUrl: 'https://issuer.example',
      verifierUrl: 'https://verifier.example',
    });
    await client.init();
    for (const proof of fixture.variants) {
      await client.issueToken(proof);
    }

    const issueCalls = fetchMock.mock.calls.slice(2);
    expect(issueCalls).toHaveLength(fixture.variants.length);
    for (const [index, call] of issueCalls.entries()) {
      const body = JSON.parse(call[1].body);
      expect(body.sybil_proof).toEqual(fixture.variants[index]);
      expect(JSON.parse(JSON.stringify(body.sybil_proof))).toEqual(fixture.variants[index]);
    }
  });
});
