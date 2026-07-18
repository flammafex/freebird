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

import { FreebirdClient } from '../src/index.js';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('existing SDK issuance, discovery, and verification APIs', () => {
  it('initializes metadata and completes the existing private issuance flow', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        json({
          issuer_id: 'issuer:test',
          voprf: { suite: 'P256-SHA256', kid: 'kid-1', pubkey: 'public-key' },
        })
      )
      .mockResolvedValueOnce(
        json({
          verifier_id: 'verifier:test',
          audience: 'audience:test',
          scope_digest_b64: 'AQID',
        })
      )
      .mockResolvedValueOnce(
        json({ token: 'evaluation', kid: 'kid-1', issuer_id: 'issuer:test' })
      );
    vi.stubGlobal('fetch', fetchMock);

    const client = new FreebirdClient({
      issuerUrl: 'https://issuer.example',
      verifierUrl: 'https://verifier.example',
    });
    await client.init();
    const token = await client.issueToken();

    expect(token).toEqual({
      tokenValue: 'CQgH',
      issuerId: 'issuer:test',
      version: 4,
      kid: 'kid-1',
    });
    expect(fetchMock.mock.calls.map((call) => call[0])).toEqual([
      'https://issuer.example/.well-known/issuer',
      'https://verifier.example/.well-known/verifier',
      'https://issuer.example/v1/oprf/issue',
    ]);
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toMatchObject({
      blinded_element_b64: 'BAU',
    });
  });

  it('preserves legacy key discovery without exchange metadata', async () => {
    const metadata = {
      issuer_id: 'issuer:legacy',
      current_epoch: 7,
      valid_epochs: [7, 6],
      epoch_duration_sec: 86400,
      voprf: { suite: 'suite', kid: 'kid', pubkey: 'key' },
      public: [],
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(metadata)));

    const discovered = await new FreebirdClient({
      issuerUrl: 'https://issuer.example',
      verifierId: 'verifier:test',
      audience: 'test',
    }).getKeyDiscoveryMetadata();

    expect(discovered).toEqual(metadata);
    expect(discovered.exchange).toBeUndefined();
  });

  it('preserves successful and rejected verifier behavior', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({ ok: true }))
      .mockResolvedValueOnce(json({ error: 'invalid_token' }, 400));
    vi.stubGlobal('fetch', fetchMock);
    const client = new FreebirdClient({
      issuerUrl: 'https://issuer.example',
      verifierUrl: 'https://verifier.example',
    });
    const token = { tokenValue: 'token', issuerId: 'issuer:test' };

    await expect(client.verifyToken(token)).resolves.toBe(true);
    await expect(client.verifyToken(token)).resolves.toBe(false);
    expect(fetchMock).toHaveBeenNthCalledWith(1, 'https://verifier.example/v1/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token_b64: 'token' }),
    });
  });
});
