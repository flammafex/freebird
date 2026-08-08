// SPDX-License-Identifier: Apache-2.0 OR MIT

import { afterEach, describe, expect, it, vi } from 'vitest';
import { FreebirdClient } from '../src/index.js';
import {
  InvalidTokenError,
  RateLimitedError,
  ReplayedTokenError,
  VerificationError,
  VerifierNotConfiguredError,
  VerifierUnavailableError,
} from '../src/index.js';
import type { FreebirdToken } from '../src/index.js';

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function client(config: ConstructorParameters<typeof FreebirdClient>[0] = {
  issuerUrl: 'https://issuer.example',
  verifierUrl: 'https://verifier.example',
}): FreebirdClient {
  return new FreebirdClient(config);
}

const token: FreebirdToken = { tokenValue: 'token-b64', issuerId: 'issuer:test' };

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
  vi.restoreAllMocks();
});

describe('verifyToken', () => {
  it('resolves with the full VerifyResp on success', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ ok: true, verified_at: 123 }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(client().verifyToken(token)).resolves.toEqual({ ok: true, verified_at: 123 });
    expect(fetchMock).toHaveBeenCalledWith('https://verifier.example/v1/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token_b64: 'token-b64' }),
    });
  });

  it('throws InvalidTokenError on 400', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ error: 'verification_failed' }, 400)));
    await expect(client().verifyToken(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('throws ReplayedTokenError only for the exact replay response on /v1/verify', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      json({ ok: false, error: 'replay_detected', verified_at: 0 }, 401),
    ));
    await expect(client().verifyToken(token)).rejects.toBeInstanceOf(ReplayedTokenError);
  });

  it('throws InvalidTokenError for an invalid-signature-like 401', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ error: 'verification_failed' }, 401)));
    await expect(client().verifyToken(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('throws InvalidTokenError for an untrusted or unknown issuer 401', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ error: 'unknown_issuer' }, 401)));
    await expect(client().verifyToken(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('throws RateLimitedError on 429 and parses Retry-After', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({}, 429, { 'Retry-After': '30' })));
    const err = await client().verifyToken(token).catch((e) => e);
    expect(err).toBeInstanceOf(RateLimitedError);
    expect((err as RateLimitedError).retryAfter).toBe(30);
  });

  it('defaults retryAfter to 0 when Retry-After is absent', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({}, 429)));
    const err = await client().verifyToken(token).catch((e) => e);
    expect(err).toBeInstanceOf(RateLimitedError);
    expect((err as RateLimitedError).retryAfter).toBe(0);
  });

  it('throws VerifierUnavailableError on 503', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('down', { status: 503 })));
    await expect(client().verifyToken(token)).rejects.toBeInstanceOf(VerifierUnavailableError);
  });

  it('throws a generic VerificationError on other non-2xx statuses', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('oops', { status: 500 })));
    await expect(client().verifyToken(token)).rejects.toBeInstanceOf(VerificationError);
  });

  it('throws VerifierNotConfiguredError when verifierUrl is unset', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(client({ issuerUrl: 'https://issuer.example' }).verifyToken(token))
      .rejects.toBeInstanceOf(VerifierNotConfiguredError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('does not leak server error bodies into the message', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ error: 'secret-internal-detail' }, 400)));
    const err = await client().verifyToken(token).catch((e) => e);
    expect(err.message).not.toContain('secret-internal-detail');
  });
});

describe('verifyTokenValid (boolean convenience)', () => {
  it('returns true on success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ ok: true, verified_at: 1 })));
    await expect(client().verifyTokenValid(token)).resolves.toBe(true);
  });

  it('returns false for invalid and replayed tokens', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({}, 400))
      .mockResolvedValueOnce(json({}, 401));
    vi.stubGlobal('fetch', fetchMock);
    await expect(client().verifyTokenValid(token)).resolves.toBe(false);
    await expect(client().verifyTokenValid(token)).resolves.toBe(false);
  });

  it('rethrows infrastructure errors (503, 429, not configured)', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('down', { status: 503 }))
      .mockResolvedValueOnce(json({}, 429, { 'Retry-After': '5' }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(client().verifyTokenValid(token)).rejects.toBeInstanceOf(VerifierUnavailableError);
    await expect(client().verifyTokenValid(token)).rejects.toBeInstanceOf(RateLimitedError);
    await expect(client({ issuerUrl: 'https://issuer.example' }).verifyTokenValid(token))
      .rejects.toBeInstanceOf(VerifierNotConfiguredError);
  });
});

describe('checkToken', () => {
  it('hits /v1/check (not /v1/verify) and does not consume', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ ok: true, verified_at: 7 }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(client().checkToken(token)).resolves.toEqual({ ok: true, verified_at: 7 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith('https://verifier.example/v1/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token_b64: 'token-b64' }),
    });
  });

  it('throws typed errors on failure', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({}, 400))
      .mockResolvedValueOnce(json({}, 503));
    vi.stubGlobal('fetch', fetchMock);
    await expect(client().checkToken(token)).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(client().checkToken(token)).rejects.toBeInstanceOf(VerifierUnavailableError);
  });

  it('throws InvalidTokenError for a /v1/check 401', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ error: 'replay_detected' }, 401)));
    await expect(client().checkToken(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('throws VerifierNotConfiguredError when verifierUrl is unset', async () => {
    vi.stubGlobal('fetch', vi.fn());
    await expect(client({ issuerUrl: 'https://issuer.example' }).checkToken(token))
      .rejects.toBeInstanceOf(VerifierNotConfiguredError);
  });
});

describe('verifyBatch', () => {
  const batchResp = {
    results: [
      { status: 'success', verified_at: 1 },
      { status: 'error', message: 'token already used', code: 'replay_detected' },
      { status: 'error', message: 'verification failed', code: 'verification_failed' },
    ],
    successful: 1,
    failed: 2,
    processing_time_ms: 3,
    throughput: 0.33,
  };

  it('posts the exact batch body and returns the full response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(batchResp));
    vi.stubGlobal('fetch', fetchMock);

    const tokens = [
      { tokenValue: 'a', issuerId: 'issuer:test' },
      { tokenValue: 'b', issuerId: 'issuer:test' },
      { tokenValue: 'c', issuerId: 'issuer:test' },
    ];
    await expect(client().verifyBatch(tokens)).resolves.toEqual(batchResp);
    expect(fetchMock).toHaveBeenCalledWith('https://verifier.example/v1/verify/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tokens: [{ token_b64: 'a' }, { token_b64: 'b' }, { token_b64: 'c' }] }),
    });
  });

  it('maps per-token replay_detected codes', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(batchResp)));
    const resp = await client().verifyBatch([token, token, token]);
    expect(resp.results[1]).toMatchObject({ status: 'error', code: 'replay_detected' });
    expect(resp.results[2]).toMatchObject({ status: 'error', code: 'verification_failed' });
    expect(resp.results[0]).toMatchObject({ status: 'success' });
    expect(resp.failed).toBe(2);
    expect(resp.successful).toBe(1);
  });

  it('throws typed errors on a non-2xx batch response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('down', { status: 503 })));
    await expect(client().verifyBatch([token])).rejects.toBeInstanceOf(VerifierUnavailableError);
  });

  it('throws VerifierNotConfiguredError when verifierUrl is unset', async () => {
    vi.stubGlobal('fetch', vi.fn());
    await expect(client({ issuerUrl: 'https://issuer.example' }).verifyBatch([token]))
      .rejects.toBeInstanceOf(VerifierNotConfiguredError);
  });
});
