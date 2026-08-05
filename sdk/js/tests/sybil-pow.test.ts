// SPDX-License-Identifier: Apache-2.0 OR MIT

import { afterEach, describe, expect, it, vi } from 'vitest';
import { FreebirdClient } from '../src/index.js';
import {
  buildBatchBinding,
  buildIssueBinding,
  buildPublicIssueBinding,
  buildRenewBinding,
  generateProofOfWork,
  verifyPow,
} from '../src/index.js';
import type { SybilProof } from '../src/index.js';

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

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// Fixture-locked against the Rust binding formats:
//   issue.rs:        freebird:issue:v1:<issuer_id>:<blinded_element_b64>
//   public_issue.rs: freebird:public-issue:v1:<issuer_id>:<blinded_msg_b64>
//   issue.rs (renew):freebird:renew:v1:<issuer_id>:<blinded_element_b64>
//   batch_issue.rs:  freebird:<scope>:v1:<issuer_id>:<count>:<b64(sha256(...)[..16])>
const ISSUER_ID = 'issuer:test';
const BLINDED_ELEMENT = 'BAU'; // base64url of [4, 5]
const BLINDED_MSG = 'BAU';
const BATCH_ELEMENTS = ['BAU', 'Cw'];

describe('PoW request bindings (fixture-locked against Rust)', () => {
  it('builds the exact V4 single-issue binding', () => {
    expect(buildIssueBinding(ISSUER_ID, BLINDED_ELEMENT))
      .toBe('freebird:issue:v1:issuer:test:BAU');
  });

  it('builds the exact V5 public single-issue binding', () => {
    expect(buildPublicIssueBinding(ISSUER_ID, BLINDED_MSG))
      .toBe('freebird:public-issue:v1:issuer:test:BAU');
  });

  it('builds the exact renewal binding', () => {
    expect(buildRenewBinding(ISSUER_ID, BLINDED_ELEMENT))
      .toBe('freebird:renew:v1:issuer:test:BAU');
  });

  it('builds the exact batch binding (issue-batch)', () => {
    // Matches batch_request_binding("issue-batch", ...) in batch_issue.rs.
    const binding = buildBatchBinding('issue-batch', ISSUER_ID, BATCH_ELEMENTS);
    expect(binding).toMatch(/^freebird:issue-batch:v1:issuer:test:2:[A-Za-z0-9_-]{22}$/);
    // Deterministic for the same inputs.
    expect(buildBatchBinding('issue-batch', ISSUER_ID, BATCH_ELEMENTS)).toBe(binding);
    // Different element set produces a different digest.
    expect(buildBatchBinding('issue-batch', ISSUER_ID, ['BAU'])).not.toBe(binding);
  });

  it('builds the exact batch binding (public-issue-batch)', () => {
    const binding = buildBatchBinding('public-issue-batch', ISSUER_ID, BATCH_ELEMENTS);
    expect(binding).toMatch(/^freebird:public-issue-batch:v1:issuer:test:2:[A-Za-z0-9_-]{22}$/);
  });
});

describe('PoW mining and verification', () => {
  it('mines a proof_of_work that satisfies the difficulty', async () => {
    const binding = buildIssueBinding(ISSUER_ID, BLINDED_ELEMENT);
    const proof = await generateProofOfWork(binding, 12);
    expect(proof.type).toBe('proof_of_work');
    expect(proof.input).toBe(binding);
    expect(Number.isSafeInteger(proof.nonce)).toBe(true);
    expect(Number.isSafeInteger(proof.timestamp)).toBe(true);
    expect(verifyPow(proof.input, proof.nonce, proof.timestamp, 12)).toBe(true);
    // A stricter difficulty must also pass (the proof has >= 12 leading zeros).
    expect(verifyPow(proof.input, proof.nonce, proof.timestamp, 8)).toBe(true);
  });

  it('rejects a tampered binding (wrong issuer_id)', async () => {
    const proof = await generateProofOfWork(
      buildIssueBinding(ISSUER_ID, BLINDED_ELEMENT),
      10,
    );
    const tampered = buildIssueBinding('issuer:evil', BLINDED_ELEMENT);
    expect(verifyPow(tampered, proof.nonce, proof.timestamp, 10)).toBe(false);
  });

  it('rejects a tampered binding (wrong blinded element)', async () => {
    const proof = await generateProofOfWork(
      buildIssueBinding(ISSUER_ID, BLINDED_ELEMENT),
      10,
    );
    const tampered = buildIssueBinding(ISSUER_ID, 'AAAA');
    expect(verifyPow(tampered, proof.nonce, proof.timestamp, 10)).toBe(false);
  });

  it('rejects a tampered nonce', async () => {
    const proof = await generateProofOfWork(
      buildIssueBinding(ISSUER_ID, BLINDED_ELEMENT),
      10,
    );
    expect(verifyPow(proof.input, proof.nonce + 1, proof.timestamp, 10)).toBe(false);
  });

  it('yields to the event loop during mining (no synchronous block)', async () => {
    let timerFired = false;
    const timer = setTimeout(() => {
      timerFired = true;
    }, 0);
    const proof = await generateProofOfWork(
      buildIssueBinding(ISSUER_ID, BLINDED_ELEMENT),
      14,
      { yieldEvery: 50 },
    );
    clearTimeout(timer);
    // If the mining loop never yielded, the 0ms timer could not have fired
    // before mining completed.
    expect(timerFired).toBe(true);
    expect(verifyPow(proof.input, proof.nonce, proof.timestamp, 14)).toBe(true);
  });
});

describe('PoW integration in issuance', () => {
  it('issueToken with powDifficulty attaches a valid proof_of_work', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({
        issuer_id: 'issuer:test',
        voprf: { suite: 'P256-SHA256', kid: 'kid-1', pubkey: 'public-key' },
      }))
      .mockResolvedValueOnce(json({
        verifier_id: 'verifier:test',
        audience: 'audience:test',
        scope_digest_b64: 'AQID',
      }))
      .mockResolvedValueOnce(json({
        token: 'evaluation',
        kid: 'kid-1',
        issuer_id: 'issuer:test',
      }));
    vi.stubGlobal('fetch', fetchMock);

    const client = new FreebirdClient({
      issuerUrl: 'https://issuer.example',
      verifierUrl: 'https://verifier.example',
      powDifficulty: 8,
    });
    await client.init();
    await client.issueToken();

    const issueCall = fetchMock.mock.calls[2];
    const body = JSON.parse(issueCall[1].body);
    expect(body.sybil_proof.type).toBe('proof_of_work');
    expect(body.sybil_proof.input).toBe(`freebird:issue:v1:issuer:test:${body.blinded_element_b64}`);
    expect(verifyPow(body.sybil_proof.input, body.sybil_proof.nonce, body.sybil_proof.timestamp, 8))
      .toBe(true);
  });

  it('reads pow difficulty from /.well-known/issuer sybil metadata', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({
        issuer_id: 'issuer:test',
        voprf: { suite: 'P256-SHA256', kid: 'kid-1', pubkey: 'public-key' },
        sybil: {
          mode: 'pow',
          mode_description: 'Proof of Work with 10 leading zero bits required',
          settings: { difficulty: 10 },
        },
      }))
      .mockResolvedValueOnce(json({
        verifier_id: 'verifier:test',
        audience: 'audience:test',
        scope_digest_b64: 'AQID',
      }))
      .mockResolvedValueOnce(json({
        token: 'evaluation',
        kid: 'kid-1',
        issuer_id: 'issuer:test',
      }));
    vi.stubGlobal('fetch', fetchMock);

    // No powDifficulty in config: difficulty must come from metadata.
    const client = new FreebirdClient({
      issuerUrl: 'https://issuer.example',
      verifierUrl: 'https://verifier.example',
    });
    await client.init();
    await client.issueToken();

    const issueCall = fetchMock.mock.calls[2];
    const body = JSON.parse(issueCall[1].body);
    expect(body.sybil_proof.type).toBe('proof_of_work');
    expect(verifyPow(body.sybil_proof.input, body.sybil_proof.nonce, body.sybil_proof.timestamp, 10))
      .toBe(true);
  });

  it('does not attach a proof when PoW is not required', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({
        issuer_id: 'issuer:test',
        voprf: { suite: 'P256-SHA256', kid: 'kid-1', pubkey: 'public-key' },
      }))
      .mockResolvedValueOnce(json({
        verifier_id: 'verifier:test',
        audience: 'audience:test',
        scope_digest_b64: 'AQID',
      }))
      .mockResolvedValueOnce(json({
        token: 'evaluation',
        kid: 'kid-1',
        issuer_id: 'issuer:test',
      }));
    vi.stubGlobal('fetch', fetchMock);

    const client = new FreebirdClient({
      issuerUrl: 'https://issuer.example',
      verifierUrl: 'https://verifier.example',
    });
    await client.init();
    await client.issueToken();

    const issueCall = fetchMock.mock.calls[2];
    const body = JSON.parse(issueCall[1].body);
    expect(body.sybil_proof).toBeUndefined();
  });

  it('uses an explicitly provided proof instead of mining', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({
        issuer_id: 'issuer:test',
        voprf: { suite: 'P256-SHA256', kid: 'kid-1', pubkey: 'public-key' },
      }))
      .mockResolvedValueOnce(json({
        verifier_id: 'verifier:test',
        audience: 'audience:test',
        scope_digest_b64: 'AQID',
      }))
      .mockResolvedValueOnce(json({
        token: 'evaluation',
        kid: 'kid-1',
        issuer_id: 'issuer:test',
      }));
    vi.stubGlobal('fetch', fetchMock);

    const client = new FreebirdClient({
      issuerUrl: 'https://issuer.example',
      verifierUrl: 'https://verifier.example',
      powDifficulty: 8,
    });
    await client.init();
    const provided: SybilProof = { type: 'none' };
    await client.issueToken(provided);

    const issueCall = fetchMock.mock.calls[2];
    const body = JSON.parse(issueCall[1].body);
    expect(body.sybil_proof).toEqual(provided);
  });
});
