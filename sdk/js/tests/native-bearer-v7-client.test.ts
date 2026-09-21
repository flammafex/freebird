// SPDX-License-Identifier: Apache-2.0 OR MIT

import { describe, expect, it, vi } from 'vitest';
import type { V7DirectBinding, V7KeyDiscoveryResp } from '../src/types.js';
import { createClientState } from '../src/client/state.js';
import { MemoryTokenStore } from '../src/client/token_store.js';
import { BatchIssuanceInterruptedError, DiscoveryError } from '../src/errors.js';
import { buildNativeBearerV7BatchBinding } from '../src/client/sybil.js';

let currentBinding: V7DirectBinding;
let blindCount = 0;

vi.mock('../src/crypto/native_bearer_v7.js', async () => {
  const actual = await vi.importActual<typeof import('../src/crypto/native_bearer_v7.js')>('../src/crypto/native_bearer_v7.js');
  return {
    ...actual,
    bindingFromV7Discovery: vi.fn(() => currentBinding),
    blindV7: vi.fn(async () => {
      blindCount += 1;
      const blinded = new Uint8Array(384);
      blinded[0] = blindCount;
      return { blinded, randomizer: new Uint8Array(32), state: {} };
    }),
    finalizeV7: vi.fn(async () => ({}) as never),
    serializeV7Token: vi.fn(() => Uint8Array.of(7)),
  };
});

import {
  issueNativeBearerV7,
  issueNativeBearerV7Batch,
} from '../src/client/native_bearer_v7.js';

function binding(key: string): V7DirectBinding {
  return {
    identity: { issuer_id: 'issuer:v7', token_key_id: key, __freebirdV7KeyIdentity: true },
    public_key_spki: new Uint8Array(),
    spki_fingerprint: 'f'.repeat(64),
    asset_id: 'USD',
    amount_minor: 42n,
    valid_from: 1n,
    valid_until: BigInt(Math.floor(Date.now() / 1000) + 3600),
    __freebirdV7DirectBinding: true,
  } as V7DirectBinding;
}

async function metadata(): Promise<V7KeyDiscoveryResp> {
  return {} as V7KeyDiscoveryResp;
}

function signature(): string {
  return Buffer.alloc(384).toString('base64url');
}

function state(
  fetch: typeof globalThis.fetch,
  tokenStore = new MemoryTokenStore(),
  options: { batchBodyLimitBytes?: number } = {},
) {
  return createClientState({ issuerUrl: 'https://issuer.example', fetch, tokenStore, ...options });
}

describe('direct V7 native bearer client orchestration', () => {
  it('issues a caller-bound token and stores version/expiry metadata', async () => {
    currentBinding = binding('a'.repeat(64));
    blindCount = 0;
    const tokenStore = new MemoryTokenStore();
    let posted: Record<string, unknown> | undefined;
    const sdk = state(async (_input, init) => {
      posted = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(JSON.stringify({
        issuer_id: 'issuer:v7', token_key_id: currentBinding.identity.token_key_id,
        blind_signature_b64: signature(),
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }, tokenStore);
    const owner = new Uint8Array(32).fill(9);

    const token = await issueNativeBearerV7(sdk, { owner_commitment: owner }, metadata, metadata);

    expect(posted?.token_key_id).toBe('a'.repeat(64));
    expect(typeof posted?.blinded_msg_b64).toBe('string');
    expect((token as { version: number }).version).toBe(7);
    expect((token as { valid_until: number }).valid_until).toBe(Number(currentBinding.valid_until));
    expect((await tokenStore.list())).toHaveLength(1);
  });

  it('refreshes once and creates a fresh proof bound to the rebuilt request', async () => {
    const first = binding('1'.repeat(64));
    const second = binding('2'.repeat(64));
    currentBinding = first;
    blindCount = 0;
    let refreshes = 0;
    const requests: Record<string, unknown>[] = [];
    const sdk = state(async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      requests.push(body);
      if (requests.length === 1) return new Response('token_key_not_active', { status: 400 });
      return new Response(JSON.stringify({
        issuer_id: 'issuer:v7', token_key_id: second.identity.token_key_id,
        blind_signature_b64: signature(),
      }), { status: 200 });
    });
    const proofs: string[] = [];
    const factory = ({ binding: requestBinding }: { binding: string }) => {
      proofs.push(requestBinding);
      return { type: 'proof_of_work' as const, nonce: 1, input: requestBinding, timestamp: 1 };
    };

    await issueNativeBearerV7(
      sdk,
      { owner_commitment: new Uint8Array(32), proofFactory: factory },
      async () => metadata(),
      async () => { refreshes += 1; currentBinding = second; return metadata(); },
    );

    expect(refreshes).toBe(1);
    expect(proofs).toHaveLength(2);
    expect(proofs[0]).not.toBe(proofs[1]);
    expect((requests[0].sybil_proof as { input: string }).input).toBe(proofs[0]);
    expect((requests[1].sybil_proof as { input: string }).input).toBe(proofs[1]);
    expect(requests[0].token_key_id).toBe(first.identity.token_key_id);
    expect(requests[1].token_key_id).toBe(second.identity.token_key_id);
  });

  it('rejects a response from the wrong issuer', async () => {
    currentBinding = binding('b'.repeat(64));
    const sdk = state(async () => new Response(JSON.stringify({
      issuer_id: 'wrong', token_key_id: currentBinding.identity.token_key_id,
      blind_signature_b64: signature(),
    }), { status: 200 }));

    await expect(issueNativeBearerV7(sdk, { owner_commitment: new Uint8Array(32) }, metadata, metadata))
      .rejects.toBeInstanceOf(DiscoveryError);
  });

  it('preserves ordered batch completion and exposes partial failures', async () => {
    currentBinding = binding('c'.repeat(64));
    blindCount = 0;
    const sdk = state(async () => new Response(JSON.stringify({
      issuer_id: 'issuer:v7', token_key_id: currentBinding.identity.token_key_id,
      blind_signatures_b64: [signature(), signature(), signature()], successful: 3, failed: 0,
    }), { status: 200 }));
    const cryptoModule = await import('../src/crypto/native_bearer_v7.js');
    vi.mocked(cryptoModule.finalizeV7).mockImplementationOnce(async () => ({}) as never)
      .mockImplementationOnce(async () => { throw new Error('bad signature'); });

    await expect(issueNativeBearerV7Batch(sdk, {
      owner_commitments: [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), new Uint8Array(32).fill(3)],
    }, metadata, metadata)).rejects.toMatchObject({
      completed: expect.any(Array),
    });
    try {
      await issueNativeBearerV7Batch(sdk, {
        owner_commitments: [new Uint8Array(32)],
      }, metadata, metadata);
    } catch (error) {
      expect(error).not.toBeInstanceOf(BatchIssuanceInterruptedError);
    }
  });

  it('splits V7 requests by exact serialized UTF-8 body size and binds each chunk', async () => {
    currentBinding = binding('d'.repeat(64));
    blindCount = 0;
    const requests: Record<string, unknown>[] = [];
    const bindings: string[] = [];
    const sdk = state(async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      requests.push(body);
      const count = (body.blinded_msgs_b64 as string[]).length;
      return new Response(JSON.stringify({
        issuer_id: 'issuer:v7', token_key_id: currentBinding.identity.token_key_id,
        blind_signatures_b64: Array.from({ length: count }, () => signature()),
        successful: count, failed: 0,
      }), { status: 200 });
    });
    const ownerCommitments = Array.from({ length: 130 }, (_, index) => new Uint8Array(32).fill(index));
    const factory = ({ binding: requestBinding }: { binding: string }) => {
      bindings.push(requestBinding);
      return { type: 'proof_of_work' as const, nonce: 1, input: requestBinding, timestamp: 1 };
    };

    const issued = await issueNativeBearerV7Batch(sdk, { owner_commitments: ownerCommitments, proofFactory: factory }, metadata, metadata);

    expect(issued).toHaveLength(ownerCommitments.length);
    expect(requests.length).toBeGreaterThan(1);
    for (const request of requests) {
      expect(new TextEncoder().encode(JSON.stringify(request)).byteLength).toBeLessThanOrEqual(60 * 1024);
    }
    expect(requests.map((request) => (request.blinded_msgs_b64 as string[]).length).reduce((a, b) => a + b, 0))
      .toBe(ownerCommitments.length);
    expect(requests.every((request) => {
      const blinded = request.blinded_msgs_b64 as string[];
      const expected = buildNativeBearerV7BatchBinding(currentBinding.identity.issuer_id, currentBinding.identity.token_key_id, blinded);
      return (request.sybil_proof as { input: string }).input === expected;
    })).toBe(true);
    expect(bindings.length).toBeGreaterThanOrEqual(requests.length);
  });

  it('rejects a fixed proof before V7 batch blinding when chunking is required', async () => {
    currentBinding = binding('e'.repeat(64));
    blindCount = 0;
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }));
    const sdk = state(fetchMock);
    const proof = {
      type: 'proof_of_work' as const,
      nonce: 1,
      input: 'not-the-batch-binding',
      timestamp: 1,
    };

    await expect(issueNativeBearerV7Batch(sdk, {
      owner_commitments: Array.from({ length: 130 }, () => new Uint8Array(32)),
      sybilProof: proof,
    }, metadata, metadata)).rejects.toThrow(/chunking is required/);
    expect(blindCount).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('validates a fixed proof against the exact single-chunk binding', async () => {
    currentBinding = binding('f'.repeat(64));
    blindCount = 0;
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }));
    const sdk = state(fetchMock);
    const proof = {
      type: 'proof_of_work' as const,
      nonce: 1,
      input: 'wrong-binding',
      timestamp: 1,
    };

    await expect(issueNativeBearerV7Batch(sdk, {
      owner_commitments: [new Uint8Array(32)],
      sybilProof: proof,
    }, metadata, metadata)).rejects.toThrow(/bound to a different request/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('accepts an exact body limit and rejects one byte below it', async () => {
    currentBinding = binding('6'.repeat(64));
    const blinded = Buffer.alloc(384).toString('base64url');
    const exactLimit = new TextEncoder().encode(JSON.stringify({
      token_key_id: currentBinding.identity.token_key_id,
      blinded_msgs_b64: [blinded],
    })).byteLength;
    const response = JSON.stringify({
      issuer_id: 'issuer:v7', token_key_id: currentBinding.identity.token_key_id,
      blind_signatures_b64: [signature()], successful: 1, failed: 0,
    });
    const exactFetch = vi.fn(async () => new Response(response, { status: 200 }));
    await expect(issueNativeBearerV7Batch(state(exactFetch, undefined, { batchBodyLimitBytes: exactLimit }), {
      owner_commitments: [new Uint8Array(32)],
    }, metadata, metadata)).resolves.toHaveLength(1);

    blindCount = 0;
    const overFetch = vi.fn(async () => new Response(response, { status: 200 }));
    await expect(issueNativeBearerV7Batch(state(overFetch, undefined, { batchBodyLimitBytes: exactLimit - 1 }), {
      owner_commitments: [new Uint8Array(32)],
    }, metadata, metadata)).rejects.toThrow(/exceeds the configured JSON body limit/);
    expect(overFetch).not.toHaveBeenCalled();
  });

  it('wraps a later chunk transport failure with a copy of completed tokens', async () => {
    currentBinding = binding('7'.repeat(64));
    blindCount = 0;
    let requests = 0;
    const sdk = state(async (_input, init) => {
      requests += 1;
      const body = JSON.parse(String(init?.body)) as { blinded_msgs_b64: string[] };
      if (requests > 1) return new Response('transport failed', { status: 503 });
      const count = body.blinded_msgs_b64.length;
      return new Response(JSON.stringify({
        issuer_id: 'issuer:v7', token_key_id: currentBinding.identity.token_key_id,
        blind_signatures_b64: Array.from({ length: count }, () => signature()), successful: count, failed: 0,
      }), { status: 200 });
    });

    await expect(issueNativeBearerV7Batch(sdk, {
      owner_commitments: Array.from({ length: 130 }, () => new Uint8Array(32)),
    }, metadata, metadata)).rejects.toMatchObject({
      name: 'BatchIssuanceInterruptedError',
      completed: expect.any(Array),
      cause: expect.objectContaining({ code: 'issuance' }),
    });
  });
});
