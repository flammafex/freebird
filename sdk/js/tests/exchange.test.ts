import { afterEach, describe, expect, it, vi } from 'vitest';
import { FreebirdClient } from '../src/index.js';
import type {
  ExchangeReceiptKeyInfo,
  ExchangeRequest,
  ExchangeSuccessResponse,
  KeyDiscoveryMetadata,
} from '../src/index.js';

const operationId = 'AAAAAAAAAAAAAAAAAAAAAA'; // canonical base64url for 16 zero bytes
const otherOperationId = 'AQEBAQEBAQEBAQEBAQEBAQ';
const base64Zeros = (length: number): string =>
  btoa(String.fromCharCode(...new Uint8Array(length)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
const resultDigest = base64Zeros(32);
const targetKeysetId = 'b'.repeat(64);
const firstSlot = {
  descriptor_id: 'a'.repeat(64),
  keyset_id: targetKeysetId,
  slot_id: 'out-1',
  quantity: 1,
};
const secondSlot = {
  descriptor_id: 'e'.repeat(64),
  keyset_id: targetKeysetId,
  slot_id: 'out-2',
  quantity: 2,
};
const request: ExchangeRequest = {
  profile: 'freebird/public-bearer-exchange/v1',
  rule_id: 'c'.repeat(64),
  sources: [{ slot: { ...firstSlot, slot_id: 'in' }, artifact: 'c291cmNl' }],
  outputs: [
    { slot: firstSlot, blinded_value: base64Zeros(256) },
    { slot: secondSlot, blinded_value: base64Zeros(255) },
  ],
};
const successResponse: ExchangeSuccessResponse = {
  result: {
    operation_id: operationId,
    profile: request.profile,
    target_keyset_id: targetKeysetId,
    outputs: request.outputs.map((output) => ({
      slot: { ...output.slot },
      blinded_value: output.blinded_value,
      blind_signature: base64Zeros(256),
    })),
    result_digest: resultDigest,
  },
  receipt: {
    operation_id: operationId,
    profile: request.profile,
    target_keyset_id: targetKeysetId,
    result_digest: resultDigest,
    created_at: 10,
    expires_at: 20,
    receipt_key_id: 'd'.repeat(64),
    signature: base64Zeros(64),
  },
};
const successBody = JSON.stringify(successResponse);

function response(body: string, status: number, extraHeaders: Record<string, string> = {}): Response {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...extraHeaders,
    },
  });
}

function client(): FreebirdClient {
  return new FreebirdClient({
    issuerUrl: 'https://issuer.example',
    verifierId: 'verifier:test',
    audience: 'test',
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('public bearer exchange client', () => {
  it('posts the exact request with one capability header and preserves response text', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response(successBody, 200));
    vi.stubGlobal('fetch', fetchMock);

    const outcome = await client().exchange(request, operationId);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith('https://issuer.example/v1/public/exchange', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': operationId,
      },
      body: JSON.stringify(request),
    });
    expect(outcome.kind).toBe('committed');
    expect(outcome.cacheControl).toBe('no-store');
    expect(outcome.rawResponseBody).toBe(successBody);
    if (outcome.kind === 'committed') {
      expect(outcome.response.result.outputs[0].blind_signature).toBe(base64Zeros(256));
      expect(outcome.response.receipt.receipt_key_id).toBe('d'.repeat(64));
    }
  });

  it('uses the fixed status URL and keeps the capability out of URL and query', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      response('{"error":"exchange_retryable"}', 202, { 'Retry-After': '1' })
    );
    vi.stubGlobal('fetch', fetchMock);

    const outcome = await client().getExchangeStatus(operationId, request);

    expect(fetchMock).toHaveBeenCalledWith('https://issuer.example/v1/public/exchange/status', {
      method: 'GET',
      headers: { 'Idempotency-Key': operationId },
    });
    expect(fetchMock.mock.calls[0][0]).not.toContain(operationId);
    expect(outcome).toMatchObject({
      kind: 'pending',
      httpStatus: 202,
      retryAfter: 1,
      response: { error: 'exchange_retryable' },
      cacheControl: 'no-store',
    });
  });

  it.each([
    [400, 'invalid_exchange_request'],
    [400, 'invalid_exchange'],
    [409, 'operation_conflict'],
    [503, 'exchange_unavailable'],
  ] as const)('models HTTP %i %s as a generic exchange error', async (status, code) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(JSON.stringify({ error: code }), status)));

    const outcome = await client().exchange(request, operationId);

    expect(outcome).toMatchObject({
      kind: 'error',
      httpStatus: status,
      response: { error: code },
    });
  });

  it('models unknown status and rejects malformed endpoint errors', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(response('{"error":"unknown_operation"}', 404))
      .mockResolvedValueOnce(response('{"message":"operation_conflict"}', 409));
    vi.stubGlobal('fetch', fetchMock);

    await expect(client().getExchangeStatus(operationId, request)).resolves.toMatchObject({
      kind: 'error',
      response: { error: 'unknown_operation' },
    });
    await expect(client().exchange(request, operationId)).rejects.toThrow(
      'Exchange endpoint returned malformed error JSON'
    );
  });

  it('rejects missing no-store and malformed pending responses', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response('{"error":"exchange_retryable"}', {
          status: 202,
          headers: { 'Retry-After': '1' },
        })
      )
      .mockResolvedValueOnce(response('{"error":"exchange_retryable"}', 202));
    vi.stubGlobal('fetch', fetchMock);

    await expect(client().exchange(request, operationId)).rejects.toThrow('Cache-Control: no-store');
    await expect(client().exchange(request, operationId)).rejects.toThrow('invalid Retry-After');
  });

  it.each([
    ['result operation ID', (body: ExchangeSuccessResponse) => { body.result.operation_id = otherOperationId; }],
    ['result operation ID encoding', (body: ExchangeSuccessResponse) => { body.result.operation_id = `${operationId}==`; }],
    ['receipt operation ID', (body: ExchangeSuccessResponse) => { body.receipt.operation_id = otherOperationId; }],
    ['result profile', (body: ExchangeSuccessResponse) => { body.result.profile = 'wrong'; }],
    ['receipt profile', (body: ExchangeSuccessResponse) => { body.receipt.profile = 'wrong'; }],
    ['target keyset agreement', (body: ExchangeSuccessResponse) => { body.receipt.target_keyset_id = 'c'.repeat(64); }],
    ['canonical target keyset', (body: ExchangeSuccessResponse) => { body.result.target_keyset_id = 'B'.repeat(64); }],
    ['result digest agreement', (body: ExchangeSuccessResponse) => { body.receipt.result_digest = base64Zeros(32).replace(/^A/, 'A'); body.result.result_digest = base64Zeros(32).replace(/^A/, 'B'); }],
    ['canonical result digest', (body: ExchangeSuccessResponse) => { body.result.result_digest = 'digest'; }],
    ['ordered output slots', (body: ExchangeSuccessResponse) => { body.result.outputs.reverse(); }],
    ['output descriptor', (body: ExchangeSuccessResponse) => { body.result.outputs[0].slot.descriptor_id = 'f'.repeat(64); }],
    ['output keyset', (body: ExchangeSuccessResponse) => { body.result.outputs[0].slot.keyset_id = 'c'.repeat(64); }],
    ['output quantity', (body: ExchangeSuccessResponse) => { body.result.outputs[0].slot.quantity = 2; }],
    ['output slot ID', (body: ExchangeSuccessResponse) => { body.result.outputs[0].slot.slot_id = 'other'; }],
    ['bound output blinded value', (body: ExchangeSuccessResponse) => { body.result.outputs[0].blinded_value = 'AQ'; }],
    ['output blinded value', (body: ExchangeSuccessResponse) => { body.result.outputs[0].blinded_value = 'AA='; }],
    ['blind signature encoding', (body: ExchangeSuccessResponse) => { body.result.outputs[0].blind_signature = 'not+base64url'; }],
    ['receipt key ID', (body: ExchangeSuccessResponse) => { body.receipt.receipt_key_id = 'D'.repeat(64); }],
    ['receipt signature', (body: ExchangeSuccessResponse) => { body.receipt.signature = base64Zeros(63); }],
  ] as const)('rejects committed response mismatch: %s', async (_name, mutate) => {
    const body = structuredClone(successResponse);
    mutate(body);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(JSON.stringify(body), 200)));

    await expect(client().exchange(request, operationId)).rejects.toThrow(
      'malformed success JSON'
    );
  });

  it.each([
    '',
    'AAAAAAAAAAAAAAAAAAAA', // 15 bytes
    'AAAAAAAAAAAAAAAAAAAAAA==',
    'AAAAAAAAAAAAAAAAAAAAA+',
    'AAAAAAAAAAAAAAAAAAAAAB', // nonzero trailing base64 pad bits
    'aaaaaaaaaaaaaaaaaaaaaaa',
  ])('rejects a non-canonical operation capability before fetch: %s', async (invalid) => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    await expect(client().exchange(request, invalid)).rejects.toThrow(
      'canonical base64url for exactly 16 bytes'
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('exchange discovery typing', () => {
  it('types receipt verification metadata and remains compatible with legacy discovery', async () => {
    const receiptKey: ExchangeReceiptKeyInfo = {
      key_id: 'd'.repeat(64),
      algorithm: 'Ed25519',
      purpose: 'exchange_receipt_retained',
      public_key_b64: 'a2V5',
      valid_from: 10,
      valid_until: 20,
    };
    const exchangeMetadata: KeyDiscoveryMetadata = {
      issuer_id: 'issuer:test',
      current_epoch: 1,
      valid_epochs: [1],
      epoch_duration_sec: 86400,
      voprf: { suite: 'suite', kid: 'kid', pubkey: 'key' },
      public: [],
      exchange: {
        profile_id: 'freebird/public-bearer-exchange/v1',
        target_keysets: [],
        descriptors: [],
        receipt_keys: [receiptKey],
      },
    };
    expect(exchangeMetadata.exchange?.receipt_keys[0].algorithm).toBe('Ed25519');

    const legacyMetadata: KeyDiscoveryMetadata = {
      issuer_id: 'issuer:legacy',
      current_epoch: 1,
      valid_epochs: [1],
      epoch_duration_sec: 86400,
      voprf: { suite: 'suite', kid: 'kid', pubkey: 'key' },
      public: [],
    };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        response(JSON.stringify(legacyMetadata), 200)
      )
    );
    const discovered = await client().getKeyDiscoveryMetadata();
    expect(discovered.exchange).toBeUndefined();
    expect(discovered.issuer_id).toBe('issuer:legacy');
  });
});
