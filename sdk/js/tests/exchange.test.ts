import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { FreebirdClient } from '../src/index.js';
import type {
  ExchangeRequest,
  ExchangeSuccessResponse,
  KeyDiscoveryMetadata,
} from '../src/index.js';

const b64 = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const ascii = (value: string): Uint8Array => new TextEncoder().encode(value);
const concat = (...values: Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) { output.set(value, offset); offset += value.length; }
  return output;
};
const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
const domainHex = (domain: string, bytes: Uint8Array): string => hex(sha256(concat(ascii(domain), bytes)));
const domainB64 = (domain: string, bytes: Uint8Array): string => b64(sha256(concat(ascii(domain), bytes)));
const u32 = (value: number): number[] => [value >>> 24, value >>> 16, value >>> 8, value].map((x) => x & 255);
const u64 = (value: number): number[] => {
  let integer = BigInt(value);
  const output = Array<number>(8);
  for (let index = 7; index >= 0; index--) { output[index] = Number(integer & 255n); integer >>= 8n; }
  return output;
};
const put = (output: number[], value: Uint8Array): void => { output.push(...u32(value.length), ...value); };
const slotBytes = (slot: { descriptor_id: string; keyset_id: string; slot_id: string; quantity: number }): number[] => {
  const output: number[] = [];
  put(output, ascii(slot.descriptor_id)); put(output, ascii(slot.keyset_id)); put(output, ascii(slot.slot_id));
  output.push(...u32(slot.quantity));
  return output;
};
const selectorBytes = (value: ExchangeRequest): number[] => {
  const output = [2];
  put(output, fromB64(value.public_operation_id));
  for (const field of [value.graph_id, value.transition_id, value.source_keyset_id, value.target_keyset_id]) {
    put(output, ascii(field));
  }
  return output;
};
const fromB64 = (value: string): Uint8Array => {
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '='));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

const operationId = b64(new Uint8Array(16));
const otherOperationId = b64(new Uint8Array(16).fill(1));
const statusCapability = b64(new Uint8Array(32).fill(7));
const otherCapability = b64(new Uint8Array(32).fill(8));
const receiptSecret = new Uint8Array(32).fill(9);

interface Fixture {
  metadata: KeyDiscoveryMetadata;
  request: ExchangeRequest;
  success: ExchangeSuccessResponse;
}

let fixture: Fixture;

async function rsaSpki(): Promise<Uint8Array> {
  const pair = await crypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-384' },
    true,
    ['sign', 'verify']
  );
  const standard = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const raw = standard.slice(24);
  const template = new Uint8Array([
    0x30, 0x82, 0, 0, 0x30, 61, 0x06, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    1, 1, 0x0a, 0x30, 48, 0xa0, 13, 0x30, 11, 0x06, 9, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0xa1, 26, 0x30, 24, 0x06, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1,
    8, 0x30, 11, 0x06, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa2, 3, 0x02, 1, 0,
    0x03, 0x82, 0, 0, 0,
  ]);
  const writeU16 = (offset: number, value: number) => {
    template[offset] = value >>> 8;
    template[offset + 1] = value & 255;
  };
  writeU16(2, template.length - 4 + raw.length);
  writeU16(69, 1 + raw.length);
  template[66] = 48;
  const sha384Oid = [0x30, 11, 0x06, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 2];
  template.set(sha384Oid, 21);
  template.set(sha384Oid, 49);
  return concat(template, raw);
}

function descriptor(spki: Uint8Array, issuerId: string) {
  const tokenKeyId = hex(sha256(spki));
  const value = {
    descriptor_id: '',
    profile_id: 'freebird/public-bearer-exchange/v2' as const,
    issuer_id: issuerId,
    token_key_id: tokenKeyId,
    pubkey_spki_b64: b64(spki),
    suite: 'RSABSSA-SHA384-PSS-Deterministic',
    valid_from: 1,
    valid_until: 4_000_000_000,
  };
  const bytes: number[] = [];
  for (const field of [value.profile_id, value.issuer_id, value.token_key_id, value.suite]) put(bytes, ascii(field));
  bytes.push(0); put(bytes, new Uint8Array()); put(bytes, spki); bytes.push(...u64(value.valid_from), ...u64(value.valid_until));
  value.descriptor_id = domainHex('freebird exchange descriptor v2\0', new Uint8Array(bytes));
  return value;
}

beforeAll(async () => {
  const issuerId = 'issuer:test';
  const [sourceDescriptor, targetDescriptor] = await Promise.all([
    rsaSpki().then((key) => descriptor(key, issuerId)),
    rsaSpki().then((key) => descriptor(key, issuerId)),
  ]);
  const keyset = (descriptorId: string) => {
    const bytes: number[] = []; put(bytes, ascii(descriptorId));
    return { keyset_id: domainHex('freebird exchange keyset v2\0', new Uint8Array(bytes)), descriptor_ids: [descriptorId] };
  };
  const sourceKeyset = keyset(sourceDescriptor.descriptor_id);
  const targetKeyset = keyset(targetDescriptor.descriptor_id);
  const transition = {
    transition_id: '',
    source_keyset_id: sourceKeyset.keyset_id,
    target_keyset_id: targetKeyset.keyset_id,
    source_slots: [{ descriptor_id: sourceDescriptor.descriptor_id, slot_id: 'source-0', class: 'source', quantity: 1 }],
    output_slots: [{ descriptor_id: targetDescriptor.descriptor_id, slot_id: 'output-0', class: 'target', quantity: 2 }],
    budget_id: 'budget-1',
    budget_limit: 10,
    admission_state: 'accepting_new' as const,
  };
  const transitionBytes: number[] = [];
  put(transitionBytes, ascii(transition.source_keyset_id)); put(transitionBytes, ascii(transition.target_keyset_id));
  for (const slots of [transition.source_slots, transition.output_slots]) {
    transitionBytes.push(...u32(slots.length));
    for (const slot of slots) {
      put(transitionBytes, ascii(slot.descriptor_id)); put(transitionBytes, ascii(slot.slot_id));
      put(transitionBytes, ascii(slot.class)); transitionBytes.push(...u32(slot.quantity));
    }
  }
  put(transitionBytes, ascii(transition.budget_id)); transitionBytes.push(...u64(transition.budget_limit));
  transition.transition_id = domainHex('freebird exchange transition v2\0', new Uint8Array(transitionBytes));
  const graph = {
    profile_id: 'freebird/public-bearer-exchange/v2' as const,
    graph_id: '',
    descriptors: [sourceDescriptor, targetDescriptor],
    keysets: [sourceKeyset, targetKeyset],
    transitions: [transition],
  };
  const graphBytes: number[] = []; put(graphBytes, ascii(graph.profile_id));
  for (const value of graph.keysets) put(graphBytes, ascii(value.keyset_id));
  put(graphBytes, ascii(transition.transition_id));
  graph.graph_id = domainHex('freebird exchange graph v2\0', new Uint8Array(graphBytes));
  const receiptPublic = ed25519.getPublicKey(receiptSecret);
  const receiptKeyId = hex(sha256(receiptPublic));
  const metadata: KeyDiscoveryMetadata = {
    issuer_id: issuerId,
    current_epoch: 1,
    valid_epochs: [1],
    epoch_duration_sec: 86_400,
    voprf: { suite: 'suite', kid: 'kid', pubkey: 'key' },
    public: [],
    exchange: {
      active_graph: graph,
      retained_graphs: [],
      active_receipt_key: {
        key_id: receiptKeyId,
        algorithm: 'Ed25519',
        purpose: 'exchange_receipt_active',
        public_key_b64: b64(receiptPublic),
        valid_from: 1,
        valid_until: 4_000_000_000,
      },
      retained_receipt_keys: [],
    },
  };
  const request: ExchangeRequest = {
    version: 2,
    public_operation_id: operationId,
    graph_id: graph.graph_id,
    transition_id: transition.transition_id,
    source_keyset_id: sourceKeyset.keyset_id,
    target_keyset_id: targetKeyset.keyset_id,
    sources: [{
      slot: { descriptor_id: sourceDescriptor.descriptor_id, keyset_id: sourceKeyset.keyset_id, slot_id: 'source-0', quantity: 1 },
      artifact: b64(ascii('source artifact')),
    }],
    outputs: [{
      slot: { descriptor_id: targetDescriptor.descriptor_id, keyset_id: targetKeyset.keyset_id, slot_id: 'output-0', quantity: 2 },
      blinded_value: b64(ascii('blinded output')),
    }],
  };
  const result: ExchangeSuccessResponse['result'] = {
    version: 2,
    public_operation_id: operationId,
    graph_id: graph.graph_id,
    transition_id: transition.transition_id,
    source_keyset_id: sourceKeyset.keyset_id,
    target_keyset_id: targetKeyset.keyset_id,
    outputs: request.outputs.map((output) => ({ ...structuredClone(output), blind_signature: b64(ascii('blind signature')) })),
    result_digest: '',
  };
  const resultBytes = selectorBytes(request); resultBytes.push(...u32(result.outputs.length));
  for (const output of result.outputs) {
    resultBytes.push(...slotBytes(output.slot)); put(resultBytes, fromB64(output.blinded_value));
    put(resultBytes, fromB64(output.blind_signature));
  }
  result.result_digest = domainB64('freebird exchange result v2\0', new Uint8Array(resultBytes));
  const receipt: ExchangeSuccessResponse['receipt'] = {
    version: 2,
    public_operation_id: operationId,
    graph_id: graph.graph_id,
    transition_id: transition.transition_id,
    source_keyset_id: sourceKeyset.keyset_id,
    target_keyset_id: targetKeyset.keyset_id,
    result_digest: result.result_digest,
    created_at: 10,
    expires_at: 20,
    receipt_key_id: receiptKeyId,
    signature: '',
  };
  const receiptBytes = selectorBytes(request); put(receiptBytes, fromB64(receipt.result_digest));
  receiptBytes.push(...u64(receipt.created_at), ...u64(receipt.expires_at)); put(receiptBytes, ascii(receipt.receipt_key_id));
  receipt.signature = b64(ed25519.sign(sha256(concat(ascii('freebird exchange receipt v2\0'), new Uint8Array(receiptBytes))), receiptSecret));
  fixture = { metadata, request, success: { result, receipt } };
});

function response(body: string, status: number, headers: Record<string, string> = {}): Response {
  return new Response(body, { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers } });
}
function client(): FreebirdClient {
  return new FreebirdClient({ issuerUrl: 'https://issuer.example', verifierId: 'verifier:test', audience: 'test' });
}
function exchangeFetch(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return vi.fn()
    .mockResolvedValueOnce(response(JSON.stringify(fixture.metadata), 200))
    .mockResolvedValueOnce(response(typeof body === 'string' ? body : JSON.stringify(body), status, headers));
}

afterEach(() => vi.unstubAllGlobals());

describe('V2 public bearer exchange client', () => {
  it('validates discovery, selects an explicit transition, and completes a bound graph flow', async () => {
    const fetchMock = exchangeFetch(fixture.success);
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();
    const selection = await sdk.selectExchangeTransition(fixture.request.graph_id, fixture.request.transition_id);
    expect(selection.transition.source_keyset_id).toBe(fixture.request.source_keyset_id);
    const outcome = await sdk.exchange(fixture.request, statusCapability);
    expect(fetchMock).toHaveBeenLastCalledWith('https://issuer.example/v2/public/exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'exchange-status-capability': statusCapability },
      body: JSON.stringify(fixture.request),
    });
    expect(outcome).toMatchObject({ kind: 'committed', response: fixture.success, cacheControl: 'no-store' });
  });

  it('matches the frozen Rust V2 request digest vector', () => {
    const vector: ExchangeRequest = {
      version: 2, public_operation_id: 'BwcHBwcHBwcHBwcHBwcHBw', graph_id: '3'.repeat(64),
      transition_id: '4'.repeat(64), source_keyset_id: '1'.repeat(64), target_keyset_id: '2'.repeat(64),
      sources: [{ slot: { descriptor_id: 'a'.repeat(64), keyset_id: '1'.repeat(64), slot_id: 'source-0', quantity: 1 }, artifact: b64(ascii('source artifact')) }],
      outputs: [{ slot: { descriptor_id: 'b'.repeat(64), keyset_id: '2'.repeat(64), slot_id: 'output-0', quantity: 2 }, blinded_value: b64(ascii('blinded output')) }],
    };
    expect(client().exchangeRequestDigest(vector)).toBe('IBYktiUpR2qjh5APuO2X38WRFbC4zm-ng3Q4dYV21wo');
  });

  it('uses the public operation query and keeps the 32-byte capability header-only', async () => {
    const fetchMock = exchangeFetch('{"error":"exchange_retryable"}', 202, { 'Retry-After': '1' });
    vi.stubGlobal('fetch', fetchMock);
    const outcome = await client().getExchangeStatus(operationId, statusCapability, fixture.request);
    expect(fetchMock).toHaveBeenLastCalledWith(
      `https://issuer.example/v2/public/exchange/status?public_operation_id=${operationId}`,
      { method: 'GET', headers: { 'exchange-status-capability': statusCapability } }
    );
    expect(fetchMock.mock.calls[1][0]).not.toContain(statusCapability);
    expect(outcome).toMatchObject({ kind: 'pending', retryAfter: 1 });
  });

  it.each([
    [400, 'invalid_status_capability'], [400, 'invalid_public_operation_id'],
    [400, 'invalid_exchange_request'], [400, 'invalid_exchange'],
    [409, 'operation_conflict'], [413, 'exchange_request_too_large'], [503, 'exchange_unavailable'],
  ] as const)('models HTTP %i %s', async (status, code) => {
    vi.stubGlobal('fetch', exchangeFetch({ error: code }, status));
    await expect(client().exchange(fixture.request, statusCapability)).resolves.toMatchObject({
      kind: 'error', httpStatus: status, response: { error: code },
    });
  });

  it('rejects unauthorized status instead of exposing it as an ordinary outcome', async () => {
    vi.stubGlobal('fetch', exchangeFetch({ error: 'status_unauthorized' }, 403));
    await expect(client().getExchangeStatus(operationId, otherCapability, fixture.request))
      .rejects.toThrow('not authorized');
  });

  it('rejects malformed endpoint responses and cache controls', async () => {
    const sdk = client();
    const malformed = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(fixture.metadata), 200))
      .mockResolvedValueOnce(response('{', 200));
    vi.stubGlobal('fetch', malformed);
    await expect(sdk.exchange(fixture.request, statusCapability)).rejects.toThrow('malformed JSON');

    const noStore = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(fixture.metadata), 200))
      .mockResolvedValueOnce(new Response(JSON.stringify(fixture.success), { status: 200 }));
    vi.stubGlobal('fetch', noStore);
    await expect(client().exchange(fixture.request, statusCapability)).rejects.toThrow('Cache-Control: no-store');
  });

  it.each([
    ['graph', (body: ExchangeSuccessResponse) => { body.result.graph_id = 'a'.repeat(64); }],
    ['transition', (body: ExchangeSuccessResponse) => { body.result.transition_id = 'a'.repeat(64); }],
    ['source keyset', (body: ExchangeSuccessResponse) => { body.result.source_keyset_id = 'a'.repeat(64); }],
    ['target keyset', (body: ExchangeSuccessResponse) => { body.receipt.target_keyset_id = 'a'.repeat(64); }],
    ['operation', (body: ExchangeSuccessResponse) => { body.result.public_operation_id = otherOperationId; }],
    ['output', (body: ExchangeSuccessResponse) => { body.result.outputs[0].blinded_value = b64(ascii('altered')); }],
    ['result digest', (body: ExchangeSuccessResponse) => { body.result.result_digest = b64(new Uint8Array(32)); }],
    ['receipt time', (body: ExchangeSuccessResponse) => { body.receipt.expires_at++; }],
    ['receipt key', (body: ExchangeSuccessResponse) => { body.receipt.receipt_key_id = 'a'.repeat(64); }],
    ['receipt signature', (body: ExchangeSuccessResponse) => { body.receipt.signature = b64(new Uint8Array(64)); }],
  ] as const)('rejects tampered committed %s binding', async (_name, mutate) => {
    const body = structuredClone(fixture.success); mutate(body);
    vi.stubGlobal('fetch', exchangeFetch(body));
    await expect(client().exchange(fixture.request, statusCapability)).rejects.toThrow('malformed success JSON');
  });

  it('rejects capabilities anywhere in a success response or receipt', async () => {
    for (const mutate of [
      (body: any) => { body.status_capability = statusCapability; },
      (body: any) => { body.result.status_capability = statusCapability; },
      (body: any) => { body.receipt.exchange_status_capability = statusCapability; },
    ]) {
      const body: any = structuredClone(fixture.success); mutate(body);
      vi.stubGlobal('fetch', exchangeFetch(body));
      await expect(client().exchange(fixture.request, statusCapability)).rejects.toThrow('malformed success JSON');
    }
  });

  it.each(['', operationId, `${statusCapability}=`, `${statusCapability.slice(0, -1)}+`])(
    'rejects malformed status capability before fetch: %s', async (capability) => {
      const fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock);
      await expect(client().exchange(fixture.request, capability)).rejects.toThrow('exactly 32 bytes');
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  it('rejects request selector and transition tampering before exchange POST', async () => {
    for (const mutate of [
      (request: ExchangeRequest) => { request.graph_id = 'a'.repeat(64); },
      (request: ExchangeRequest) => { request.transition_id = 'a'.repeat(64); },
      (request: ExchangeRequest) => { request.target_keyset_id = request.source_keyset_id; request.outputs[0].slot.keyset_id = request.source_keyset_id; },
      (request: ExchangeRequest) => { request.outputs[0].slot.quantity++; },
    ]) {
      const request = structuredClone(fixture.request); mutate(request);
      const fetchMock = vi.fn().mockResolvedValue(response(JSON.stringify(fixture.metadata), 200));
      vi.stubGlobal('fetch', fetchMock);
      await expect(client().exchange(request, statusCapability)).rejects.toThrow();
      expect(fetchMock).toHaveBeenCalledTimes(request.source_keyset_id === request.target_keyset_id ? 0 : 1);
    }
  });
});

describe('strict V2 graph discovery', () => {
  it.each([
    ['graph ID', (metadata: any) => { metadata.exchange.active_graph.graph_id = 'a'.repeat(64); }],
    ['transition ID', (metadata: any) => { metadata.exchange.active_graph.transitions[0].transition_id = 'a'.repeat(64); }],
    ['descriptor ID', (metadata: any) => { metadata.exchange.active_graph.descriptors[0].descriptor_id = 'a'.repeat(64); }],
    ['keyset membership', (metadata: any) => { metadata.exchange.active_graph.keysets[0].descriptor_ids.push(metadata.exchange.active_graph.descriptors[0].descriptor_id); }],
    ['receipt key ID', (metadata: any) => { metadata.exchange.active_receipt_key.key_id = 'a'.repeat(64); }],
    ['unknown field', (metadata: any) => { metadata.exchange.active_graph.capability = statusCapability; }],
  ] as const)('rejects altered %s', async (_name, mutate) => {
    const metadata: any = structuredClone(fixture.metadata); mutate(metadata);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(JSON.stringify(metadata), 200)));
    await expect(client().getKeyDiscoveryMetadata()).rejects.toThrow('Invalid V2 exchange discovery metadata');
  });

  it('preserves legacy discovery without an exchange graph', async () => {
    const metadata = structuredClone(fixture.metadata); delete metadata.exchange;
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(JSON.stringify(metadata), 200)));
    await expect(client().getKeyDiscoveryMetadata()).resolves.toMatchObject({ issuer_id: 'issuer:test' });
  });
});
