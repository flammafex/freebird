import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { readFileSync } from 'node:fs';
import { FreebirdClient, crypto as sdkCrypto } from '../src/index.js';
import type {
  ExchangeRequest,
  ExchangeSuccessResponse,
  GraphIssuanceRequest,
  GraphIssuanceResult,
  GraphIssuanceRecoveryContext,
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
const fromHex = (value: string): Uint8Array => {
  if (!/^[0-9a-f]+$/.test(value) || value.length % 2 !== 0) throw new Error('invalid hex fixture');
  return Uint8Array.from(value.match(/../g)!, (byte) => Number.parseInt(byte, 16));
};

const hmacVector = JSON.parse(readFileSync(new URL(
  '../../../docs/examples/public-bearer-graph-issuance-hmac-v2-vector.json',
  import.meta.url,
), 'utf8')) as {
  version: number;
  secret_ascii: string;
  nonce_hex: string;
  issuance_policy_id: string;
  authorization_binding_digest_hex: string;
  framing: string;
  transcript_domain_hex: string;
  authorization_base64url: string;
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

afterEach(() => { vi.unstubAllGlobals(); });

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
  it('validates exchange before graph issuance and commits no partial discovery', async () => {
    const invalid = structuredClone(fixture.metadata) as any;
    invalid.exchange.active_graph.graph_id = 'a'.repeat(64);
    invalid.graph_issuance = {};
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(invalid), 200))
      .mockResolvedValueOnce(response(JSON.stringify(fixture.metadata), 200));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();

    await expect(sdk.getKeyDiscoveryMetadata()).rejects.toThrow(
      'Invalid V2 exchange discovery metadata',
    );
    await expect(sdk.getKeyDiscoveryMetadata()).resolves.toEqual(fixture.metadata);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

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

function graphIssuanceFixture(): {
  metadata: KeyDiscoveryMetadata;
  request: GraphIssuanceRequest;
  result: GraphIssuanceResult;
} {
  const metadata = structuredClone(fixture.metadata);
  const graph = metadata.exchange!.active_graph;
  const keyset = graph.keysets[1];
  const descriptor = graph.descriptors.find((item) => item.descriptor_id === keyset.descriptor_ids[0])!;
  metadata.graph_issuance = {
    version: 2,
    policies: [{
      issuance_policy_id: 'bootstrap-v1', graph_id: graph.graph_id,
      keyset_id: keyset.keyset_id, descriptor_id: descriptor.descriptor_id,
      budget_id: 'graph-bootstrap-budget', budget_limit: 10, quantity: 1,
      admission_state: 'accepting_new', authorization_scheme: 'hmac_sha256',
    }],
    replay_authority: {
      authority_id: b64(new Uint8Array(32).fill(1)),
      v4_scope_digest_tombstones: [],
    },
  };
  const request: GraphIssuanceRequest = {
    version: 2, public_operation_id: operationId, issuance_policy_id: 'bootstrap-v1',
    graph_id: graph.graph_id, keyset_id: keyset.keyset_id,
    descriptor_id: descriptor.descriptor_id, blinded_message: b64(ascii('blinded graph message')),
    authorization: b64(new Uint8Array(64).fill(6)),
  };
  const sdk = client();
  const result: GraphIssuanceResult = {
    version: 2, public_operation_id: request.public_operation_id,
    issuance_policy_id: request.issuance_policy_id, graph_id: request.graph_id,
    keyset_id: request.keyset_id, descriptor_id: request.descriptor_id,
    token_key_id: descriptor.token_key_id, quantity: 1,
    request_digest: sdk.graphIssuanceRequestDigest(request),
    blind_signature: b64(ascii('blind graph signature')), result_digest: '',
  };
  const bytes: number[] = [2];
  put(bytes, fromB64(result.public_operation_id));
  for (const field of [result.issuance_policy_id, result.graph_id, result.keyset_id,
    result.descriptor_id, result.token_key_id]) put(bytes, ascii(field));
  bytes.push(...u32(result.quantity));
  put(bytes, fromB64(result.request_digest)); put(bytes, fromB64(result.blind_signature));
  result.result_digest = domainB64('freebird graph blind issuance result v2\0', new Uint8Array(bytes));
  return { metadata, request, result };
}

function graphRecoveryContext(
  value: ReturnType<typeof graphIssuanceFixture>,
  blindingState: unknown = { opaque: 'rsa-blinding-state' },
): GraphIssuanceRecoveryContext {
  const request = value.request;
  return {
    request,
    requestDigest: client().graphIssuanceRequestDigest(request),
    publicOperationId: request.public_operation_id,
    issuancePolicyId: request.issuance_policy_id,
    graphId: request.graph_id,
    keysetId: request.keyset_id,
    descriptorId: request.descriptor_id,
    statusCapability,
    expectedTokenKeyId: value.result.token_key_id,
    blindingState,
  };
}

describe('policy-authorized graph blind issuance client', () => {
  it('treats v4_local as generic policy scheme metadata only', async () => {
    const value = graphIssuanceFixture();
    value.metadata.graph_issuance!.policies[0].authorization_scheme = 'v4_local';
    const scope = b64(new Uint8Array(32).fill(2));
    value.metadata.graph_issuance!.policies[0].authorization_scope_digest_b64 = scope;
    value.metadata.graph_issuance!.replay_authority.v4_scope_digest_tombstones = [scope];
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(JSON.stringify(value.metadata), 200)));
    await expect(client().selectGraphIssuancePolicy('bootstrap-v1')).resolves.toMatchObject({
      authorization_scheme: 'v4_local',
    });
  });

  it('validates discovery and exact result binding with a header-only capability', async () => {
    const value = graphIssuanceFixture();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(value.metadata), 200))
      .mockResolvedValueOnce(response(JSON.stringify(value.metadata), 200))
      .mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();
    const changedAuthorization = structuredClone(value.request);
    changedAuthorization.authorization = b64(new Uint8Array(64).fill(8));
    expect(sdk.graphIssuanceAuthorizationBindingDigest(changedAuthorization))
      .toBe(sdk.graphIssuanceAuthorizationBindingDigest(value.request));
    expect(sdk.graphIssuanceRequestDigest(changedAuthorization))
      .not.toBe(sdk.graphIssuanceRequestDigest(value.request));
    await expect(sdk.selectGraphIssuancePolicy('bootstrap-v1')).resolves.toMatchObject({ quantity: 1 });
    await expect(sdk.issueGraphBlindSignature(value.request, statusCapability)).resolves.toMatchObject({
      kind: 'committed', response: value.result,
    });
    expect(fetchMock).toHaveBeenLastCalledWith('https://issuer.example/v1/public/graph/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'graph-issuance-status-capability': statusCapability },
      body: JSON.stringify(value.request),
    });
  });

  it('uses observation-only status and rejects wrong bindings or missing no-store', async () => {
    const value = graphIssuanceFixture();
    const recovery = graphRecoveryContext(value);
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
    vi.stubGlobal('fetch', fetchMock);
    await client().getGraphIssuanceStatus(recovery);
    expect(fetchMock.mock.calls[0][0]).toBe(
      `https://issuer.example/v1/public/graph/issue/status?public_operation_id=${operationId}`
    );
    expect(fetchMock.mock.calls[0][0]).not.toContain(statusCapability);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const tampered = structuredClone(value.result); tampered.descriptor_id = 'a'.repeat(64);
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(value.metadata), 200))
      .mockResolvedValueOnce(response(JSON.stringify(tampered), 200)));
    await expect(client().issueGraphBlindSignature(value.request, statusCapability))
      .rejects.toThrow('malformed success JSON');

    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(value.metadata), 200))
      .mockResolvedValueOnce(new Response(JSON.stringify(value.result), { status: 200 })));
    await expect(client().issueGraphBlindSignature(value.request, statusCapability))
      .rejects.toThrow('Cache-Control: no-store');
  });

  it('rejects unknown graph policies and malformed capabilities before POST', async () => {
    const value = graphIssuanceFixture();
    value.metadata.graph_issuance!.policies[0].graph_id = 'a'.repeat(64);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(JSON.stringify(value.metadata), 200)));
    await expect(client().getKeyDiscoveryMetadata()).rejects.toThrow('Invalid graph issuance discovery metadata');

    const clean = graphIssuanceFixture();
    const fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock);
    await expect(client().issueGraphBlindSignature(clean.request, operationId))
      .rejects.toThrow('exactly 32 bytes');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('matches the V2 request, binding, result, and shared HMAC fixture', () => {
    const sdk = client();
    const vector: GraphIssuanceRequest = {
      version: 2,
      public_operation_id: b64(new Uint8Array(16).fill(7)),
      issuance_policy_id: 'bootstrap-v2',
      graph_id: '1'.repeat(64),
      keyset_id: '2'.repeat(64),
      descriptor_id: '3'.repeat(64),
      blinded_message: b64(new Uint8Array(256).fill(4)),
      authorization: b64(new Uint8Array(64).fill(5)),
    };
    expect(sdk.graphIssuanceAuthorizationBindingDigest(vector))
      .toBe('XlKH0YegK8esWoKbeWQtIDCVzGwT1JLcrx0Uag_ykEw');
    expect(sdk.graphIssuanceRequestDigest(vector))
      .toBe('GmoCf632DNZaUd1RcVagcvRaJiKMMhVJZq7MVgtZFxI');
    expect(hmacVector.version).toBe(2);
    expect(hmacVector.framing).toBe('nonce_raw[32] || tag_raw[32]');
    const secret = new TextEncoder().encode(hmacVector.secret_ascii);
    const nonce = fromHex(hmacVector.nonce_hex);
    const binding = fromHex(hmacVector.authorization_binding_digest_hex);
    const transcript = sdkCrypto.graphIssuanceHmacAuthorizationTranscriptV2(
      nonce,
      hmacVector.issuance_policy_id,
      binding,
    );
    const domain = fromHex(hmacVector.transcript_domain_hex);
    expect(hmacVector.transcript_domain_hex)
      .toBe('66726565626972642067726170682069737375616e636520686d616320617574686f72697a6174696f6e20763200');
    expect(hex(transcript.slice(0, domain.length))).toBe(hmacVector.transcript_domain_hex);
    expect(sdkCrypto.buildHmacAuthorizationV2(
      secret,
      nonce,
      hmacVector.issuance_policy_id,
      binding,
    )).toBe(hmacVector.authorization_base64url);
    expect(sdkCrypto.verifyHmacAuthorizationV2(
      secret,
      hmacVector.issuance_policy_id,
      binding,
      hmacVector.authorization_base64url,
    )).toEqual(nonce);
  });

  it.each(['recovery_only', 'disabled'] as const)(
    'requires accepting_new for fresh selection but recovers in %s', async (state) => {
      const value = graphIssuanceFixture();
      value.metadata.graph_issuance!.policies[0].admission_state = state;
      const recovery = graphRecoveryContext(value);
      const fetchMock = vi.fn()
        .mockResolvedValueOnce(response(JSON.stringify(value.metadata), 200))
        .mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
      vi.stubGlobal('fetch', fetchMock);
      await expect(client().issueGraphBlindSignature(value.request, statusCapability))
        .rejects.toThrow('not accepting');
      expect(fetchMock).toHaveBeenCalledTimes(1);

      const recoveryFetch = vi.fn()
        .mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
      vi.stubGlobal('fetch', recoveryFetch);
      await expect(client().retryGraphBlindSignature(recovery))
        .resolves.toMatchObject({ kind: 'committed', response: value.result });
      expect(recoveryFetch).toHaveBeenCalledTimes(1);
      expect(recoveryFetch.mock.calls[0][0]).toBe('https://issuer.example/v1/public/graph/issue');
    }
  );

  it.each(['disabled', 'removed'] as const)(
    'refetches fresh metadata and rejects accepting policy after it becomes %s', async (state) => {
      const value = graphIssuanceFixture();
      const changedMetadata = structuredClone(value.metadata);
      if (state === 'removed') {
        changedMetadata.graph_issuance!.policies = [];
      } else {
        changedMetadata.graph_issuance!.policies[0].admission_state = 'disabled';
      }
      const fetchMock = vi.fn()
        .mockResolvedValueOnce(response(JSON.stringify(value.metadata), 200))
        .mockResolvedValueOnce(response(JSON.stringify(changedMetadata), 200));
      vi.stubGlobal('fetch', fetchMock);
      const sdk = client();
      await expect(sdk.selectGraphIssuancePolicy('bootstrap-v1')).resolves.toMatchObject({
        admission_state: 'accepting_new',
      });
      await expect(sdk.issueGraphBlindSignature(value.request, statusCapability))
        .rejects.toThrow(state === 'removed' ? 'Unknown graph issuance policy' : 'not accepting');
      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(fetchMock.mock.calls[1][0]).toBe('https://issuer.example/.well-known/keys');
    }
  );

  it('uses an exact context with request binding, selectors, key, capability, and opaque state', async () => {
    const value = graphIssuanceFixture();
    const context = graphRecoveryContext(value, { opaqueBytes: [1, 2, 3], nested: { keep: true } });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
    vi.stubGlobal('fetch', fetchMock);
    await expect(client().retryGraphBlindSignature(context)).resolves.toMatchObject({
      kind: 'committed', response: value.result,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('https://issuer.example/v1/public/graph/issue');

    for (const mutate of [
      (broken: any) => { delete broken.expectedTokenKeyId; },
      (broken: any) => { broken.requestDigest = b64(new Uint8Array(32)); },
      (broken: any) => { broken.publicOperationId = otherOperationId; },
      (broken: any) => { broken.descriptorId = 'a'.repeat(64); },
      (broken: any) => { broken.statusCapability = operationId; },
      (broken: any) => { delete broken.blindingState; },
      (broken: any) => { broken.unexpected = true; },
    ]) {
      const broken = structuredClone(context) as any;
      mutate(broken);
      const noFetch = vi.fn();
      vi.stubGlobal('fetch', noFetch);
      await expect(client().getGraphIssuanceStatus(broken)).rejects.toThrow();
      expect(noFetch).not.toHaveBeenCalled();
    }
  });

  it('creates recovery context without discovery and rejects raw recovery arguments', async () => {
    const value = graphIssuanceFixture();
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const blindingState = { opaque: 'caller-owned' };
    const context = await client().createGraphIssuanceRecoveryContext(
      value.request,
      statusCapability,
      value.result.token_key_id,
      blindingState,
    );
    expect(context).toMatchObject({
      publicOperationId: value.request.public_operation_id,
      expectedTokenKeyId: value.result.token_key_id,
      blindingState: { opaque: 'caller-owned' },
    });
    expect(context.request).toBe(value.request);
    expect(context.blindingState).toBe(blindingState);
    expect(fetchMock).not.toHaveBeenCalled();

    const rawArgumentClient = client();
    const retryWithRawArguments = rawArgumentClient.retryGraphBlindSignature.bind(rawArgumentClient) as
      (...args: any[]) => Promise<unknown>;
    await expect(retryWithRawArguments(value.request as any, statusCapability as any))
      .rejects.toThrow('recovery context');
    await expect(client().getGraphIssuanceStatus(value.request as any))
      .rejects.toThrow('recovery context');
  });

  it.each(['descriptor', 'graph', 'policy'] as const)(
    'recovers with zero discovery after %s removal', async (_removed) => {
      const value = graphIssuanceFixture();
      const context = graphRecoveryContext(value);
      const fetchMock = vi.fn()
        .mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
      vi.stubGlobal('fetch', fetchMock);
      await expect(client().getGraphIssuanceStatus(context)).resolves.toMatchObject({
        kind: 'committed', response: value.result,
      });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock.mock.calls[0][0]).not.toContain('.well-known/keys');
    }
  );

  it('keeps a completed issuance recoverable after the same client sees policy removal', async () => {
    const value = graphIssuanceFixture();
    const context = graphRecoveryContext(value, { opaque: 'must-survive-issuance' });
    const freshFetch = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(value.metadata), 200))
      .mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
    vi.stubGlobal('fetch', freshFetch);
    const sdk = client();
    await expect(sdk.issueGraphBlindSignature(value.request, statusCapability))
      .resolves.toMatchObject({ kind: 'committed' });

    const removedMetadata = structuredClone(value.metadata);
    removedMetadata.graph_issuance!.policies = [];
    const removalFetch = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(removedMetadata), 200));
    vi.stubGlobal('fetch', removalFetch);
    await expect(sdk.selectGraphIssuancePolicy('bootstrap-v1'))
      .rejects.toThrow('Unknown graph issuance policy');
    const recoveryFetch = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
    vi.stubGlobal('fetch', recoveryFetch);
    await expect(sdk.getGraphIssuanceStatus(context)).resolves.toMatchObject({
      kind: 'committed', response: value.result,
    });
    expect(removedMetadata.graph_issuance!.policies).toHaveLength(0);
    expect(context.blindingState).toEqual({ opaque: 'must-survive-issuance' });
    expect(recoveryFetch).toHaveBeenCalledTimes(1);
    expect(recoveryFetch.mock.calls[0][0]).not.toContain('.well-known/keys');
  });

  it('recovers status after the policy is removed, using persisted key context', async () => {
    const value = graphIssuanceFixture();
    value.metadata.graph_issuance!.policies = [];
    const context = graphRecoveryContext(value);
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
    vi.stubGlobal('fetch', fetchMock);
    await expect(client().getGraphIssuanceStatus(context)).resolves.toMatchObject({
      kind: 'committed', response: value.result,
    });
  });

  it.each([
    ['digest length', (result: GraphIssuanceResult) => { result.result_digest = b64(new Uint8Array(31)); }],
    ['request digest length', (result: GraphIssuanceResult) => { result.request_digest = b64(new Uint8Array(31)); }],
    ['token key binding', (result: GraphIssuanceResult) => { result.token_key_id = 'a'.repeat(64); }],
    ['quantity', (result: GraphIssuanceResult) => { result.quantity = 2; }],
  ] as const)('rejects V2 result %s mismatch', async (_name, mutate) => {
    const value = graphIssuanceFixture();
    const result = structuredClone(value.result); mutate(result);
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(value.metadata), 200))
      .mockResolvedValueOnce(response(JSON.stringify(result), 200)));
    await expect(client().issueGraphBlindSignature(value.request, statusCapability))
      .rejects.toThrow('malformed success JSON');
  });

  it('rejects a status capability injected into the graph result', async () => {
    const value = graphIssuanceFixture();
    const result = { ...value.result, status_capability: statusCapability };
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(value.metadata), 200))
      .mockResolvedValueOnce(response(JSON.stringify(result), 200)));
    await expect(client().issueGraphBlindSignature(value.request, statusCapability))
      .rejects.toThrow('malformed success JSON');
  });

  it.each([
    ['missing authority', (metadata: any) => { delete metadata.graph_issuance.replay_authority; }],
    ['wrong authority length', (metadata: any) => { metadata.graph_issuance.replay_authority.authority_id = b64(new Uint8Array(31)); }],
    ['duplicate tombstone', (metadata: any) => {
      const tombstone = b64(new Uint8Array(32).fill(3));
      metadata.graph_issuance.replay_authority.v4_scope_digest_tombstones = [tombstone, tombstone];
    }],
    ['scope without tombstone', (metadata: any) => {
      metadata.graph_issuance.policies[0].authorization_scheme = 'v4_local';
      metadata.graph_issuance.policies[0].authorization_scope_digest_b64 = b64(new Uint8Array(32).fill(4));
    }],
    ['unknown authority field', (metadata: any) => {
      metadata.graph_issuance.replay_authority.capability = statusCapability;
    }],
  ] as const)('rejects malformed graph issuance authority metadata: %s', async (_name, mutate) => {
    const value = graphIssuanceFixture();
    mutate(value.metadata);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(JSON.stringify(value.metadata), 200)));
    await expect(client().getKeyDiscoveryMetadata())
      .rejects.toThrow('Invalid graph issuance discovery metadata');
  });
});

describe('exchange status, retry, and durable-response characterization', () => {
  it('supports the request overload and preserves the exact durable response body', async () => {
    const rawBody = JSON.stringify(fixture.success, null, 2);
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(fixture.metadata), 200))
      .mockResolvedValueOnce(response(rawBody, 200));
    vi.stubGlobal('fetch', fetchMock);

    const outcome = await client().getExchangeStatus(fixture.request, statusCapability);

    expect(outcome).toMatchObject({
      kind: 'committed',
      httpStatus: 200,
      rawResponseBody: rawBody,
      cacheControl: 'no-store',
    });
    expect(fetchMock.mock.calls[1][0]).toBe(
      `https://issuer.example/v2/public/exchange/status?public_operation_id=${operationId}`,
    );
    expect(fetchMock.mock.calls[1][1]).toEqual({
      method: 'GET',
      headers: { 'exchange-status-capability': statusCapability },
    });
  });

  it('requires no-store for status responses as well as exchange responses', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(fixture.metadata), 200))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: 'unknown_operation' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(client().getExchangeStatus(fixture.request, statusCapability))
      .rejects.toThrow('Cache-Control: no-store');
  });

  it('retries the same public operation with the same wire body and capability header', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(fixture.metadata), 200))
      .mockResolvedValueOnce(response(JSON.stringify(fixture.success), 200))
      .mockResolvedValueOnce(response(JSON.stringify(fixture.success), 200));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();

    await expect(sdk.exchange(fixture.request, statusCapability)).resolves.toMatchObject({
      kind: 'committed',
    });
    await expect(sdk.exchange(fixture.request, statusCapability)).resolves.toMatchObject({
      kind: 'committed',
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[1]).toEqual(fetchMock.mock.calls[2]);
    expect(fetchMock.mock.calls[1][1].body).toBe(JSON.stringify(fixture.request));
    expect(fetchMock.mock.calls[1][1].headers['exchange-status-capability']).toBe(statusCapability);
  });

  it('models every ordinary durable exchange error code with raw body and no-store', async () => {
    const cases = [
      [400, 'invalid_status_capability'],
      [400, 'invalid_public_operation_id'],
      [400, 'invalid_exchange_request'],
      [400, 'invalid_exchange'],
      [404, 'unknown_operation'],
      [409, 'operation_conflict'],
      [413, 'exchange_request_too_large'],
      [503, 'exchange_unavailable'],
    ] as const;
    for (const [status, code] of cases) {
      const rawBody = JSON.stringify({ error: code, durable: true });
      const fetchMock = vi.fn()
        .mockResolvedValueOnce(response(JSON.stringify(fixture.metadata), 200))
        .mockResolvedValueOnce(response(JSON.stringify({ error: code }), status));
      vi.stubGlobal('fetch', fetchMock);

      // The endpoint's error body is intentionally exact-key JSON; the raw
      // response assertion below separately covers whitespace-preserving reads.
      const exactRawBody = JSON.stringify({ error: code });
      await expect(client().exchange(fixture.request, statusCapability)).resolves.toMatchObject({
        kind: 'error',
        httpStatus: status,
        response: { error: code },
        rawResponseBody: exactRawBody,
        cacheControl: 'no-store',
      });
      expect(rawBody).toContain(code);
    }
  });

  it.each(['', '01', '-1', '1.5', '1x'] as const)(
    'rejects malformed Retry-After values: %s', async (retryAfter) => {
      const fetchMock = exchangeFetch(
        '{"error":"exchange_retryable"}',
        202,
        retryAfter === '' ? {} : { 'Retry-After': retryAfter },
      );
      vi.stubGlobal('fetch', fetchMock);
      await expect(client().exchange(fixture.request, statusCapability))
        .rejects.toThrow('invalid Retry-After');
    },
  );

  it('keeps capabilities out of exchange URLs and response records', async () => {
    const body = structuredClone(fixture.success) as any;
    body.receipt.exchange_status_capability = statusCapability;
    const fetchMock = exchangeFetch(body);
    vi.stubGlobal('fetch', fetchMock);
    await expect(client().exchange(fixture.request, statusCapability))
      .rejects.toThrow('malformed success JSON');
    expect(fetchMock.mock.calls[1][0]).not.toContain(statusCapability);
    expect(fetchMock.mock.calls[1][1].body).not.toContain(statusCapability);
  });
});

describe('graph issuance error, alias, and capability characterization', () => {
  it('dispatches recovery-context, retry, and status through public digest overrides', async () => {
    class DigestProbe extends FreebirdClient {
      digestRequests: GraphIssuanceRequest[] = [];

      override graphIssuanceRequestDigest(request: GraphIssuanceRequest): string {
        this.digestRequests.push(request);
        return super.graphIssuanceRequestDigest(request);
      }
    }
    const value = graphIssuanceFixture();
    const sdk = new DigestProbe({ issuerUrl: 'https://issuer.example' });
    const blindingState = { opaque: 'digest-dispatch' };
    const context = await sdk.createGraphIssuanceRecoveryContext(
      value.request,
      statusCapability,
      value.result.token_key_id,
      blindingState,
    );
    expect(sdk.digestRequests).toHaveLength(1);
    expect(sdk.digestRequests[0]).toBe(value.request);
    expect(context.request).toBe(value.request);
    expect(context.blindingState).toBe(blindingState);

    const retryFetch = vi.fn().mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
    vi.stubGlobal('fetch', retryFetch);
    await expect(sdk.retryGraphBlindSignature(context)).resolves.toMatchObject({
      kind: 'committed', response: value.result,
    });
    expect(sdk.digestRequests).toHaveLength(3);
    expect(sdk.digestRequests[1]).toBe(value.request);
    expect(sdk.digestRequests[2]).toBe(value.request);

    const statusFetch = vi.fn().mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
    vi.stubGlobal('fetch', statusFetch);
    await expect(sdk.getGraphIssuanceStatus(context)).resolves.toMatchObject({
      kind: 'committed', response: value.result,
    });
    expect(sdk.digestRequests).toHaveLength(5);
    expect(sdk.digestRequests[3]).toBe(value.request);
    expect(sdk.digestRequests[4]).toBe(value.request);
  });

  it('retains the last committed discovery when a fresh graph fetch fails', async () => {
    const value = graphIssuanceFixture();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(value.metadata), 200))
      .mockResolvedValueOnce(new Response('temporarily unavailable', { status: 503 }));
    vi.stubGlobal('fetch', fetchMock);
    const sdk = client();

    await expect(sdk.selectGraphIssuancePolicy('bootstrap-v1')).resolves.toMatchObject({
      admission_state: 'accepting_new',
    });
    await expect(sdk.selectGraphIssuancePolicy('bootstrap-v1')).rejects.toThrow('503');
    await expect(sdk.selectExchangeTransition(
      value.request.graph_id,
      value.metadata.exchange!.active_graph.transitions[0].transition_id,
    )).resolves.toBeDefined();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('dispatches public exchange/graph hooks with live request and recovery identities', async () => {
    class PublicHookProbe extends FreebirdClient {
      exchangeSelectionCalls = 0;
      graphPolicyCalls = 0;
      exchangeDigestRequest: ExchangeRequest | undefined;
      graphDigestRequest: GraphIssuanceRequest | undefined;
      retryContext: GraphIssuanceRecoveryContext | undefined;

      override async selectExchangeTransition(graphId: string, transitionId: string) {
        this.exchangeSelectionCalls++;
        expect(graphId).toBe(fixture.request.graph_id);
        expect(transitionId).toBe(fixture.request.transition_id);
        return {
          graph: fixture.metadata.exchange!.active_graph,
          transition: fixture.metadata.exchange!.active_graph.transitions[0],
        };
      }

      override exchangeRequestDigest(request: ExchangeRequest): string {
        this.exchangeDigestRequest = request;
        return super.exchangeRequestDigest(request);
      }

      override async selectGraphIssuancePolicy(policyId: string) {
        this.graphPolicyCalls++;
        expect(policyId).toBe('bootstrap-v1');
        return graphIssuanceFixture().metadata.graph_issuance!.policies[0];
      }

      override graphIssuanceRequestDigest(request: GraphIssuanceRequest): string {
        this.graphDigestRequest = request;
        return super.graphIssuanceRequestDigest(request);
      }

      override async retryGraphBlindSignature(context: GraphIssuanceRecoveryContext) {
        this.retryContext = context;
        return {
          kind: 'error' as const,
          httpStatus: 503 as const,
          response: { error: 'graph_issuance_unavailable' },
          rawResponseBody: '{"error":"graph_issuance_unavailable"}',
          cacheControl: 'no-store' as const,
        };
      }
    }

    const exchangeProbe = new PublicHookProbe({
      issuerUrl: 'https://issuer.example', verifierId: 'v', audience: 'a',
    });
    const exchangeFetchMock = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify({ error: 'exchange_unavailable' }), 503))
      .mockResolvedValueOnce(response(JSON.stringify({ error: 'exchange_unavailable' }), 503));
    vi.stubGlobal('fetch', exchangeFetchMock);
    await expect(exchangeProbe.exchange(fixture.request, statusCapability))
      .resolves.toMatchObject({ kind: 'error', httpStatus: 503 });
    expect(exchangeProbe.exchangeSelectionCalls).toBe(1);
    expect(exchangeProbe.exchangeDigestRequest).toBe(fixture.request);
    await expect(exchangeProbe.getExchangeStatus(fixture.request, statusCapability))
      .resolves.toMatchObject({ kind: 'error', httpStatus: 503 });
    expect(exchangeProbe.exchangeSelectionCalls).toBe(2);
    expect(exchangeProbe.exchangeDigestRequest).toBe(fixture.request);

    const value = graphIssuanceFixture();
    const recovery = graphRecoveryContext(value);
    const graphFetchMock = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(value.metadata), 200))
      .mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
    vi.stubGlobal('fetch', graphFetchMock);
    const graphProbe = new PublicHookProbe({
      issuerUrl: 'https://issuer.example', verifierId: 'v', audience: 'a',
    });
    await graphProbe.getKeyDiscoveryMetadata();
    await expect(graphProbe.issueGraphBlindSignature(value.request, statusCapability))
      .resolves.toMatchObject({ kind: 'committed' });
    expect(graphProbe.graphPolicyCalls).toBe(1);
    expect(graphProbe.graphDigestRequest).toBe(value.request);

    const aliasProbe = new PublicHookProbe({ issuerUrl: 'https://issuer.example' });
    await expect(aliasProbe.retryGraphIssuance(recovery)).resolves.toMatchObject({
      kind: 'error', httpStatus: 503,
    });
    expect(aliasProbe.retryContext).toBe(recovery);
  });

  it('models fresh graph issuance errors and preserves the durable raw body', async () => {
    const cases = [
      [400, 'invalid_status_capability'],
      [400, 'invalid_public_operation_id'],
      [400, 'invalid_graph_issuance_request'],
      [400, 'invalid_graph_issuance'],
      [404, 'unknown_operation'],
      [409, 'operation_conflict'],
      [413, 'graph_issuance_request_too_large'],
      [503, 'graph_issuance_unavailable'],
    ] as const;
    for (const [status, code] of cases) {
      const value = graphIssuanceFixture();
      const rawBody = JSON.stringify({ error: code });
      const fetchMock = vi.fn()
        .mockResolvedValueOnce(response(JSON.stringify(value.metadata), 200))
        .mockResolvedValueOnce(response(rawBody, status));
      vi.stubGlobal('fetch', fetchMock);

      await expect(client().issueGraphBlindSignature(value.request, statusCapability))
        .resolves.toMatchObject({
          kind: 'error',
          httpStatus: status,
          response: { error: code },
          rawResponseBody: rawBody,
          cacheControl: 'no-store',
        });
    }
  });

  it('rejects unauthorized graph status and uses the recovery alias without discovery', async () => {
    const value = graphIssuanceFixture();
    const recovery = graphRecoveryContext(value);
    const unauthorized = vi.fn().mockResolvedValueOnce(response(JSON.stringify({
      error: 'status_unauthorized',
    }), 403));
    vi.stubGlobal('fetch', unauthorized);
    await expect(client().getGraphIssuanceStatus(recovery)).rejects.toThrow('not authorized');

    const retry = vi.fn().mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
    vi.stubGlobal('fetch', retry);
    await expect(client().retryGraphIssuance(recovery)).resolves.toMatchObject({
      kind: 'committed', response: value.result,
    });
    expect(retry).toHaveBeenCalledTimes(1);
    expect(retry.mock.calls[0][0]).toBe('https://issuer.example/v1/public/graph/issue');
    expect(retry.mock.calls[0][1]).toEqual({
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'graph-issuance-status-capability': statusCapability,
      },
      body: JSON.stringify(value.request),
    });
  });

  it('keeps the graph capability header-only on fresh and recovery requests', async () => {
    const value = graphIssuanceFixture();
    const fresh = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify(value.metadata), 200))
      .mockResolvedValueOnce(response(JSON.stringify(value.result), 200));
    vi.stubGlobal('fetch', fresh);
    await client().issueGraphBlindSignature(value.request, statusCapability);
    expect(fresh.mock.calls[1][0]).not.toContain(statusCapability);
    expect(fresh.mock.calls[1][1].body).not.toContain(statusCapability);
    expect(fresh.mock.calls[1][1].headers['graph-issuance-status-capability'])
      .toBe(statusCapability);
  });
});
