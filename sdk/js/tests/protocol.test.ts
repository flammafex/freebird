// SPDX-License-Identifier: Apache-2.0 OR MIT

import { beforeAll, describe, expect, it, vi } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';
import { FreebirdClient, generateOperationId, generateStatusCapability } from '../src/index.js';
import { isCanonicalBase64Url } from '../src/client/wire.js';
import type {
  ExchangeRequestSource,
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
const u32 = (value: number): number[] => [value >>> 24, value >>> 16, value >>> 8, value].map((x) => x & 255);
const u64 = (value: number): number[] => {
  let integer = BigInt(value);
  const output = Array<number>(8);
  for (let index = 7; index >= 0; index--) { output[index] = Number(integer & 255n); integer >>= 8n; }
  return output;
};
const put = (output: number[], value: Uint8Array): void => { output.push(...u32(value.length), ...value); };

async function rsaSpki(): Promise<Uint8Array> {
  const pair = await crypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-384' },
    true,
    ['sign', 'verify'],
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

interface Fixture {
  metadata: KeyDiscoveryMetadata;
  graphId: string;
  transitionId: string;
  sourceKeysetId: string;
  targetKeysetId: string;
  sourceDescriptorId: string;
  targetDescriptorId: string;
}

let fixture: Fixture;

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
  const receiptPublic = ed25519.getPublicKey(new Uint8Array(32).fill(9));
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
  fixture = {
    metadata,
    graphId: graph.graph_id,
    transitionId: transition.transition_id,
    sourceKeysetId: sourceKeyset.keyset_id,
    targetKeysetId: targetKeyset.keyset_id,
    sourceDescriptorId: sourceDescriptor.descriptor_id,
    targetDescriptorId: targetDescriptor.descriptor_id,
  };
});

function response(body: string, status: number): Response {
  return new Response(body, { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}

function client(): FreebirdClient {
  return new FreebirdClient({ issuerUrl: 'https://issuer.example', verifierId: 'verifier:test', audience: 'test' });
}

function sourceArtifact(): ExchangeRequestSource {
  return {
    slot: {
      descriptor_id: fixture.sourceDescriptorId,
      keyset_id: fixture.sourceKeysetId,
      slot_id: 'source-0',
      quantity: 1,
    },
    artifact: b64(ascii('source artifact')),
  };
}

describe('protocol utilities', () => {
  it('generateOperationId produces canonical 16-byte base64url values that are unique', () => {
    const first = generateOperationId();
    const second = generateOperationId();
    expect(isCanonicalBase64Url(first, 16)).toBe(true);
    expect(isCanonicalBase64Url(second, 16)).toBe(true);
    expect(first).not.toBe(second);
  });

  it('generateStatusCapability produces canonical 32-byte base64url values that are unique', () => {
    const first = generateStatusCapability();
    const second = generateStatusCapability();
    expect(isCanonicalBase64Url(first, 32)).toBe(true);
    expect(isCanonicalBase64Url(second, 32)).toBe(true);
    expect(first).not.toBe(second);
  });

  it('exchangePasses assembles a request that passes digest and selection validation', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(JSON.stringify(fixture.metadata), 200)));
    const sdk = client();
    const request = await sdk.exchangePasses(
      [sourceArtifact()],
      { graphId: fixture.graphId, transitionId: fixture.transitionId },
      { messages: [ascii('target message')] },
    );
    expect(request.version).toBe(2);
    expect(request.graph_id).toBe(fixture.graphId);
    expect(request.transition_id).toBe(fixture.transitionId);
    expect(request.source_keyset_id).toBe(fixture.sourceKeysetId);
    expect(request.target_keyset_id).toBe(fixture.targetKeysetId);
    expect(isCanonicalBase64Url(request.public_operation_id, 16)).toBe(true);
    expect(request.sources).toHaveLength(1);
    expect(request.sources[0].slot.keyset_id).toBe(fixture.sourceKeysetId);
    expect(request.outputs).toHaveLength(1);
    expect(request.outputs[0].slot.keyset_id).toBe(fixture.targetKeysetId);
    expect(request.outputs[0].slot.quantity).toBe(2);
    expect(isCanonicalBase64Url(request.outputs[0].blinded_value, undefined, 16 * 1024, 1)).toBe(true);

    // The assembled request must be wire-valid (digest does not throw) and must
    // pass validateExchangeRequestSelection: exchange() reaches the POST rather
    // than rejecting the request before any fetch.
    expect(typeof sdk.exchangeRequestDigest(request)).toBe('string');
    // Metadata is already cached from exchangePasses, so the exchange POST is
    // the first fetch of this mock. Reaching the POST proves the assembled
    // request passed validateExchangeRequestSelection.
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(JSON.stringify({ error: 'exchange_unavailable' }), 503));
    vi.stubGlobal('fetch', fetchMock);
    const outcome = await sdk.exchange(request, generateStatusCapability());
    expect(outcome).toMatchObject({ kind: 'error', httpStatus: 503 });
    expect(fetchMock.mock.calls[0][0]).toBe('https://issuer.example/v2/public/exchange');
  });

  it('rejects sources whose keyset does not match the transition source keyset', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(JSON.stringify(fixture.metadata), 200)));
    const sdk = client();
    const mismatched = sourceArtifact();
    mismatched.slot.keyset_id = fixture.targetKeysetId;
    await expect(sdk.exchangePasses(
      [mismatched],
      { graphId: fixture.graphId, transitionId: fixture.transitionId },
      { messages: [ascii('target message')] },
    )).rejects.toThrow('do not match');
  });

  it('rejects a source count that does not match the transition source slots', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(JSON.stringify(fixture.metadata), 200)));
    const sdk = client();
    await expect(sdk.exchangePasses(
      [],
      { graphId: fixture.graphId, transitionId: fixture.transitionId },
      { messages: [ascii('target message')] },
    )).rejects.toThrow('do not match');
  });
});
