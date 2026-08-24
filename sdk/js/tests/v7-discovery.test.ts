// SPDX-License-Identifier: Apache-2.0 OR MIT

import { createHash, generateKeyPairSync } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  canonicalV7DirectDescriptorId,
  canonicalV7ExchangeDescriptorId,
  canonicalV7GraphId,
  canonicalV7GraphPolicyId,
  canonicalV7KeysetId,
  canonicalV7TransitionId,
  materializeV7Registry,
  parseV7KeyDiscovery,
  refreshV7KeyDiscoveryMetadata,
} from '../src/client/v7_discovery.js';
import { createClientState } from '../src/client/state.js';
import { refreshKeyDiscoveryMetadata } from '../src/client/discovery.js';

function v7Spki(): Uint8Array {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 65537 });
  const standard = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }) as Buffer);
  const raw = standard.slice(24);
  const template = Uint8Array.from([
    0x30, 0x82, 0, 0, 0x30, 0x3d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
    0x30, 0x30, 0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09,
    0, 0, 0, 0, 0, 0, 0, 0, 0,
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
    0x30, 0x0b, 0x06, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0xa2, 0x03, 0x02, 0x01, 0, 0x03, 0x82, 0, 0, 0,
  ]);
  const sha384 = Uint8Array.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]);
  template.set(sha384, 25);
  template.set(sha384, 53);
  template[66] = 48;
  template[2] = (template.length + raw.length - 4) >>> 8;
  template[3] = (template.length + raw.length - 4) & 0xff;
  template[69] = (raw.length + 1) >>> 8;
  template[70] = (raw.length + 1) & 0xff;
  const result = new Uint8Array(template.length + raw.length);
  result.set(template);
  result.set(raw, template.length);
  return result;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function documentFor(issuerId = 'issuer:test') {
  const spki = v7Spki();
  const spkiB64 = Buffer.from(spki).toString('base64url');
  const record: Record<string, unknown> = {
    profile_id: 'scarcity/native-bearer/v7', issuer_id: issuerId,
    descriptor_id: '', token_key_id: '11'.repeat(32), asset_id: 'USD', amount_minor: 42,
    suite: 'RSABSSA-SHA384-PSS-Randomized-V7', modulus_bits: 3072, exponent: 65537,
    pubkey_spki_b64: spkiB64, spki_fingerprint: hex(new Uint8Array(createHash('sha256').update(spki).digest())),
    valid_from: 1, valid_until: 2,
  };
  record.descriptor_id = canonicalV7DirectDescriptorId(record, spki);
  return {
    issuer_id: issuerId, current_epoch: 1, valid_epochs: [1], epoch_duration_sec: 86400,
    voprf: { suite: 'VOPRF-P256-SHA256', kid: 'kid', pubkey: 'pubkey' },
    native_bearer_v7: record, native_bearer_v7_retained: [],
  };
}

function exchangeDescriptor(spki: Uint8Array, issuerId: string, tokenKeyId: string, amount: string) {
  const record: Record<string, unknown> = {
    descriptor_id: '', profile_id: 'freebird/native-exchange/v3', issuer_id: issuerId,
    token_key_id: tokenKeyId, asset_id: 'USD', amount_minor: amount,
    suite: 'RSABSSA-SHA384-PSS-Randomized-V7', modulus_bits: 3072, exponent: 65537,
    pubkey_spki_b64: Buffer.from(spki).toString('base64url'),
    spki_fingerprint: hex(new Uint8Array(createHash('sha256').update(spki).digest())),
    valid_from: 1, valid_until: 2,
  };
  record.descriptor_id = canonicalV7ExchangeDescriptorId(record, spki);
  return record;
}

type TestRecord = Record<string, unknown>;
type TestSlot = TestRecord & { descriptor_id: string; keyset_id: string; slot_id: string; quantity: number };
type TestTransition = TestRecord & { source_slots: TestSlot[]; output_slots: TestSlot[] };
type TestExchange = TestRecord & {
  profile: TestRecord;
  active_descriptors: TestRecord[];
  retained_descriptors: TestRecord[];
  active_keysets: TestRecord[];
  retained_keysets: TestRecord[];
  transitions: TestTransition[];
};
type TestGraph = TestRecord & { active_policies: TestRecord[]; retained_policies: TestRecord[] };
type TestDocument = ReturnType<typeof documentFor> & {
  native_exchange_v7?: TestExchange;
  native_graph_issuance_v7?: TestGraph;
};

function fullDocument(issuerId = 'issuer:test'): TestDocument {
  const document = documentFor(issuerId);
  const directSpki = Buffer.from(document.native_bearer_v7.pubkey_spki_b64 as string, 'base64url');
  const secondSpki = v7Spki();
  const firstDescriptor = exchangeDescriptor(directSpki, issuerId, '11'.repeat(32), '42');
  const secondDescriptor = exchangeDescriptor(secondSpki, issuerId, '22'.repeat(32), '43');
  const firstKeyset = { keyset_id: '', profile_id: 'freebird/native-exchange/v3', descriptor_ids: [firstDescriptor.descriptor_id] };
  const secondKeyset = { keyset_id: '', profile_id: 'freebird/native-exchange/v3', descriptor_ids: [secondDescriptor.descriptor_id] };
  firstKeyset.keyset_id = canonicalV7KeysetId(firstKeyset.descriptor_ids as string[]);
  secondKeyset.keyset_id = canonicalV7KeysetId(secondKeyset.descriptor_ids as string[]);
  const transition: Record<string, unknown> = {
    transition_id: '', profile_id: 'freebird/native-exchange/v3',
    source_keyset_id: firstKeyset.keyset_id, target_keyset_id: secondKeyset.keyset_id,
    source_slots: [{ descriptor_id: firstDescriptor.descriptor_id, keyset_id: firstKeyset.keyset_id, slot_id: 'input', quantity: 1 }],
    output_slots: [{ descriptor_id: secondDescriptor.descriptor_id, keyset_id: secondKeyset.keyset_id, slot_id: 'output', quantity: 1 }],
  };
  transition.transition_id = canonicalV7TransitionId(transition);
  const exchange: Record<string, unknown> = {
    version: 3,
    profile: { version: 3, profile_id: 'freebird/native-exchange/v3', graph_id: '', suite: 'RSABSSA-SHA384-PSS-Randomized-V7', modulus_bits: 3072, exponent: 65537 },
    active_descriptors: [firstDescriptor, secondDescriptor], retained_descriptors: [],
    active_keysets: [firstKeyset, secondKeyset], retained_keysets: [], transitions: [transition],
  };
  (exchange.profile as Record<string, unknown>).graph_id = canonicalV7GraphId(exchange);
  const policy: Record<string, unknown> = {
    policy_id: '', profile_id: 'freebird/native-graph-issuance/v7',
    graph_id: (exchange.profile as Record<string, unknown>).graph_id,
    keyset_id: firstKeyset.keyset_id, descriptor_id: firstDescriptor.descriptor_id,
    token_key_id: firstDescriptor.token_key_id, issuer_id: issuerId, asset_id: firstDescriptor.asset_id,
    amount_minor: firstDescriptor.amount_minor, suite: firstDescriptor.suite,
    modulus_bits: 3072, exponent: 65537, quantity: 1,
    pubkey_spki_b64: firstDescriptor.pubkey_spki_b64,
    spki_fingerprint: firstDescriptor.spki_fingerprint, valid_from: 1, valid_until: 2,
  };
  policy.policy_id = canonicalV7GraphPolicyId(policy, directSpki);
  return {
    ...document,
    native_exchange_v7: exchange,
    native_graph_issuance_v7: { version: 7, profile_id: 'freebird/native-graph-issuance/v7', active_policies: [policy], retained_policies: [] },
  } as unknown as TestDocument;
}

describe('strict V7 discovery', () => {
  it('parses u64 values losslessly as bigint and accepts normalized PSS SPKI', async () => {
    const document = documentFor();
    document.native_bearer_v7.amount_minor = 18446744073709551615n;
    document.native_bearer_v7.descriptor_id = canonicalV7DirectDescriptorId(
      document.native_bearer_v7, Buffer.from(document.native_bearer_v7.pubkey_spki_b64 as string, 'base64url'),
    );
    const serialized = JSON.stringify({
      ...document,
      native_bearer_v7: { ...document.native_bearer_v7, amount_minor: 42 },
    }).replace('"amount_minor":42', '"amount_minor":18446744073709551615');
    const parsed = await parseV7KeyDiscovery(serialized);
    expect(parsed.epoch_duration_sec).toBe(86400n);
    expect(parsed.native_bearer_v7.amount_minor).toBe(18446744073709551615n);
  });

  it.each(['public', 'v5', 'native_bearer_v6'])('rejects legacy or unknown field %s', async (field) => {
    const document = documentFor() as Record<string, unknown>;
    document[field] = [];
    await expect(parseV7KeyDiscovery(JSON.stringify(document))).rejects.toThrow();
  });

  it('rejects canonical ID tampering and non-V7 PSS parameters', async () => {
    const document = documentFor();
    document.native_bearer_v7.descriptor_id = 'aa'.repeat(32);
    await expect(parseV7KeyDiscovery(JSON.stringify(document))).rejects.toThrow();
    const malformed = documentFor();
    const bytes = Buffer.from(malformed.native_bearer_v7.pubkey_spki_b64 as string, 'base64url');
    bytes[66] = 49;
    malformed.native_bearer_v7.pubkey_spki_b64 = bytes.toString('base64url');
    await expect(parseV7KeyDiscovery(JSON.stringify(malformed))).rejects.toThrow();
  });

  it('rejects byte-identical duplicate direct registry entries', async () => {
    const document = documentFor() as {
      native_bearer_v7: Record<string, unknown>;
      native_bearer_v7_retained: unknown[];
    } & Record<string, unknown>;
    document.native_bearer_v7_retained = [document.native_bearer_v7];
    await expect(parseV7KeyDiscovery(JSON.stringify(document))).rejects.toThrow();
  });

  it('accepts a complete canonical exchange and graph fixture and merges shared roles', async () => {
    const parsed = await parseV7KeyDiscovery(JSON.stringify(fullDocument()));
    expect(parsed.native_exchange_v7?.profile.graph_id).toMatch(/^[0-9a-f]{64}$/);
    expect(parsed.native_graph_issuance_v7?.active_policies[0].policy_id).toMatch(/^[0-9a-f]{64}$/);
    const registry = await materializeV7Registry(parsed);
    const shared = registry.by_token_key_id.get(parsed.native_bearer_v7.token_key_id);
    expect(shared?.roles).toEqual(['direct', 'exchange', 'graph_issuance']);
    expect(shared?.references).toHaveLength(3);
    expect(registry.entries).toHaveLength(2);
  });

  it.each([
    ['descriptor', (document: ReturnType<typeof fullDocument>) => {
      document.native_exchange_v7!.active_descriptors[0].descriptor_id = 'aa'.repeat(32);
    }],
    ['keyset', (document: ReturnType<typeof fullDocument>) => {
      document.native_exchange_v7!.active_keysets[0].keyset_id = 'aa'.repeat(32);
    }],
    ['transition', (document: ReturnType<typeof fullDocument>) => {
      document.native_exchange_v7!.transitions[0].transition_id = 'aa'.repeat(32);
    }],
    ['graph', (document: ReturnType<typeof fullDocument>) => {
      document.native_exchange_v7!.profile.graph_id = 'aa'.repeat(32);
    }],
    ['policy', (document: ReturnType<typeof fullDocument>) => {
      document.native_graph_issuance_v7!.active_policies[0].policy_id = 'aa'.repeat(32);
    }],
  ])('rejects tampered canonical %s IDs', async (_name, mutate) => {
    const document = fullDocument();
    mutate(document);
    await expect(parseV7KeyDiscovery(JSON.stringify(document))).rejects.toThrow();
  });

  it.each([
    ['exchange descriptor', (document: ReturnType<typeof fullDocument>) => {
      document.native_exchange_v7!.retained_descriptors = [document.native_exchange_v7!.active_descriptors[0]];
    }],
    ['exchange keyset', (document: ReturnType<typeof fullDocument>) => {
      document.native_exchange_v7!.retained_keysets = [document.native_exchange_v7!.active_keysets[0]];
    }],
    ['exchange transition', (document: ReturnType<typeof fullDocument>) => {
      document.native_exchange_v7!.transitions.push(document.native_exchange_v7!.transitions[0]);
    }],
    ['graph policy', (document: ReturnType<typeof fullDocument>) => {
      document.native_graph_issuance_v7!.retained_policies = [document.native_graph_issuance_v7!.active_policies[0]];
    }],
  ])('rejects repeated entries within the same %s role', async (_name, mutate) => {
    const document = fullDocument();
    mutate(document);
    await expect(parseV7KeyDiscovery(JSON.stringify(document))).rejects.toThrow();
  });

  it.each([
    ['duplicate slot ID', (document: ReturnType<typeof fullDocument>) => {
      const transition = document.native_exchange_v7!.transitions[0];
      transition.output_slots[0].slot_id = transition.source_slots[0].slot_id;
    }],
    ['duplicate descriptor membership', (document: ReturnType<typeof fullDocument>) => {
      const transition = document.native_exchange_v7!.transitions[0];
      transition.source_slots.push({ ...transition.source_slots[0], slot_id: 'second-input' });
    }],
    ['too many slots', (document: ReturnType<typeof fullDocument>) => {
      const transition = document.native_exchange_v7!.transitions[0];
      transition.source_slots.push(...Array.from({ length: 64 }, (_, index) => ({
        ...transition.source_slots[0], slot_id: `extra-${index}`,
      })));
    }],
  ])('rejects transition %s', async (_name, mutate) => {
    const document = fullDocument();
    mutate(document);
    await expect(parseV7KeyDiscovery(JSON.stringify(document))).rejects.toThrow();
  });

  it('rejects a conflicting graph role and a graph policy without an exchange role', async () => {
    const conflicting = fullDocument();
    const policy = conflicting.native_graph_issuance_v7!.active_policies[0];
    policy.asset_id = 'EUR';
    await expect(parseV7KeyDiscovery(JSON.stringify(conflicting))).rejects.toThrow();

    const unlinked = fullDocument();
    delete unlinked.native_exchange_v7;
    await expect(parseV7KeyDiscovery(JSON.stringify(unlinked))).rejects.toThrow();
  });

  it('binds refreshes to the established issuer and rolls back failed refreshes', async () => {
    const first = documentFor('issuer:first');
    const second = documentFor('issuer:second');
    const state = createClientState({ issuerUrl: 'https://issuer.example', fetch: vi.fn() });
    state.metadata = { issuer_id: 'issuer:first', voprf: first.voprf };
    state.v7KeyDiscoveryMetadata = await parseV7KeyDiscovery(JSON.stringify(first));
    state.v7KeyDiscoveryMetadataFetchedAt = Date.now();
    const before = state.v7KeyDiscoveryMetadata;
    const beforeRegistry = await materializeV7Registry(state.v7KeyDiscoveryMetadata);
    state.v7Registry = beforeRegistry;
    const beforeFetchedAt = state.v7KeyDiscoveryMetadataFetchedAt;
    const beforePin = state.issuerIdentityPin;
    state.config.fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(second)));
    await expect(refreshV7KeyDiscoveryMetadata(state)).rejects.toThrow(/issuer identity/);
    expect(state.v7KeyDiscoveryMetadata).toBe(before);
    expect(state.v7Registry).toBe(beforeRegistry);
    expect(state.v7KeyDiscoveryMetadataFetchedAt).toBe(beforeFetchedAt);
    expect(state.issuerIdentityPin).toBe(beforePin);
  });

  it('pins one issuer across V4-before/after-V7 discovery without losing either state', async () => {
    const v4 = { issuer_id: 'issuer:shared', current_epoch: 1, epoch_duration_sec: 86400,
      voprf: { suite: 'VOPRF-P256-SHA256', kid: 'kid', pubkey: 'pubkey' } };
    const v7 = fullDocument('issuer:shared');
    const first = createClientState({ issuerUrl: 'https://issuer.example', fetch: vi.fn() });
    first.config.fetch = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify(v4)))
      .mockResolvedValueOnce(new Response(JSON.stringify(v7)));
    await refreshKeyDiscoveryMetadata(first);
    const legacyBefore = first.keyDiscoveryMetadata;
    await refreshV7KeyDiscoveryMetadata(first);
    expect(first.issuerIdentityPin).toBe('issuer:shared');
    expect(first.keyDiscoveryMetadata).toBe(legacyBefore);
    expect(first.v7KeyDiscoveryMetadata?.issuer_id).toBe('issuer:shared');

    const second = createClientState({ issuerUrl: 'https://issuer.example', fetch: vi.fn() });
    second.config.fetch = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify(v7)))
      .mockResolvedValueOnce(new Response(JSON.stringify(v4)));
    await refreshV7KeyDiscoveryMetadata(second);
    const v7Before = second.v7KeyDiscoveryMetadata;
    await refreshKeyDiscoveryMetadata(second);
    expect(second.issuerIdentityPin).toBe('issuer:shared');
    expect(second.v7KeyDiscoveryMetadata).toBe(v7Before);
    expect(second.keyDiscoveryMetadata?.issuer_id).toBe('issuer:shared');

    const mismatch = createClientState({ issuerUrl: 'https://issuer.example', fetch: vi.fn() });
    mismatch.config.fetch = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify(v7)));
    await refreshV7KeyDiscoveryMetadata(mismatch);
    const mismatchV7 = mismatch.v7KeyDiscoveryMetadata;
    mismatch.config.fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...v4, issuer_id: 'issuer:other' })));
    await expect(refreshKeyDiscoveryMetadata(mismatch)).rejects.toThrow(/issuer identity/);
    expect(mismatch.v7KeyDiscoveryMetadata).toBe(mismatchV7);
    expect(mismatch.keyDiscoveryMetadata).toBeNull();
    expect(mismatch.issuerIdentityPin).toBe('issuer:shared');
  });
});
