// SPDX-License-Identifier: Apache-2.0 OR MIT

import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';
import * as voprf from '../crypto/voprf.js';
import type {
  ExchangeDiscoveryMetadata,
  ExchangeGraphInfo,
  ExchangeReceiptKeyInfo,
  ExchangeTransitionSelection,
  IssuerMetadata,
  KeyDiscoveryMetadata,
  VerifierMetadata,
} from '../types.js';
import type { ClientState } from './state.js';
import {
  ascii,
  bytesToBase64Url,
  decodeCanonical,
  domainHex,
  hasExactKeys,
  hex,
  isBoundedAscii,
  isCanonicalBase64Url,
  isLowerHexId,
  isSafePositive,
  pushI64,
  pushU32,
  pushU64,
  put,
} from './wire.js';

export async function init(state: ClientState): Promise<void> {
  if (state.metadata && state.verifierMetadata) return;

  if (!state.metadata) {
    const url = `${state.config.issuerUrl}/.well-known/issuer`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Failed to fetch issuer metadata: ${res.status} ${res.statusText}`);
    }
    state.metadata = (await res.json()) as IssuerMetadata;
  }

  if (!state.verifierMetadata) {
    if (state.config.verifierUrl) {
      const url = `${state.config.verifierUrl}/.well-known/verifier`;
      const res = await fetch(url);
      if (!res.ok) {
        throw new Error(`Failed to fetch verifier metadata: ${res.status} ${res.statusText}`);
      }
      state.verifierMetadata = (await res.json()) as VerifierMetadata;
    } else if (state.config.verifierId && state.config.audience) {
      state.verifierMetadata = {
        verifier_id: state.config.verifierId,
        audience: state.config.audience,
        scope_digest_b64: bytesToBase64Url(
          voprf.buildScopeDigest(state.config.verifierId, state.config.audience),
        ),
      };
    } else {
      throw new Error('Verifier scope required: configure verifierUrl or verifierId+audience');
    }
  }
}

export async function getKeyDiscoveryMetadata(state: ClientState): Promise<KeyDiscoveryMetadata> {
  if (state.keyDiscoveryMetadata) return state.keyDiscoveryMetadata;
  return fetchKeyDiscoveryMetadata(state);
}

export async function refreshKeyDiscoveryMetadata(state: ClientState): Promise<KeyDiscoveryMetadata> {
  return fetchKeyDiscoveryMetadata(state);
}

async function fetchKeyDiscoveryMetadata(state: ClientState): Promise<KeyDiscoveryMetadata> {
  const url = `${state.config.issuerUrl}/.well-known/keys`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch issuer key metadata: ${res.status} ${res.statusText}`);
  }
  const metadata = (await res.json()) as KeyDiscoveryMetadata;
  if (metadata.exchange !== undefined) {
    await validateExchangeDiscovery(metadata.issuer_id, metadata.exchange);
  }
  if (metadata.graph_issuance !== undefined) {
    if (!metadata.exchange) throw new Error('Invalid graph issuance discovery metadata');
    validateGraphIssuanceDiscovery(metadata.graph_issuance, metadata.exchange);
  }
  state.keyDiscoveryMetadata = metadata;
  return state.keyDiscoveryMetadata;
}

export async function selectExchangeTransition(
  getMetadata: () => Promise<KeyDiscoveryMetadata>,
  graphId: string,
  transitionId: string,
): Promise<ExchangeTransitionSelection> {
  const metadata = await getMetadata();
  if (!metadata.exchange) throw new Error('Issuer does not publish V2 exchange discovery');
  const graph = [metadata.exchange.active_graph, ...metadata.exchange.retained_graphs]
    .find((candidate) => candidate.graph_id === graphId);
  const transition = graph?.transitions.find((candidate) => candidate.transition_id === transitionId);
  if (!graph || !transition) throw new Error('Unknown exchange graph or transition');
  return { graph, transition };
}

function validateGraphIssuanceDiscovery(
  issuance: NonNullable<KeyDiscoveryMetadata['graph_issuance']>,
  exchange: ExchangeDiscoveryMetadata,
): void {
  const invalid = (): never => { throw new Error('Invalid graph issuance discovery metadata'); };
  if (!hasExactKeys(issuance, ['version', 'policies', 'replay_authority']) ||
    issuance.version !== 2 || !Array.isArray(issuance.policies) || issuance.policies.length > 64 ||
    !hasExactKeys(issuance.replay_authority, ['authority_id', 'v4_scope_digest_tombstones']) ||
    !isCanonicalBase64Url(issuance.replay_authority.authority_id, 32) ||
    !Array.isArray(issuance.replay_authority.v4_scope_digest_tombstones) ||
    issuance.replay_authority.v4_scope_digest_tombstones.length > 64) invalid();

  const tombstones = new Set<string>();
  for (const tombstone of issuance.replay_authority.v4_scope_digest_tombstones) {
    if (!isCanonicalBase64Url(tombstone, 32) || tombstones.has(tombstone)) invalid();
    tombstones.add(tombstone);
  }
  const ids = new Set<string>();
  const budgets = new Set<string>();
  for (const policy of issuance.policies) {
    if (typeof policy !== 'object' || policy === null || Array.isArray(policy)) invalid();
    const policyKeys = Object.prototype.hasOwnProperty.call(policy, 'authorization_scope_digest_b64')
      ? [
          'issuance_policy_id', 'graph_id', 'keyset_id', 'descriptor_id', 'budget_id',
          'budget_limit', 'quantity', 'admission_state', 'authorization_scheme',
          'authorization_scope_digest_b64',
        ]
      : [
          'issuance_policy_id', 'graph_id', 'keyset_id', 'descriptor_id', 'budget_id',
          'budget_limit', 'quantity', 'admission_state', 'authorization_scheme',
        ];
    if (!hasExactKeys(policy, policyKeys) ||
      !isBoundedAscii(policy.issuance_policy_id) || !isLowerHexId(policy.graph_id) ||
      !isLowerHexId(policy.keyset_id) || !isLowerHexId(policy.descriptor_id) ||
      !isBoundedAscii(policy.budget_id) || !isSafePositive(policy.budget_limit) ||
      !isSafePositive(policy.quantity) || policy.quantity !== 1 ||
      policy.quantity > policy.budget_limit ||
      !['accepting_new', 'recovery_only', 'disabled'].includes(policy.admission_state) ||
      !isBoundedAscii(policy.authorization_scheme) ||
      !['hmac_sha256', 'v4_local', 'development_mock'].includes(policy.authorization_scheme) ||
      ids.has(policy.issuance_policy_id) || budgets.has(policy.budget_id)) invalid();
    const active = exchange.active_graph.graph_id === policy.graph_id;
    const graph = [exchange.active_graph, ...exchange.retained_graphs]
      .find((candidate) => candidate.graph_id === policy.graph_id);
    const keyset = graph?.keysets.find((candidate) => candidate.keyset_id === policy.keyset_id);
    if (!keyset?.descriptor_ids.includes(policy.descriptor_id) ||
      (policy.admission_state === 'accepting_new' && !active)) invalid();
    if (policy.authorization_scheme === 'v4_local') {
      if (typeof policy.authorization_scope_digest_b64 !== 'string' ||
        !isCanonicalBase64Url(policy.authorization_scope_digest_b64, 32) ||
        !tombstones.has(policy.authorization_scope_digest_b64)) invalid();
    } else if (policy.authorization_scope_digest_b64 !== undefined) invalid();
    ids.add(policy.issuance_policy_id);
    budgets.add(policy.budget_id);
  }
}

async function validateExchangeDiscovery(
  issuerId: string,
  discovery: ExchangeDiscoveryMetadata,
): Promise<void> {
  const invalid = (): never => { throw new Error('Invalid V2 exchange discovery metadata'); };
  if (!hasExactKeys(discovery, [
    'active_graph', 'retained_graphs', 'active_receipt_key', 'retained_receipt_keys',
  ]) || !Array.isArray(discovery.retained_graphs) ||
    !Array.isArray(discovery.retained_receipt_keys) ||
    discovery.retained_graphs.length >= 64 || discovery.retained_receipt_keys.length >= 64) invalid();

  const graphs = [discovery.active_graph, ...discovery.retained_graphs];
  const graphIds = new Set<string>();
  const descriptorContracts = new Map<string, string>();
  const budgetContracts = new Map<string, string>();
  for (let graphIndex = 0; graphIndex < graphs.length; graphIndex++) {
    const graph = graphs[graphIndex];
    const retained = graphIndex > 0;
    if (!hasExactKeys(graph, ['profile_id', 'graph_id', 'descriptors', 'keysets', 'transitions']) ||
      graph.profile_id !== 'freebird/public-bearer-exchange/v2' ||
      !Array.isArray(graph.descriptors) || !Array.isArray(graph.keysets) ||
      !Array.isArray(graph.transitions) || graph.descriptors.length === 0 ||
      graph.descriptors.length > 64 || graph.keysets.length === 0 || graph.keysets.length > 64 ||
      graph.transitions.length === 0 || graph.transitions.length > 64 ||
      !isLowerHexId(graph.graph_id) || graphIds.has(graph.graph_id)) invalid();
    graphIds.add(graph.graph_id);

    const descriptors = new Map<string, ExchangeGraphInfo['descriptors'][number]>();
    const graphTokenKeys = new Set<string>();
    for (const descriptor of graph.descriptors) {
      const descriptorKeys = Object.prototype.hasOwnProperty.call(descriptor, 'audience')
        ? ['descriptor_id', 'profile_id', 'issuer_id', 'token_key_id', 'audience',
            'pubkey_spki_b64', 'suite', 'valid_from', 'valid_until']
        : ['descriptor_id', 'profile_id', 'issuer_id', 'token_key_id',
            'pubkey_spki_b64', 'suite', 'valid_from', 'valid_until'];
      if (!hasExactKeys(descriptor, descriptorKeys) ||
        !isLowerHexId(descriptor.descriptor_id) || descriptor.profile_id !== graph.profile_id ||
        descriptor.issuer_id !== issuerId || !isLowerHexId(descriptor.token_key_id) ||
        descriptor.suite !== 'RSABSSA-SHA384-PSS-Deterministic' ||
        !isSafePositive(descriptor.valid_from) || !isSafePositive(descriptor.valid_until) ||
        descriptor.valid_from >= descriptor.valid_until ||
        (descriptor.audience !== undefined && !isBoundedAscii(descriptor.audience)) ||
        descriptors.has(descriptor.descriptor_id) || graphTokenKeys.has(descriptor.token_key_id)) invalid();
      const spki = decodeCanonical(descriptor.pubkey_spki_b64, undefined, 4096, 1);
      if (hex(sha256(spki)) !== descriptor.token_key_id) invalid();
      const pssOid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
      if (spki.length > 800 || spki.length <= 72 ||
        !pssOid.every((byte, index) => spki[index + 6] === byte) || spki[17] !== 0x30) invalid();
      try {
        const rawOffset = spki[5] + 10;
        if (spki.length <= rawOffset) invalid();
        const raw = spki.slice(rawOffset);
        const standardHeader = new Uint8Array([
          0x30, 0x82, 0, 0, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
          0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0, 0,
        ]);
        standardHeader[2] = (raw.length + 19) >>> 8;
        standardHeader[3] = (raw.length + 19) & 0xff;
        standardHeader[21] = raw.length >>> 8;
        standardHeader[22] = raw.length & 0xff;
        const standardSpki = new Uint8Array(standardHeader.length + raw.length);
        standardSpki.set(standardHeader);
        standardSpki.set(raw, standardHeader.length);
        const publicKey = await crypto.subtle.importKey(
          'spki',
          new Uint8Array(standardSpki).buffer as ArrayBuffer,
          { name: 'RSA-PSS', hash: 'SHA-384' },
          false,
          ['verify'],
        );
        const algorithm = publicKey.algorithm as RsaHashedKeyAlgorithm;
        const exponent = Array.from(algorithm.publicExponent)
          .reduce((value, byte) => value * 256 + byte, 0);
        if (algorithm.modulusLength < 2048 || algorithm.modulusLength > 4096 ||
          (exponent !== 3 && exponent !== 65537)) invalid();
      } catch { invalid(); }
      if (domainHex('freebird exchange descriptor v2\0', descriptorBytes(descriptor)) !==
        descriptor.descriptor_id) invalid();
      const contract = bytesToBase64Url(descriptorBytes(descriptor));
      const previous = descriptorContracts.get(descriptor.token_key_id);
      if (previous !== undefined && previous !== contract) invalid();
      descriptorContracts.set(descriptor.token_key_id, contract);
      descriptors.set(descriptor.descriptor_id, descriptor);
      graphTokenKeys.add(descriptor.token_key_id);
    }

    const keysets = new Map<string, Set<string>>();
    const memberships = new Set<string>();
    for (const keyset of graph.keysets) {
      if (!hasExactKeys(keyset, ['keyset_id', 'descriptor_ids']) ||
        !isLowerHexId(keyset.keyset_id) || !Array.isArray(keyset.descriptor_ids) ||
        keyset.descriptor_ids.length === 0 || keyset.descriptor_ids.length > 64 ||
        keysets.has(keyset.keyset_id)) invalid();
      const members = new Set<string>();
      for (const descriptorId of keyset.descriptor_ids) {
        if (typeof descriptorId !== 'string' || !descriptors.has(descriptorId) ||
          members.has(descriptorId) || memberships.has(descriptorId)) invalid();
        members.add(descriptorId);
        memberships.add(descriptorId);
      }
      const keysetBytes: number[] = [];
      for (const descriptorId of keyset.descriptor_ids) put(keysetBytes, ascii(descriptorId));
      if (domainHex('freebird exchange keyset v2\0', new Uint8Array(keysetBytes)) !== keyset.keyset_id) invalid();
      keysets.set(keyset.keyset_id, members);
    }
    if (memberships.size !== descriptors.size) invalid();

    const transitionIds = new Set<string>();
    const graphBudgetIds = new Set<string>();
    for (const transition of graph.transitions) {
      if (!hasExactKeys(transition, [
        'transition_id', 'source_keyset_id', 'target_keyset_id', 'source_slots',
        'output_slots', 'budget_id', 'budget_limit', 'admission_state',
      ]) || !isLowerHexId(transition.transition_id) ||
        !isLowerHexId(transition.source_keyset_id) || !isLowerHexId(transition.target_keyset_id) ||
        transition.source_keyset_id === transition.target_keyset_id ||
        !keysets.has(transition.source_keyset_id) || !keysets.has(transition.target_keyset_id) ||
        !isBoundedAscii(transition.budget_id) || !isSafePositive(transition.budget_limit) ||
        !['accepting_new', 'recovery_only', 'disabled'].includes(transition.admission_state) ||
        (retained && transition.admission_state === 'accepting_new') ||
        transitionIds.has(transition.transition_id) || graphBudgetIds.has(transition.budget_id)) invalid();
      validateDiscoverySlots(transition.source_slots, keysets.get(transition.source_keyset_id)!);
      validateDiscoverySlots(transition.output_slots, keysets.get(transition.target_keyset_id)!);
      const stable = transitionBytes(transition);
      if (domainHex('freebird exchange transition v2\0', stable) !== transition.transition_id) invalid();
      const contract = bytesToBase64Url(stable);
      const previous = budgetContracts.get(transition.budget_id);
      if (previous !== undefined && previous !== contract) invalid();
      budgetContracts.set(transition.budget_id, contract);
      transitionIds.add(transition.transition_id);
      graphBudgetIds.add(transition.budget_id);
      const outputQuantity = transition.output_slots.reduce((sum, slot) => sum + slot.quantity, 0);
      if (!Number.isSafeInteger(outputQuantity) || outputQuantity > transition.budget_limit) invalid();
    }

    const graphBytes: number[] = [];
    put(graphBytes, ascii(graph.profile_id));
    for (const keyset of graph.keysets) put(graphBytes, ascii(keyset.keyset_id));
    for (const transition of graph.transitions) put(graphBytes, ascii(transition.transition_id));
    if (domainHex('freebird exchange graph v2\0', new Uint8Array(graphBytes)) !== graph.graph_id) invalid();
  }

  const receiptIds = new Set<string>();
  validateReceiptDiscoveryKey(discovery.active_receipt_key, 'exchange_receipt_active', receiptIds);
  for (const key of discovery.retained_receipt_keys) {
    validateReceiptDiscoveryKey(key, 'exchange_receipt_retained', receiptIds);
  }
}

function validateDiscoverySlots(value: unknown, members: Set<string>): void {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
    throw new Error('Invalid V2 exchange discovery metadata');
  }
  const slotIds = new Set<string>();
  const descriptorIds = new Set<string>();
  for (const slot of value) {
    if (!hasExactKeys(slot, ['descriptor_id', 'slot_id', 'class', 'quantity']) ||
      typeof slot.descriptor_id !== 'string' || !isLowerHexId(slot.descriptor_id) ||
      typeof slot.slot_id !== 'string' || !isBoundedAscii(slot.slot_id) ||
      typeof slot.class !== 'string' || !isBoundedAscii(slot.class) ||
      !isSafePositive(slot.quantity) || slot.quantity > 64 ||
      !members.has(slot.descriptor_id) || slotIds.has(slot.slot_id) ||
      descriptorIds.has(slot.descriptor_id)) {
      throw new Error('Invalid V2 exchange discovery metadata');
    }
    slotIds.add(slot.slot_id);
    descriptorIds.add(slot.descriptor_id);
  }
}

function validateReceiptDiscoveryKey(
  key: ExchangeReceiptKeyInfo,
  purpose: ExchangeReceiptKeyInfo['purpose'],
  ids: Set<string>,
): void {
  if (!hasExactKeys(key, [
    'key_id', 'algorithm', 'purpose', 'public_key_b64', 'valid_from', 'valid_until',
  ]) || !isLowerHexId(key.key_id) || key.algorithm !== 'Ed25519' || key.purpose !== purpose ||
    !isSafePositive(key.valid_from) || !isSafePositive(key.valid_until) ||
    key.valid_from >= key.valid_until || ids.has(key.key_id)) {
    throw new Error('Invalid V2 exchange discovery metadata');
  }
  const publicKey = decodeCanonical(key.public_key_b64, 32);
  if (!ed25519.utils.isValidPublicKey(publicKey, false) || hex(sha256(publicKey)) !== key.key_id) {
    throw new Error('Invalid V2 exchange discovery metadata');
  }
  ids.add(key.key_id);
}

function descriptorBytes(descriptor: ExchangeGraphInfo['descriptors'][number]): Uint8Array {
  const output: number[] = [];
  for (const value of [descriptor.profile_id, descriptor.issuer_id, descriptor.token_key_id,
    descriptor.suite]) put(output, ascii(value));
  if (descriptor.audience === undefined) {
    output.push(0);
    put(output, new Uint8Array());
  } else {
    output.push(1);
    put(output, ascii(descriptor.audience));
  }
  put(output, decodeCanonical(descriptor.pubkey_spki_b64, undefined, 4096, 1));
  pushI64(output, descriptor.valid_from);
  pushI64(output, descriptor.valid_until);
  return new Uint8Array(output);
}

function transitionBytes(transition: ExchangeGraphInfo['transitions'][number]): Uint8Array {
  const output: number[] = [];
  put(output, ascii(transition.source_keyset_id));
  put(output, ascii(transition.target_keyset_id));
  for (const slots of [transition.source_slots, transition.output_slots]) {
    pushU32(output, slots.length);
    for (const slot of slots) {
      put(output, ascii(slot.descriptor_id));
      put(output, ascii(slot.slot_id));
      put(output, ascii(slot.class));
      pushU32(output, slot.quantity);
    }
  }
  put(output, ascii(transition.budget_id));
  pushU64(output, transition.budget_limit);
  return new Uint8Array(output);
}
