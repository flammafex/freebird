// SPDX-License-Identifier: Apache-2.0 OR MIT

import { sha256 } from '@noble/hashes/sha256';
import { parse, parseNumberAndBigInt } from 'lossless-json';
import { DiscoveryError } from '../errors.js';
import type {
  V7ExchangeDescriptor,
  V7ExchangeDiscovery,
  V7ExchangeKeyset,
  V7ExchangeProfile,
  V7ExchangeSlot,
  V7ExchangeTransition,
  V7DirectKeyDiscovery,
  V7GraphIssuanceDiscovery,
  V7GraphIssuancePolicy,
  V7KeyDiscoveryResp,
  V7NativeBearerKeyInfo,
  V7Registry,
  V7RegistryEntry,
  V7RegistryReference,
  V7RegistryRole,
} from '../types.js';
import { pinIssuerIdentity, type ClientState } from './state.js';
import { bytesToBase64Url } from './wire.js';

const DIRECT_PROFILE = 'scarcity/native-bearer/v7';
const EXCHANGE_PROFILE = 'freebird/native-exchange/v3';
const GRAPH_PROFILE = 'freebird/native-graph-issuance/v7';
const SUITE = 'RSABSSA-SHA384-PSS-Randomized-V7';
const MAX_SPKI_BYTES = 4096;
const MAX_TEXT = 128;
const MAX_ID = 64;
const MAX_U64 = (1n << 64n) - 1n;
const MAX_VALID_UNTIL = 9_007_199_254_740_991n;
const MAX_ITEMS = 64;
const RSA_ENCRYPTION_OID = Uint8Array.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);

function invalid(message = 'Invalid V7 key discovery metadata'): never {
  throw new DiscoveryError(message);
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}

function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const record = object(value);
  const actual = Object.keys(record);
  if (actual.length !== keys.length || keys.some((key) => !actual.includes(key))) invalid();
  return record;
}

function exactOptional(value: unknown, required: readonly string[], optional: readonly string[]): Record<string, unknown> {
  const record = object(value);
  const allowed = new Set([...required, ...optional]);
  const actual = Object.keys(record);
  if (required.some((key) => !actual.includes(key)) || actual.some((key) => !allowed.has(key))) invalid();
  return record;
}

function text(value: unknown, max = MAX_TEXT): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max &&
    /^[\x00-\x7f]+$/.test(value);
}

function id(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function positiveNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function nonnegativeNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function positiveU64(value: unknown): value is bigint {
  return typeof value === 'bigint' && value > 0n && value <= MAX_U64;
}

function validity(from: unknown, until: unknown, max = MAX_VALID_UNTIL): boolean {
  return typeof from === 'bigint' && typeof until === 'bigint' && from >= 0n && from < until && until <= max;
}

function canonicalB64(value: unknown, exactBytes?: number): Uint8Array {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) invalid();
  let bytes: Uint8Array;
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '=');
    const binary = atob(padded);
    bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    invalid();
  }
  if (bytesToBase64Url(bytes) !== value || bytes.length === 0 || bytes.length > MAX_SPKI_BYTES ||
    (exactBytes !== undefined && bytes.length !== exactBytes)) invalid();
  return bytes;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

/*
 * blind-rsa-signatures emits this exact RSASSA-PSS SPKI template.  Checking
 * the template, rather than deriving an identifier from it, catches alternate
 * DER encodings and keeps the advertised V7 token key ID authoritative.
 */
function canonicalV7Spki(bytes: Uint8Array): void {
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
  const sha384Oid = Uint8Array.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]);
  template.set(sha384Oid, 25);
  template.set(sha384Oid, 53);
  template[66] = 48;

  const rawStart = template.length;
  if (bytes.length <= rawStart || bytes.length > 800 || bytes[0] !== 0x30 || bytes[1] !== 0x82 ||
    ((bytes[2] << 8) | bytes[3]) !== bytes.length - 4) invalid('Invalid canonical V7 SPKI');
  const raw = bytes.slice(rawStart);
  if (raw.length !== 398 || raw[0] !== 0x30 || raw[1] !== 0x82 ||
    ((raw[2] << 8) | raw[3]) !== 394 || raw[4] !== 0x02 || raw[5] !== 0x82 ||
    ((raw[6] << 8) | raw[7]) !== 385 || raw[8] !== 0 || raw[9] < 0x80 ||
    raw[393] !== 0x02 || raw[394] !== 0x03 || raw[395] !== 0x01 ||
    raw[396] !== 0x00 || raw[397] !== 0x01) {
    invalid('Invalid V7 RSA-3072 SPKI');
  }
  template[2] = (bytes.length - 4) >>> 8;
  template[3] = (bytes.length - 4) & 0xff;
  template[69] = (raw.length + 1) >>> 8;
  template[70] = (raw.length + 1) & 0xff;
  if (!sameBytes(bytes.slice(0, template.length), template) || bytes.length !== template.length + raw.length) {
    invalid('Invalid canonical V7 SPKI');
  }
}

/** Convert the validated RFC9474 PSS SPKI to the rsaEncryption SPKI accepted by WebCrypto. */
function rsaEncryptionSpki(bytes: Uint8Array): Uint8Array {
  const templateLength = 72;
  const raw = bytes.slice(templateLength);
  const header = Uint8Array.from([
    0x30, 0x82, 0, 0,
    0x30, 0x0d, 0x06, 0x09, ...RSA_ENCRYPTION_OID, 0x05, 0x00,
    0x03, 0x82, 0, 0, 0,
  ]);
  const bitLength = raw.length + 1;
  header[2] = (header.length + raw.length - 4) >>> 8;
  header[3] = (header.length + raw.length - 4) & 0xff;
  header[19] = 0x03;
  header[20] = 0x82;
  header[21] = bitLength >>> 8;
  header[22] = bitLength & 0xff;
  const normalized = new Uint8Array(header.length + raw.length);
  normalized.set(header);
  normalized.set(raw, header.length);
  return normalized;
}

async function validateSpki(value: unknown, fingerprint: unknown): Promise<void> {
  const spki = canonicalB64(value);
  canonicalV7Spki(spki);
  if (typeof fingerprint !== 'string' || !id(fingerprint) ||
    bytesToHex(sha256(spki)) !== fingerprint) invalid('Invalid V7 SPKI fingerprint');
  try {
    const normalized = rsaEncryptionSpki(spki);
    const key = await crypto.subtle.importKey(
      'spki', new Uint8Array(normalized).buffer as ArrayBuffer, { name: 'RSA-PSS', hash: 'SHA-384' }, false, ['verify'],
    );
    const algorithm = key.algorithm as RsaHashedKeyAlgorithm;
    if (algorithm.name !== 'RSA-PSS' || algorithm.modulusLength !== 3072 ||
      !sameBytes(new Uint8Array(algorithm.publicExponent), Uint8Array.from([1, 0, 1]))) invalid('Invalid V7 RSA-3072 SPKI');
  } catch {
    invalid('Invalid V7 RSA-3072 SPKI');
  }
}

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function distinctIds(token: unknown, descriptor: unknown, fingerprint: unknown): void {
  if (!id(token) || !id(descriptor) || !id(fingerprint) ||
    new Set([token, descriptor, fingerprint]).size !== 3) invalid('V7 identifier collision');
}

function amountString(value: unknown): boolean {
  return typeof value === 'string' && /^[1-9][0-9]*$/.test(value) && BigInt(value) <= MAX_U64;
}

function lp(output: number[], value: string | Uint8Array): void {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  output.push((bytes.length >>> 24) & 0xff, (bytes.length >>> 16) & 0xff,
    (bytes.length >>> 8) & 0xff, bytes.length & 0xff, ...bytes);
}

function u16(output: number[], value: number): void {
  output.push((value >>> 8) & 0xff, value & 0xff);
}

function u32(output: number[], value: number): void {
  output.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function u64(output: number[], value: bigint | number): void {
  const integer = typeof value === 'bigint' ? value : BigInt(value);
  for (let shift = 56n; shift >= 0n; shift -= 8n) output.push(Number((integer >> shift) & 0xffn));
}

function domainId(domain: string, transcript: readonly number[]): string {
  return bytesToHex(sha256(new Uint8Array([
    ...new TextEncoder().encode(domain), ...transcript,
  ])));
}

/* These are the frozen V7 identity domains. Keep framing here byte-for-byte
 * aligned with the native V7 canonical contracts; IDs are not opaque labels. */
function directDescriptorId(record: Record<string, unknown>, spki: Uint8Array): string {
  const bytes: number[] = [];
  for (const value of [record.profile_id, record.issuer_id, record.token_key_id, record.asset_id,
    record.suite]) lp(bytes, value as string);
  u16(bytes, record.modulus_bits as number);
  u32(bytes, record.exponent as number);
  lp(bytes, spki);
  lp(bytes, record.spki_fingerprint as string);
  u64(bytes, record.amount_minor as bigint);
  u64(bytes, record.valid_from as bigint);
  u64(bytes, record.valid_until as bigint);
  return domainId('scarcity native bearer descriptor v7\0', bytes);
}

/** Compute the frozen canonical ID used by a direct V7 descriptor. */
export function canonicalV7DirectDescriptorId(record: Record<string, unknown>, spki: Uint8Array): string {
  return directDescriptorId(record, spki);
}

function exchangeDescriptorId(record: Record<string, unknown>, spki: Uint8Array): string {
  const bytes: number[] = [];
  for (const value of [record.profile_id, record.issuer_id, record.token_key_id, record.asset_id]) {
    lp(bytes, value as string);
  }
  u64(bytes, record.amount_minor as bigint);
  lp(bytes, record.suite as string);
  u16(bytes, record.modulus_bits as number);
  u32(bytes, record.exponent as number);
  lp(bytes, spki);
  lp(bytes, record.spki_fingerprint as string);
  u64(bytes, record.valid_from as bigint);
  u64(bytes, record.valid_until as bigint);
  return domainId('freebird native exchange descriptor v3\0', bytes);
}

/** Compute the frozen canonical ID used by an exchange V7 descriptor. */
export function canonicalV7ExchangeDescriptorId(record: Record<string, unknown>, spki: Uint8Array): string {
  return exchangeDescriptorId(record, spki);
}

function keysetId(descriptorIds: readonly string[]): string {
  const bytes: number[] = [];
  for (const descriptorId of descriptorIds) lp(bytes, descriptorId);
  return domainId('freebird native exchange keyset v3\0', bytes);
}

/** Compute the frozen canonical ordered keyset ID. */
export function canonicalV7KeysetId(descriptorIds: readonly string[]): string {
  return keysetId(descriptorIds);
}

function transitionId(record: Record<string, unknown>): string {
  const bytes: number[] = [];
  lp(bytes, record.source_keyset_id as string);
  lp(bytes, record.target_keyset_id as string);
  for (const slots of [record.source_slots, record.output_slots] as unknown[][]) {
    u32(bytes, slots.length);
    for (const value of slots) {
      const slot = value as Record<string, unknown>;
      lp(bytes, slot.descriptor_id as string);
      lp(bytes, slot.keyset_id as string);
      lp(bytes, slot.slot_id as string);
      u32(bytes, slot.quantity as number);
    }
  }
  return domainId('freebird native exchange transition v3\0', bytes);
}

/** Compute the frozen canonical directed transition ID. */
export function canonicalV7TransitionId(record: Record<string, unknown>): string {
  return transitionId(record);
}

function graphId(record: Record<string, unknown>): string {
  const profile = record.profile as Record<string, unknown>;
  const bytes: number[] = [];
  lp(bytes, profile.profile_id as string);
  for (const keyset of [...record.active_keysets as unknown[], ...record.retained_keysets as unknown[]]) {
    lp(bytes, (keyset as Record<string, unknown>).keyset_id as string);
  }
  for (const transition of record.transitions as unknown[]) {
    lp(bytes, (transition as Record<string, unknown>).transition_id as string);
  }
  return domainId('freebird native exchange graph v3\0', bytes);
}

/** Compute the frozen canonical exchange graph ID. */
export function canonicalV7GraphId(record: Record<string, unknown>): string {
  return graphId(record);
}

function graphPolicyId(record: Record<string, unknown>, spki: Uint8Array): string {
  const bytes: number[] = [];
  for (const value of [record.profile_id, record.graph_id, record.keyset_id, record.descriptor_id,
    record.token_key_id, record.issuer_id, record.asset_id, record.amount_minor, record.suite]) {
    lp(bytes, value as string);
  }
  u16(bytes, record.modulus_bits as number);
  u32(bytes, record.exponent as number);
  u32(bytes, record.quantity as number);
  lp(bytes, spki);
  lp(bytes, record.spki_fingerprint as string);
  u64(bytes, record.valid_from as bigint);
  u64(bytes, record.valid_until as bigint);
  return domainId('freebird native graph issuance policy v7\0', bytes);
}

function validateGraphLinks(exchange: V7ExchangeDiscovery | undefined, graph: V7GraphIssuanceDiscovery): void {
  if (!exchange) invalid('V7 graph issuance requires native exchange discovery');
  const descriptors = new Map<string, V7ExchangeDescriptor>();
  for (const descriptor of [...exchange.active_descriptors, ...exchange.retained_descriptors]) {
    descriptors.set(descriptor.descriptor_id, descriptor);
  }
  const keysets = new Map<string, V7ExchangeKeyset>();
  for (const keyset of [...exchange.active_keysets, ...exchange.retained_keysets]) {
    keysets.set(keyset.keyset_id, keyset);
  }
  for (const policy of [...graph.active_policies, ...graph.retained_policies]) {
    const descriptor = descriptors.get(policy.descriptor_id);
    const keyset = keysets.get(policy.keyset_id);
    if (!descriptor || !keyset || policy.graph_id !== exchange.profile.graph_id ||
      !keyset.descriptor_ids.includes(policy.descriptor_id) ||
      policy.token_key_id !== descriptor.token_key_id || policy.asset_id !== descriptor.asset_id ||
      policy.amount_minor !== descriptor.amount_minor || policy.suite !== descriptor.suite ||
      policy.modulus_bits !== descriptor.modulus_bits || policy.exponent !== descriptor.exponent ||
      policy.pubkey_spki_b64 !== descriptor.pubkey_spki_b64 ||
      policy.spki_fingerprint !== descriptor.spki_fingerprint ||
      policy.valid_from !== descriptor.valid_from || policy.valid_until !== descriptor.valid_until) {
      invalid('Unlinked V7 graph issuance policy');
    }
  }
}

/** Compute the frozen canonical graph-issuance policy ID. */
export function canonicalV7GraphPolicyId(record: Record<string, unknown>, spki: Uint8Array): string {
  return graphPolicyId(record, spki);
}

type RegistryRecord = V7NativeBearerKeyInfo | V7ExchangeDescriptor | V7GraphIssuancePolicy;

function registryBinding(record: RegistryRecord, issuerId: string): V7RegistryEntry {
  return {
    profile_id: record.profile_id,
    issuer_id: issuerId,
    descriptor_id: record.descriptor_id,
    token_key_id: record.token_key_id,
    spki_fingerprint: record.spki_fingerprint,
    pubkey_spki_b64: record.pubkey_spki_b64,
    asset_id: record.asset_id,
    amount_minor: typeof record.amount_minor === 'bigint' ? record.amount_minor : BigInt(record.amount_minor),
    suite: record.suite,
    modulus_bits: record.modulus_bits,
    exponent: record.exponent,
    valid_from: record.valid_from,
    valid_until: record.valid_until,
    roles: [],
    references: [],
    identity: Object.freeze({ issuer_id: issuerId, token_key_id: record.token_key_id,
      __freebirdV7KeyIdentity: true as const }),
    __freebirdV7KeyBinding: true as const,
  } as unknown as V7RegistryEntry;
}

function registryReference(record: RegistryRecord, role: V7RegistryRole): V7RegistryReference {
  if (role === 'graph_issuance') {
    const policy = record as V7GraphIssuancePolicy;
    return Object.freeze({ role, descriptor_id: policy.descriptor_id, policy_id: policy.policy_id,
      graph_id: policy.graph_id, keyset_id: policy.keyset_id });
  }
  return Object.freeze({ role, descriptor_id: record.descriptor_id });
}

function sameBinding(left: V7RegistryEntry, right: V7RegistryEntry): boolean {
  return left.issuer_id === right.issuer_id && left.token_key_id === right.token_key_id &&
    left.spki_fingerprint === right.spki_fingerprint && left.pubkey_spki_b64 === right.pubkey_spki_b64 &&
    left.asset_id === right.asset_id && left.amount_minor === right.amount_minor &&
    left.suite === right.suite && left.modulus_bits === right.modulus_bits && left.exponent === right.exponent &&
    left.valid_from === right.valid_from && left.valid_until === right.valid_until;
}

async function validateDirect(record: unknown, issuerId: string): Promise<V7NativeBearerKeyInfo> {
  const raw = exact(record, [
    'profile_id', 'issuer_id', 'descriptor_id', 'token_key_id', 'asset_id', 'amount_minor',
    'suite', 'modulus_bits', 'exponent', 'pubkey_spki_b64', 'spki_fingerprint',
    'valid_from', 'valid_until',
  ]);
  if (raw.profile_id !== DIRECT_PROFILE || raw.issuer_id !== issuerId || !text(raw.issuer_id) ||
    !id(raw.descriptor_id) || !id(raw.token_key_id) || !text(raw.asset_id) ||
    !positiveU64(raw.amount_minor) || raw.suite !== SUITE || raw.modulus_bits !== 3072 ||
    raw.exponent !== 65537 || !id(raw.spki_fingerprint) || !validity(raw.valid_from, raw.valid_until) ||
    (raw.valid_from as bigint) <= 0n) invalid();
  distinctIds(raw.token_key_id, raw.descriptor_id, raw.spki_fingerprint);
  const spki = canonicalB64(raw.pubkey_spki_b64);
  if (directDescriptorId(raw, spki) !== raw.descriptor_id) invalid('Non-canonical V7 direct descriptor ID');
  await validateSpki(raw.pubkey_spki_b64, raw.spki_fingerprint);
  return Object.freeze(raw) as unknown as V7NativeBearerKeyInfo;
}

function validateSlot(record: unknown, descriptorIds: ReadonlySet<string>, keysetId: string): V7ExchangeSlot {
  const raw = exact(record, ['descriptor_id', 'keyset_id', 'slot_id', 'quantity']);
  if (!id(raw.descriptor_id) || raw.keyset_id !== keysetId || !text(raw.slot_id) || raw.quantity !== 1 ||
    !descriptorIds.has(raw.descriptor_id)) invalid('Invalid V7 exchange slot');
  return Object.freeze(raw) as unknown as V7ExchangeSlot;
}

function validateSlotArray(
  slots: unknown[],
  descriptorIds: ReadonlySet<string>,
  keysetId: string,
  slotIds: Set<string>,
  descriptorMembership: Set<string>,
): V7ExchangeSlot[] {
  if (slots.length === 0 || slots.length > MAX_ITEMS) invalid('Invalid V7 exchange slot array');
  const validated: V7ExchangeSlot[] = [];
  for (const value of slots) {
    const slot = validateSlot(value, descriptorIds, keysetId);
    if (slotIds.has(slot.slot_id) || descriptorMembership.has(slot.descriptor_id)) {
      invalid('Duplicate V7 exchange slot membership');
    }
    slotIds.add(slot.slot_id);
    descriptorMembership.add(slot.descriptor_id);
    validated.push(slot);
  }
  return validated;
}

async function validateExchange(record: unknown, issuerId: string): Promise<V7ExchangeDiscovery> {
  const raw = exact(record, [
    'version', 'profile', 'active_descriptors', 'retained_descriptors', 'active_keysets',
    'retained_keysets', 'transitions',
  ]);
  if (raw.version !== 3 || !Array.isArray(raw.active_descriptors) || !Array.isArray(raw.retained_descriptors) ||
    !Array.isArray(raw.active_keysets) || !Array.isArray(raw.retained_keysets) || !Array.isArray(raw.transitions) ||
    raw.active_descriptors.length > MAX_ITEMS || raw.retained_descriptors.length > MAX_ITEMS ||
    raw.active_keysets.length > MAX_ITEMS || raw.retained_keysets.length > MAX_ITEMS || raw.transitions.length > MAX_ITEMS) invalid('Invalid V7 exchange discovery');
  const profileRaw = exact(raw.profile, ['version', 'profile_id', 'graph_id', 'suite', 'modulus_bits', 'exponent']);
  if (profileRaw.version !== 3 || profileRaw.profile_id !== EXCHANGE_PROFILE || !id(profileRaw.graph_id) ||
    profileRaw.suite !== SUITE || profileRaw.modulus_bits !== 3072 || profileRaw.exponent !== 65537) invalid('Invalid V7 exchange profile');

  const descriptors: V7ExchangeDescriptor[] = [];
  const descriptorIdsSeen = new Set<string>();
  const descriptorKeysSeen = new Set<string>();
  for (const value of [...raw.active_descriptors, ...raw.retained_descriptors]) {
    const descriptor = exact(value, [
      'descriptor_id', 'profile_id', 'issuer_id', 'token_key_id', 'asset_id', 'amount_minor', 'suite',
      'modulus_bits', 'exponent', 'pubkey_spki_b64', 'spki_fingerprint', 'valid_from', 'valid_until',
    ]);
    if (descriptor.profile_id !== EXCHANGE_PROFILE || descriptor.issuer_id !== issuerId || !text(descriptor.issuer_id) ||
      !id(descriptor.descriptor_id) || !id(descriptor.token_key_id) || !text(descriptor.asset_id) ||
      !amountString(descriptor.amount_minor) || descriptor.suite !== SUITE || descriptor.modulus_bits !== 3072 ||
      descriptor.exponent !== 65537 || !id(descriptor.spki_fingerprint) ||
      !validity(descriptor.valid_from, descriptor.valid_until)) invalid('Invalid V7 exchange descriptor');
    distinctIds(descriptor.token_key_id, descriptor.descriptor_id, descriptor.spki_fingerprint);
    const spki = canonicalB64(descriptor.pubkey_spki_b64);
    if (exchangeDescriptorId(descriptor, spki) !== descriptor.descriptor_id ||
      descriptorIdsSeen.has(descriptor.descriptor_id) || descriptorKeysSeen.has(descriptor.token_key_id)) {
      invalid('Non-canonical or duplicate V7 exchange descriptor');
    }
    descriptorIdsSeen.add(descriptor.descriptor_id);
    descriptorKeysSeen.add(descriptor.token_key_id);
    await validateSpki(descriptor.pubkey_spki_b64, descriptor.spki_fingerprint);
    descriptors.push(Object.freeze(descriptor) as unknown as V7ExchangeDescriptor);
  }
  const descriptorIds = new Set<string>(descriptors.map((descriptor) => descriptor.descriptor_id));
  const keysets: V7ExchangeKeyset[] = [];
  const keysetIdsSeen = new Set<string>();
  for (const value of [...raw.active_keysets, ...raw.retained_keysets]) {
    const keyset = exact(value, ['keyset_id', 'profile_id', 'descriptor_ids']);
    if (!id(keyset.keyset_id) || keyset.profile_id !== EXCHANGE_PROFILE || !Array.isArray(keyset.descriptor_ids) ||
      keyset.descriptor_ids.length === 0 || keyset.descriptor_ids.length > MAX_ITEMS ||
      new Set(keyset.descriptor_ids).size !== keyset.descriptor_ids.length ||
      keyset.descriptor_ids.some((descriptorId) => !id(descriptorId) || !descriptorIds.has(descriptorId)) ||
      keysetIdsSeen.has(keyset.keyset_id) || keyset.keyset_id !== keysetId(keyset.descriptor_ids as string[])) invalid('Invalid V7 exchange keyset');
    keysetIdsSeen.add(keyset.keyset_id);
    keysets.push(Object.freeze({ ...keyset, descriptor_ids: Object.freeze([...keyset.descriptor_ids]) }) as unknown as V7ExchangeKeyset);
  }
  const keysetIds = new Set<string>(keysets.map((keyset) => keyset.keyset_id));
  const transitions: V7ExchangeTransition[] = [];
  const transitionIdsSeen = new Set<string>();
  for (const value of raw.transitions) {
    const transition = exact(value, ['transition_id', 'profile_id', 'source_keyset_id', 'target_keyset_id', 'source_slots', 'output_slots']);
    if (!id(transition.transition_id) || transition.profile_id !== EXCHANGE_PROFILE || !id(transition.source_keyset_id) ||
      !id(transition.target_keyset_id) || transition.source_keyset_id === transition.target_keyset_id ||
      !keysetIds.has(transition.source_keyset_id) || !keysetIds.has(transition.target_keyset_id) ||
       !Array.isArray(transition.source_slots) || !Array.isArray(transition.output_slots) ||
       transitionIdsSeen.has(transition.transition_id)) invalid('Invalid V7 exchange transition');
     const sourceKeysetId = transition.source_keyset_id as string;
     const targetKeysetId = transition.target_keyset_id as string;
     if (transition.source_slots.length + transition.output_slots.length > MAX_ITEMS) {
       invalid('V7 exchange transition has too many slots');
     }
     const sourceSet = new Set<string>(keysets.find((keyset) => keyset.keyset_id === sourceKeysetId)!.descriptor_ids);
    const outputSet = new Set<string>(keysets.find((keyset) => keyset.keyset_id === targetKeysetId)!.descriptor_ids);
     const slotIds = new Set<string>();
     const descriptorMembership = new Set<string>();
     const sourceSlots = validateSlotArray(transition.source_slots, sourceSet, sourceKeysetId, slotIds, descriptorMembership);
     const outputSlots = validateSlotArray(transition.output_slots, outputSet, targetKeysetId, slotIds, descriptorMembership);
     transitions.push(Object.freeze({ ...transition,
       source_slots: Object.freeze(sourceSlots),
       output_slots: Object.freeze(outputSlots),
     }) as unknown as V7ExchangeTransition);
    transitionIdsSeen.add(transition.transition_id);
    if (transitionId(transition) !== transition.transition_id) invalid('Non-canonical V7 exchange transition ID');
  }
  if (graphId(raw) !== profileRaw.graph_id) invalid('Non-canonical V7 exchange graph ID');
  return Object.freeze({ ...raw, profile: Object.freeze(profileRaw),
    active_descriptors: Object.freeze(descriptors.slice(0, raw.active_descriptors.length)),
    retained_descriptors: Object.freeze(descriptors.slice(raw.active_descriptors.length)),
    active_keysets: Object.freeze(keysets.slice(0, raw.active_keysets.length)),
    retained_keysets: Object.freeze(keysets.slice(raw.active_keysets.length)),
    transitions: Object.freeze(transitions),
  }) as unknown as V7ExchangeDiscovery;
}

async function validateGraph(record: unknown, issuerId: string): Promise<V7GraphIssuanceDiscovery> {
  const raw = exact(record, ['version', 'profile_id', 'active_policies', 'retained_policies']);
  if (raw.version !== 7 || raw.profile_id !== GRAPH_PROFILE || !Array.isArray(raw.active_policies) ||
    !Array.isArray(raw.retained_policies) || raw.active_policies.length > MAX_ITEMS || raw.retained_policies.length > MAX_ITEMS) invalid('Invalid V7 graph issuance discovery');
  const policies: V7GraphIssuancePolicy[] = [];
  const policyIdsSeen = new Set<string>();
  for (const value of [...raw.active_policies, ...raw.retained_policies]) {
    const policy = exact(value, [
      'policy_id', 'profile_id', 'graph_id', 'keyset_id', 'descriptor_id', 'token_key_id', 'issuer_id',
      'asset_id', 'amount_minor', 'suite', 'modulus_bits', 'exponent', 'quantity', 'pubkey_spki_b64',
      'spki_fingerprint', 'valid_from', 'valid_until',
    ]);
    if (!id(policy.policy_id) || policy.profile_id !== GRAPH_PROFILE || !id(policy.graph_id) ||
      !id(policy.keyset_id) || !id(policy.descriptor_id) || !id(policy.token_key_id) ||
      policy.issuer_id !== issuerId || !text(policy.issuer_id) || !text(policy.asset_id) ||
      !amountString(policy.amount_minor) || policy.suite !== SUITE || policy.modulus_bits !== 3072 ||
      policy.exponent !== 65537 || policy.quantity !== 1 || !id(policy.spki_fingerprint) ||
      !validity(policy.valid_from, policy.valid_until)) invalid('Invalid V7 graph issuance policy');
    distinctIds(policy.token_key_id, policy.descriptor_id, policy.spki_fingerprint);
    const spki = canonicalB64(policy.pubkey_spki_b64);
    if (policyIdsSeen.has(policy.policy_id) || graphPolicyId(policy, spki) !== policy.policy_id) {
      invalid('Non-canonical or duplicate V7 graph policy ID');
    }
    policyIdsSeen.add(policy.policy_id);
    await validateSpki(policy.pubkey_spki_b64, policy.spki_fingerprint);
    policies.push(Object.freeze(policy) as unknown as V7GraphIssuancePolicy);
  }
  return Object.freeze({ ...raw,
    active_policies: Object.freeze(policies.slice(0, raw.active_policies.length)),
    retained_policies: Object.freeze(policies.slice(raw.active_policies.length)),
  }) as unknown as V7GraphIssuanceDiscovery;
}

/** Materialize a complete immutable V7 registry after all records validate. */
export async function materializeV7Registry(metadata: V7KeyDiscoveryResp): Promise<V7Registry> {
  const records: V7RegistryEntry[] = [];
  const byTokenKeyId = new Map<V7RegistryEntry['token_key_id'], V7RegistryEntry>();
  const byDescriptorId = new Map<string, V7RegistryEntry>();
  const byFingerprint = new Map<string, V7RegistryEntry>();
  const add = (record: RegistryRecord, role: V7RegistryRole): void => {
    const candidate = registryBinding(record, metadata.issuer_id);
    const reference = registryReference(record, role);
    const descriptorOwner = byDescriptorId.get(candidate.descriptor_id);
    const fingerprintOwner = byFingerprint.get(candidate.spki_fingerprint);
    if ((descriptorOwner && descriptorOwner.token_key_id !== candidate.token_key_id) ||
      (fingerprintOwner && fingerprintOwner.token_key_id !== candidate.token_key_id)) {
      invalid('V7 registry descriptor or key fingerprint collision');
    }
    const existing = byTokenKeyId.get(candidate.token_key_id);
    if (!existing) {
      if (role === 'graph_issuance') invalid('V7 graph policy has no exchange key binding');
      const entry = Object.freeze({ ...candidate, roles: Object.freeze([role]), references: Object.freeze([reference]) });
      records.push(entry);
      byTokenKeyId.set(candidate.token_key_id, entry);
      byDescriptorId.set(candidate.descriptor_id, entry);
      byFingerprint.set(candidate.spki_fingerprint, entry);
      return;
    }
    if (!sameBinding(existing, candidate)) invalid('Conflicting V7 key binding');
    if (existing.roles.includes(role) || existing.references.some((item) =>
      item.role === reference.role && item.descriptor_id === reference.descriptor_id)) {
      invalid('Repeated V7 registry role reference');
    }
    if (role === 'graph_issuance' && !existing.roles.includes('exchange')) {
      invalid('V7 graph policy has no exchange key binding');
    }
    const merged = Object.freeze({ ...existing,
      roles: Object.freeze([...existing.roles, role]),
      references: Object.freeze([...existing.references, reference]),
    });
    const index = records.indexOf(existing);
    records[index] = merged;
    byTokenKeyId.set(candidate.token_key_id, merged);
    byDescriptorId.set(candidate.descriptor_id, merged);
    byFingerprint.set(candidate.spki_fingerprint, merged);
  };
  add(metadata.native_bearer_v7, 'direct');
  for (const record of metadata.native_bearer_v7_retained) add(record, 'direct');
  for (const container of [metadata.native_exchange_v7]) {
    if (container) for (const record of [...container.active_descriptors, ...container.retained_descriptors]) add(record, 'exchange');
  }
  if (metadata.native_graph_issuance_v7) {
    for (const record of [...metadata.native_graph_issuance_v7.active_policies, ...metadata.native_graph_issuance_v7.retained_policies]) add(record, 'graph_issuance');
  }
  const mutableByTokenKeyId = byTokenKeyId;
  const readonlyByTokenKeyId = Object.freeze({
    get size(): number { return mutableByTokenKeyId.size; },
    get: (key: V7RegistryEntry['token_key_id']) => mutableByTokenKeyId.get(key),
    has: (key: V7RegistryEntry['token_key_id']) => mutableByTokenKeyId.has(key),
    entries: () => mutableByTokenKeyId.entries(),
    keys: () => mutableByTokenKeyId.keys(),
    values: () => mutableByTokenKeyId.values(),
    forEach: (callback: (value: V7RegistryEntry, key: V7RegistryEntry['token_key_id'], map: ReadonlyMap<V7RegistryEntry['token_key_id'], V7RegistryEntry>) => void) =>
      mutableByTokenKeyId.forEach((value, key) => callback(value, key, readonlyByTokenKeyId)),
    [Symbol.iterator]: () => mutableByTokenKeyId[Symbol.iterator](),
  }) as ReadonlyMap<V7RegistryEntry['token_key_id'], V7RegistryEntry>;
  return Object.freeze({ issuer_id: metadata.issuer_id, entries: Object.freeze(records),
    by_token_key_id: readonlyByTokenKeyId, __freebirdV7Registry: true as const });
}

/** Strictly validate and normalize a lossless V7 discovery object. */
export async function validateV7KeyDiscovery(value: unknown): Promise<V7KeyDiscoveryResp> {
  const raw = exactOptional(value, [
    'issuer_id', 'current_epoch', 'valid_epochs', 'epoch_duration_sec', 'voprf', 'native_bearer_v7',
    'native_bearer_v7_retained',
  ], ['native_exchange_v7', 'native_graph_issuance_v7']);
  const validEpochs = raw.valid_epochs;
  if (!text(raw.issuer_id) || !positiveNumber(raw.current_epoch) || !Array.isArray(validEpochs) ||
    validEpochs.length === 0 || validEpochs.some((epoch) => !positiveNumber(epoch)) ||
    !validEpochs.every((epoch, index) => index === 0 || (validEpochs[index - 1] as number) < epoch) ||
    !positiveU64(raw.epoch_duration_sec)) invalid('Invalid V7 issuer discovery envelope');
  const voprf = exact(raw.voprf, ['suite', 'kid', 'pubkey']);
  if (!text(voprf.suite, 512) || !text(voprf.kid, 512) || !text(voprf.pubkey, 512) ||
    !Array.isArray(raw.native_bearer_v7_retained) || raw.native_bearer_v7_retained.length > MAX_ITEMS) invalid();
  const issuerId = raw.issuer_id as string;
  const retainedRecords = raw.native_bearer_v7_retained as unknown[];
  const active = await validateDirect(raw.native_bearer_v7, issuerId);
  const retained = await Promise.all(retainedRecords.map((record) => validateDirect(record, issuerId)));
  const directIds = new Set<string>();
  for (const record of [active, ...retained]) {
    if (directIds.has(record.token_key_id) || directIds.has(record.spki_fingerprint)) {
      invalid('V7 direct key rotation collision');
    }
    directIds.add(record.token_key_id);
    directIds.add(record.spki_fingerprint);
  }
  const exchange = raw.native_exchange_v7 === undefined ? undefined : await validateExchange(raw.native_exchange_v7, issuerId);
  const graph = raw.native_graph_issuance_v7 === undefined ? undefined : await validateGraph(raw.native_graph_issuance_v7, issuerId);
  if (graph) validateGraphLinks(exchange, graph);
  const normalized = Object.freeze({ ...raw, voprf: Object.freeze(voprf), native_bearer_v7: active,
    native_bearer_v7_retained: Object.freeze(retained), native_exchange_v7: exchange, native_graph_issuance_v7: graph,
  }) as unknown as V7KeyDiscoveryResp;
  await materializeV7Registry(normalized);
  return normalized;
}

/** Parse strict JSON without ever first converting Rust integer fields through Number. */
export async function parseV7KeyDiscovery(body: string): Promise<V7KeyDiscoveryResp> {
  let parsed: unknown;
  try {
    parsed = parse(body, undefined, parseNumberAndBigInt);
  } catch {
    invalid('Invalid V7 key discovery JSON');
  }
  return validateV7KeyDiscovery(normalizeLossless(parsed));
}

const BIGINT_FIELDS = new Set(['amount_minor', 'epoch_duration_sec', 'valid_from', 'valid_until']);
function normalizeLossless(value: unknown, key = ''): unknown {
  if (typeof value === 'bigint') {
    if (BIGINT_FIELDS.has(key)) return value;
    if (value <= BigInt(Number.MAX_SAFE_INTEGER) && value >= BigInt(Number.MIN_SAFE_INTEGER)) return Number(value);
    return value;
  }
  if (Array.isArray(value)) return value.map((entry) => normalizeLossless(entry, key));
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([entryKey, entry]) => [entryKey, normalizeLossless(entry, entryKey)]));
  }
  return value;
}

function fresh(state: ClientState): boolean {
  if (!state.v7KeyDiscoveryMetadata || state.v7KeyDiscoveryMetadataFetchedAt === null) return false;
  const ttl = state.config.keyCacheTtlMs;
  if (ttl !== undefined) return Date.now() - state.v7KeyDiscoveryMetadataFetchedAt < ttl;
  const seconds = state.v7KeyDiscoveryMetadata.epoch_duration_sec;
  const ttlMs = seconds > BigInt(Math.floor(Number.MAX_SAFE_INTEGER / 1000)) ? Number.MAX_SAFE_INTEGER : Number(seconds) * 1000;
  return Date.now() - state.v7KeyDiscoveryMetadataFetchedAt < ttlMs;
}

/** Read cached strict V7 discovery, or atomically refresh it. */
export async function getV7KeyDiscoveryMetadata(state: ClientState): Promise<V7DirectKeyDiscovery> {
  if (fresh(state)) return directDiscovery(state.v7KeyDiscoveryMetadata!);
  return refreshV7KeyDiscoveryMetadata(state);
}

/** Fetch and atomically commit the complete strict V7 discovery registry. */
export async function refreshV7KeyDiscoveryMetadata(state: ClientState): Promise<V7DirectKeyDiscovery> {
  const url = `${state.config.issuerUrl}/.well-known/keys`;
  const response = await (state.config.fetch ?? fetch)(url);
  if (!response.ok) throw new DiscoveryError('Failed to fetch V7 issuer key metadata');
  const metadata = await parseV7KeyDiscovery(await response.text());
  const registry = await materializeV7Registry(metadata);
  pinIssuerIdentity(state, metadata.issuer_id);
  state.v7KeyDiscoveryMetadata = metadata;
  state.v7Registry = registry;
  state.v7KeyDiscoveryMetadataFetchedAt = Date.now();
  return directDiscovery(metadata);
}

/** Project the validated full document without exposing exchange/graph DTOs. */
function directDiscovery(metadata: V7KeyDiscoveryResp): V7DirectKeyDiscovery {
  return Object.freeze({
    issuer_id: metadata.issuer_id,
    current_epoch: metadata.current_epoch,
    valid_epochs: metadata.valid_epochs,
    epoch_duration_sec: metadata.epoch_duration_sec,
    voprf: metadata.voprf,
    native_bearer_v7: metadata.native_bearer_v7,
    native_bearer_v7_retained: metadata.native_bearer_v7_retained,
  });
}

/** Alias used by callers that explicitly distinguish the network operation. */
export const fetchV7KeyDiscoveryMetadata = refreshV7KeyDiscoveryMetadata;
