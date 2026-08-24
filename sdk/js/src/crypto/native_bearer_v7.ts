// SPDX-License-Identifier: Apache-2.0 OR MIT

import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { sha256 } from '@noble/hashes/sha256';
import { sha384 } from '@noble/hashes/sha512';
import type {
  V7Amount,
  V7Body,
  V7DirectBinding,
  V7KeyIdentity,
  V7MessageRandomizer,
  V7NativeBearerKeyInfo,
  V7Nullifier,
  V7OwnerCommitment,
  V7Raw384,
  V7Token,
  V7TokenKeyId,
} from '../types.js';

export const V7_ENVELOPE_VERSION = 0x07;
export const V7_RETIRED_ENVELOPE_VERSION = 0x05;
export const V7_RESERVED_ENVELOPE_VERSION = 0x06;
export const V7_ARTIFACT_TYPE = 'scarcity/native-bearer/v7';
export const V7_SUITE = 'RSABSSA-SHA384-PSS-Randomized-V7';
export const V7_NULLIFIER_DOMAIN = new TextEncoder().encode('scarcity native bearer nullifier v7\0');
export const V7_BLIND_MESSAGE_DOMAIN = new TextEncoder().encode('scarcity native bearer blind message v7\0');
export const V7_ARTIFACT_DOMAIN = new TextEncoder().encode('scarcity native bearer artifact v7\0');

const RSA_ENCRYPTION_OID = Uint8Array.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
const SHA384_OID = Uint8Array.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]);
const MAX_TEXT_BYTES = 128;
const MAX_U64 = (1n << 64n) - 1n;
const MAX_VALID_UNTIL = 9_007_199_254_740_991n;
const V7_BODY_SUFFIX_LEN = 32 + 384;
const V7_MIN_BODY_LEN = 4 + 4 + V7_ARTIFACT_TYPE.length + 4 + 1 + 8 + 4 + 1 + 32 + 32 + 32 + 32;
const V7_MAX_BODY_LEN = 4 + 4 + V7_ARTIFACT_TYPE.length + 4 + MAX_TEXT_BYTES + 8 + 4 + MAX_TEXT_BYTES + 32 + 32 + 32 + 32;

const suite = RSABSSA.SHA384.PSS.Randomized();
const blindSecrets = new WeakMap<object, { readonly inverse: Uint8Array }>();

export interface V7BodyInput {
  readonly asset_id: string;
  readonly amount_minor: bigint;
  readonly issuer_id: string;
  readonly token_key_id: Uint8Array | string;
  readonly nonce?: Uint8Array;
  readonly nullifier?: Uint8Array;
  readonly owner_commitment: Uint8Array;
}

function invalid(message: string): never {
  throw new Error(message);
}

function copy32(value: Uint8Array, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) invalid(`${name} must be exactly 32 bytes`);
  return value.slice();
}

function copy384(value: Uint8Array, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 384) invalid(`${name} must be exactly 384 bytes`);
  return value.slice();
}

function utf8(value: string, name: string): Uint8Array {
  if (typeof value !== 'string') invalid(`${name} must be UTF-8 text`);
  const bytes = new TextEncoder().encode(value);
  try {
    if (new TextDecoder('utf-8', { fatal: true }).decode(bytes) !== value) invalid(`${name} is not canonical UTF-8`);
  } catch {
    invalid(`${name} is not canonical UTF-8`);
  }
  if (bytes.length === 0 || bytes.length > MAX_TEXT_BYTES) invalid(`${name} must be 1-${MAX_TEXT_BYTES} UTF-8 bytes`);
  return bytes;
}

function decodeText(bytes: Uint8Array, name: string): string {
  try {
    const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    utf8(value, name);
    return value;
  } catch {
    invalid(`${name} is not valid UTF-8`);
  }
}

function tokenId(value: Uint8Array | string, name: string): V7TokenKeyId {
  if (typeof value === 'string') {
    if (!/^[0-9a-f]{64}$/.test(value)) invalid(`${name} must be lowercase hex32`);
    return value as V7TokenKeyId;
  }
  return hex(copy32(value, name)) as V7TokenKeyId;
}

function amount(value: bigint): V7Amount {
  if (typeof value !== 'bigint' || value <= 0n || value > MAX_U64) invalid('amount_minor must be a nonzero u64 bigint');
  return value as V7Amount;
}

function lp(output: number[], bytes: Uint8Array): void {
  output.push((bytes.length >>> 24) & 0xff, (bytes.length >>> 16) & 0xff,
    (bytes.length >>> 8) & 0xff, bytes.length & 0xff, ...bytes);
}

function u32(value: number): Uint8Array {
  return Uint8Array.from([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
}

function u64(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  let current = value;
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number(current & 0xffn);
    current >>= 8n;
  }
  return bytes;
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function fromHex(value: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(value)) invalid('V7 SPKI fingerprint must be lowercase hex32');
  return Uint8Array.from(value.match(/../g)!, (pair) => Number.parseInt(pair, 16));
}

function fromBase64Url(value: string): Uint8Array {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) invalid('invalid canonical base64url');
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '='));
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (toBase64Url(bytes) !== value) invalid('invalid canonical base64url');
    return bytes;
  } catch {
    invalid('invalid canonical base64url');
  }
}

function toBase64Url(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function canonicalPssSpki(bytes: Uint8Array): Uint8Array {
  const template = Uint8Array.from([
    0x30, 0x82, 0, 0, 0x30, 0x3d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
    0x30, 0x30, 0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09,
    ...SHA384_OID,
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
    0x30, 0x0b, 0x06, 0x09, ...SHA384_OID,
    0xa2, 0x03, 0x02, 0x01, 48, 0x03, 0x82, 0, 0, 0,
  ]);
  const rawStart = template.length;
  if (bytes.length <= rawStart || bytes.length > 800 || bytes[0] !== 0x30 || bytes[1] !== 0x82 ||
    ((bytes[2] << 8) | bytes[3]) !== bytes.length - 4) invalid('Invalid canonical V7 SPKI');
  const raw = bytes.slice(rawStart);
  if (raw.length !== 398 || raw[0] !== 0x30 || raw[1] !== 0x82 || ((raw[2] << 8) | raw[3]) !== 394 ||
    raw[4] !== 0x02 || raw[5] !== 0x82 || ((raw[6] << 8) | raw[7]) !== 385 || raw[8] !== 0 || raw[9] < 0x80 ||
    raw[393] !== 0x02 || raw[394] !== 0x03 || raw[395] !== 1 || raw[396] !== 0 || raw[397] !== 1) {
    invalid('Invalid V7 RSA-3072 SPKI');
  }
  template[2] = (bytes.length - 4) >>> 8;
  template[3] = (bytes.length - 4) & 0xff;
  template[69] = (raw.length + 1) >>> 8;
  template[70] = (raw.length + 1) & 0xff;
  if (!equal(bytes.slice(0, rawStart), template)) invalid('Invalid canonical V7 SPKI');
  return bytes.slice();
}

function normalizedRsaEncryptionSpki(spki: Uint8Array): Uint8Array {
  const raw = spki.slice(72);
  const header = Uint8Array.from([
    0x30, 0x82, 0, 0,
    0x30, 0x0d, 0x06, 0x09, ...RSA_ENCRYPTION_OID, 0x05, 0x00,
    0x03, 0x82, 0, 0, 0,
  ]);
  const bitLength = raw.length + 1;
  header[2] = (header.length + raw.length - 4) >>> 8;
  header[3] = (header.length + raw.length - 4) & 0xff;
  header[21] = bitLength >>> 8;
  header[22] = bitLength & 0xff;
  const result = new Uint8Array(header.length + raw.length);
  result.set(header);
  result.set(raw, header.length);
  return result;
}

async function importV7PublicKey(binding: V7DirectBinding): Promise<CryptoKey> {
  const spki = canonicalPssSpki(binding.public_key_spki);
  const normalized = normalizedRsaEncryptionSpki(spki);
  const key = await crypto.subtle.importKey(
    'spki', normalized.buffer as ArrayBuffer, { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify'],
  );
  const algorithm = key.algorithm as RsaHashedKeyAlgorithm;
  if (algorithm.name !== 'RSA-PSS' || algorithm.modulusLength !== 3072 ||
    !equal(new Uint8Array(algorithm.publicExponent), Uint8Array.from([1, 0, 1]))) invalid('Invalid V7 RSA-3072 SPKI');
  return key;
}

function identity(issuerId: string, tokenKeyId: Uint8Array | string): V7KeyIdentity {
  utf8(issuerId, 'issuer_id');
  return Object.freeze({ issuer_id: issuerId, token_key_id: tokenId(tokenKeyId, 'token_key_id'), __freebirdV7KeyIdentity: true as const });
}

function bodyValue(input: V7BodyInput): V7Body {
  const asset = utf8(input.asset_id, 'asset_id');
  const issuer = utf8(input.issuer_id, 'issuer_id');
  const tokenKeyId = tokenId(input.token_key_id, 'token_key_id');
  const nonce = input.nonce === undefined ? crypto.getRandomValues(new Uint8Array(32)) : copy32(input.nonce, 'nonce');
  const owner = copy32(input.owner_commitment, 'owner_commitment') as V7OwnerCommitment;
  const derived = deriveV7Nullifier(input.issuer_id, nonce, owner);
  const nullifier = input.nullifier === undefined ? derived : copy32(input.nullifier, 'nullifier');
  if (!equal(nullifier, derived)) invalid('V7 supplied nullifier does not match body fields');
  return Object.freeze({
    asset_id: new TextDecoder().decode(asset), amount_minor: amount(input.amount_minor),
    identity: identity(input.issuer_id, tokenKeyId), nonce: nonce as V7Body['nonce'],
    nullifier: nullifier as V7Nullifier, owner_commitment: owner,
    __freebirdV7Body: true as const,
  });
}

/** Derive the exact V7 replay nullifier from issuer, nonce, and owner commitment. */
export function deriveV7Nullifier(issuerId: string, nonce: Uint8Array, ownerCommitment: Uint8Array): V7Nullifier {
  const issuer = utf8(issuerId, 'issuer_id');
  const nonceBytes = copy32(nonce, 'nonce');
  const owner = copy32(ownerCommitment, 'owner_commitment');
  return sha256(new Uint8Array([...V7_NULLIFIER_DOMAIN, ...u32(issuer.length), ...issuer, ...nonceBytes, ...owner])) as V7Nullifier;
}

/** Build a canonical V7 body, generating a secure nonce only when omitted. */
export function buildV7Body(input: V7BodyInput): V7Body {
  return bodyValue(input);
}

/** Return the canonical V7 body transcript. */
export function v7BodyTranscript(body: V7Body): Uint8Array {
  const asset = utf8(body.asset_id, 'asset_id');
  const issuer = utf8(body.identity.issuer_id, 'issuer_id');
  const output: number[] = [];
  output.push(...u32(7));
  lp(output, new TextEncoder().encode(V7_ARTIFACT_TYPE));
  lp(output, asset);
  output.push(...u64(amount(body.amount_minor)));
  lp(output, issuer);
  output.push(...fromHex(body.identity.token_key_id), ...copy32(body.nonce, 'nonce'), ...copy32(body.nullifier, 'nullifier'), ...copy32(body.owner_commitment, 'owner_commitment'));
  const transcript = Uint8Array.from(output);
  const expected = deriveV7Nullifier(body.identity.issuer_id, body.nonce, body.owner_commitment);
  if (!equal(expected, body.nullifier)) invalid('V7 body nullifier is inconsistent');
  return transcript;
}

/** Compute the exact SHA-384 RFC 9474 application message for a V7 body. */
export function v7ApplicationDigest(body: V7Body): Uint8Array {
  return sha384(new Uint8Array([...V7_BLIND_MESSAGE_DOMAIN, ...v7BodyTranscript(body)]));
}

/** Compute the authenticated presentation digest for a serialized V7 envelope. */
export function v7ArtifactDigest(token: V7Token): Uint8Array {
  return sha256(new Uint8Array([...V7_ARTIFACT_DOMAIN, ...serializeV7Token(token)]));
}

function validateBinding(binding: V7DirectBinding): void {
  if (!binding || !binding.identity || !binding.identity.__freebirdV7KeyIdentity) invalid('Invalid V7 key binding');
  if (!/^[0-9a-f]{64}$/.test(binding.identity.token_key_id)) invalid('Invalid V7 token key ID');
  utf8(binding.identity.issuer_id, 'issuer_id');
  utf8(binding.asset_id, 'asset_id');
  amount(binding.amount_minor);
  if (typeof binding.valid_from !== 'bigint' || typeof binding.valid_until !== 'bigint' ||
    binding.valid_from <= 0n || binding.valid_from >= binding.valid_until || binding.valid_until > MAX_VALID_UNTIL) invalid('Invalid V7 validity window');
  const spki = canonicalPssSpki(binding.public_key_spki);
  if (!equal(sha256(spki), fromHex(binding.spki_fingerprint))) invalid('Invalid V7 SPKI fingerprint');
}

function validateBodyPolicy(binding: V7DirectBinding, body: V7Body): void {
  v7BodyTranscript(body);
  if (body.identity.issuer_id !== binding.identity.issuer_id || body.identity.token_key_id !== binding.identity.token_key_id) invalid('V7 body identity does not match key binding');
  if (body.asset_id !== binding.asset_id || body.amount_minor !== binding.amount_minor) invalid('V7 body does not match key policy');
}

/** Convert a validated V7 discovery record into the binding consumed by crypto primitives. */
export function bindingFromV7Discovery(record: V7NativeBearerKeyInfo): V7DirectBinding {
  if (record.profile_id !== 'scarcity/native-bearer/v7' || record.suite !== V7_SUITE ||
    record.modulus_bits !== 3072 || record.exponent !== 65537) invalid('V7 crypto accepts direct native-bearer bindings only');
  const spki = fromBase64Url(record.pubkey_spki_b64);
  const canonical = canonicalPssSpki(spki);
  const binding = Object.freeze({
    identity: identity(record.issuer_id, record.token_key_id), public_key_spki: canonical,
    spki_fingerprint: record.spki_fingerprint,
    asset_id: record.asset_id, amount_minor: record.amount_minor,
    valid_from: record.valid_from, valid_until: record.valid_until,
    __freebirdV7DirectBinding: true as const,
  });
  validateBinding(binding);
  return binding;
}

/** Blind a direct V7 application message using randomized RFC 9474 preparation. */
export async function blindV7(binding: V7DirectBinding, body: V7Body): Promise<{
  readonly blinded: V7Raw384;
  readonly randomizer: V7MessageRandomizer;
  readonly state: import('../types.js').V7BlindState;
}> {
  validateBinding(binding);
  validateBodyPolicy(binding, body);
  const key = await importV7PublicKey(binding);
  const prepared = suite.prepare(v7ApplicationDigest(body));
  if (prepared.length !== 80) invalid('Invalid V7 randomized preparation');
  const result = await suite.blind(key, prepared);
  if (result.blindedMsg.length !== 384 || result.inv.length !== 384) invalid('Invalid V7 raw384 blind result');
  const randomizer = prepared.slice(0, 32);
  const state = Object.freeze({ identity: binding.identity, spki_fingerprint: binding.spki_fingerprint,
    randomizer: randomizer as V7MessageRandomizer, __freebirdV7BlindState: true as const });
  blindSecrets.set(state, { inverse: result.inv.slice() });
  return { blinded: result.blindedMsg.slice() as V7Raw384, randomizer: state.randomizer, state };
}

/** Finalize a direct V7 blind signature and locally verify the resulting signature. */
export async function finalizeV7(
  binding: V7DirectBinding,
  body: V7Body,
  state: import('../types.js').V7BlindState,
  blindSignature: Uint8Array,
): Promise<V7Token> {
  validateBinding(binding);
  validateBodyPolicy(binding, body);
  const secret = blindSecrets.get(state as object);
  if (!secret || state.identity.token_key_id !== binding.identity.token_key_id ||
    state.identity.issuer_id !== binding.identity.issuer_id || state.spki_fingerprint !== binding.spki_fingerprint) invalid('Invalid V7 opaque blind state');
  const blindSig = copy384(blindSignature, 'blind signature');
  const key = await importV7PublicKey(binding);
  const prepared = new Uint8Array([...copy32(state.randomizer, 'randomizer'), ...v7ApplicationDigest(body)]);
  const signature = await suite.finalize(key, prepared, blindSig, secret.inverse);
  if (signature.length !== 384) invalid('Invalid V7 raw384 signature');
  const token = Object.freeze({ body, message_randomizer: state.randomizer, signature: signature.slice() as V7Raw384, __freebirdV7Token: true as const });
  if (!await verifyV7Token(binding, token)) invalid('V7 finalized signature failed local verification');
  return token;
}

/** Serialize one strict V7 envelope with no optional or trailing fields. */
export function serializeV7Token(token: V7Token): Uint8Array {
  const body = v7BodyTranscript(token.body);
  const randomizer = copy32(token.message_randomizer, 'randomizer');
  const signature = copy384(token.signature, 'signature');
  return Uint8Array.from([V7_ENVELOPE_VERSION, ...body, ...randomizer, ...signature]);
}

function take(bytes: Uint8Array, position: { value: number }, length: number, name: string): Uint8Array {
  const end = position.value + length;
  if (end > bytes.length) invalid(`truncated ${name}`);
  const value = bytes.slice(position.value, end);
  position.value = end;
  return value;
}

function readU32(bytes: Uint8Array, position: { value: number }, name: string): number {
  const value = take(bytes, position, 4, name);
  return (((value[0] * 0x100 + value[1]) * 0x100 + value[2]) * 0x100 + value[3]);
}

function readLp(bytes: Uint8Array, position: { value: number }, name: string): Uint8Array {
  const length = readU32(bytes, position, `${name} length`);
  if (length === 0 || length > MAX_TEXT_BYTES) invalid(`invalid ${name} length`);
  return take(bytes, position, length, name);
}

/** Parse exactly one canonical V7 body transcript. */
export function parseV7Body(bytes: Uint8Array): V7Body {
  if (bytes.length < V7_MIN_BODY_LEN || bytes.length > V7_MAX_BODY_LEN) invalid('Invalid V7 body length');
  const position = { value: 0 };
  if (readU32(bytes, position, 'V7 version') !== 7) invalid('Unsupported V7 body version');
  if (!equal(readLp(bytes, position, 'artifact type'), new TextEncoder().encode(V7_ARTIFACT_TYPE))) invalid('Invalid V7 artifact type');
  const asset = decodeText(readLp(bytes, position, 'asset_id'), 'asset_id');
  const amountBytes = take(bytes, position, 8, 'amount_minor');
  let minor = 0n;
  for (const byte of amountBytes) minor = (minor << 8n) | BigInt(byte);
  const issuer = decodeText(readLp(bytes, position, 'issuer_id'), 'issuer_id');
  const tokenKeyId = take(bytes, position, 32, 'token_key_id');
  const nonce = take(bytes, position, 32, 'nonce');
  const nullifier = take(bytes, position, 32, 'nullifier');
  const owner = take(bytes, position, 32, 'owner_commitment');
  if (position.value !== bytes.length) invalid('Trailing V7 body bytes');
  return bodyValue({ asset_id: asset, amount_minor: minor, issuer_id: issuer, token_key_id: tokenKeyId, nonce, nullifier, owner_commitment: owner });
}

/** Parse exactly one V7 envelope; V5, V6, unknown versions, and trailing bytes are rejected. */
export function parseV7Token(bytes: Uint8Array): V7Token {
  if (!(bytes instanceof Uint8Array) || bytes.length < 1 + V7_MIN_BODY_LEN + V7_BODY_SUFFIX_LEN ||
    bytes.length > 1 + V7_MAX_BODY_LEN + V7_BODY_SUFFIX_LEN) invalid('Invalid V7 envelope length');
  if (bytes[0] === V7_RETIRED_ENVELOPE_VERSION) invalid('V5 envelope is not a V7 token');
  if (bytes[0] === V7_RESERVED_ENVELOPE_VERSION) invalid('V6 envelope is not a V7 token');
  if (bytes[0] !== V7_ENVELOPE_VERSION) invalid('Unsupported V7 envelope version');
  const bodyEnd = bytes.length - V7_BODY_SUFFIX_LEN;
  const body = parseV7Body(bytes.slice(1, bodyEnd));
  return Object.freeze({ body, message_randomizer: bytes.slice(bodyEnd, bodyEnd + 32) as V7MessageRandomizer,
    signature: bytes.slice(bodyEnd + 32) as V7Raw384, __freebirdV7Token: true as const });
}

/** Verify V7 identity, SPKI fingerprint, fixed policy, validity, randomizer, and signature. */
export async function verifyV7Token(binding: V7DirectBinding, token: V7Token, now = BigInt(Math.floor(Date.now() / 1000))): Promise<boolean> {
  try {
    validateBinding(binding);
    validateBodyPolicy(binding, token.body);
    if (typeof now !== 'bigint' || now < binding.valid_from || now > binding.valid_until) return false;
    const key = await importV7PublicKey(binding);
    const prepared = new Uint8Array([...copy32(token.message_randomizer, 'randomizer'), ...v7ApplicationDigest(token.body)]);
    return await suite.verify(key, copy384(token.signature, 'signature'), prepared);
  } catch {
    return false;
  }
}

/** Convert a strict V7 discovery record into a crypto binding without deriving its token key ID. */
export function directBindingFromDiscovery(record: V7NativeBearerKeyInfo): V7DirectBinding {
  return bindingFromV7Discovery(record);
}
