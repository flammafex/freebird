// SPDX-License-Identifier: Apache-2.0 OR MIT

import type { SybilProof, SybilProofFactory, FreebirdToken, V7Body, V7DirectBinding, V7Token } from '../types.js';
import type { ClientState } from './state.js';
import { decodeCanonical, bytesToBase64Url } from './wire.js';
import {
  BatchIssuanceInterruptedError,
  DiscoveryError,
  FreebirdError,
  StalePublicKeyError,
} from '../errors.js';
import {
  bindingFromV7Discovery,
  blindV7,
  buildV7Body,
  finalizeV7,
  serializeV7Token,
} from '../crypto/native_bearer_v7.js';
import {
  buildNativeBearerV7BatchBinding,
  buildNativeBearerV7IssueBinding,
  resolveSybilProof,
} from './sybil.js';
import { getV7KeyDiscoveryMetadata, refreshV7KeyDiscoveryMetadata } from './v7_discovery.js';

const MAX_V7_BATCH_SIZE = 10_000;
const MAX_V7_BATCH_BODY_BYTES = 60 * 1024;
const V7_BLINDED_MESSAGE_B64_LENGTH = 512;

export interface NativeBearerV7IssueOptions {
  readonly owner_commitment: Uint8Array;
  readonly nonce?: Uint8Array;
  readonly sybilProof?: SybilProof;
  readonly proofFactory?: SybilProofFactory;
}

export interface NativeBearerV7BatchIssueOptions {
  readonly owner_commitments: readonly Uint8Array[];
  readonly nonces?: readonly Uint8Array[];
  readonly sybilProof?: SybilProof;
  readonly proofFactory?: SybilProofFactory;
}

type V7IssuedToken = Omit<FreebirdToken, 'version'> & {
  readonly version: 7;
  readonly tokenKeyId: string;
  readonly valid_until: number;
};

type V7Prepared = {
  readonly body: V7Body;
  readonly binding: V7DirectBinding;
  readonly blinded: string;
  readonly state: Awaited<ReturnType<typeof blindV7>>['state'];
};

function proofFactory(options: { proofFactory?: SybilProofFactory }): SybilProofFactory | undefined {
  return options.proofFactory;
}

function assertProofOptions(options: { sybilProof?: SybilProof; proofFactory?: SybilProofFactory }): void {
  if (options.sybilProof !== undefined && options.proofFactory !== undefined) {
    throw new FreebirdError('issuance', 'Specify either sybilProof or proofFactory, not both');
  }
}

function responseObject(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new FreebirdError('issuance', 'V7 issuance response is malformed');
  }
  return value as Record<string, unknown>;
}

function responseError(value: unknown): string | undefined {
  try {
    const body = responseObject(value);
    return typeof body.error === 'string' ? body.error : undefined;
  } catch {
    return undefined;
  }
}

async function readError(res: Response): Promise<string | undefined> {
  try {
    const text = await res.text();
    try {
      return (responseError(JSON.parse(text)) ?? text.trim()) || undefined;
    } catch {
      return text.trim() || undefined;
    }
  } catch {
    return undefined;
  }
}

function isStaleResponse(status: number, error: string | undefined): boolean {
  return status === 400 && error === 'token_key_not_active';
}

function asIssuedToken(token: V7Token, binding: V7DirectBinding): V7IssuedToken {
  const validUntil = Number(binding.valid_until);
  if (!Number.isSafeInteger(validUntil)) throw new DiscoveryError('V7 key validity is not a safe timestamp');
  return {
    tokenValue: bytesToBase64Url(serializeV7Token(token)),
    issuerId: binding.identity.issuer_id,
    version: 7,
    tokenKeyId: binding.identity.token_key_id,
    valid_until: validUntil,
  };
}

async function proofFor(
  state: ClientState,
  proof: SybilProof | undefined,
  factory: SybilProofFactory | undefined,
  binding: string,
): Promise<SybilProof | undefined> {
  return resolveSybilProof(state, proof, binding, factory, true);
}

async function prepare(
  binding: V7DirectBinding,
  ownerCommitment: Uint8Array,
  nonce: Uint8Array | undefined,
): Promise<V7Prepared> {
  const body = buildV7Body({
    asset_id: binding.asset_id,
    amount_minor: binding.amount_minor,
    issuer_id: binding.identity.issuer_id,
    token_key_id: binding.identity.token_key_id,
    nonce,
    owner_commitment: ownerCommitment,
  });
  const result = await blindV7(binding, body);
  return { body, binding, blinded: bytesToBase64Url(result.blinded), state: result.state };
}

async function post(state: ClientState, path: string, serializedBody: string): Promise<Response> {
  return (state.config.fetch ?? fetch)(`${state.config.issuerUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: serializedBody,
  });
}

function v7BatchBodyLimitBytes(state: ClientState): number {
  const limit = state.config.batchBodyLimitBytes ?? MAX_V7_BATCH_BODY_BYTES;
  if (!Number.isSafeInteger(limit) || limit <= 0) {
    throw new FreebirdError('issuance', 'Batch body byte limit must be a positive safe integer');
  }
  if (limit > MAX_V7_BATCH_BODY_BYTES) {
    throw new FreebirdError('issuance', 'Batch body byte limit cannot exceed 60 KiB');
  }
  return limit;
}

function serializedBody(body: Record<string, unknown>): { value: string; bytes: number } {
  const value = JSON.stringify(body);
  return { value, bytes: new TextEncoder().encode(value).byteLength };
}

function v7BatchBody(
  tokenKeyId: string,
  blinded: string[],
  proof: SybilProof | undefined,
): Record<string, unknown> {
  return { token_key_id: tokenKeyId, blinded_msgs_b64: blinded, sybil_proof: proof };
}

function placeholderV7BatchBody(
  binding: V7DirectBinding,
  count: number,
  proof: SybilProof | undefined,
): Record<string, unknown> {
  return v7BatchBody(
    binding.identity.token_key_id,
    Array.from({ length: count }, () => 'A'.repeat(V7_BLINDED_MESSAGE_B64_LENGTH)),
    proof,
  );
}

function maximumPlaceholderChunkSize(
  binding: V7DirectBinding,
  remaining: number,
  limit: number,
  proof: SybilProof | undefined,
): number {
  let count = 0;
  while (count < remaining && serializedBody(placeholderV7BatchBody(binding, count + 1, proof)).bytes <= limit) {
    count += 1;
  }
  return count;
}

type PreparedV7Chunk = {
  readonly prepared: V7Prepared[];
  readonly proof: SybilProof | undefined;
  readonly serializedBody: string;
};

async function prepareV7Chunk(args: {
  state: ClientState;
  binding: V7DirectBinding;
  ownerCommitments: readonly Uint8Array[];
  nonces: readonly Uint8Array[] | undefined;
  start: number;
  fixedProof: SybilProof | undefined;
  factory: SybilProofFactory | undefined;
  limit: number;
}): Promise<PreparedV7Chunk> {
  const maxCount = maximumPlaceholderChunkSize(
    args.binding,
    args.ownerCommitments.length - args.start,
    args.limit,
    args.fixedProof === undefined ? undefined : args.fixedProof,
  );
  if (maxCount === 0) {
    throw new FreebirdError('issuance', 'A single V7 batch item exceeds the configured JSON body limit');
  }

  const prepared: V7Prepared[] = [];
  for (let index = 0; index < maxCount; index += 1) {
    prepared.push(await prepare(
      args.binding,
      args.ownerCommitments[args.start + index],
      args.nonces?.[args.start + index],
    ));
  }

  for (;;) {
    const blinded = prepared.map((item) => item.blinded);
    const bindingText = buildNativeBearerV7BatchBinding(
      args.binding.identity.issuer_id,
      args.binding.identity.token_key_id,
      blinded,
    );
    // Resolve even caller-supplied proofs through the same exact binding
    // validation as factory-generated proofs. Chunking is rejected for fixed
    // proofs before preparation, so this is the one exact chunk they attest.
    const proof = await proofFor(args.state, args.fixedProof, args.factory, bindingText);
    const serialized = serializedBody(v7BatchBody(args.binding.identity.token_key_id, blinded, proof));
    if (serialized.bytes <= args.limit) return { prepared, proof, serializedBody: serialized.value };
    if (prepared.length === 1) {
      throw new FreebirdError('issuance', 'A single V7 batch item exceeds the configured JSON body limit');
    }
    prepared.pop();
  }
}

function rejectFixedProofIfChunkingRequired(
  binding: V7DirectBinding,
  total: number,
  proof: SybilProof | undefined,
  limit: number,
): void {
  if (proof === undefined) return;
  const full = serializedBody(placeholderV7BatchBody(binding, total, proof));
  if (full.bytes > limit) {
    throw new FreebirdError(
      'issuance',
      'A fixed Sybil proof cannot be reused when V7 batch request chunking is required',
    );
  }
}

function assertIdentity(response: Record<string, unknown>, binding: V7DirectBinding): void {
  if (response.issuer_id !== binding.identity.issuer_id) throw new DiscoveryError('Issuer identity changed during V7 issuance');
  if (response.token_key_id !== binding.identity.token_key_id) throw new StalePublicKeyError();
}

function blindSignature(response: Record<string, unknown>): Uint8Array {
  if (typeof response.blind_signature_b64 !== 'string') throw new FreebirdError('issuance', 'V7 issuance response is malformed');
  return decodeCanonical(response.blind_signature_b64, 384);
}

async function save(state: ClientState, token: V7IssuedToken): Promise<void> {
  if (state.config.tokenStore) await state.config.tokenStore.save(token as unknown as FreebirdToken);
}

/** Issue one direct V7 native bearer token, rebuilding all key-bound state once on rotation. */
export async function issueNativeBearerV7(
  state: ClientState,
  options: NativeBearerV7IssueOptions,
  getDiscovery: () => Promise<Awaited<ReturnType<typeof getV7KeyDiscoveryMetadata>>> = () => getV7KeyDiscoveryMetadata(state),
  refreshDiscovery: () => Promise<Awaited<ReturnType<typeof refreshV7KeyDiscoveryMetadata>>> = () => refreshV7KeyDiscoveryMetadata(state),
): Promise<FreebirdToken> {
  assertProofOptions(options);
  const factory = proofFactory(options);
  let metadata = await getDiscovery();
  let retried = false;
  for (;;) {
    const binding = bindingFromV7Discovery(metadata.native_bearer_v7);
    const prepared = await prepare(binding, options.owner_commitment, options.nonce);
    const bindingText = buildNativeBearerV7IssueBinding(binding.identity.issuer_id, binding.identity.token_key_id, prepared.blinded);
    const sybilProof = await proofFor(state, options.sybilProof, factory, bindingText);
    const response = await post(state, '/v7/native-bearer/issue', serializedBody({
      token_key_id: binding.identity.token_key_id,
      blinded_msg_b64: prepared.blinded,
      sybil_proof: sybilProof,
    }).value);
    if (!response.ok) {
      const error = await readError(response);
      if (isStaleResponse(response.status, error) && !retried) {
        if (options.sybilProof !== undefined && factory === undefined) throw new StalePublicKeyError('A fresh V7 proof factory is required after key rotation');
        retried = true;
        metadata = await refreshDiscovery();
        continue;
      }
      throw new FreebirdError('issuance', 'V7 native bearer issuance failed');
    }
    const body = responseObject(await response.json());
    if (body.issuer_id !== binding.identity.issuer_id) throw new DiscoveryError('Issuer identity changed during V7 issuance');
    if (body.token_key_id !== binding.identity.token_key_id) {
      if (!retried) {
        if (options.sybilProof !== undefined && factory === undefined) throw new StalePublicKeyError('A fresh V7 proof factory is required after key rotation');
        retried = true;
        metadata = await refreshDiscovery();
        continue;
      }
      throw new StalePublicKeyError();
    }
    const signature = blindSignature(body);
    const token = await finalizeV7(binding, prepared.body, prepared.state, signature);
    const issued = asIssuedToken(token, binding);
    await save(state, issued);
    return issued as unknown as FreebirdToken;
  }
}

/** Issue a bounded ordered direct V7 batch without dropping or reordering results. */
export async function issueNativeBearerV7Batch(
  state: ClientState,
  options: NativeBearerV7BatchIssueOptions,
  getDiscovery: () => Promise<Awaited<ReturnType<typeof getV7KeyDiscoveryMetadata>>> = () => getV7KeyDiscoveryMetadata(state),
  refreshDiscovery: () => Promise<Awaited<ReturnType<typeof refreshV7KeyDiscoveryMetadata>>> = () => refreshV7KeyDiscoveryMetadata(state),
): Promise<FreebirdToken[]> {
  assertProofOptions(options);
  if (options.owner_commitments.length === 0 || options.owner_commitments.length > MAX_V7_BATCH_SIZE) {
    throw new FreebirdError('issuance', 'V7 batch size must be between 1 and 10000');
  }
  if (options.nonces !== undefined && options.nonces.length !== options.owner_commitments.length) {
    throw new FreebirdError('issuance', 'V7 nonce count must match owner commitment count');
  }
  const factory = proofFactory(options);
  const limit = v7BatchBodyLimitBytes(state);
  let metadata = await getDiscovery();
  let retried = false;
  const completed: V7IssuedToken[] = [];
  let offset = 0;

  while (offset < options.owner_commitments.length) {
    try {
      const binding = bindingFromV7Discovery(metadata.native_bearer_v7);
      if (offset === 0) {
        // This check uses the exact request envelope and fixed-width V7 blinded
        // messages, so a fixed proof is rejected before any blinding work when
        // the logical batch would need more than one request.
        rejectFixedProofIfChunkingRequired(binding, options.owner_commitments.length, options.sybilProof, limit);
      }

      const chunk = await prepareV7Chunk({
        state,
        binding,
        ownerCommitments: options.owner_commitments,
        nonces: options.nonces,
        start: offset,
        fixedProof: options.sybilProof,
        factory,
        limit,
      });
      const response = await post(state, '/v7/native-bearer/issue/batch', chunk.serializedBody);
      if (!response.ok) {
        const error = await readError(response);
        if (isStaleResponse(response.status, error) && !retried) {
          if (options.sybilProof !== undefined && factory === undefined) {
            throw new StalePublicKeyError('A fresh V7 proof factory is required after key rotation');
          }
          retried = true;
          metadata = await refreshDiscovery();
          continue;
        }
        throw new FreebirdError('issuance', 'V7 native bearer batch issuance failed');
      }

      const body = responseObject(await response.json());
      if (body.issuer_id !== binding.identity.issuer_id) {
        throw new DiscoveryError('Issuer identity changed during V7 batch issuance');
      }
      if (body.token_key_id !== binding.identity.token_key_id) {
        if (!retried) {
          if (options.sybilProof !== undefined && factory === undefined) {
            throw new StalePublicKeyError('A fresh V7 proof factory is required after key rotation');
          }
          retried = true;
          metadata = await refreshDiscovery();
          continue;
        }
        throw new StalePublicKeyError();
      }

      if (!Array.isArray(body.blind_signatures_b64) || body.blind_signatures_b64.length !== chunk.prepared.length ||
        body.successful !== chunk.prepared.length || body.failed !== 0) {
        throw new FreebirdError('issuance', 'V7 native bearer batch response is malformed');
      }
      for (let index = 0; index < chunk.prepared.length; index += 1) {
          const signature = blindSignature({ blind_signature_b64: body.blind_signatures_b64[index] });
          const token = await finalizeV7(binding, chunk.prepared[index].body, chunk.prepared[index].state, signature);
          const issued = asIssuedToken(token, binding);
          completed.push(issued);
          await save(state, issued);
      }
      offset += chunk.prepared.length;
    } catch (cause) {
      if (completed.length > 0) throw new BatchIssuanceInterruptedError(completed.slice(), cause);
      throw cause;
    }
  }

  return completed as unknown as FreebirdToken[];
}
