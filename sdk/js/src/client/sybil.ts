// SPDX-License-Identifier: Apache-2.0 OR MIT

import { sha256 } from '@noble/hashes/sha256';
import type { SybilProof, SybilProofFactory } from '../types.js';
import type { ClientState } from './state.js';
import { bytesToBase64Url, concatBytes } from './wire.js';
import { FreebirdError } from '../errors.js';

/**
 * Proof-of-Work Sybil resistance helpers.
 *
 * Only PoW (plus `rate_limit` and `multi` composition) is client-generable.
 * The HMAC-keyed variants (`progressive_trust`, `proof_of_diversity`,
 * `multi_party_vouching`, `invitation`) are bound to server-side secrets and
 * must never be fabricated here.
 *
 * The mining scheme mirrors `issuer/src/sybil_resistance/proof_of_work.rs`:
 * a nonce is sought such that
 *
 *   `SHA256(input || nonce_le_u64 || timestamp_le_u64)`
 *
 * has `difficulty` leading zero bits. `nonce` and `timestamp` are serialized
 * as little-endian u64, exactly as the server's `hash_pow` does.
 */

/** Maximum difficulty the client-side miner supports (matches the Rust `compute` cap). */
export const MAX_POW_DIFFICULTY = 32;

/** The `proof_of_work` {@link SybilProof} variant produced by the miner. */
export type ProofOfWorkProof = Extract<SybilProof, { type: 'proof_of_work' }>;

/** Number of mining iterations between event-loop yields. */
const DEFAULT_YIELD_EVERY = 1000;

/** Serializes a non-negative integer as a little-endian u64 byte array. */
function u64Le(value: number): Uint8Array {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, value >>> 0, true);
  view.setUint32(4, Math.floor(value / 0x1_0000_0000), true);
  return bytes;
}

/**
 * Computes the PoW hash for a given (input, nonce, timestamp) triple.
 * Matches `ProofOfWork::hash_pow` in `proof_of_work.rs`.
 */
export function hashPow(input: string, nonce: number, timestamp: number): Uint8Array {
  return sha256(concatBytes(
    new TextEncoder().encode(input),
    u64Le(nonce),
    u64Le(timestamp),
  ));
}

/**
 * Verifies that a (input, nonce, timestamp) triple satisfies `difficulty`
 * leading zero bits. Matches `ProofOfWork::verify_hash`.
 */
export function verifyPow(
  input: string,
  nonce: number,
  timestamp: number,
  difficulty: number,
): boolean {
  if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 256) return false;
  const hash = hashPow(input, nonce, timestamp);
  const requiredZeros = Math.floor(difficulty / 8);
  const remainingBits = difficulty % 8;
  for (let i = 0; i < requiredZeros; i++) {
    if (hash[i] !== 0) return false;
  }
  if (remainingBits > 0) {
    const mask = 0xff << (8 - remainingBits);
    if ((hash[requiredZeros] & mask) !== 0) return false;
  }
  return true;
}

/**
 * Mines a `proof_of_work` {@link SybilProof} for the given request-binding
 * `input` at the given `difficulty` (leading zero bits).
 *
 * The loop is async and yields to the event loop every `yieldEvery`
 * iterations so a long mine does not block other work.
 */
export async function generateProofOfWork(
  input: string,
  difficulty: number,
  opts: { timestamp?: number; yieldEvery?: number } = {},
): Promise<ProofOfWorkProof> {
  if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > MAX_POW_DIFFICULTY) {
    throw new Error(`difficulty must be an integer in [1, ${MAX_POW_DIFFICULTY}]`);
  }
  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000);
  const yieldEvery = opts.yieldEvery ?? DEFAULT_YIELD_EVERY;
  const requiredZeros = Math.floor(difficulty / 8);
  const remainingBits = difficulty % 8;
  const mask = remainingBits > 0 ? 0xff << (8 - remainingBits) : 0;

  let nonce = 0;
  for (;;) {
    const hash = hashPow(input, nonce, timestamp);
    let ok = true;
    for (let i = 0; i < requiredZeros; i++) {
      if (hash[i] !== 0) {
        ok = false;
        break;
      }
    }
    if (ok && (remainingBits === 0 || (hash[requiredZeros] & mask) === 0)) {
      return { type: 'proof_of_work', nonce, input, timestamp };
    }
    nonce++;
    if (nonce % yieldEvery === 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }
    if (nonce >= Number.MAX_SAFE_INTEGER) {
      throw new Error('exhausted nonce space');
    }
  }
}

/**
 * V4 single-issue request binding.
 * Matches `issue.rs`: `freebird:issue:v1:<issuer_id>:<blinded_element_b64>`.
 */
export function buildIssueBinding(issuerId: string, blindedElementB64: string): string {
  return `freebird:issue:v1:${issuerId}:${blindedElementB64}`;
}

/**
 * V5 public single-issue request binding.
 * Matches `public_issue.rs`: `freebird:public-issue:v1:<issuer_id>:<blinded_msg_b64>`.
 */
export function buildPublicIssueBinding(issuerId: string, blindedMsgB64: string): string {
  return `freebird:public-issue:v1:${issuerId}:${blindedMsgB64}`;
}

/**
 * V4 renewal request binding.
 * Matches `issue.rs`: `freebird:renew:v1:<issuer_id>:<blinded_element_b64>`.
 */
export function buildRenewBinding(issuerId: string, blindedElementB64: string): string {
  return `freebird:renew:v1:${issuerId}:${blindedElementB64}`;
}

/**
 * Batch request binding. Matches `batch_request_binding` in `batch_issue.rs`:
 * the SHA-256 of each element's little-endian u64 length followed by its bytes,
 * truncated to 16 bytes and base64url-encoded.
 *
 * `routeScope` is `"issue-batch"` (V4) or `"public-issue-batch"` (V5).
 */
export function buildBatchBinding(
  routeScope: string,
  issuerId: string,
  blindedElements: string[],
): string {
  const hasher = sha256.create();
  for (const element of blindedElements) {
    hasher.update(u64Le(element.length));
    hasher.update(new TextEncoder().encode(element));
  }
  const digest = hasher.digest();
  return `freebird:${routeScope}:v1:${issuerId}:${blindedElements.length}:${bytesToBase64Url(digest.slice(0, 16))}`;
}

/**
 * Resolves the PoW difficulty the client should mine at.
 *
 * Precedence: the issuer-published `/.well-known/issuer` `sybil` requirements
 * (when the mode is `pow`/`proof_of_work`), falling back to the client
 * `powDifficulty` config. Returns `undefined` when PoW is not required.
 */
export function resolvePowDifficulty(state: ClientState): number | undefined {
  const sybil = state.metadata?.sybil;
  if (sybil && (sybil.mode === 'pow' || sybil.mode === 'proof_of_work')) {
    const settings = sybil.settings as { difficulty?: number };
    if (typeof settings.difficulty === 'number' && settings.difficulty > 0) {
      return settings.difficulty;
    }
  }
  if (typeof state.config.powDifficulty === 'number' && state.config.powDifficulty > 0) {
    return state.config.powDifficulty;
  }
  return undefined;
}

/**
 * Resolves the effective sybil proof for a request.
 *
 * An explicitly provided proof is used verbatim. Otherwise, when PoW is
 * required (from metadata or config), a `proof_of_work` proof is mined against
 * the exact per-endpoint `binding`. Returns `undefined` when no proof is
 * required and none was provided.
 */
export async function resolveSybilProof(
  state: ClientState,
  provided: SybilProof | undefined,
  binding: string,
  factory?: SybilProofFactory,
  enforceProvidedBinding = false,
): Promise<SybilProof | undefined> {
  if (factory !== undefined) {
    const proof = await factory({ binding });
    assertProofBinding(proof, binding);
    return proof;
  }
  if (provided !== undefined) {
    if (enforceProvidedBinding) assertProofBinding(provided, binding);
    return provided;
  }
  const difficulty = resolvePowDifficulty(state);
  if (difficulty === undefined) return undefined;
  return generateProofOfWork(binding, difficulty);
}

/**
 * A PoW proof is the only proof variant whose request binding is visible to
 * the SDK.  Never silently reuse it for another chunk or retry: doing so
 * would make the proof attest to a different payload than the one posted.
 */
function assertProofBinding(proof: SybilProof, binding: string): void {
  if (proof.type === 'proof_of_work' && proof.input !== binding) {
    throw new FreebirdError('issuance', 'Sybil proof is bound to a different request');
  }
  if (proof.type === 'multi') {
    for (const nested of proof.proofs) assertProofBinding(nested, binding);
  }
}
