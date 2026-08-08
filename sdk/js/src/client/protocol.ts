// SPDX-License-Identifier: Apache-2.0 OR MIT

import type {
  ExchangeOutcome,
  ExchangeRequest,
  ExchangeRequestSource,
  ExchangeSlot,
  FinalizedExchangeOutput,
  PreparedExchange,
  PreparedExchangeOutput,
  RsaBlindState,
} from '../types.js';
import { ExchangeError } from '../errors.js';
import * as rsa from '../crypto/rsa.js';
import * as voprf from '../crypto/voprf.js';
import {
  base64UrlToBytes,
  bytesEqual,
  bytesToBase64Url,
  decodeCanonical,
  hasExactKeys,
  isCanonicalBase64Url,
} from './wire.js';
import type { SelectExchangeTransition } from './exchange.js';

/**
 * Options for {@link exchangePasses}.
 */
export interface ExchangePassesOptions {
  /**
   * Explicit public operation id. Defaults to a fresh {@link generateOperationId}.
   */
  publicOperationId?: string;
  /**
   * Messages to blind for each output slot, in `transition.output_slots` order.
   *
   * When omitted, a fresh 32-byte nonce is generated per output and the message
   * is built with the target descriptor's token key and issuer id, so the caller
   * writes no bespoke protocol code. Supply matching `nonces` and `messages`
   * when the caller needs to control the message while retaining finalization
   * state.
   */
  messages?: Uint8Array[];
  /** Per-output public bearer nonces, retained for later finalization. */
  nonces?: Uint8Array[];
}

interface PreparedOutputMetadata {
  owner: PreparedExchange;
  index: number;
  slot: ExchangeSlot;
  message: Uint8Array;
  nonce: Uint8Array;
  blindedValue: string;
  blindingState: RsaBlindState;
  issuerId: string;
  tokenKeyId: Uint8Array;
}

interface PreparedMetadata {
  request: ExchangeRequest;
  requestSnapshot: ExchangeRequest;
  outputs: PreparedOutputMetadata[];
}

/** In-memory details needed to build a pass, never included in the request. */
const preparedMetadata = new WeakMap<PreparedExchange, PreparedMetadata>();
const outputMetadata = new WeakMap<PreparedExchangeOutput, PreparedOutputMetadata>();

/**
 * Generates a canonical base64url operation id for exactly 16 bytes, matching
 * `validateExchangeOperationId` / `isCanonicalBase64Url(…, 16)`.
 *
 * The value is drawn from a CSPRNG because it is a public, non-secret operation
 * identifier that must still be unguessable to avoid operation collisions.
 */
export function generateOperationId(): string {
  return bytesToBase64Url(randomBytes(16));
}

/**
 * Generates a canonical base64url status capability for exactly 32 bytes,
 * matching `validateStatusCapability` / `validateGraphStatusCapability`.
 *
 * The value is drawn from a CSPRNG because it is an unguessable capability
 * token that authorizes status lookups for an exchange operation.
 */
export function generateStatusCapability(): string {
  return bytesToBase64Url(randomBytes(32));
}

/**
 * Prepares a V2 exchange request and retains the in-memory state required to
 * finalize the issuer's committed blind signatures.
 */
export async function prepareExchange(
  sources: ExchangeRequestSource[],
  transition: { graphId: string; transitionId: string },
  opts: ExchangePassesOptions = {},
  selectTransition: SelectExchangeTransition,
): Promise<PreparedExchange> {
  const selection = await selectTransition(transition.graphId, transition.transitionId);
  const { graph, transition: rule } = selection;
  if (sources.length !== rule.source_slots.length) {
    throw new ExchangeError('Exchange sources do not match the selected transition');
  }

  const messages = opts.messages;
  if (messages !== undefined && messages.length !== rule.output_slots.length) {
    throw new ExchangeError('Exchange output messages do not match the selected transition');
  }
  const nonces = opts.nonces;
  if (nonces !== undefined && nonces.length !== rule.output_slots.length) {
    throw new ExchangeError('Exchange output nonces do not match the selected transition');
  }

  const sourceKeysetId = rule.source_keyset_id;
  const targetKeysetId = rule.target_keyset_id;
  const assembledSources = sources.map((source, index) => {
    const expected = rule.source_slots[index];
    if (source.slot.descriptor_id !== expected.descriptor_id ||
      source.slot.keyset_id !== sourceKeysetId ||
      source.slot.slot_id !== expected.slot_id ||
      source.slot.quantity !== expected.quantity ||
      !isCanonicalBase64Url(source.artifact, undefined, 16 * 1024, 1)) {
      throw new ExchangeError('Exchange sources do not match the selected transition');
    }
    return source;
  });

  const preparedInputs = await Promise.all(rule.output_slots.map(async (slot, index) => {
    const descriptor = graph.descriptors.find(
      (candidate) => candidate.descriptor_id === slot.descriptor_id,
    );
    if (!descriptor) {
      throw new ExchangeError('Exchange output descriptor is not in the selected graph');
    }

    const nonce = nonces?.[index] ? new Uint8Array(nonces[index]) : randomBytes(32);
    if (nonce.length !== 32) throw new ExchangeError('Exchange output nonce must be 32 bytes');
    const tokenKeyId = voprf.tokenKeyIdFromHex(descriptor.token_key_id);
    const canonicalMessage = voprf.buildPublicBearerMessage(
      nonce,
      tokenKeyId,
      descriptor.issuer_id,
    );
    const message = messages?.[index]
      ? new Uint8Array(messages[index])
      : canonicalMessage;
    if (messages !== undefined && nonces !== undefined && !bytesEqual(message, canonicalMessage)) {
      throw new ExchangeError('Exchange output message does not match its nonce');
    }

    const publicKey = base64UrlToBytes(descriptor.pubkey_spki_b64);
    const { blinded, state } = await rsa.rsaBlind(publicKey, message);
    return {
      slot: {
        descriptor_id: slot.descriptor_id,
        keyset_id: targetKeysetId,
        slot_id: slot.slot_id,
        quantity: slot.quantity,
      },
      message,
      nonce,
      blindedValue: bytesToBase64Url(blinded),
      blindingState: state,
      issuerId: descriptor.issuer_id,
      tokenKeyId,
    };
  }));

  const request: ExchangeRequest = {
    version: 2,
    public_operation_id: opts.publicOperationId ?? generateOperationId(),
    graph_id: graph.graph_id,
    transition_id: rule.transition_id,
    source_keyset_id: sourceKeysetId,
    target_keyset_id: targetKeysetId,
    sources: assembledSources,
    outputs: preparedInputs.map((input) => ({
      slot: input.slot,
      blinded_value: input.blindedValue,
    })),
  };

  const prepared: PreparedExchange = {
    request,
    outputs: preparedInputs.map((input) => ({
      slot: input.slot,
      message: input.message,
      nonce: input.nonce,
      blindedValue: input.blindedValue,
      blindingState: input.blindingState,
    })),
  };
  const metadata: PreparedMetadata = {
    request,
    requestSnapshot: cloneRequest(request),
    outputs: [],
  };
  metadata.outputs = prepared.outputs.map((output, index) => {
    const input = preparedInputs[index];
    const details: PreparedOutputMetadata = {
      owner: prepared,
      index,
      slot: cloneSlot(output.slot),
      message: new Uint8Array(output.message),
      nonce: new Uint8Array(output.nonce),
      blindedValue: output.blindedValue,
      blindingState: output.blindingState,
      issuerId: input.issuerId,
      tokenKeyId: new Uint8Array(input.tokenKeyId),
    };
    outputMetadata.set(output, details);
    return details;
  });
  preparedMetadata.set(prepared, metadata);
  return prepared;
}

/**
 * Finalizes a prepared exchange after a committed issuer response. The result
 * is always in request/output order; any count, selector, slot, or blinded
 * value mismatch is rejected before a pass is returned.
 */
export async function finalizeExchange(
  prepared: PreparedExchange,
  outcome: ExchangeOutcome,
): Promise<FinalizedExchangeOutput[]> {
  if (!prepared || typeof prepared !== 'object') {
    throw new ExchangeError('Prepared exchange state is invalid');
  }
  const metadata = preparedMetadata.get(prepared);
  if (!metadata || prepared.request !== metadata.request ||
    !sameRequest(prepared.request, metadata.requestSnapshot) ||
    !Array.isArray(prepared.outputs) || prepared.outputs.length !== metadata.outputs.length) {
    throw new ExchangeError('Prepared exchange state is invalid');
  }
  for (const [index, output] of prepared.outputs.entries()) {
    if (!output || typeof output !== 'object') {
      throw new ExchangeError('Prepared exchange state is invalid');
    }
    const details = outputMetadata.get(output);
    if (!details || details.owner !== prepared || details.index !== index ||
      !sameSlot(output.slot, details.slot) || output.blindedValue !== details.blindedValue ||
      !(output.message instanceof Uint8Array) || !(output.nonce instanceof Uint8Array) ||
      !bytesEqual(output.message, details.message) || !bytesEqual(output.nonce, details.nonce) ||
      output.blindingState !== details.blindingState) {
      throw new ExchangeError('Prepared exchange state is invalid');
    }
  }

  if (!outcome || outcome.kind !== 'committed' || outcome.httpStatus !== 200 ||
    !outcome.response || !hasExactKeys(outcome.response, ['result', 'receipt'])) {
    throw new ExchangeError('Exchange outcome was not committed');
  }
  const result = outcome.response.result;
  if (!result || !hasExactKeys(result, [
    'version', 'public_operation_id', 'graph_id', 'transition_id', 'source_keyset_id',
    'target_keyset_id', 'outputs', 'result_digest',
  ]) || result.version !== 2 || result.public_operation_id !== prepared.request.public_operation_id ||
    result.graph_id !== prepared.request.graph_id || result.transition_id !== prepared.request.transition_id ||
    result.source_keyset_id !== prepared.request.source_keyset_id ||
    result.target_keyset_id !== prepared.request.target_keyset_id ||
    !isCanonicalBase64Url(result.result_digest, 32) || !Array.isArray(result.outputs) ||
    result.outputs.length !== prepared.request.outputs.length) {
    throw new ExchangeError('Exchange outcome does not match the prepared request');
  }

  const resultOutputs = result.outputs;
  if (!resultOutputs.every((output, index) => {
    const submitted = prepared.request.outputs[index];
    return hasExactKeys(output, ['slot', 'blinded_value', 'blind_signature']) &&
      sameSlot(output.slot, submitted.slot) && output.blinded_value === submitted.blinded_value &&
      typeof output.blind_signature === 'string' &&
      isCanonicalBase64Url(output.blind_signature, undefined, 512, 1);
  })) {
    throw new ExchangeError('Exchange outcome outputs do not match the prepared request');
  }

  try {
    return await Promise.all(resultOutputs.map(async (resultOutput, index) => {
      const output = prepared.outputs[index];
      const details = metadata.outputs[index];
      const expectedMessage = voprf.buildPublicBearerMessage(
        details.nonce,
        details.tokenKeyId,
        details.issuerId,
      );
      if (!bytesEqual(details.message, expectedMessage)) {
        throw new ExchangeError('Prepared exchange message does not match its nonce');
      }
      const blindSignature = decodeCanonical(resultOutput.blind_signature, undefined, 512, 1);
      const signature = await rsa.rsaUnblind(details.blindingState, blindSignature);
      if (!await rsa.rsaVerify(details.blindingState.publicKey, details.message, signature)) {
        throw new ExchangeError('Exchange blind signature did not verify');
      }
      return {
        slot: cloneSlot(output.slot),
        nonce: new Uint8Array(details.nonce),
        pass: voprf.buildPublicBearerPass(
          details.nonce,
          details.tokenKeyId,
          details.issuerId,
          signature,
        ),
      };
    }));
  } catch (error) {
    if (error instanceof ExchangeError) throw error;
    throw new ExchangeError('Exchange output finalization failed');
  }
}

/** Alias retained for callers that name the operation after its passes. */
export const prepareExchangePasses = prepareExchange;

/** Alias retained for callers that name the operation after its passes. */
export const finalizeExchangePasses = finalizeExchange;

/**
 * Assembles a valid V2 `ExchangeRequest` from an explicit graph/transition
 * selection, filling `public_operation_id`, `graph_id`, `transition_id`,
 * `source_keyset_id`, `target_keyset_id`, `sources`, and blinded `outputs`.
 *
 * `sources` must carry one artifact per `transition.source_slots` entry, with
 * slots matching the transition's source slots and keyset. Each output slot is
 * blinded with the target descriptor's RSA public key.
 */
export async function exchangePasses(
  sources: ExchangeRequestSource[],
  transition: { graphId: string; transitionId: string },
  opts: ExchangePassesOptions = {},
  selectTransition: SelectExchangeTransition,
): Promise<ExchangeRequest> {
  const prepared = await prepareExchange(sources, transition, opts, selectTransition);
  return prepared.request;
}

function cloneSlot(slot: ExchangeSlot): ExchangeSlot {
  return { ...slot };
}

function cloneRequest(request: ExchangeRequest): ExchangeRequest {
  return {
    ...request,
    sources: request.sources.map((source) => ({
      slot: cloneSlot(source.slot),
      artifact: source.artifact,
    })),
    outputs: request.outputs.map((output) => ({
      slot: cloneSlot(output.slot),
      blinded_value: output.blinded_value,
    })),
  };
}

function sameSlot(left: ExchangeSlot, right: ExchangeSlot): boolean {
  return !!left && !!right && left.descriptor_id === right.descriptor_id &&
    left.keyset_id === right.keyset_id &&
    left.slot_id === right.slot_id && left.quantity === right.quantity;
}

function sameRequest(left: ExchangeRequest, right: ExchangeRequest): boolean {
  if (!left || !right || !Array.isArray(left.sources) || !Array.isArray(right.sources) ||
    !Array.isArray(left.outputs) || !Array.isArray(right.outputs)) return false;
  return left.version === right.version &&
    left.public_operation_id === right.public_operation_id && left.graph_id === right.graph_id &&
    left.transition_id === right.transition_id && left.source_keyset_id === right.source_keyset_id &&
    left.target_keyset_id === right.target_keyset_id && left.sources.length === right.sources.length &&
    left.outputs.length === right.outputs.length &&
    left.sources.every((source, index) => source.artifact === right.sources[index].artifact &&
      sameSlot(source.slot, right.sources[index].slot)) &&
    left.outputs.every((output, index) => output.blinded_value === right.outputs[index].blinded_value &&
      sameSlot(output.slot, right.outputs[index].slot));
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}
