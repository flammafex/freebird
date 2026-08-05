// SPDX-License-Identifier: Apache-2.0 OR MIT

import type {
  ExchangeRequest,
  ExchangeRequestSource,
} from '../types.js';
import { ExchangeError } from '../errors.js';
import * as rsa from '../crypto/rsa.js';
import * as voprf from '../crypto/voprf.js';
import {
  base64UrlToBytes,
  bytesToBase64Url,
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
   * writes no bespoke protocol code. Supply explicit messages when the caller
   * needs to retain the nonces (and blinding state) for later unblinding.
   */
  messages?: Uint8Array[];
}

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
  const selection = await selectTransition(transition.graphId, transition.transitionId);
  const { graph, transition: rule } = selection;
  if (sources.length !== rule.source_slots.length) {
    throw new ExchangeError('Exchange sources do not match the selected transition');
  }
  const messages = opts.messages ?? [];
  if (messages.length !== rule.output_slots.length) {
    throw new ExchangeError('Exchange output messages do not match the selected transition');
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

  const outputs = await Promise.all(rule.output_slots.map(async (slot, index) => {
    const descriptor = graph.descriptors.find(
      (candidate) => candidate.descriptor_id === slot.descriptor_id,
    );
    if (!descriptor) {
      throw new ExchangeError('Exchange output descriptor is not in the selected graph');
    }
    const message = messages[index] ?? voprf.buildPublicBearerMessage(
      randomBytes(32),
      voprf.tokenKeyIdFromHex(descriptor.token_key_id),
      descriptor.issuer_id,
    );
    const { blinded } = await rsa.rsaBlind(
      base64UrlToBytes(descriptor.pubkey_spki_b64),
      message,
    );
    return {
      slot: {
        descriptor_id: slot.descriptor_id,
        keyset_id: targetKeysetId,
        slot_id: slot.slot_id,
        quantity: slot.quantity,
      },
      blinded_value: bytesToBase64Url(blinded),
    };
  }));

  return {
    version: 2,
    public_operation_id: opts.publicOperationId ?? generateOperationId(),
    graph_id: graph.graph_id,
    transition_id: rule.transition_id,
    source_keyset_id: sourceKeysetId,
    target_keyset_id: targetKeysetId,
    sources: assembledSources,
    outputs,
  };
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}
