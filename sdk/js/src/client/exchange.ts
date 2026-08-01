// SPDX-License-Identifier: Apache-2.0 OR MIT

import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';
import type {
  ExchangeErrorCode,
  ExchangeGraphInfo,
  ExchangeReceipt,
  ExchangeOutcome,
  ExchangeRequest,
  ExchangeResult,
  ExchangeSlot,
  ExchangeSuccessResponse,
  ExchangeTransitionSelection,
} from '../types.js';
import type { ClientState } from './state.js';
import {
  ascii,
  base64UrlToBytes,
  bytesToBase64Url,
  decodeCanonical,
  hasExactKeys,
  isCanonicalBase64Url,
  isLowerHexId,
  isSafeUnsigned,
  pushU32,
  pushU64,
  put,
} from './wire.js';

export type SelectExchangeTransition = (
  graphId: string,
  transitionId: string,
) => Promise<ExchangeTransitionSelection>;
export type ExchangeDigest = (request: ExchangeRequest) => string;

function validateExchangeOperationId(operationId: string): void {
  if (!/^[A-Za-z0-9_-]{22}$/.test(operationId)) {
    throw new Error('Exchange operation ID must be canonical base64url for exactly 16 bytes');
  }
  let decoded: Uint8Array;
  try {
    decoded = base64UrlToBytes(operationId);
  } catch {
    throw new Error('Exchange operation ID must be canonical base64url for exactly 16 bytes');
  }
  if (decoded.length !== 16 || bytesToBase64Url(decoded) !== operationId) {
    throw new Error('Exchange operation ID must be canonical base64url for exactly 16 bytes');
  }
}

function validateStatusCapability(capability: string): void {
  if (!isCanonicalBase64Url(capability, 32)) {
    throw new Error('Exchange status capability must be canonical base64url for exactly 32 bytes');
  }
}

function isExchangeSlot(value: unknown): value is ExchangeSlot {
  return hasExactKeys(value, ['descriptor_id', 'keyset_id', 'slot_id', 'quantity']) &&
    typeof value.descriptor_id === 'string' && isLowerHexId(value.descriptor_id) &&
    typeof value.keyset_id === 'string' && isLowerHexId(value.keyset_id) &&
    typeof value.slot_id === 'string' && value.slot_id.length > 0 && value.slot_id.length <= 128 &&
    /^[\x00-\x7F]+$/.test(value.slot_id) && typeof value.quantity === 'number' &&
    Number.isSafeInteger(value.quantity) && value.quantity > 0 && value.quantity <= 0xffff_ffff;
}

function v2SelectorBytes(value: {
  version: number;
  public_operation_id: string;
  graph_id: string;
  transition_id: string;
  source_keyset_id: string;
  target_keyset_id: string;
}): Uint8Array {
  if (value.version !== 2 || !isCanonicalBase64Url(value.public_operation_id, 16) ||
    !isLowerHexId(value.graph_id) || !isLowerHexId(value.transition_id) ||
    !isLowerHexId(value.source_keyset_id) || !isLowerHexId(value.target_keyset_id) ||
    value.source_keyset_id === value.target_keyset_id) {
    throw new Error('Invalid V2 exchange selectors');
  }
  const output: number[] = [2];
  put(output, base64UrlToBytes(value.public_operation_id));
  for (const field of [value.graph_id, value.transition_id, value.source_keyset_id,
    value.target_keyset_id]) put(output, ascii(field));
  return new Uint8Array(output);
}

function slotBytes(slot: ExchangeSlot): number[] {
  const output: number[] = [];
  put(output, ascii(slot.descriptor_id));
  put(output, ascii(slot.keyset_id));
  put(output, ascii(slot.slot_id));
  pushU32(output, slot.quantity);
  return output;
}

function requestBytes(request: ExchangeRequest): Uint8Array {
  if (!hasExactKeys(request, [
    'version', 'public_operation_id', 'graph_id', 'transition_id', 'source_keyset_id',
    'target_keyset_id', 'sources', 'outputs',
  ])) throw new Error('Invalid V2 exchange request');
  const output: number[] = [...v2SelectorBytes(request)];
  if (!Array.isArray(request.sources) || !Array.isArray(request.outputs) ||
    request.sources.length === 0 || request.sources.length > 64 ||
    request.outputs.length === 0 || request.outputs.length > 64) {
    throw new Error('Invalid V2 exchange request');
  }
  pushU32(output, request.sources.length);
  for (const source of request.sources) {
    if (!hasExactKeys(source, ['slot', 'artifact']) || !isExchangeSlot(source.slot) ||
      source.slot.keyset_id !== request.source_keyset_id || typeof source.artifact !== 'string') {
      throw new Error('Invalid V2 exchange request');
    }
    const artifact = decodeCanonical(source.artifact, undefined, 16 * 1024, 1);
    output.push(...slotBytes(source.slot));
    put(output, artifact);
  }
  pushU32(output, request.outputs.length);
  for (const requestedOutput of request.outputs) {
    if (!hasExactKeys(requestedOutput, ['slot', 'blinded_value']) ||
      !isExchangeSlot(requestedOutput.slot) ||
      requestedOutput.slot.keyset_id !== request.target_keyset_id ||
      typeof requestedOutput.blinded_value !== 'string') {
      throw new Error('Invalid V2 exchange request');
    }
    const blinded = decodeCanonical(requestedOutput.blinded_value, undefined, 16 * 1024, 1);
    output.push(...slotBytes(requestedOutput.slot));
    put(output, blinded);
  }
  return new Uint8Array(output);
}

function resultBytes(result: ExchangeResult): Uint8Array {
  const output: number[] = [...v2SelectorBytes(result)];
  pushU32(output, result.outputs.length);
  for (const item of result.outputs) {
    output.push(...slotBytes(item.slot));
    put(output, decodeCanonical(item.blinded_value, undefined, 16 * 1024, 1));
    put(output, decodeCanonical(item.blind_signature, undefined, 512, 1));
  }
  return new Uint8Array(output);
}

function receiptPayload(receipt: ExchangeReceipt): Uint8Array {
  const output: number[] = [...v2SelectorBytes(receipt)];
  put(output, decodeCanonical(receipt.result_digest, 32));
  pushU64(output, receipt.created_at);
  pushU64(output, receipt.expires_at);
  put(output, ascii(receipt.receipt_key_id));
  return new Uint8Array(output);
}

export async function exchange(
  state: ClientState,
  request: ExchangeRequest,
  statusCapability: string,
  selectTransition: SelectExchangeTransition,
  digest: ExchangeDigest,
): Promise<ExchangeOutcome> {
  validateStatusCapability(statusCapability);
  const selection = await validateExchangeRequestSelection(request, selectTransition);
  digest(request);
  const response = await fetch(`${state.config.issuerUrl}/v2/public/exchange`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'exchange-status-capability': statusCapability,
    },
    body: JSON.stringify(request),
  });
  return parseExchangeResponse(state, response, request, selection.graph);
}

export async function getExchangeStatus(
  state: ClientState,
  publicOperationIdOrRequest: string | ExchangeRequest,
  statusCapability: string,
  request: ExchangeRequest | undefined,
  selectTransition: SelectExchangeTransition,
  digest: ExchangeDigest,
): Promise<ExchangeOutcome> {
  const submittedRequest = typeof publicOperationIdOrRequest === 'string'
    ? request
    : publicOperationIdOrRequest;
  const publicOperationId = typeof publicOperationIdOrRequest === 'string'
    ? publicOperationIdOrRequest
    : publicOperationIdOrRequest.public_operation_id;
  if (!submittedRequest) throw new Error('Original exchange request is required for status');
  validateExchangeOperationId(publicOperationId);
  validateStatusCapability(statusCapability);
  if (submittedRequest.public_operation_id !== publicOperationId) {
    throw new Error('Exchange status request does not match the submitted request');
  }
  const selection = await validateExchangeRequestSelection(submittedRequest, selectTransition);
  digest(submittedRequest);
  const url = `${state.config.issuerUrl}/v2/public/exchange/status?public_operation_id=${encodeURIComponent(publicOperationId)}`;
  const response = await fetch(url, {
    method: 'GET',
    headers: { 'exchange-status-capability': statusCapability },
  });
  return parseExchangeResponse(state, response, submittedRequest, selection.graph);
}

export function exchangeRequestDigest(request: ExchangeRequest): string {
  return bytesToBase64Url(sha256(new Uint8Array([
    ...ascii('freebird exchange request v2\0'),
    ...requestBytes(request),
  ])));
}

async function validateExchangeRequestSelection(
  request: ExchangeRequest,
  selectTransition: SelectExchangeTransition,
): Promise<ExchangeTransitionSelection> {
  requestBytes(request);
  const selection = await selectTransition(request.graph_id, request.transition_id);
  const transition = selection.transition;
  if (transition.source_keyset_id !== request.source_keyset_id ||
    transition.target_keyset_id !== request.target_keyset_id ||
    request.sources.length !== transition.source_slots.length ||
    request.outputs.length !== transition.output_slots.length) {
    throw new Error('Exchange request does not match the selected transition');
  }
  const slotsMatch = (
    actual: ExchangeRequest['sources'][number]['slot'],
    expected: { descriptor_id: string; slot_id: string; quantity: number },
    keysetId: string,
  ) => actual.descriptor_id === expected.descriptor_id && actual.keyset_id === keysetId &&
    actual.slot_id === expected.slot_id && actual.quantity === expected.quantity;
  if (!request.sources.every((source, index) =>
    slotsMatch(source.slot, transition.source_slots[index], request.source_keyset_id)) ||
    !request.outputs.every((output, index) =>
      slotsMatch(output.slot, transition.output_slots[index], request.target_keyset_id))) {
    throw new Error('Exchange request does not match the selected transition');
  }
  return selection;
}

async function parseExchangeResponse(
  state: ClientState,
  response: Response,
  submittedRequest: ExchangeRequest,
  selectedGraph: ExchangeGraphInfo,
): Promise<ExchangeOutcome> {
  const cacheControl = response.headers.get('Cache-Control');
  if (!cacheControl?.split(',').some((value) => value.trim().toLowerCase() === 'no-store')) {
    throw new Error('Exchange response did not enforce Cache-Control: no-store');
  }
  const rawResponseBody = await response.text();
  let body: unknown;
  try { body = JSON.parse(rawResponseBody) as unknown; }
  catch { throw new Error('Exchange endpoint returned malformed JSON'); }
  if (response.status === 200) {
    if (!await isExchangeSuccessResponse(state, body, submittedRequest, selectedGraph)) {
      throw new Error('Exchange endpoint returned malformed success JSON');
    }
    return {
      kind: 'committed', httpStatus: 200, response: body as ExchangeSuccessResponse,
      rawResponseBody, cacheControl: 'no-store',
    };
  }
  if (response.status === 202) {
    if (!hasExactKeys(body, ['error']) || body.error !== 'exchange_retryable') {
      throw new Error('Exchange endpoint returned malformed pending JSON');
    }
    const retryAfterHeader = response.headers.get('Retry-After');
    if (!retryAfterHeader || !/^(0|[1-9][0-9]*)$/.test(retryAfterHeader)) {
      throw new Error('Exchange pending response has invalid Retry-After');
    }
    return {
      kind: 'pending', httpStatus: 202, response: { error: 'exchange_retryable' },
      retryAfter: Number(retryAfterHeader), rawResponseBody, cacheControl: 'no-store',
    };
  }
  if (!hasExactKeys(body, ['error']) || !isExchangeErrorCode(body.error)) {
    throw new Error('Exchange endpoint returned malformed error JSON');
  }
  if (response.status === 403 && body.error === 'status_unauthorized') {
    throw new Error('Exchange status capability was not authorized');
  }
  const common = { rawResponseBody, cacheControl: 'no-store' as const };
  if (response.status === 400 && (
    body.error === 'invalid_status_capability' || body.error === 'invalid_public_operation_id' ||
    body.error === 'invalid_exchange_request' || body.error === 'invalid_exchange')) {
    return { ...common, kind: 'error', httpStatus: 400, response: { error: body.error } };
  }
  if (response.status === 413 && body.error === 'exchange_request_too_large') {
    return { ...common, kind: 'error', httpStatus: 413, response: { error: 'exchange_request_too_large' } };
  }
  if (response.status === 404 && body.error === 'unknown_operation') {
    return { ...common, kind: 'error', httpStatus: 404, response: { error: 'unknown_operation' } };
  }
  if (response.status === 409 && body.error === 'operation_conflict') {
    return { ...common, kind: 'error', httpStatus: 409, response: { error: 'operation_conflict' } };
  }
  if (response.status === 503 && body.error === 'exchange_unavailable') {
    return { ...common, kind: 'error', httpStatus: 503, response: { error: 'exchange_unavailable' } };
  }
  throw new Error('Exchange endpoint returned an unexpected error status');
}

async function isExchangeSuccessResponse(
  state: ClientState,
  value: unknown,
  submittedRequest: ExchangeRequest,
  selectedGraph: ExchangeGraphInfo,
): Promise<boolean> {
  if (!hasExactKeys(value, ['result', 'receipt'])) return false;
  const { result, receipt } = value;
  if (!hasExactKeys(result, [
    'version', 'public_operation_id', 'graph_id', 'transition_id', 'source_keyset_id',
    'target_keyset_id', 'outputs', 'result_digest',
  ]) || result.version !== 2 || typeof result.public_operation_id !== 'string' ||
    typeof result.graph_id !== 'string' || typeof result.transition_id !== 'string' ||
    typeof result.source_keyset_id !== 'string' || typeof result.target_keyset_id !== 'string' ||
    typeof result.result_digest !== 'string' || !Array.isArray(result.outputs) ||
    result.outputs.length === 0 || result.outputs.length > 64 ||
    result.outputs.length !== submittedRequest.outputs.length) return false;
  if (!result.outputs.every((output, index) =>
    isExchangeResultOutput(output, submittedRequest.outputs[index], result.target_keyset_id as string))) return false;
  if (!isCanonicalBase64Url(result.public_operation_id, 16) ||
    result.public_operation_id !== submittedRequest.public_operation_id ||
    result.graph_id !== submittedRequest.graph_id || result.transition_id !== submittedRequest.transition_id ||
    result.source_keyset_id !== submittedRequest.source_keyset_id ||
    result.target_keyset_id !== submittedRequest.target_keyset_id || !isLowerHexId(result.graph_id) ||
    !isLowerHexId(result.transition_id) || !isLowerHexId(result.source_keyset_id) ||
    !isLowerHexId(result.target_keyset_id) || !isCanonicalBase64Url(result.result_digest, 32)) return false;
  const calculatedResultDigest = bytesToBase64Url(
    sha256(new Uint8Array([
      ...ascii('freebird exchange result v2\0'),
      ...resultBytes(result as unknown as ExchangeSuccessResponse['result']),
    ])),
  );
  if (calculatedResultDigest !== result.result_digest) return false;
  if (!hasExactKeys(receipt, [
    'version', 'public_operation_id', 'graph_id', 'transition_id', 'source_keyset_id',
    'target_keyset_id', 'result_digest', 'created_at', 'expires_at', 'receipt_key_id', 'signature',
  ]) || receipt.version !== 2 || typeof receipt.public_operation_id !== 'string' ||
    typeof receipt.graph_id !== 'string' || typeof receipt.transition_id !== 'string' ||
    typeof receipt.source_keyset_id !== 'string' || typeof receipt.target_keyset_id !== 'string' ||
    typeof receipt.result_digest !== 'string' || !isSafeUnsigned(receipt.created_at) ||
    !isSafeUnsigned(receipt.expires_at) || receipt.expires_at <= receipt.created_at ||
    typeof receipt.receipt_key_id !== 'string' || typeof receipt.signature !== 'string' ||
    !isCanonicalBase64Url(receipt.public_operation_id, 16) || !isLowerHexId(receipt.graph_id) ||
    !isLowerHexId(receipt.transition_id) || !isLowerHexId(receipt.source_keyset_id) ||
    !isLowerHexId(receipt.target_keyset_id) || !isCanonicalBase64Url(receipt.result_digest, 32) ||
    !isLowerHexId(receipt.receipt_key_id) || !isCanonicalBase64Url(receipt.signature, 64)) return false;
  for (const field of [
    'public_operation_id', 'graph_id', 'transition_id', 'source_keyset_id',
    'target_keyset_id', 'result_digest',
  ] as const) if (receipt[field] !== result[field]) return false;
  const receiptKeys = state.keyDiscoveryMetadata?.exchange
    ? [state.keyDiscoveryMetadata.exchange.active_receipt_key,
      ...state.keyDiscoveryMetadata.exchange.retained_receipt_keys]
    : [];
  const receiptKey = receiptKeys.find((key) => key.key_id === receipt.receipt_key_id);
  if (!receiptKey || receipt.created_at < receiptKey.valid_from || receipt.expires_at > receiptKey.valid_until) return false;
  const receiptDigest = sha256(new Uint8Array([
    ...ascii('freebird exchange receipt v2\0'),
    ...receiptPayload(receipt as unknown as ExchangeSuccessResponse['receipt']),
  ]));
  try {
    return ed25519.verify(
      base64UrlToBytes(receipt.signature), receiptDigest, base64UrlToBytes(receiptKey.public_key_b64),
      { zip215: false },
    ) && selectedGraph.graph_id === result.graph_id;
  } catch {
    return false;
  }
}

function isExchangeResultOutput(
  value: unknown,
  submitted: ExchangeRequest['outputs'][number],
  targetKeysetId: string,
): boolean {
  return hasExactKeys(value, ['slot', 'blinded_value', 'blind_signature']) &&
    isExchangeSlot(value.slot) && value.slot.descriptor_id === submitted.slot.descriptor_id &&
    value.slot.keyset_id === submitted.slot.keyset_id && value.slot.keyset_id === targetKeysetId &&
    value.slot.slot_id === submitted.slot.slot_id && value.slot.quantity === submitted.slot.quantity &&
    typeof value.blinded_value === 'string' && value.blinded_value === submitted.blinded_value &&
    isCanonicalBase64Url(value.blinded_value, undefined, 16 * 1024) &&
    typeof value.blind_signature === 'string' &&
    isCanonicalBase64Url(value.blind_signature, undefined, 512, 1);
}

function isExchangeErrorCode(value: unknown): value is ExchangeErrorCode {
  return typeof value === 'string' && [
    'invalid_status_capability', 'invalid_public_operation_id', 'exchange_request_too_large',
    'exchange_unavailable', 'invalid_exchange_request', 'operation_conflict', 'invalid_exchange',
    'unknown_operation', 'status_unauthorized',
  ].includes(value);
}
