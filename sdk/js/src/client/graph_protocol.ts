// SPDX-License-Identifier: Apache-2.0 OR MIT

import { sha256 } from '@noble/hashes/sha256';
import type {
  GraphIssuanceRequest,
  GraphIssuanceResult,
} from '../types.js';
import {
  ascii,
  bytesToBase64Url,
  decodeCanonical,
  hasExactKeys,
  isBoundedAscii,
  isCanonicalBase64Url,
  isLowerHexId,
  pushU32,
  put,
} from './wire.js';

export function validateGraphStatusCapability(capability: string): void {
  if (!isCanonicalBase64Url(capability, 32)) {
    throw new Error('Graph issuance status capability must be canonical base64url for exactly 32 bytes');
  }
}

export function graphIssuanceRequestBytes(
  request: GraphIssuanceRequest,
  includeAuthorization: boolean,
): Uint8Array {
  if (!hasExactKeys(request, [
    'version', 'public_operation_id', 'issuance_policy_id', 'graph_id', 'keyset_id',
    'descriptor_id', 'blinded_message', 'authorization',
  ]) || request.version !== 2 || !isCanonicalBase64Url(request.public_operation_id, 16) ||
    !isBoundedAscii(request.issuance_policy_id) || !isLowerHexId(request.graph_id) ||
    !isLowerHexId(request.keyset_id) || !isLowerHexId(request.descriptor_id) ||
    typeof request.blinded_message !== 'string' || typeof request.authorization !== 'string') {
    throw new Error('Invalid graph issuance request');
  }
  const output: number[] = [2];
  put(output, decodeCanonical(request.public_operation_id, 16));
  for (const selector of [request.issuance_policy_id, request.graph_id, request.keyset_id,
    request.descriptor_id]) put(output, ascii(selector));
  put(output, decodeCanonical(request.blinded_message, undefined, 512, 1));
  if (includeAuthorization) put(output, decodeCanonical(request.authorization, undefined, 16 * 1024, 1));
  return new Uint8Array(output);
}

function graphResultBytes(value: GraphIssuanceResult): Uint8Array {
  const output: number[] = [2];
  put(output, decodeCanonical(value.public_operation_id, 16));
  for (const selector of [value.issuance_policy_id, value.graph_id, value.keyset_id,
    value.descriptor_id, value.token_key_id]) put(output, ascii(selector));
  pushU32(output, value.quantity);
  put(output, decodeCanonical(value.request_digest, 32));
  put(output, decodeCanonical(value.blind_signature, undefined, 512, 1));
  return new Uint8Array(output);
}

export function graphIssuanceRequestDigest(request: GraphIssuanceRequest): string {
  return bytesToBase64Url(sha256(new Uint8Array([
    ...ascii('freebird graph blind issuance request v2\0'),
    ...graphIssuanceRequestBytes(request, true),
  ])));
}

export function graphIssuanceAuthorizationBindingDigest(request: GraphIssuanceRequest): string {
  return bytesToBase64Url(sha256(new Uint8Array([
    ...ascii('freebird graph blind issuance authorization binding v2\0'),
    ...graphIssuanceRequestBytes(request, false),
  ])));
}

export function validateGraphIssuanceRequest(request: GraphIssuanceRequest): void {
  graphIssuanceRequestBytes(request, true);
}

export type GraphDigest = (request: GraphIssuanceRequest) => string;

export async function parseGraphIssuanceResponse(
  response: Response,
  request: GraphIssuanceRequest,
  expectedTokenKeyId: string,
  digest: GraphDigest,
): Promise<import('../types.js').GraphIssuanceOutcome> {
  const cacheControl = response.headers.get('Cache-Control');
  if (!cacheControl?.split(',').some((value) => value.trim().toLowerCase() === 'no-store')) {
    throw new Error('Graph issuance response did not enforce Cache-Control: no-store');
  }
  const rawResponseBody = await response.text();
  let body: unknown;
  try { body = JSON.parse(rawResponseBody) as unknown; }
  catch { throw new Error('Graph issuance endpoint returned malformed JSON'); }
  if (response.status === 200) {
    if (!isGraphIssuanceResult(body, request, expectedTokenKeyId, digest)) {
      throw new Error('Graph issuance endpoint returned malformed success JSON');
    }
    return { kind: 'committed', httpStatus: 200, response: body, rawResponseBody, cacheControl: 'no-store' };
  }
  if (!hasExactKeys(body, ['error']) || !isGraphIssuanceErrorCode(body.error)) {
    throw new Error('Graph issuance endpoint returned malformed error JSON');
  }
  if (response.status === 403 && body.error === 'status_unauthorized') {
    throw new Error('Graph issuance status capability was not authorized');
  }
  if (![400, 404, 409, 413, 503].includes(response.status) ||
    (response.status === 400 && ![
      'invalid_status_capability', 'invalid_public_operation_id',
      'invalid_graph_issuance_request', 'invalid_graph_issuance',
    ].includes(body.error)) ||
    (response.status === 404 && body.error !== 'unknown_operation') ||
    (response.status === 409 && body.error !== 'operation_conflict') ||
    (response.status === 413 && body.error !== 'graph_issuance_request_too_large') ||
    (response.status === 503 && body.error !== 'graph_issuance_unavailable')) {
    throw new Error('Graph issuance endpoint returned an unexpected error status');
  }
  return {
    kind: 'error',
    httpStatus: response.status as 400 | 404 | 409 | 413 | 503,
    response: { error: body.error },
    rawResponseBody,
    cacheControl: 'no-store',
  };
}

function isGraphIssuanceErrorCode(value: unknown): value is string {
  return typeof value === 'string' && [
    'invalid_status_capability',
    'invalid_public_operation_id',
    'graph_issuance_request_too_large',
    'invalid_graph_issuance_request',
    'invalid_graph_issuance',
    'operation_conflict',
    'unknown_operation',
    'graph_issuance_unavailable',
    'status_unauthorized',
  ].includes(value);
}

function isGraphIssuanceResult(
  value: unknown,
  request: GraphIssuanceRequest,
  expectedTokenKeyId: string,
  digest: GraphDigest,
): value is GraphIssuanceResult {
  if (!hasExactKeys(value, [
    'version', 'public_operation_id', 'issuance_policy_id', 'graph_id', 'keyset_id',
    'descriptor_id', 'token_key_id', 'quantity', 'request_digest', 'blind_signature',
    'result_digest',
  ]) || value.version !== 2 || typeof value.public_operation_id !== 'string' ||
    typeof value.issuance_policy_id !== 'string' || typeof value.graph_id !== 'string' ||
    typeof value.keyset_id !== 'string' || typeof value.descriptor_id !== 'string' ||
    typeof value.token_key_id !== 'string' || typeof value.quantity !== 'number' ||
    typeof value.request_digest !== 'string' || typeof value.blind_signature !== 'string' ||
    typeof value.result_digest !== 'string' ||
    value.public_operation_id !== request.public_operation_id ||
    value.issuance_policy_id !== request.issuance_policy_id || value.graph_id !== request.graph_id ||
    value.keyset_id !== request.keyset_id || value.descriptor_id !== request.descriptor_id ||
    !isLowerHexId(value.graph_id) || !isLowerHexId(value.keyset_id) ||
    !isLowerHexId(value.descriptor_id) || !isLowerHexId(value.token_key_id) ||
    value.token_key_id !== expectedTokenKeyId || value.quantity !== 1 ||
    !isCanonicalBase64Url(value.public_operation_id, 16) ||
    !isCanonicalBase64Url(value.request_digest, 32) ||
    !isCanonicalBase64Url(value.blind_signature, undefined, 512, 1) ||
    !isCanonicalBase64Url(value.result_digest, 32)) return false;
  if (value.request_digest !== digest(request)) return false;
  const resultDigest = bytesToBase64Url(sha256(new Uint8Array([
    ...ascii('freebird graph blind issuance result v2\0'),
    ...graphResultBytes(value as unknown as GraphIssuanceResult),
  ])));
  return resultDigest === value.result_digest;
}
