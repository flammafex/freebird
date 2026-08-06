// SPDX-License-Identifier: Apache-2.0 OR MIT

import type {
  GraphIssuanceOutcome,
  GraphIssuanceRecoveryContext,
  GraphIssuanceRequest,
} from '../types.js';
import type { ClientState } from './state.js';
import { GraphIssuanceError } from '../errors.js';
import {
  hasExactKeys,
  isCanonicalBase64Url,
  isLowerHexId,
} from './wire.js';
import {
  graphIssuanceRequestBytes,
  parseGraphIssuanceResponse,
  validateGraphStatusCapability,
  type GraphDigest,
} from './graph_protocol.js';

export async function createGraphIssuanceRecoveryContext(
  request: GraphIssuanceRequest,
  statusCapability: string,
  expectedTokenKeyId: string,
  blindingState: unknown,
  digest: GraphDigest,
): Promise<GraphIssuanceRecoveryContext> {
  validateGraphIssuanceRequest(request);
  validateGraphStatusCapability(statusCapability);
  if (!isLowerHexId(expectedTokenKeyId)) throw new GraphIssuanceError('Invalid graph issuance token key ID');
  if (blindingState === undefined || blindingState === null) {
    throw new GraphIssuanceError('Graph issuance blinding state is required for recovery');
  }
  return {
    request,
    requestDigest: digest(request),
    publicOperationId: request.public_operation_id,
    issuancePolicyId: request.issuance_policy_id,
    graphId: request.graph_id,
    keysetId: request.keyset_id,
    descriptorId: request.descriptor_id,
    statusCapability,
    expectedTokenKeyId,
    blindingState,
  };
}

export async function retryGraphBlindSignature(
  state: ClientState,
  context: GraphIssuanceRecoveryContext,
  digest: GraphDigest,
): Promise<GraphIssuanceOutcome> {
  const recovery = graphIssuanceRecovery(context, digest);
  const response = await (state.config.fetch ?? fetch)(`${state.config.issuerUrl}/v1/public/graph/issue`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'graph-issuance-status-capability': recovery.statusCapability,
    },
    body: JSON.stringify(recovery.request),
  });
  return parseGraphIssuanceResponse(
    response, recovery.request, recovery.expectedTokenKeyId, digest,
  );
}

export async function getGraphIssuanceStatus(
  state: ClientState,
  context: GraphIssuanceRecoveryContext,
  digest: GraphDigest,
): Promise<GraphIssuanceOutcome> {
  const recovery = graphIssuanceRecovery(context, digest);
  const url = `${state.config.issuerUrl}/v1/public/graph/issue/status?public_operation_id=${encodeURIComponent(recovery.request.public_operation_id)}`;
  const response = await (state.config.fetch ?? fetch)(url, {
    method: 'GET',
    headers: { 'graph-issuance-status-capability': recovery.statusCapability },
  });
  return parseGraphIssuanceResponse(
    response, recovery.request, recovery.expectedTokenKeyId, digest,
  );
}

function validateGraphIssuanceRequest(request: GraphIssuanceRequest): void {
  graphIssuanceRequestBytes(request, true);
}

/**
 * The serialization version for {@link serializeGraphIssuanceRecoveryContext}.
 * Bump on any breaking change to the envelope or context shape.
 */
const RECOVERY_CONTEXT_SERIALIZATION_VERSION = 1;
const RECOVERY_CONTEXT_TYPE = 'graph_issuance_recovery_context';

/**
 * Serializes a {@link GraphIssuanceRecoveryContext} to a documented JSON
 * envelope:
 *
 * ```json
 * {
 *   "version": 1,
 *   "type": "graph_issuance_recovery_context",
 *   "context": { ...GraphIssuanceRecoveryContext }
 * }
 * ```
 *
 * SECURITY: `blindingState` is opaque and caller-owned. It is included in the
 * round-trip so the context can be reconstructed in memory, but it may contain
 * secret RFC 9474 blinding material (`RsaBlindState.inv`). Do NOT persist this
 * serialization to a durable store; keep it in memory only. The token store
 * never stores recovery contexts.
 */
export function serializeGraphIssuanceRecoveryContext(
  context: GraphIssuanceRecoveryContext,
): string {
  return JSON.stringify({
    version: RECOVERY_CONTEXT_SERIALIZATION_VERSION,
    type: RECOVERY_CONTEXT_TYPE,
    context,
  });
}

/**
 * Deserializes a {@link GraphIssuanceRecoveryContext} produced by
 * {@link serializeGraphIssuanceRecoveryContext}. Validates the envelope and
 * the context shape. Throws {@link GraphIssuanceError} on malformed input.
 */
export function deserializeGraphIssuanceRecoveryContext(
  serialized: string,
): GraphIssuanceRecoveryContext {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new GraphIssuanceError('Invalid graph issuance recovery context serialization');
  }
  if (typeof parsed !== 'object' || parsed === null ||
    !hasExactKeys(parsed, ['version', 'type', 'context']) ||
    (parsed as { version: unknown }).version !== RECOVERY_CONTEXT_SERIALIZATION_VERSION ||
    (parsed as { type: unknown }).type !== RECOVERY_CONTEXT_TYPE) {
    throw new GraphIssuanceError('Invalid graph issuance recovery context serialization');
  }
  const context = (parsed as { context: unknown }).context;
  if (typeof context !== 'object' || context === null || !hasExactKeys(context, [
    'request', 'requestDigest', 'publicOperationId', 'issuancePolicyId', 'graphId',
    'keysetId', 'descriptorId', 'statusCapability', 'expectedTokenKeyId', 'blindingState',
  ])) {
    throw new GraphIssuanceError('Invalid graph issuance recovery context serialization');
  }
  return context as unknown as GraphIssuanceRecoveryContext;
}

function graphIssuanceRecovery(
  context: GraphIssuanceRecoveryContext,
  digest: GraphDigest,
): GraphIssuanceRecoveryContext {
  if (typeof context !== 'object' || context === null || !hasExactKeys(context, [
    'request', 'requestDigest', 'publicOperationId', 'issuancePolicyId', 'graphId',
    'keysetId', 'descriptorId', 'statusCapability', 'expectedTokenKeyId', 'blindingState',
  ])) {
    throw new GraphIssuanceError('Invalid graph issuance recovery context');
  }
  if (context.blindingState === undefined || context.blindingState === null ||
    !isLowerHexId(context.expectedTokenKeyId)) {
    throw new GraphIssuanceError('Invalid graph issuance recovery context');
  }
  validateGraphIssuanceRequest(context.request);
  if (!isCanonicalBase64Url(context.requestDigest, 32) ||
    context.requestDigest !== digest(context.request) ||
    !isCanonicalBase64Url(context.publicOperationId, 16) ||
    context.publicOperationId !== context.request.public_operation_id ||
    context.issuancePolicyId !== context.request.issuance_policy_id ||
    context.graphId !== context.request.graph_id ||
    context.keysetId !== context.request.keyset_id ||
    context.descriptorId !== context.request.descriptor_id) {
    throw new GraphIssuanceError('Invalid graph issuance recovery context');
  }
  validateGraphStatusCapability(context.statusCapability);
  return context;
}
