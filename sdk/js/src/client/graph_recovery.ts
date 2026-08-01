// SPDX-License-Identifier: Apache-2.0 OR MIT

import type {
  GraphIssuanceOutcome,
  GraphIssuanceRecoveryContext,
  GraphIssuanceRequest,
} from '../types.js';
import type { ClientState } from './state.js';
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
  if (!isLowerHexId(expectedTokenKeyId)) throw new Error('Invalid graph issuance token key ID');
  if (blindingState === undefined || blindingState === null) {
    throw new Error('Graph issuance blinding state is required for recovery');
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
  const response = await fetch(`${state.config.issuerUrl}/v1/public/graph/issue`, {
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
  const response = await fetch(url, {
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

function graphIssuanceRecovery(
  context: GraphIssuanceRecoveryContext,
  digest: GraphDigest,
): GraphIssuanceRecoveryContext {
  if (typeof context !== 'object' || context === null || !hasExactKeys(context, [
    'request', 'requestDigest', 'publicOperationId', 'issuancePolicyId', 'graphId',
    'keysetId', 'descriptorId', 'statusCapability', 'expectedTokenKeyId', 'blindingState',
  ])) {
    throw new Error('Invalid graph issuance recovery context');
  }
  if (context.blindingState === undefined || context.blindingState === null ||
    !isLowerHexId(context.expectedTokenKeyId)) {
    throw new Error('Invalid graph issuance recovery context');
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
    throw new Error('Invalid graph issuance recovery context');
  }
  validateGraphStatusCapability(context.statusCapability);
  return context;
}
