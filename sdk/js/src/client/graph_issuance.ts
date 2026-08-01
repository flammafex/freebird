// SPDX-License-Identifier: Apache-2.0 OR MIT

import type {
  GraphIssuanceOutcome,
  GraphIssuancePolicyInfo,
  GraphIssuanceRequest,
} from '../types.js';
import type { ClientState } from './state.js';
import {
  refreshKeyDiscoveryMetadata,
} from './discovery.js';
import type { ExchangeDiscoveryMetadata } from '../types.js';
import {
  graphIssuanceRequestBytes,
  parseGraphIssuanceResponse,
  validateGraphStatusCapability,
  type GraphDigest,
} from './graph_protocol.js';

type SelectGraphPolicy = (policyId: string) => Promise<GraphIssuancePolicyInfo>;

export async function selectGraphIssuancePolicy(
  state: ClientState,
  policyId: string,
): Promise<GraphIssuancePolicyInfo> {
  const metadata = await refreshKeyDiscoveryMetadata(state);
  const policy = metadata.graph_issuance?.policies.find(
    (candidate) => candidate.issuance_policy_id === policyId,
  );
  if (!policy) throw new Error('Unknown graph issuance policy');
  if (policy.admission_state !== 'accepting_new' ||
    policy.graph_id !== metadata.exchange?.active_graph.graph_id) {
    throw new Error('Graph issuance policy is not accepting new issuance');
  }
  graphIssuanceTokenKeyId(metadata.exchange, policy.graph_id, policy.keyset_id, policy.descriptor_id);
  return policy;
}

export async function issueGraphBlindSignature(
  state: ClientState,
  request: GraphIssuanceRequest,
  statusCapability: string,
  selectPolicy: SelectGraphPolicy,
  digest: GraphDigest,
): Promise<GraphIssuanceOutcome> {
  validateGraphStatusCapability(statusCapability);
  const selection = await validateGraphIssuanceRequestSelection(
    state, request, selectPolicy,
  );
  digest(request);
  const response = await fetch(`${state.config.issuerUrl}/v1/public/graph/issue`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'graph-issuance-status-capability': statusCapability,
    },
    body: JSON.stringify(request),
  });
  return parseGraphIssuanceResponse(response, request, selection.tokenKeyId, digest);
}

async function validateGraphIssuanceRequestSelection(
  state: ClientState,
  request: GraphIssuanceRequest,
  selectPolicy: SelectGraphPolicy,
): Promise<{ policy: GraphIssuancePolicyInfo; tokenKeyId: string }> {
  graphIssuanceRequestBytes(request, true);
  const policy = await selectPolicy(request.issuance_policy_id);
  if (policy.admission_state !== 'accepting_new' || policy.graph_id !== request.graph_id ||
    policy.keyset_id !== request.keyset_id || policy.descriptor_id !== request.descriptor_id) {
    throw new Error('Graph issuance request does not match the selected active policy');
  }
  return {
    policy,
    tokenKeyId: graphIssuanceTokenKeyId(
      state.keyDiscoveryMetadata?.exchange,
      request.graph_id,
      request.keyset_id,
      request.descriptor_id,
    ),
  };
}

function graphIssuanceTokenKeyId(
  exchange: ExchangeDiscoveryMetadata | undefined,
  graphId: string,
  keysetId: string,
  descriptorId: string,
): string {
  const graph = exchange && [exchange.active_graph, ...exchange.retained_graphs]
    .find((candidate) => candidate.graph_id === graphId);
  const keyset = graph?.keysets.find((candidate) => candidate.keyset_id === keysetId);
  if (!keyset || !keyset.descriptor_ids.includes(descriptorId)) {
    throw new Error('Graph issuance selection has no valid token key');
  }
  const tokenKeyId = graph?.descriptors.find(
    (candidate) => candidate.descriptor_id === descriptorId,
  )?.token_key_id;
  if (!tokenKeyId) throw new Error('Graph issuance selection has no valid token key');
  return tokenKeyId;
}
