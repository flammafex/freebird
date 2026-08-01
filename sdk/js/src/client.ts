// SPDX-License-Identifier: Apache-2.0 OR MIT

import type {
  ClientConfig,
  ExchangeOutcome,
  ExchangeRequest,
  ExchangeTransitionSelection,
  FreebirdToken,
  GraphIssuanceOutcome,
  GraphIssuancePolicyInfo,
  GraphIssuanceRecoveryContext,
  GraphIssuanceRequest,
  KeyDiscoveryMetadata,
  PublicIssueResponse,
  SybilProof,
} from './types.js';
import * as discovery from './client/discovery.js';
import * as exchangeProtocol from './client/exchange.js';
import * as graphIssuance from './client/graph_issuance.js';
import * as graphProtocol from './client/graph_protocol.js';
import * as graphRecovery from './client/graph_recovery.js';
import * as issuance from './client/issuance.js';
import { createClientState, type ClientState } from './client/state.js';
import * as verification from './client/verification.js';

export class FreebirdClient {
  private state: ClientState;

  constructor(config: ClientConfig) {
    this.state = createClientState(config);
  }

  /** Initializes the client by fetching the issuer's public key. */
  async init(): Promise<void> {
    return discovery.init(this.state);
  }

  /** Issues a new anonymous V4 token. */
  async issueToken(sybilProof?: SybilProof): Promise<FreebirdToken> {
    return issuance.issueToken(this.state, sybilProof, () => this.init());
  }

  async getKeyDiscoveryMetadata(): Promise<KeyDiscoveryMetadata> {
    return discovery.getKeyDiscoveryMetadata(this.state);
  }

  /** Requests a V5 public bearer pass blind signature. */
  async issuePublicBlindSignature(
    blindedMsg: Uint8Array | string,
    sybilProof?: SybilProof,
    tokenKeyId?: string,
  ): Promise<PublicIssueResponse> {
    return issuance.issuePublicBlindSignature(
      this.state,
      blindedMsg,
      sybilProof,
      tokenKeyId,
      () => this.getKeyDiscoveryMetadata(),
    );
  }

  /** Resolves an explicit immutable graph and transition selection. */
  async selectExchangeTransition(
    graphId: string,
    transitionId: string,
  ): Promise<ExchangeTransitionSelection> {
    return discovery.selectExchangeTransition(
      () => this.getKeyDiscoveryMetadata(), graphId, transitionId,
    );
  }

  /** Starts or exactly retries a V2 public bearer exchange operation. */
  async exchange(request: ExchangeRequest, statusCapability: string): Promise<ExchangeOutcome> {
    return exchangeProtocol.exchange(
      this.state,
      request,
      statusCapability,
      (graphId, transitionId) => this.selectExchangeTransition(graphId, transitionId),
      (submittedRequest) => this.exchangeRequestDigest(submittedRequest),
    );
  }

  /** Looks up a V2 exchange operation. */
  async getExchangeStatus(
    submittedRequest: ExchangeRequest,
    statusCapability: string,
  ): Promise<ExchangeOutcome>;
  async getExchangeStatus(
    publicOperationId: string,
    statusCapability: string,
    submittedRequest: ExchangeRequest,
  ): Promise<ExchangeOutcome>;
  async getExchangeStatus(
    publicOperationIdOrRequest: string | ExchangeRequest,
    statusCapability: string,
    request?: ExchangeRequest,
  ): Promise<ExchangeOutcome> {
    return exchangeProtocol.getExchangeStatus(
      this.state,
      publicOperationIdOrRequest,
      statusCapability,
      request,
      (graphId, transitionId) => this.selectExchangeTransition(graphId, transitionId),
      (submittedRequest) => this.exchangeRequestDigest(submittedRequest),
    );
  }

  exchangeRequestDigest(request: ExchangeRequest): string {
    return exchangeProtocol.exchangeRequestDigest(request);
  }

  /** Resolves one current graph issuance policy. */
  async selectGraphIssuancePolicy(policyId: string): Promise<GraphIssuancePolicyInfo> {
    return graphIssuance.selectGraphIssuancePolicy(this.state, policyId);
  }

  /** Starts a fresh policy-authorized graph blind issuance operation. */
  async issueGraphBlindSignature(
    request: GraphIssuanceRequest,
    statusCapability: string,
  ): Promise<GraphIssuanceOutcome> {
    return graphIssuance.issueGraphBlindSignature(
      this.state,
      request,
      statusCapability,
      (policyId) => this.selectGraphIssuancePolicy(policyId),
      (graphRequest) => this.graphIssuanceRequestDigest(graphRequest),
    );
  }

  /** Retries an already-created graph issuance operation. */
  async retryGraphBlindSignature(
    context: GraphIssuanceRecoveryContext,
  ): Promise<GraphIssuanceOutcome> {
    return graphRecovery.retryGraphBlindSignature(
      this.state,
      context,
      (graphRequest) => this.graphIssuanceRequestDigest(graphRequest),
    );
  }

  /** Alias with the protocol name used by recovery callers. */
  async retryGraphIssuance(
    context: GraphIssuanceRecoveryContext,
  ): Promise<GraphIssuanceOutcome> {
    return this.retryGraphBlindSignature(context);
  }

  /** Builds a complete context suitable for durable recovery. */
  async createGraphIssuanceRecoveryContext(
    request: GraphIssuanceRequest,
    statusCapability: string,
    expectedTokenKeyId: string,
    blindingState: unknown,
  ): Promise<GraphIssuanceRecoveryContext> {
    return graphRecovery.createGraphIssuanceRecoveryContext(
      request,
      statusCapability,
      expectedTokenKeyId,
      blindingState,
      (graphRequest) => this.graphIssuanceRequestDigest(graphRequest),
    );
  }

  /** Observes a graph issuance result using persisted recovery context. */
  async getGraphIssuanceStatus(
    context: GraphIssuanceRecoveryContext,
  ): Promise<GraphIssuanceOutcome> {
    return graphRecovery.getGraphIssuanceStatus(
      this.state,
      context,
      (graphRequest) => this.graphIssuanceRequestDigest(graphRequest),
    );
  }

  graphIssuanceRequestDigest(request: GraphIssuanceRequest): string {
    return graphProtocol.graphIssuanceRequestDigest(request);
  }

  graphIssuanceAuthorizationBindingDigest(request: GraphIssuanceRequest): string {
    return graphProtocol.graphIssuanceAuthorizationBindingDigest(request);
  }

  async verifyToken(token: FreebirdToken): Promise<boolean> {
    return verification.verifyToken(this.state, token);
  }
}
