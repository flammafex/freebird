// SPDX-License-Identifier: Apache-2.0 OR MIT

import type {
  BatchVerifyResp,
  ClientConfig,
  ExchangeOutcome,
  ExchangeRequest,
  ExchangeRequestSource,
  ExchangeTransitionSelection,
  FreebirdToken,
  GraphIssuanceOutcome,
  GraphIssuancePolicyInfo,
  GraphIssuanceRecoveryContext,
  GraphIssuanceRequest,
  IssuePublicTokenOptions,
  IssuePublicTokensOptions,
  IssuePublicTokenForCurrentKeyOptions,
  IssuePublicTokensForCurrentKeyOptions,
  IssueTokensOptions,
  KeyDiscoveryMetadata,
  PublicBearerPass,
  PublicIssueResponse,
  PublicKeyInfo,
  FinalizedExchangeOutput,
  PreparedExchange,
  SybilProof,
  SybilProofFactory,
  VerifyResp,
} from './types.js';
import * as discovery from './client/discovery.js';
import * as exchangeProtocol from './client/exchange.js';
import * as graphIssuance from './client/graph_issuance.js';
import * as graphProtocol from './client/graph_protocol.js';
import * as graphRecovery from './client/graph_recovery.js';
import * as issuance from './client/issuance.js';
import * as poll from './client/poll.js';
import type { PollOptions } from './client/poll.js';
import * as protocol from './client/protocol.js';
import type { ExchangePassesOptions } from './client/protocol.js';
import { createClientState, type ClientState } from './client/state.js';
import type { TokenStore } from './types.js';
import * as verification from './client/verification.js';
import { base64UrlToBytes, bytesEqual } from './client/wire.js';
import * as rsa from './crypto/rsa.js';
import * as voprf from './crypto/voprf.js';

export class FreebirdClient {
  private state: ClientState;

  constructor(config: ClientConfig) {
    this.state = createClientState(config);
  }

  /**
   * The optional {@link TokenStore} configured for this client, or `undefined`
   * if none was provided.
   */
  get tokenStore(): TokenStore | undefined {
    return this.state.config.tokenStore;
  }

  /** Initializes the client by fetching the issuer's public key. */
  async init(): Promise<void> {
    return discovery.init(this.state);
  }

  /** Issues a new anonymous V4 token. */
  async issueToken(sybilProof?: SybilProof): Promise<FreebirdToken> {
    return issuance.issueToken(
      this.state,
      sybilProof,
      () => this.init(),
      () => this.refreshKeyDiscoveryMetadata(),
    );
  }

  /** Issues V4 with a fresh request-bound Sybil proof on every retry. */
  async issueTokenWithProofFactory(proofFactory: SybilProofFactory): Promise<FreebirdToken> {
    return issuance.issueToken(
      this.state,
      proofFactory,
      () => this.init(),
      () => this.refreshKeyDiscoveryMetadata(),
    );
  }

  /**
   * Issues a batch of anonymous V4 tokens.
   *
   * `msgs` determines how many tokens to issue (one per element; the element
   * content is not part of the V4 input). Inputs larger than 10_000 are
   * chunked into multiple requests. If any token fails, a
   * {@link BatchIssuanceError} is thrown carrying the per-token outcomes and
   * the successfully finalized tokens.
   */
  async issueTokens(
    msgs: Uint8Array[],
    opts: IssueTokensOptions = {},
  ): Promise<FreebirdToken[]> {
    return issuance.issueTokens(
      this.state,
      msgs,
      opts,
      () => this.init(),
      () => this.refreshKeyDiscoveryMetadata(),
    );
  }

  async getKeyDiscoveryMetadata(): Promise<KeyDiscoveryMetadata> {
    return discovery.getKeyDiscoveryMetadata(this.state);
  }

  /**
   * Forces a fresh fetch of the issuer's `/.well-known/keys` discovery
   * metadata, bypassing the TTL-based cache. Useful for long-lived clients
   * that want to observe key rotation proactively.
   */
  async refreshKeyDiscoveryMetadata(): Promise<KeyDiscoveryMetadata> {
    return discovery.refreshKeyDiscoveryMetadata(this.state);
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
      () => this.refreshKeyDiscoveryMetadata(),
    );
  }

  /**
   * Issues a complete V5 public bearer pass in one call.
   *
   * `msg` is the message to be blindly signed (typically the output of
   * `crypto.buildPublicBearerMessage(nonce, tokenKeyId, issuerId)`). The
   * caller supplies the nonce, token key ID, and issuer ID via `opts`, which
   * are also embedded in the returned pass.
   *
   * The blinding factor is held only in memory for the duration of the call
   * and is never persisted.
   */
  async issuePublicToken(
    msg: Uint8Array,
    opts: IssuePublicTokenOptions,
  ): Promise<PublicBearerPass> {
    return issuance.issuePublicToken(
      this.state,
      msg,
      opts,
      () => this.getKeyDiscoveryMetadata(),
      () => this.refreshKeyDiscoveryMetadata(),
    );
  }

  /**
   * Issues a batch of V5 public bearer passes in one call.
   *
   * Each `msgs[i]` is the message to be blindly signed (typically the output of
   * `crypto.buildPublicBearerMessage(nonces[i], tokenKeyId, issuerId)`).
   * `opts.nonces[i]` and `opts.issuerId` are embedded in the returned pass.
   * Inputs larger than 10_000 are chunked into multiple requests.
   */
  async issuePublicTokens(
    msgs: Uint8Array[],
    opts: IssuePublicTokensOptions,
  ): Promise<PublicBearerPass[]> {
    return issuance.issuePublicTokens(
      this.state,
      msgs,
      opts,
      () => this.getKeyDiscoveryMetadata(),
      () => this.refreshKeyDiscoveryMetadata(),
    );
  }

  /** Issues a V5 pass using the issuer's freshly refreshed current key. */
  async issuePublicTokenForCurrentKey(
    opts: IssuePublicTokenForCurrentKeyOptions = {},
  ): Promise<PublicBearerPass> {
    return issuance.issueCurrentPublicToken(
      this.state,
      opts,
      () => this.refreshKeyDiscoveryMetadata(),
    );
  }

  /** Issues V5 passes using the issuer's current key, one per nonce. */
  async issuePublicTokensForCurrentKey(
    nonces: Uint8Array[],
    opts: IssuePublicTokensForCurrentKeyOptions = {},
  ): Promise<PublicBearerPass[]> {
    return issuance.issueCurrentPublicTokens(
      this.state,
      nonces,
      opts,
      () => this.refreshKeyDiscoveryMetadata(),
    );
  }

  /**
   * Locally verifies the RSA-PSS signature of a V5 public bearer pass against
   * the given public key.
   *
   * NOTE: local verification checks only cryptographic validity. It does NOT
   * check spend status (whether the pass has already been used). Only the
   * verifier's `/v1/verify` endpoint enforces single-use replay protection.
   */
  async verifyPublicBearerPassLocally(
    pass: PublicBearerPass,
    keyInfo: PublicKeyInfo,
  ): Promise<boolean> {
    try {
      const { nonce, tokenKeyId, issuerId, signature } = voprf.parsePublicBearerPass(pass);
      if (issuerId !== keyInfo.issuer_id) return false;
      const publicKey = base64UrlToBytes(keyInfo.pubkey_spki_b64);
      const derivedKeyId = voprf.tokenKeyIdFromSpki(publicKey);
      const advertisedKeyId = voprf.tokenKeyIdFromHex(keyInfo.token_key_id);
      if (!bytesEqual(tokenKeyId, advertisedKeyId) || !bytesEqual(derivedKeyId, advertisedKeyId)) {
        return false;
      }
      const msg = voprf.buildPublicBearerMessage(nonce, tokenKeyId, issuerId);
      return rsa.rsaVerify(publicKey, msg, signature);
    } catch {
      return false;
    }
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

  /** Generates a canonical 16-byte base64url exchange operation id. */
  generateOperationId(): string {
    return protocol.generateOperationId();
  }

  /** Generates a canonical 32-byte base64url exchange status capability. */
  generateStatusCapability(): string {
    return protocol.generateStatusCapability();
  }

  /**
   * Assembles a valid V2 `ExchangeRequest` from an explicit graph/transition
   * selection, blinding the output slots with the target descriptors' keys.
   */
  async exchangePasses(
    sources: ExchangeRequestSource[],
    transition: { graphId: string; transitionId: string },
    opts: ExchangePassesOptions = {},
  ): Promise<ExchangeRequest> {
    return protocol.exchangePasses(
      sources,
      transition,
      opts,
      (graphId, transitionId) => this.selectExchangeTransition(graphId, transitionId),
    );
  }

  /** Prepares a V2 exchange and retains the state needed to finalize passes. */
  async prepareExchangePasses(
    sources: ExchangeRequestSource[],
    transition: { graphId: string; transitionId: string },
    opts: ExchangePassesOptions = {},
  ): Promise<PreparedExchange> {
    return protocol.prepareExchangePasses(
      sources,
      transition,
      opts,
      (graphId, transitionId) => this.selectExchangeTransition(graphId, transitionId),
    );
  }

  /** Finalizes the committed blind signatures from a prepared V2 exchange. */
  async finalizeExchangePasses(
    prepared: PreparedExchange,
    outcome: ExchangeOutcome,
  ): Promise<FinalizedExchangeOutput[]> {
    return protocol.finalizeExchangePasses(prepared, outcome);
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

  /**
   * Polls an exchange operation until it is committed or fails terminally.
   *
   * Retries while the status is `pending`, honoring the server's `retryAfter`
   * as the floor for the next poll. Throws {@link PollTimeoutError} on
   * `timeoutMs` and {@link PollAbortedError} on `signal` abort.
   */
  async pollExchangeStatus(
    request: ExchangeRequest,
    statusCapability: string,
    options: PollOptions = {},
  ): Promise<ExchangeOutcome> {
    return poll.pollExchangeStatus(
      () => this.getExchangeStatus(request, statusCapability),
      options,
    );
  }

  /**
   * Polls a graph issuance operation until it is committed or fails
   * terminally. Retries on retryable 503 outcomes. Throws
   * {@link PollTimeoutError} on `timeoutMs` and {@link PollAbortedError} on
   * `signal` abort.
   */
  async pollGraphIssuanceStatus(
    context: GraphIssuanceRecoveryContext,
    options: PollOptions = {},
  ): Promise<GraphIssuanceOutcome> {
    return poll.pollGraphIssuanceStatus(
      () => this.getGraphIssuanceStatus(context),
      options,
    );
  }

  graphIssuanceRequestDigest(request: GraphIssuanceRequest): string {
    return graphProtocol.graphIssuanceRequestDigest(request);
  }

  graphIssuanceAuthorizationBindingDigest(request: GraphIssuanceRequest): string {
    return graphProtocol.graphIssuanceAuthorizationBindingDigest(request);
  }

  /**
   * Verifies a token against the configured verifier, consuming it. Throws
   * typed errors on failure (see {@link verification.verifyToken}).
   */
  async verifyToken(token: FreebirdToken): Promise<VerifyResp> {
    return verification.verifyToken(this.state, token);
  }

  /**
   * Boolean convenience over {@link verifyToken}. Returns `false` for invalid
   * or replayed tokens; rethrows infrastructure errors (verifier unavailable,
   * rate limited, not configured).
   */
  async verifyTokenValid(token: FreebirdToken): Promise<boolean> {
    return verification.verifyTokenValid(this.state, token);
  }

  /**
   * Checks token validity WITHOUT consuming it (distinct `/v1/check` endpoint).
   */
  async checkToken(token: FreebirdToken): Promise<VerifyResp> {
    return verification.checkToken(this.state, token);
  }

  /** Verifies a batch of tokens in one request, consuming each. */
  async verifyBatch(tokens: FreebirdToken[]): Promise<BatchVerifyResp> {
    return verification.verifyBatch(this.state, tokens);
  }
}
