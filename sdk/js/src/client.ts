import {
  ClientConfig,
  IssuerMetadata,
  VerifierMetadata,
  IssueRequest,
  IssueResponse,
  KeyDiscoveryMetadata,
  PublicIssueResponse,
  ExchangeRequest,
  ExchangeOutcome,
  ExchangeSuccessResponse,
  ExchangeErrorCode,
  ExchangeSlot,
  ExchangeDiscoveryMetadata,
  ExchangeGraphInfo,
  ExchangeTransitionInfo,
  ExchangeTransitionSelection,
  ExchangeReceiptKeyInfo,
  GraphIssuancePolicyInfo,
  GraphIssuanceRequest,
  GraphIssuanceResult,
  GraphIssuanceOutcome,
  FreebirdToken,
  SybilProof,
} from './types.js';
import * as voprf from './crypto/voprf.js';
import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';

export class FreebirdClient {
  private config: ClientConfig;
  private metadata: IssuerMetadata | null = null;
  private keyDiscoveryMetadata: KeyDiscoveryMetadata | null = null;
  private verifierMetadata: VerifierMetadata | null = null;
  private context: Uint8Array;

  constructor(config: ClientConfig) {
    this.config = config;
    // This context MUST match the Rust server's context
    // Rust: freebird_crypto::VOPRF_CONTEXT_V4
    this.context = new TextEncoder().encode('freebird:v4');
  }

  /**
   * Initializes the client by fetching the issuer's public key.
   * This must be called before issuing tokens.
   */
  async init(): Promise<void> {
    if (this.metadata && this.verifierMetadata) return;

    if (!this.metadata) {
      const url = `${this.config.issuerUrl}/.well-known/issuer`;
      const res = await fetch(url);

      if (!res.ok) {
        throw new Error(`Failed to fetch issuer metadata: ${res.status} ${res.statusText}`);
      }

      this.metadata = (await res.json()) as IssuerMetadata;
    }

    if (!this.verifierMetadata) {
      if (this.config.verifierUrl) {
        const url = `${this.config.verifierUrl}/.well-known/verifier`;
        const res = await fetch(url);

        if (!res.ok) {
          throw new Error(`Failed to fetch verifier metadata: ${res.status} ${res.statusText}`);
        }

        this.verifierMetadata = (await res.json()) as VerifierMetadata;
      } else if (this.config.verifierId && this.config.audience) {
        this.verifierMetadata = {
          verifier_id: this.config.verifierId,
          audience: this.config.audience,
          scope_digest_b64: this.bytesToBase64Url(
            voprf.buildScopeDigest(this.config.verifierId, this.config.audience)
          ),
        };
      } else {
        throw new Error('Verifier scope required: configure verifierUrl or verifierId+audience');
      }
    }
  }

  /**
   * Issues a new anonymous token.
   *
   * @param sybilProof - Optional proof (e.g. invite code, PoW) if required by the issuer
   */
  async issueToken(sybilProof?: SybilProof): Promise<FreebirdToken> {
    if (!this.metadata) {
      await this.init();
    }

    // 1. Generate the public V4 token input and blind it.
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const scopeDigest = this.base64UrlToBytes(this.verifierMetadata!.scope_digest_b64);
    const expectedScopeDigest = voprf.buildScopeDigest(
      this.verifierMetadata!.verifier_id,
      this.verifierMetadata!.audience
    );
    if (!this.bytesEqual(scopeDigest, expectedScopeDigest)) {
      throw new Error('Verifier scope metadata is inconsistent');
    }
    const input = voprf.buildPrivateTokenInput(
      this.metadata!.issuer_id,
      this.metadata!.voprf.kid,
      nonce,
      scopeDigest
    );
    const { blinded, state } = voprf.blind(input, this.context);

    // 2. Prepare request
    const reqBody: IssueRequest = {
      blinded_element_b64: this.bytesToBase64Url(blinded),
      sybil_proof: sybilProof,
    };

    // 3. Send to Issuer
    const res = await fetch(`${this.config.issuerUrl}/v1/oprf/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reqBody),
    });

    if (!res.ok) {
      const errText = await res.text();
      // Handle Sybil resistance errors explicitly
      if (res.status === 400 || res.status === 401 || res.status === 403) {
        throw new Error(`Issuer rejected request: ${errText}`);
      }
      throw new Error(`Token issuance failed (${res.status}): ${errText}`);
    }

    const resp = (await res.json()) as IssueResponse;
    if (
      resp.kid !== this.metadata!.voprf.kid ||
      resp.issuer_id !== this.metadata!.issuer_id
    ) {
      throw new Error('Issuer metadata changed during issuance');
    }

    // 4. Finalize: verify DLEQ proof and unblind to get PRF output
    const output = voprf.finalize(
      state,
      resp.token,
      this.metadata!.voprf.pubkey,
      this.context
    );

    // 5. Build V4 redemption token (private-verification wire format)
    const redemptionToken = voprf.buildRedemptionToken(
      nonce,
      scopeDigest,
      resp.kid,
      resp.issuer_id,
      output,
    );

    // 6. Return usable token
    return {
      tokenValue: this.bytesToBase64Url(redemptionToken),
      issuerId: resp.issuer_id,
      version: 4,
      kid: resp.kid,
    };
  }

  async getKeyDiscoveryMetadata(): Promise<KeyDiscoveryMetadata> {
    if (this.keyDiscoveryMetadata) return this.keyDiscoveryMetadata;

    const url = `${this.config.issuerUrl}/.well-known/keys`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Failed to fetch issuer key metadata: ${res.status} ${res.statusText}`);
    }
    const metadata = (await res.json()) as KeyDiscoveryMetadata;
    if (metadata.exchange !== undefined) {
      await this.validateExchangeDiscovery(metadata.issuer_id, metadata.exchange);
    }
    if (metadata.graph_issuance !== undefined) {
      if (!metadata.exchange) throw new Error('Invalid graph issuance discovery metadata');
      this.validateGraphIssuanceDiscovery(metadata.graph_issuance, metadata.exchange);
    }
    this.keyDiscoveryMetadata = metadata;
    return this.keyDiscoveryMetadata;
  }

  /**
   * Requests a V5 public bearer pass blind signature.
   *
   * The SDK builds V5 message/token bytes, but it does not implement RSA
   * blinding. Pass `blindedMsg` from an RFC 9474
   * RSABSSA-SHA384-PSS-Deterministic implementation and finalize the returned
   * `blind_signature_b64` with that same implementation.
   */
  async issuePublicBlindSignature(
    blindedMsg: Uint8Array | string,
    sybilProof?: SybilProof,
    tokenKeyId?: string
  ): Promise<PublicIssueResponse> {
    const requestedKeyId =
      tokenKeyId ?? (await this.getKeyDiscoveryMetadata()).public.find((key) =>
        key.token_type === 'public_bearer_pass' &&
        key.rfc9474_variant === 'RSABSSA-SHA384-PSS-Deterministic' &&
        key.spend_policy === 'single_use'
      )?.token_key_id;

    if (!requestedKeyId) {
      throw new Error('No V5 public bearer key is available');
    }

    const blinded_msg_b64 =
      typeof blindedMsg === 'string' ? blindedMsg : this.bytesToBase64Url(blindedMsg);

    const res = await fetch(`${this.config.issuerUrl}/v1/public/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        blinded_msg_b64,
        token_key_id: requestedKeyId,
        sybil_proof: sybilProof,
      }),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Public bearer issuance failed (${res.status}): ${errText}`);
    }

    return (await res.json()) as PublicIssueResponse;
  }

  /** Resolves an explicit immutable graph and transition selection. */
  async selectExchangeTransition(
    graphId: string,
    transitionId: string
  ): Promise<ExchangeTransitionSelection> {
    const metadata = await this.getKeyDiscoveryMetadata();
    if (!metadata.exchange) throw new Error('Issuer does not publish V2 exchange discovery');
    const graph = [metadata.exchange.active_graph, ...metadata.exchange.retained_graphs]
      .find((candidate) => candidate.graph_id === graphId);
    const transition = graph?.transitions.find(
      (candidate) => candidate.transition_id === transitionId
    );
    if (!graph || !transition) throw new Error('Unknown exchange graph or transition');
    return { graph, transition };
  }

  /**
   * Starts or exactly retries a V2 public bearer exchange operation.
   * The public operation ID is part of `request`; the independent 32-byte
   * status capability is sent only in `exchange-status-capability`.
   */
  async exchange(request: ExchangeRequest, statusCapability: string): Promise<ExchangeOutcome> {
    this.validateStatusCapability(statusCapability);
    const selection = await this.validateExchangeRequestSelection(request);
    // Recompute the exact digest the server will bind to the operation.
    this.exchangeRequestDigest(request);
    const response = await fetch(`${this.config.issuerUrl}/v2/public/exchange`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'exchange-status-capability': statusCapability,
      },
      body: JSON.stringify(request),
    });
    return this.parseExchangeResponse(response, request, selection.graph);
  }

  /**
   * Looks up an exchange operation. The public ID is put in the query while
   * the unrelated status capability remains header-only.
   */
  async getExchangeStatus(
    submittedRequest: ExchangeRequest,
    statusCapability: string
  ): Promise<ExchangeOutcome>;
  async getExchangeStatus(
    publicOperationId: string,
    statusCapability: string,
    submittedRequest: ExchangeRequest
  ): Promise<ExchangeOutcome>;
  async getExchangeStatus(
    publicOperationIdOrRequest: string | ExchangeRequest,
    statusCapability: string,
    request?: ExchangeRequest
  ): Promise<ExchangeOutcome> {
    const submittedRequest = typeof publicOperationIdOrRequest === 'string'
      ? request
      : publicOperationIdOrRequest;
    const publicOperationId = typeof publicOperationIdOrRequest === 'string'
      ? publicOperationIdOrRequest
      : publicOperationIdOrRequest.public_operation_id;
    if (!submittedRequest) throw new Error('Original exchange request is required for status');
    this.validateExchangeOperationId(publicOperationId);
    this.validateStatusCapability(statusCapability);
    if (submittedRequest.public_operation_id !== publicOperationId) {
      throw new Error('Exchange status request does not match the submitted request');
    }
    const selection = await this.validateExchangeRequestSelection(submittedRequest);
    this.exchangeRequestDigest(submittedRequest);
    const url = `${this.config.issuerUrl}/v2/public/exchange/status?public_operation_id=${encodeURIComponent(publicOperationId)}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'exchange-status-capability': statusCapability },
    });
    return this.parseExchangeResponse(response, submittedRequest, selection.graph);
  }

  /** Canonical V2 request digest, matching `ExchangeRequestV2::request_digest`. */
  exchangeRequestDigest(request: ExchangeRequest): string {
    return this.bytesToBase64Url(
      sha256(this.concatBytes(this.ascii('freebird exchange request v2\0'), this.requestBytes(request)))
    );
  }

  /** Resolve one explicitly configured graph initial-issuance policy. */
  async selectGraphIssuancePolicy(policyId: string): Promise<GraphIssuancePolicyInfo> {
    const metadata = await this.getKeyDiscoveryMetadata();
    const policy = metadata.graph_issuance?.policies.find(
      (candidate) => candidate.issuance_policy_id === policyId
    );
    if (!policy) throw new Error('Unknown graph issuance policy');
    return policy;
  }

  /** Start or exactly retry policy-authorized graph blind issuance. */
  async issueGraphBlindSignature(
    request: GraphIssuanceRequest,
    statusCapability: string
  ): Promise<GraphIssuanceOutcome> {
    this.validateGraphStatusCapability(statusCapability);
    await this.validateGraphIssuanceRequestSelection(request);
    this.graphIssuanceRequestDigest(request);
    const response = await fetch(`${this.config.issuerUrl}/v1/public/graph/issue`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'graph-issuance-status-capability': statusCapability,
      },
      body: JSON.stringify(request),
    });
    return this.parseGraphIssuanceResponse(response, request);
  }

  /** Observe a graph issuance result; exact POST remains the recovery action. */
  async getGraphIssuanceStatus(
    request: GraphIssuanceRequest,
    statusCapability: string
  ): Promise<GraphIssuanceOutcome> {
    this.validateGraphStatusCapability(statusCapability);
    await this.validateGraphIssuanceRequestSelection(request);
    const url = `${this.config.issuerUrl}/v1/public/graph/issue/status?public_operation_id=${encodeURIComponent(request.public_operation_id)}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'graph-issuance-status-capability': statusCapability },
    });
    return this.parseGraphIssuanceResponse(response, request);
  }

  /** Canonical request digest matching `GraphIssuanceRequestV1::request_digest`. */
  graphIssuanceRequestDigest(request: GraphIssuanceRequest): string {
    return this.bytesToBase64Url(sha256(this.concatBytes(
      this.ascii('freebird graph blind issuance request v1\0'),
      this.graphIssuanceRequestBytes(request, true)
    )));
  }

  /** Binding an external policy verifier signs before adding opaque authorization. */
  graphIssuanceAuthorizationBindingDigest(request: GraphIssuanceRequest): string {
    return this.bytesToBase64Url(sha256(this.concatBytes(
      this.ascii('freebird graph blind issuance authorization binding v1\0'),
      this.graphIssuanceRequestBytes(request, false)
    )));
  }

  /**
   * Verifies a token with the configured verifier.
   * Useful for testing or client-side checks.
   */
  async verifyToken(token: FreebirdToken): Promise<boolean> {
    if (!this.config.verifierUrl) {
      throw new Error('Verifier URL not configured');
    }

    const res = await fetch(`${this.config.verifierUrl}/v1/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token_b64: token.tokenValue,
      }),
    });

    if (!res.ok) return false;
    const body = await res.json();
    return body.ok === true;
  }

  // --- Utilities ---

  private validateExchangeOperationId(operationId: string): void {
    if (!/^[A-Za-z0-9_-]{22}$/.test(operationId)) {
      throw new Error('Exchange operation ID must be canonical base64url for exactly 16 bytes');
    }
    let decoded: Uint8Array;
    try {
      decoded = this.base64UrlToBytes(operationId);
    } catch {
      throw new Error('Exchange operation ID must be canonical base64url for exactly 16 bytes');
    }
    if (decoded.length !== 16 || this.bytesToBase64Url(decoded) !== operationId) {
      throw new Error('Exchange operation ID must be canonical base64url for exactly 16 bytes');
    }
  }

  private validateStatusCapability(capability: string): void {
    if (!this.isCanonicalBase64Url(capability, 32)) {
      throw new Error('Exchange status capability must be canonical base64url for exactly 32 bytes');
    }
  }

  private async parseExchangeResponse(
    response: Response,
    submittedRequest: ExchangeRequest,
    selectedGraph: ExchangeGraphInfo
  ): Promise<ExchangeOutcome> {
    const cacheControl = response.headers.get('Cache-Control');
    if (!cacheControl?.split(',').some((value) => value.trim().toLowerCase() === 'no-store')) {
      throw new Error('Exchange response did not enforce Cache-Control: no-store');
    }

    const rawResponseBody = await response.text();
    let body: unknown;
    try {
      body = JSON.parse(rawResponseBody) as unknown;
    } catch {
      throw new Error('Exchange endpoint returned malformed JSON');
    }

    if (response.status === 200) {
      if (!(await this.isExchangeSuccessResponse(body, submittedRequest, selectedGraph))) {
        throw new Error('Exchange endpoint returned malformed success JSON');
      }
      return {
        kind: 'committed',
        httpStatus: 200,
        response: body as ExchangeSuccessResponse,
        rawResponseBody,
        cacheControl: 'no-store',
      };
    }

    if (response.status === 202) {
      if (!this.hasExactKeys(body, ['error']) || body.error !== 'exchange_retryable') {
        throw new Error('Exchange endpoint returned malformed pending JSON');
      }
      const retryAfterHeader = response.headers.get('Retry-After');
      if (!retryAfterHeader || !/^(0|[1-9][0-9]*)$/.test(retryAfterHeader)) {
        throw new Error('Exchange pending response has invalid Retry-After');
      }
      return {
        kind: 'pending',
        httpStatus: 202,
        response: { error: 'exchange_retryable' },
        retryAfter: Number(retryAfterHeader),
        rawResponseBody,
        cacheControl: 'no-store',
      };
    }

    if (!this.hasExactKeys(body, ['error']) || !this.isExchangeErrorCode(body.error)) {
      throw new Error('Exchange endpoint returned malformed error JSON');
    }
    if (response.status === 403 && body.error === 'status_unauthorized') {
      throw new Error('Exchange status capability was not authorized');
    }
    const common = { rawResponseBody, cacheControl: 'no-store' as const };
    if (
      response.status === 400 &&
      (body.error === 'invalid_status_capability' ||
        body.error === 'invalid_public_operation_id' ||
        body.error === 'invalid_exchange_request' ||
        body.error === 'invalid_exchange')
    ) {
      return {
        ...common,
        kind: 'error',
        httpStatus: 400,
        response: { error: body.error },
      };
    }
    if (response.status === 413 && body.error === 'exchange_request_too_large') {
      return {
        ...common,
        kind: 'error',
        httpStatus: 413,
        response: { error: 'exchange_request_too_large' },
      };
    }
    if (response.status === 404 && body.error === 'unknown_operation') {
      return {
        ...common,
        kind: 'error',
        httpStatus: 404,
        response: { error: 'unknown_operation' },
      };
    }
    if (response.status === 409 && body.error === 'operation_conflict') {
      return {
        ...common,
        kind: 'error',
        httpStatus: 409,
        response: { error: 'operation_conflict' },
      };
    }
    if (response.status === 503 && body.error === 'exchange_unavailable') {
      return {
        ...common,
        kind: 'error',
        httpStatus: 503,
        response: { error: 'exchange_unavailable' },
      };
    }
    throw new Error('Exchange endpoint returned an unexpected error status');
  }

  private async isExchangeSuccessResponse(
    value: unknown,
    submittedRequest: ExchangeRequest,
    selectedGraph: ExchangeGraphInfo
  ): Promise<boolean> {
    if (!this.hasExactKeys(value, ['result', 'receipt'])) return false;
    const { result, receipt } = value;
    if (
      !this.hasExactKeys(result, [
        'version',
        'public_operation_id',
        'graph_id',
        'transition_id',
        'source_keyset_id',
        'target_keyset_id',
        'outputs',
        'result_digest',
      ]) ||
      result.version !== 2 ||
      typeof result.public_operation_id !== 'string' ||
      typeof result.graph_id !== 'string' ||
      typeof result.transition_id !== 'string' ||
      typeof result.source_keyset_id !== 'string' ||
      typeof result.target_keyset_id !== 'string' ||
      typeof result.result_digest !== 'string' ||
      !Array.isArray(result.outputs) ||
      result.outputs.length === 0 ||
      result.outputs.length > 64 ||
      result.outputs.length !== submittedRequest.outputs.length
    ) {
      return false;
    }
    if (
      !result.outputs.every((output, index) =>
        this.isExchangeResultOutput(
          output,
          submittedRequest.outputs[index],
          result.target_keyset_id as string
        )
      )
    ) {
      return false;
    }
    if (
      !this.isCanonicalBase64Url(result.public_operation_id, 16) ||
      result.public_operation_id !== submittedRequest.public_operation_id ||
      result.graph_id !== submittedRequest.graph_id ||
      result.transition_id !== submittedRequest.transition_id ||
      result.source_keyset_id !== submittedRequest.source_keyset_id ||
      result.target_keyset_id !== submittedRequest.target_keyset_id ||
      !this.isLowerHexId(result.graph_id) ||
      !this.isLowerHexId(result.transition_id) ||
      !this.isLowerHexId(result.source_keyset_id) ||
      !this.isLowerHexId(result.target_keyset_id) ||
      !this.isCanonicalBase64Url(result.result_digest, 32)
    ) {
      return false;
    }
    const calculatedResultDigest = this.bytesToBase64Url(
      sha256(this.concatBytes(
        this.ascii('freebird exchange result v2\0'),
        this.resultBytes(result as unknown as ExchangeSuccessResponse['result'])
      ))
    );
    if (calculatedResultDigest !== result.result_digest) return false;

    if (
      !this.hasExactKeys(receipt, [
        'version',
        'public_operation_id',
        'graph_id',
        'transition_id',
        'source_keyset_id',
        'target_keyset_id',
        'result_digest',
        'created_at',
        'expires_at',
        'receipt_key_id',
        'signature',
      ]) ||
      receipt.version !== 2 ||
      typeof receipt.public_operation_id !== 'string' ||
      typeof receipt.graph_id !== 'string' ||
      typeof receipt.transition_id !== 'string' ||
      typeof receipt.source_keyset_id !== 'string' ||
      typeof receipt.target_keyset_id !== 'string' ||
      typeof receipt.result_digest !== 'string' ||
      !this.isSafeUnsigned(receipt.created_at) ||
      !this.isSafeUnsigned(receipt.expires_at) ||
      receipt.expires_at <= receipt.created_at ||
      typeof receipt.receipt_key_id !== 'string' ||
      typeof receipt.signature !== 'string' ||
      !this.isCanonicalBase64Url(receipt.public_operation_id, 16) ||
      !this.isLowerHexId(receipt.graph_id) ||
      !this.isLowerHexId(receipt.transition_id) ||
      !this.isLowerHexId(receipt.source_keyset_id) ||
      !this.isLowerHexId(receipt.target_keyset_id) ||
      !this.isCanonicalBase64Url(receipt.result_digest, 32) ||
      !this.isLowerHexId(receipt.receipt_key_id) ||
      !this.isCanonicalBase64Url(receipt.signature, 64)
    ) return false;

    for (const field of [
      'public_operation_id', 'graph_id', 'transition_id', 'source_keyset_id',
      'target_keyset_id', 'result_digest',
    ] as const) {
      if (receipt[field] !== result[field]) return false;
    }

    const receiptKeys = this.keyDiscoveryMetadata?.exchange
      ? [
          this.keyDiscoveryMetadata.exchange.active_receipt_key,
          ...this.keyDiscoveryMetadata.exchange.retained_receipt_keys,
        ]
      : [];
    const receiptKey = receiptKeys.find((key) => key.key_id === receipt.receipt_key_id);
    if (
      !receiptKey ||
      receipt.created_at < receiptKey.valid_from ||
      receipt.expires_at > receiptKey.valid_until
    ) return false;
    const receiptDigest = sha256(
      this.concatBytes(
        this.ascii('freebird exchange receipt v2\0'),
        this.receiptPayload(receipt as unknown as ExchangeSuccessResponse['receipt'])
      )
    );
    try {
      return ed25519.verify(
        this.base64UrlToBytes(receipt.signature),
        receiptDigest,
        this.base64UrlToBytes(receiptKey.public_key_b64),
        { zip215: false }
      ) && selectedGraph.graph_id === result.graph_id;
    } catch {
      return false;
    }
  }

  private isExchangeResultOutput(
    value: unknown,
    submitted: ExchangeRequest['outputs'][number],
    targetKeysetId: string
  ): boolean {
    return (
      this.hasExactKeys(value, ['slot', 'blinded_value', 'blind_signature']) &&
      this.isExchangeSlot(value.slot) &&
      value.slot.descriptor_id === submitted.slot.descriptor_id &&
      value.slot.keyset_id === submitted.slot.keyset_id &&
      value.slot.keyset_id === targetKeysetId &&
      value.slot.slot_id === submitted.slot.slot_id &&
      value.slot.quantity === submitted.slot.quantity &&
      typeof value.blinded_value === 'string' &&
      value.blinded_value === submitted.blinded_value &&
      this.isCanonicalBase64Url(value.blinded_value, undefined, 16 * 1024) &&
      typeof value.blind_signature === 'string' &&
      this.isCanonicalBase64Url(value.blind_signature, undefined, 512, 1)
    );
  }

  private isExchangeSlot(value: unknown): value is ExchangeSlot {
    return (
      this.hasExactKeys(value, ['descriptor_id', 'keyset_id', 'slot_id', 'quantity']) &&
      typeof value.descriptor_id === 'string' &&
      this.isLowerHexId(value.descriptor_id) &&
      typeof value.keyset_id === 'string' &&
      this.isLowerHexId(value.keyset_id) &&
      typeof value.slot_id === 'string' &&
      value.slot_id.length > 0 &&
      value.slot_id.length <= 128 &&
      /^[\x00-\x7F]+$/.test(value.slot_id) &&
      typeof value.quantity === 'number' &&
      Number.isSafeInteger(value.quantity) &&
      value.quantity > 0 &&
      value.quantity <= 0xffff_ffff
    );
  }

  private async validateExchangeRequestSelection(
    request: ExchangeRequest
  ): Promise<ExchangeTransitionSelection> {
    // Canonicalization performs strict wire validation before discovery lookup.
    this.requestBytes(request);
    const selection = await this.selectExchangeTransition(request.graph_id, request.transition_id);
    const transition = selection.transition;
    if (
      transition.source_keyset_id !== request.source_keyset_id ||
      transition.target_keyset_id !== request.target_keyset_id ||
      request.sources.length !== transition.source_slots.length ||
      request.outputs.length !== transition.output_slots.length
    ) throw new Error('Exchange request does not match the selected transition');
    const slotsMatch = (
      actual: ExchangeSlot,
      expected: { descriptor_id: string; slot_id: string; quantity: number },
      keysetId: string
    ) => actual.descriptor_id === expected.descriptor_id &&
      actual.keyset_id === keysetId &&
      actual.slot_id === expected.slot_id &&
      actual.quantity === expected.quantity;
    if (
      !request.sources.every((source, index) =>
        slotsMatch(source.slot, transition.source_slots[index], request.source_keyset_id)) ||
      !request.outputs.every((output, index) =>
        slotsMatch(output.slot, transition.output_slots[index], request.target_keyset_id))
    ) throw new Error('Exchange request does not match the selected transition');
    return selection;
  }

  private requestBytes(request: ExchangeRequest): Uint8Array {
    if (!this.hasExactKeys(request, [
      'version', 'public_operation_id', 'graph_id', 'transition_id', 'source_keyset_id',
      'target_keyset_id', 'sources', 'outputs',
    ])) throw new Error('Invalid V2 exchange request');
    const output: number[] = [...this.v2SelectorBytes(request)];
    if (!Array.isArray(request.sources) || !Array.isArray(request.outputs) ||
      request.sources.length === 0 || request.sources.length > 64 ||
      request.outputs.length === 0 || request.outputs.length > 64) {
      throw new Error('Invalid V2 exchange request');
    }
    this.pushU32(output, request.sources.length);
    for (const source of request.sources) {
      if (!this.hasExactKeys(source, ['slot', 'artifact']) ||
        !this.isExchangeSlot(source.slot) || source.slot.keyset_id !== request.source_keyset_id ||
        typeof source.artifact !== 'string') throw new Error('Invalid V2 exchange request');
      const artifact = this.decodeCanonical(source.artifact, undefined, 16 * 1024, 1);
      output.push(...this.slotBytes(source.slot));
      this.put(output, artifact);
    }
    this.pushU32(output, request.outputs.length);
    for (const requestedOutput of request.outputs) {
      if (!this.hasExactKeys(requestedOutput, ['slot', 'blinded_value']) ||
        !this.isExchangeSlot(requestedOutput.slot) ||
        requestedOutput.slot.keyset_id !== request.target_keyset_id ||
        typeof requestedOutput.blinded_value !== 'string') {
        throw new Error('Invalid V2 exchange request');
      }
      const blinded = this.decodeCanonical(requestedOutput.blinded_value, undefined, 16 * 1024, 1);
      output.push(...this.slotBytes(requestedOutput.slot));
      this.put(output, blinded);
    }
    return new Uint8Array(output);
  }

  private resultBytes(result: ExchangeSuccessResponse['result']): Uint8Array {
    const output: number[] = [...this.v2SelectorBytes(result)];
    this.pushU32(output, result.outputs.length);
    for (const item of result.outputs) {
      output.push(...this.slotBytes(item.slot));
      this.put(output, this.decodeCanonical(item.blinded_value, undefined, 16 * 1024, 1));
      this.put(output, this.decodeCanonical(item.blind_signature, undefined, 512, 1));
    }
    return new Uint8Array(output);
  }

  private receiptPayload(receipt: ExchangeSuccessResponse['receipt']): Uint8Array {
    const output: number[] = [...this.v2SelectorBytes(receipt)];
    this.put(output, this.decodeCanonical(receipt.result_digest, 32));
    this.pushU64(output, receipt.created_at);
    this.pushU64(output, receipt.expires_at);
    this.put(output, this.ascii(receipt.receipt_key_id));
    return new Uint8Array(output);
  }

  private v2SelectorBytes(value: {
    version: number;
    public_operation_id: string;
    graph_id: string;
    transition_id: string;
    source_keyset_id: string;
    target_keyset_id: string;
  }): Uint8Array {
    if (value.version !== 2 || !this.isCanonicalBase64Url(value.public_operation_id, 16) ||
      !this.isLowerHexId(value.graph_id) || !this.isLowerHexId(value.transition_id) ||
      !this.isLowerHexId(value.source_keyset_id) || !this.isLowerHexId(value.target_keyset_id) ||
      value.source_keyset_id === value.target_keyset_id) {
      throw new Error('Invalid V2 exchange selectors');
    }
    const output: number[] = [2];
    this.put(output, this.base64UrlToBytes(value.public_operation_id));
    for (const field of [value.graph_id, value.transition_id, value.source_keyset_id,
      value.target_keyset_id]) this.put(output, this.ascii(field));
    return new Uint8Array(output);
  }

  private slotBytes(slot: ExchangeSlot): number[] {
    const output: number[] = [];
    this.put(output, this.ascii(slot.descriptor_id));
    this.put(output, this.ascii(slot.keyset_id));
    this.put(output, this.ascii(slot.slot_id));
    this.pushU32(output, slot.quantity);
    return output;
  }

  private validateGraphStatusCapability(capability: string): void {
    if (!this.isCanonicalBase64Url(capability, 32)) {
      throw new Error('Graph issuance status capability must be canonical base64url for exactly 32 bytes');
    }
  }

  private graphIssuanceRequestBytes(
    request: GraphIssuanceRequest,
    includeAuthorization: boolean
  ): Uint8Array {
    if (!this.hasExactKeys(request, [
      'version', 'public_operation_id', 'issuance_policy_id', 'graph_id', 'keyset_id',
      'descriptor_id', 'blinded_message', 'authorization',
    ]) || request.version !== 1 || !this.isCanonicalBase64Url(request.public_operation_id, 16) ||
      !this.isBoundedAscii(request.issuance_policy_id) || !this.isLowerHexId(request.graph_id) ||
      !this.isLowerHexId(request.keyset_id) || !this.isLowerHexId(request.descriptor_id) ||
      typeof request.blinded_message !== 'string' || typeof request.authorization !== 'string') {
      throw new Error('Invalid graph issuance request');
    }
    const output: number[] = [1];
    this.put(output, this.decodeCanonical(request.public_operation_id, 16));
    for (const selector of [request.issuance_policy_id, request.graph_id, request.keyset_id,
      request.descriptor_id]) this.put(output, this.ascii(selector));
    this.put(output, this.decodeCanonical(request.blinded_message, undefined, 512, 1));
    if (includeAuthorization) {
      this.put(output, this.decodeCanonical(request.authorization, undefined, 16 * 1024, 1));
    }
    return new Uint8Array(output);
  }

  private async validateGraphIssuanceRequestSelection(
    request: GraphIssuanceRequest
  ): Promise<GraphIssuancePolicyInfo> {
    this.graphIssuanceRequestBytes(request, true);
    const policy = await this.selectGraphIssuancePolicy(request.issuance_policy_id);
    if (policy.admission_state !== 'accepting_new' || policy.graph_id !== request.graph_id ||
      policy.keyset_id !== request.keyset_id || policy.descriptor_id !== request.descriptor_id) {
      throw new Error('Graph issuance request does not match the selected active policy');
    }
    return policy;
  }

  private async parseGraphIssuanceResponse(
    response: Response,
    request: GraphIssuanceRequest
  ): Promise<GraphIssuanceOutcome> {
    const cacheControl = response.headers.get('Cache-Control');
    if (!cacheControl?.split(',').some((value) => value.trim().toLowerCase() === 'no-store')) {
      throw new Error('Graph issuance response did not enforce Cache-Control: no-store');
    }
    const rawResponseBody = await response.text();
    let body: unknown;
    try { body = JSON.parse(rawResponseBody) as unknown; }
    catch { throw new Error('Graph issuance endpoint returned malformed JSON'); }
    if (response.status === 200) {
      if (!this.isGraphIssuanceResult(body, request)) {
        throw new Error('Graph issuance endpoint returned malformed success JSON');
      }
      return { kind: 'committed', httpStatus: 200, response: body, rawResponseBody, cacheControl: 'no-store' };
    }
    if (!this.hasExactKeys(body, ['error']) || typeof body.error !== 'string') {
      throw new Error('Graph issuance endpoint returned malformed error JSON');
    }
    if (response.status === 403 && body.error === 'status_unauthorized') {
      throw new Error('Graph issuance status capability was not authorized');
    }
    if (![400, 404, 409, 413, 503].includes(response.status)) {
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

  private isGraphIssuanceResult(
    value: unknown,
    request: GraphIssuanceRequest
  ): value is GraphIssuanceResult {
    if (!this.hasExactKeys(value, [
      'version', 'public_operation_id', 'issuance_policy_id', 'graph_id', 'keyset_id',
      'descriptor_id', 'token_key_id', 'quantity', 'request_digest', 'blind_signature',
      'result_digest',
    ]) || value.version !== 1 || value.public_operation_id !== request.public_operation_id ||
      value.issuance_policy_id !== request.issuance_policy_id || value.graph_id !== request.graph_id ||
      value.keyset_id !== request.keyset_id || value.descriptor_id !== request.descriptor_id ||
      !this.isLowerHexId(value.token_key_id as string) || !this.isSafePositive(value.quantity) ||
      !this.isCanonicalBase64Url(value.request_digest as string, 32) ||
      !this.isCanonicalBase64Url(value.blind_signature as string, undefined, 512, 1) ||
      !this.isCanonicalBase64Url(value.result_digest as string, 32)) return false;
    const requestDigest = this.graphIssuanceRequestDigest(request);
    if (value.request_digest !== requestDigest) return false;
    const output: number[] = [1];
    this.put(output, this.decodeCanonical(value.public_operation_id as string, 16));
    for (const selector of [value.issuance_policy_id, value.graph_id, value.keyset_id,
      value.descriptor_id, value.token_key_id] as string[]) this.put(output, this.ascii(selector));
    this.pushU32(output, value.quantity as number);
    this.put(output, this.decodeCanonical(value.request_digest as string, 32));
    this.put(output, this.decodeCanonical(value.blind_signature as string, undefined, 512, 1));
    const digest = this.bytesToBase64Url(sha256(this.concatBytes(
      this.ascii('freebird graph blind issuance result v1\0'), new Uint8Array(output)
    )));
    return digest === value.result_digest;
  }

  private validateGraphIssuanceDiscovery(
    issuance: NonNullable<KeyDiscoveryMetadata['graph_issuance']>,
    exchange: ExchangeDiscoveryMetadata
  ): void {
    const invalid = (): never => { throw new Error('Invalid graph issuance discovery metadata'); };
    if (!this.hasExactKeys(issuance, ['version', 'policies']) || issuance.version !== 1 ||
      !Array.isArray(issuance.policies) || issuance.policies.length === 0 || issuance.policies.length > 64) invalid();
    const ids = new Set<string>(); const budgets = new Set<string>();
    for (const policy of issuance.policies) {
      if (!this.hasExactKeys(policy, [
        'issuance_policy_id', 'graph_id', 'keyset_id', 'descriptor_id', 'budget_id',
        'budget_limit', 'quantity', 'admission_state', 'authorization_scheme',
      ]) || !this.isBoundedAscii(policy.issuance_policy_id) || !this.isLowerHexId(policy.graph_id) ||
        !this.isLowerHexId(policy.keyset_id) || !this.isLowerHexId(policy.descriptor_id) ||
        !this.isBoundedAscii(policy.budget_id) || !this.isSafePositive(policy.budget_limit) ||
        !this.isSafePositive(policy.quantity) || policy.quantity > policy.budget_limit ||
        !['accepting_new', 'recovery_only', 'disabled'].includes(policy.admission_state) ||
        !this.isBoundedAscii(policy.authorization_scheme) || ids.has(policy.issuance_policy_id) ||
        budgets.has(policy.budget_id)) invalid();
      const active = exchange.active_graph.graph_id === policy.graph_id;
      const graph = [exchange.active_graph, ...exchange.retained_graphs]
        .find((candidate) => candidate.graph_id === policy.graph_id);
      const keyset = graph?.keysets.find((candidate) => candidate.keyset_id === policy.keyset_id);
      if (!keyset?.descriptor_ids.includes(policy.descriptor_id) ||
        (policy.admission_state === 'accepting_new' && !active)) invalid();
      ids.add(policy.issuance_policy_id); budgets.add(policy.budget_id);
    }
  }

  private async validateExchangeDiscovery(
    issuerId: string,
    discovery: ExchangeDiscoveryMetadata
  ): Promise<void> {
    const invalid = (): never => { throw new Error('Invalid V2 exchange discovery metadata'); };
    if (!this.hasExactKeys(discovery, [
      'active_graph', 'retained_graphs', 'active_receipt_key', 'retained_receipt_keys',
    ]) || !Array.isArray(discovery.retained_graphs) ||
      !Array.isArray(discovery.retained_receipt_keys) ||
      discovery.retained_graphs.length >= 64 || discovery.retained_receipt_keys.length >= 64) invalid();

    const graphs = [discovery.active_graph, ...discovery.retained_graphs];
    const graphIds = new Set<string>();
    const descriptorContracts = new Map<string, string>();
    const budgetContracts = new Map<string, string>();
    for (let graphIndex = 0; graphIndex < graphs.length; graphIndex++) {
      const graph = graphs[graphIndex];
      const retained = graphIndex > 0;
      if (!this.hasExactKeys(graph, ['profile_id', 'graph_id', 'descriptors', 'keysets', 'transitions']) ||
        graph.profile_id !== 'freebird/public-bearer-exchange/v2' ||
        !Array.isArray(graph.descriptors) || !Array.isArray(graph.keysets) ||
        !Array.isArray(graph.transitions) || graph.descriptors.length === 0 ||
        graph.descriptors.length > 64 || graph.keysets.length === 0 || graph.keysets.length > 64 ||
        graph.transitions.length === 0 || graph.transitions.length > 64 ||
        !this.isLowerHexId(graph.graph_id) || graphIds.has(graph.graph_id)) invalid();
      graphIds.add(graph.graph_id);

      const descriptors = new Map<string, ExchangeGraphInfo['descriptors'][number]>();
      const graphTokenKeys = new Set<string>();
      for (const descriptor of graph.descriptors) {
        const descriptorKeys = Object.prototype.hasOwnProperty.call(descriptor, 'audience')
          ? ['descriptor_id', 'profile_id', 'issuer_id', 'token_key_id', 'audience',
              'pubkey_spki_b64', 'suite', 'valid_from', 'valid_until']
          : ['descriptor_id', 'profile_id', 'issuer_id', 'token_key_id',
              'pubkey_spki_b64', 'suite', 'valid_from', 'valid_until'];
        if (!this.hasExactKeys(descriptor, descriptorKeys) ||
          !this.isLowerHexId(descriptor.descriptor_id) || descriptor.profile_id !== graph.profile_id ||
          descriptor.issuer_id !== issuerId || !this.isLowerHexId(descriptor.token_key_id) ||
          descriptor.suite !== 'RSABSSA-SHA384-PSS-Deterministic' ||
          !this.isSafePositive(descriptor.valid_from) || !this.isSafePositive(descriptor.valid_until) ||
          descriptor.valid_from >= descriptor.valid_until ||
          (descriptor.audience !== undefined && !this.isBoundedAscii(descriptor.audience)) ||
          descriptors.has(descriptor.descriptor_id) || graphTokenKeys.has(descriptor.token_key_id)) invalid();
        const spki = this.decodeCanonical(descriptor.pubkey_spki_b64, undefined, 4096, 1);
        if (this.hex(sha256(spki)) !== descriptor.token_key_id) invalid();
        const pssOid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
        if (spki.length > 800 || spki.length <= 72 ||
          !pssOid.every((byte, index) => spki[index + 6] === byte) || spki[17] !== 0x30) invalid();
        try {
          const rawOffset = spki[5] + 10;
          if (spki.length <= rawOffset) invalid();
          const raw = spki.slice(rawOffset);
          const standardHeader = new Uint8Array([
            0x30, 0x82, 0, 0, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0, 0,
          ]);
          standardHeader[2] = (raw.length + 19) >>> 8;
          standardHeader[3] = (raw.length + 19) & 0xff;
          standardHeader[21] = raw.length >>> 8;
          standardHeader[22] = raw.length & 0xff;
          const standardSpki = this.concatBytes(standardHeader, raw);
          const publicKey = await crypto.subtle.importKey(
            'spki',
            new Uint8Array(standardSpki).buffer as ArrayBuffer,
            { name: 'RSA-PSS', hash: 'SHA-384' },
            false,
            ['verify']
          );
          const algorithm = publicKey.algorithm as RsaHashedKeyAlgorithm;
          const exponent = Array.from(algorithm.publicExponent)
            .reduce((value, byte) => value * 256 + byte, 0);
          if (algorithm.modulusLength < 2048 || algorithm.modulusLength > 4096 ||
            (exponent !== 3 && exponent !== 65537)) invalid();
        } catch { invalid(); }
        if (this.domainHex('freebird exchange descriptor v2\0', this.descriptorBytes(descriptor)) !==
          descriptor.descriptor_id) invalid();
        const contract = this.bytesToBase64Url(this.descriptorBytes(descriptor));
        const previous = descriptorContracts.get(descriptor.token_key_id);
        if (previous !== undefined && previous !== contract) invalid();
        descriptorContracts.set(descriptor.token_key_id, contract);
        descriptors.set(descriptor.descriptor_id, descriptor);
        graphTokenKeys.add(descriptor.token_key_id);
      }

      const keysets = new Map<string, Set<string>>();
      const memberships = new Set<string>();
      for (const keyset of graph.keysets) {
        if (!this.hasExactKeys(keyset, ['keyset_id', 'descriptor_ids']) ||
          !this.isLowerHexId(keyset.keyset_id) || !Array.isArray(keyset.descriptor_ids) ||
          keyset.descriptor_ids.length === 0 || keyset.descriptor_ids.length > 64 ||
          keysets.has(keyset.keyset_id)) invalid();
        const members = new Set<string>();
        for (const descriptorId of keyset.descriptor_ids) {
          if (typeof descriptorId !== 'string' || !descriptors.has(descriptorId) ||
            members.has(descriptorId) || memberships.has(descriptorId)) invalid();
          members.add(descriptorId);
          memberships.add(descriptorId);
        }
        const keysetBytes: number[] = [];
        for (const descriptorId of keyset.descriptor_ids) this.put(keysetBytes, this.ascii(descriptorId));
        if (this.domainHex('freebird exchange keyset v2\0', new Uint8Array(keysetBytes)) !== keyset.keyset_id) invalid();
        keysets.set(keyset.keyset_id, members);
      }
      if (memberships.size !== descriptors.size) invalid();

      const transitionIds = new Set<string>();
      const graphBudgetIds = new Set<string>();
      for (const transition of graph.transitions) {
        if (!this.hasExactKeys(transition, [
          'transition_id', 'source_keyset_id', 'target_keyset_id', 'source_slots',
          'output_slots', 'budget_id', 'budget_limit', 'admission_state',
        ]) || !this.isLowerHexId(transition.transition_id) ||
          !this.isLowerHexId(transition.source_keyset_id) ||
          !this.isLowerHexId(transition.target_keyset_id) ||
          transition.source_keyset_id === transition.target_keyset_id ||
          !keysets.has(transition.source_keyset_id) || !keysets.has(transition.target_keyset_id) ||
          !this.isBoundedAscii(transition.budget_id) || !this.isSafePositive(transition.budget_limit) ||
          !['accepting_new', 'recovery_only', 'disabled'].includes(transition.admission_state) ||
          (retained && transition.admission_state === 'accepting_new') ||
          transitionIds.has(transition.transition_id) || graphBudgetIds.has(transition.budget_id)) invalid();
        this.validateDiscoverySlots(transition.source_slots, keysets.get(transition.source_keyset_id)!);
        this.validateDiscoverySlots(transition.output_slots, keysets.get(transition.target_keyset_id)!);
        const stable = this.transitionBytes(transition);
        if (this.domainHex('freebird exchange transition v2\0', stable) !== transition.transition_id) invalid();
        const contract = this.bytesToBase64Url(stable);
        const previous = budgetContracts.get(transition.budget_id);
        if (previous !== undefined && previous !== contract) invalid();
        budgetContracts.set(transition.budget_id, contract);
        transitionIds.add(transition.transition_id);
        graphBudgetIds.add(transition.budget_id);
        const outputQuantity = transition.output_slots.reduce((sum, slot) => sum + slot.quantity, 0);
        if (!Number.isSafeInteger(outputQuantity) || outputQuantity > transition.budget_limit) invalid();
      }

      const graphBytes: number[] = [];
      this.put(graphBytes, this.ascii(graph.profile_id));
      for (const keyset of graph.keysets) this.put(graphBytes, this.ascii(keyset.keyset_id));
      for (const transition of graph.transitions) this.put(graphBytes, this.ascii(transition.transition_id));
      if (this.domainHex('freebird exchange graph v2\0', new Uint8Array(graphBytes)) !== graph.graph_id) invalid();
    }

    const receiptIds = new Set<string>();
    this.validateReceiptDiscoveryKey(discovery.active_receipt_key, 'exchange_receipt_active', receiptIds);
    for (const key of discovery.retained_receipt_keys) {
      this.validateReceiptDiscoveryKey(key, 'exchange_receipt_retained', receiptIds);
    }
  }

  private validateDiscoverySlots(value: unknown, members: Set<string>): void {
    if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
      throw new Error('Invalid V2 exchange discovery metadata');
    }
    const slotIds = new Set<string>();
    const descriptorIds = new Set<string>();
    for (const slot of value) {
      if (!this.hasExactKeys(slot, ['descriptor_id', 'slot_id', 'class', 'quantity']) ||
        typeof slot.descriptor_id !== 'string' || !this.isLowerHexId(slot.descriptor_id) ||
        typeof slot.slot_id !== 'string' || !this.isBoundedAscii(slot.slot_id) ||
        typeof slot.class !== 'string' || !this.isBoundedAscii(slot.class) ||
        !this.isSafePositive(slot.quantity) || slot.quantity > 64 ||
        !members.has(slot.descriptor_id) || slotIds.has(slot.slot_id) ||
        descriptorIds.has(slot.descriptor_id)) {
        throw new Error('Invalid V2 exchange discovery metadata');
      }
      slotIds.add(slot.slot_id);
      descriptorIds.add(slot.descriptor_id);
    }
  }

  private validateReceiptDiscoveryKey(
    key: ExchangeReceiptKeyInfo,
    purpose: ExchangeReceiptKeyInfo['purpose'],
    ids: Set<string>
  ): void {
    if (!this.hasExactKeys(key, [
      'key_id', 'algorithm', 'purpose', 'public_key_b64', 'valid_from', 'valid_until',
    ]) || !this.isLowerHexId(key.key_id) || key.algorithm !== 'Ed25519' ||
      key.purpose !== purpose || !this.isSafePositive(key.valid_from) ||
      !this.isSafePositive(key.valid_until) || key.valid_from >= key.valid_until || ids.has(key.key_id)) {
      throw new Error('Invalid V2 exchange discovery metadata');
    }
    const publicKey = this.decodeCanonical(key.public_key_b64, 32);
    if (!ed25519.utils.isValidPublicKey(publicKey, false) ||
      this.hex(sha256(publicKey)) !== key.key_id) {
      throw new Error('Invalid V2 exchange discovery metadata');
    }
    ids.add(key.key_id);
  }

  private descriptorBytes(descriptor: ExchangeGraphInfo['descriptors'][number]): Uint8Array {
    const output: number[] = [];
    for (const value of [descriptor.profile_id, descriptor.issuer_id, descriptor.token_key_id,
      descriptor.suite]) this.put(output, this.ascii(value));
    if (descriptor.audience === undefined) {
      output.push(0);
      this.put(output, new Uint8Array());
    } else {
      output.push(1);
      this.put(output, this.ascii(descriptor.audience));
    }
    this.put(output, this.decodeCanonical(descriptor.pubkey_spki_b64, undefined, 4096, 1));
    this.pushI64(output, descriptor.valid_from);
    this.pushI64(output, descriptor.valid_until);
    return new Uint8Array(output);
  }

  private transitionBytes(transition: ExchangeTransitionInfo): Uint8Array {
    const output: number[] = [];
    this.put(output, this.ascii(transition.source_keyset_id));
    this.put(output, this.ascii(transition.target_keyset_id));
    for (const slots of [transition.source_slots, transition.output_slots]) {
      this.pushU32(output, slots.length);
      for (const slot of slots) {
        this.put(output, this.ascii(slot.descriptor_id));
        this.put(output, this.ascii(slot.slot_id));
        this.put(output, this.ascii(slot.class));
        this.pushU32(output, slot.quantity);
      }
    }
    this.put(output, this.ascii(transition.budget_id));
    this.pushU64(output, transition.budget_limit);
    return new Uint8Array(output);
  }

  private isLowerHexId(value: string): boolean {
    return /^[0-9a-f]{64}$/.test(value);
  }

  private isSafeUnsigned(value: unknown): value is number {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
  }

  private isSafePositive(value: unknown): value is number {
    return this.isSafeUnsigned(value) && value > 0;
  }

  private isBoundedAscii(value: unknown): value is string {
    return typeof value === 'string' && value.length > 0 && value.length <= 128 &&
      /^[\x00-\x7F]+$/.test(value);
  }

  private isCanonicalBase64Url(
    value: string,
    exactBytes?: number,
    maxBytes?: number,
    minBytes = 0
  ): boolean {
    if (!/^[A-Za-z0-9_-]*$/.test(value)) return false;
    try {
      const decoded = this.base64UrlToBytes(value);
      return (
        this.bytesToBase64Url(decoded) === value &&
        (exactBytes === undefined || decoded.length === exactBytes) &&
        (maxBytes === undefined || decoded.length <= maxBytes) &&
        decoded.length >= minBytes
      );
    } catch {
      return false;
    }
  }

  private hasExactKeys(value: unknown, keys: string[]): value is Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
    const actualKeys = Object.keys(value);
    return actualKeys.length === keys.length && keys.every((key) => actualKeys.includes(key));
  }

  private isExchangeErrorCode(value: unknown): value is ExchangeErrorCode {
    return (
      typeof value === 'string' &&
      [
        'invalid_status_capability',
        'invalid_public_operation_id',
        'exchange_request_too_large',
        'exchange_unavailable',
        'invalid_exchange_request',
        'operation_conflict',
        'invalid_exchange',
        'unknown_operation',
        'status_unauthorized',
      ].includes(value)
    );
  }

  private decodeCanonical(
    value: string,
    exactBytes?: number,
    maxBytes?: number,
    minBytes = 0
  ): Uint8Array {
    if (!this.isCanonicalBase64Url(value, exactBytes, maxBytes, minBytes)) {
      throw new Error('Invalid canonical base64url');
    }
    return this.base64UrlToBytes(value);
  }

  private ascii(value: string): Uint8Array {
    return new TextEncoder().encode(value);
  }

  private put(output: number[], value: Uint8Array): void {
    this.pushU32(output, value.length);
    output.push(...value);
  }

  private pushU32(output: number[], value: number): void {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
      throw new Error('Integer is outside the V2 exchange wire range');
    }
    output.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
  }

  private pushU64(output: number[], value: number): void {
    if (!this.isSafeUnsigned(value)) throw new Error('Invalid V2 exchange integer');
    let integer = BigInt(value);
    const bytes = new Array<number>(8);
    for (let index = 7; index >= 0; index--) {
      bytes[index] = Number(integer & 0xffn);
      integer >>= 8n;
    }
    output.push(...bytes);
  }

  private pushI64(output: number[], value: number): void {
    if (!Number.isSafeInteger(value)) throw new Error('Invalid V2 exchange integer');
    let integer = BigInt.asUintN(64, BigInt(value));
    const bytes = new Array<number>(8);
    for (let index = 7; index >= 0; index--) {
      bytes[index] = Number(integer & 0xffn);
      integer >>= 8n;
    }
    output.push(...bytes);
  }

  private concatBytes(...values: Uint8Array[]): Uint8Array {
    const length = values.reduce((sum, value) => sum + value.length, 0);
    const output = new Uint8Array(length);
    let offset = 0;
    for (const value of values) {
      output.set(value, offset);
      offset += value.length;
    }
    return output;
  }

  private domainHex(domain: string, value: Uint8Array): string {
    return this.hex(sha256(this.concatBytes(this.ascii(domain), value)));
  }

  private hex(value: Uint8Array): string {
    return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  private base64UrlToBytes(b64: string): Uint8Array {
    const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  private bytesToBase64Url(bytes: Uint8Array): string {
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  private bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }
}
