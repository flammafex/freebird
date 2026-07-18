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
  FreebirdToken,
  SybilProof,
} from './types.js';
import * as voprf from './crypto/voprf.js';

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
    this.keyDiscoveryMetadata = (await res.json()) as KeyDiscoveryMetadata;
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

  /**
   * Starts or exactly retries a public bearer exchange operation.
   *
   * `operationId` is a private capability: it must be canonical unpadded
   * base64url for exactly 16 bytes. It is sent once in `Idempotency-Key` and is
   * never placed in the URL.
   */
  async exchange(request: ExchangeRequest, operationId: string): Promise<ExchangeOutcome> {
    this.validateExchangeOperationId(operationId);
    const response = await fetch(`${this.config.issuerUrl}/v1/public/exchange`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': operationId,
      },
      body: JSON.stringify(request),
    });
    return this.parseExchangeResponse(response, operationId, request);
  }

  /**
   * Looks up an exchange operation through the fixed status endpoint.
   * The original request is required locally to bind any committed response;
   * it is not sent. The private operation capability is sent only as
   * `Idempotency-Key`.
   */
  async getExchangeStatus(
    operationId: string,
    submittedRequest: ExchangeRequest
  ): Promise<ExchangeOutcome> {
    this.validateExchangeOperationId(operationId);
    const response = await fetch(`${this.config.issuerUrl}/v1/public/exchange/status`, {
      method: 'GET',
      headers: { 'Idempotency-Key': operationId },
    });
    return this.parseExchangeResponse(response, operationId, submittedRequest);
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

  private async parseExchangeResponse(
    response: Response,
    operationId: string,
    submittedRequest: ExchangeRequest
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
      if (!this.isExchangeSuccessResponse(body, operationId, submittedRequest)) {
        throw new Error('Exchange endpoint returned malformed success JSON');
      }
      return {
        kind: 'committed',
        httpStatus: 200,
        response: body,
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
    const common = { rawResponseBody, cacheControl: 'no-store' as const };
    if (
      response.status === 400 &&
      (body.error === 'invalid_idempotency_key' ||
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

  private isExchangeSuccessResponse(
    value: unknown,
    operationId: string,
    submittedRequest: ExchangeRequest
  ): value is ExchangeSuccessResponse {
    if (!this.hasExactKeys(value, ['result', 'receipt'])) return false;
    const { result, receipt } = value;
    if (
      !this.hasExactKeys(result, [
        'operation_id',
        'profile',
        'target_keyset_id',
        'outputs',
        'result_digest',
      ]) ||
      typeof result.operation_id !== 'string' ||
      typeof result.profile !== 'string' ||
      typeof result.target_keyset_id !== 'string' ||
      typeof result.result_digest !== 'string' ||
      !Array.isArray(result.outputs) ||
      result.outputs.length === 0 ||
      result.outputs.length > 64 ||
      result.outputs.length !== submittedRequest.outputs.length
    ) {
      return false;
    }
    const targetKeysetId = result.target_keyset_id;
    if (
      !result.outputs.every((output, index) =>
        this.isExchangeResultOutput(
          output,
          submittedRequest.outputs[index],
          targetKeysetId
        )
      )
    ) {
      return false;
    }
    if (
      !this.isCanonicalBase64Url(result.operation_id, 16) ||
      result.operation_id !== operationId ||
      result.profile !== submittedRequest.profile ||
      !this.isLowerHexId(result.target_keyset_id) ||
      !this.isCanonicalBase64Url(result.result_digest, 32)
    ) {
      return false;
    }
    return (
      this.hasExactKeys(receipt, [
        'operation_id',
        'profile',
        'target_keyset_id',
        'result_digest',
        'created_at',
        'expires_at',
        'receipt_key_id',
        'signature',
      ]) &&
      typeof receipt.operation_id === 'string' &&
      typeof receipt.profile === 'string' &&
      typeof receipt.target_keyset_id === 'string' &&
      typeof receipt.result_digest === 'string' &&
      typeof receipt.created_at === 'number' &&
      Number.isSafeInteger(receipt.created_at) &&
      receipt.created_at >= 0 &&
      typeof receipt.expires_at === 'number' &&
      Number.isSafeInteger(receipt.expires_at) &&
      receipt.expires_at >= 0 &&
      typeof receipt.receipt_key_id === 'string' &&
      typeof receipt.signature === 'string' &&
      this.isCanonicalBase64Url(receipt.operation_id, 16) &&
      receipt.operation_id === operationId &&
      receipt.operation_id === result.operation_id &&
      receipt.profile === submittedRequest.profile &&
      receipt.profile === result.profile &&
      this.isLowerHexId(receipt.target_keyset_id) &&
      receipt.target_keyset_id === result.target_keyset_id &&
      this.isCanonicalBase64Url(receipt.result_digest, 32) &&
      receipt.result_digest === result.result_digest &&
      receipt.expires_at > receipt.created_at &&
      this.isLowerHexId(receipt.receipt_key_id) &&
      this.isCanonicalBase64Url(receipt.signature, 64)
    );
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
      value.quantity > 0
    );
  }

  private isLowerHexId(value: string): boolean {
    return /^[0-9a-f]{64}$/.test(value);
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
        'invalid_idempotency_key',
        'exchange_unavailable',
        'invalid_exchange_request',
        'operation_conflict',
        'invalid_exchange',
        'unknown_operation',
      ].includes(value)
    );
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
