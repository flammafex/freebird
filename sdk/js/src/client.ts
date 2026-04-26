import {
  ClientConfig,
  IssuerMetadata,
  VerifierMetadata,
  IssueRequest,
  IssueResponse,
  KeyDiscoveryMetadata,
  PublicIssueResponse,
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
