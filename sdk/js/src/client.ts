import {
  ClientConfig,
  IssuerMetadata,
  IssueRequest,
  IssueResponse,
  FreebirdToken,
  SybilProof,
} from './types';
import * as voprf from './crypto/voprf';

export class FreebirdClient {
  private config: ClientConfig;
  private metadata: IssuerMetadata | null = null;
  private context: Uint8Array;

  constructor(config: ClientConfig) {
    this.config = config;
    // This context MUST match the Rust server's context
    // Rust: const ctx = b"freebird:v1";
    this.context = new TextEncoder().encode('freebird:v1');
  }

  /**
   * Initializes the client by fetching the issuer's public key.
   * This must be called before issuing tokens.
   */
  async init(): Promise<void> {
    if (this.metadata) return;

    const url = `${this.config.issuerUrl}/.well-known/issuer`;
    const res = await fetch(url);

    if (!res.ok) {
      throw new Error(`Failed to fetch issuer metadata: ${res.status} ${res.statusText}`);
    }

    this.metadata = (await res.json()) as IssuerMetadata;
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

    // 1. Generate random input and blind it
    const input = crypto.getRandomValues(new Uint8Array(32));
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

    // 4. Finalize (Unblind) the token
    // This verifies the DLEQ proof and extracts the final token value
    const tokenBytes = voprf.finalize(
      state,
      resp.token,
      this.metadata!.voprf.pubkey,
      this.context
    );

    // 5. Return usable token
    return {
      tokenValue: this.bytesToBase64Url(tokenBytes),
      expiration: resp.exp,
      issuerId: this.metadata!.issuer_id,
    };
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
        issuer_id: token.issuerId,
        exp: token.expiration,
      }),
    });

    if (!res.ok) return false;
    const body = await res.json();
    return body.ok === true;
  }

  // --- Utilities ---

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
}