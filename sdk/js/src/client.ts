// SPDX-License-Identifier: Apache-2.0 OR MIT

import type {
  BatchVerifyResp,
  ClientConfig,
  FreebirdToken,
  IssueTokensOptions,
  KeyDiscoveryMetadata,
  SybilProof,
  SybilProofFactory,
  TokenStore,
  VerifyResp,
  V7DirectBinding,
  V7DirectKeyDiscovery,
  V7Token,
} from './types.js';
import * as discovery from './client/discovery.js';
import * as issuance from './client/issuance.js';
import * as nativeBearerV7 from './client/native_bearer_v7.js';
import type {
  NativeBearerV7BatchIssueOptions,
  NativeBearerV7IssueOptions,
} from './client/native_bearer_v7.js';
import { createClientState, type ClientState } from './client/state.js';
import * as verification from './client/verification.js';
import * as v7Discovery from './client/v7_discovery.js';
import { base64UrlToBytes } from './client/wire.js';
import * as v7Crypto from './crypto/native_bearer_v7.js';

export class FreebirdClient {
  private readonly state: ClientState;

  constructor(config: ClientConfig) {
    this.state = createClientState(config);
  }

  /** The optional token store configured for this client. */
  get tokenStore(): TokenStore | undefined {
    return this.state.config.tokenStore;
  }

  /** Initializes the V4 client by fetching issuer and verifier metadata. */
  async init(): Promise<void> {
    return discovery.init(this.state);
  }

  /** Issues one anonymous V4 token. */
  async issueToken(sybilProof?: SybilProof): Promise<FreebirdToken> {
    return issuance.issueToken(
      this.state,
      sybilProof,
      () => this.init(),
      () => this.refreshKeyDiscoveryMetadataInternal(),
    );
  }

  /** Issues V4 with a fresh request-bound Sybil proof on every retry. */
  async issueTokenWithProofFactory(proofFactory: SybilProofFactory): Promise<FreebirdToken> {
    return issuance.issueToken(
      this.state,
      proofFactory,
      () => this.init(),
      () => this.refreshKeyDiscoveryMetadataInternal(),
    );
  }

  /** Issues an ordered batch of anonymous V4 tokens. */
  async issueTokens(msgs: Uint8Array[], opts: IssueTokensOptions = {}): Promise<FreebirdToken[]> {
    return issuance.issueTokens(
      this.state,
      msgs,
      opts,
      () => this.init(),
      () => this.refreshKeyDiscoveryMetadataInternal(),
    );
  }

  /** Returns the strict V7 discovery snapshot, refreshing it when stale. */
  async getV7KeyDiscoveryMetadata(): Promise<V7DirectKeyDiscovery> {
    return v7Discovery.getV7KeyDiscoveryMetadata(this.state);
  }

  /** Forces an atomic refresh of the strict V7 discovery snapshot and registry. */
  async refreshV7KeyDiscoveryMetadata(): Promise<V7DirectKeyDiscovery> {
    return v7Discovery.refreshV7KeyDiscoveryMetadata(this.state);
  }

  /** Issues one direct V7 native bearer token. */
  async issueNativeBearerV7(options: NativeBearerV7IssueOptions): Promise<FreebirdToken> {
    return nativeBearerV7.issueNativeBearerV7(this.state, options);
  }

  /** Issues an ordered bounded batch of direct V7 native bearer tokens. */
  async issueNativeBearerV7Batch(options: NativeBearerV7BatchIssueOptions): Promise<FreebirdToken[]> {
    return nativeBearerV7.issueNativeBearerV7Batch(this.state, options);
  }

  /**
   * Verifies a serialized or parsed V7 token locally without contacting a
   * verifier. If no binding is supplied, the active/retained V7 key registry
   * is used to select the matching issuer key.
   */
  async verifyNativeBearerV7Locally(
    token: Uint8Array | string | V7Token,
    binding?: V7DirectBinding,
  ): Promise<boolean> {
    try {
      const parsed = token instanceof Uint8Array
        ? v7Crypto.parseV7Token(token)
        : typeof token === 'string'
          ? v7Crypto.parseV7Token(base64UrlToBytes(token))
          : token;
      let selected = binding;
      if (!selected) {
        const metadata = await this.getV7KeyDiscoveryMetadata();
        const records = [metadata.native_bearer_v7, ...metadata.native_bearer_v7_retained];
        const record = records.find((candidate) =>
          candidate.issuer_id === parsed.body.identity.issuer_id &&
          candidate.token_key_id === parsed.body.identity.token_key_id,
        );
        if (!record) return false;
        selected = v7Crypto.bindingFromV7Discovery(record);
      }
      return await v7Crypto.verifyV7Token(selected, parsed);
    } catch {
      return false;
    }
  }

  /** Verifies a token against the configured verifier, consuming it. */
  async verifyToken(token: FreebirdToken): Promise<VerifyResp> {
    return verification.verifyToken(this.state, token);
  }

  /** Boolean convenience over {@link verifyToken}. */
  async verifyTokenValid(token: FreebirdToken): Promise<boolean> {
    return verification.verifyTokenValid(this.state, token);
  }

  /** Checks token validity without consuming it. */
  async checkToken(token: FreebirdToken): Promise<VerifyResp> {
    return verification.checkToken(this.state, token);
  }

  /** Verifies a batch of tokens in one request, consuming each. */
  async verifyBatch(tokens: FreebirdToken[]): Promise<BatchVerifyResp> {
    return verification.verifyBatch(this.state, tokens);
  }

  private async refreshKeyDiscoveryMetadataInternal(): Promise<KeyDiscoveryMetadata> {
    return discovery.refreshKeyDiscoveryMetadata(this.state);
  }
}
