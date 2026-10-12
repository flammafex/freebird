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
} from './types.js';
import * as discovery from './client/discovery.js';
import * as issuance from './client/issuance.js';
import { createClientState, type ClientState } from './client/state.js';
import * as verification from './client/verification.js';

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
