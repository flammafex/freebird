// SPDX-License-Identifier: Apache-2.0 OR MIT

import type {
  ClientConfig,
  IssuerMetadata,
  KeyDiscoveryMetadata,
  V7KeyDiscoveryResp,
  V7Registry,
  VerifierMetadata,
} from '../types.js';
import { DiscoveryError } from '../errors.js';

export interface ClientState {
  config: ClientConfig;
  metadata: IssuerMetadata | null;
  keyDiscoveryMetadata: KeyDiscoveryMetadata | null;
  /** Epoch ms at which `keyDiscoveryMetadata` was last fetched (null if never). */
  keyDiscoveryMetadataFetchedAt: number | null;
  /** Strict V7-only discovery snapshot; independent from legacy V4/V5 state. */
  v7KeyDiscoveryMetadata: V7KeyDiscoveryResp | null;
  /** Atomically materialized V7 issuer-local registry. */
  v7Registry: V7Registry | null;
  v7KeyDiscoveryMetadataFetchedAt: number | null;
  /** Issuer identity shared by legacy V4 and strict V7 discovery. */
  issuerIdentityPin: string | null;
  verifierMetadata: VerifierMetadata | null;
  context: Uint8Array;
}

export function createClientState(config: ClientConfig): ClientState {
  return {
    config,
    metadata: null,
    keyDiscoveryMetadata: null,
    keyDiscoveryMetadataFetchedAt: null,
    v7KeyDiscoveryMetadata: null,
    v7Registry: null,
    v7KeyDiscoveryMetadataFetchedAt: null,
    issuerIdentityPin: null,
    verifierMetadata: null,
    context: new TextEncoder().encode('freebird:v4'),
  };
}

/** Establish or verify the single issuer identity used by both discovery lanes. */
export function pinIssuerIdentity(state: ClientState, issuerId: string): void {
  const established = state.issuerIdentityPin ?? state.metadata?.issuer_id ?? state.v7KeyDiscoveryMetadata?.issuer_id;
  if (established !== undefined && established !== issuerId) {
    throw new DiscoveryError('V7 issuer identity changed after discovery pin');
  }
  state.issuerIdentityPin ??= issuerId;
}
