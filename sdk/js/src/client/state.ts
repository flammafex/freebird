// SPDX-License-Identifier: Apache-2.0 OR MIT

import type {
  ClientConfig,
  IssuerMetadata,
  KeyDiscoveryMetadata,
  VerifierMetadata,
} from '../types.js';
import { DiscoveryError } from '../errors.js';

export interface ClientState {
  config: ClientConfig;
  metadata: IssuerMetadata | null;
  keyDiscoveryMetadata: KeyDiscoveryMetadata | null;
  /** Epoch ms at which `keyDiscoveryMetadata` was last fetched (null if never). */
  keyDiscoveryMetadataFetchedAt: number | null;
  /** Issuer identity pinned by V4 discovery. */
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
    issuerIdentityPin: null,
    verifierMetadata: null,
    context: new TextEncoder().encode('freebird:v4'),
  };
}

/** Establish or verify the issuer identity used by V4 discovery. */
export function pinIssuerIdentity(state: ClientState, issuerId: string): void {
  const established = state.issuerIdentityPin ?? state.metadata?.issuer_id;
  if (established !== undefined && established !== issuerId) {
    throw new DiscoveryError('Issuer identity changed after discovery pin');
  }
  state.issuerIdentityPin ??= issuerId;
}
