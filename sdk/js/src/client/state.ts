// SPDX-License-Identifier: Apache-2.0 OR MIT

import type {
  ClientConfig,
  IssuerMetadata,
  KeyDiscoveryMetadata,
  VerifierMetadata,
} from '../types.js';

export interface ClientState {
  config: ClientConfig;
  metadata: IssuerMetadata | null;
  keyDiscoveryMetadata: KeyDiscoveryMetadata | null;
  verifierMetadata: VerifierMetadata | null;
  context: Uint8Array;
}

export function createClientState(config: ClientConfig): ClientState {
  return {
    config,
    metadata: null,
    keyDiscoveryMetadata: null,
    verifierMetadata: null,
    context: new TextEncoder().encode('freebird:v4'),
  };
}
