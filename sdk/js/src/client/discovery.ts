// SPDX-License-Identifier: Apache-2.0 OR MIT

import * as voprf from '../crypto/voprf.js';
import type {
  IssuerMetadata,
  KeyDiscoveryMetadata,
  VerifierMetadata,
} from '../types.js';
import { pinIssuerIdentity, type ClientState } from './state.js';
import { DiscoveryError, VerifierNotConfiguredError } from '../errors.js';
import { bytesToBase64Url } from './wire.js';

export async function init(state: ClientState): Promise<void> {
  if (state.metadata && state.verifierMetadata) return;

  if (!state.metadata) {
    await getIssuerMetadata(state);
  }

  if (!state.verifierMetadata) {
    if (state.config.verifierUrl) {
      const url = `${state.config.verifierUrl}/.well-known/verifier`;
      const res = await (state.config.fetch ?? fetch)(url);
      if (!res.ok) {
        throw new DiscoveryError('Failed to fetch verifier metadata');
      }
      state.verifierMetadata = (await res.json()) as VerifierMetadata;
    } else if (state.config.verifierId && state.config.audience) {
      state.verifierMetadata = {
        verifier_id: state.config.verifierId,
        audience: state.config.audience,
        scope_digest_b64: bytesToBase64Url(
          voprf.buildScopeDigest(state.config.verifierId, state.config.audience),
        ),
      };
    } else {
      throw new VerifierNotConfiguredError('Verifier scope required: configure verifierUrl or verifierId+audience');
    }
  }
}

/**
 * Loads the issuer discovery document used for issuer identity and Sybil
 * requirements. A few older test/development issuers served key discovery
 * from this URL; accepting that shape as a compatibility fallback keeps
 * discovery usable while still preferring the issuer document whenever it is
 * available.
 */
export async function getIssuerMetadata(state: ClientState): Promise<IssuerMetadata> {
  if (state.metadata) {
    pinIssuerIdentity(state, state.metadata.issuer_id);
    return state.metadata;
  }

  const url = `${state.config.issuerUrl}/.well-known/issuer`;
  const res = await (state.config.fetch ?? fetch)(url);
  if (!res.ok) {
    throw new DiscoveryError('Failed to fetch issuer metadata');
  }
  const body = (await res.json()) as Record<string, unknown>;

  if (typeof body.issuer_id !== 'string' || typeof body.voprf !== 'object' || body.voprf === null) {
    throw new DiscoveryError('Invalid issuer metadata');
  }
  pinIssuerIdentity(state, body.issuer_id);
  state.metadata = body as unknown as IssuerMetadata;
  return state.metadata;
}

/** Forces a fresh fetch of issuer requirements and identity metadata. */
export async function refreshIssuerMetadata(state: ClientState): Promise<IssuerMetadata> {
  const previous = state.metadata;
  state.metadata = null;
  try {
    return await getIssuerMetadata(state);
  } catch (error) {
    state.metadata = previous;
    throw error;
  }
}

export async function getKeyDiscoveryMetadata(state: ClientState): Promise<KeyDiscoveryMetadata> {
  if (state.keyDiscoveryMetadata && isKeyDiscoveryFresh(state)) {
    return state.keyDiscoveryMetadata;
  }
  return fetchKeyDiscoveryMetadata(state);
}

export async function refreshKeyDiscoveryMetadata(state: ClientState): Promise<KeyDiscoveryMetadata> {
  return fetchKeyDiscoveryMetadata(state);
}

/**
 * Returns true when the cached key discovery metadata is still within its TTL.
 *
 * The TTL is `ClientConfig.keyCacheTtlMs` when configured, otherwise derived
 * from the metadata's `epoch_duration_sec` so the cache expires as the current
 * epoch advances.
 */
function isKeyDiscoveryFresh(state: ClientState): boolean {
  if (!state.keyDiscoveryMetadata || state.keyDiscoveryMetadataFetchedAt === null) return false;
  const ttlMs = state.config.keyCacheTtlMs ??
    state.keyDiscoveryMetadata.epoch_duration_sec * 1000;
  return Date.now() - state.keyDiscoveryMetadataFetchedAt < ttlMs;
}

async function fetchKeyDiscoveryMetadata(state: ClientState): Promise<KeyDiscoveryMetadata> {
  const url = `${state.config.issuerUrl}/.well-known/keys`;
  const res = await (state.config.fetch ?? fetch)(url);
  if (!res.ok) {
    throw new DiscoveryError('Failed to fetch issuer key metadata');
  }
  const metadata = (await res.json()) as KeyDiscoveryMetadata;
  pinIssuerIdentity(state, metadata.issuer_id);
  state.keyDiscoveryMetadata = metadata;
  state.keyDiscoveryMetadataFetchedAt = Date.now();
  return state.keyDiscoveryMetadata;
}
