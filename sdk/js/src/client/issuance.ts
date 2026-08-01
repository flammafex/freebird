// SPDX-License-Identifier: Apache-2.0 OR MIT

import * as voprf from '../crypto/voprf.js';
import type {
  IssueRequest,
  IssueResponse,
  KeyDiscoveryMetadata,
  PublicIssueResponse,
  SybilProof,
  FreebirdToken,
} from '../types.js';
import type { ClientState } from './state.js';
import { base64UrlToBytes, bytesEqual, bytesToBase64Url } from './wire.js';

export async function issueToken(
  state: ClientState,
  sybilProof: SybilProof | undefined,
  initialize: () => Promise<void>,
): Promise<FreebirdToken> {
  if (!state.metadata) await initialize();

  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const scopeDigest = base64UrlToBytes(state.verifierMetadata!.scope_digest_b64);
  const expectedScopeDigest = voprf.buildScopeDigest(
    state.verifierMetadata!.verifier_id,
    state.verifierMetadata!.audience,
  );
  if (!bytesEqual(scopeDigest, expectedScopeDigest)) {
    throw new Error('Verifier scope metadata is inconsistent');
  }
  const input = voprf.buildPrivateTokenInput(
    state.metadata!.issuer_id,
    state.metadata!.voprf.kid,
    nonce,
    scopeDigest,
  );
  const { blinded, state: blindState } = voprf.blind(input, state.context);
  const reqBody: IssueRequest = {
    blinded_element_b64: bytesToBase64Url(blinded),
    sybil_proof: sybilProof,
  };
  const res = await fetch(`${state.config.issuerUrl}/v1/oprf/issue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(reqBody),
  });
  if (!res.ok) {
    const errText = await res.text();
    if (res.status === 400 || res.status === 401 || res.status === 403) {
      throw new Error(`Issuer rejected request: ${errText}`);
    }
    throw new Error(`Token issuance failed (${res.status}): ${errText}`);
  }
  const resp = (await res.json()) as IssueResponse;
  if (resp.kid !== state.metadata!.voprf.kid || resp.issuer_id !== state.metadata!.issuer_id) {
    throw new Error('Issuer metadata changed during issuance');
  }
  const output = voprf.finalize(
    blindState,
    resp.token,
    state.metadata!.voprf.pubkey,
    state.context,
  );
  const redemptionToken = voprf.buildRedemptionToken(
    nonce,
    scopeDigest,
    resp.kid,
    resp.issuer_id,
    output,
  );
  return {
    tokenValue: bytesToBase64Url(redemptionToken),
    issuerId: resp.issuer_id,
    version: 4,
    kid: resp.kid,
  };
}

export async function issuePublicBlindSignature(
  state: ClientState,
  blindedMsg: Uint8Array | string,
  sybilProof: SybilProof | undefined,
  tokenKeyId: string | undefined,
  getDiscovery: () => Promise<KeyDiscoveryMetadata>,
): Promise<PublicIssueResponse> {
  const requestedKeyId = tokenKeyId ?? (await getDiscovery()).public.find((key) =>
    key.token_type === 'public_bearer_pass' &&
    key.rfc9474_variant === 'RSABSSA-SHA384-PSS-Deterministic' &&
    key.spend_policy === 'single_use'
  )?.token_key_id;
  if (!requestedKeyId) throw new Error('No V5 public bearer key is available');
  const blinded_msg_b64 = typeof blindedMsg === 'string' ? blindedMsg : bytesToBase64Url(blindedMsg);
  const res = await fetch(`${state.config.issuerUrl}/v1/public/issue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ blinded_msg_b64, token_key_id: requestedKeyId, sybil_proof: sybilProof }),
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Public bearer issuance failed (${res.status}): ${errText}`);
  }
  return (await res.json()) as PublicIssueResponse;
}
