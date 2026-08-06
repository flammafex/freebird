// SPDX-License-Identifier: Apache-2.0 OR MIT

import * as voprf from '../crypto/voprf.js';
import * as rsa from '../crypto/rsa.js';
import type {
  IssueRequest,
  IssueResponse,
  KeyDiscoveryMetadata,
  PublicIssueResponse,
  SybilProof,
  FreebirdToken,
  PublicBearerPass,
  BatchIssueReq,
  BatchIssueResp,
  TokenResult,
  PublicBatchIssueReq,
  PublicBatchIssueResp,
  IssueTokensOptions,
  IssuePublicTokensOptions,
} from '../types.js';
import type { ClientState } from './state.js';
import { base64UrlToBytes, bytesEqual, bytesToBase64Url } from './wire.js';
import { BatchIssuanceError, DiscoveryError, FreebirdError } from '../errors.js';
import {
  buildBatchBinding,
  buildIssueBinding,
  buildPublicIssueBinding,
  generateProofOfWork,
  resolvePowDifficulty,
  resolveSybilProof,
} from './sybil.js';

/**
 * Maximum number of blinded elements the issuer accepts in a single batch
 * request. Mirrors `MAX_BATCH_SIZE` in `issuer/src/routes/batch_issue.rs`.
 */
const MAX_BATCH_SIZE = 10_000;

function chunk<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}

function chunkPairs<T, U>(a: T[], b: U[], size: number): { msgs: T[]; nonces: U[] }[] {
  const pairs: { msgs: T[]; nonces: U[] }[] = [];
  for (let i = 0; i < a.length; i += size) {
    pairs.push({ msgs: a.slice(i, i + size), nonces: b.slice(i, i + size) });
  }
  return pairs;
}

export async function issueToken(
  state: ClientState,
  sybilProof: SybilProof | undefined,
  initialize: () => Promise<void>,
  refreshKeyDiscovery: () => Promise<KeyDiscoveryMetadata>,
): Promise<FreebirdToken> {
  if (!state.metadata) await initialize();

  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const scopeDigest = base64UrlToBytes(state.verifierMetadata!.scope_digest_b64);
  const expectedScopeDigest = voprf.buildScopeDigest(
    state.verifierMetadata!.verifier_id,
    state.verifierMetadata!.audience,
  );
  if (!bytesEqual(scopeDigest, expectedScopeDigest)) {
    throw new DiscoveryError('Verifier scope metadata is inconsistent');
  }

  // On a kid/issuer mismatch the issuer may have rotated keys since we last
  // cached discovery. Refresh once and retry with the freshly derived input.
  let refreshed = false;
  for (;;) {
    const input = voprf.buildPrivateTokenInput(
      state.metadata!.issuer_id,
      state.metadata!.voprf.kid,
      nonce,
      scopeDigest,
    );
    const { blinded, state: blindState } = voprf.blind(input, state.context);
    const blinded_element_b64 = bytesToBase64Url(blinded);
    const binding = buildIssueBinding(state.metadata!.issuer_id, blinded_element_b64);
    const effectiveProof = await resolveSybilProof(state, sybilProof, binding);
    const reqBody: IssueRequest = {
      blinded_element_b64,
      sybil_proof: effectiveProof,
    };
    const res = await (state.config.fetch ?? fetch)(`${state.config.issuerUrl}/v1/oprf/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reqBody),
    });
    if (!res.ok) {
      if (res.status === 400 || res.status === 401 || res.status === 403) {
        throw new FreebirdError('issuance', 'Issuer rejected the request');
      }
      throw new FreebirdError('issuance', 'Token issuance failed');
    }
    const resp = (await res.json()) as IssueResponse;
    if (resp.kid === state.metadata!.voprf.kid && resp.issuer_id === state.metadata!.issuer_id) {
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
    if (refreshed) {
      throw new DiscoveryError('Issuer metadata changed during issuance');
    }
    refreshed = true;
    const refreshedMetadata = await refreshKeyDiscovery();
    state.metadata!.voprf.kid = refreshedMetadata.voprf.kid;
    state.metadata!.voprf.pubkey = refreshedMetadata.voprf.pubkey;
  }
}

export async function issuePublicBlindSignature(
  state: ClientState,
  blindedMsg: Uint8Array | string,
  sybilProof: SybilProof | undefined,
  tokenKeyId: string | undefined,
  getDiscovery: () => Promise<KeyDiscoveryMetadata>,
  refreshKeyDiscovery: () => Promise<KeyDiscoveryMetadata>,
): Promise<PublicIssueResponse> {
  const blinded_msg_b64 = typeof blindedMsg === 'string' ? blindedMsg : bytesToBase64Url(blindedMsg);
  const powDifficulty = resolvePowDifficulty(state);

  // On a token_key_id mismatch the issuer may have rotated keys since we last
  // cached discovery. Refresh once and re-derive the requested key, then retry.
  let refreshed = false;
  for (;;) {
    // Fetch discovery only when we must resolve the key (no explicit
    // token_key_id) or need the issuer id to build a PoW binding. With an
    // explicit key and no PoW requirement, issuance proceeds without any
    // discovery call.
    const needsDiscovery = tokenKeyId === undefined || powDifficulty !== undefined;
    const discovery = needsDiscovery ? await getDiscovery() : undefined;
    const issuerId = discovery?.issuer_id ?? state.metadata?.issuer_id;
    const requestedKeyId = tokenKeyId ?? discovery?.public.find((key) =>
      key.token_type === 'public_bearer_pass' &&
      key.rfc9474_variant === 'RSABSSA-SHA384-PSS-Deterministic' &&
      key.spend_policy === 'single_use'
    )?.token_key_id;
    if (!requestedKeyId) throw new DiscoveryError('No V5 public bearer key is available');

    let effectiveProof = sybilProof;
    if (effectiveProof === undefined && powDifficulty !== undefined) {
      if (issuerId === undefined) throw new DiscoveryError('Issuer metadata is unavailable');
      effectiveProof = await generateProofOfWork(
        buildPublicIssueBinding(issuerId, blinded_msg_b64),
        powDifficulty,
      );
    }

    const res = await (state.config.fetch ?? fetch)(`${state.config.issuerUrl}/v1/public/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blinded_msg_b64, token_key_id: requestedKeyId, sybil_proof: effectiveProof }),
    });
    if (!res.ok) {
      throw new FreebirdError('issuance', 'Public bearer issuance failed');
    }
    const resp = (await res.json()) as PublicIssueResponse;
    if (resp.token_key_id === requestedKeyId) {
      return resp;
    }
    if (refreshed) {
      throw new DiscoveryError('Issuer metadata changed during public issuance');
    }
    refreshed = true;
    await refreshKeyDiscovery();
  }
}

/**
 * Issues a batch of anonymous V4 tokens in one or more requests.
 *
 * `msgs` determines how many tokens to issue (one per element; the element
 * content is not part of the V4 input, which is derived from a fresh random
 * nonce plus the verifier scope digest). Inputs larger than `MAX_BATCH_SIZE`
 * (10_000) are chunked into multiple requests and the results concatenated.
 *
 * On a kid/issuer mismatch the issuer may have rotated keys since we last
 * cached discovery; the whole (chunked) batch is refreshed and retried once.
 *
 * If any token in the batch fails, a {@link BatchIssuanceError} is thrown
 * carrying the per-token `TokenResult` outcomes and the successfully finalized
 * tokens — failures are never silently dropped.
 */
export async function issueTokens(
  state: ClientState,
  msgs: Uint8Array[],
  opts: IssueTokensOptions,
  initialize: () => Promise<void>,
  refreshKeyDiscovery: () => Promise<KeyDiscoveryMetadata>,
): Promise<FreebirdToken[]> {
  if (!state.metadata) await initialize();

  const scopeDigest = base64UrlToBytes(state.verifierMetadata!.scope_digest_b64);
  const expectedScopeDigest = voprf.buildScopeDigest(
    state.verifierMetadata!.verifier_id,
    state.verifierMetadata!.audience,
  );
  if (!bytesEqual(scopeDigest, expectedScopeDigest)) {
    throw new DiscoveryError('Verifier scope metadata is inconsistent');
  }

  let refreshed = false;
  for (;;) {
    const tokens: FreebirdToken[] = [];
    const results: TokenResult[] = [];
    let kidMismatch = false;

    for (const chunkMsgs of chunk(msgs, MAX_BATCH_SIZE)) {
      const blinded = chunkMsgs.map(() => {
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const input = voprf.buildPrivateTokenInput(
          state.metadata!.issuer_id,
          state.metadata!.voprf.kid,
          nonce,
          scopeDigest,
        );
        const { blinded, state: blindState } = voprf.blind(input, state.context);
        return { blinded: bytesToBase64Url(blinded), blindState, nonce };
      });

      const blindedElements = blinded.map((b) => b.blinded);
      const binding = buildBatchBinding('issue-batch', state.metadata!.issuer_id, blindedElements);
      const effectiveProof = await resolveSybilProof(state, opts.sybilProof, binding);

      const reqBody: BatchIssueReq = {
        blinded_elements: blindedElements,
        sybil_proof: effectiveProof,
      };
      if (opts.ctxB64 !== undefined) reqBody.ctx_b64 = opts.ctxB64;

      const res = await (state.config.fetch ?? fetch)(`${state.config.issuerUrl}/v1/oprf/issue/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reqBody),
      });
      if (!res.ok) {
        if (res.status === 400 || res.status === 401 || res.status === 403) {
          throw new FreebirdError('issuance', 'Issuer rejected the batch request');
        }
        throw new FreebirdError('issuance', 'Batch token issuance failed');
      }
      const resp = (await res.json()) as BatchIssueResp;
      if (resp.results.length !== blinded.length) {
        throw new FreebirdError('issuance', 'Batch issuance response is malformed');
      }

      for (let i = 0; i < resp.results.length; i++) {
        const result = resp.results[i];
        if (result.status === 'success') {
          if (
            result.kid !== state.metadata!.voprf.kid ||
            result.issuer_id !== state.metadata!.issuer_id
          ) {
            kidMismatch = true;
            break;
          }
          const output = voprf.finalize(
            blinded[i].blindState,
            result.token,
            state.metadata!.voprf.pubkey,
            state.context,
          );
          const redemptionToken = voprf.buildRedemptionToken(
            blinded[i].nonce,
            scopeDigest,
            result.kid,
            result.issuer_id,
            output,
          );
          tokens.push({
            tokenValue: bytesToBase64Url(redemptionToken),
            issuerId: result.issuer_id,
            version: 4,
            kid: result.kid,
          });
        }
        results.push(result);
      }
      if (kidMismatch) break;
    }

    if (!kidMismatch) {
      const failed = results.filter((r) => r.status === 'error').length;
      if (failed > 0) throw new BatchIssuanceError(results, tokens);
      return tokens;
    }
    if (refreshed) {
      throw new DiscoveryError('Issuer metadata changed during batch issuance');
    }
    refreshed = true;
    const refreshedMetadata = await refreshKeyDiscovery();
    state.metadata!.voprf.kid = refreshedMetadata.voprf.kid;
    state.metadata!.voprf.pubkey = refreshedMetadata.voprf.pubkey;
  }
}

/**
 * Issues a batch of V5 public bearer passes in one or more requests.
 *
 * Each `msgs[i]` is the RFC 9474 message to be blindly signed (typically the
 * output of `crypto.buildPublicBearerMessage(nonces[i], tokenKeyId,
 * issuerId)`); `opts.nonces[i]` and `opts.issuerId` are embedded in the
 * returned pass. Inputs larger than `MAX_BATCH_SIZE` (10_000) are chunked into
 * multiple requests and the results concatenated.
 *
 * On a token_key_id mismatch the issuer may have rotated keys since we last
 * cached discovery; the whole (chunked) batch is refreshed and retried once.
 */
export async function issuePublicTokens(
  state: ClientState,
  msgs: Uint8Array[],
  opts: IssuePublicTokensOptions,
  getDiscovery: () => Promise<KeyDiscoveryMetadata>,
  refreshKeyDiscovery: () => Promise<KeyDiscoveryMetadata>,
): Promise<PublicBearerPass[]> {
  if (opts.nonces.length !== msgs.length) {
    throw new FreebirdError('issuance', 'Nonces must be provided for each message');
  }

  let refreshed = false;
  for (;;) {
    const metadata = await getDiscovery();
    const requestedKeyId = opts.tokenKeyId ?? metadata.public.find((key) =>
      key.token_type === 'public_bearer_pass' &&
      key.rfc9474_variant === 'RSABSSA-SHA384-PSS-Deterministic' &&
      key.spend_policy === 'single_use'
    )?.token_key_id;
    if (!requestedKeyId) throw new DiscoveryError('No V5 public bearer key is available');
    const key = metadata.public.find((candidate) => candidate.token_key_id === requestedKeyId);
    if (!key) throw new DiscoveryError('No V5 public bearer key is available');

    const passes: PublicBearerPass[] = [];
    let mismatch = false;

    for (const { msgs: chunkMsgs, nonces: chunkNonces } of chunkPairs(
      msgs,
      opts.nonces,
      MAX_BATCH_SIZE,
    )) {
      const blinded = [];
      for (let i = 0; i < chunkMsgs.length; i++) {
        const { blinded: b, state: blindState } = await rsa.rsaBlind(
          base64UrlToBytes(key.pubkey_spki_b64),
          chunkMsgs[i],
        );
        blinded.push({ blinded: bytesToBase64Url(b), blindState });
      }

      const blindedMsgs = blinded.map((b) => b.blinded);
      const binding = buildBatchBinding('public-issue-batch', metadata.issuer_id, blindedMsgs);
      const effectiveProof = await resolveSybilProof(state, opts.sybilProof, binding);

      const reqBody: PublicBatchIssueReq = {
        blinded_msgs: blindedMsgs,
        token_key_id: requestedKeyId,
        sybil_proof: effectiveProof,
      };
      const res = await (state.config.fetch ?? fetch)(`${state.config.issuerUrl}/v1/public/issue/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reqBody),
      });
      if (!res.ok) {
        throw new FreebirdError('issuance', 'Public bearer batch issuance failed');
      }
      const resp = (await res.json()) as PublicBatchIssueResp;
      if (resp.token_key_id !== requestedKeyId) {
        mismatch = true;
        break;
      }
      if (resp.blind_signatures.length !== blinded.length) {
        throw new FreebirdError('issuance', 'Public bearer batch response is malformed');
      }
      for (let i = 0; i < blinded.length; i++) {
        const signature = await rsa.rsaUnblind(
          blinded[i].blindState,
          base64UrlToBytes(resp.blind_signatures[i]),
        );
        passes.push(voprf.buildPublicBearerPass(
          chunkNonces[i],
          voprf.tokenKeyIdFromHex(requestedKeyId),
          opts.issuerId,
          signature,
        ));
      }
    }

    if (!mismatch) return passes;
    if (refreshed) {
      throw new DiscoveryError('Issuer metadata changed during public batch issuance');
    }
    refreshed = true;
    await refreshKeyDiscovery();
  }
}
