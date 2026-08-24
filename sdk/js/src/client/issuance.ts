// SPDX-License-Identifier: Apache-2.0 OR MIT

import * as voprf from '../crypto/voprf.js';
import type {
  IssueRequest,
  IssueResponse,
  KeyDiscoveryMetadata,
  SybilProof,
  FreebirdToken,
  BatchIssueReq,
  BatchIssueResp,
  TokenResult,
  IssueTokensOptions,
  SybilProofFactory,
} from '../types.js';
import type { ClientState } from './state.js';
import { base64UrlToBytes, bytesEqual, bytesToBase64Url } from './wire.js';
import {
  BatchIssuanceError,
  BatchIssuanceInterruptedError,
  DiscoveryError,
  FreebirdError,
  StalePublicKeyError,
} from '../errors.js';
import {
  buildBatchBinding,
  buildIssueBinding,
  resolveSybilProof,
} from './sybil.js';

/**
 * Maximum number of blinded elements the issuer accepts in a single batch
 * request. Mirrors `MAX_BATCH_SIZE` in `issuer/src/routes/batch_issue.rs`.
 */
const MAX_BATCH_SIZE = 10_000;
const DEFAULT_BATCH_BODY_LIMIT_BYTES = 60 * 1024;
const V4_BLINDED_ELEMENT_B64_LENGTH = 44;

type ProofFactoryOptions = {
  /** Preferred name for a request-bound proof factory. */
  proofFactory?: SybilProofFactory;
  /** Compatibility spelling used by early Phase-2 callers. */
  sybilProofFactory?: SybilProofFactory;
};

function proofFactory(options: ProofFactoryOptions): SybilProofFactory | undefined {
  return options.proofFactory ?? options.sybilProofFactory;
}

function assertProofOptions(options: {
  sybilProof?: SybilProof;
  proofFactory?: SybilProofFactory;
  sybilProofFactory?: SybilProofFactory;
}): void {
  const hasProof = options.sybilProof !== undefined;
  const hasFactory = options.proofFactory !== undefined || options.sybilProofFactory !== undefined;
  if (hasProof && hasFactory) {
    throw new FreebirdError('issuance', 'Specify either sybilProof or proofFactory, not both');
  }
  if (options.proofFactory !== undefined && options.sybilProofFactory !== undefined) {
    throw new FreebirdError('issuance', 'Specify only one proof factory');
  }
}

function assertFixedProofAllowedForChunks(
  proof: SybilProof | undefined,
  factory: SybilProofFactory | undefined,
  totalChunks: number,
): void {
  if (proof !== undefined && factory === undefined && totalChunks > 1) {
    throw new FreebirdError(
      'issuance',
      'A fixed Sybil proof cannot be reused across batch request bindings',
    );
  }
}

function assertRetryProofAvailable(
  proof: SybilProof | undefined,
  factory: SybilProofFactory | undefined,
): void {
  if (proof !== undefined && factory === undefined) {
    throw new StalePublicKeyError('A fresh proof factory is required to retry after key rotation');
  }
}


function batchBodyLimitBytes(state: ClientState): number {
  const limit = state.config.batchBodyLimitBytes ?? DEFAULT_BATCH_BODY_LIMIT_BYTES;
  if (!Number.isSafeInteger(limit) || limit <= 0) {
    throw new FreebirdError('issuance', 'Batch body byte limit must be a positive safe integer');
  }
  if (limit > DEFAULT_BATCH_BODY_LIMIT_BYTES) {
    throw new FreebirdError('issuance', 'Batch body byte limit cannot exceed 60 KiB');
  }
  return limit;
}

function serializedJsonBody(body: object): { value: string; bytes: number } {
  const value = JSON.stringify(body);
  return { value, bytes: new TextEncoder().encode(value).byteLength };
}

function serializeBatchBody(body: object, limit: number): string {
  const serialized = serializedJsonBody(body);
  if (serialized.bytes > limit) {
    throw new FreebirdError('issuance', 'Batch issuance request exceeds the configured JSON body limit');
  }
  return serialized.value;
}

function assertStaticBatchFieldsFit(body: object, limit: number): void {
  if (serializedJsonBody(body).bytes > limit) {
    throw new FreebirdError('issuance', 'A single batch item exceeds the configured JSON body limit');
  }
}

type PreparedChunk<T> = {
  items: T[];
  proof: SybilProof | undefined;
  body: object;
  serializedBody: string;
  hasMore: boolean;
};

/**
 * Selects the largest ordered prefix that fits the body budget. A proof
 * factory is resolved only after a candidate prefix has been selected; if the
 * resulting proof makes it too large, the tail is returned to the queue and a
 * new request-bound proof is resolved for the smaller exact payload.
 */
async function takeGreedyChunk<T>(args: {
  next: () => Promise<T | undefined>;
  putBack: (item: T) => void;
  hasMore: () => boolean;
  buildBody: (items: T[], proof: SybilProof | undefined) => object;
  fixedProof: SybilProof | undefined;
  resolveProof: (items: T[]) => Promise<SybilProof | undefined>;
  limit: number;
}): Promise<PreparedChunk<T>> {
  const items: T[] = [];
  let fittingBody: object | undefined;
  let fittingSerializedBody: string | undefined;

  for (;;) {
    if (items.length >= MAX_BATCH_SIZE) break;
    const item = await args.next();
    if (item === undefined) break;
    const candidate = items.concat(item);
    const body = args.buildBody(candidate, args.fixedProof);
    const serialized = serializedJsonBody(body);
    if (serialized.bytes > args.limit) {
      if (items.length === 0) {
        throw new FreebirdError('issuance', 'A single batch item exceeds the configured JSON body limit');
      }
      args.putBack(item);
      break;
    }
    items.push(item);
    if (args.fixedProof !== undefined) {
      fittingBody = body;
      fittingSerializedBody = serialized.value;
    }
  }

  if (items.length === 0) {
    throw new FreebirdError('issuance', 'Unable to build a non-empty batch request');
  }

  if (args.fixedProof !== undefined) {
    if (fittingBody === undefined || fittingSerializedBody === undefined) {
      throw new FreebirdError('issuance', 'Unable to build a non-empty batch request');
    }
    return {
      items,
      proof: args.fixedProof,
      body: fittingBody,
      serializedBody: fittingSerializedBody,
      hasMore: args.hasMore(),
    };
  }

  for (;;) {
    const proof = await args.resolveProof(items);
    const body = args.buildBody(items, proof);
    const serialized = serializedJsonBody(body);
    if (serialized.bytes <= args.limit) {
      return {
        items,
        proof,
        body,
        serializedBody: serialized.value,
        hasMore: args.hasMore(),
      };
    }
    if (items.length === 1) {
      throw new FreebirdError('issuance', 'A single batch item exceeds the configured JSON body limit');
    }
    // Use the proof just resolved as an exact-size template while finding the
    // next prefix. This avoids one factory invocation per discarded item,
    // while the proof for the eventual binding is still resolved below.
    while (items.length > 1 && serializedJsonBody(args.buildBody(items, proof)).bytes > args.limit) {
      args.putBack(items.pop()!);
    }
  }
}

export function issueToken(
  state: ClientState,
  sybilProof: SybilProof | undefined,
  initialize: () => Promise<void>,
  refreshKeyDiscovery: () => Promise<KeyDiscoveryMetadata>,
): Promise<FreebirdToken>;
export function issueToken(
  state: ClientState,
  proofFactory: SybilProofFactory,
  initialize: () => Promise<void>,
  refreshKeyDiscovery: () => Promise<KeyDiscoveryMetadata>,
): Promise<FreebirdToken>;
export async function issueToken(
  state: ClientState,
  sybilProofOrFactory: SybilProof | SybilProofFactory | undefined,
  initialize: () => Promise<void>,
  refreshKeyDiscovery: () => Promise<KeyDiscoveryMetadata>,
): Promise<FreebirdToken> {
  const factory = typeof sybilProofOrFactory === 'function' ? sybilProofOrFactory : undefined;
  const sybilProof = typeof sybilProofOrFactory === 'function' ? undefined : sybilProofOrFactory;
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
    const effectiveProof = await resolveSybilProof(state, sybilProof, binding, factory);
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
    assertRetryProofAvailable(sybilProof, factory);
    refreshed = true;
    const refreshedMetadata = await refreshKeyDiscovery();
    state.metadata!.voprf.kid = refreshedMetadata.voprf.kid;
    state.metadata!.voprf.pubkey = refreshedMetadata.voprf.pubkey;
  }
}

export async function issueTokens(
  state: ClientState,
  msgs: Uint8Array[],
  opts: IssueTokensOptions,
  initialize: () => Promise<void>,
  refreshKeyDiscovery: () => Promise<KeyDiscoveryMetadata>,
): Promise<FreebirdToken[]> {
  assertProofOptions(opts);
  const factory = proofFactory(opts);
  const limit = batchBodyLimitBytes(state);
  assertFixedProofAllowedForChunks(opts.sybilProof, factory, Math.ceil(msgs.length / MAX_BATCH_SIZE));
  if (msgs.length > 0) {
    const staticBody: BatchIssueReq = {
      blinded_elements: ['A'.repeat(V4_BLINDED_ELEMENT_B64_LENGTH)],
      sybil_proof: opts.sybilProof,
    };
    if (opts.ctxB64 !== undefined) staticBody.ctx_b64 = opts.ctxB64;
    assertStaticBatchFieldsFit(staticBody, limit);
  }
  if (!state.metadata) await initialize();

  const scopeDigest = base64UrlToBytes(state.verifierMetadata!.scope_digest_b64);
  const expectedScopeDigest = voprf.buildScopeDigest(
    state.verifierMetadata!.verifier_id,
    state.verifierMetadata!.audience,
  );
  if (!bytesEqual(scopeDigest, expectedScopeDigest)) {
    throw new DiscoveryError('Verifier scope metadata is inconsistent');
  }

  const completed: FreebirdToken[] = [];
  const results: TokenResult[] = [];
  let msgIndex = 0;
  const pending: { blinded: string; blindState: ReturnType<typeof voprf.blind>['state']; nonce: Uint8Array }[] = [];
  const prepareItem = (): { blinded: string; blindState: ReturnType<typeof voprf.blind>['state']; nonce: Uint8Array } => {
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const input = voprf.buildPrivateTokenInput(
      state.metadata!.issuer_id,
      state.metadata!.voprf.kid,
      nonce,
      scopeDigest,
    );
    const { blinded, state: blindState } = voprf.blind(input, state.context);
    return { blinded: bytesToBase64Url(blinded), blindState, nonce };
  };
  const nextItem = async (): Promise<typeof pending[number] | undefined> => {
    const queued = pending.shift();
    if (queued !== undefined) return queued;
    if (msgIndex >= msgs.length) return undefined;
    msgIndex++;
    return prepareItem();
  };
  const putBack = (item: typeof pending[number]): void => { pending.unshift(item); };
  const hasMore = (): boolean => pending.length > 0 || msgIndex < msgs.length;
  const buildBody = (
    items: typeof pending,
    proof: SybilProof | undefined,
  ): BatchIssueReq => {
    const reqBody: BatchIssueReq = {
      blinded_elements: items.map((item) => item.blinded),
      sybil_proof: proof,
    };
    if (opts.ctxB64 !== undefined) reqBody.ctx_b64 = opts.ctxB64;
    return reqBody;
  };

  let chunkIndex = 0;
  let staleRetryUsed = false;

  tailLoop: while (hasMore()) {
    const chunkStartIndex = msgIndex - pending.length;
    let selected: PreparedChunk<typeof pending[number]>;
    try {
      selected = await takeGreedyChunk({
        next: nextItem,
        putBack,
        hasMore,
        fixedProof: opts.sybilProof,
        limit,
        buildBody,
        resolveProof: async (items) => {
          const binding = buildBatchBinding(
            'issue-batch',
            state.metadata!.issuer_id,
            items.map((item) => item.blinded),
          );
          const enforceProvidedBinding = factory !== undefined || chunkIndex > 0;
          return resolveSybilProof(
            state,
            opts.sybilProof,
            binding,
            factory,
            enforceProvidedBinding,
          );
        },
      });
      if (opts.sybilProof !== undefined && factory === undefined && selected.hasMore) {
        throw new FreebirdError(
          'issuance',
          'A fixed Sybil proof cannot be reused across batch request bindings',
        );
      }
    } catch (cause) {
      if (completed.length > 0) throw new BatchIssuanceInterruptedError(completed.slice(), cause);
      throw cause;
    }
    const blinded = selected.items;
    const serializedBody = selected.serializedBody;
    try {
      for (;;) {
        const res = await (state.config.fetch ?? fetch)(`${state.config.issuerUrl}/v1/oprf/issue/batch`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: serializedBody,
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

        const chunkTokens: FreebirdToken[] = [];
        let rotation = false;
        for (let i = 0; i < resp.results.length; i++) {
          const result = resp.results[i];
          if (result.status === 'success') {
            if (result.issuer_id !== state.metadata!.issuer_id) {
              throw new DiscoveryError('Issuer metadata changed during batch issuance');
            }
            if (result.kid !== state.metadata!.voprf.kid) {
              rotation = true;
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
            chunkTokens.push({
              tokenValue: bytesToBase64Url(redemptionToken),
              issuerId: result.issuer_id,
              version: 4,
              kid: result.kid,
            });
          }
        }
        if (rotation) {
          if (staleRetryUsed) {
            throw new DiscoveryError('Issuer metadata changed during batch issuance');
          }
          assertRetryProofAvailable(opts.sybilProof, factory);
          staleRetryUsed = true;
          const refreshedMetadata = await refreshKeyDiscovery();
          state.metadata!.voprf.kid = refreshedMetadata.voprf.kid;
          state.metadata!.voprf.pubkey = refreshedMetadata.voprf.pubkey;
          // Put the rejected chunk back in front of the still-pending tail.
          // The next outer iteration re-runs greedy sizing with the fresh key
          // and proof; completed chunks remain finalized and are never replayed.
          msgIndex = chunkStartIndex;
          pending.length = 0;
          continue tailLoop;
        }

        results.push(...resp.results);
        if (resp.results.some((result) => result.status === 'error')) {
          throw new BatchIssuanceError(results.slice(), completed.concat(chunkTokens));
        }
        completed.push(...chunkTokens);
        chunkIndex++;
        break;
      }
    } catch (cause) {
      if (cause instanceof BatchIssuanceError) throw cause;
      if (completed.length > 0) {
        throw new BatchIssuanceInterruptedError(completed.slice(), cause);
      }
      throw cause;
    }
  }

  return completed;
}
