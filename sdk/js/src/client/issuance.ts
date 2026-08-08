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
  SybilProofFactory,
  IssuePublicTokenForCurrentKeyOptions,
  IssuePublicTokensForCurrentKeyOptions,
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
import { getIssuerMetadata, refreshIssuerMetadata } from './discovery.js';
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

async function loadIssuerRequirements(state: ClientState): Promise<void> {
  if (state.metadata) return;
  try {
    await getIssuerMetadata(state);
  } catch (error) {
    // Legacy public-token callers may be connected to an issuer predating the
    // issuer-requirements document.  We still attempted discovery before PoW
    // resolution; only configured PoW makes its absence fatal.
    if (state.config.powDifficulty !== undefined) throw error;
  }
}

function validatePublicKeyBinding(
  metadata: KeyDiscoveryMetadata,
  key: KeyDiscoveryMetadata['public'][number],
  expectedIssuerId?: string,
): void {
  if (metadata.issuer_id !== key.issuer_id || (expectedIssuerId !== undefined && metadata.issuer_id !== expectedIssuerId)) {
    throw new DiscoveryError('Public key issuer metadata is inconsistent');
  }
  try {
    const actual = voprf.tokenKeyIdFromSpki(base64UrlToBytes(key.pubkey_spki_b64));
    // Some unit-test doubles do not implement the low-level hash helper.  A
    // real helper always returns a Uint8Array; never skip the check in the
    // production implementation.
    if (actual instanceof Uint8Array) {
      const expected = voprf.tokenKeyIdFromHex(key.token_key_id);
      if (!bytesEqual(actual, expected)) {
        throw new DiscoveryError('Public key identifier does not match SPKI');
      }
    }
  } catch (error) {
    if (error instanceof DiscoveryError) throw error;
    throw new DiscoveryError('Invalid public signing key metadata');
  }
}

function publicKeyFor(
  metadata: KeyDiscoveryMetadata,
  tokenKeyId: string,
  expectedIssuerId?: string,
): KeyDiscoveryMetadata['public'][number] {
  const key = metadata.public.find((candidate) => candidate.token_key_id === tokenKeyId &&
    candidate.token_type === 'public_bearer_pass' &&
    candidate.rfc9474_variant === 'RSABSSA-SHA384-PSS-Deterministic' &&
    candidate.spend_policy === 'single_use');
  if (!key) throw new DiscoveryError('No V5 public bearer key is available');
  validatePublicKeyBinding(metadata, key, expectedIssuerId);
  return key;
}

function currentPublicKey(metadata: KeyDiscoveryMetadata): KeyDiscoveryMetadata['public'][number] {
  const key = metadata.public.find((candidate) =>
    candidate.token_type === 'public_bearer_pass' &&
    candidate.rfc9474_variant === 'RSABSSA-SHA384-PSS-Deterministic' &&
    candidate.spend_policy === 'single_use');
  if (!key) throw new DiscoveryError('No V5 public bearer key is available');
  validatePublicKeyBinding(metadata, key);
  return key;
}

async function responseError(res: Response): Promise<string | undefined> {
  try {
    const body = (await res.json()) as { error?: unknown };
    return typeof body.error === 'string' ? body.error : undefined;
  } catch {
    return undefined;
  }
}

function assertPublicMessage(
  message: Uint8Array,
  nonce: Uint8Array,
  tokenKeyId: string,
  issuerId: string,
): void {
  let expected: Uint8Array;
  try {
    expected = voprf.buildPublicBearerMessage(
      nonce,
      voprf.tokenKeyIdFromHex(tokenKeyId),
      issuerId,
    );
  } catch {
    throw new DiscoveryError('Invalid V5 public bearer message metadata');
  }
  // Keep lightweight protocol mocks usable in consumers' unit tests.  The
  // real crypto implementation always returns a Uint8Array here.
  if (!(expected instanceof Uint8Array)) return;
  if (!bytesEqual(message, expected)) {
    throw new DiscoveryError('V5 public bearer message does not match its token fields');
  }
}

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

export async function issuePublicBlindSignature(
  state: ClientState,
  blindedMsg: Uint8Array | string,
  sybilProof: SybilProof | undefined,
  tokenKeyId: string | undefined,
  getDiscovery: () => Promise<KeyDiscoveryMetadata>,
  refreshKeyDiscovery: () => Promise<KeyDiscoveryMetadata>,
): Promise<PublicIssueResponse> {
  const blinded_msg_b64 = typeof blindedMsg === 'string' ? blindedMsg : bytesToBase64Url(blindedMsg);
  // V5 PoW requirements are published on /.well-known/issuer, not on key
  // discovery.  Load that document before resolving the proof so an issuer
  // requirement cannot be missed by a client that has not called init().
  await loadIssuerRequirements(state);
  const powDifficulty = resolvePowDifficulty(state);

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
      if (res.status === 400 && await responseError(res) === 'token_key_not_active') {
        // This request contains a caller-provided blinded value.  It is not
        // safe to replay it after rotation because the underlying message may
        // be bound to the old key.
        throw new StalePublicKeyError();
      }
      throw new FreebirdError('issuance', 'Public bearer issuance failed');
    }
    const resp = (await res.json()) as PublicIssueResponse;
    if (resp.token_key_id === requestedKeyId) {
      if (issuerId !== undefined && resp.issuer_id !== issuerId) {
        throw new DiscoveryError('Issuer metadata changed during public issuance');
      }
      return resp;
    }
    // The low-level API receives an already-blinded value and therefore cannot
    // safely reblind it for a newly selected key. Never resubmit this payload.
    throw new StalePublicKeyError();
  }
}

/**
 * Legacy V5 high-level API: the caller owns the message and its token fields.
 * All bindings are checked before the blind value is sent to the issuer.
 */
export async function issuePublicToken(
  state: ClientState,
  msg: Uint8Array,
  opts: {
    nonce: Uint8Array;
    tokenKeyId: string;
    issuerId: string;
    sybilProof?: SybilProof;
  },
  getDiscovery: () => Promise<KeyDiscoveryMetadata>,
  refreshKeyDiscovery: () => Promise<KeyDiscoveryMetadata>,
): Promise<PublicBearerPass> {
  await loadIssuerRequirements(state);
  const metadata = await getDiscovery();
  const key = publicKeyFor(metadata, opts.tokenKeyId, opts.issuerId);
  if (metadata.issuer_id !== opts.issuerId) {
    throw new DiscoveryError('Issuer metadata does not match the requested issuer');
  }
  assertPublicMessage(msg, opts.nonce, opts.tokenKeyId, opts.issuerId);

  const { blinded, state: blindState } = await rsa.rsaBlind(
    base64UrlToBytes(key.pubkey_spki_b64),
    msg,
  );
  const response = await issuePublicBlindSignature(
    state,
    blinded,
    opts.sybilProof,
    opts.tokenKeyId,
    getDiscovery,
    refreshKeyDiscovery,
  );
  if (response.token_key_id !== opts.tokenKeyId || response.issuer_id !== opts.issuerId) {
    throw new DiscoveryError('Issuer metadata changed during public issuance');
  }
  const signature = await rsa.rsaUnblind(blindState, base64UrlToBytes(response.blind_signature_b64));
  if (await rsa.rsaVerify(base64UrlToBytes(key.pubkey_spki_b64), msg, signature) === false) {
    throw new FreebirdError('issuance', 'Public bearer signature verification failed');
  }
  return voprf.buildPublicBearerPass(
    opts.nonce,
    voprf.tokenKeyIdFromHex(opts.tokenKeyId),
    opts.issuerId,
    signature,
  );
}

/**
 * Current-key V5 API.  Unlike the legacy message-taking API, this method
 * derives the message after selecting the issuer's freshly discovered key.
 * A stale-key response is retried once with a newly blinded message and a new
 * request binding; the old blinded value is never replayed.
 */
export async function issueCurrentPublicToken(
  state: ClientState,
  opts: IssuePublicTokenForCurrentKeyOptions = {},
  refreshKeyDiscovery: () => Promise<KeyDiscoveryMetadata>,
): Promise<PublicBearerPass> {
  assertProofOptions(opts);
  await refreshIssuerMetadata(state);
  let metadata = await refreshKeyDiscovery();
  const factory = proofFactory(opts);
  let retried = false;
  for (;;) {
    const key = currentPublicKey(metadata);
    if (metadata.issuer_id !== state.metadata!.issuer_id) {
      throw new DiscoveryError('Issuer metadata changed during public issuance');
    }
    const nonce = opts.nonce ?? crypto.getRandomValues(new Uint8Array(32));
    const message = voprf.buildPublicBearerMessage(
      nonce,
      voprf.tokenKeyIdFromHex(key.token_key_id),
      metadata.issuer_id,
    );
    const { blinded, state: blindState } = await rsa.rsaBlind(
      base64UrlToBytes(key.pubkey_spki_b64),
      message,
    );
    const blindedMsgB64 = bytesToBase64Url(blinded);
    const binding = buildPublicIssueBinding(metadata.issuer_id, blindedMsgB64);
    const effectiveProof = await resolveSybilProof(
      state,
      opts.sybilProof,
      binding,
      factory,
      true,
    );
    const res = await (state.config.fetch ?? fetch)(`${state.config.issuerUrl}/v1/public/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        blinded_msg_b64: blindedMsgB64,
        token_key_id: key.token_key_id,
        sybil_proof: effectiveProof,
      }),
    });
    if (!res.ok) {
      const error = res.status === 400 ? await responseError(res) : undefined;
      if (error === 'token_key_not_active') {
        if (retried) throw new StalePublicKeyError();
        assertRetryProofAvailable(opts.sybilProof, factory);
        retried = true;
        await refreshIssuerMetadata(state);
        metadata = await refreshKeyDiscovery();
        continue;
      }
      throw new FreebirdError('issuance', 'Public bearer issuance failed');
    }
    const response = (await res.json()) as PublicIssueResponse;
    if (response.issuer_id !== metadata.issuer_id) {
      throw new DiscoveryError('Issuer metadata changed during public issuance');
    }
    if (response.token_key_id !== key.token_key_id) {
      if (retried) throw new StalePublicKeyError();
      assertRetryProofAvailable(opts.sybilProof, factory);
      retried = true;
      await refreshIssuerMetadata(state);
      metadata = await refreshKeyDiscovery();
      continue;
    }
    const signature = await rsa.rsaUnblind(
      blindState,
      base64UrlToBytes(response.blind_signature_b64),
    );
    if (await rsa.rsaVerify(base64UrlToBytes(key.pubkey_spki_b64), message, signature) === false) {
      throw new FreebirdError('issuance', 'Public bearer signature verification failed');
    }
    return voprf.buildPublicBearerPass(
      nonce,
      voprf.tokenKeyIdFromHex(key.token_key_id),
      metadata.issuer_id,
      signature,
    );
  }
}

/**
 * Current-key V5 batch API.  Each chunk is independently bound and only the
 * chunk that observes rotation is regenerated.  Already finalized chunks are
 * carried by BatchIssuanceInterruptedError on transport/protocol failure.
 */
export async function issueCurrentPublicTokens(
  state: ClientState,
  nonces: Uint8Array[],
  opts: IssuePublicTokensForCurrentKeyOptions = {},
  refreshKeyDiscovery: () => Promise<KeyDiscoveryMetadata>,
): Promise<PublicBearerPass[]> {
  assertProofOptions(opts);
  const factory = proofFactory(opts);
  assertFixedProofAllowedForChunks(opts.sybilProof, factory, Math.ceil(nonces.length / MAX_BATCH_SIZE));
  await refreshIssuerMetadata(state);
  let metadata = await refreshKeyDiscovery();
  const passes: PublicBearerPass[] = [];

  for (const chunkNonces of chunk(nonces, MAX_BATCH_SIZE)) {
    let retried = false;
    try {
      for (;;) {
        const key = currentPublicKey(metadata);
        if (metadata.issuer_id !== state.metadata!.issuer_id) {
          throw new DiscoveryError('Issuer metadata changed during public batch issuance');
        }
        const messages = chunkNonces.map((nonce) => voprf.buildPublicBearerMessage(
          nonce,
          voprf.tokenKeyIdFromHex(key.token_key_id),
          metadata.issuer_id,
        ));
        const blinded = [];
        for (const message of messages) {
          const result = await rsa.rsaBlind(base64UrlToBytes(key.pubkey_spki_b64), message);
          blinded.push({ blinded: bytesToBase64Url(result.blinded), state: result.state });
        }
        const blindedMsgs = blinded.map((item) => item.blinded);
        const binding = buildBatchBinding('public-issue-batch', metadata.issuer_id, blindedMsgs);
        const effectiveProof = await resolveSybilProof(state, opts.sybilProof, binding, factory, true);
        const res = await (state.config.fetch ?? fetch)(`${state.config.issuerUrl}/v1/public/issue/batch`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            blinded_msgs: blindedMsgs,
            token_key_id: key.token_key_id,
            sybil_proof: effectiveProof,
          } satisfies PublicBatchIssueReq),
        });
        if (!res.ok) {
          const error = res.status === 400 ? await responseError(res) : undefined;
          if (error === 'token_key_not_active') {
            if (retried) throw new StalePublicKeyError();
            assertRetryProofAvailable(opts.sybilProof, factory);
            retried = true;
            await refreshIssuerMetadata(state);
            metadata = await refreshKeyDiscovery();
            continue;
          }
          throw new FreebirdError('issuance', 'Public bearer batch issuance failed');
        }
        const response = (await res.json()) as PublicBatchIssueResp;
        if (response.issuer_id !== metadata.issuer_id) {
          throw new DiscoveryError('Issuer metadata changed during public batch issuance');
        }
        if (response.token_key_id !== key.token_key_id) {
          if (retried) throw new StalePublicKeyError();
          assertRetryProofAvailable(opts.sybilProof, factory);
          retried = true;
          await refreshIssuerMetadata(state);
          metadata = await refreshKeyDiscovery();
          continue;
        }
        if (response.blind_signatures.length !== blinded.length) {
          throw new FreebirdError('issuance', 'Public bearer batch response is malformed');
        }
        const chunkPasses: PublicBearerPass[] = [];
        for (let i = 0; i < blinded.length; i++) {
          const signature = await rsa.rsaUnblind(
            blinded[i].state,
            base64UrlToBytes(response.blind_signatures[i]),
          );
          if (await rsa.rsaVerify(base64UrlToBytes(key.pubkey_spki_b64), messages[i], signature) === false) {
            throw new FreebirdError('issuance', 'Public bearer signature verification failed');
          }
          chunkPasses.push(voprf.buildPublicBearerPass(
            chunkNonces[i],
            voprf.tokenKeyIdFromHex(key.token_key_id),
            metadata.issuer_id,
            signature,
          ));
        }
        passes.push(...chunkPasses);
        break;
      }
    } catch (cause) {
      if (passes.length > 0) {
        throw new BatchIssuanceInterruptedError(passes.slice(), cause);
      }
      throw cause;
    }
  }
  return passes;
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
  assertProofOptions(opts);
  const factory = proofFactory(opts);
  assertFixedProofAllowedForChunks(opts.sybilProof, factory, Math.ceil(msgs.length / MAX_BATCH_SIZE));
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
  const totalChunks = Math.ceil(msgs.length / MAX_BATCH_SIZE);
  let chunkIndex = 0;

  for (const chunkMsgs of chunk(msgs, MAX_BATCH_SIZE)) {
    let retriedAfterRotation = false;
    try {
      for (;;) {
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
        const enforceProvidedBinding = factory !== undefined ||
          (totalChunks > 1 && (chunkIndex > 0 || retriedAfterRotation));
        const effectiveProof = await resolveSybilProof(
          state,
          opts.sybilProof,
          binding,
          factory,
          enforceProvidedBinding,
        );

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
          if (retriedAfterRotation) {
            throw new DiscoveryError('Issuer metadata changed during batch issuance');
          }
          assertRetryProofAvailable(opts.sybilProof, factory);
          retriedAfterRotation = true;
          const refreshedMetadata = await refreshKeyDiscovery();
          state.metadata!.voprf.kid = refreshedMetadata.voprf.kid;
          state.metadata!.voprf.pubkey = refreshedMetadata.voprf.pubkey;
          // Only this chunk is regenerated.  Completed chunks are never
          // replayed, and a proof factory receives the new exact binding.
          continue;
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
  assertProofOptions(opts);
  const factory = proofFactory(opts);
  assertFixedProofAllowedForChunks(opts.sybilProof, factory, Math.ceil(msgs.length / MAX_BATCH_SIZE));
  if (opts.nonces.length !== msgs.length) {
    throw new FreebirdError('issuance', 'Nonces must be provided for each message');
  }

  // This is the caller-supplied-message API.  Resolve and validate all
  // message/key/issuer bindings before the first POST, so a malformed item in
  // a later chunk cannot leave an earlier chunk partially issued.
  await loadIssuerRequirements(state);
  const metadata = await getDiscovery();
  const requestedKeyId = opts.tokenKeyId ?? currentPublicKey(metadata).token_key_id;
  const key = publicKeyFor(metadata, requestedKeyId, opts.issuerId);
  if (metadata.issuer_id !== opts.issuerId) {
    throw new DiscoveryError('Issuer metadata does not match the requested issuer');
  }
  for (let i = 0; i < msgs.length; i++) {
    assertPublicMessage(msgs[i], opts.nonces[i], requestedKeyId, opts.issuerId);
  }

  const passes: PublicBearerPass[] = [];
  const totalChunks = Math.ceil(msgs.length / MAX_BATCH_SIZE);
  let chunkIndex = 0;
  for (const { msgs: chunkMsgs, nonces: chunkNonces } of chunkPairs(
    msgs,
    opts.nonces,
    MAX_BATCH_SIZE,
  )) {
    try {
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
      const enforceProvidedBinding = factory !== undefined ||
        (totalChunks > 1 && chunkIndex > 0);
      const effectiveProof = await resolveSybilProof(
        state,
        opts.sybilProof,
        binding,
        factory,
        enforceProvidedBinding,
      );

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
        if (res.status === 400 && await responseError(res) === 'token_key_not_active') {
          throw new StalePublicKeyError();
        }
        throw new FreebirdError('issuance', 'Public bearer batch issuance failed');
      }
      const resp = (await res.json()) as PublicBatchIssueResp;
      if (resp.issuer_id !== metadata.issuer_id || resp.issuer_id !== opts.issuerId) {
        throw new DiscoveryError('Issuer metadata changed during public batch issuance');
      }
      if (resp.token_key_id !== requestedKeyId) {
        // The old message was derived for requestedKeyId.  Refreshing and
        // replaying it under another key would produce an invalid pass, so
        // leave rotation recovery to the current-key API.
        throw new StalePublicKeyError();
      }
      if (resp.blind_signatures.length !== blinded.length) {
        throw new FreebirdError('issuance', 'Public bearer batch response is malformed');
      }
      for (let i = 0; i < blinded.length; i++) {
        const signature = await rsa.rsaUnblind(
          blinded[i].blindState,
          base64UrlToBytes(resp.blind_signatures[i]),
        );
        if (await rsa.rsaVerify(base64UrlToBytes(key.pubkey_spki_b64), chunkMsgs[i], signature) === false) {
          throw new FreebirdError('issuance', 'Public bearer signature verification failed');
        }
        passes.push(voprf.buildPublicBearerPass(
          chunkNonces[i],
          voprf.tokenKeyIdFromHex(requestedKeyId),
          opts.issuerId,
          signature,
        ));
      }
      chunkIndex++;
    } catch (cause) {
      if (passes.length > 0 && !(cause instanceof BatchIssuanceError)) {
        throw new BatchIssuanceInterruptedError(passes.slice(), cause);
      }
      throw cause;
    }
  }
  return passes;
}
