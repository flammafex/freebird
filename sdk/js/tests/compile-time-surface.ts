// SPDX-License-Identifier: Apache-2.0 OR MIT

import {
  FreebirdClient,
  MemoryTokenStore,
  StorageTokenStore,
  buildGraphIssuanceHmacAuthorizationV2,
  buildHmacAuthorizationV2,
  crypto,
  deserializeGraphIssuanceRecoveryContext,
  graphIssuanceHmacAuthorizationTagV2,
  graphIssuanceHmacAuthorizationTranscriptV2,
  hmacAuthorizationTagV2,
  hmacAuthorizationTranscriptV2,
  parseGraphIssuanceHmacAuthorizationV2,
  parseHmacAuthorizationV2,
  pollExchangeStatus,
  pollGraphIssuanceStatus,
  serializeGraphIssuanceRecoveryContext,
  verifyGraphIssuanceHmacAuthorizationV2,
  verifyHmacAuthorizationV2,
  DiscoveryError,
  ExchangeError,
  FreebirdError,
  GraphIssuanceError,
  InvalidTokenError,
  PollAbortedError,
  PollError,
  PollTimeoutError,
  RateLimitedError,
  ReplayedTokenError,
  VerificationError,
  VerifierNotConfiguredError,
  VerifierUnavailableError,
  BatchIssuanceError,
  buildBatchBinding,
  buildIssueBinding,
  buildPublicIssueBinding,
  buildRenewBinding,
  generateProofOfWork,
  verifyPow,
} from '../src/index.js';
import type {
  BatchIssueReq,
  BatchIssueResp,
  BatchVerifyReq,
  BatchVerifyResp,
  ClientConfig,
  ExchangeOutcome,
  ExchangeRequest,
  ExchangeRequestSource,
  FreebirdErrorCode,
  FreebirdToken,
  GraphIssuancePolicyInfo,
  GraphIssuanceOutcome,
  GraphIssuanceRecoveryContext,
  GraphIssuanceRequest,
  IssuePublicTokenOptions,
  IssuePublicTokensOptions,
  IssuePublicTokenForCurrentKeyOptions,
  IssuePublicTokensForCurrentKeyOptions,
  IssueTokensOptions,
  KeyDiscoveryMetadata,
  PollOptions,
  PublicBatchIssueReq,
  PublicBatchIssueResp,
  PublicBearerPass,
  PublicIssueResponse,
  PublicKeyInfo,
  PreparedExchange,
  FinalizedExchangeOutput,
  RsaBlindState,
  SybilProof,
  SybilProofFactory,
  SybilConfigSummary,
  SybilModeSettings,
  TokenResult,
  TokenStore,
  TokenToVerify,
  TrustLevelSummary,
  VerifyReq,
  VerifyResp,
  VerifyResult,
} from '../src/index.js';
import type { ExchangeTransitionSelection } from '../src/types.js';
import type { ExchangePassesOptions } from '../src/index.js';

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends
  (<Value>() => Value extends Right ? 1 : 2) ? true : false;
type Assert<Value extends true> = Value;
type PublicClientKeys =
  | 'init'
  | 'issueToken'
  | 'issueTokenWithProofFactory'
  | 'issueTokens'
  | 'getKeyDiscoveryMetadata'
  | 'refreshKeyDiscoveryMetadata'
  | 'issuePublicBlindSignature'
  | 'issuePublicToken'
  | 'issuePublicTokens'
  | 'issuePublicTokenForCurrentKey'
  | 'issuePublicTokensForCurrentKey'
  | 'verifyPublicBearerPassLocally'
  | 'selectExchangeTransition'
  | 'exchange'
  | 'getExchangeStatus'
  | 'exchangeRequestDigest'
  | 'generateOperationId'
  | 'generateStatusCapability'
  | 'exchangePasses'
  | 'prepareExchangePasses'
  | 'finalizeExchangePasses'
  | 'selectGraphIssuancePolicy'
  | 'issueGraphBlindSignature'
  | 'retryGraphBlindSignature'
  | 'retryGraphIssuance'
  | 'createGraphIssuanceRecoveryContext'
  | 'getGraphIssuanceStatus'
  | 'pollExchangeStatus'
  | 'pollGraphIssuanceStatus'
  | 'graphIssuanceRequestDigest'
  | 'graphIssuanceAuthorizationBindingDigest'
  | 'verifyToken'
  | 'verifyTokenValid'
  | 'checkToken'
  | 'verifyBatch'
  | 'tokenStore';

type ExpectedExchangeStatus = {
  (submittedRequest: ExchangeRequest, statusCapability: string): Promise<ExchangeOutcome>;
  (
    publicOperationId: string,
    statusCapability: string,
    submittedRequest: ExchangeRequest,
  ): Promise<ExchangeOutcome>;
};

// This interface is deliberately written independently of FreebirdClient. Do
// not derive it from the implementation: the bidirectional and per-member
// checks below are intended to catch API widening, narrowing, or extra args.
interface ExpectedFreebirdClient {
  init: () => Promise<void>;
  issueToken: (sybilProof?: SybilProof) => Promise<FreebirdToken>;
  issueTokenWithProofFactory: (proofFactory: SybilProofFactory) => Promise<FreebirdToken>;
  issueTokens: (msgs: Uint8Array[], opts?: IssueTokensOptions) => Promise<FreebirdToken[]>;
  getKeyDiscoveryMetadata: () => Promise<KeyDiscoveryMetadata>;
  refreshKeyDiscoveryMetadata: () => Promise<KeyDiscoveryMetadata>;
  issuePublicBlindSignature: (
    blindedMsg: Uint8Array | string,
    sybilProof?: SybilProof,
    tokenKeyId?: string,
  ) => Promise<PublicIssueResponse>;
  issuePublicToken: (
    msg: Uint8Array,
    opts: IssuePublicTokenOptions,
  ) => Promise<PublicBearerPass>;
  issuePublicTokens: (
    msgs: Uint8Array[],
    opts: IssuePublicTokensOptions,
  ) => Promise<PublicBearerPass[]>;
  issuePublicTokenForCurrentKey: (
    opts?: IssuePublicTokenForCurrentKeyOptions,
  ) => Promise<PublicBearerPass>;
  issuePublicTokensForCurrentKey: (
    nonces: Uint8Array[],
    opts?: IssuePublicTokensForCurrentKeyOptions,
  ) => Promise<PublicBearerPass[]>;
  verifyPublicBearerPassLocally: (
    pass: PublicBearerPass,
    keyInfo: PublicKeyInfo,
  ) => Promise<boolean>;
  selectExchangeTransition: (
    graphId: string,
    transitionId: string,
  ) => Promise<ExchangeTransitionSelection>;
  exchange: (request: ExchangeRequest, statusCapability: string) => Promise<ExchangeOutcome>;
  getExchangeStatus: ExpectedExchangeStatus;
  exchangeRequestDigest: (request: ExchangeRequest) => string;
  generateOperationId: () => string;
  generateStatusCapability: () => string;
  exchangePasses: (
    sources: ExchangeRequestSource[],
    transition: { graphId: string; transitionId: string },
    opts?: ExchangePassesOptions,
  ) => Promise<ExchangeRequest>;
  prepareExchangePasses: (
    sources: ExchangeRequestSource[],
    transition: { graphId: string; transitionId: string },
    opts?: ExchangePassesOptions,
  ) => Promise<PreparedExchange>;
  finalizeExchangePasses: (
    prepared: PreparedExchange,
    outcome: ExchangeOutcome,
  ) => Promise<FinalizedExchangeOutput[]>;
  selectGraphIssuancePolicy: (policyId: string) => Promise<GraphIssuancePolicyInfo>;
  issueGraphBlindSignature: (
    request: GraphIssuanceRequest,
    statusCapability: string,
  ) => Promise<GraphIssuanceOutcome>;
  retryGraphBlindSignature: (
    context: GraphIssuanceRecoveryContext,
  ) => Promise<GraphIssuanceOutcome>;
  retryGraphIssuance: (
    context: GraphIssuanceRecoveryContext,
  ) => Promise<GraphIssuanceOutcome>;
  createGraphIssuanceRecoveryContext: (
    request: GraphIssuanceRequest,
    statusCapability: string,
    expectedTokenKeyId: string,
    blindingState: unknown,
  ) => Promise<GraphIssuanceRecoveryContext>;
  getGraphIssuanceStatus: (
    context: GraphIssuanceRecoveryContext,
  ) => Promise<GraphIssuanceOutcome>;
  pollExchangeStatus: (
    request: ExchangeRequest,
    statusCapability: string,
    options?: PollOptions,
  ) => Promise<ExchangeOutcome>;
  pollGraphIssuanceStatus: (
    context: GraphIssuanceRecoveryContext,
    options?: PollOptions,
  ) => Promise<GraphIssuanceOutcome>;
  graphIssuanceRequestDigest: (request: GraphIssuanceRequest) => string;
  graphIssuanceAuthorizationBindingDigest: (request: GraphIssuanceRequest) => string;
  verifyToken: (token: FreebirdToken) => Promise<VerifyResp>;
  verifyTokenValid: (token: FreebirdToken) => Promise<boolean>;
  checkToken: (token: FreebirdToken) => Promise<VerifyResp>;
  verifyBatch: (tokens: FreebirdToken[]) => Promise<BatchVerifyResp>;
  readonly tokenStore: TokenStore | undefined;
}

type PublicClientProjection = {
  [Key in keyof FreebirdClient]: FreebirdClient[Key]
};

type _expectedPublicKeys = Assert<Equal<keyof ExpectedFreebirdClient, PublicClientKeys>>;
type _exactPublicKeys = Assert<Equal<keyof PublicClientProjection, keyof ExpectedFreebirdClient>>;
type _exactConstructorArgs = Assert<Equal<ConstructorParameters<typeof FreebirdClient>, [ClientConfig]>>;
type _constructorAssignable = Assert<
  typeof FreebirdClient extends new (config: ClientConfig) => FreebirdClient ? true : false
>;
type _implementationSatisfiesContract = Assert<PublicClientProjection extends ExpectedFreebirdClient ? true : false>;
type _contractSatisfiesImplementation = Assert<ExpectedFreebirdClient extends PublicClientProjection ? true : false>;
type _exactPublicMethods = {
  [Key in keyof ExpectedFreebirdClient]: Assert<
    Equal<PublicClientProjection[Key], ExpectedFreebirdClient[Key]>
  >
};

const config: ClientConfig = { issuerUrl: 'https://issuer.example', verifierUrl: 'https://verifier.example' };
const configWithCacheTtl: ClientConfig = {
  issuerUrl: 'https://issuer.example',
  verifierUrl: 'https://verifier.example',
  keyCacheTtlMs: 30_000,
};
const cacheTtl: number | undefined = configWithCacheTtl.keyCacheTtlMs;
const client = new FreebirdClient(config);
const constructor: new (config: ClientConfig) => FreebirdClient = FreebirdClient;
const publicFacade: Pick<FreebirdClient, PublicClientKeys> = client;

declare const exchangeRequest: ExchangeRequest;
declare const exchangeSources: ExchangeRequestSource[];
declare const graphRequest: GraphIssuanceRequest;
declare const recoveryContext: GraphIssuanceRecoveryContext;
declare const capability: string;
declare const operationId: string;
declare const expectedTokenKeyId: string;
declare const blindingState: unknown;

// Keep the facade's ordinary and protocol-specific methods in the compiler gate.
const initialized: Promise<void> = client.init();
const v4: Promise<FreebirdToken> = client.issueToken();
const v4WithProof: Promise<FreebirdToken> = client.issueToken({ type: 'none' });
const v4WithProofFactory: Promise<FreebirdToken> = client.issueTokenWithProofFactory(
  ({ binding }) => ({ type: 'proof_of_work', input: binding, nonce: 0, timestamp: 0 }),
);
const v4Batch: Promise<FreebirdToken[]> = client.issueTokens([new Uint8Array(32), new Uint8Array(32)]);
const v4BatchWithOpts: Promise<FreebirdToken[]> = client.issueTokens(
  [new Uint8Array(32)],
  { sybilProof: { type: 'none' }, ctxB64: 'ctx' },
);
const discovery: Promise<KeyDiscoveryMetadata> = client.getKeyDiscoveryMetadata();
const refreshedDiscovery: Promise<KeyDiscoveryMetadata> = client.refreshKeyDiscoveryMetadata();
const v5Bytes: Promise<PublicIssueResponse> = client.issuePublicBlindSignature(new Uint8Array());
const v5String: Promise<PublicIssueResponse> = client.issuePublicBlindSignature('blinded-message');
const publicToken: Promise<PublicBearerPass> = client.issuePublicToken(
  new Uint8Array(48),
  { nonce: new Uint8Array(32), tokenKeyId: 'a'.repeat(64), issuerId: 'issuer:test' },
);
const publicTokensBatch: Promise<PublicBearerPass[]> = client.issuePublicTokens(
  [new Uint8Array(48), new Uint8Array(48)],
  {
    tokenKeyId: 'a'.repeat(64),
    issuerId: 'issuer:test',
    nonces: [new Uint8Array(32), new Uint8Array(32)],
  },
);
const currentPublicToken: Promise<PublicBearerPass> = client.issuePublicTokenForCurrentKey({
  nonce: new Uint8Array(32),
});
const currentPublicTokens: Promise<PublicBearerPass[]> = client.issuePublicTokensForCurrentKey(
  [new Uint8Array(32), new Uint8Array(32)],
);
const locallyVerified: Promise<boolean> = client.verifyPublicBearerPassLocally(
  new Uint8Array(),
  {
    token_key_id: 'a'.repeat(64),
    token_type: 'public_bearer_pass',
    rfc9474_variant: 'RSABSSA-SHA384-PSS-Deterministic',
    modulus_bits: 2048,
    pubkey_spki_b64: 'spki',
    issuer_id: 'issuer:test',
    valid_from: 0,
    valid_until: 1,
    spend_policy: 'single_use',
  },
);
const transitionSelection = client.selectExchangeTransition('a'.repeat(64), 'b'.repeat(64));
const exchange: Promise<ExchangeOutcome> = client.exchange(exchangeRequest, capability);
const preparedExchange: Promise<PreparedExchange> = client.prepareExchangePasses(
  exchangeSources,
  { graphId: 'a'.repeat(64), transitionId: 'b'.repeat(64) },
);
declare const committedExchange: ExchangeOutcome;
declare const preparedForFinalization: PreparedExchange;
const finalizedExchange: Promise<FinalizedExchangeOutput[]> = client.finalizeExchangePasses(
  preparedForFinalization,
  committedExchange,
);
const exchangeStatusRequest: Promise<ExchangeOutcome> = client.getExchangeStatus(
  exchangeRequest,
  capability,
);
const exchangeStatusId: Promise<ExchangeOutcome> = client.getExchangeStatus(
  operationId,
  capability,
  exchangeRequest,
);
const graphFresh: Promise<GraphIssuanceOutcome> = client.issueGraphBlindSignature(
  graphRequest,
  capability,
);
const graphPolicy: Promise<GraphIssuancePolicyInfo> = client.selectGraphIssuancePolicy('policy');
const graphRetry: Promise<GraphIssuanceOutcome> = client.retryGraphBlindSignature(recoveryContext);
const graphAlias: Promise<GraphIssuanceOutcome> = client.retryGraphIssuance(recoveryContext);
const graphContext: Promise<GraphIssuanceRecoveryContext> = client.createGraphIssuanceRecoveryContext(
  graphRequest,
  capability,
  expectedTokenKeyId,
  blindingState,
);
const graphStatus: Promise<GraphIssuanceOutcome> = client.getGraphIssuanceStatus(recoveryContext);
const exchangeDigest: string = client.exchangeRequestDigest(exchangeRequest);
const generatedOperationId: string = client.generateOperationId();
const generatedStatusCapability: string = client.generateStatusCapability();
const exchangePassesRequest: Promise<ExchangeRequest> = client.exchangePasses(
  exchangeSources,
  { graphId: 'a'.repeat(64), transitionId: 'b'.repeat(64) },
  { messages: [new Uint8Array(48)] },
);
const graphDigest: string = client.graphIssuanceRequestDigest(graphRequest);
const graphBindingDigest: string = client.graphIssuanceAuthorizationBindingDigest(graphRequest);
const verified: Promise<VerifyResp> = client.verifyToken({ tokenValue: 'token', issuerId: 'issuer' });
const verifiedValid: Promise<boolean> = client.verifyTokenValid({ tokenValue: 'token', issuerId: 'issuer' });
const checked: Promise<VerifyResp> = client.checkToken({ tokenValue: 'token', issuerId: 'issuer' });
const batchVerified: Promise<BatchVerifyResp> = client.verifyBatch([
  { tokenValue: 'token', issuerId: 'issuer' },
]);

// Phase 8: token store + polling surface.
const configWithStore: ClientConfig = {
  issuerUrl: 'https://issuer.example',
  tokenStore: new MemoryTokenStore(),
};
const store: TokenStore | undefined = client.tokenStore;
const memoryStore: TokenStore = new MemoryTokenStore();
const storageStore: TokenStore = new StorageTokenStore({ key: 'freebird-tokens' });
const saved: Promise<void> = memoryStore.save({ tokenValue: 't', issuerId: 'i', valid_until: 1 });
const loaded: Promise<FreebirdToken | null> = memoryStore.load();
const loadedById: Promise<FreebirdToken | null> = memoryStore.load('t');
const listed: Promise<FreebirdToken[]> = memoryStore.list();
const cleared: Promise<void> = memoryStore.clear();
const pollOptions: PollOptions = { intervalMs: 100, timeoutMs: 1000, signal: new AbortController().signal };
const polledExchange: Promise<ExchangeOutcome> = client.pollExchangeStatus(exchangeRequest, capability, pollOptions);
const polledGraph: Promise<GraphIssuanceOutcome> = client.pollGraphIssuanceStatus(recoveryContext, pollOptions);
const standalonePollExchange: Promise<ExchangeOutcome> = pollExchangeStatus(
  () => Promise.resolve({ kind: 'committed', httpStatus: 200, response: {} as never, rawResponseBody: '', cacheControl: 'no-store' }),
  pollOptions,
);
const standalonePollGraph: Promise<GraphIssuanceOutcome> = pollGraphIssuanceStatus(
  () => Promise.resolve({ kind: 'committed', httpStatus: 200, response: {} as never, rawResponseBody: '', cacheControl: 'no-store' }),
  pollOptions,
);
const serializedContext: string = serializeGraphIssuanceRecoveryContext(recoveryContext);
const deserializedContext: GraphIssuanceRecoveryContext = deserializeGraphIssuanceRecoveryContext(serializedContext);
const pollErr: PollError = new PollTimeoutError();
const pollAborted: PollError = new PollAbortedError();
const pollCode: FreebirdErrorCode = pollErr.code;

// The HMAC names are intentionally available in both their protocol-qualified and
// compatibility-alias forms, including through the `crypto` facade.
const transcript: typeof graphIssuanceHmacAuthorizationTranscriptV2 = hmacAuthorizationTranscriptV2;
const tag: typeof graphIssuanceHmacAuthorizationTagV2 = hmacAuthorizationTagV2;
const build: typeof buildGraphIssuanceHmacAuthorizationV2 = buildHmacAuthorizationV2;
const parse: typeof parseGraphIssuanceHmacAuthorizationV2 = parseHmacAuthorizationV2;
const verify: typeof verifyGraphIssuanceHmacAuthorizationV2 = verifyHmacAuthorizationV2;
const cryptoTranscript: typeof graphIssuanceHmacAuthorizationTranscriptV2 =
  crypto.graphIssuanceHmacAuthorizationTranscriptV2;
const cryptoAlias: typeof graphIssuanceHmacAuthorizationTranscriptV2 =
  crypto.hmacAuthorizationTranscriptV2;

// The RFC 9474 RSA blind-signature facade is part of the crypto surface.
const rsaBlindResult: Promise<{ blinded: Uint8Array; state: RsaBlindState }> =
  crypto.rsaBlind(new Uint8Array(), new Uint8Array());
const rsaUnblindResult: Promise<Uint8Array> =
  crypto.rsaUnblind({ inv: new Uint8Array(), prepared: new Uint8Array(), publicKey: new Uint8Array() }, new Uint8Array());
const rsaVerifyResult: Promise<boolean> =
  crypto.rsaVerify(new Uint8Array(), new Uint8Array(), new Uint8Array());

// The typed error hierarchy is part of the public surface. Every concrete
// error is assignable to FreebirdError, and FreebirdErrorCode is a closed
// string-literal union.
type _errorsExtendFreebirdError = Assert<
  DiscoveryError extends FreebirdError ? true : false
>;
type _verificationErrorsExtendVerificationError = Assert<
  InvalidTokenError extends VerificationError ? true : false
>;
type _replayedExtendsVerificationError = Assert<
  ReplayedTokenError extends VerificationError ? true : false
>;
type _verificationExtendsFreebirdError = Assert<
  VerificationError extends FreebirdError ? true : false
>;
type _verifierNotConfiguredExtendsFreebirdError = Assert<
  VerifierNotConfiguredError extends FreebirdError ? true : false
>;
type _exchangeExtendsFreebirdError = Assert<
  ExchangeError extends FreebirdError ? true : false
>;
type _graphIssuanceExtendsFreebirdError = Assert<
  GraphIssuanceError extends FreebirdError ? true : false
>;
type _rateLimitedExtendsFreebirdError = Assert<
  RateLimitedError extends FreebirdError ? true : false
>;
type _verifierUnavailableExtendsFreebirdError = Assert<
  VerifierUnavailableError extends FreebirdError ? true : false
>;
type _freebirdErrorCodeIsStringUnion = Assert<
  FreebirdErrorCode extends string ? true : false
>;
type _freebirdErrorCodeCoversExpectedCodes = Assert<
  'discovery' | 'verification' | 'verifier_not_configured' | 'exchange' |
  'graph_issuance' | 'issuance' | 'rate_limited' | 'verifier_unavailable' |
  'invalid_token' | 'replayed_token' extends FreebirdErrorCode ? true : false
>;

// The error classes are constructible and carry the expected fields.
const err: FreebirdError = new DiscoveryError();
const invalidToken: InvalidTokenError = new InvalidTokenError();
const replayed: ReplayedTokenError = new ReplayedTokenError();
const rateLimited: RateLimitedError = new RateLimitedError(30);
const retryAfter: number = rateLimited.retryAfter;
const code: FreebirdErrorCode = err.code;
const exchangeErr: ExchangeError = new ExchangeError();
const graphErr: GraphIssuanceError = new GraphIssuanceError();
const outcome: ExchangeOutcome | undefined = exchangeErr.outcome;
const graphOutcome: GraphIssuanceOutcome | undefined = graphErr.outcome;
const batchErr: BatchIssuanceError = new BatchIssuanceError(
  [{ status: 'error', message: 'boom', code: 'validation_failed' }],
  [],
);
const batchErrCode: FreebirdErrorCode = batchErr.code;
const batchErrFailed: number = batchErr.failed;
const batchErrTokens: FreebirdToken[] = batchErr.tokens;
const batchErrResults: { status: string }[] = batchErr.results;
type _batchIssuanceExtendsFreebirdError = Assert<
  BatchIssuanceError extends FreebirdError ? true : false
>;

// Phase 5: batch issuance request/response wire types are part of the public
// surface and must stay structurally stable.
const batchIssueReq: BatchIssueReq = {
  blinded_elements: ['BAU'],
  ctx_b64: 'ctx',
  sybil_proof: { type: 'none' },
};
const batchIssueResp: BatchIssueResp = {
  results: [{ status: 'success', token: 't', kid: 'kid', issuer_id: 'issuer' }],
  successful: 1,
  failed: 0,
  processing_time_ms: 1,
  throughput: 1,
};
const tokenResult: TokenResult = { status: 'error', message: 'boom', code: 'validation_failed' };
const publicBatchIssueReq: PublicBatchIssueReq = {
  blinded_msgs: ['BAU'],
  token_key_id: 'a'.repeat(64),
  sybil_proof: { type: 'none' },
};
const publicBatchIssueResp: PublicBatchIssueResp = {
  blind_signatures: ['sig'],
  token_key_id: 'a'.repeat(64),
  issuer_id: 'issuer',
  successful: 1,
  failed: 0,
  processing_time_ms: 1,
  throughput: 1,
};

// Phase 2: verification request/response wire types are part of the public
// surface and must stay structurally stable.
const verifyReq: VerifyReq = { token_b64: 'token' };
const tokenToVerify: TokenToVerify = { token_b64: 'token' };
const batchVerifyReq: BatchVerifyReq = { tokens: [tokenToVerify] };
const verifyResult: VerifyResult = { status: 'success', verified_at: 1 };
const verifyResp: VerifyResp = { ok: true, verified_at: 1 };

void v4;
void v4WithProof;
void v4Batch;
void v4BatchWithOpts;
void initialized;
void discovery;
void refreshedDiscovery;
void v5Bytes;
void v5String;
void publicToken;
void publicTokensBatch;
void locallyVerified;
void transitionSelection;
void exchange;
void exchangeStatusRequest;
void exchangeStatusId;
void graphFresh;
void graphPolicy;
void graphRetry;
void graphAlias;
void graphContext;
void graphStatus;
void exchangeDigest;
void generatedOperationId;
void generatedStatusCapability;
void exchangePassesRequest;
void graphDigest;
void graphBindingDigest;
void verified;
void verifiedValid;
void checked;
void batchVerified;
void configWithStore;
void store;
void memoryStore;
void storageStore;
void saved;
void loaded;
void loadedById;
void listed;
void cleared;
void pollOptions;
void polledExchange;
void polledGraph;
void standalonePollExchange;
void standalonePollGraph;
void serializedContext;
void deserializedContext;
void pollErr;
void pollAborted;
void pollCode;
void transcript;
void tag;
void build;
void parse;
void verify;
void cryptoTranscript;
void cryptoAlias;
void rsaBlindResult;
void rsaUnblindResult;
void rsaVerifyResult;
void constructor;
void publicFacade;
void cacheTtl;
void err;
void invalidToken;
void replayed;
void rateLimited;
void retryAfter;
void code;
void exchangeErr;
void graphErr;
void outcome;
void graphOutcome;
void batchErr;
void batchErrCode;
void batchErrFailed;
void batchErrTokens;
void batchErrResults;
void batchIssueReq;
void batchIssueResp;
void tokenResult;
void publicBatchIssueReq;
void publicBatchIssueResp;
void verifyReq;
void tokenToVerify;
void batchVerifyReq;
void verifyResult;
void verifyResp;

// Phase 6: PoW Sybil helpers + config/metadata surface.
const configWithPow: ClientConfig = {
  issuerUrl: 'https://issuer.example',
  powDifficulty: 16,
};
const powDifficulty: number | undefined = configWithPow.powDifficulty;
const sybilSummary: SybilConfigSummary = {
  mode: 'pow',
  mode_description: 'Proof of Work',
  settings: { difficulty: 16 },
};
const sybilSettings: SybilModeSettings = sybilSummary.settings;
const trustLevel: TrustLevelSummary = {
  min_age: '1d',
  min_age_secs: 86400,
  max_tokens: 1,
  cooldown: '1h',
  cooldown_secs: 3600,
};
const issuerMetadata: import('../src/index.js').IssuerMetadata = {
  issuer_id: 'issuer:test',
  voprf: { suite: 'P256-SHA256', kid: 'kid', pubkey: 'pub' },
  sybil: sybilSummary,
};
const mined: Promise<SybilProof> = generateProofOfWork('freebird:issue:v1:issuer:test:BAU', 16);
const minedWithOpts: Promise<SybilProof> = generateProofOfWork(
  'freebird:issue:v1:issuer:test:BAU',
  16,
  { timestamp: 1700000000, yieldEvery: 100 },
);
const powValid: boolean = verifyPow('input', 1, 1700000000, 16);
const issueBinding: string = buildIssueBinding('issuer:test', 'BAU');
const publicIssueBinding: string = buildPublicIssueBinding('issuer:test', 'BAU');
const renewBinding: string = buildRenewBinding('issuer:test', 'BAU');
const batchBinding: string = buildBatchBinding('issue-batch', 'issuer:test', ['BAU']);
void configWithPow;
void powDifficulty;
void sybilSummary;
void sybilSettings;
void trustLevel;
void issuerMetadata;
void mined;
void minedWithOpts;
void powValid;
void issueBinding;
void publicIssueBinding;
void renewBinding;
void batchBinding;
