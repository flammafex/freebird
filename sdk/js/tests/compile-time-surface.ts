// SPDX-License-Identifier: Apache-2.0 OR MIT

import {
  FreebirdClient,
  buildGraphIssuanceHmacAuthorizationV2,
  buildHmacAuthorizationV2,
  crypto,
  graphIssuanceHmacAuthorizationTagV2,
  graphIssuanceHmacAuthorizationTranscriptV2,
  hmacAuthorizationTagV2,
  hmacAuthorizationTranscriptV2,
  parseGraphIssuanceHmacAuthorizationV2,
  parseHmacAuthorizationV2,
  verifyGraphIssuanceHmacAuthorizationV2,
  verifyHmacAuthorizationV2,
} from '../src/index.js';
import type {
  ClientConfig,
  ExchangeOutcome,
  ExchangeRequest,
  FreebirdToken,
  GraphIssuancePolicyInfo,
  GraphIssuanceOutcome,
  GraphIssuanceRecoveryContext,
  GraphIssuanceRequest,
  KeyDiscoveryMetadata,
  PublicIssueResponse,
  SybilProof,
} from '../src/index.js';
import type { ExchangeTransitionSelection } from '../src/types.js';

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends
  (<Value>() => Value extends Right ? 1 : 2) ? true : false;
type Assert<Value extends true> = Value;
type PublicClientKeys =
  | 'init'
  | 'issueToken'
  | 'getKeyDiscoveryMetadata'
  | 'issuePublicBlindSignature'
  | 'selectExchangeTransition'
  | 'exchange'
  | 'getExchangeStatus'
  | 'exchangeRequestDigest'
  | 'selectGraphIssuancePolicy'
  | 'issueGraphBlindSignature'
  | 'retryGraphBlindSignature'
  | 'retryGraphIssuance'
  | 'createGraphIssuanceRecoveryContext'
  | 'getGraphIssuanceStatus'
  | 'graphIssuanceRequestDigest'
  | 'graphIssuanceAuthorizationBindingDigest'
  | 'verifyToken';

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
  getKeyDiscoveryMetadata: () => Promise<KeyDiscoveryMetadata>;
  issuePublicBlindSignature: (
    blindedMsg: Uint8Array | string,
    sybilProof?: SybilProof,
    tokenKeyId?: string,
  ) => Promise<PublicIssueResponse>;
  selectExchangeTransition: (
    graphId: string,
    transitionId: string,
  ) => Promise<ExchangeTransitionSelection>;
  exchange: (request: ExchangeRequest, statusCapability: string) => Promise<ExchangeOutcome>;
  getExchangeStatus: ExpectedExchangeStatus;
  exchangeRequestDigest: (request: ExchangeRequest) => string;
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
  graphIssuanceRequestDigest: (request: GraphIssuanceRequest) => string;
  graphIssuanceAuthorizationBindingDigest: (request: GraphIssuanceRequest) => string;
  verifyToken: (token: FreebirdToken) => Promise<boolean>;
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
const client = new FreebirdClient(config);
const constructor: new (config: ClientConfig) => FreebirdClient = FreebirdClient;
const publicFacade: Pick<FreebirdClient, PublicClientKeys> = client;

declare const exchangeRequest: ExchangeRequest;
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
const discovery: Promise<KeyDiscoveryMetadata> = client.getKeyDiscoveryMetadata();
const v5Bytes: Promise<PublicIssueResponse> = client.issuePublicBlindSignature(new Uint8Array());
const v5String: Promise<PublicIssueResponse> = client.issuePublicBlindSignature('blinded-message');
const transitionSelection = client.selectExchangeTransition('a'.repeat(64), 'b'.repeat(64));
const exchange: Promise<ExchangeOutcome> = client.exchange(exchangeRequest, capability);
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
const graphDigest: string = client.graphIssuanceRequestDigest(graphRequest);
const graphBindingDigest: string = client.graphIssuanceAuthorizationBindingDigest(graphRequest);
const verified: Promise<boolean> = client.verifyToken({ tokenValue: 'token', issuerId: 'issuer' });

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

void v4;
void v4WithProof;
void initialized;
void discovery;
void v5Bytes;
void v5String;
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
void graphDigest;
void graphBindingDigest;
void verified;
void transcript;
void tag;
void build;
void parse;
void verify;
void cryptoTranscript;
void cryptoAlias;
void constructor;
void publicFacade;
