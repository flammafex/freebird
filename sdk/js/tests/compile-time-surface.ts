// SPDX-License-Identifier: Apache-2.0 OR MIT

import { FreebirdClient, FreebirdError, crypto } from '../src/index.js';
import type {
  BatchVerifyResp,
  ClientConfig,
  FreebirdToken,
  IssuerMetadata,
  IssueTokensOptions,
  SybilProof,
  SybilProofFactory,
  VerifyResp,
} from '../src/index.js';
import type { KeyDiscoveryMetadata } from '../src/types.js';

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends
  (<Value>() => Value extends Right ? 1 : 2) ? true : false;
type Assert<Value extends true> = Value;

type ExpectedClientKeys =
  | 'init'
  | 'issueToken'
  | 'issueTokenWithProofFactory'
  | 'issueTokens'
  | 'verifyToken'
  | 'verifyTokenValid'
  | 'checkToken'
  | 'verifyBatch'
  | 'tokenStore';

type _clientKeys = Assert<Equal<Exclude<keyof FreebirdClient, 'state'>, ExpectedClientKeys>>;
type _tokenVersion = Assert<Equal<NonNullable<FreebirdToken['version']>, 4>>;
type _issuerHasNoV5Public = Assert<Equal<Extract<keyof IssuerMetadata, 'public'>, never>>;
type _keyDiscoveryHasNoV5Public = Assert<Equal<Extract<keyof KeyDiscoveryMetadata, 'public'>, never>>;

const config: ClientConfig = { issuerUrl: 'https://issuer.example' };
const client = new FreebirdClient(config);
const proof: SybilProof | undefined = undefined;
const factory: SybilProofFactory = async ({ binding }) => ({
  type: 'proof_of_work', nonce: 0, input: binding, timestamp: 0,
});
const v4: Promise<FreebirdToken> = client.issueToken(proof);
const v4Factory: Promise<FreebirdToken> = client.issueTokenWithProofFactory(factory);
const v4Batch: Promise<FreebirdToken[]> = client.issueTokens([], {} satisfies IssueTokensOptions);
const verified: Promise<VerifyResp> = client.verifyToken({ tokenValue: 'BAU', issuerId: 'issuer' });
const checked: Promise<VerifyResp> = client.checkToken({ tokenValue: 'BAU', issuerId: 'issuer' });
const batchVerified: Promise<BatchVerifyResp> = client.verifyBatch([{ tokenValue: 'BAU', issuerId: 'issuer' }]);
const publicError = new FreebirdError('issuance', 'request failed');
// @ts-expect-error retired exchange error codes are not public
const retiredError = new FreebirdError('exchange', 'retired');

void v4;
void v4Factory;
void v4Batch;
void verified;
void checked;
void batchVerified;
void publicError;
void retiredError;

// V5/V2 package surface intentionally does not compile.
// @ts-expect-error V5 public bearer API removed
import { PublicBearerPass } from '../src/index.js';
// @ts-expect-error V5 token-key helper removed from the public crypto namespace
const retiredKeyHelper = crypto.tokenKeyIdFromSpki;
// @ts-expect-error V5 public bearer API removed
import { buildPublicIssueBinding } from '../src/index.js';
// @ts-expect-error V2 exchange facade removed
import { exchangePasses } from '../src/index.js';
// @ts-expect-error V2 graph/polling facade removed
import { pollGraphIssuanceStatus } from '../src/index.js';
// @ts-expect-error V5 token versions are retired
const retired: FreebirdToken = { tokenValue: 'BQ', issuerId: 'issuer', version: 5 };
// @ts-expect-error retired public issuance DTOs are removed from the source surface
import type { PublicIssueRequest } from '../src/types.js';
// @ts-expect-error retired public batch issuance DTOs are removed from the source surface
import type { PublicBatchIssueReq } from '../src/types.js';
void PublicBearerPass;
void buildPublicIssueBinding;
void exchangePasses;
void pollGraphIssuanceStatus;
void retired;
void retiredKeyHelper;
