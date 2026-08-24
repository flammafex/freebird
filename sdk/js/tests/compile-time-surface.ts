// SPDX-License-Identifier: Apache-2.0 OR MIT

import { FreebirdClient, FreebirdError, crypto, buildNativeBearerV7IssueBinding } from '../src/index.js';
import type {
  BatchVerifyResp,
  ClientConfig,
  FreebirdToken,
  IssuerMetadata,
  IssueTokensOptions,
  NativeBearerV7BatchIssueOptions,
  NativeBearerV7IssueOptions,
  SybilProof,
  SybilProofFactory,
  V7DirectBinding,
  V7DirectKeyDiscovery,
  V7DirectRegistry,
  V7DirectRegistryEntry,
  V7Token,
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
  | 'getV7KeyDiscoveryMetadata'
  | 'refreshV7KeyDiscoveryMetadata'
  | 'issueNativeBearerV7'
  | 'issueNativeBearerV7Batch'
  | 'verifyNativeBearerV7Locally'
  | 'verifyToken'
  | 'verifyTokenValid'
  | 'checkToken'
  | 'verifyBatch'
  | 'tokenStore';

type _clientKeys = Assert<Equal<Exclude<keyof FreebirdClient, 'state'>, ExpectedClientKeys>>;
type _tokenVersion = Assert<Equal<NonNullable<FreebirdToken['version']>, 4 | 7>>;
type _issuerHasNoV5Public = Assert<Equal<Extract<keyof IssuerMetadata, 'public'>, never>>;
type _keyDiscoveryHasNoV5Public = Assert<Equal<Extract<keyof KeyDiscoveryMetadata, 'public'>, never>>;
type _directDiscoveryHasNoNonDirectFields = Assert<Equal<Exclude<keyof V7DirectKeyDiscovery,
  'issuer_id' | 'current_epoch' | 'valid_epochs' | 'epoch_duration_sec' | 'voprf' |
  'native_bearer_v7' | 'native_bearer_v7_retained'>, never>>;
type _directRegistryHasNoRoleReferences = Assert<Equal<Exclude<keyof V7DirectRegistryEntry,
  'identity' | 'token_key_id' | 'descriptor_id' | 'spki_fingerprint' | 'pubkey_spki_b64' |
  '__freebirdV7KeyBinding' | 'profile_id' | 'issuer_id' | 'asset_id' | 'amount_minor' |
  'suite' | 'modulus_bits' | 'exponent' | 'valid_from' | 'valid_until'>, never>>;

const config: ClientConfig = { issuerUrl: 'https://issuer.example' };
const client = new FreebirdClient(config);
const proof: SybilProof | undefined = undefined;
const factory: SybilProofFactory = async ({ binding }) => ({
  type: 'proof_of_work', nonce: 0, input: binding, timestamp: 0,
});
const v4: Promise<FreebirdToken> = client.issueToken(proof);
const v4Factory: Promise<FreebirdToken> = client.issueTokenWithProofFactory(factory);
const v4Batch: Promise<FreebirdToken[]> = client.issueTokens([], {} satisfies IssueTokensOptions);
const discovery: Promise<V7DirectKeyDiscovery> = client.getV7KeyDiscoveryMetadata();
const refreshed: Promise<V7DirectKeyDiscovery> = client.refreshV7KeyDiscoveryMetadata();
const v7Options: NativeBearerV7IssueOptions = { owner_commitment: new Uint8Array(32) };
const v7BatchOptions: NativeBearerV7BatchIssueOptions = { owner_commitments: [new Uint8Array(32)] };
const v7: Promise<FreebirdToken> = client.issueNativeBearerV7(v7Options);
const v7Batch: Promise<FreebirdToken[]> = client.issueNativeBearerV7Batch(v7BatchOptions);
const binding = {} as V7DirectBinding;
const v7Token = {} as V7Token;
const localParsed: Promise<boolean> = client.verifyNativeBearerV7Locally(v7Token, binding);
const localBytes: Promise<boolean> = client.verifyNativeBearerV7Locally(new Uint8Array([7]), binding);
const verified: Promise<VerifyResp> = client.verifyToken({ tokenValue: 'BAU', issuerId: 'issuer' });
const checked: Promise<VerifyResp> = client.checkToken({ tokenValue: 'BAU', issuerId: 'issuer' });
const batchVerified: Promise<BatchVerifyResp> = client.verifyBatch([{ tokenValue: 'BAU', issuerId: 'issuer' }]);
const v7BindingText: string = buildNativeBearerV7IssueBinding('issuer', 'a'.repeat(64), 'AQ');
const v7Verifier: Promise<boolean> = crypto.nativeBearerV7.verifyV7Token(binding, v7Token);
const publicError = new FreebirdError('issuance', 'request failed');
// @ts-expect-error retired exchange error codes are not public
const retiredError = new FreebirdError('exchange', 'retired');

void v4;
void v4Factory;
void v4Batch;
void discovery;
void refreshed;
void v7;
void v7Batch;
void localParsed;
void localBytes;
void verified;
void checked;
void batchVerified;
void v7BindingText;
void v7Verifier;
void publicError;
void retiredError;
const directRegistry: V7DirectRegistry | undefined = undefined;
const directRegistryEntry: V7DirectRegistryEntry | undefined = undefined;
void directRegistry;
void directRegistryEntry;

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
