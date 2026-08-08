import {
  FreebirdClient,
  MemoryTokenStore,
  StorageTokenStore,
  crypto,
  exchangePasses,
  finalizeExchangePasses,
  generateOperationId,
  generateStatusCapability,
  prepareExchangePasses,
  pollExchangeStatus,
  pollGraphIssuanceStatus,
} from '@freebird/sdk';
import type {
  BatchVerifyResp,
  ClientConfig,
  ExchangeOutcome,
  ExchangeRequest,
  FreebirdErrorCode,
  FreebirdToken,
  GraphIssuanceOutcome,
  GraphIssuanceRecoveryContext,
  PublicBearerPass,
  RsaBlindState,
  TokenStore,
  VerifyResp,
} from '@freebird/sdk';

const config: ClientConfig = {
  issuerUrl: 'https://issuer.example',
  verifierUrl: 'https://verifier.example',
  tokenStore: new MemoryTokenStore(),
};
const client = new FreebirdClient(config);
const token: FreebirdToken = {
  tokenValue: 'token',
  issuerId: 'issuer:test',
  version: 4,
};

// The complete high-level surface must resolve types for a consumer.
const v4: Promise<FreebirdToken> = client.issueToken();
const v4Factory: Promise<FreebirdToken> = client.issueTokenWithProofFactory(
  ({ binding }) => ({ type: 'proof_of_work', input: binding, nonce: 0, timestamp: 0 }),
);
const v4Batch: Promise<FreebirdToken[]> = client.issueTokens([new Uint8Array(32)]);
const v5: Promise<PublicBearerPass> = client.issuePublicToken(new Uint8Array(48), {
  nonce: new Uint8Array(32),
  tokenKeyId: 'a'.repeat(64),
  issuerId: 'issuer:test',
});
const v5Batch: Promise<PublicBearerPass[]> = client.issuePublicTokens(
  [new Uint8Array(48)],
  { issuerId: 'issuer:test', nonces: [new Uint8Array(32)] },
);
const currentV5: Promise<PublicBearerPass> = client.issuePublicTokenForCurrentKey();
const currentV5Batch: Promise<PublicBearerPass[]> = client.issuePublicTokensForCurrentKey([
  new Uint8Array(32),
]);
const verified: Promise<VerifyResp> = client.verifyToken(token);
const verifiedValid: Promise<boolean> = client.verifyTokenValid(token);
const checked: Promise<VerifyResp> = client.checkToken(token);
const batchVerified: Promise<BatchVerifyResp> = client.verifyBatch([token]);
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
const refreshed: Promise<import('@freebird/sdk').KeyDiscoveryMetadata> =
  client.refreshKeyDiscoveryMetadata();
const opId: string = client.generateOperationId();
const capability: string = client.generateStatusCapability();
const exchangeRequest: Promise<ExchangeRequest> = client.exchangePasses(
  [],
  { graphId: 'a'.repeat(64), transitionId: 'b'.repeat(64) },
);
const store: TokenStore | undefined = client.tokenStore;
const storageStore: TokenStore = new StorageTokenStore({ key: 'freebird-tokens' });
const rsaBlind: Promise<{ blinded: Uint8Array; state: RsaBlindState }> =
  crypto.rsaBlind(new Uint8Array(), new Uint8Array());
const rsaUnblind: Promise<Uint8Array> = crypto.rsaUnblind(
  { inv: new Uint8Array(), prepared: new Uint8Array(), publicKey: new Uint8Array() },
  new Uint8Array(),
);
const rsaVerify: Promise<boolean> = crypto.rsaVerify(
  new Uint8Array(),
  new Uint8Array(),
  new Uint8Array(),
);
const code: FreebirdErrorCode = 'invalid_token';

void client;
void token;
void v4;
void v4Factory;
void v4Batch;
void v5;
void v5Batch;
void currentV5;
void currentV5Batch;
void prepareExchangePasses;
void finalizeExchangePasses;
void verified;
void verifiedValid;
void checked;
void batchVerified;
void locallyVerified;
void refreshed;
void opId;
void capability;
void exchangeRequest;
void store;
void storageStore;
void rsaBlind;
void rsaUnblind;
void rsaVerify;
void code;
void crypto.buildScopeDigest('verifier:test', 'audience:test');
void exchangePasses;
void generateOperationId;
void generateStatusCapability;
void pollExchangeStatus;
void pollGraphIssuanceStatus;
void (null as unknown as ExchangeOutcome);
void (null as unknown as GraphIssuanceOutcome);
void (null as unknown as GraphIssuanceRecoveryContext);
