import sdk = require('@freebird/sdk');
import type {
  BatchVerifyResp,
  ClientConfig,
  ExchangeRequest,
  FreebirdErrorCode,
  FreebirdToken,
  PublicBearerPass,
  RsaBlindState,
  TokenStore,
  VerifyResp,
} from '@freebird/sdk';

const config: ClientConfig = {
  issuerUrl: 'https://issuer.example',
  verifierUrl: 'https://verifier.example',
  tokenStore: new sdk.MemoryTokenStore(),
};
const client = new sdk.FreebirdClient(config);
const token: FreebirdToken = {
  tokenValue: 'token',
  issuerId: 'issuer:test',
  version: 5,
  tokenKeyId: 'a'.repeat(64),
};

// The complete high-level surface must resolve types for a CJS consumer.
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
const currentV5: Promise<PublicBearerPass> = client.issuePublicTokenForCurrentKey();
const currentV5Batch: Promise<PublicBearerPass[]> = client.issuePublicTokensForCurrentKey([
  new Uint8Array(32),
]);
const verified: Promise<VerifyResp> = client.verifyToken(token);
const verifiedValid: Promise<boolean> = client.verifyTokenValid(token);
const checked: Promise<VerifyResp> = client.checkToken(token);
const batchVerified: Promise<BatchVerifyResp> = client.verifyBatch([token]);
const opId: string = client.generateOperationId();
const capability: string = client.generateStatusCapability();
const exchangeRequest: Promise<ExchangeRequest> = client.exchangePasses(
  [],
  { graphId: 'a'.repeat(64), transitionId: 'b'.repeat(64) },
);
const store: TokenStore | undefined = client.tokenStore;
const rsaBlind: Promise<{ blinded: Uint8Array; state: RsaBlindState }> =
  sdk.crypto.rsaBlind(new Uint8Array(), new Uint8Array());
const code: FreebirdErrorCode = 'replayed_token';

void client;
void token;
void v4;
void v4Factory;
void v4Batch;
void v5;
void currentV5;
void currentV5Batch;
void verified;
void verifiedValid;
void checked;
void batchVerified;
void opId;
void capability;
void exchangeRequest;
void store;
void rsaBlind;
void code;
void sdk.crypto.buildScopeDigest('verifier:test', 'audience:test');
