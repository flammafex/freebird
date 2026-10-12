import sdk = require('@flammafex/freebird');
import type {
  BatchVerifyResp,
  ClientConfig,
  FreebirdToken,
  TokenStore,
  VerifyResp,
} from '@flammafex/freebird';

const config: ClientConfig = {
  issuerUrl: 'https://issuer.example', verifierUrl: 'https://verifier.example', tokenStore: new sdk.MemoryTokenStore(),
};
const client = new sdk.FreebirdClient(config);
const token: FreebirdToken = { tokenValue: 'BAU', issuerId: 'issuer:test', version: 4 };
const v4: Promise<FreebirdToken> = client.issueToken();
const v4Factory: Promise<FreebirdToken> = client.issueTokenWithProofFactory(
  ({ binding }) => ({ type: 'proof_of_work', input: binding, nonce: 0, timestamp: 0 }),
);
const v4Batch: Promise<FreebirdToken[]> = client.issueTokens([new Uint8Array(32)]);
const verified: Promise<VerifyResp> = client.verifyToken(token);
const verifiedValid: Promise<boolean> = client.verifyTokenValid(token);
const checked: Promise<VerifyResp> = client.checkToken(token);
const batchVerified: Promise<BatchVerifyResp> = client.verifyBatch([token]);
const store: TokenStore | undefined = client.tokenStore;
void client; void v4; void v4Factory; void v4Batch; void verified;
void verifiedValid; void checked; void batchVerified; void store;
