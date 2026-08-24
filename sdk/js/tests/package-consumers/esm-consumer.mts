import { FreebirdClient, MemoryTokenStore, StorageTokenStore, crypto } from '@flammafex/freebird';
import type {
  BatchVerifyResp,
  ClientConfig,
  FreebirdToken,
  NativeBearerV7BatchIssueOptions,
  NativeBearerV7IssueOptions,
  TokenStore,
  V7DirectBinding,
  V7Token,
  VerifyResp,
} from '@flammafex/freebird';

const config: ClientConfig = {
  issuerUrl: 'https://issuer.example', verifierUrl: 'https://verifier.example', tokenStore: new MemoryTokenStore(),
};
const client = new FreebirdClient(config);
const token: FreebirdToken = { tokenValue: 'BAU', issuerId: 'issuer:test', version: 4 };
const v7Options: NativeBearerV7IssueOptions = { owner_commitment: new Uint8Array(32) };
const v7BatchOptions: NativeBearerV7BatchIssueOptions = { owner_commitments: [new Uint8Array(32)] };

const v4: Promise<FreebirdToken> = client.issueToken();
const v4Factory: Promise<FreebirdToken> = client.issueTokenWithProofFactory(
  ({ binding }) => ({ type: 'proof_of_work', input: binding, nonce: 0, timestamp: 0 }),
);
const v4Batch: Promise<FreebirdToken[]> = client.issueTokens([new Uint8Array(32)]);
const v7: Promise<FreebirdToken> = client.issueNativeBearerV7(v7Options);
const v7Batch: Promise<FreebirdToken[]> = client.issueNativeBearerV7Batch(v7BatchOptions);
const verified: Promise<VerifyResp> = client.verifyToken(token);
const verifiedValid: Promise<boolean> = client.verifyTokenValid(token);
const checked: Promise<VerifyResp> = client.checkToken(token);
const batchVerified: Promise<BatchVerifyResp> = client.verifyBatch([token]);
const local: Promise<boolean> = client.verifyNativeBearerV7Locally({} as V7Token, {} as V7DirectBinding);
const store: TokenStore | undefined = client.tokenStore;
const storageStore: TokenStore = new StorageTokenStore({ key: 'freebird-tokens' });
const v7Verify: Promise<boolean> = crypto.nativeBearerV7.verifyV7Token({} as V7DirectBinding, {} as V7Token);
void client; void v4; void v4Factory; void v4Batch; void v7; void v7Batch; void verified;
void verifiedValid; void checked; void batchVerified; void local; void store; void storageStore; void v7Verify;
