import { FreebirdClient, crypto } from '@freebird/sdk';
import type { ClientConfig, FreebirdToken } from '@freebird/sdk';

const config: ClientConfig = {
  issuerUrl: 'https://issuer.example',
  verifierId: 'verifier:test',
  audience: 'audience:test',
};
const client = new FreebirdClient(config);
const token: FreebirdToken = {
  tokenValue: 'token',
  issuerId: 'issuer:test',
  version: 4,
};

void client;
void token;
void crypto.buildScopeDigest('verifier:test', 'audience:test');
