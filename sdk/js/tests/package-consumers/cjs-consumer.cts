import sdk = require('@freebird/sdk');
import type { ClientConfig, FreebirdToken } from '@freebird/sdk';

const config: ClientConfig = {
  issuerUrl: 'https://issuer.example',
  verifierUrl: 'https://verifier.example',
};
const client = new sdk.FreebirdClient(config);
const token: FreebirdToken = {
  tokenValue: 'token',
  issuerId: 'issuer:test',
  version: 5,
  tokenKeyId: 'a'.repeat(64),
};

void client;
void token;
void sdk.crypto.buildScopeDigest('verifier:test', 'audience:test');
