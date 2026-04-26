# Freebird SDK

The TypeScript SDK supports the V4 private option directly and exposes V5 public-option helpers for applications that provide an RFC 9474 RSA blind-signature implementation.

---

## Install

```bash
npm install @freebird/sdk
```

Requirements:

- Node.js 18+ or a modern browser;
- global `fetch`;
- Web Crypto `crypto.getRandomValues()`.

## V4 Private Option

V4 is the default high-privacy flow exposed by `issueToken()`.

```typescript
import { FreebirdClient } from '@freebird/sdk';

const client = new FreebirdClient({
  issuerUrl: 'https://issuer.example.com',
  verifierUrl: 'https://verifier.example.com'
});

await client.init();

const token = await client.issueToken();
console.log(token.version);    // 4
console.log(token.tokenValue); // base64url V4 redemption token

const ok = await client.verifyToken(token);
```

`init()` fetches:

- issuer metadata from `/.well-known/issuer`;
- verifier scope metadata from `/.well-known/verifier`.

`issueToken()`:

1. generates a nonce;
2. builds the V4 verifier-bound token input;
3. blinds the input with the P-256 VOPRF client;
4. sends `POST /v1/oprf/issue`;
5. verifies the DLEQ proof;
6. unblinds the authenticator;
7. returns a base64url V4 redemption token.

## V5 Public Option

The SDK includes V5 message and token codecs plus an issuer request helper. It does not implement RSA blinding itself.

Use an RFC 9474 `RSABSSA-SHA384-PSS-Deterministic` implementation to blind and finalize the V5 message.

```typescript
import { FreebirdClient, crypto as freebirdCrypto } from '@freebird/sdk';

const client = new FreebirdClient({
  issuerUrl: 'https://issuer.example.com',
  verifierUrl: 'https://verifier.example.com'
});

const keys = await client.getKeyDiscoveryMetadata();
const publicKey = keys.public.find((key) =>
  key.token_type === 'public_bearer_pass' &&
  key.rfc9474_variant === 'RSABSSA-SHA384-PSS-Deterministic' &&
  key.spend_policy === 'single_use'
);

if (!publicKey) throw new Error('No public bearer key available');

const nonce = globalThis.crypto.getRandomValues(new Uint8Array(32));
const tokenKeyId = freebirdCrypto.tokenKeyIdFromHex(publicKey.token_key_id);
const message = freebirdCrypto.buildPublicBearerMessage(
  nonce,
  tokenKeyId,
  publicKey.issuer_id
);

// Use an RFC 9474 library here:
// const { blindedMsg, blindState } = rsaBlind(publicKey.pubkey_spki_b64, message);

const issueResp = await client.issuePublicBlindSignature(
  blindedMsg,
  undefined,
  publicKey.token_key_id
);

// const signature = rsaFinalize(issueResp.blind_signature_b64, blindState, message);
const tokenBytes = freebirdCrypto.buildPublicBearerPass(
  nonce,
  tokenKeyId,
  issueResp.issuer_id,
  signature
);
```

The resulting base64url token can be sent to the same verifier endpoint:

```typescript
const tokenValue = bytesToBase64Url(tokenBytes);
await fetch('https://verifier.example.com/v1/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token_b64: tokenValue })
});

function bytesToBase64Url(bytes: Uint8Array): string {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

## Client API

### `new FreebirdClient(config)`

| Field | Required | Description |
|-------|----------|-------------|
| `issuerUrl` | yes | Base issuer URL, without trailing endpoint path. |
| `verifierUrl` | for V4 convenience | Base verifier URL used to fetch V4 scope and verify tokens. |
| `verifierId` | alternative | Verifier scope ID when `verifierUrl` is not available. |
| `audience` | alternative | Verifier audience when `verifierUrl` is not available. |

### `init(): Promise<void>`

Initializes issuer metadata and V4 verifier metadata.

### `issueToken(proof?: SybilProof): Promise<FreebirdToken>`

Issues a V4 private-verification token.

### `getKeyDiscoveryMetadata(): Promise<KeyDiscoveryMetadata>`

Fetches issuer key metadata from `/.well-known/keys`, including V5 public bearer keys.

### `issuePublicBlindSignature(blindedMsg, proof?, tokenKeyId?): Promise<PublicIssueResponse>`

Calls `POST /v1/public/issue` for a V5 blind signature.

`blindedMsg` can be a `Uint8Array` or an already base64url-encoded string.

### `verifyToken(token): Promise<boolean>`

Calls `/v1/verify` with `token.tokenValue`. The verifier handles V4 and V5 dispatch by token version.

## Low-Level Crypto Helpers

```typescript
import { crypto } from '@freebird/sdk';
```

V4:

- `crypto.blind(input, context)`
- `crypto.finalize(state, evaluationB64, issuerPubkeyB64, context)`
- `crypto.buildScopeDigest(verifierId, audience)`
- `crypto.buildPrivateTokenInput(issuerId, kid, nonce, scopeDigest)`
- `crypto.buildRedemptionToken(nonce, scopeDigest, kid, issuerId, authenticator)`
- `crypto.parseRedemptionToken(bytes)`

V5:

- `crypto.tokenKeyIdFromSpki(pubkeySpki)`
- `crypto.tokenKeyIdToHex(tokenKeyId)`
- `crypto.tokenKeyIdFromHex(tokenKeyIdHex)`
- `crypto.buildPublicBearerMessage(nonce, tokenKeyId, issuerId)`
- `crypto.buildPublicBearerPass(nonce, tokenKeyId, issuerId, signature)`
- `crypto.parsePublicBearerPass(bytes)`

## Types

```typescript
interface FreebirdToken {
  tokenValue: string;
  issuerId: string;
  version?: 4 | 5;
  kid?: string;
  tokenKeyId?: string;
}
```

V4 tokens include `kid`. V5 tokens include `tokenKeyId`.

`SybilProof` supports:

- `proof_of_work`
- `rate_limit`
- `invitation`
- `registered_user`
- `webauthn`
- `progressive_trust`
- `proof_of_diversity`
- `multi_party_vouching`
- `multi`
- `none`

## Error Handling

SDK methods throw `Error` with human-readable messages for:

- issuer metadata fetch failure;
- verifier metadata fetch failure;
- missing V4 verifier scope;
- issuer rejection of Sybil proof;
- DLEQ verification failure;
- public bearer key metadata absence;
- verifier rejection or replay.

Tokens are bearer credentials. Use HTTPS and store tokens as sensitive data.
