# @flammafex/freebird

The Freebird SDK provides the active V4 private-token and direct V7 native-bearer
client flows. It ships ESM and CommonJS builds with TypeScript declarations and
uses the platform `fetch` implementation.

The SDK requires **Node.js 24 or newer**. This requirement comes from the
approved `@cloudflare/blindrsa-ts@0.4.6` dependency used by the direct V7 flow.

## Install

```bash
npm install @flammafex/freebird
```

## V4 quick start

```ts
import { FreebirdClient } from '@flammafex/freebird';

const client = new FreebirdClient({
  issuerUrl: 'https://issuer.example.com',
  verifierUrl: 'https://verifier.example.com',
});

await client.init();
const token = await client.issueToken();
const result = await client.verifyToken(token);
```

`issueToken` accepts an optional request-bound `SybilProof`. Use
`issueTokenWithProofFactory` when a fresh proof must be created after retry.
`checkToken` validates without consuming; `verifyToken` consumes the token.
`issueTokens` and `verifyBatch` provide bounded V4 batch operations.

## Direct V7 native bearer

```ts
const v7 = await client.issueNativeBearerV7({
  owner_commitment: globalThis.crypto.getRandomValues(new Uint8Array(32)),
});

const v7Batch = await client.issueNativeBearerV7Batch({
  owner_commitments: [globalThis.crypto.getRandomValues(new Uint8Array(32))],
});

const locallyValid = await client.verifyNativeBearerV7Locally(v7.tokenValue);
```

Direct V7 issuance uses the validated `/.well-known/keys` direct-bearer record
and these routes:

- `POST /v7/native-bearer/issue`
- `POST /v7/native-bearer/issue/batch`

The owner commitment must be exactly 32 bytes. The SDK constructs the canonical
body, blinds it, binds Sybil proofs to the exact request, finalizes the returned
blind signature, and stores the token when a `tokenStore` is configured.

`getV7KeyDiscoveryMetadata()` and `refreshV7KeyDiscoveryMetadata()` return only
direct-bearer discovery DTOs. Internal validation may process additional issuer
metadata, but those structures are not part of the public SDK declarations.

For local verification, pass either a serialized token value, serialized bytes,
or a parsed `V7Token`. The SDK can select an active or retained direct key from
validated discovery, or you can provide a `V7DirectBinding` explicitly.

## Remote verification

`verifyToken`, `verifyTokenValid`, `checkToken`, and `verifyBatch` support V4 and
V7 token envelopes. Retired, reserved, malformed, and unknown envelope versions
are rejected before any verifier request is made.

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `issuerUrl` | yes | Issuer base URL. |
| `verifierUrl` | no | Verifier base URL for remote checks. |
| `verifierId` / `audience` | no | V4 scope overrides when verifier discovery is unavailable. |
| `keyCacheTtlMs` | no | Direct V7 discovery cache lifetime. |
| `tokenStore` | no | `MemoryTokenStore` or `StorageTokenStore` for issued tokens. |
| `powDifficulty` | no | Optional client PoW difficulty when required by the issuer. |
| `batchBodyLimitBytes` | no | V4 batch JSON limit, up to 60 KiB. |
| `fetch` | no | Custom fetch implementation for browser, proxy, or test use. |

## Sybil proofs

Proofs are bound to the exact issuance request. Direct V7 single-issue bindings
include the issuer ID, token key ID, and blinded message. Batch bindings include
the issuer ID, token key ID, ordered item count, and ordered-message digest.
Never reuse a proof after changing request data.

## Errors

SDK errors are typed `FreebirdError` subclasses with stable public codes. Branch
on `error.code`, not message text. Common codes include `discovery`,
`verification`, `invalid_token`, `replayed_token`, `issuance`,
`rate_limited`, `verifier_unavailable`, and `verifier_not_configured`.

## Token storage

`MemoryTokenStore` is process-local. `StorageTokenStore` persists token records
with restrictive permissions in Node.js and uses local storage in browsers.
Keep blinding state and other secrets out of logs and analytics.

## Low-level crypto

The `crypto` namespace exposes V4 VOPRF helpers and the direct V7 native-bearer
helpers under `crypto.nativeBearerV7`. These are lower-level primitives; callers
must protect opaque blinding state and validate discovery before using key-bound
operations.

## Live service acceptance

The live acceptance test runs V4 and direct V7 issue/check/verify/replay flows
against explicitly configured services:

```bash
FREEBIRD_SDK_ISSUER_URL=http://127.0.0.1:8081 \
FREEBIRD_SDK_VERIFIER_URL=http://127.0.0.1:8082 \
npm test -- --run tests/live-service.test.ts
```

When either URL is absent, the live test is skipped.

## License

MIT OR Apache-2.0
