# TypeScript SDK

The package is `@flammafex/freebird`:

```bash
npm install @flammafex/freebird
```

The SDK requires **Node.js 24 or newer**. It provides ESM and CommonJS builds,
TypeScript declarations, and uses the platform `fetch` implementation.

## Supported client flows

The SDK supports the active **V4 private-token** flow and **direct V7
native-bearer** flow. V4 uses `issueToken`, `checkToken`, and `verifyToken`;
V4 also has bounded `issueTokens` and `verifyBatch` operations. Direct V7 uses
`issueNativeBearerV7`, `issueNativeBearerV7Batch`, and local verification helpers
after validating `/.well-known/keys` discovery.

```ts
import { FreebirdClient } from '@flammafex/freebird';

const client = new FreebirdClient({
  issuerUrl: 'https://issuer.example.com',
  verifierUrl: 'https://verifier.example.com',
});

await client.init();
const token = await client.issueToken();
const checked = await client.checkToken(token); // does not consume
const verified = await client.verifyToken(token); // consumes once
```

Direct V7 issuance requires a 32-byte owner commitment and validated key
discovery. The SDK binds Sybil proofs to the exact request. Create a fresh proof
when request data changes or a retry requires a new request; do not reuse a
proof across different bodies.

## Configuration highlights

`issuerUrl` is required. `verifierUrl` is required for remote checks; V4 scope
overrides, token storage, a custom `fetch`, optional proof-of-work settings, and
the bounded batch body limit are optional. `MemoryTokenStore` is process-local;
`StorageTokenStore` provides persistence appropriate to its runtime. SDK
configuration does not replace issuer/verifier TLS, Redis, key, or persistence
configuration.

## Safe handling

- Treat tokens, blinding state, Sybil proofs, and discovery-derived material as
  sensitive application data.
- Never log blinding state, proof material, bearer bodies, private keys, or
  status capabilities; keep them out of analytics and URLs.
- Use HTTPS service URLs and validate issuer discovery before key-bound V7
  operations.
- Use typed `FreebirdError.code` values rather than matching human-readable
  error messages.
- A local `checkToken` is non-consuming; `verifyToken` consumes and replay
  protection is a service-side property backed by the verifier's configured
  replay store.

The SDK does not make an application anonymous, authorize a user, or turn a
development deployment into a production security boundary. See [Production
Deployment](../production-deployment.md) and [Client Sybil
Proofs](../client-proofs.md) for deployment and proof responsibilities.
