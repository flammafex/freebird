# @freebird/sdk

Anonymous authentication using VOPRF (Verifiable Oblivious Pseudorandom Function).
This is the TypeScript client SDK for [Freebird](https://git.carpocratian.org/sibyl/freebird),
a privacy-preserving token issuance and verification system.

The SDK lets you issue anonymous tokens from a Freebird issuer and verify them
against a Freebird verifier without composing bespoke protocol code. It covers
the V4 (private VOPRF), V5 (RFC 9474 public bearer blind RSA), V2 (public bearer
exchange), and policy-authorized graph-issuance flows.

## Install

```bash
npm install @freebird/sdk
```

The package ships dual ESM/CJS builds with TypeScript declarations. It has no
runtime dependency on Node.js-specific APIs beyond `fetch`, so it works in
modern browsers and Node.js (>= 18) alike.

## Quick start

```ts
import { FreebirdClient } from '@freebird/sdk';

const client = new FreebirdClient({
  issuerUrl: 'https://issuer.example.com',
  verifierUrl: 'https://verifier.example.com',
});

await client.init();

// Issue an anonymous token, then verify it.
const token = await client.issueToken();
const valid = await client.verifyToken(token);
```

## Configuration

`FreebirdClient` takes a single `ClientConfig`:

| Field           | Required | Description                                                                 |
| --------------- | -------- | --------------------------------------------------------------------------- |
| `issuerUrl`     | yes      | Base URL of the issuer (e.g. `https://issuer.example.com`).                 |
| `verifierUrl`   | no       | Base URL of the verifier. Required for verification methods.                |
| `verifierId`    | no       | Optional verifier scope override when `verifierUrl` is unavailable.         |
| `audience`      | no       | Optional audience override when `verifierUrl` is unavailable.               |
| `keyCacheTtlMs` | no       | Optional TTL (ms) for the cached `/.well-known/keys` metadata. When unset,  |
|                 |          | the TTL is derived from the metadata's `epoch_duration_sec`.                |
| `tokenStore`    | no       | Optional persistent store for issued tokens (see `TokenStore` below).       |
| `powDifficulty` | no       | Optional Proof-of-Work difficulty (leading zero bits) to mine when the      |
|                 |          | issuer requires PoW Sybil resistance.                                       |

## Flows

The SDK supports the four core Freebird token flows.

### V4 — private VOPRF token

The classic anonymous token flow. The client blinds a private input, the issuer
signs it without learning the input, and the client unblinds to obtain a
redemption token.

```ts
const token = await client.issueToken();
const valid = await client.verifyToken(token);
```

`issueToken` accepts an optional `SybilProof` when the issuer requires one.

### V5 — public bearer pass (RFC 9474 blind RSA)

A public bearer pass is a blind-RSA signature over a public message. The client
blinds a message, requests a blind signature from the issuer, and unblinds it.

```ts
const message = new TextEncoder().encode('public message');
const response = await client.issuePublicBlindSignature(message);
// response.blind_signature_b64, response.token_key_id, response.issuer_id
```

`issuePublicBlindSignature` accepts an optional `SybilProof` and an optional
`tokenKeyId` to target a specific key.

### V2 — public bearer exchange

The V2 exchange flow converts public bearer passes between keysets along an
immutable graph/transition. It is durable: operations are identified by a
`public_operation_id` and can be retried or observed via a status capability.

```ts
const selection = await client.selectExchangeTransition(graphId, transitionId);

const request = {
  version: 2,
  public_operation_id: /* canonical base64url, 16 bytes */,
  graph_id: selection.graph.graph_id,
  transition_id: selection.transition.transition_id,
  source_keyset_id: selection.transition.source_keyset_id,
  target_keyset_id: selection.transition.target_keyset_id,
  sources: /* ExchangeRequestSource[] */,
  outputs: /* ExchangeRequestOutput[] */,
};

const outcome = await client.exchange(request, statusCapability);
// outcome.kind === 'committed' | 'pending' | 'error'
```

`getExchangeStatus` looks up an in-flight operation by request (or by
`public_operation_id` plus the original request). `exchangeRequestDigest`
computes the request digest used for status capabilities.

### Graph issuance (policy-authorized)

The SDK also supports policy-authorized graph blind issuance, including durable
recovery:

```ts
const policy = await client.selectGraphIssuancePolicy(policyId);
const outcome = await client.issueGraphBlindSignature(request, statusCapability);
```

`createGraphIssuanceRecoveryContext`, `retryGraphBlindSignature`, and
`getGraphIssuanceStatus` support resuming an operation from a persisted
`GraphIssuanceRecoveryContext`.

## API surface

### Issuance

| Method | Description |
| ------ | ----------- |
| `init()` | Fetches the issuer's public key metadata. |
| `issueToken(sybilProof?)` | Issues a single V4 anonymous token. |
| `issueTokens(msgs, opts?)` | Issues a batch of V4 tokens (chunked above 10_000 inputs). Throws `BatchIssuanceError` on partial failure. |
| `issuePublicBlindSignature(blindedMsg, sybilProof?, tokenKeyId?)` | Requests a V5 public bearer blind signature. |
| `issuePublicToken(msg, opts)` | Issues a complete V5 public bearer pass in one call (blinds, signs, unblinds). |
| `issuePublicTokens(msgs, opts)` | Issues a batch of V5 public bearer passes. |
| `getKeyDiscoveryMetadata()` | Fetches the issuer's `/.well-known/keys` discovery metadata. |
| `refreshKeyDiscoveryMetadata()` | Forces a fresh discovery fetch, bypassing the TTL cache. |

### Verification

| Method | Description |
| ------ | ----------- |
| `verifyToken(token)` | Verifies a token against the configured verifier, consuming it. Throws typed errors on failure. |
| `verifyTokenValid(token)` | Boolean convenience over `verifyToken`; returns `false` for invalid/replayed tokens, rethrows infrastructure errors. |
| `checkToken(token)` | Checks token validity WITHOUT consuming it (distinct `/v1/check` endpoint). |
| `verifyBatch(tokens)` | Verifies a batch of tokens in one request, consuming each. |
| `verifyPublicBearerPassLocally(pass, keyInfo)` | Locally verifies the RSA-PSS signature of a V5 pass. Does NOT check spend status. |

### V2 exchange

| Method | Description |
| ------ | ----------- |
| `selectExchangeTransition(graphId, transitionId)` | Resolves an explicit immutable graph/transition selection. |
| `exchange(request, statusCapability)` | Starts or exactly retries a V2 exchange operation. |
| `getExchangeStatus(...)` | Looks up a V2 exchange operation. |
| `exchangeRequestDigest(request)` | Computes the request digest used for status capabilities. |
| `generateOperationId()` | Generates a canonical 16-byte base64url exchange operation id. |
| `generateStatusCapability()` | Generates a canonical 32-byte base64url exchange status capability. |
| `exchangePasses(sources, transition, opts?)` | Assembles a valid V2 `ExchangeRequest`, blinding the output slots. |
| `pollExchangeStatus(request, statusCapability, options?)` | Polls an exchange operation until committed or terminally failed. |

### Graph issuance

| Method | Description |
| ------ | ----------- |
| `selectGraphIssuancePolicy(policyId)` | Resolves one current graph issuance policy. |
| `issueGraphBlindSignature(request, statusCapability)` | Starts a fresh policy-authorized graph blind issuance operation. |
| `retryGraphBlindSignature(context)` / `retryGraphIssuance(context)` | Retries an already-created graph issuance operation. |
| `createGraphIssuanceRecoveryContext(...)` | Builds a complete context suitable for durable recovery. |
| `getGraphIssuanceStatus(context)` | Observes a graph issuance result using persisted recovery context. |
| `pollGraphIssuanceStatus(context, options?)` | Polls a graph issuance operation until committed or terminally failed. |
| `graphIssuanceRequestDigest(request)` | Computes the graph issuance request digest. |
| `graphIssuanceAuthorizationBindingDigest(request)` | Computes the graph issuance authorization binding digest. |

### Token persistence

The `TokenStore` interface (`save`, `load`, `list`, `clear`) lets you persist
issued tokens across sessions. Two implementations ship with the SDK:

- `MemoryTokenStore` — an in-memory store (not durable across restarts).
- `StorageTokenStore` — a durable store backed by a `Storage`-like interface
  (e.g. `localStorage`), configured via `StorageTokenStoreOptions`.

Configure one via `ClientConfig.tokenStore` and access it through
`client.tokenStore`. The `tokenId(token)` helper returns the stable id (the
token's `tokenValue`) used to key stored tokens.

## Typed errors

Every failure thrown by the SDK is a subclass of `FreebirdError`, which carries
a stable machine-readable `code` (`FreebirdErrorCode`) and a generic,
non-leaky message. Branch on the `code` rather than message text.

| Error | `code` | Meaning |
| ----- | ------ | ------- |
| `FreebirdError` | — | Base class for all typed errors. |
| `DiscoveryError` | `discovery` | Discovery metadata could not be fetched or failed validation. |
| `VerificationError` | `verification` | A token could not be verified. |
| `VerifierNotConfiguredError` | `verifier_not_configured` | The client has no verifier endpoint configured. |
| `InvalidTokenError` | `invalid_token` | The presented token is invalid (subclass of `VerificationError`). |
| `ReplayedTokenError` | `replayed_token` | The presented token has already been used (subclass of `VerificationError`). |
| `RateLimitedError` | `rate_limited` | The server rate-limited the request; `retryAfter` is in whole seconds. |
| `VerifierUnavailableError` | `verifier_unavailable` | The verifier is temporarily unavailable (retryable). |
| `ExchangeError` | `exchange` | A V2 public bearer exchange operation failed. |
| `GraphIssuanceError` | `graph_issuance` | A graph issuance operation failed. |
| `BatchIssuanceError` | `issuance` | One or more tokens in a batch issuance failed; carries `results`, `tokens`, and `failed`. |
| `PollError` | `poll` | Base class for poll-specific errors. |
| `PollTimeoutError` | `poll` | A polling operation exceeded its `timeoutMs` cap. |
| `PollAbortedError` | `poll` | A polling operation was cancelled via its `AbortSignal`. |

## Low-level `crypto` escape hatch

For advanced use cases, the SDK exports a `crypto` namespace with the raw
protocol primitives, so you can blind/unblind and build/parse token wire
formats without the client wrapper:

```ts
import { crypto } from '@freebird/sdk';

const { blinded, state } = crypto.blind(input);
const token = crypto.buildRedemptionToken(/* ... */);
```

Available primitives include:

- VOPRF: `blind`, `finalize`, `buildScopeDigest`, `buildPrivateTokenInput`,
  `buildRedemptionToken`, `parseRedemptionToken`.
- Token-key helpers: `tokenKeyIdFromSpki`, `tokenKeyIdToHex`, `tokenKeyIdFromHex`.
- V5 public bearer: `buildPublicBearerMessage`, `buildPublicBearerPass`,
  `parsePublicBearerPass`.
- RSA blind RSA: `rsaBlind`, `rsaUnblind`, `rsaVerify`.
- V2 HMAC authorization helpers: `buildHmacAuthorizationV2`,
  `parseHmacAuthorizationV2`, `verifyHmacAuthorizationV2`, and their
  graph-issuance-qualified aliases (`buildGraphIssuanceHmacAuthorizationV2`,
  `parseGraphIssuanceHmacAuthorizationV2`,
  `verifyGraphIssuanceHmacAuthorizationV2`, plus the transcript/tag helpers).

> **Warning:** these are low-level primitives. Prefer the high-level
> `FreebirdClient` methods unless you have a specific need. Blinding state
> contains secret material — keep it secure and never persist it.

## Scope

The core `FreebirdClient` is scoped to the **client-side issuance, exchange,
and verification** flows described above. The following are **out of scope** for
the core client:

- **Admin operations** — managing issuers, keys, Sybil configuration, and other
  operator tasks. Use the `freebird-cli` binary or the `admin-ui` instead.
- **WebAuthn ceremony** — the browser passkey flow used to obtain `web_authn`
  Sybil proofs. See `docs/webauthn-browser-flow.md`.
- **Attester interaction** — obtaining `social_graph` proofs requires talking to
  the external Social Graph Attester service; the core client does not do this.
- **`/v1/oprf/renew`** — an admin-authenticated, `RegisteredUser`-only endpoint;
  not exposed by the core client.
- **`POST /v1/public/graph/replay-authority/probe`** — a verifier-operator-only
  endpoint; not exposed by the core client.

## Versioning and compatibility

The Rust workspace is versioned in lockstep (currently `0.9.0`). The JS SDK
**follows its own semver** and is not forced to match the Rust release number.

Instead, each SDK release records the wire-format and API compatibility it was
built against. See the [CHANGELOG](./CHANGELOG.md) for the compatibility notes
attached to each release. When upgrading, check the CHANGELOG entry for the
Rust release your issuer/verifier runs to confirm the SDK speaks the same wire
format.

## License

MIT OR Apache-2.0
