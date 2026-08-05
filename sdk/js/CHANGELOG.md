# Changelog

All notable changes to `@freebird/sdk` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-05

Expands the SDK surface with the methods and types added across Phases 1-8 of
the SDK enhancement plan: a richer verification surface, V5 public bearer
issuance helpers, batch issuance, key-rotation refresh, V2 exchange request
assembly, durable polling, token persistence, and the typed error hierarchy.

### Added

- Verification surface:
  - `verifyToken(token)` — verifies a token against the configured verifier,
    consuming it, and throws typed errors on failure.
  - `verifyTokenValid(token)` — boolean convenience over `verifyToken`; returns
    `false` for invalid/replayed tokens and rethrows infrastructure errors.
  - `checkToken(token)` — checks token validity WITHOUT consuming it (distinct
    `/v1/check` endpoint).
  - `verifyBatch(tokens)` — verifies a batch of tokens in one request.
  - `verifyPublicBearerPassLocally(pass, keyInfo)` — locally verifies the
    RSA-PSS signature of a V5 public bearer pass (does not check spend status).
- V5 public bearer issuance:
  - `issuePublicToken(msg, opts)` — issues a complete V5 public bearer pass in
    one call (blinds, signs, unblinds).
  - `issuePublicTokens(msgs, opts)` — issues a batch of V5 public bearer passes.
- Batch V4 issuance:
  - `issueTokens(msgs, opts?)` — issues a batch of V4 tokens, chunked above
    10_000 inputs, throwing `BatchIssuanceError` on partial failure.
- Key discovery:
  - `refreshKeyDiscoveryMetadata()` — forces a fresh `/.well-known/keys` fetch,
    bypassing the TTL cache.
- V2 exchange request assembly:
  - `generateOperationId()` — canonical 16-byte base64url operation id.
  - `generateStatusCapability()` — canonical 32-byte base64url status capability.
  - `exchangePasses(sources, transition, opts?)` — assembles a valid V2
    `ExchangeRequest`, blinding the output slots.
- Durable polling:
  - `pollExchangeStatus(request, statusCapability, options?)` — polls an
    exchange operation until committed or terminally failed.
  - `pollGraphIssuanceStatus(context, options?)` — polls a graph issuance
    operation until committed or terminally failed.
  - `pollUntilTerminal`, `PollOptions`, `PollError`, `PollTimeoutError`,
    `PollAbortedError`.
- Token persistence:
  - `TokenStore` interface (`save`, `load`, `list`, `clear`).
  - `MemoryTokenStore` and `StorageTokenStore` implementations, plus the
    `tokenId(token)` helper and `StorageTokenStoreOptions`.
- Typed error hierarchy:
  - `FreebirdError` base class with a stable `FreebirdErrorCode`.
  - `DiscoveryError`, `VerificationError`, `VerifierNotConfiguredError`,
    `InvalidTokenError`, `ReplayedTokenError`, `RateLimitedError`,
    `VerifierUnavailableError`, `ExchangeError`, `GraphIssuanceError`,
    `BatchIssuanceError`.
- Low-level `crypto` RSA helpers: `rsaBlind`, `rsaUnblind`, `rsaVerify`.
- Proof-of-Work Sybil helpers (client-generable PoW only): `generateProofOfWork`,
  `verifyPow`, `buildIssueBinding`, `buildPublicIssueBinding`, `buildRenewBinding`,
  `buildBatchBinding`.
- Recovery-context serialization helpers:
  `serializeGraphIssuanceRecoveryContext` / `deserializeGraphIssuanceRecoveryContext`.
- New public types: `VerifyResp`, `VerifyResult`, `BatchVerifyResp`,
  `PublicBearerPass`, `RsaBlindState`, `IssuePublicTokenOptions`,
  `IssuePublicTokensOptions`, `IssueTokensOptions`, `ExchangePassesOptions`,
  `SybilConfigSummary`, `SybilModeSettings`, `TrustLevelSummary`, and more.

### Compatibility

- Wire-format/API compatibility is recorded against the Rust release this SDK
  was built for. The JS SDK follows its own semver and is **not** forced to
  match the Rust workspace version (currently `0.9.0`).

## [0.1.0] - 2026-08-05

Initial publishable release of the Freebird TypeScript SDK.

### Added

- `FreebirdClient` with the following public surface:
  - `init()` — fetches the issuer's public key metadata.
  - `issueToken(sybilProof?)` — issues a V4 anonymous token.
  - `issuePublicBlindSignature(blindedMsg, sybilProof?, tokenKeyId?)` — requests
    a V5 public bearer blind signature.
  - `getKeyDiscoveryMetadata()` — fetches key discovery metadata.
  - `selectExchangeTransition(graphId, transitionId)` — resolves a V2 exchange
    graph/transition selection.
  - `exchange(request, statusCapability)` / `getExchangeStatus(...)` /
    `exchangeRequestDigest(request)` — V2 public bearer exchange.
  - `selectGraphIssuancePolicy(policyId)` / `issueGraphBlindSignature(...)` /
    `retryGraphBlindSignature(...)` / `retryGraphIssuance(...)` /
    `createGraphIssuanceRecoveryContext(...)` / `getGraphIssuanceStatus(...)` /
    `graphIssuanceRequestDigest(...)` /
    `graphIssuanceAuthorizationBindingDigest(...)` — policy-authorized graph
    issuance with durable recovery.
  - `verifyToken(token)` — verifies a token against the configured verifier.
- Low-level `crypto` escape hatch exposing VOPRF blind/finalize, token wire
  format builders/parsers, token-key helpers, and V2 HMAC authorization helpers.
- TypeScript declarations for all public types (`ClientConfig`, `FreebirdToken`,
  `SybilProof`, `KeyDiscoveryMetadata`, `ExchangeOutcome`,
  `GraphIssuanceRecoveryContext`, and more).
- Dual ESM/CJS builds with conditional `exports` and `types` for both module
  systems.
- Packaging metadata (`license`, `repository`, `homepage`, `keywords`) and a
  `prepublishOnly` build+test gate.

### Compatibility

- Wire-format/API compatibility is recorded against the Rust release this SDK
  was built for. The JS SDK follows its own semver and is **not** forced to
  match the Rust workspace version (currently `0.9.0`).

[0.2.0]: https://git.carpocratian.org/sibyl/freebird
[0.1.0]: https://git.carpocratian.org/sibyl/freebird
