# Architecture

Freebird is a Rust workspace for private token issuance and verification. The
core deployment has three actors:

- client: creates blinded requests, finalizes tokens, and later redeems tokens
- issuer: checks optional admission policy and evaluates blinded requests
- verifier: validates tokens and records nullifiers to prevent double spend

The issuer does not need to know where a token will be redeemed. The verifier
does not need to know which issuance request produced a redeemed token.

## Workspace Components

| Component | Role |
| --- | --- |
| `issuer` | HTTP issuer, key management, Sybil gates, admin routes, WebAuthn support. |
| `verifier` | HTTP verifier, issuer metadata refresh, nullifier storage, admin routes. |
| `interface` | Local V4 smoke-test client for source builds. |
| `crypto` | VOPRF, blind RSA, token, and provider primitives. |
| `common` | Shared API types, metrics, TLS enforcement, duration parsing, rate limits. |
| `sdk/js` | TypeScript client SDK and examples. |
| `integration_tests` | Cross-crate protocol and storage regression tests. |

## V4 Private-Verification Flow

V4 uses a P-256 VOPRF. It is the flow exercised by `freebird-interface`.

1. The client creates a private input and blinds it.
2. The client sends the blinded element to `POST /v1/oprf/issue`.
3. If the issuer has Sybil resistance configured, the issuer verifies the
   supplied `sybil_proof` before evaluating the blinded element.
4. The issuer returns a VOPRF evaluation.
5. The client unblinds the evaluation and builds a token bound to verifier
   scope.
6. The client sends the token to the verifier.
7. The verifier validates the token and records its nullifier.
8. A second redemption of the same token is rejected.

Batch V4 issuance uses `POST /v1/oprf/issue/batch` and applies one Sybil proof
to the batch request.

## V5 Public Bearer Flow

V5 uses blind RSA signatures for public bearer passes.

1. The client blinds a public-token message.
2. The client sends the blinded message to `POST /v1/public/issue`.
3. The issuer verifies any configured Sybil proof.
4. The issuer returns a blind signature.
5. The client finalizes the public bearer pass.
6. The verifier validates the token against issuer metadata and consumes it.

Batch V5 issuance uses `POST /v1/public/issue/batch`.

## Metadata

The issuer exposes discovery endpoints:

- `/.well-known/issuer`
- `/.well-known/keys`

The verifier periodically refreshes issuer metadata from `ISSUER_URL` or
`ISSUER_URLS`. With `REQUIRE_TLS=true`, issuer metadata URLs must use HTTPS.

## Storage

Issuer storage includes:

- V4 issuer secret key path
- V4 key rotation state
- optional V5 RSA private key and metadata
- optional Sybil-state files for invitation, progressive trust,
  proof-of-diversity, and multi-party vouching
- audit log JSON
- optional WebAuthn credential storage in Redis

Verifier storage includes:

- nullifier store, in-memory by default
- Redis nullifier store when `REDIS_URL` is configured
- optional V4 private verification key or keyring

For public deployments, verifier nullifier storage should be Redis-backed.

## Sybil Gate Placement

Sybil resistance runs before blinded issuance. It does not reveal the client
secret input or final token, but it controls access to issuance.

Issuance routes pass server-observed request context into the Sybil layer. That
context can include client IP/User-Agent derived data and a request-binding
string. Mechanisms that use the context can reject caller-chosen identities or
proofs computed for a different issuance request.

## Trust Boundaries

The main trust boundaries are:

- client to issuer over HTTP
- client to verifier over HTTP
- verifier to issuer metadata discovery
- admin client to admin routes
- service process to Redis or local persistence

Production deployments should terminate real TLS, set `REQUIRE_TLS=true`, and
protect admin routes with network controls in addition to `ADMIN_API_KEY`.
Issuer admin workflows are documented in [admin-operations.md](admin-operations.md).
Production deployment guidance is documented in
[production-deployment.md](production-deployment.md).
