# Architecture

Freebird is a Rust workspace for private token issuance and verification. The
core deployment has three actors:

- client: creates blinded requests, finalizes tokens, and later redeems tokens
- issuer: checks optional admission policy and evaluates blinded requests
- verifier: validates tokens and records nullifiers to prevent double spend

The current issuance API is transitional and experimental. It is not a named
deployment profile; see the authoritative [Profile and Claim
Matrix](profile-claim-matrix.md) before making profile or privacy claims.

The issuer does not need to know where a token will be redeemed. The verifier
does not need to know which issuance request produced a redeemed token.

## Workspace Components

| Component | Role |
| --- | --- |
| `issuer` | HTTP issuer, key management, Sybil gates, admin routes, WebAuthn support. |
| `verifier` | HTTP verifier, issuer metadata refresh, nullifier storage, admin routes. |
| `attester` | Optional Social Graph Attester service: signed-edge scoring, short-lived attestations, and JWKS publication. |
| `interface` | Local V4 smoke-test client for source builds. |
| `crypto` | VOPRF, blind RSA, token, and provider primitives. |
| `common` | Shared API types, metrics, TLS enforcement, duration parsing, rate limits. |
| `sdk/js` | TypeScript client SDK and examples. |
| `integration_tests` | Cross-crate protocol and storage regression tests. |

## V4 Private-Verification Flow

V4 uses a Freebird-specific, bespoke P-256 VOPRF-like construction. It is not
an RFC 9497 VOPRF implementation and is not interoperable with RFC 9497 or
Privacy Pass VOPRF deployments. It is the flow exercised by
`freebird-interface`.

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

## Durable Public Operations

The optional V2 public-bearer exchange and V2 graph-issuance routes are
durable Redis-backed operations. Each request carries two independent values:

- `public_operation_id` is a canonical 16-byte, base64url-encoded,
  non-secret correlation ID. It identifies the operation but does not
  authorize access to its result.
- The exchange or graph-issuance status capability is a separate canonical
  32-byte random bearer value. It is sent only in the corresponding status
  header and authorizes retries and status reads. It must not be placed in a
  body, URL, discovery document, or log.

The public operation ID may appear in a status query because it has no
authority without the separate capability. Status reads are observation-only;
after an ambiguous response, clients retry the exact original request with the
same operation ID and capability. See [Public Bearer Exchange](public-bearer-exchange.md)
and [Public Graph Blind Issuance](public-graph-blind-issuance.md).

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
- optional Redis-backed V2 exchange/graph-issuance operation records, spend
  markers, budgets, and replay-authority state
- audit log JSON
- optional WebAuthn credential storage in Redis

Verifier storage includes:

- Redis nullifier/replay store, required by default
- process-local in-memory replay only when `IN_MEMORY_REPLAY_STORE=true` and
  `VERIFIER_ENV=development`; it is not restart-safe and is never suitable for
  production, exchange, or graph issuance
- optional V4 private verification key or keyring

For public deployments, verifier nullifier/replay storage must be Redis-backed.

## Sybil Gate Placement

Sybil resistance runs before blinded issuance. It does not reveal the client
secret input or final token, but it controls access to issuance.

Issuance routes pass server-observed request context into the Sybil layer. That
context can include client IP/User-Agent derived data and a request-binding
string. Mechanisms that use the context can reject caller-chosen identities or
proofs computed for a different issuance request.

## Optional Social Graph Attester

When `SYBIL_RESISTANCE=social_graph` is enabled, a separate `attester` service
evaluates signed social-graph evidence and issues a short-lived Ed25519-signed
attestation. A client or proof agent presents that attestation in the
Cred-shaped `SybilProof::SocialGraph` payload. The issuer verifies the
attestation and presentation signatures, accepted policy, expiry, eligibility
level, request binding, and replay state; it does not receive or analyze raw
graph edges.

The attester is an optional, independently operated trust boundary. The issuer
currently trusts public keys loaded from `SOCIAL_GRAPH_ATTESTERS_PATH`; its
configured JWKS URL is not refreshed at runtime, revocation state is not
persistent, and the reference attester does not enforce per-identity quotas or
emit quota nullifiers. See the [Social Graph Sybil Gate](social-graph-gate.md)
and [Production Deployment](production-deployment.md) guidance before using
this experimental gate.

## Trust Boundaries

The main trust boundaries are:

- client to issuer over HTTP
- client to verifier over HTTP
- verifier to issuer metadata discovery
- client/proof agent to the optional Social Graph Attester, which receives
  graph evidence and becomes a separate trust boundary
- attester to issuer through signed social-graph presentations; the issuer
  trusts configured attester keys and policy, not the underlying graph analysis
- admin client to admin routes
- service process to Redis or local persistence

Production deployments should terminate real TLS, set `REQUIRE_TLS=true`, and
protect admin routes with network controls in addition to `ADMIN_API_KEY`.
Issuer admin workflows are documented in [admin-operations.md](admin-operations.md).
Production deployment guidance is documented in
[production-deployment.md](production-deployment.md).
