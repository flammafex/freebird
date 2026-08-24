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

## V7 Native Bearer Flow

V7 uses randomized RSA blind signatures for native bearer tokens. V5 public
bearer passes are retired and are not accepted; V6 is reserved.

1. The client constructs the fixed V7 bearer body, including its body nullifier,
   and blinds the message with the V7 randomized RSA suite.
2. The client sends the blinded message to `POST /v7/native-bearer/issue`.
3. The issuer validates the active V7 descriptor and any configured Sybil proof.
4. The issuer returns a blind signature.
5. The client finalizes the V7 native bearer token.
6. The verifier validates the token against immutable V7 key discovery and
   consumes the replay identity derived from the issuer ID and body nullifier.

Batch V7 issuance uses `POST /v7/native-bearer/issue/batch`.

For V7 consuming verification, the replay identity is the issuer namespace
plus the lowercase hexadecimal body nullifier. Signature bytes, the complete
artifact, descriptor, graph, keyset, verifier, and audience are intentionally
excluded, so a second signature over the same body nullifier is still a replay.

Both V7 native bearer issuance routes return HTTP 400 with
`{"error":"token_key_not_active"}` when a requested V7 key is stale. The
`/v1/verify` route returns HTTP 401 with
`{"ok":false,"error":"replay_detected","verified_at":0}` for replay; other
verification failures remain generic.

## Durable Public Operations

The optional V7 native-bearer exchange and V7 graph-issuance routes are durable
Redis-backed operations. Each request carries two independent values:

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

The issuer exposes separate discovery/authority endpoints:

- `/.well-known/issuer`
- `/.well-known/keys` — strict V7 native-bearer key and graph discovery.
- `/.well-known/replay-authority` — V4 authority-only metadata for verifier
  health refresh.
- `POST /v1/public/graph/replay-authority/probe` — separate V4 authority probe.

The verifier periodically refreshes issuer metadata from `ISSUER_URL` or
`ISSUER_URLS`; those inputs are normalized to strict V7 `GET /.well-known/keys`
for V7 trust. Graph participants additionally configure
`VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS`, which is used only for V4
`GET /.well-known/replay-authority` metadata and the separate POST probe. The
graph-authority URL must never replace `ISSUER_URL(S)` for V7 key discovery.
With `REQUIRE_TLS=true`, all configured issuer URLs must use HTTPS.

## Storage

Issuer storage includes:

- V4 issuer secret key path
- V4 key rotation state
  - mandatory V7 native bearer RSA private key, metadata, and append-only registry
- optional Sybil-state files for invitation, progressive trust,
  proof-of-diversity, and multi-party vouching
  - optional Redis-backed V7 exchange/graph-issuance operation records, spend
  markers, budgets, and replay-authority state
- audit log JSON
- optional WebAuthn credential storage in Redis

Verifier storage includes:

- Redis nullifier/replay store, required by default
- process-local in-memory replay only when `IN_MEMORY_REPLAY_STORE=true` and
  `VERIFIER_ENV=development`; it is not restart-safe and is never suitable for
  production, exchange, or graph issuance
  - optional V4 private verification key or keyring; V7 verification uses
    issuer-published discovery

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
