# HTTP API

Freebird exposes public protocol routes and a separately protected operator
control plane. Route availability can also depend on configuration and readiness
state. The lists below describe the supported V4 surface.

## Public issuer routes

The issuer publishes discovery metadata and accepts blinded issuance requests:

| Method | Path | Role |
| --- | --- | --- |
| `GET` | `/.well-known/issuer` | V4 issuer metadata. |
| `GET` | `/.well-known/keys` | V4 signing-key discovery used by clients to discover keys and refresh after a stale-key response. |
| `POST` | `/v1/oprf/issue` | One V4 blinded issuance evaluation. |
| `POST` | `/v1/oprf/issue/batch` | Bounded V4 batch issuance. |

V4 issuance accepts a blinded element and may require a request-bound
`sybil_proof`. See [Client Sybil Proofs](../client-proofs.md) for its contract.
Both discovery routes are served by the issuer. Publish `/.well-known/keys` at
the issuer's public HTTPS origin and proxy it to the issuer backend on port
8081; it is not a verifier or admin route. The key response must be revalidated
on each discovery so stale-key recovery can observe prompt signing-key changes.

## Public verifier routes

| Method | Path | Role |
| --- | --- | --- |
| `GET` | `/health` | Basic verifier health. |
| `GET` | `/ready` | Readiness after configured dependencies are available. |
| `GET` | `/.well-known/verifier` | Verifier ID, audience, scope digest, and accepted token families. |
| `POST` | `/v1/check` | Validate a V4 token without consuming it. |
| `POST` | `/v1/verify` | Validate and consume a token; replay is rejected. |
| `POST` | `/v1/verify/batch` | Bounded batch validation and consumption. |

The single-token verification body is:

```json
{"token_b64":"<base64url token>"}
```

`/v1/check` and `/v1/verify` return a response containing `ok` and
`verified_at`; failures may include an error code. A successful check does not
consume the token. A successful verify records its spend/nullifier, so a later
verify of the same token is rejected. Batch requests contain a `tokens` array
of objects with `token_b64`; the batch response contains per-item results and
aggregate counters. Batch limits are enforced by the service.

## Health and issuer process routes

The issuer also has process/readiness checks at `/healthz` and `/readyz`. These
are distinct from verifier `/health` and `/ready`. Use the endpoints exposed by
the deployment in its health checks; do not assume a health route is an
issuance or verification route.

## Admin routes

Issuer and verifier admin routers live under `/admin`. They require
`X-Admin-Key: <ADMIN_API_KEY>` or the authenticated session cookie created by
`POST /admin/login`. Restrict this control plane at the network boundary; it is
not a public client API. The complete supported operator route inventory is in
[Admin Operations](../admin-operations.md), including invitations, vouching,
WebAuthn, keys, and audit operations.

For issuance proofs and browser operations, also consult [Client
Proofs](../client-proofs.md) and [WebAuthn Browser Flow](../webauthn-browser-flow.md).

## Transport and errors

Production traffic must use HTTPS through the configured trusted proxy and
`REQUIRE_TLS=true`. Public routes are rate-limited. Clients should handle
generic verification/issuance failures and stable replay rejection without
depending on internal error text. Never put private keys, blinding state,
capabilities, bearer bodies, or nullifiers in URLs or logs.
