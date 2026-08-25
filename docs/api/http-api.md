# HTTP API

Freebird exposes public protocol routes and a separately protected operator
control plane. Route availability can also depend on configuration, token
family, and readiness state. The lists below are the supported bounded surface;
they are not a promise that every optional V7 feature is enabled.

## Public issuer routes

The issuer publishes discovery metadata and accepts blinded issuance requests:

| Method | Path | Role |
| --- | --- | --- |
| `GET` | `/.well-known/issuer` | V4 issuer metadata. |
| `GET` | `/.well-known/replay-authority` | V4 replay-authority metadata used for verifier health refresh. |
| `GET` | `/.well-known/keys` | Strict V7 native-bearer discovery when V7 is configured. |
| `POST` | `/v1/oprf/issue` | One V4 blinded issuance evaluation. |
| `POST` | `/v1/oprf/issue/batch` | Bounded V4 batch issuance. |
| `POST` | `/v7/native-bearer/issue` | Direct V7 native-bearer issuance when enabled. |
| `POST` | `/v7/native-bearer/issue/batch` | Direct V7 batch issuance when enabled. |

V4 issuance accepts a blinded element and may require a request-bound
`sybil_proof`. V7 issuance is key-bound and uses the exact request contract;
use the SDK or the source types rather than constructing an unvalidated payload
from this overview. See [Client Sybil Proofs](../client-proofs.md) and [Public
Bearer Exchange](../public-bearer-exchange.md) for their respective contracts.

Optional V7 exchange and graph-issuance routes are documented in [Public Bearer
Exchange](../public-bearer-exchange.md) and are disabled unless configured. Do
not expose an operator probe or an internal authority route as a general public
API.

## Public verifier routes

| Method | Path | Role |
| --- | --- | --- |
| `GET` | `/health` | Basic verifier health. |
| `GET` | `/ready` | Readiness after configured dependencies are available. |
| `GET` | `/.well-known/verifier` | Verifier ID, audience, scope digest, and accepted token families. |
| `POST` | `/v1/check` | Validate a V4 or V7 token without consuming it. |
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

For full version-specific issuance/proof and browser operations, also consult
[Client Proofs](../client-proofs.md), [WebAuthn Browser
Flow](../webauthn-browser-flow.md), and the V7 exchange documentation. This
bounded page intentionally does not restate every legacy or optional payload.

## Transport and errors

Production traffic must use HTTPS through the configured trusted proxy and
`REQUIRE_TLS=true`. Public routes are rate-limited. Clients should handle
generic verification/issuance failures and stable replay rejection without
depending on internal error text. Never put private keys, blinding state,
capabilities, bearer bodies, or nullifiers in URLs or logs.
