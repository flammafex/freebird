# Freebird

Freebird is a Rust workspace for privacy-preserving token issuance and
verification. The issuer evaluates blinded client requests, the client finalizes
the result into a bearer token, and the verifier checks that token while
recording a nullifier so the same token cannot be spent twice.

The current source tree supports two token modes:

- V4 private-verification tokens using a Freebird-specific, bespoke P-256
  VOPRF-like construction; it is not RFC 9497 interoperable.
- V5 public bearer passes using RFC 9474 blind RSA signatures.

The `freebird-interface` binary exercises the V4 flow against local services on
`127.0.0.1:8081` and `127.0.0.1:8082`.

The optional public bearer exchange atomically spends one or more single-use V5
artifacts and signs configured caller-blinded outputs. Clients use
`POST /v2/public/exchange` and
`GET /v2/public/exchange/status?public_operation_id=...`. A request carries a
public, non-authorizing 16-byte operation ID in its body; both routes require
exactly one separate `Exchange-Status-Capability` header containing canonical
base64url for 32 random bytes. The capability is header-only and must never be
put in a body, URL, query, or log. Responses use `Cache-Control: no-store`, and
durable retries recover the original response without signing or spending
twice. Discovery publishes role-neutral V2 graphs and active/retained Ed25519
receipt verification keys; public-only history keeps outputs and receipts
verifiable after private signers retire. See [Public Bearer
Exchange](docs/public-bearer-exchange.md) for the API, graph, Redis, recovery,
and retention contract.

## Project Documents

- [Security Policy](SECURITY.md): vulnerability reporting, production baseline,
  and known limitations.
- [Profile and Claim Matrix](docs/profile-claim-matrix.md): authoritative status
  of planned issuance profiles, limits on public claims, and the Phase B
  transitional-client inventory.
- [Architecture](docs/architecture.md): issuer, verifier, client, storage, and
  token flows.
- [Public Bearer Exchange](docs/public-bearer-exchange.md): exchange API,
  operation capabilities, receipt verification, durable Redis, and retention.
- [Threat Model](docs/threat-model.md): security goals, assumptions, non-goals,
  and current gaps.
- [Sybil Modes](docs/sybil-modes.md): what each admission gate resists, where it
  is weak, and how combined modes behave.
- [Admin Operations](docs/admin-operations.md): issuer operator workflows for
  invitations, vouching, WebAuthn, keys, and audit.
- [Client Proofs](docs/client-proofs.md): attaching PoW, invitation, WebAuthn,
  and vouching Sybil proofs to issuance requests.
- [WebAuthn Browser Flow](docs/webauthn-browser-flow.md): browser passkey
  registration, authentication, and WebAuthn Sybil proof export.
- [Production Deployment](docs/production-deployment.md): Redis replay stores,
  TLS/proxy settings, persistence, and preflight checks.
- [Release Packaging](docs/release.md): version tags, release archives,
  checksums, container images, and signature verification.
- [Kubernetes Deployment](docs/deployment-kubernetes.md): hardened Kubernetes
  manifests and production notes.
- [Systemd Deployment](docs/deployment-systemd.md): single-host service units
  and environment file templates.
- [Audit Logging](docs/audit-logging.md): audit fields, retention model, privacy
  impact, and limitations.

## Workspace

| Path | Purpose |
| --- | --- |
| `issuer` | Axum issuer service, admin CLI, config validator, key rotation, Sybil gates. |
| `verifier` | Axum verifier service, issuer metadata refresh, nullifier storage, admin UI. |
| `interface` | Local V4 token test client. |
| `crypto` | VOPRF, redemption-token, blind-RSA, and provider primitives. |
| `common` | Shared API types, metrics, logging, rate limits, TLS enforcement. |
| `integration_tests` | Cross-crate protocol and storage regression tests. |
| `sdk/js` | TypeScript client SDK and examples. |
| `docker-compose.yaml`, `Dockerfile`, `k8s`, `server-configs` | Deployment assets. |

## Prerequisites

- Rust stable with Cargo.
- `curl` for the smoke checks below.
- Redis is required by default for verifier replay protection. For explicitly
  unsafe local development only, use `IN_MEMORY_REPLAY_STORE=true` together
  with `VERIFIER_ENV=development`.
- Node.js is only needed for the TypeScript SDK.

## Quickstart (Docker)

The fastest way to get Freebird running is with Docker Compose. This is an
explicit direct-development deployment, not a production reverse-proxy mode:

Compose sets `COMPOSE_DIRECT_ONLY=true`; its validator refuses
`DEPLOYMENT_MODE=trusted-proxy` or production settings because no proxy-aware
Compose profile is provided. The `/readyz` and `/ready` checks only admit the
direct development services after their configured dependencies are ready.

```bash
cp .env.example .env
./launch.sh up
```

`launch.sh` checks prerequisites, creates `.env` from `.env.example` if it does
not exist, offers to generate a secure `ADMIN_API_KEY`, pulls or builds the
images, and waits for both services to become healthy.

Compose publishes the issuer and verifier on `127.0.0.1:8081` and
`127.0.0.1:8082` by default. Override those host addresses with
`ISSUER_HOST_BIND_ADDR` and `VERIFIER_HOST_BIND_ADDR`; keep `ISSUER_BIND_ADDR`
and `VERIFIER_BIND_ADDR` for the in-container listeners (defaulting to
`0.0.0.0:8081` and `0.0.0.0:8082`).

When it finishes, verify the services are up:

```bash
curl http://127.0.0.1:8081/.well-known/issuer
curl http://127.0.0.1:8082/.well-known/verifier
curl http://127.0.0.1:8082/health
```

Then run the V4 token round-trip from the interface binary:

```bash
cargo run -p freebird-interface -- \
  --issuer-url http://127.0.0.1:8081 \
  --verifier-url http://127.0.0.1:8082
```

Expected result: a fresh V4 token is issued by the issuer and accepted once by
the verifier.

Other useful `launch.sh` subcommands:

```bash
./launch.sh status     # show running containers
./launch.sh logs       # follow service logs
./launch.sh stop       # stop all services
```

The default `.env` uses `SYBIL_RESISTANCE=invitation` with a bootstrap admin
user. For local testing without Sybil resistance, set `SYBIL_RESISTANCE=none`
in `.env` before starting.

## Build And Test

```bash
cargo build --workspace
cargo test --workspace
```

Redis-specific integration tests skip themselves when Redis is not reachable at
`REDIS_URL` or `redis://127.0.0.1:6379`.

To check the JavaScript SDK:

```bash
cd sdk/js
npm install
npm run lint
npm test
```

## Local Source Round Trip (Without Docker)

Use this workflow when you want to build from source and run
`freebird-interface`.

The interface defaults to local URLs but accepts overrides:

- issuer: `http://127.0.0.1:8081` (override with `--issuer-url` or `FREEBIRD_ISSUER_URL`)
- verifier: `http://127.0.0.1:8082` (override with `--verifier-url` or `FREEBIRD_VERIFIER_URL`)

For this local flow, run with `REQUIRE_TLS=false` and disable Sybil resistance so
the interface can request tokens without an invitation, proof of work, or
WebAuthn proof.

### 1. Start The Issuer

From the repository root:

```bash
ADMIN_API_KEY=local-admin-key-must-be-at-least-32-chars \
BIND_ADDR=127.0.0.1:8081 \
ISSUER_ID=issuer:local:v4 \
ISSUER_SK_PATH=issuer_sk.bin \
KEY_ROTATION_STATE_PATH=key_rotation_state.json \
SYBIL_RESISTANCE=none \
REQUIRE_TLS=false \
cargo run -p freebird-issuer --bin freebird-issuer
```

Leave this process running.

The issuer creates `issuer_sk.bin` if it does not already exist. The verifier
must read the same key file for V4 private verification.

### 2. Start The Verifier

Open a second terminal in the repository root:

```bash
ADMIN_API_KEY=local-admin-key-must-be-at-least-32-chars \
BIND_ADDR=127.0.0.1:8082 \
VERIFIER_ID=verifier:local:v4 \
VERIFIER_AUDIENCE=local \
VERIFIER_ACCEPTED_TOKEN_VERSIONS=v4 \
VERIFIER_ENV=development \
IN_MEMORY_REPLAY_STORE=true \
ISSUER_URL=http://127.0.0.1:8081/.well-known/issuer \
VERIFIER_SK_PATH=issuer_sk.bin \
REFRESH_INTERVAL_MIN=1 \
REQUIRE_TLS=false \
cargo run -p freebird-verifier --bin freebird-verifier
```

Leave this process running. The verifier should log that issuer metadata was
updated. If it logs that no private verification key is available, check
`VERIFIER_SK_PATH`.

### 3. Check The Services

In a third terminal:

```bash
curl http://127.0.0.1:8081/.well-known/issuer
curl http://127.0.0.1:8082/.well-known/verifier
curl http://127.0.0.1:8082/health
```

### 4. Run The Interface

```bash
cargo run -p freebird-interface
```

Expected result: a fresh V4 token is issued by the issuer and accepted once by
the verifier.

Useful interface modes:

```bash
cargo run -p freebird-interface -- --replay
cargo run -p freebird-interface -- --double-spend
cargo run -p freebird-interface -- --stress 10
cargo run -p freebird-interface -- --save
cargo run -p freebird-interface -- --load
```

`--replay` and `--double-spend` should show that the first verification succeeds
and the second use of the same token is rejected.

## Why These Local Settings Matter

- `ADMIN_API_KEY` is required by both services and must be at least 32
  characters.
- `SYBIL_RESISTANCE=none` is needed for the local interface. If the issuer uses
  `invitation`, `pow`, `webauthn`, or another Sybil mode, `/v1/oprf/issue`
  expects a matching `sybil_proof`.
- `VERIFIER_ID` and `VERIFIER_AUDIENCE` define the verifier scope. V4 clients
  bind this scope into the token before issuance.
- `VERIFIER_SK_PATH=issuer_sk.bin` lets the verifier validate V4 private tokens
  from the local issuer. V5 public bearer verification uses public key discovery
  instead.
- `VERIFIER_ACCEPTED_TOKEN_VERSIONS` is required and controls both accepted and
  advertised token families. The local V4 command enables only `v4`.
- `VERIFIER_ENV=development` plus `IN_MEMORY_REPLAY_STORE=true` is the explicit
  unsafe local memory-backend configuration. Production deployments must use
  Redis; an unsafe override cannot enable memory replay in production.
- `REQUIRE_TLS=false` is for local development. With `REQUIRE_TLS=true`, inbound
  HTTP requests are rejected unless a reverse proxy supplies
  `X-Forwarded-Proto: https`, and verifier issuer metadata URLs must be HTTPS.

## HTTP API

Issuer public endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/.well-known/issuer` | Issuer ID, active VOPRF key, and V5 public mode summary. |
| `GET` | `/.well-known/keys` | Key discovery, active epoch, valid epochs, V5 public keys. |
| `POST` | `/v1/oprf/issue` | Issue one V4 VOPRF evaluation for a blinded element. |
| `POST` | `/v1/oprf/issue/batch` | Batch V4 issuance. |
| `POST` | `/v1/public/issue` | Issue one V5 blind RSA signature. |
| `POST` | `/v1/public/issue/batch` | Batch V5 public bearer issuance. |
| `POST` | `/v2/public/exchange` | Atomically consume V5 sources and blind-sign outputs selected by a V2 graph transition. |
| `GET` | `/v2/public/exchange/status?public_operation_id=...` | Recover exchange status using the separate 32-byte `Exchange-Status-Capability` header. |

Verifier public endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Basic verifier health. |
| `GET` | `/.well-known/verifier` | Verifier ID, audience, and scope digest. |
| `POST` | `/v1/check` | Validate a token without consuming it. |
| `POST` | `/v1/verify` | Validate and consume a token. Reuse is rejected. |
| `POST` | `/v1/verify/batch` | Batch verify and consume tokens. |

Admin endpoints live under `/admin` and require `X-Admin-Key:
<ADMIN_API_KEY>` or a login session cookie. The verifier always mounts its admin
router. The issuer mounts its admin router for all Sybil modes and includes
operator endpoints for invitation state, user bans, key rotation, audit export,
WebAuthn credential/policy review, and multi-party vouching state.

Issuer operator workflows:

| Area | Endpoints |
| --- | --- |
| Invitation users | `GET /admin/users`, `GET /admin/users/:user_id`, `POST /admin/bootstrap/add`, `POST /admin/invites/grant`, `POST /admin/users/ban`, `POST /admin/users/unban` |
| Invitation codes | `GET /admin/invitations`, `POST /admin/invitations/create`, `GET /admin/invitations/:code`, `DELETE /admin/invitations/:code` |
| Multi-party vouching | `GET/POST /admin/vouching/vouchers`, `DELETE /admin/vouching/vouchers/:user_id`, `POST /admin/vouching/vouches`, `GET/DELETE /admin/vouching/pending`, `POST /admin/vouching/mark-successful`, `POST /admin/vouching/mark-problematic` |
| WebAuthn | `GET /admin/webauthn/policy`, `GET /admin/webauthn/stats`, `GET /admin/webauthn/credentials`, `DELETE /admin/webauthn/credentials/:cred_id` |
| Keys and audit | `GET /admin/keys`, `POST /admin/keys/rotate`, `POST /admin/keys/cleanup`, `DELETE /admin/keys/:kid`, `GET /admin/audit`, `GET /admin/export/audit` |

## Configuration Reference

Common service variables:

| Variable | Service | Default | Notes |
| --- | --- | --- | --- |
| `ADMIN_API_KEY` | both | none | Required, minimum 32 characters. |
| `BIND_ADDR` | both | issuer `0.0.0.0:8081`, verifier `0.0.0.0:8082` | Listen address. |
| `ISSUER_HOST_BIND_ADDR` / `VERIFIER_HOST_BIND_ADDR` | Docker Compose | `127.0.0.1:8081` / `127.0.0.1:8082` | Host-published addresses; separate from container listeners. |
| `REQUIRE_TLS` | both | `false` | Set `true` in production behind TLS. |
| `BEHIND_PROXY` | both | `false` | Trust forwarded client IP and proto headers. |
| `RUST_LOG` | both | set by logging init | Standard tracing filter. |

Issuer variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `ISSUER_ID` | `issuer:freebird:v4` | Embedded in issued tokens and metadata. |
| `ISSUER_SK_PATH` | `issuer_sk.bin` | V4 issuer secret key path. Created if missing. |
| `KEY_ROTATION_STATE_PATH` | `key_rotation_state.json` | V4 key rotation state. |
| `KID` | derived | Optional key ID override; mismatched values are corrected with the derived prefix. |
| `EPOCH_DURATION` | `1d` | Human-readable duration accepted. |
| `EPOCH_RETENTION` | `2` | Number of previous epochs accepted. |
| `SYBIL_RESISTANCE` | `none` | `none`, `invitation`, `pow`, `rate_limit`, `progressive_trust`, `proof_of_diversity`, `multi_party_vouching`, `social_graph`, `webauthn`, or `combined`. |
| `SYBIL_REPLAY_STORE` | `memory` | Replay store for accepted PoW, WebAuthn, vouching, and social-graph proofs. Use `redis` for public multi-instance or restart-safe issuers. |
| `SYBIL_REPLAY_REDIS_URL` | none | Redis URL for `SYBIL_REPLAY_STORE=redis`; falls back to `REDIS_URL`. |
| `SYBIL_REPLAY_KEY_PREFIX` | `freebird:sybil:replay` | Redis key prefix for Sybil replay records. |
| `SOCIAL_GRAPH_ATTESTERS_PATH` | `social_graph_attesters.json` | Trusted attester key config JSON; required for `SYBIL_RESISTANCE=social_graph`. |
| `SOCIAL_GRAPH_JWKS_URL` | none | Optional JWKS URL for attester key refresh; refresh is not yet implemented. |
| `SOCIAL_GRAPH_KEY_REFRESH_INTERVAL` | `3600` | Attester key refresh interval. |
| `SOCIAL_GRAPH_MIN_LEVEL` | `1` | Minimum eligibility level: `1` basic, `2` standard, `3` high-value. |
| `SOCIAL_GRAPH_ACCEPTED_POLICY_IDS` | none | Comma-separated accepted attester policy IDs; required and must not be empty. |
| `SOCIAL_GRAPH_ATTESTATION_MAX_AGE` | `300` | Maximum attestation age. |
| `SOCIAL_GRAPH_CLOCK_SKEW_SECS` | `30` | Allowed clock skew. |
| `SOCIAL_GRAPH_REQUIRE_REQUEST_BINDING` | `true` | Require Cred presentation request-binding match. |
| `SOCIAL_GRAPH_REQUIRE_QUOTA_NULLIFIER` | `false` | Require an attestation quota nullifier and replay-check it. |
| `SOCIAL_GRAPH_REPLAY_TTL` | `600` | Replay-store TTL for accepted social-graph proofs. |
| `SOCIAL_GRAPH_STATE_PATH` | `social_graph_state.json` | Persistent social-graph gate state path. |
| `SOCIAL_GRAPH_FAIL_CLOSED` | `true` | Reject startup/verification if trusted attester keys are unavailable. |
| `PUBLIC_BEARER_ENABLE` | `true` | Enables V5 public bearer issuer. |
| `PUBLIC_BEARER_SK_PATH` | `public_bearer_sk.der` | V5 RSA private key path. |
| `PUBLIC_BEARER_METADATA_PATH` | `public_bearer_metadata.json` | V5 key metadata path. |
| `PUBLIC_BEARER_VALIDITY` | `30d` | V5 key validity window. |
| `PUBLIC_BEARER_AUDIENCE` | none | Optional V5 audience binding. |

Verifier variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `VERIFIER_ID` | none | Required. V4 tokens are bound to this verifier ID. |
| `VERIFIER_AUDIENCE` | `VERIFIER_ID` | Audience used in the verifier scope digest. |
| `VERIFIER_ACCEPTED_TOKEN_VERSIONS` | none | Required comma-separated accepted families (`v4`, `v5`). |
| `VERIFIER_ENV` | none | Must be `development` for the explicit in-memory development backend. |
| `IN_MEMORY_REPLAY_STORE` | `false` | Must be `true` with `VERIFIER_ENV=development`; otherwise Redis is required. |
| `ISSUER_URL` / `ISSUER_URLS` | `http://127.0.0.1:8081/.well-known/issuer` | One issuer URL or comma-separated issuer URLs. HTTPS is required when `REQUIRE_TLS=true`. |
| `VERIFIER_SK_PATH` | none | V4 private verification key. Usually the issuer key file for local testing. |
| `VERIFIER_SK_B64` | none | Base64url raw 32-byte V4 key alternative. |
| `VERIFIER_KEYRING_B64` | none | JSON map of `kid` to base64url raw 32-byte keys for rotation windows. |
| `REDIS_URL` | none | Required for verifier nullifier storage outside explicit development memory mode. |
| `REFRESH_INTERVAL_MIN` | `10` | Issuer metadata refresh interval. |
| `EPOCH_DURATION_SEC` | `86400` | Verifier display/config value. |
| `EPOCH_RETENTION` | `2` | Verifier display/config value. |

## Docker And Deployment Assets

The repository includes a multi-stage `Dockerfile`, `docker-compose.yaml`,
Kubernetes manifests, reverse-proxy examples, monitoring rules, and validation
scripts. Treat those as deployment-oriented assets, not as the easiest way to
run the local interface.

For production:

- Use real TLS and set `REQUIRE_TLS=true`.
- Use a high-entropy `ADMIN_API_KEY` from a secret manager.
- Use Redis for verifier nullifier storage.
- Use `SYBIL_REPLAY_STORE=redis` for issuer Sybil proof replay protection.
- Keep issuer key material on protected storage or an HSM-backed path.
- Do not use `SYBIL_RESISTANCE=none` for a public issuer.
- Pin container image versions or digests instead of `latest`.
- Keep `/admin` on a private hostname, VPN, or explicit source allowlist.

## Admin CLI

The issuer package includes `freebird-cli`. Use it when the issuer is running
and you need scripted access to issuer admin routes:

```bash
cargo run -p freebird-issuer --bin freebird-cli -- \
  --url http://127.0.0.1:8081 \
  --key local-admin-key-must-be-at-least-32-chars \
  health
```

Run with `--help` to see health, stats, config, users, invites, keys, export,
metrics, and audit commands.

## Troubleshooting

`freebird-interface` cannot connect:

- Confirm the issuer is on `127.0.0.1:8081` and the verifier is on
  `127.0.0.1:8082`.
- Confirm both services were started from the repository root or point
  `ISSUER_SK_PATH` and `VERIFIER_SK_PATH` at the same file.

Token issuance returns an authorization or Sybil error:

- Use `SYBIL_RESISTANCE=none` for the local interface, or provide a matching
  `sybil_proof` from a custom client.
- For proof-of-work, the proof input must match the request binding documented
  in [Sybil Modes](docs/sybil-modes.md).
- For `social_graph`, check that `SOCIAL_GRAPH_ATTESTERS_PATH` points to a valid
  attester key config and `SOCIAL_GRAPH_ACCEPTED_POLICY_IDS` is not empty.

Verification always fails:

- Check verifier logs for issuer metadata refresh errors.
- Check that `VERIFIER_ID` and `VERIFIER_AUDIENCE` match the metadata fetched by
  the client.
- Check that `VERIFIER_SK_PATH` points at the issuer's V4 secret key.

HTTP requests fail with `tls_required`:

- You started a service with `REQUIRE_TLS=true`. Use HTTPS through a reverse
  proxy or set `REQUIRE_TLS=false` for local development.

The second use of a token fails:

- That is expected. `/v1/verify` consumes the token by recording its nullifier.
  Use `/v1/check` when you need a non-consuming validity check.
