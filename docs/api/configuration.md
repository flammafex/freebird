# Configuration

Freebird reads configuration from environment variables. This page lists the
settings needed to understand the local flow and the production baseline; it is
not an exhaustive environment-variable reference. Defaults and requirements
can change with the selected token family and optional feature.

## Common service settings

| Variable | Purpose |
| --- | --- |
| `ADMIN_API_KEY` | Mandatory admin authentication key for both services; it must be at least 32 characters. |
| `BIND_ADDR` | Service listen address (`0.0.0.0:8081` issuer, `0.0.0.0:8082` verifier by default). |
| `REQUIRE_TLS` | Enforce HTTPS at the trusted proxy boundary; use `false` only for deliberate local development. |
| `BEHIND_PROXY` | Enables the trusted-proxy handling used with forwarded request metadata. |

Production should set `REQUIRE_TLS=true`, configure `BEHIND_PROXY` and trusted
proxy CIDRs, and expose the services only through an independently managed HTTPS
reverse proxy. Compose's direct local HTTP mode does not satisfy this baseline.

## Issuer settings

| Variable | Purpose |
| --- | --- |
| `ISSUER_ID` | Issuer namespace embedded in metadata and issued material. |
| `ISSUER_SK_PATH` | Persistent V4 issuer secret-key path. |
| `KEY_ROTATION_STATE_PATH` | V4 key-rotation state path. |
| `SYBIL_RESISTANCE` | Admission mode; use an explicit mode, and do not use `none` for a public issuer. |
| `SYBIL_REPLAY_STORE` | Replay backend for applicable Sybil proofs; use `redis` for restart-safe/public multi-instance operation. |
| `SYBIL_REPLAY_REDIS_URL` | Redis URL for that Sybil replay backend; it can fall back to `REDIS_URL`. |
| `NATIVE_BEARER_V7_ENABLE` | V7 issuance is mandatory; `false` (or `0`) is rejected. Set `true`. |
| `NATIVE_BEARER_V7_SK_PATH` / `NATIVE_BEARER_V7_METADATA_PATH` | Persistent V7 signer key and metadata paths. |
| `NATIVE_BEARER_V7_REGISTRY_PATH` | Append-only V7 registry path. |
| `NATIVE_BEARER_V7_TOKEN_KEY_ID` | Mandatory 64-character lowercase hexadecimal V7 token key ID. |
| `NATIVE_BEARER_V7_ASSET_ID` | Mandatory V7 fixed-body asset identifier. |
| `NATIVE_BEARER_V7_AMOUNT_MINOR` | Mandatory V7 fixed-body amount in minor units; it must be an integer. |

WebAuthn additionally requires `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_ORIGIN`, and a
high-entropy `WEBAUTHN_PROOF_SECRET`. The origin must match the browser origin;
production should use HTTPS. Optional V7 exchange and graph issuance have
additional strict JSON, signer, and Redis settings; see [Production
Deployment](../production-deployment.md) and [Public Bearer
Exchange](../public-bearer-exchange.md), rather than enabling them from this
summary.

## Verifier settings

| Variable | Purpose |
| --- | --- |
| `VERIFIER_ID` | Required verifier identity; V4 tokens bind to its scope. |
| `VERIFIER_AUDIENCE` | Audience in the verifier scope; defaults to the verifier ID. |
| `VERIFIER_ACCEPTED_TOKEN_VERSIONS` | Comma-separated accepted families, `v4` and/or `v7`. |
| `ISSUER_URL` / `ISSUER_URLS` | Issuer discovery URL(s); HTTPS is required when TLS enforcement is enabled. |
| `REDIS_URL` | Verifier replay/nullifier store outside explicit development memory mode. |
| `VERIFIER_ENV` and `IN_MEMORY_REPLAY_STORE` | The explicit development-only opt-in for an in-memory replay store. |
| `VERIFIER_SK_PATH` | V4 private verification key; V7 uses issuer discovery instead. |
| `REFRESH_INTERVAL_MIN` | Issuer metadata refresh interval. |

## Production storage baseline

Production requires durable Redis for verifier replay protection and issuer Sybil
replay state, plus persistent protected storage for issuer keys, V7 key/registry
and discovery material where used, and audit logs. Do not use
`IN_MEMORY_REPLAY_STORE=true` in production. For V7 exchange/graph deployments,
the participating services must use the same standalone writable Redis logical
database with AOF, `appendfsync always`, and `maxmemory-policy noeviction`.

Keep keys at restrictive filesystem permissions, back up Redis and related key,
discovery, registry, receipt, and audit data as one coherent recovery unit, and
run [the configuration validator](cli.md#configuration-validation) against the
exact production environment. See [Production Deployment](../production-deployment.md)
for the complete baseline and [Admin Operations](../admin-operations.md) for
operator controls.
