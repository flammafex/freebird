# Production Deployment

This is an operational baseline for a public self-hosted Freebird deployment.
It is intentionally conservative and describes the implementation that exists
today, not a future deployment profile.

Before production rollout, obtain and verify issuer and verifier image digests
from the release artifact and deploy operator-provided `@sha256:` references.
No immutable GHCR digest is checked into these examples; do not substitute an
older pre-feature image for this feature or use a floating tag.

The configuration below applies to the current transitional, experimental
issuance API. Issuance is transitional and experimental: no named production
profile, claim policy, or profile guarantees are implemented here. Do not
present planned profiles as available. The [Profile and Claim
Matrix](profile-claim-matrix.md) is planning documentation only.

V4 key rotation is unsafe for production until Phase C. Keep one stable V4
issuer key and matching verifier key; do not use the rotation workflow as a
production rotation procedure yet.

## Required Services

- issuer
- verifier
- Redis for verifier nullifier storage
- Redis-backed issuer Sybil replay store
- reverse proxy with HTTPS
- persistent storage for issuer keys, key rotation state, invitation/vouching
  state, public bearer keys, graph files/signers, replay authority state, and
  audit logs

Docker Compose is an explicit direct-development deployment probe only. It
binds local HTTP ports and disables TLS/proxy enforcement; it is not the
trusted-proxy production profile. Production requires an independently managed
HTTPS reverse proxy with `REQUIRE_TLS=true`, `BEHIND_PROXY=true`, and an
explicit `TRUSTED_PROXY_CIDRS` allowlist. Compose sets
`COMPOSE_DIRECT_ONLY=true`, and its startup validator rejects
`DEPLOYMENT_MODE=trusted-proxy` or any other production mode rather than
allowing readiness to imply a proxy boundary.

For public deployment, Redis is a security requirement: `REDIS_URL` must be
durable verifier nullifier storage and `SYBIL_REPLAY_REDIS_URL` must be durable
issuer Sybil replay storage. Do not use in-memory defaults.

Public bearer exchange and V2 graph issuance additionally require the issuer and
every participating verifier to share one standalone Redis logical database.
The configured endpoint must report
`role:master`, `appendonly yes`, `appendfsync always`,
`maxmemory-policy noeviction`, non-cluster mode, active AOF, and
`aof_last_write_status:ok`. Use persistent storage; RDB-only durability is not a
fallback. Exchange startup and readiness fail closed when these settings,
connectivity, AOF health, or retained signer pins are unavailable. Redis
Cluster, a replica endpoint, eviction, asynchronous durability, and failover
that can lose acknowledged writes are unsupported.

Keep retained V2 graphs, required RSA output signers, and receipt seeds until
pending-reference counts reach zero. Before removing private signers, copy the
complete public graph and receipt verification keys to
`PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH`. Keep that public history through
the expiry of every corresponding output artifact and receipt; public history
outlives private-key retention.

Graph issuance creates a permanent replay authority identity and append-only
V4 scope tombstones in the shared Redis database. A shared Redis hostname or
equal URL strings are not proof of authority: the verifier proves the same
logical database by a bidirectional challenge/probe through its actual spend
store. Do not delete `freebird:v4-replay-authority:v1:id` or
`freebird:v4-replay-authority:v1:scope-tombstones` during rotation or restore.

## Minimum Environment

Use high-entropy secrets. Do not reuse the example values below.

```bash
ADMIN_API_KEY=<at-least-32-random-characters>
REQUIRE_TLS=true
BEHIND_PROXY=true
TRUSTED_PROXY_CIDRS=<reverse-proxy-CIDR>

ISSUER_ID=issuer:example:v4
ISSUER_SK_PATH=/data/keys/issuer_sk.bin
KEY_ROTATION_STATE_PATH=/data/keys/key_rotation_state.json

VERIFIER_ID=verifier:example:v4
VERIFIER_AUDIENCE=example
VERIFIER_ACCEPTED_TOKEN_VERSIONS=v4,v5
VERIFIER_ENV=production
IN_MEMORY_REPLAY_STORE=false
ISSUER_URL=https://issuer.example.org/.well-known/issuer
VERIFIER_SK_PATH=/issuer-data/keys/issuer_sk.bin

REDIS_URL=redis://redis:6379
SYBIL_REPLAY_STORE=redis
SYBIL_REPLAY_REDIS_URL=redis://redis:6379

SYBIL_RESISTANCE=combined
SYBIL_COMBINED_MODE=and
SYBIL_COMBINED_MECHANISMS=pow,rate_limit
SYBIL_POW_DIFFICULTY=20
SYBIL_RATE_LIMIT=1h
```

When the verifier participates in V2 graph issuance, add the explicit graph
authority settings below. These values are intentionally not inferred from
`ISSUER_URL`:

```bash
VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS=https://issuer.example.org
VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL=30s
VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS=60s
```

Graph enablement is coupled across the deployment. Set
`PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE=true` in the issuer and in every
participating verifier environment; set it to `false` and leave
`VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS` empty on non-participants. Before
starting services outside Compose, run
`scripts/validate-graph-coupling.sh <issuer.env> <verifier.env>` for each
verifier environment. The preflight fails closed on an issuer-only graph
configuration, an unconfigured verifier authority URL, or non-HTTPS authority
URLs.

If public bearer exchange is enabled, add reviewed deployment-specific paths:

```bash
PUBLIC_BEARER_EXCHANGE_ENABLE=true
PUBLIC_BEARER_EXCHANGE_REDIS_URL=redis://redis:6379
PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH=/data/config/public-bearer-exchange-graph-v2.json
PUBLIC_BEARER_EXCHANGE_RETAINED_GRAPH_PATHS=/data/config/exchange-graph-previous.json
PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH=/data/config/exchange-public-history-v2.json
PUBLIC_BEARER_EXCHANGE_DISABLED_PUBLICATION_ACK_PATHS=/data/config/exchange-publication-ack.json
PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_KEY_PATH=/data/keys/exchange-receipt-active.key
PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_METADATA_PATH=/data/config/exchange-receipt-active.json
PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_KEY_PATHS=/data/keys/exchange-receipt-previous.key
PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_METADATA_PATHS=/data/config/exchange-receipt-previous.json
```

For graph blind issuance, add a V2 policy and one authorizer. The old
graph-issuance replay-URL setting is obsolete and must not be configured:

```bash
PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE=true
PUBLIC_BEARER_GRAPH_ISSUANCE_POLICY_PATH=/data/config/graph-issuance-policy-v2.json
PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION=hmac_sha256
PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64=<canonical-base64url-secret>
```

The policy quantity is always one. `v4_local` instead requires the issuer-local
`PUBLIC_BEARER_GRAPH_ISSUANCE_V4_KEYRING_B64` secret keyring. See [Policy-
authorized graph blind issuance](public-graph-blind-issuance.md) for the V2
HMAC nonce framing/vector, signer validity and `0600` requirements, and the
fresh/recovery SDK split.

RSA keys used as outputs of accepting exchange transitions must be isolated from
the direct V5 issuance key; receipt signing uses a separate Ed25519 key. Run
`freebird-validate-config` before enabling traffic to validate graph/history and
signer configuration, publication acknowledgements, and Redis durability. The
validator does not create or mutate the durable key registry: issuer runtime
startup initializes or byte-verifies that append-only registry, and readiness
continues to verify it. See [Public Bearer Exchange](public-bearer-exchange.md).

Use the parser's exact invitation names: `SYBIL_INVITE_COOLDOWN`,
`SYBIL_INVITE_EXPIRES`, `SYBIL_INVITE_NEW_USER_WAIT`, and
`SYBIL_INVITE_AUTOSAVE_INTERVAL`. Names ending in `_SECS` are not recognized.

For invitation-based deployments, persist the invitation state and signing key:

```bash
SYBIL_RESISTANCE=invitation
SYBIL_INVITE_PERSISTENCE_PATH=/data/state/invitations.json
SYBIL_INVITE_SIGNING_KEY_PATH=/data/keys/invitation_signing_key.bin
SYBIL_INVITE_BOOTSTRAP_USERS=admin:100
```

For multi-party vouching:

```bash
SYBIL_RESISTANCE=multi_party_vouching
SYBIL_MULTI_PARTY_VOUCHING_REQUIRED=3
SYBIL_MULTI_PARTY_VOUCHING_PERSISTENCE_PATH=/data/state/multi_party_vouching.json
SYBIL_MULTI_PARTY_VOUCHING_SECRET_PATH=/data/keys/multi_party_vouching_secret.bin
SYBIL_MULTI_PARTY_VOUCHING_SALT=<random-deployment-salt>
```

For WebAuthn:

```bash
SYBIL_RESISTANCE=webauthn
WEBAUTHN_RP_ID=issuer.example.org
WEBAUTHN_RP_ORIGIN=https://issuer.example.org
WEBAUTHN_PROOF_SECRET=<random-secret>
WEBAUTHN_ATTESTATION_POLICY=direct
WEBAUTHN_ALLOWED_AAGUIDS=<comma-separated-aaguids>
```

When WebAuthn is enabled, the issuer serves a browser registration and
authentication flow at `/webauthn/`. See
[WebAuthn Browser Flow](webauthn-browser-flow.md).

For social-graph deployments, run the Social Graph Attester service from the
`attester/` crate on infrastructure separate from the issuer. Configure the
issuer with the attester's public key and explicit policy IDs:

```bash
SYBIL_RESISTANCE=social_graph
SOCIAL_GRAPH_FAIL_CLOSED=true
SOCIAL_GRAPH_ATTESTERS_PATH=/data/config/social_graph_attesters.json
SOCIAL_GRAPH_ACCEPTED_POLICY_IDS=clout-trust-v1
```

Never leave `SOCIAL_GRAPH_ACCEPTED_POLICY_IDS` empty. For higher-value issuance,
prefer `SYBIL_RESISTANCE=combined` with `SYBIL_COMBINED_MODE=and` or `threshold`
so social-graph attestations compose with another gate. See
[Social Graph Sybil Gate](social-graph-gate.md) for the full design.

The current Social Graph integration has important production limitations:

- **No JWKS refresh:** the issuer loads trusted attester keys from
  `SOCIAL_GRAPH_ATTESTERS_PATH`; `SOCIAL_GRAPH_JWKS_URL` and
  `SOCIAL_GRAPH_KEY_REFRESH_INTERVAL` do not refresh keys at runtime. Rotate
  keys by updating the local trusted-key configuration and coordinating
  attester retirement.
- **No persistent revocation:** `SOCIAL_GRAPH_STATE_PATH` is not a persistent
  revocation store. Do not claim durable key or attestation revocation from
  this setting; use short attestation lifetimes and an operator-controlled key
  replacement procedure.
- **No reference quota-nullifier enforcement:** the reference attester does
  not emit `quota_nullifier` or enforce a per-identity epoch quota. Setting
  `SOCIAL_GRAPH_REQUIRE_QUOTA_NULLIFIER=true` makes the issuer require and
  replay-check a supplied nullifier, but does not add attester-side quota
  enforcement; use an attester that supplies that control if it is required.

Issuer HSM startup integration is currently unsupported. `HSM_ENABLE=true` is
rejected by issuer configuration validation and `freebird-validate-config`
until the startup provider integration exists. The optional PKCS#11 provider
remains separately scoped to provider-level experiments and must not be
presented as an issuer HSM deployment.

## Reverse Proxy

Expose public issuance and verification routes. Restrict `/admin` to an
operator VPN, private network, or trusted IP allowlist. `ADMIN_API_KEY` is
still required, but must not be the only boundary. Keep admin credentials out
of public clients, logs, proxy access logs, and shared service accounts; isolate
issuer and verifier admin endpoints and use separate operator credentials where
possible.

Set:

```bash
REQUIRE_TLS=true
BEHIND_PROXY=true
TRUSTED_PROXY_CIDRS=<reverse-proxy-CIDR>
```

The proxy must overwrite (not append) exactly one `X-Forwarded-Proto: https`
and exactly one valid `X-Forwarded-For` IP. `TRUSTED_PROXY_CIDRS` must contain
only the reverse-proxy networks; direct pod/service ports remain private. The
application evaluates this against the **immediate TCP peer**, not the client
IP in a forwarded header. Configure it with the proxy's actual backend source
CIDR (or narrow proxy address range), never a broad pod or client CIDR. The
examples in `server-configs/` use a loopback backend, 10 MiB request limit, and
60-second connect/read/send deadlines for the 10,000-item blind issuance and
verification batch limits.

Expose `POST /v2/public/exchange` and
`GET /v2/public/exchange/status?public_operation_id=...` only over HTTPS.
Preserve exactly one `Exchange-Status-Capability` header containing canonical
base64url for 32 random bytes and preserve `Cache-Control: no-store`. This
private capability is header-only: never copy it into a body, URL, query string,
access log, tracing field, metric, or error page, and disable request-header
logging for it. The 16-byte `public_operation_id` is a separate non-secret
correlation identifier and provides no authorization. A client recovering from
transport ambiguity must retry POST with the same public operation ID, same
status capability, and exact body; 202 responses are retried after
`Retry-After`, while a changed body or capability returns 409.

For graph issuance, also expose `POST
/v1/public/graph/replay-authority/probe` and `/.well-known/keys` through the
same trusted HTTPS proxy. The probe is a fixed public issuer route used only
for the bidirectional Redis authority check; allow POST/JSON, preserve the
path and body, overwrite forwarded headers, disable caching and sensitive
request logging, and never route it through `/admin` or a direct backend port.

The public health model separates process liveness from dependency readiness:
keep liveness process-local (or a private TCP probe) so it cannot bypass the
proxy trust boundary. Route readiness through the trusted HTTPS proxy and use
it for traffic admission: issuer readiness requires Redis, writable
authoritative state, and an active issuance key; verifier readiness requires
Redis, its configured usable key families, and fresh issuer metadata. A
successful liveness response does not mean the service is ready for traffic.
For a configured graph participant, verifier readiness also requires valid
authority discovery and a successful probe for every retained scope. Probes run
every 30 seconds and become stale after 60 seconds. V4 `/v1/verify` and
`/v1/verify/batch` fail closed with `503` before replay mutation when this
authority is unavailable; V5 is unaffected.
Do not publish backend ports or `/admin` on the public listener; use a separate
private operator ingress with an explicit network allowlist if administration
is required.

## Persistence

Back up:

- `issuer_sk.bin`
- `key_rotation_state.json`
- public bearer key and metadata files
- exchange active/retained V2 graphs and still-required RSA output private keys
- exchange active/retained receipt seeds and public history
- graph-issuance policy and still-required signer files
- invitation signing key and state
- multi-party vouching secret and state
- audit log, if retained for operations
- Redis data or managed Redis backups

Keep issuer key files, verifier key material, rotation state, and invitation
signing material on separate access-controlled persistent volumes. The verifier
needs matching V4 key material, but must not have issuer state or issuer admin
access.

Losing verifier Redis data can allow already-spent tokens to be accepted again
until old tokens expire. Losing the issuer Sybil replay store can allow replay
of recently accepted PoW, WebAuthn, or vouching proofs. Use Redis persistence
for public deployments.

For exchange and graph issuance, Redis also stores authoritative source spends,
pending operation state, the append-only key registry, lifetime budgets,
byte-exact committed responses, the permanent replay authority identity,
scope tombstones, and V4 spend markers. Back it up coherently with exchange
graphs, graph policy, output keys, receipt seeds, public history, and the
authority/tombstone state. Never restore Redis or one side of the signer ring
independently. Follow
[Backup and Restore](backup-restore.md) and verify readiness, discovery history,
and a protected committed-operation retry before reopening traffic.

## Preflight

Run:

```bash
freebird-validate-config
cargo test --workspace
```

Then exercise the deployed services:

```bash
freebird-cli --url https://issuer.example.org --key "$ADMIN_API_KEY" health
freebird-cli --url https://issuer.example.org --key "$ADMIN_API_KEY" config
cargo run -p freebird-interface -- \
  --issuer-url https://issuer.example.org \
  --verifier-url https://verifier.example.org \
  --pow-difficulty 20
```

## Deployment Guides

- [Release Packaging](release.md)
- [Kubernetes Deployment](deployment-kubernetes.md)
- [Systemd Deployment](deployment-systemd.md)
