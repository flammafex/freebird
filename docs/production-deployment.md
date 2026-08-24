# Production Deployment

This is the operator baseline for a public Freebird deployment. V4 private
verification and V7 native bearer verification are active. V5 public bearer
passes are retired and not accepted; V6 is reserved. Do not copy retired V5
configuration into a deployment.

Before rollout, verify issuer and verifier image digests from the release
artifact and deploy operator-provided immutable `@sha256:` references. Keep one
stable V4 issuer key until the documented rotation procedure is approved.

## Required services and storage

- issuer and verifier;
- durable standalone Redis for verifier replay and issuer Sybil replay state;
- an independently managed HTTPS reverse proxy;
- persistent storage for V4 keys, V7 native bearer keys and registry, V7
  discovery/history, receipt keys, graph signers, and audit logs.

Compose is a direct-development probe only. It binds local HTTP ports and does
not provide the trusted TLS/proxy boundary required in production.

When V7 exchange or graph issuance is enabled, the issuer and every
participating verifier must use the same standalone Redis logical database. It
must be a writable master with AOF enabled, `appendfsync always`, and
`maxmemory-policy noeviction`. URL equality is not proof; the V4 replay
authority probe proves the logical-database relationship.

## Minimum environment

```bash
ADMIN_API_KEY=<at-least-32-random-characters>
REQUIRE_TLS=true
BEHIND_PROXY=true
TRUSTED_PROXY_CIDRS=<reverse-proxy-CIDR>

ISSUER_ID=issuer:example:v4
ISSUER_SK_PATH=/data/keys/issuer_sk.bin
VERIFIER_ID=verifier:example:v4
VERIFIER_AUDIENCE=example
VERIFIER_ACCEPTED_TOKEN_VERSIONS=v4,v7
VERIFIER_ENV=production
IN_MEMORY_REPLAY_STORE=false
ISSUER_URL=https://issuer.example.org/.well-known/issuer
VERIFIER_SK_PATH=/issuer-data/keys/issuer_sk.bin

REDIS_URL=redis://redis:6379
SYBIL_REPLAY_STORE=redis
SYBIL_REPLAY_REDIS_URL=redis://redis:6379

NATIVE_BEARER_V7_ENABLE=true
NATIVE_BEARER_V7_SK_PATH=/data/keys/native_bearer_v7.der
NATIVE_BEARER_V7_METADATA_PATH=/data/config/native_bearer_v7.json
NATIVE_BEARER_V7_REGISTRY_PATH=/data/config/native_bearer_v7_registry.json
NATIVE_BEARER_V7_PROFILE_ID=scarcity/native-bearer/v7
NATIVE_BEARER_V7_DESCRIPTOR_ID=<64-lowercase-hex>
NATIVE_BEARER_V7_TOKEN_KEY_ID=<64-lowercase-hex>
NATIVE_BEARER_V7_ASSET_ID=USD
NATIVE_BEARER_V7_AMOUNT_MINOR=1
NATIVE_BEARER_V7_VALIDITY=30d
```

The V7 descriptor and token-key IDs are operator-pinned canonical identities.
Do not replace them casually or reuse an RSA key with changed issuer, suite,
audience, or validity bounds.

## V7 exchange and graph issuance

Enable exchange only after reviewing the active and retained native V7
discovery files:

```bash
NATIVE_EXCHANGE_V7_ENABLE=true
NATIVE_EXCHANGE_V7_REDIS_URL=redis://redis:6379
NATIVE_EXCHANGE_V7_DISCOVERY_PATH=/data/config/native-exchange-v7-discovery.json
NATIVE_EXCHANGE_V7_RETAINED_DISCOVERY_PATHS=/data/config/native-exchange-v7-previous.json
NATIVE_EXCHANGE_V7_PUBLIC_HISTORY_PATH=/data/config/native-exchange-v7-history.json
NATIVE_EXCHANGE_V7_DISABLED_PUBLICATION_ACK_PATHS=/data/config/native-exchange-v7-ack.json
NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_KEY_PATH=/data/keys/native-exchange-v7-receipt.key
NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_METADATA_PATH=/data/config/native-exchange-v7-receipt.json
NATIVE_EXCHANGE_V7_RECEIPT_LIFETIME=1d
NATIVE_EXCHANGE_V7_MAX_BODY_BYTES=3145728
NATIVE_EXCHANGE_V7_TIMEOUT=30s
```

For graph blind issuance, couple issuer and participating verifiers and use
the approved local V4 authorizer:

```bash
NATIVE_GRAPH_ISSUANCE_V7_ENABLE=true
NATIVE_GRAPH_ISSUANCE_V7_POLICY_PATH=/data/config/native-graph-issuance-v7-discovery.json
NATIVE_GRAPH_ISSUANCE_V7_AUTHORIZATION=v4_local
NATIVE_GRAPH_ISSUANCE_V7_VERIFIER_ID=verifier:issuer
NATIVE_GRAPH_ISSUANCE_V7_AUDIENCE=freebird-native-graph-v7
NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64=<issuer-local-secret-json>
VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS=https://issuer.example.org
VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL=30s
VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS=60s
```

Leave the V7 graph marker false and authority URL empty on non-participating
verifiers. Retain private signers until pending references reach zero, then
publish public discovery/history before retirement.

## Proxy and replay requirements

Expose only these native V7 public routes through HTTPS:

- `POST /v7/native-bearer/issue` and `/v7/native-bearer/issue/batch`;
- `POST /v7/public/exchange` and
  `GET /v7/public/exchange/status?public_operation_id=...`;
- `POST /v7/public/graph/issue` and its status route;
- `GET /.well-known/issuer`;
- `GET /.well-known/replay-authority` for V4 authority-only verifier health metadata;
- `GET /.well-known/keys` for strict V7 native-bearer discovery.

Preserve exactly one status-capability header, use `Cache-Control: no-store`,
and never log capabilities, bearer bodies, or nullifiers. The public operation
ID is non-secret and is not authorization.

V7 replay identity is exactly the issuer namespace plus the lowercase
hexadecimal **body nullifier**. The artifact, descriptor, graph, keyset,
verifier, and audience do not participate. Store this identity in durable Redis
with the inclusive V7 validity expiry; never substitute a signature digest or
whole-artifact digest.

The fixed `GET /.well-known/replay-authority` route is the V4 authority-only
metadata endpoint used by verifier health refresh. Keep it distinct from strict
V7 `/.well-known/keys` discovery. The separate
`POST /v1/public/graph/replay-authority/probe` route remains the operator-only V4
authority check for graph participants; it is not metadata or a bearer issuance
route and must not be exposed through `/admin` or a direct backend port.

## Preflight and backup

Run `freebird-validate-config` against the exact production environment, then
exercise discovery and readiness through the HTTPS proxy. Back up Redis AOF,
V4/V7 key material, the append-only V7 registry, active/retained discovery,
public history, receipt metadata, graph signers, and audit logs as one coherent
recovery unit. Never restore Redis independently from V7 discovery or signers.

Use `k8s/validate-overlays.sh` for Kubernetes manifests and see
[Kubernetes Deployment](deployment-kubernetes.md) for the ingress boundary.
