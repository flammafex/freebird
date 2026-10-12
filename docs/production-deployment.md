# Production Deployment

This is the operator baseline for a public Freebird V4 deployment.

Before rollout, verify issuer and verifier image digests from the release
artifact and deploy operator-provided immutable `@sha256:` references. Keep one
stable V4 issuer key until the documented rotation procedure is approved.

## Required services and storage

- issuer and verifier;
- durable standalone Redis for verifier replay and issuer Sybil replay state;
- an independently managed HTTPS reverse proxy;
- persistent storage for V4 keys and audit logs.

Compose is a direct-development probe only. It binds local HTTP ports and does
not provide the trusted TLS/proxy boundary required in production.

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
VERIFIER_ENV=production
IN_MEMORY_REPLAY_STORE=false
ISSUER_URL=https://issuer.example.org/.well-known/issuer
VERIFIER_SK_PATH=/issuer-data/keys/issuer_sk.bin

REDIS_URL=redis://redis:6379
SYBIL_REPLAY_STORE=redis
SYBIL_REPLAY_REDIS_URL=redis://redis:6379
```

## Proxy and replay requirements

Expose only the supported V4 public routes through HTTPS:

- `POST /v1/oprf/issue` and `/v1/oprf/issue/batch`;
- `POST /v1/check`, `/v1/verify`, and `/v1/verify/batch`;
- `GET /.well-known/issuer` for V4 issuer metadata;
- `GET /.well-known/keys` at the issuer origin for V4 signing-key discovery
  and stale-key refresh.

Route `/.well-known/keys` to the issuer backend on port 8081 and configure its
cache policy for immediate revalidation so clients can recover from a stale
key after rotation. Keep it separate from the private admin surface.

Keep Redis state durable and restrict access to the services that require it.
Never log token bodies, blinding state, or nullifiers.

## Preflight and backup

Run `freebird-validate-config` against the exact production environment, then
exercise discovery and readiness through the HTTPS proxy. Back up Redis AOF,
V4 key material, and audit logs as a coherent recovery unit.

Use `k8s/validate-overlays.sh` for Kubernetes manifests and see
[Kubernetes Deployment](deployment-kubernetes.md) for the ingress boundary.
