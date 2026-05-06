# Kubernetes Deployment

The manifests in `k8s/` are production-oriented examples. They assume:

- an ingress controller that terminates HTTPS
- cert-manager or equivalent TLS provisioning
- Redis with persistence enabled
- secret management outside Git
- one issuer replica and one or more verifier replicas

## Image Pinning

The manifests pin `ghcr.io/flammafex/freebird-issuer:0.5.1` and
`ghcr.io/flammafex/freebird-verifier:0.5.1`. For production, pin image digests
after verifying signatures:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/.*/.github/workflows/docker.yml@refs/tags/v0.5.1' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/flammafex/freebird-issuer@sha256:<digest>
```

## Apply Order

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/secrets-template.yaml
kubectl apply -f k8s/redis-deployment.yaml
kubectl apply -f k8s/issuer-deployment.yaml
kubectl apply -f k8s/verifier-deployment.yaml
kubectl apply -f k8s/network-policy.yaml
kubectl apply -f k8s/ingress.yaml
```

Do not apply `secrets-template.yaml` unchanged. Replace it with sealed secrets,
External Secrets, Vault, or manually created Kubernetes secrets.

## Public And Admin Surfaces

`issuer-ingress` exposes only public issuer routes:

- `/.well-known/issuer`
- `/.well-known/keys`
- `/v1/oprf`
- `/v1/public`
- `/webauthn`

`issuer-admin-ingress` exposes `/admin` on a separate hostname and includes an
nginx source allowlist. Replace the example CIDRs with your VPN or operator
network ranges.

The verifier ingress exposes verifier routes. If your verifier admin routes are
not intended to be public, split verifier admin access onto a separate private
hostname in the same style as the issuer admin ingress.

## Redis

Redis is used for verifier nullifier storage and issuer Sybil replay storage.
The examples enable append-only persistence and password authentication.

The issuer receives:

- `REDIS_URL`
- `SYBIL_REPLAY_REDIS_URL`
- `WEBAUTHN_REDIS_URL`

The verifier receives:

- `REDIS_URL`

Network policies allow Redis access only from issuer and verifier pods.

## Issuer Scaling

The issuer deployment is intentionally a singleton because it owns issuer key
material and local persisted Sybil state. Before scaling issuer replicas beyond
one, move all mutable state to shared stores and review key-generation and
rotation behavior.

The verifier deployment can scale horizontally because token nullifiers are
stored in Redis.

## WebAuthn

For WebAuthn as a recommended Sybil gate:

- build and publish issuer images with `--features human-gate-webauthn`
- set `WEBAUTHN_RP_ID` to the issuer host
- set `WEBAUTHN_RP_ORIGIN` to `https://issuer.example.com`
- keep `/webauthn` on the public issuer ingress
- store `WEBAUTHN_PROOF_SECRET` in `webauthn-credentials`
- use `SYBIL_REPLAY_STORE=redis`

The browser flow is available at:

```text
https://issuer.example.com/webauthn/
```

Registration and authentication are separate pages:

```text
https://issuer.example.com/webauthn/register
https://issuer.example.com/webauthn/authenticate
```

The authenticate page hands WebAuthn Sybil proof material directly to the
requesting client when a callback or opener window is present. It shows proof
JSON only as a developer fallback.
