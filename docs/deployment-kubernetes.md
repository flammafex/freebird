# Kubernetes Deployment

The base in `k8s/` is not directly deployable. Select an overlay; the
production overlay intentionally contains required-value markers rather than
publishing example hosts or CIDRs.

They assume:

- an ingress controller that terminates HTTPS
- cert-manager or equivalent TLS provisioning
- Redis with persistence enabled
- secret management outside Git
- one issuer replica and one or more verifier replicas

The current release supports V4 and V7. V5 and V2 have been removed and are
rejected; V6 is reserved and rejected.

## Image Pinning

Every registry image in the raw and base manifests is a
`@sha256:REQUIRED_*_IMAGE_DIGEST` sentinel. Replace both sentinels with
operator-provided, signature-verified immutable `@sha256:` references from the
feature-bearing release artifact before applying. No v0.10.0 GHCR digest is
invented or checked in here because those release digests are not publicly
discoverable in this lane. Historical v0.7.0 images are not graph-capable and
must not be used for graph issuance.

The kind overlay deliberately substitutes `freebird-issuer:kind-smoke` and
`freebird-verifier:kind-smoke`; `scripts/release-kind-smoke.sh` retags and
loads the operator-provided smoke images before rollout. Those local names are
not production image references.

After obtaining the release digests, verify each pinned image:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/.*/.github/workflows/docker.yml@refs/tags/<feature-release-tag>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/flammafex/freebird-issuer@sha256:<operator-provided-digest>
```

## Validate and apply

```bash
# First replace REQUIRED_* values in the production overlay, including both
# image digest markers and graph coupling choices.
k8s/validate-overlays.sh
# This complete overlay apply is for an availability-preserving production
# rollout only; use the clean bootstrap waves below for a new installation.
# If Redis still has clusterIP: None, complete the Service-only migration below
# before applying the full overlay.
kubectl apply -k k8s/overlays/production
```

Do not apply `secrets-template.yaml` unchanged. Replace it with sealed secrets,
External Secrets, Vault, or manually created Kubernetes secrets.

Production values include the public issuer, issuer-admin, and verifier hosts;
the ingress source CIDR; and the proxy service name, namespace, controller
label, and DNS wiring. `TRUSTED_PROXY_CIDRS` must identify only the actual
trusted ingress source, never a pod CIDR. The proxy-policy patch supplies the
matching namespace and controller label. Probe and health egress use HTTPS
port 443 in both overlays.

The base manifests use the native V7 exchange names. Do not restore retired V5
or legacy `PUBLIC_BEARER_EXCHANGE_*` profile settings. Exchange and graph
issuance remain disabled in the base; enabling them requires setting
`NATIVE_EXCHANGE_V7_ENABLE` and
`NATIVE_GRAPH_ISSUANCE_V7_ENABLE` to `true` in the issuer ConfigMap,
setting the same V7 graph marker and a non-empty
`VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS` in the verifier ConfigMap, mounting the
V7 discovery/history/acknowledgement/policy files and signer material at the paths
in the issuer ConfigMap, and creating the referenced
`graph-issuance-credentials` secret with exactly one production authorizer
secret. Run `freebird-validate-config` against the same Redis database used by
the verifiers. The overlay validator rejects an issuer-only graph
configuration or a non-HTTPS authority URL.

## Ingress controller forwarding and TLS boundary

The overlays use ingress-nginx's built-in forwarding behavior; they do not
install a custom forwarded-header ConfigMap or rely on snippet annotations.
Configure the ingress-nginx controller ConfigMap with the exact built-in
settings below:

```bash
export REQUIRED_PROXY_NAMESPACE=ingress-nginx  # production ingress controller namespace
kubectl -n "$REQUIRED_PROXY_NAMESPACE" patch configmap ingress-nginx-controller --type merge \
  -p '{"data":{"proxy-set-headers":"","use-forwarded-headers":"false","compute-full-forwarded-for":"false"}}'
kubectl -n "$REQUIRED_PROXY_NAMESPACE" rollout restart deployment ingress-nginx-controller
```

With `use-forwarded-headers=false` and
`compute-full-forwarded-for=false`, ingress-nginx derives one forwarding chain
from the immediate controller peer and overwrites client-supplied duplicate or
spoofed `X-Forwarded-For` and `X-Forwarded-Proto` values. Confirm the effective
controller ConfigMap before applying workloads. The production overlay uses
`REQUIRED_PROXY_NAMESPACE` for the controller Service/network-policy wiring;
set it to the namespace where ingress-nginx is installed. Do not widen the
trusted source CIDR or enable `configuration-snippet` or `server-snippet` as a
workaround.

Every public and status route crosses the HTTPS ingress boundary. The Kind
smoke script creates one temporary CA and one temporary leaf certificate with
exactly these SANs: `issuer.freebird.test` and `verifier.freebird.test`. The
same temporary `issuer-tls-cert` Secret terminates TLS for both Kind hosts;
client checks use the generated CA and separately verify that an unrelated CA
is rejected for both hosts. The trusted controller pod IP is observed after
restart and supplied as the exact `/32` value; no pod or node CIDR is trusted.

An upstream TLS-termination design is a separately reviewed deployment choice.
Do not combine it with this controller-termination contract without a separate
security review.

## Kind smoke deployment

Install the pinned ingress-nginx kind provider first. The smoke script uses
release `v1.15.1` at commit
`0a5901f3c64f11e92e487799b8da3f00cca37515`:

```bash
# Illustrative commands only. This is not the reviewed smoke path: it does not
# perform CRI image preloading or transform imagePullPolicy to Never before
# admission. It is not the reviewed CRI-preload/`Never` no-admission-pull path;
# use scripts/release-kind-smoke.sh for that reviewed path.
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/0a5901f3c64f11e92e487799b8da3f00cca37515/deploy/static/provider/kind/deploy.yaml
kubectl -n ingress-nginx wait --for=condition=ready pod \
  -l app.kubernetes.io/component=controller --timeout=180s
kubectl apply -k k8s/overlays/kind
```

The kind overlay uses the provider's `ingress-nginx-controller` Service in the
`ingress-nginx` namespace, its `app.kubernetes.io/component=controller` label,
and HTTPS port 443. The smoke script clears custom forwarding configuration,
verifies the built-in settings, discovers the controller pod IP after restart,
and configures that address as a temporary `/32` trusted source. It does not
assume a kind node or pod CIDR. Add `issuer.freebird.test`,
`issuer-admin.freebird.test`, and
`verifier.freebird.test` to the client `/etc/hosts` pointing at the kind
ingress address (or use the provider's documented port mapping).

Kind smoke retains `BEHIND_PROXY=true` and `REQUIRE_TLS=true`; public and status
requests use HTTPS and the controller's built-in forwarding behavior. Before
workloads are applied, the smoke script generates one
ephemeral 32-byte V4 issuer key, seeds it into the issuer PVC, and supplies
the identical base64url key to the verifier. The overlay explicitly accepts
V4 tokens, so readiness can complete after issuer metadata and matching key
material are available.

The kind issuer and verifier ingresses are HTTPS with a test-only ephemeral CA
and the exact two-host SAN leaf. The verifier mounts the CA Secret and uses
`SSL_CERT_FILE`; both hostnames are routed to the ingress controller Service
with pod host aliases. No insecure TLS flag, certificate bypass, synthetic
HTTPS header, or direct-Service acceptance path is used. The CA, leaf key, TLS
Secret, and seeded key are temporary and are removed with the kind cluster and
smoke temporary directory.

The smoke health pod is labeled separately and receives only TCP 443 egress to
the ingress controller through a dedicated NetworkPolicy. It resolves both
test hosts to the controller Service while retaining those names in the HTTPS
URLs, so SNI and certificate verification use the SAN hostnames. It asserts
that the unrelated CA is rejected for both hosts, then checks both status paths
with the provisioned CA while sending duplicate/spoofed forwarding headers;
the controller's built-in settings must overwrite them. The smoke script also
checks the generated nginx configuration has exactly one upstream
`X-Forwarded-For` and `X-Forwarded-Proto` directive per status location.

### Clean bootstrap waves

For a clean production bootstrap, use these waves without taking an already
serving verifier deployment offline:

1. Establish prerequisites and durable secrets. Create the IPv4 Redis Service
   **before any issuer Pods**, using the ordering in the Redis section below.
   Then deploy and verify Redis and the issuer.
2. From the verifier's actual trusted HTTPS ingress boundary, verify issuer
   discovery and metadata before starting verifier replicas.
3. Start the verifier replicas with the normal availability-preserving rollout
   and verify readiness, endpoints, and metadata convergence.

Do not scale a live production verifier deployment to zero. The Kind smoke's
scale-to-zero step is disposable test initialization only, not a production
bootstrap or rollout procedure.

Kind smoke uses a disposable bootstrap order to establish the issuer discovery
boundary before starting verifier replicas: it applies the unchanged overlay,
scales verifier to zero, patches the temporary host aliases, trusted
controller `/32`, and local images, restarts and waits for issuer, confirms the
issuer primary Service endpoint, fetches `/.well-known/issuer` through verified
HTTPS ingress from an in-cluster health-labeled curl pod, and only then scales
verifier directly to three and verifies issuer-metadata refresh in every
verifier log. This scale-to-zero sequence is only smoke initialization
behavior; it is not production rollout guidance.

Production must make the issuer discovery route reachable from the verifier's
trusted HTTPS boundary before initial verifier replicas start. Production
rollouts must use the normal availability-preserving deployment procedure,
not the disposable Kind scale-to-zero sequence.

Run the complete smoke test with immutable local images:

```bash
ISSUER_IMAGE=issuer:test@sha256:<digest> \
VERIFIER_IMAGE=verifier:test@sha256:<digest> \
  scripts/release-kind-smoke.sh
```

It tests both services through the ingress controller and deliberately does
not probe their ClusterIP Services directly. On failure, inspect the printed
all-namespace pod and event diagnostics; the EXIT trap then deletes the kind
cluster and temporary files.

The verifier has no public `LoadBalancer` Service; ingress is the sole public
entry point. Production deployments must provide the required external
secrets before applying the overlay.

## Probe alignment

Both deployments use process-local TCP liveness and startup probes. Readiness
crosses the trusted HTTPS ingress boundary: issuer uses `GET /readyz`, while
verifier uses `GET /ready`. The corresponding diagnostic endpoints are
`/healthz` and `/health`; they are routed through the public ingress only for
safe status diagnosis. Probe failures therefore indicate ingress, forwarded
header, dependency, or application readiness problems without allowing a
direct application-port bypass.

## Public And Admin Surfaces

`issuer-ingress` exposes only public issuer routes (including the non-admin
probe status endpoints):

- `/.well-known/issuer`
- `/.well-known/replay-authority` (V4 authority-only metadata for verifier health refresh)
- `/.well-known/keys`
- `/v1/oprf`
- `/v7/native-bearer`
- `/v7/public`
- `/v1/public/graph/replay-authority/probe` (V4 authority probe for V7 graph participants)
- `/webauthn`
- `/healthz`
- `/readyz`

`issuer-admin-ingress` exposes `/admin` on a separate hostname and includes an
nginx source allowlist. Replace the example CIDRs with your VPN or operator
network ranges.

The verifier ingress exposes only `/health`, `/ready`, `/.well-known/verifier`,
`/v1/verify`, `/v1/verify/batch`, and `/v1/check`. Verifier `/admin` is not
included in the public ingress. Expose it separately on a private hostname
with an operator CIDR allowlist only if required.

## Redis

Redis is used for verifier nullifier storage and issuer Sybil replay storage.
The examples enable a standalone writable master, append-only persistence with
`appendfsync always`, `maxmemory-policy noeviction`, and password
authentication. These settings are required for V7 exchange/graph issuance;
RDB-only or `everysec` durability is not a fallback.

The issuer receives:

- `REDIS_URL`
- `SYBIL_REPLAY_REDIS_URL`
- `WEBAUTHN_REDIS_URL`

The verifier receives:

- `REDIS_URL`
- `VERIFIER_ACCEPTED_TOKEN_VERSIONS` (`v4,v7`; V5 and V2 are removed and
  rejected; V6 is reserved and rejected)
- `VERIFIER_ENV=production`
- `IN_MEMORY_REPLAY_STORE=false`
- `VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS` when participating in V7 graph
  issuance;
- `VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL=30s` and
  `VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS=60s` for the authority health
  contract.

Network policies allow Redis access only from issuer and verifier pods.

### Numeric replay endpoint and fresh installation ordering

Only `SYBIL_REPLAY_REDIS_URL` must avoid DNS. The Redis Service is an ordinary
IPv4 SingleStack ClusterIP Service (`ipFamilies: [IPv4]`,
`ipFamilyPolicy: SingleStack`); Kubernetes allocates its address. Do not pin a
cluster-specific IP or restore `clusterIP: None`. IPv6-only clusters are not
supported by this deployment configuration.

The issuer explicitly uses `enableServiceLinks: true` and constructs
`redis://:$(REDIS_PASSWORD)@$(REDIS_SERVICE_HOST):$(REDIS_SERVICE_PORT)`.
`REDIS_PASSWORD` remains earlier in its environment list so Kubernetes expands
the reference. Keep existing credentials URL-safe/percent-encoded as required
by the Redis URL format. Other URLs (`REDIS_URL`, `WEBAUTHN_REDIS_URL`,
`NATIVE_EXCHANGE_V7_REDIS_URL`, and verifier Redis access) still use `redis:6379`.
The Service selector, TCP port, authentication, Deployment, and persistent data
configuration are unchanged.

Service-link variables are supplied to new Pods, not dynamically refreshed in
running Pods. Create the Redis Service before creating/restarting issuer Pods;
after any future Service recreation, restart issuer Pods again to pick up the
new address. Do not override the injected `REDIS_SERVICE_HOST` or
`REDIS_SERVICE_PORT` in a ConfigMap or environment list.

For a **fresh installation**, first fill the selected overlay's required values
and provision its external secrets. Render the same overlay used for the rest
of the rollout (commands below require Mike Farah `yq` v4):

```bash
kubectl kustomize k8s/overlays/production > freebird-rendered.yaml
yq 'select(.kind == "Namespace")' freebird-rendered.yaml | kubectl apply -f -
yq 'select(.kind == "Service" and .metadata.name == "redis")' freebird-rendered.yaml > redis-service.yaml
kubectl apply -f redis-service.yaml
kubectl -n freebird get service redis -o wide
```

Confirm it has an allocated IPv4 ClusterIP, then continue the clean bootstrap
waves above: provision Redis/issuer dependencies and start the issuer before
the initial verifier rollout. The Service must exist even if Redis Pods are
not yet ready. For kind, select `k8s/overlays/kind`; the reviewed smoke script
restarts issuer Pods after applying the overlay, so those Pods receive the
Service links.

### Existing headless Redis Service: Service-only migration

Use this procedure **only** when `kubectl -n freebird get service redis
-o jsonpath='{.spec.clusterIP}'` reports `None`. The headless-to-ClusterIP change
cannot be applied in place. Schedule a maintenance window: deleting/recreating
the Service temporarily disrupts **all** Redis consumers, including verifier,
exchange, WebAuthn, and issuer replay traffic. Some consumers may require
reconnection or a controlled restart after DNS caches refresh.

1. Keep the existing Redis Deployment, `redis-data` PVC, `redis-credentials`
   Secret, and their contents. Do not delete/recreate the namespace, workload,
   PVC, or secret, and do not use a full-stack delete or force-replace.
2. Render your updated, configured overlay as above. Extract **only** its Redis
   Service into `redis-service.yaml`. Compare its selector and port against the
   existing Service; retain the existing `app: freebird`, `component: redis`
   selector and TCP 6379 targeting named port `redis`, including any intentional
   operator customizations. The replacement must request IPv4 SingleStack and
   omit `clusterIP` so Kubernetes allocates it.
3. Recreate only the Service, then confirm allocation before touching issuer Pods:

   ```bash
   kubectl -n freebird delete service redis
   kubectl apply -f redis-service.yaml
   kubectl -n freebird get service redis -o wide
   kubectl -n freebird get endpointslices -l kubernetes.io/service-name=redis
   ```

4. Once the Service exists, apply the updated issuer Deployment from the same
   render, then restart issuer Pods to refresh their Service-link environment:

   ```bash
   yq 'select(.kind == "Deployment" and .metadata.name == "issuer")' freebird-rendered.yaml | kubectl apply -f -
   kubectl -n freebird rollout restart deployment/issuer
   kubectl -n freebird rollout status deployment/issuer
   ```

5. Verify issuer readiness through its normal HTTPS boundary and verify recovery
   of the other Redis consumers. Resume the normal overlay rollout only after
   recovery. Service recreation does not erase Redis data; never delete volumes
   or credentials as a remedy for readiness failures.

When V7 graph issuance is enabled, set the verifier graph URL to the issuer's
public HTTPS host (for example, `https://issuer.example.com`) and expose the
distinct V4 `GET /.well-known/replay-authority` metadata route, strict V7
`GET /.well-known/keys` discovery route, and exact
`POST /v1/public/graph/replay-authority/probe` path on the issuer ingress. The
verifier health refresh consumes the V4 metadata route; it must not use V7 keys
or the POST probe as a metadata substitute. The fixed V4 probe is retained for
V7 graph participants and proves that the verifier's `REDIS_URL` and issuer
exchange Redis reach the same logical database; URL string equality is not used
as proof. The verifier readiness probe must use the HTTPS ingress boundary, not
the issuer ClusterIP.

## Issuer Scaling

The issuer deployment is intentionally a singleton because it owns issuer key
material and local persisted Sybil state. Before scaling issuer replicas beyond
one, move all mutable state to shared stores and review key-generation and
rotation behavior.

The verifier deployment can scale horizontally because token nullifiers are
stored in Redis.

## WebAuthn

For WebAuthn as a recommended Sybil gate:

- build and publish issuer images
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
