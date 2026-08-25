# Systemd Deployment

Use the systemd templates for a single-host production deployment behind a
reverse proxy such as nginx.

This guide covers the current transitional V4 and native V7 issuance APIs;
it does not implement or select a named profile. V4 key rotation is unsafe for
production until Phase C. Keep the stable issuer key and matching verifier key
in place until then.

V4 and V7 are supported. V5 and V2 have been removed and are rejected; V6 is
reserved and rejected.

## Layout

Install binaries:

```bash
install -o root -g root -m 0755 freebird-issuer /usr/local/bin/freebird-issuer
install -o root -g root -m 0755 freebird-cli /usr/local/bin/freebird-cli
install -o root -g root -m 0755 freebird-validate-config /usr/local/bin/freebird-validate-config
install -o root -g root -m 0755 freebird-verifier /usr/local/bin/freebird-verifier
```

Create the service user and data directories:

```bash
useradd --system --home /var/lib/freebird --shell /usr/sbin/nologin freebird
install -o freebird -g freebird -m 0750 -d /var/lib/freebird/issuer/keys
install -o freebird -g freebird -m 0750 -d /var/lib/freebird/issuer/state
install -o freebird -g freebird -m 0750 -d /var/lib/freebird/verifier/keys
install -o freebird -g freebird -m 0750 -d /etc/freebird
```

Copy and edit:

```bash
install -o root -g root -m 0644 deploy/systemd/freebird-issuer.service /etc/systemd/system/
install -o root -g root -m 0644 deploy/systemd/freebird-verifier.service /etc/systemd/system/
install -o root -g freebird -m 0640 deploy/systemd/issuer.env.example /etc/freebird/issuer.env
install -o root -g freebird -m 0640 deploy/systemd/verifier.env.example /etc/freebird/verifier.env
```

## Required Adjacent Services

- Redis for verifier nullifier storage.
- Redis for issuer Sybil replay storage.
- nginx or another TLS reverse proxy.
- Backups for `/var/lib/freebird`.

For a single-host deployment, Redis can run locally. For public use, enable a
standalone writable Redis master with AOF, `appendfsync always`, and
`maxmemory-policy noeviction`, and restrict it to localhost or a private
network. Set both `REDIS_URL` and `SYBIL_REPLAY_REDIS_URL`; in-memory stores are
not safe. When native V7 exchange or graph issuance is enabled, set
`NATIVE_EXCHANGE_V7_REDIS_URL` to the same logical database as every
participating verifier's `REDIS_URL`. Do not use URL string equality as proof;
the graph authority probe proves the shared store.
Verifier deployments must also set `VERIFIER_ACCEPTED_TOKEN_VERSIONS` explicitly,
`VERIFIER_ENV=production`, and `IN_MEMORY_REPLAY_STORE=false`.
Keep issuer keys/state and verifier data in separate directories and backups.

## Start

Validate the issuer environment first:

```bash
set -a
. /etc/freebird/issuer.env
set +a
freebird-validate-config
```

Then start:

```bash
# This preflight is required when using the two systemd environment files. It
# rejects a graph-enabled issuer unless the verifier is explicitly configured
# as a graph participant through the same trusted HTTPS boundary.
scripts/validate-graph-coupling.sh \
  /etc/freebird/issuer.env /etc/freebird/verifier.env

systemctl daemon-reload
systemctl enable --now freebird-issuer
systemctl enable --now freebird-verifier
systemctl status freebird-issuer freebird-verifier
```

## Reverse Proxy

Use the nginx templates in `server-configs/`. Public deployments should expose
only public issuance, verification, metadata, and optional WebAuthn routes.
The templates deliberately return 404 for `/admin`; if administration is
required, expose it through a separate private operator ingress and allowlist
the VPN/operator network. Keep the service ports loopback/private and configure
`TRUSTED_PROXY_CIDRS` to the reverse proxy's immediate backend source CIDR.
The proxy must overwrite (not append) exactly one `X-Forwarded-Proto: https`
and one `X-Forwarded-For` client IP. Use the proxy path for readiness; liveness
should remain process-local and must not provide a public HTTP bypass. The
templates explicitly proxy issuer `GET /healthz` and `GET /readyz`, and
verifier `GET /health` and `GET /ready`; these exact routes are safe health
surfaces and carry the same strict forwarded headers. Do not substitute an
admin or wildcard route for probes.

The active issuer routes are `POST /v1/oprf/issue` and `/v1/oprf/issue/batch`
for V4, `POST /v7/native-bearer/issue` and `/v7/native-bearer/issue/batch` for
V7 direct issuance, and the V7 exchange and graph routes under `/v7/public/`.
V5 and V2 direct/public routes are removed and rejected; they must not be
proxied. V6 is reserved and rejected.

For native V7 graph issuance, proxy the strict V7 discovery route
`GET /.well-known/keys` and the exact issuer route
`POST /v1/public/graph/replay-authority/probe` through HTTPS. The keys route must
serve the complete `native_bearer_v7` container; do not merge it with V4 issuer
metadata or accept legacy V5/V2 discovery shapes. Also proxy the distinct V4
authority-only metadata route `GET /.well-known/replay-authority`; verifier
health refresh uses that route, not V7 key discovery. The probe is the stable
V4 authority check, separate from both metadata and V7 bearer routes; preserve
the JSON body/path, allow POST, disable caching and request-header/body logging,
and do not expose the loopback backend directly. Verifiers configure the issuer
separately with `VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS`, plus the frozen
`VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL=30s` and
`VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS=60s` values.

Graph enablement is a coupled deployment setting, not an issuer-only switch.
Set `NATIVE_GRAPH_ISSUANCE_V7_ENABLE=true` in both environment files, set
the issuer's V7 exchange and graph policy/authorizer settings, and set the
verifier's `VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS` to the issuer's public HTTPS
URL. Run `validate-graph-coupling.sh` and `freebird-validate-config` before
starting either unit. A verifier with the marker or URL missing is not a valid
participant and must not serve V4 traffic for this deployment.

Admin API keys are secrets: do not expose them to clients or logs, and isolate
issuer and verifier admin access (use separate operator credentials where
possible). Invitation configuration must use the actual parser keys:
`SYBIL_INVITE_COOLDOWN`, `SYBIL_INVITE_EXPIRES`,
`SYBIL_INVITE_NEW_USER_WAIT`, and `SYBIL_INVITE_AUTOSAVE_INTERVAL`; `_SECS`
variants are ignored. PKCS#11 provider support is not integrated with issuer
startup. `HSM_ENABLE=true` is rejected by the issuer and
`freebird-validate-config`; keep it disabled until the startup provider
integration exists.

## WebAuthn

If WebAuthn is used as a recommended Sybil gate:

- set `WEBAUTHN_RP_ID` to the issuer host name
- set `WEBAUTHN_RP_ORIGIN` to the exact HTTPS origin
- set a high-entropy `WEBAUTHN_PROOF_SECRET`
- expose `/webauthn/` through the reverse proxy
- consider `WEBAUTHN_REQUIRE_ATTESTATION=true` and
  `WEBAUTHN_ALLOWED_AAGUIDS` for hardware/device policy

The browser flow is served by the issuer at `/webauthn/`, with distinct
registration and authentication pages at `/webauthn/register` and
`/webauthn/authenticate`.
