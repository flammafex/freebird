# Systemd Deployment

Use the systemd templates for a single-host production deployment behind a
reverse proxy such as nginx.

This guide covers the current transitional, experimental issuance API only;
it does not implement or select a named profile. V4 key rotation is unsafe for
production until Phase C. Keep the stable issuer key and matching verifier key
in place until then.

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

For a single-host deployment, Redis can run locally. For public use, enable
Redis persistence and restrict Redis to localhost or a private network. Set
both `REDIS_URL` and `SYBIL_REPLAY_REDIS_URL`; in-memory stores are not safe.
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

Admin API keys are secrets: do not expose them to clients or logs, and isolate
issuer and verifier admin access (use separate operator credentials where
possible). Invitation configuration must use the actual parser keys:
`SYBIL_INVITE_COOLDOWN`, `SYBIL_INVITE_EXPIRES`,
`SYBIL_INVITE_NEW_USER_WAIT`, and `SYBIL_INVITE_AUTOSAVE_INTERVAL`; `_SECS`
variants are ignored. PKCS#11 can store key material, but HSM-native/full
VOPRF is unsupported.

## WebAuthn

If WebAuthn is used as a recommended Sybil gate:

- build the issuer with `--features human-gate-webauthn`
- set `WEBAUTHN_RP_ID` to the issuer host name
- set `WEBAUTHN_RP_ORIGIN` to the exact HTTPS origin
- set a high-entropy `WEBAUTHN_PROOF_SECRET`
- expose `/webauthn/` through the reverse proxy
- consider `WEBAUTHN_REQUIRE_ATTESTATION=true` and
  `WEBAUTHN_ALLOWED_AAGUIDS` for hardware/device policy

The browser flow is served by the issuer at `/webauthn/`, with distinct
registration and authentication pages at `/webauthn/register` and
`/webauthn/authenticate`.
