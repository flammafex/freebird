# Systemd Deployment

Use the systemd templates for a single-host production deployment behind a
reverse proxy such as nginx.

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
Redis persistence and restrict Redis to localhost or a private network.

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
Restrict `/admin` by VPN, private network, or explicit IP allowlist.

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
