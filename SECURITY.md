# Security Policy

Freebird is pre-1.0 software. Treat public deployments as experimental unless
you have reviewed the code, configuration, and operational controls for your
own threat model.

## Reporting Vulnerabilities

Use GitHub private vulnerability reporting for this repository if it is
available. If private reporting is not available, open a public issue asking the
maintainers for a private security contact and do not include exploit details,
secrets, logs, or proof-of-concept code in the public issue.

Useful reports include:

- affected commit or release
- deployment mode and relevant feature flags
- reproduction steps
- expected and actual behavior
- whether the issue affects issuer, verifier, client SDK, admin routes, or
  deployment assets

## Supported Versions

Until tagged stable releases exist, security fixes target the main development
branch. Operators should pin a reviewed commit and update deliberately after
reading the changelog or commit diff.

## Known Security Boundaries

Freebird separates three concerns:

- token issuance: the issuer evaluates blinded client requests
- token redemption: the verifier checks and consumes finalized tokens
- admission control: optional Sybil-resistance gates decide who may request
  issuance

The privacy property is about unlinking issuance from redemption. Sybil
resistance is configurable and local to the issuer. A weak or disabled Sybil
mode means tokens may be easy to farm even if the token cryptography works.

## Known Limitations

- The project has not had an external security audit.
- `SYBIL_RESISTANCE=none` is for local testing or fully trusted issuers only.
- In-memory verifier nullifier storage rejects replay only until the verifier
  restarts. Use Redis for public deployments.
- Sybil proof replay protection for proof-of-work, WebAuthn gate proofs, and
  multi-party vouching defaults to process-local memory. Use
  `SYBIL_REPLAY_STORE=redis` for restart-safe and multi-instance issuer
  deployments.
- `combined` mode with `SYBIL_COMBINED_MODE=or` is only as strong as the
  easiest configured mechanism to satisfy.
- WebAuthn attestation is not automatic. It must be enabled and configured with
  `WEBAUTHN_REQUIRE_ATTESTATION`, `WEBAUTHN_ATTESTATION_POLICY`, and, where
  appropriate, `WEBAUTHN_ALLOWED_AAGUIDS`.
- Admin APIs rely on `ADMIN_API_KEY` or an admin session cookie. Public
  deployments should put admin routes behind TLS, network policy, and a reverse
  proxy or VPN boundary.
- Audit logs are operational records, not tamper-evident security logs.

## Production Baseline

For an internet-exposed issuer or verifier:

- set `REQUIRE_TLS=true`
- set a high-entropy `ADMIN_API_KEY`
- use Redis for verifier nullifier storage
- use `SYBIL_REPLAY_STORE=redis` for issuer Sybil proof replay protection
- use protected persistent storage for issuer key material and Sybil state
- avoid `SYBIL_RESISTANCE=none`
- document which Sybil mode is configured and what it does not prevent
- keep admin routes off the public internet where possible

See also:

- [Architecture](docs/architecture.md)
- [Threat Model](docs/threat-model.md)
- [Sybil Modes](docs/sybil-modes.md)
- [Audit Logging](docs/audit-logging.md)
