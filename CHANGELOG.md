# Changelog

## 0.5.1 - 2026-05-05

- Added public-readiness documentation: security policy, architecture, threat
  model, Sybil modes, admin operations, client proofs, production deployment,
  and audit logging.
- Added HTTP integration coverage for Sybil admission modes and admin operator
  workflows.
- Added Redis-backed Sybil proof replay storage for restart-safe and
  multi-instance issuer deployments.
- Expanded issuer admin API, CLI, and admin UI coverage for invitations,
  vouching, WebAuthn credentials, user bans, and key rotation.
- Added `freebird-interface` support for configurable issuer/verifier URLs,
  request-bound proof-of-work, and JSON Sybil proofs.
- Added a browser WebAuthn flow at `/webauthn/` and `/webauthn/app` for
  passkey registration, authentication, and WebAuthn Sybil proof export.
- Added release packaging, container signing, Kubernetes hardening, and systemd
  deployment examples.

## 0.5.0

- Initial pre-1.0 workspace release.
