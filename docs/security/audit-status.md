# Audit Status

## Current status

Freebird is pre-1.0 and public deployments are experimental. The project has
not had an external security audit. No page in this documentation is an audit
report, certification, formal proof, or production-readiness approval.

The repository contains automated tests, protocol regression fixtures, negative
cases, and deployment guidance. Those activities provide engineering feedback;
they do not replace independent cryptographic, application, infrastructure, or
privacy review.

## Known security boundaries

- V4 is a bespoke, Freebird-specific P-256 VOPRF-like construction and is not
  RFC 9497 interoperable.
- Redis-backed verifier nullifiers are the production path. In-memory verifier
  nullifiers are an explicit development option and lose replay state on restart.
- PoW, WebAuthn, multi-party vouching, and social-graph proof replay protection
  defaults to process-local memory. `SYBIL_REPLAY_STORE=redis` is required for
  restart-safe or multi-instance issuer behavior.
- `SYBIL_RESISTANCE=none` has no token-farming resistance.
- Combined Sybil `or` mode is only as strong as the easiest configured mechanism.
- WebAuthn attestation is policy-gated and does not prove a unique human.
- Audit logs are operational JSON records, not append-only or tamper-evident
  security logs. They can contain identifiers and should be treated as
  sensitive.
- Admin APIs depend on admin keys/session cookies and should be isolated by TLS,
  network policy, and proxy/VPN controls.

## Dependency audit conditions

CI runs `cargo audit` without advisory ignores. It currently reports
RUSTSEC-2024-0436 (`paste` 1.0.15, unmaintained) through the optional PKCS#11
dependency path as an allowed warning under cargo-audit's default warning
policy. The optional PKCS#11 feature is not enabled by default, and its provider
has not been validated against real HSM hardware or SoftHSM; see the
repository-level `SECURITY.md` (“Dependency Audit Notes”).

## Operational logging

Issuer audit logging records administrative activity such as invitations, user
state changes, vouching, WebAuthn-related events, and key rotation. Storage is
local JSON with bounded entry count and restrictive file handling, but it is not
tamper-evident. Current entries can include user IDs, invite data, admin IDs,
and free-form details. Retention, access, encryption at rest, proxy-log
duplication, and incident handling remain deployment responsibilities.

## Review priorities

The bounded next review targets are durable shared replay state, complete Sybil
mode integration coverage, operator workflows and persistence, WebAuthn and
combined-mode deployment guidance, and an explicit log-retention/privacy policy.
An external review should occur before any broader production or anonymity
claim. Until then, operators should pin a reviewed commit and inspect changes
deliberately.
