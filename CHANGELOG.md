# Changelog

## 0.9.0 - 2026-08-01

- Removed the obsolete fixed-profile public bearer exchange V1 protocol,
  persistence, receipt/history paths, and accepted configuration aliases; V2
  directed graph exchange is now the only public bearer exchange protocol.
- HSM-enabled issuer startup and configuration validation now fail closed:
  `HSM_ENABLE=true` is rejected until issuer provider integration is available.
- Corrected the SDK `web_authn.subject_hash` field and the social-graph proof
  shape to match the API.
- Batch Sybil failures now return generic client-facing errors.
- Aligned configuration validation with runtime configuration behavior.
- Hardened Kubernetes deployment and bootstrap validation.
- Repaired SDK package entry points for supported import and require consumers.

## 0.8.1 - 2026-07-28

- Added policy-authorized V2 graph issuance for blind initial issuance into
  configured V4/V5 graph scopes, with durable operation recovery and private
  status capabilities.
- Added a shared Redis replay-authority protocol, append-only scope tombstones,
  explicit V4 graph authorization, and fail-closed issuer/verifier coupling.
- Hardened graph and public-bearer readiness, discovery, signer/receipt
  retention, Redis durability checks, and deployment validation.
- Added graph-issuance API, SDK, integration coverage, deployment examples, and
  recovery documentation.

## 0.8.0 - 2026-07-21

- Reworked public bearer exchange into a directed, role-neutral V2 transition
  graph with canonical descriptors, keysets, transitions, budgets, and
  admission-state lifecycle.
- Added public discovery and retention handling for active/retained graph
  profiles, receipt verification keys, and disabled-publication acknowledgements.
- Expanded durable exchange recovery, Redis spend/replay coupling, readiness,
  configuration validation, SDK support, and integration coverage.

## 0.7.5 - 2026-07-18

- Added the optional V2 public bearer exchange for atomic spending of single-use
  V5 artifacts and blind signing of configured outputs.
- Added durable Redis operation records, receipt signing, public history, key
  retention guidance, HTTP integration coverage, and JavaScript SDK support.

## 0.7.0 - 2026-07-12

- Completed the Phase A production-hardening baseline: explicit readiness,
  TLS/proxy enforcement, Redis-backed verifier replay by default, shutdown
  handling, audit logging, and safer configuration validation.
- Added the experimental Social Graph Sybil gate and standalone attester
  integration for signed trust-edge scoring and Cred-shaped attestations.
- Added hardened Kubernetes/systemd deployment assets, backup/restore tooling,
  release gating, container signing, and broader protocol/operator tests.

## 0.6.0 - 2026-06-26

- Version bump across all workspace crates.

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
