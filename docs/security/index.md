# Freebird Security Documentation

Freebird is pre-1.0 software. Public deployments are experimental and must be
reviewed against the operator's own threat model, configuration, and operational
controls. The project has not had an external security audit.

This section separates what the current implementation is intended to do from
deployment assumptions, known limits, and future work. It is not a security
certification, a production-readiness statement, or a promise of anonymity.

## Pages

- [Threat model](threat-model.md) — actors, assets, security properties, threats,
  assumptions, and non-goals.
- [Privacy properties](privacy-properties.md) — the token-layer privacy claim
  and the metadata that remains visible to surrounding systems.
- [Non-goals](non-goals.md) — claims Freebird does not make.
- [Cryptographic assumptions](cryptographic-assumptions.md) — the assumptions
  behind the current V4 and V7 token flows, without claiming formal proof or
  interoperability.
- [Audit status](audit-status.md) — current review status, operational logging,
  and known security exceptions.

## Current boundary

The current issuance API is transitional and experimental. V4 uses a
Freebird-specific bespoke P-256 VOPRF-like construction and is not RFC 9497
interoperable. V7 uses randomized RSA blind signatures and issuer-published
discovery metadata. In both cases, the client obtains a blinded issuance result,
finalizes a token, and the verifier checks and consumes a replay identity or
nullifier.

Optional Sybil mechanisms are issuer admission controls. They can raise cost,
apply local quotas, or require configured credentials, but none proves global
human uniqueness. A weak or disabled Sybil configuration can allow token farming
even when token verification works as intended.

## Operational minimum

For an internet-exposed deployment, the repository security guidance calls for
TLS, a high-entropy admin key, protected key and state storage, Redis-backed
verifier nullifiers, and Redis-backed Sybil-proof replay protection. In-memory
replay storage is an explicitly unsafe development option: verifier nullifiers
are lost on verifier restart, and the default Sybil replay store is process
local unless configured otherwise.

See the root [Security Policy](https://github.com/flammafex/freebird/blob/main/SECURITY.md) and the repository's existing
deployment and Sybil documentation for configuration details.
