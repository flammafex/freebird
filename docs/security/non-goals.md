# Security Non-Goals

These are explicit limits on what Freebird should be understood to provide.
They apply to the current transitional issuance API and to public deployments
unless a future, independently reviewed profile says otherwise. Freebird is
pre-1.0, experimental for public deployment, and has no external security audit.

## Admission and identity

- Freebird is not global bot detection.
- Freebird does not prove that a user is a unique human.
- Freebird does not prevent every farm of real devices, real accounts, or real
  invitations.
- A Sybil mode is a local issuer policy. Its result does not transfer to another
  issuer, route, key domain, or verifier.
- `SYBIL_RESISTANCE=none` provides no token-farming resistance and is intended
  only for local testing or a deliberately trusted issuer.
- Combined `or` mode is a fallback policy, not a stronger security boundary.

## Privacy and observation

- Token-layer unlinkability is not anonymity against a party controlling both
  issuer and verifier.
- Freebird does not prevent timing, IP, User-Agent, browser-fingerprint,
  application-account, proxy, hosting, or audit-log correlation.
- Freebird does not force a malicious verifier or issuer to minimize, protect,
  or delete logs.
- TLS does not hide metadata from the endpoints or their operators.
- Audit logs are not tamper-evident security evidence.

## Availability and lifecycle

- In-memory verifier replay state is not restart-safe.
- Process-local Sybil proof replay state is not restart-safe or safe for a
  multi-instance issuer. Redis must be configured before making that claim.
- Current key and state files do not constitute HSM-backed key custody.
- A successful local round trip is not evidence of production readiness,
  high availability, or disaster-recovery correctness.

## Cryptographic and standards claims

- V4 is not an RFC 9497 interoperable VOPRF implementation.
- Existing regression tests and known-answer fixtures are not an external audit,
  formal security proof, or standards-conformance result.
- Freebird does not claim that a named future profile exists merely because it is
  described in planning documentation.

## Product and governance claims

- Freebird does not define a universal identity, reputation, voting, or
  proof-of-personhood product.
- Optional future integrations or demonstrations must not be represented as
  current products or as guarantees supplied by Freebird.
