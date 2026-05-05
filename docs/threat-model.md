# Threat Model

This document describes the current security model for Freebird. It is not a
formal audit.

## Security Goals

Freebird aims to provide:

- unlinkability between token issuance and token redemption
- verifier-side double-spend rejection
- issuer-controlled admission policy through configurable Sybil gates
- bounded operational state for key rotation, nullifiers, and Sybil mechanisms
- deployability by small operators without relying on a central CAPTCHA or
  identity provider

## Non-Goals

Freebird does not currently provide:

- global bot detection
- proof that a user is a unique human
- protection against all farms of real devices or real invited accounts
- anonymity against an operator who controls both issuer and verifier and also
  correlates timing, network metadata, logs, or application behavior
- tamper-evident audit logging
- restart-safe or multi-instance Sybil proof replay protection unless the
  issuer is configured with a shared replay store

## Assets

Important assets include:

- issuer secret keys
- verifier private verification keys or keyrings
- Redis nullifier state
- Sybil persistence files and HMAC secrets
- WebAuthn credential storage and proof secret
- admin API key and session cookies
- audit logs and exported audit data

## Actors

| Actor | Capability |
| --- | --- |
| Honest client | Requests and redeems tokens according to the protocol. |
| Token farmer | Attempts to obtain many tokens cheaply. |
| Replay attacker | Reuses tokens or Sybil proofs. |
| Malicious verifier | Attempts to link redemptions or accept invalid tokens. |
| Malicious issuer | Attempts to issue outside policy or log identifying metadata. |
| Network attacker | Observes or modifies traffic when TLS/proxy policy is wrong. |
| Admin attacker | Obtains admin key/session or access to service storage. |

## Assumptions

- Production traffic uses HTTPS, and services run with `REQUIRE_TLS=true`.
- Reverse proxies are configured correctly before `BEHIND_PROXY=true` is used.
- Admin routes are protected by strong secrets and network access controls.
- Issuer and verifier keys are stored on protected persistent storage.
- Public verifier deployments use Redis for nullifier storage.
- Operators understand that Sybil mode choice determines token-farming
  resistance.

## Privacy Model

The cryptographic token flow is designed so that a verifier can validate a
token without learning the issuance request that produced it. This does not hide
all metadata. Operators can still correlate by:

- client IP address
- User-Agent and browser fingerprinting performed outside Freebird
- request timing
- application account identifiers
- logs from reverse proxies or hosting providers

If issuer and verifier are run by the same operator, operational separation and
log minimization matter.

## Replay Model

Verifier token replay is handled by nullifier storage. Redis-backed nullifier
storage is the production path. In-memory nullifier storage is suitable for
local testing and loses replay state on restart.

Sybil proof replay protection currently exists for proof-of-work, WebAuthn gate
proofs, and multi-party vouching proofs. The default replay store is
process-local memory, which protects a single running issuer process. Configure
`SYBIL_REPLAY_STORE=redis` with `SYBIL_REPLAY_REDIS_URL` or `REDIS_URL` before
claiming restart-safe or horizontally scaled Sybil proof replay protection.

## Sybil Model

Sybil resistance happens before issuance. Each mode makes a different tradeoff:

- proof-of-work raises marginal cost
- rate limiting throttles observed network identity
- invitations encode local social trust
- WebAuthn binds issuance to registered authenticators
- progressive trust slows fresh identities
- proof-of-diversity scores observed diversity
- multi-party vouching requires existing trusted accounts to endorse a user

None of these alone proves global human uniqueness. Combined modes should be
configured conservatively. `SYBIL_COMBINED_MODE=or` accepts the easiest passing
mechanism, so it is useful for fallback UX but weak as a security boundary.

## Current High-Priority Gaps

- production deployment examples for Redis-backed Sybil replay storage
- HTTP integration tests covering every Sybil mode and public issuance route
- operator-facing admin workflows for all Sybil state
- clearer production examples for WebAuthn attestation and combined modes
- documented log retention and privacy policy for deployed services
