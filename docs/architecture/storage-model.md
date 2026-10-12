# Storage Model

## Issuer

Issuer persistence can include:

- V4 issuer secret key and key-rotation state;
- invitation, progressive-trust, diversity, vouching, and social-graph state;
- Sybil replay records, when configured for Redis;
- optional WebAuthn credentials and audit log data.

## Verifier

The verifier stores token replay identities in Redis by default. V4 spend
records are non-expiring because V4 has no issuer-enforced expiry. A
process-local map is only an explicit development backend.

## WebAuthn and Redis

WebAuthn credential storage can use Redis; without it the current subsystem can
use in-memory credential storage, which is not restart-safe. WebAuthn proof
replay uses the issuer Sybil replay-store choice.

For production Redis topology, AOF durability, no-eviction policy, backup, and
recovery requirements, follow [production deployment](../production-deployment.md).
