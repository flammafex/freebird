# Storage Model

## Issuer

Issuer persistence can include:

- V4 issuer secret key and key-rotation state;
- V7 RSA private key, public metadata, and append-only registry;
- invitation, progressive-trust, diversity, vouching, and social-graph state;
- Sybil replay records, when configured for Redis;
- optional WebAuthn credentials and audit log data;
- optional V7 exchange/graph operation records, spend markers, budgets, and
  replay-authority state.

V7 discovery/history and retained public verification material must be kept
coherent with private signers and Redis operation state. Do not restore only one
part of that set.

## Verifier

The verifier stores token replay identities in Redis by default. V4 spend
records are non-expiring because V4 has no issuer-enforced expiry. V7 records
expire through the inclusive validity endpoint. A process-local map is only an
explicit development backend.

The verifier also keeps in-process issuer metadata and a process-lifetime V7
trust history. V7 retained bindings cannot silently disappear or be rebound in
later discovery snapshots.

## WebAuthn and Redis

WebAuthn credential storage can use Redis; without it the current subsystem can
use in-memory credential storage, which is not restart-safe. WebAuthn proof
replay uses the issuer Sybil replay-store choice.

For production Redis topology, AOF durability, no-eviction policy, backup, and
recovery requirements, follow [production deployment](../production-deployment.md).
