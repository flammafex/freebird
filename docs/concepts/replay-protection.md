# Replay Protection

Freebird has two related replay controls:

1. the verifier records token spends; and
2. issuer-side admission mechanisms may record accepted proof identities.

Both require shared durable state when a service can restart or run more than
one instance.

## Verifier token replay

The verifier uses an atomic set-if-absent operation. For V4, Redis uses an
atomic Lua `SETNX` without expiry because V4 has no issuer-enforced expiration.
For V7, Redis uses `SET NX EXAT` with an absolute expiry at
`valid_until + 1`; this preserves the inclusive `valid_until` validity second.
The operation returns fresh or already-present; only fresh spends are accepted.

```bash
REDIS_URL=redis://redis:6379
VERIFIER_ENV=production
IN_MEMORY_REPLAY_STORE=false
```

Redis is required by default. In-memory replay is explicitly limited to
development:

```bash
VERIFIER_ENV=development
IN_MEMORY_REPLAY_STORE=true
```

This loses all replay state on restart and does not coordinate instances.

## Sybil-proof replay

PoW, WebAuthn, multi-party vouching, and social-graph proof paths can record
accepted proofs. The configured issuer replay backend is process-local memory
by default; choose Redis for restart-safe and horizontally scaled admission
replay:

```bash
SYBIL_REPLAY_STORE=redis
SYBIL_REPLAY_REDIS_URL=redis://redis:6379
```

The same Redis durability and access controls should be reviewed with the
[threat model](../threat-model.md) and [production deployment
requirements](../production-deployment.md).

## Boundary

Replay rejection is not proof that a client is a unique human, nor does it
hide network timing, logs, or application identifiers. It only prevents reuse
of the recorded identity under the implemented namespace rules.
