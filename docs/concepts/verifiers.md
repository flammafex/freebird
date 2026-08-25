# Verifiers

The verifier accepts configured token families, validates them against its
trust material, and consumes a replay identity on `/v1/verify`.

## Implemented endpoints

- `POST /v1/verify` validates and consumes a token.
- `POST /v1/check` validates without consuming it.
- `POST /v1/verify/batch` verifies a batch and records each successful spend.
- `GET /.well-known/verifier` publishes `verifier_id`, `audience`, and the V4
  scope digest.
- `GET /health` and `GET /ready` expose liveness/readiness checks.

The verifier refreshes issuer metadata from `ISSUER_URL` or `ISSUER_URLS`.
Those inputs are normalized to `/.well-known/keys` for V7 trust. V4 uses
issuer-authorized verification material and the verifier's configured scope;
V7 uses a fully validated V7 discovery container and retained key bindings.

## Scope and trust

V4 tokens are bound to `(verifier_id, audience)` through a scope digest. A V7
token is checked against the issuer ID and typed V7 token key ID in its body,
the discovered public key and body policy, and its validity window.

The verifier must not treat graph-authority metadata as a V7 key source. The
separate V4 replay-authority relationship is described in [federation](federation.md)
and [trust boundaries](../architecture/trust-boundaries.md).

## Replay storage

Redis is the implemented restart-safe and multi-instance backend. In-memory
replay is permitted only with `IN_MEMORY_REPLAY_STORE=true` and
`VERIFIER_ENV=development`; it loses state on restart and is not suitable for
production. See [replay protection](replay-protection.md).
