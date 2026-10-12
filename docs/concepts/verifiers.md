# Verifiers

The verifier validates V4 tokens against its trust material and consumes a
replay identity on `/v1/verify`.

## Implemented endpoints

- `POST /v1/verify` validates and consumes a token.
- `POST /v1/check` validates without consuming it.
- `POST /v1/verify/batch` verifies a batch and records each successful spend.
- `GET /.well-known/verifier` publishes `verifier_id`, `audience`, and the V4
  scope digest.
- `GET /health` and `GET /ready` expose liveness/readiness checks.

The verifier refreshes V4 issuer metadata from `ISSUER_URL` or `ISSUER_URLS`
and uses issuer-authorized verification material with its configured scope.

## Scope and trust

V4 tokens are bound to `(verifier_id, audience)` through a scope digest.

## Replay storage

Redis is the implemented restart-safe and multi-instance backend. In-memory
replay is permitted only with `IN_MEMORY_REPLAY_STORE=true` and
`VERIFIER_ENV=development`; it loses state on restart and is not suitable for
production. See [replay protection](replay-protection.md).
