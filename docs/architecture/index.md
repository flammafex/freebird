# Architecture

Freebird is organized around a client, an issuer, and a verifier. The client
blinds and finalizes; the issuer applies admission policy and signs/evaluates;
the verifier validates and consumes replay state.

- [Protocol overview](protocol-overview.md) — implemented V4 and V7 paths.
- [Trust boundaries](trust-boundaries.md) — service, metadata, admin, and
  storage boundaries.
- [Data flow](data-flow.md) — request and redemption sequence.
- [Storage model](storage-model.md) — keys, registries, Redis, and local state.
- [Deployment modes](deployment-modes.md) — development and production
  topology.

The older [architecture summary](../architecture.md) remains a useful
cross-reference. Security goals, assumptions, and non-goals are authoritative
in the [threat model](../threat-model.md); operational requirements are in the
[production deployment guide](../production-deployment.md).
