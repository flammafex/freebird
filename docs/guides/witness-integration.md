# Witness integration (future/demo only)

This page describes a possible future integration in which an external witness
or attester supplies an application-specific eligibility statement before token
issuance. **No witness integration is implemented in Freebird.** This is not an
API contract and no witness, attester, trust list, or deployment guarantee
should be inferred from it.

## Conceptual boundary

A future adapter could:

1. obtain a short-lived statement from a separately operated witness;
2. validate that statement against an explicitly configured policy;
3. bind the resulting proof to the exact issuance request; and
4. submit the proof to the issuer as the configured Sybil proof.

The adapter would need an independently reviewed trust model, key discovery and
rotation process, replay handling, privacy policy, failure behavior, and audit
rules. The witness must not be treated as an implicit Freebird authority.

## What exists today

Freebird has documented Sybil proof shapes and optional social-graph/attester
configuration, but this page does not turn those features into a generic
witness integration. See [Client Sybil Proofs](../client-proofs.md) and the
[social-graph documentation](../social-graph-gate.md) for the implemented,
configuration-specific material. Do not build a client against the conceptual
steps above or claim that a witness deployment is supported.

For a demo, mock the adapter entirely inside an isolated test harness and use
synthetic statements. Do not connect it to production users, access control,
financial decisions, or other high-stakes workflows without a separate review.
