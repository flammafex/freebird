# Protocol Overview

## V4 private verification

1. The client creates and blinds a private input.
2. It sends `POST /v1/oprf/issue` (or the batch route), including a Sybil proof
   when issuer policy requires one.
3. The issuer evaluates the blinded P-256 element and returns the evaluation,
   key ID, and issuer ID.
4. The client unblinds and builds a V4 redemption token bound to the verifier
   scope.
5. The verifier validates the token at `/v1/check` or `/v1/verify`; only the
   latter records a spend.

This construction is bespoke and not RFC 9497 interoperable.

## Discovery

The verifier refreshes V4 issuer metadata from `/.well-known/issuer`. See
[federation](../concepts/federation.md).
