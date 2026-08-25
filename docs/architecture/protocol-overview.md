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

## V7 native bearer

1. The client constructs the fixed body and blinds its RSA message.
2. It sends the explicit key ID and blinded message to
   `POST /v7/native-bearer/issue` (or batch).
3. The issuer validates the active key and any admission proof, then returns a
   blind signature.
4. The client finalizes the V7 token.
5. The verifier validates it against the issuer's strict V7 discovery and
   atomically consumes the body-nullifier replay identity.

V7 also has optional durable exchange and graph-issuance routes. They are not
legacy V2/V5 compatibility paths. V5 and V2 are removed; V6 is reserved.

## Discovery

The verifier refreshes `/.well-known/keys` for V7. The separate V4
`/.well-known/replay-authority` metadata and graph probe attest replay-authority
relationships only. See [federation](../concepts/federation.md).
