# Concepts

Freebird is a Rust service pair for issuing and redeeming privacy-preserving
tokens. A client submits a blinded request to an issuer, finishes the token
locally, and later presents it to a verifier. The verifier validates the token
and atomically records a spend handle.

The implemented token families are:

- **V4**: a Freebird-specific, bespoke P-256 VOPRF-like private-verification
  construction. It is not RFC 9497 or Privacy Pass interoperable.
- **V7**: native bearer tokens using randomized RSA blind signatures and
  issuer-published discovery metadata.

V5 and V2 are removed and rejected. V6 is reserved and rejected. Start with
[issuers](issuers.md), [verifiers](verifiers.md), and [tokens](tokens.md), then
follow the [protocol overview](../architecture/protocol-overview.md).

## Status vocabulary

These pages use **implemented** for behavior present in the current source,
**expected** for an operator or client requirement stated by current
documentation, and **future** for material that is not a current protocol
contract. Future interoperability or profile work requires maintainer review.

Security boundaries and deployment assumptions are summarized in the
[threat model](../threat-model.md) and [production deployment
baseline](../production-deployment.md).
