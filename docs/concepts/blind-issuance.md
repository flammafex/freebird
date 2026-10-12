# Blind Issuance

Blind issuance lets the client obtain an issuer response without sending the
final V4 input in the clear to the issuer.

## V4 flow

The client creates its input, blinds it, and sends the blinded element to
`POST /v1/oprf/issue`. After any configured admission proof passes, the issuer
returns an evaluation. The client unblinds the evaluation and builds the final
V4 redemption token bound to verifier scope.

Blindness does not remove operational metadata. IP addresses, timing,
User-Agent data, logs, or an operator controlling both services can still
enable correlation. Read the [threat model](../threat-model.md) before making
privacy claims.
