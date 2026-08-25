# Blind Issuance

Blind issuance lets the client obtain an issuer response without sending the
final V4 input or V7 bearer artifact in the clear to the issuer.

## V4 flow

The client creates its input, blinds it, and sends the blinded element to
`POST /v1/oprf/issue`. After any configured admission proof passes, the issuer
returns an evaluation. The client unblinds the evaluation and builds the final
V4 redemption token bound to verifier scope.

## V7 flow

The client constructs the canonical V7 body, including its body nullifier, and
blinds the message with the randomized RSA suite. It sends the canonical
384-byte blinded message and explicit key ID to
`POST /v7/native-bearer/issue`. The issuer returns one blind signature; the
client finalizes the V7 token and later presents it to a verifier.

V7 exchange and graph issuance are optional durable operations, distinct from
direct blind issuance. Their status capabilities are bearer secrets and must
remain header-only; see [Public Bearer Exchange](../public-bearer-exchange.md).

Blindness does not remove operational metadata. IP addresses, timing,
User-Agent data, logs, or an operator controlling both services can still
enable correlation. Read the [threat model](../threat-model.md) before making
privacy claims.
