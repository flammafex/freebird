# Data Flow

```text
client -- blinded request + optional proof --> issuer
client <-- evaluation or blind signature -- issuer
client -- finalized V4/V7 token ----------> verifier
verifier -- validated metadata -----------> issuer discovery
verifier -- atomic spend -----------------> Redis
```

## Issuance

For V4, the issuer checks the optional Sybil proof and evaluates a 33-byte
base64url-decoded blinded P-256 element. The client performs unblinding and
constructs the redemption token. For V7, the issuer checks the explicit active
key ID, validates the 384-byte blinded message, applies admission policy, and
returns a randomized-RSA blind signature.

## Verification

`POST /v1/verify` dispatches by the token's version byte. V4 verification checks
scope and issuer-trusted private verification material. V7 verification parses
the canonical envelope, resolves issuer ID and token key ID from the trusted
V7 snapshot, checks policy/signature/time, and derives a body-nullifier spend
key. An atomic store mutation decides whether the request is fresh.

`POST /v1/check` follows validation paths but deliberately skips the spend
mutation. It must not be used as evidence that a token has been consumed.

## Durable public operations

Optional V7 exchange requests use a public, non-secret 16-byte operation ID and
a separate 32-byte status capability. The capability is accepted in exactly
one header and is never a body or URL value. Exact retries recover committed
responses without signing or spending twice. See [Public Bearer
Exchange](../public-bearer-exchange.md).
