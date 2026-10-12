# Data Flow

```text
client -- blinded request + optional proof --> issuer
client <-- evaluation or blind signature -- issuer
client -- finalized V4 token -------------> verifier
verifier -- validated metadata -----------> issuer discovery
verifier -- atomic spend -----------------> Redis
```

## Issuance

The issuer checks the optional Sybil proof and evaluates a 33-byte
base64url-decoded blinded P-256 element. The client performs unblinding and
constructs the redemption token.

## Verification

`POST /v1/verify` validates the V4 token against verifier scope and
issuer-trusted private verification material. An atomic store mutation decides
whether the request is fresh.

`POST /v1/check` follows validation paths but deliberately skips the spend
mutation. It must not be used as evidence that a token has been consumed.
