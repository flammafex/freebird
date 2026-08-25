# Tokens

Freebird currently accepts two token families: V4 and V7.

## V4 private-verification token

V4 is a bespoke P-256 VOPRF-like construction using the `freebird:v4` context.
It is not RFC 9497 compatible. The final redemption-token wire format is:

```text
[version(1) | nonce(32) | scope_digest(32) | kid_len(1) | kid
 | issuer_id_len(1) | issuer_id | authenticator(32)]
```

The client receives an issuer evaluation from `/v1/oprf/issue`, unblinds it,
and constructs the final token. The authenticator is the unblinded result over
the issuer ID, key ID, nonce, and verifier-scope digest. The verifier
recomputes it with issuer-trusted private verification material.

## V7 native bearer token

V7 uses randomized RSA blind signatures. Its canonical body includes the
configured asset ID and minor amount, issuer/key identity, a nonce, a 32-byte
body nullifier, and an owner commitment. The envelope carries the V7 dispatch
version, message randomizer, and RSA signature. The verifier checks the body
policy, discovered binding, signature, and inclusive validity window.

V7 direct issuance is exposed at `/v7/native-bearer/issue`; optional durable
exchange and graph issuance are separate V7 operations. See
[blind issuance](blind-issuance.md).

## Version status

V4 and V7 are implemented. V5 public bearer passes and V2 exchange/issuance
are removed and rejected. V6 is reserved and rejected. No compatibility or
interoperability claim should be inferred from a version number.

For security goals, non-goals, and metadata leakage limits, read the [threat
model](../threat-model.md).
