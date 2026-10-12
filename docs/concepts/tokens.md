# Tokens

Freebird currently issues and verifies V4 private-verification tokens.

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

For security goals, non-goals, and metadata leakage limits, read the [threat
model](../threat-model.md).
