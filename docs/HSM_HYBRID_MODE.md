# HSM Status

Freebird's active issuance paths are software-backed today.

- V4 private option: P-256 VOPRF using the issuer key at `ISSUER_SK_PATH`.
- V5 public option: RFC 9474 RSA blind signatures using the key at `PUBLIC_BEARER_SK_PATH`.
- Invitation signing: P-256 ECDSA using `INVITE_SIGNING_KEY_PATH`.

The PKCS#11 provider in `freebird-crypto` is experimental. It can connect to a
PKCS#11 module and read a P-256 public key, but it does not perform VOPRF
evaluation. The issuer startup path does not route V4 or V5 issuance through an
HSM provider.

## What Works Now

Use OS and deployment controls to protect key files:

- mount key directories with `0600` file permissions;
- keep key volumes private to the issuer process;
- use container, VM, or filesystem encryption for keys at rest;
- store backup copies in an external secret manager or KMS;
- rotate V4 and V5 keys through the key rotation procedures in
  [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md).

This protects keys at rest. During issuance, V4 and V5 private key material is
loaded into issuer process memory.

## Configuration Surface

These variables are parsed by the issuer config layer:

```bash
HSM_ENABLE=true
HSM_MODE=storage
HSM_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
HSM_SLOT=0
HSM_PIN=1234
HSM_KEY_LABEL=freebird-voprf-key
```

Do not treat these settings as production HSM-backed issuance. `HSM_MODE=full`
is not implemented, and `HSM_MODE=storage` does not change the current V4 or V5
issuer path.

## PKCS#11 Provider Scope

The optional provider lives behind the `pkcs11` feature in `freebird-crypto`.
It currently supports:

- loading a PKCS#11 module;
- authenticating to a slot;
- locating a P-256 public key by label;
- exporting that public key in SEC1 compressed form.

It does not currently support:

- V4 VOPRF evaluation;
- V4 DLEQ proof generation inside the HSM;
- V5 RFC 9474 RSA blind signing;
- V5 public metadata generation from HSM-managed RSA keys;
- issuer startup integration.

## Requirements for Native HSM Issuance

V4 private issuance needs a provider that can evaluate the VOPRF over a blinded
P-256 group element and produce the proof expected by Freebird's V4 verifier.
Standard PKCS#11 ECDH and ECDSA mechanisms are not enough by themselves because
the blinded element is not a normal application public key workflow.

V5 public issuance needs an RSA provider that can produce
`RSABSSA-SHA384-PSS-Deterministic` blind signatures over the client-supplied
blinded message. The issuer must also expose matching metadata:

- `token_key_id = SHA-256(pubkey_spki_der)`;
- `token_type = public_bearer_pass`;
- `rfc9474_variant = RSABSSA-SHA384-PSS-Deterministic`;
- `spend_policy = single_use`;
- an optional audience restriction.

## Testing the Experimental Provider

PKCS#11 tests require a configured SoftHSM or hardware HSM:

```bash
cargo test -p freebird-crypto --features pkcs11 -- --ignored
```

The normal software-backed crypto tests are:

```bash
cargo test -p freebird-crypto
```

## References

- [PKCS#11 v2.40 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [YubiHSM 2 Documentation](https://developers.yubico.com/YubiHSM2/)
- [SoftHSM Documentation](https://www.opendnssec.org/softhsm/)
- [RFC 9576: The Privacy Pass HTTP Authentication Scheme](https://www.rfc-editor.org/rfc/rfc9576.html)
- [RFC 9474: RSA Blind Signatures](https://www.rfc-editor.org/rfc/rfc9474.html)
