# Cryptographic Providers

This module defines Freebird's provider traits.

- `CryptoProvider` is the V4 private-option VOPRF interface.
- `BlindRsaProvider` is the V5 public-option RFC 9474 blind RSA interface.

The production issuer currently uses the software implementations for both
active token modes.

## V4 Provider

`CryptoProvider` evaluates a blinded P-256 VOPRF element and exposes the
matching public key metadata.

```rust
use freebird_crypto::provider::{create_provider, ProviderConfig};

let config = ProviderConfig::Software {
    secret_key: [42u8; 32],
    key_id: "key-2026-04".to_string(),
    context: freebird_crypto::VOPRF_CONTEXT_V4.to_vec(),
};

let provider = create_provider(config).await?;
let evaluation = provider.voprf_evaluate(blinded_element).await?;
```

Implemented V4 providers:

| Provider | Status | Notes |
|----------|--------|-------|
| `SoftwareCryptoProvider` | implemented | Used by issuer startup. |
| `Pkcs11CryptoProvider` | experimental | Can connect and read a P-256 public key; VOPRF evaluation returns an error. |

## V5 Provider

`BlindRsaProvider` signs RFC 9474 blinded messages and exposes the SPKI public
key used to compute the V5 `token_key_id`.

```rust
use freebird_crypto::provider::software::SoftwareBlindRsaProvider;
use freebird_crypto::provider::BlindRsaProvider;

let provider = SoftwareBlindRsaProvider::generate(2048)?;
let blind_signature = provider.blind_sign(blinded_msg).await?;
let token_key_id = provider.token_key_id();
```

Implemented V5 providers:

| Provider | Status | Notes |
|----------|--------|-------|
| `SoftwareBlindRsaProvider` | implemented | Used by issuer startup for V5 public bearer passes. |
| PKCS#11 / HSM RSA provider | not implemented | Needed for native HSM-backed V5 issuance. |

## PKCS#11 Scope

The optional `pkcs11` feature exposes `Pkcs11CryptoProvider` for V4 provider
experiments. It currently supports module loading, login, public-key lookup, and
P-256 public-key export.

It does not currently support:

- V4 VOPRF evaluation;
- V4 DLEQ proof generation inside the HSM;
- V5 RSA blind signing;
- issuer startup integration.

Standard PKCS#11 ECDH and ECDSA mechanisms do not directly provide Freebird's
V4 operation, which is scalar multiplication over a blinded group element plus
the proof format expected by the V4 protocol.

## Tests

Software provider tests:

```bash
cargo test -p freebird-crypto
```

PKCS#11 tests require a configured SoftHSM or hardware HSM:

```bash
cargo test -p freebird-crypto --features pkcs11 -- --ignored
```

## References

- [PKCS#11 v2.40 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [RFC 9474: RSA Blind Signatures](https://www.rfc-editor.org/rfc/rfc9474.html)
- [RFC 9497: Oblivious Pseudorandom Functions](https://www.rfc-editor.org/rfc/rfc9497.html)
