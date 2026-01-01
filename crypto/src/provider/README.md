# Cryptographic Provider Abstraction

This module provides a pluggable architecture for cryptographic operations in Freebird, supporting both software-based and hardware security module (HSM) backends.

## Architecture

```
┌─────────────────────┐
│  CryptoProvider     │  ← Trait interface
│   (trait)           │
└──────────┬──────────┘
           │
    ┌──────┴───────┐
    │              │
    ▼              ▼
┌─────────┐   ┌──────────┐
│Software │   │ PKCS#11  │
│Provider │   │ Provider │
└─────────┘   └──────────┘
    │              │
    ▼              ▼
┌─────────┐   ┌──────────┐
│  p256   │   │   HSM    │
│  crate  │   │ (YubiHSM,│
│         │   │ SoftHSM) │
└─────────┘   └──────────┘
```

## Providers

### Software Provider

**Use case:** Development, testing, non-critical deployments

**Pros:**
- No hardware required
- Fast and simple
- Easy to test

**Cons:**
- Keys stored in RAM (vulnerable to memory dumps)
- No hardware protection
- Not suitable for high-security deployments

**Example:**
```rust
use crypto::provider::{ProviderConfig, create_provider};

let config = ProviderConfig::Software {
    secret_key: [42u8; 32],
    key_id: "key-2024-01".to_string(),
    context: b"freebird-v1".to_vec(),
};

let provider = create_provider(config).await?;
```

### PKCS#11 Provider

**Use case:** Production deployments requiring hardware key protection

**Pros:**
- Secret keys never leave HSM
- Hardware tamper resistance
- Audit logging
- Physical security

**Cons:**
- Requires HSM hardware or SoftHSM
- More complex setup
- **Current limitation:** VOPRF evaluation not yet implemented (requires vendor-specific extensions)

**Supported HSMs:**
- YubiHSM 2
- Nitrokey HSM
- SoftHSM (for testing)
- Any PKCS#11-compatible HSM

**Example:**
```rust
use crypto::provider::{ProviderConfig, create_provider};

let config = ProviderConfig::Pkcs11 {
    module_path: "/usr/lib/libykcs11.so".to_string(),  // YubiHSM
    slot: 0,
    pin: "123456".to_string(),
    key_label: "freebird-voprf-key".to_string(),
    key_id: "key-2024-01".to_string(),
    context: b"freebird-v1".to_vec(),
};

let provider = create_provider(config).await?;
```

## Operations

### VOPRF Evaluation

Performs P-256 scalar multiplication: `B = k * A` where `k` is the secret key and `A` is the blinded element.

```rust
// Blinded element (33-byte SEC1 compressed P-256 point)
let blinded: &[u8] = &[0x02, /* ... 32 more bytes ... */];

// Evaluate
let token = provider.voprf_evaluate(blinded).await?;

// Returns: [VERSION||A||B||DLEQ_proof] (131 bytes)
assert_eq!(token.len(), 131);
```

**Status:**
- ✅ Software: Fully implemented
- ⚠️ PKCS#11: Not yet implemented (requires vendor-specific extensions)

### MAC Key Derivation

Derives epoch-specific MAC keys using HKDF for token metadata binding.

```rust
let mac_key = provider.derive_mac_key(
    "issuer-id",    // Issuer identifier
    "key-2024-01",  // Key ID
    12345,          // Epoch number
).await?;

// Returns: 32-byte HMAC-SHA256 key
assert_eq!(mac_key.len(), 32);
```

**Status:**
- ✅ Software: Uses HKDF directly on secret key
- ✅ PKCS#11: Derives base key from HSM, then HKDF in software

### Public Key Export

Returns the P-256 public key in SEC1 compressed format (33 bytes).

```rust
let pubkey = provider.public_key();
assert_eq!(pubkey.len(), 33);
```

## HSM Setup Guide

### SoftHSM (for testing)

1. **Install SoftHSM:**
   ```bash
   # Ubuntu/Debian
   sudo apt install softhsm2

   # macOS
   brew install softhsm
   ```

2. **Initialize token:**
   ```bash
   softhsm2-util --init-token --slot 0 --label "freebird-test" --pin 1234 --so-pin 1234
   ```

3. **Generate P-256 key:**
   ```bash
   pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
               --login --pin 1234 \
               --keypairgen --key-type EC:secp256r1 \
               --label "freebird-voprf-key"
   ```

4. **Configure Freebird:**
   ```bash
   export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
   export PKCS11_SLOT=0
   export PKCS11_PIN=1234
   export PKCS11_KEY_LABEL="freebird-voprf-key"
   ```

### YubiHSM 2

1. **Install YubiHSM libraries:**
   ```bash
   # Follow: https://developers.yubico.com/YubiHSM2/
   ```

2. **Initialize YubiHSM:**
   ```bash
   yubihsm-setup
   ```

3. **Generate P-256 key:**
   ```bash
   # Use yubihsm-shell to generate asymmetric key
   # Algorithm: ecp256
   # Capabilities: sign-ecdsa, derive-ecdh
   ```

4. **Configure Freebird:**
   ```bash
   export PKCS11_MODULE="/usr/lib/libykcs11.so"
   export PKCS11_SLOT=0
   export PKCS11_PIN="<your-auth-key-password>"
   export PKCS11_KEY_LABEL="freebird-voprf-key"
   ```

### Nitrokey HSM

1. **Install OpenSC:**
   ```bash
   sudo apt install opensc
   ```

2. **Initialize Nitrokey:**
   ```bash
   sc-hsm-tool --initialize --so-pin 3537363231383830 --pin 648219
   ```

3. **Generate P-256 key:**
   ```bash
   pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
               --login --pin 648219 \
               --keypairgen --key-type EC:secp256r1 \
               --label "freebird-voprf-key"
   ```

## Current Limitations

### PKCS#11 VOPRF Evaluation

The PKCS#11 provider does not yet implement VOPRF evaluation because:

1. **No standard operation:** PKCS#11 doesn't define a "scalar multiply arbitrary point" operation
2. **ECDH limitations:** CKM_ECDH1_DERIVE requires a valid peer public key, but blinded elements are arbitrary curve points
3. **Vendor extensions needed:** YubiHSM has raw crypto commands, but they're vendor-specific

**Workarounds:**

1. **Use software provider** for now (keys in RAM)
2. **Implement vendor-specific extensions** for your HSM:
   - YubiHSM: Use `YHM_ECHO` + raw crypto operations
   - Other HSMs: Check vendor documentation for custom mechanisms

**Future work:**

- Implement YubiHSM-specific VOPRF evaluation
- Add support for other HSM vendors
- Consider using HSM only for MAC key protection, software for VOPRF

## Testing

### Unit Tests

```bash
# Test software provider
cargo test --lib -p crypto

# Test PKCS#11 provider (requires SoftHSM)
cargo test --lib -p crypto --features pkcs11
```

### Integration Tests

```bash
# End-to-end test with SoftHSM
./scripts/test-hsm-integration.sh
```

## Security Considerations

### Software Provider

- ✅ Constant-time operations (via subtle crate)
- ✅ Zeroization of sensitive data
- ⚠️ Keys vulnerable to memory dumps
- ⚠️ No protection against cold boot attacks
- ⚠️ Process memory accessible to root

**Mitigation:** Use HSM provider for production

### PKCS#11 Provider

- ✅ Secret keys never leave HSM
- ✅ Hardware tamper resistance (HSM-dependent)
- ✅ Access control via PIN
- ⚠️ MAC derivation in software (base key from HSM)
- ⚠️ VOPRF evaluation not implemented yet

**Best practices:**

1. Use hardware HSM (not SoftHSM) in production
2. Store HSM PIN securely (env var, secrets manager)
3. Rotate keys regularly (epoch-based)
4. Monitor HSM audit logs
5. Use separate HSMs for different environments

## Migration Path

### From Software to HSM

1. **Generate new key in HSM**
2. **Use key rotation:** Add HSM key while keeping software key
3. **Grace period:** Both keys valid for token verification
4. **Cutover:** New tokens use HSM key
5. **Cleanup:** Remove software key after grace period

Example:
```rust
// Current: software provider
let software_provider = create_software_provider(sk, kid1, ctx)?;

// Add HSM key
let hsm_provider = create_pkcs11_provider(module, slot, pin, label, kid2, ctx)?;

// Rotate using MultiKeyVoprfCore
multi_key.rotate_key_with_provider(hsm_provider).await?;

// After 30 days: cleanup old software key
multi_key.force_remove_key(kid1).await?;
```

## Performance

### Benchmarks (approximate)

| Operation | Software | SoftHSM | YubiHSM 2 |
|-----------|----------|---------|-----------|
| VOPRF Eval | 200 µs | N/A | N/A |
| MAC Derive | 10 µs | 50 µs | 100 µs |
| Pubkey Get | 1 µs | 1 µs | 1 µs |

**Notes:**
- Software: Pure Rust, optimized
- SoftHSM: Software emulation with IPC overhead
- YubiHSM 2: USB communication latency

## Troubleshooting

### "PKCS#11 module not found"

```bash
# Find PKCS#11 module path
find /usr -name "*.so" | grep -E "(pkcs11|softhsm|ykcs11)"

# Common locations:
# - SoftHSM: /usr/lib/softhsm/libsofthsm2.so
# - YubiHSM: /usr/lib/libykcs11.so
# - OpenSC: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
```

### "Key not found in HSM"

```bash
# List objects in HSM
pkcs11-tool --module <path> --login --pin <pin> --list-objects
```

### "Invalid slot number"

```bash
# List available slots
pkcs11-tool --module <path> --list-slots
```

## References

- [PKCS#11 v2.40 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [YubiHSM 2 Documentation](https://developers.yubico.com/YubiHSM2/)
- [SoftHSM Documentation](https://www.opendnssec.org/softhsm/)
- [RFC 9380: Hash to Elliptic Curve](https://www.rfc-editor.org/rfc/rfc9380)
- [VOPRF Draft Specification](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf)
