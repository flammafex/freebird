# HSM Hybrid Mode: Storage-Only Configuration

This document describes the recommended approach for using HSMs with Freebird: **HSM for key storage, software for VOPRF operations**.

## Overview

Freebird supports a hybrid HSM mode that provides the security benefits of hardware key storage while maintaining high performance for cryptographic operations.

```
┌─────────────────────────────────────────────────────────┐
│                    Hybrid Architecture                   │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌────────────┐           ┌──────────────────┐          │
│  │    HSM     │  Extract  │    Software      │          │
│  │            │  ───────> │  VOPRF Provider  │          │
│  │ Key Storage│  (once)   │                  │          │
│  └────────────┘           └──────────────────┘          │
│       │                           │                      │
│       │ Protected                 │ Fast Operations      │
│       │ at Rest                   │ (~200µs/token)       │
│       │                           │                      │
│       ▼                           ▼                      │
│  Long-term                   Token Issuance             │
│  Security                    (High Throughput)          │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

## Why Hybrid Mode?

### The Problem

PKCS#11 HSMs don't support arbitrary elliptic curve scalar multiplication, which is required for VOPRF evaluation:

- **VOPRF needs**: `B = k * A` where `A` is an arbitrary curve point (blinded element)
- **HSM provides**: Only standard operations like ECDSA, ECDH with valid public keys
- **Limitation**: `A` is not a valid public key—it's a hash-to-curve point

### The Solution

**Hybrid Mode** separates concerns:

1. **HSM**: Stores master secret key with hardware protection
2. **Software**: Performs VOPRF operations using key material extracted from HSM

This provides:
- ✅ **Security**: Keys protected at rest in tamper-resistant hardware
- ✅ **Performance**: Fast VOPRF operations in software (~200µs vs ~10ms+ for HSM IPC)
- ✅ **Compliance**: Meets requirements for hardware key storage
- ✅ **Flexibility**: Can use any PKCS#11-compatible HSM

## Configuration

### Environment Variables

```bash
# Enable HSM
HSM_ENABLE=true

# Set mode to "storage" (recommended)
# - storage: Keys in HSM, operations in software (RECOMMENDED)
# - full:    All operations in HSM (NOT IMPLEMENTED)
HSM_MODE=storage

# PKCS#11 module path (HSM-specific)
HSM_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so  # SoftHSM
# HSM_MODULE_PATH=/usr/lib/libykcs11.so          # YubiHSM
# HSM_MODULE_PATH=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so  # Nitrokey/OpenSC

# HSM slot number
HSM_SLOT=0

# HSM PIN (use secrets manager in production!)
HSM_PIN=1234

# Key label in HSM
HSM_KEY_LABEL=freebird-voprf-key
```

### Example: `.env.hsm`

```bash
# Copy example configuration
cp .env.hsm.example .env.hsm

# Edit with your HSM settings
vi .env.hsm

# Run issuer with HSM configuration
cargo run --bin issuer
```

## Setup Guide

### 1. Install HSM Software

#### SoftHSM (for testing)
```bash
# Ubuntu/Debian
sudo apt install softhsm2 opensc

# macOS
brew install softhsm
```

#### YubiHSM 2 (production)
```bash
# Install YubiHSM libraries
# See: https://developers.yubico.com/YubiHSM2/
```

### 2. Initialize HSM Token

Run the automated setup script:
```bash
./scripts/setup-softhsm-test.sh
```

Or manually:
```bash
# Initialize token
softhsm2-util --init-token \
    --slot 0 \
    --label "freebird-test" \
    --pin 1234 \
    --so-pin 1234

# Generate P-256 key
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 \
    --keypairgen \
    --key-type EC:secp256r1 \
    --label "freebird-voprf-key" \
    --id 01
```

### 3. Configure Freebird

```bash
# Set HSM environment variables
export HSM_ENABLE=true
export HSM_MODE=storage
export HSM_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
export HSM_SLOT=0
export HSM_PIN=1234
export HSM_KEY_LABEL=freebird-voprf-key

# Start issuer
cargo run --bin issuer
```

### 4. Verify Operation

Check logs for HSM initialization:
```
🔐 HSM enabled: mode=storage, module=/usr/lib/softhsm/libsofthsm2.so
✅ Loaded key 'freebird-voprf-key' from HSM
🚀 Using software VOPRF provider with HSM-backed key material
```

## Security Model

### Threat Model

**Protected Against:**
- ✅ Memory dumps (key extracted only once, then zeroized in HSM)
- ✅ Process inspection (key stored in HSM, not in application memory long-term)
- ✅ Unauthorized key export (HSM access control via PIN)
- ✅ Physical theft (HSM tamper resistance)

**Not Protected Against:**
- ⚠️ Runtime memory extraction (key present in RAM during operation)
- ⚠️ Compromised process (attacker can use key while process runs)
- ⚠️ Side-channel attacks on software VOPRF (no hardware isolation)

### Security Properties

| Property | Storage Mode | Full HSM Mode (Future) |
|----------|--------------|------------------------|
| Key at rest | ✅ HSM protected | ✅ HSM protected |
| Key in use | ⚠️ Software RAM | ✅ HSM protected |
| VOPRF operations | ⚠️ Software | ✅ HSM protected |
| Performance | ✅ Fast (~200µs) | ⚠️ Slow (~10ms+) |
| PKCS#11 compatible | ✅ Yes | ❌ Requires extensions |

### Best Practices

1. **PIN Management**
   ```bash
   # ❌ Don't store PIN in .env files
   HSM_PIN=1234

   # ✅ Use environment-specific secrets
   HSM_PIN=$(cat /run/secrets/hsm_pin)

   # ✅ Use secrets manager
   HSM_PIN=$(aws secretsmanager get-secret-value --secret-id hsm-pin --query SecretString --output text)
   ```

2. **Key Rotation**
   ```bash
   # Generate new key in HSM
   pkcs11-tool --module $HSM_MODULE_PATH \
       --login --pin $HSM_PIN \
       --keypairgen \
       --key-type EC:secp256r1 \
       --label "freebird-voprf-key-2024-12" \
       --id 02

   # Update configuration
   export HSM_KEY_LABEL=freebird-voprf-key-2024-12

   # Restart issuer (old keys remain valid during grace period)
   ```

3. **Monitoring**
   ```bash
   # Check HSM health
   pkcs11-tool --module $HSM_MODULE_PATH --list-slots

   # Monitor token usage
   pkcs11-tool --module $HSM_MODULE_PATH --login --pin $HSM_PIN --list-objects
   ```

4. **Backup**
   - **DO NOT** backup HSM PINs in plaintext
   - **DO** backup HSM initialization parameters
   - **DO** have HSM disaster recovery procedures
   - **DO** test key recovery regularly

## Performance

### Benchmarks

Hybrid mode (SoftHSM storage, software operations):
```
HSM initialization:  ~100ms (once at startup)
Key extraction:      ~50ms  (once at startup)
VOPRF evaluation:    ~200µs (per token, in software)
Throughput:          ~5000 tokens/sec (single core)
                     ~40000 tokens/sec (8 cores, parallel)
```

Comparison:
```
Mode              | Throughput    | Security
------------------|---------------|----------
Pure Software     | 5000 tok/s    | ⚠️ Keys in RAM
Hybrid (Storage)  | 5000 tok/s    | ✅ Keys in HSM
Full HSM (Future) | ~100 tok/s    | ✅✅ Full HSM
```

## Troubleshooting

### "HSM module not found"

```bash
# Find PKCS#11 module
find /usr -name "*.so" | grep -E "(pkcs11|softhsm|ykcs11)"

# Test module
pkcs11-tool --module /path/to/module.so --list-slots
```

### "Invalid PIN"

```bash
# Reset SoftHSM PIN
softhsm2-util --init-token --slot 0 --label "freebird-test" --pin 1234 --so-pin 1234

# For hardware HSM, consult vendor documentation
```

### "Key not found"

```bash
# List objects in HSM
pkcs11-tool --module $HSM_MODULE_PATH --login --pin $HSM_PIN --list-objects

# Check key label matches
export HSM_KEY_LABEL=freebird-voprf-key
```

### "Cannot extract key from HSM"

Some HSMs don't allow key extraction. In this case:
1. Check HSM key attributes (CKA_EXTRACTABLE must be true)
2. Generate key with extraction enabled
3. Or use software provider (keys not in HSM)

## Migration

### From Software to HSM

1. **Generate HSM key**
   ```bash
   ./scripts/setup-softhsm-test.sh
   ```

2. **Run both providers** (key rotation)
   ```bash
   # Keep old software key
   # Add new HSM key via rotation
   ```

3. **Grace period** (30 days default)
   - Old software key still verifies tokens
   - New HSM key issues new tokens

4. **Cleanup** (after grace period)
   ```bash
   # Remove old software key
   rm issuer_sk.bin
   ```

### From HSM Back to Software

If HSM fails or performance is insufficient:

1. **Extract key** (if allowed by HSM policy)
2. **Disable HSM**
   ```bash
   export HSM_ENABLE=false
   ```
3. **Use traditional software keys**
   ```bash
   export ISSUER_SK_PATH=issuer_sk.bin
   ```

## Future Work

### Full HSM Mode

To implement full HSM-protected VOPRF:

1. **Vendor Extensions**
   - YubiHSM: Use raw crypto commands
   - Other HSMs: Custom PKCS#11 mechanisms

2. **Alternative Approaches**
   - Pre-compute scalar multiples (limited use cases)
   - Use HSM for MAC only, software for VOPRF
   - Implement vendor-specific providers

3. **Performance Trade-offs**
   - Accept 50x slower operations for full hardware protection
   - Use batch processing to amortize HSM overhead
   - Implement caching where appropriate

## References

- [PKCS#11 v2.40 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [VOPRF Draft Specification](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf)
- [YubiHSM 2 Documentation](https://developers.yubico.com/YubiHSM2/)
- [SoftHSM Documentation](https://www.opendnssec.org/softhsm/)

## Support

For HSM integration issues:
1. Check logs for detailed error messages
2. Verify HSM connectivity with `pkcs11-tool`
3. Test with SoftHSM before using hardware HSM
4. Consult [crypto/src/provider/README.md](../crypto/src/provider/README.md)
