# Multi-Issuer Federation

Freebird supports multi-issuer federation through signature-based token authentication (Layer 1 Federation). This allows verifiers to authenticate tokens from multiple issuers without requiring shared secrets.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Token Formats](#token-formats)
4. [Configuration](#configuration)
5. [Migration Guide](#migration-guide)
6. [Security Considerations](#security-considerations)
7. [Example Scenarios](#example-scenarios)

## Overview

### What is Layer 1 Federation?

Layer 1 Federation enables verifiers to authenticate tokens from multiple issuers using only public keys. This eliminates the need for shared secrets between issuers and verifiers, making true multi-issuer scenarios possible.

### Key Benefits

- **No Shared Secrets**: Verifiers only need issuer public keys
- **Multi-Issuer Support**: Authenticate tokens from multiple independent issuers
- **Federation-Ready**: Foundation for ActivityPub-style trust networks (Layer 2)
- **Backward Compatible**: Supports both MAC-based (V1) and signature-based (V2) tokens

### Use Cases

1. **Federated Networks**: Multiple independent issuers serve a common verifier pool
2. **Microservices**: Different services issue tokens for different purposes
3. **Geographic Distribution**: Regional issuers with global verifiers
4. **Trust Networks**: Issuers vouch for each other (Layer 2, coming soon)

## Architecture

### MAC-Based Authentication (V1) - Legacy Mode

```
┌─────────┐                    ┌──────────┐
│ Issuer  │──── Secret Key ────│ Verifier │
└─────────┘                    └──────────┘
     │                              │
     │    Token (163 bytes)         │
     │  ┌─────────────────┐         │
     └─▶│ VOPRF (131)     │────────▶│
        │ HMAC  (32)      │         │
        └─────────────────┘         │
                                    │
        ⚠️ Verifier needs secret key!
```

**Limitations**:
- Requires shared secret between issuer and verifier
- Cannot support true multi-issuer federation
- Suitable only when issuer and verifier are managed by the same entity

### Signature-Based Authentication (V2) - Federation Mode

```
┌─────────┐                    ┌──────────┐
│ Issuer  │── Public Key ──────│ Verifier │
└─────────┘                    └──────────┘
     │                              │
     │    Token (195 bytes)         │
     │  ┌─────────────────┐         │
     └─▶│ VOPRF (131)     │────────▶│
        │ ECDSA (64)      │         │
        └─────────────────┘         │
                                    │
        ✅ Verifier needs only public key!
```

**Advantages**:
- Verifier only needs public key (no secrets)
- Supports tokens from multiple independent issuers
- Foundation for trust network federation
- Slightly larger tokens (32 bytes overhead) for federation capability

## Token Formats

### V1: MAC-Based Token (163 bytes)

```
┌─────────────────────────────────────────┐
│ VERSION (1)                             │
│ Point A (33) - SEC1 compressed          │
│ Point B (33) - SEC1 compressed          │
│ DLEQ Proof (64) - c (32) + s (32)       │
│ HMAC-SHA256 (32) - metadata MAC         │
└─────────────────────────────────────────┘
Total: 163 bytes
```

**Authentication**: HMAC over token metadata using epoch-specific MAC key derived from issuer secret

### V2: Signature-Based Token (195 bytes)

```
┌─────────────────────────────────────────┐
│ VERSION (1)                             │
│ Point A (33) - SEC1 compressed          │
│ Point B (33) - SEC1 compressed          │
│ DLEQ Proof (64) - c (32) + s (32)       │
│ ECDSA Signature (64) - r (32) + s (32)  │
└─────────────────────────────────────────┘
Total: 195 bytes
```

**Authentication**: ECDSA (P-256) signature over token metadata, verifiable with issuer's public key

**Message Signed**: `token_bytes || kid || exp || issuer_id`

### Auto-Detection

Both issuer and verifier support automatic format detection based on token length:
- 163 bytes → V1 (MAC-based)
- 195 bytes → V2 (Signature-based)

This enables seamless backward compatibility and gradual migration.

## Configuration

### Issuer Configuration

#### Enable Signature-Based Tokens

Set the `TOKEN_FORMAT` environment variable:

```bash
# Use signature-based tokens (V2, federation-ready)
TOKEN_FORMAT=signature

# Or use MAC-based tokens (V1, legacy mode)
TOKEN_FORMAT=mac  # default
```

**Valid values**: `signature`, `sig`, `ecdsa` (for V2) or `mac`, `hmac` (for V1)

#### Example Configuration

```bash
# Issuer configuration for federation mode
ISSUER_ID="issuer:example:v1"
BIND_ADDR="0.0.0.0:8081"
TOKEN_TTL_MIN=10
TOKEN_FORMAT=signature  # Enable signature-based tokens
EPOCH_DURATION_SEC=86400
EPOCH_RETENTION=2
```

### Verifier Configuration

#### Federation Mode (Signature-Based Tokens Only)

**Do not set** `ISSUER_SECRET_KEY` - the verifier will operate in federation mode:

```bash
# Verifier configuration for federation mode
BIND_ADDR="0.0.0.0:8082"
MAX_CLOCK_SKEW_SECS=300
EPOCH_DURATION_SEC=86400
EPOCH_RETENTION=2
# ISSUER_SECRET_KEY not set - federation mode!
```

**Behavior**:
- ✅ Accepts signature-based tokens (V2, 195 bytes)
- ❌ Rejects MAC-based tokens (V1, 163 bytes)
- ℹ️  Logs warning at startup about limited token support

#### Hybrid Mode (Both Token Formats)

Set `ISSUER_SECRET_KEY` for backward compatibility:

```bash
# Verifier configuration for hybrid mode
BIND_ADDR="0.0.0.0:8082"
MAX_CLOCK_SKEW_SECS=300
EPOCH_DURATION_SEC=86400
EPOCH_RETENTION=2
ISSUER_SECRET_KEY=<hex-encoded-32-byte-key>  # Enables MAC verification
```

**Behavior**:
- ✅ Accepts signature-based tokens (V2, 195 bytes)
- ✅ Accepts MAC-based tokens (V1, 163 bytes)
- ⚠️  Still requires secret key (not true federation)

## Migration Guide

### Migrating from V1 to V2

Follow these steps for a smooth migration:

#### Step 1: Update Issuer to Dual Mode

1. Deploy issuer with `TOKEN_FORMAT=signature`
2. Existing clients will receive V2 tokens
3. Old V1 tokens remain valid until expiration

#### Step 2: Monitor Token Distribution

Track token format distribution in logs:
- Issuer logs: `✅ Token issued (auth=ECDSA)`
- Verifier logs: `✅ Token verified (auth=ECDSA)`

#### Step 3: Update Verifier Configuration

Once all tokens are V2 (after `TOKEN_TTL_MIN` expires):
1. Remove `ISSUER_SECRET_KEY` from verifier configuration
2. Restart verifier in federation mode
3. Verify logs show: `⚠️ ISSUER_SECRET_KEY not set - only signature-based tokens (V2) will be supported`

#### Step 4: Verification

Test both scenarios:
```bash
# Test V2 token verification
curl -X POST http://verifier:8082/v1/verify \
  -H "Content-Type: application/json" \
  -d '{
    "token_b64": "<v2-token>",
    "issuer_id": "issuer:example:v1",
    "epoch": 12345,
    "exp": 1234567890
  }'
```

### Rollback Plan

If you need to rollback to V1:

1. Redeploy issuer with `TOKEN_FORMAT=mac`
2. Ensure verifier has `ISSUER_SECRET_KEY` set
3. New tokens will be V1 (163 bytes)
4. Existing V2 tokens remain valid until expiration

## Security Considerations

### Cryptographic Properties

#### ECDSA Signatures
- **Algorithm**: P-256 (secp256r1) ECDSA
- **Determinism**: RFC 6979 (deterministic k generation)
- **Hash**: SHA-256
- **Security Level**: ~128-bit (matching P-256 VOPRF)

#### Signature Verification
```rust
// Verifier checks:
let signature_valid = crypto::verify_token_signature(
    &issuer_pubkey,      // Only public key needed!
    &token_bytes,
    &received_signature,
    &kid,
    exp,
    &issuer_id,
);
```

### Attack Resistance

#### Tampering Protection
- ✅ **Token Modification**: Signature becomes invalid
- ✅ **Metadata Forgery**: Signature covers `kid`, `exp`, `issuer_id`
- ✅ **Replay Protection**: Nullifier system (unchanged)
- ✅ **Double Spending**: Nullifier system (unchanged)

#### Constant-Time Operations
- ✅ **Signature Verification**: Not timing-sensitive (public key crypto)
- ✅ **MAC Verification**: Constant-time comparison (V1 mode)
- ✅ **Key Matching**: Constant-time string comparison (defense-in-depth)

### Public Key Distribution

#### Trust Establishment

Verifiers must obtain authentic issuer public keys through:

1. **Manual Configuration**: Pre-configured trusted issuers
2. **HTTPS Discovery**: Fetch from `/.well-known/issuer` endpoint
3. **Layer 2 Federation**: Trust graph vouching (coming soon)

#### Example: Public Key Discovery

```bash
# Fetch issuer metadata
curl https://issuer.example.com/.well-known/issuer

# Response includes public key
{
  "issuer_id": "issuer:example:v1",
  "suite": "OPRF(P-256, SHA-256)-verifiable",
  "pubkey": "<base64-encoded-public-key>",
  "kid": "exmpl-2025-01-15"
}
```

### Best Practices

1. **Key Rotation**: Use epoch-based rotation (already supported)
2. **Public Key Pinning**: Validate issuer public keys on first use
3. **HTTPS Only**: Always fetch public keys over HTTPS
4. **Audit Logs**: Monitor token verification for anomalies
5. **Clock Sync**: Keep issuer/verifier clocks synchronized (NTP)

## Example Scenarios

### Scenario 1: Single Issuer Migration

**Before** (V1 - Shared Secret):
```
Issuer A (secret: SK_A) ──┐
                          ├─→ Verifier (has SK_A)
                          │
Clients ──────────────────┘
```

**After** (V2 - Public Key):
```
Issuer A (pubkey: PK_A) ──┐
                          ├─→ Verifier (has PK_A)
                          │
Clients ──────────────────┘
```

**Configuration**:
```bash
# Issuer A
TOKEN_FORMAT=signature

# Verifier (remove ISSUER_SECRET_KEY after migration)
# ISSUER_SECRET_KEY not set
```

### Scenario 2: Multi-Issuer Federation

**Architecture**:
```
Issuer A (PK_A) ──┐
                  │
Issuer B (PK_B) ──┼─→ Verifier (has PK_A, PK_B, PK_C)
                  │
Issuer C (PK_C) ──┘
```

**Configuration**:

```bash
# Issuer A
ISSUER_ID="issuer:a:v1"
TOKEN_FORMAT=signature

# Issuer B
ISSUER_ID="issuer:b:v1"
TOKEN_FORMAT=signature

# Issuer C
ISSUER_ID="issuer:c:v1"
TOKEN_FORMAT=signature

# Verifier (no secrets!)
# Verifier maintains registry of (issuer_id → public_key) mappings
# Fetched from /.well-known/issuer endpoints
```

**Token Verification**:
```rust
// Verifier auto-detects issuer and verifies with correct public key
match token_length {
    195 => {
        let issuer = lookup_issuer(&req.issuer_id)?;
        let valid = verify_token_signature(
            &issuer.pubkey,
            &token_data,
            &signature,
            &issuer.kid,
            exp,
            &req.issuer_id
        );
    }
    // ...
}
```

### Scenario 3: Geographic Distribution

**Use Case**: Regional issuers, global verifiers

```
┌─────────────────────────────────────────┐
│ Region: North America                   │
│ Issuer NA (issuer:na:v1)                │
│ PK_NA: <public-key>                     │
└─────────────────────────────────────────┘
                  │
                  │ Tokens (195 bytes)
                  │
┌─────────────────▼─────────────────────┐
│ Global Verifier Pool                  │
│ - Verifier 1 (has PK_NA, PK_EU, PK_AP)│
│ - Verifier 2 (has PK_NA, PK_EU, PK_AP)│
│ - Verifier 3 (has PK_NA, PK_EU, PK_AP)│
└────────────────────────────────────────┘
                  ▲
                  │ Tokens (195 bytes)
                  │
┌─────────────────┴─────────────────────┐
│ Region: Europe                        │
│ Issuer EU (issuer:eu:v1)              │
│ PK_EU: <public-key>                   │
└───────────────────────────────────────┘
```

**Benefits**:
- Regional issuers operate independently
- Verifiers accept tokens from any region
- No secret key sharing across regions
- Simplified key management

### Scenario 4: Microservices Architecture

**Use Case**: Different services issue tokens for different scopes

```
Auth Service    (issuer:auth:v1)  ──┐
Payment Service (issuer:pay:v1)   ──┼─→ API Gateway
Content Service (issuer:cdn:v1)   ──┘   (verifies all)
```

**Configuration**:
```bash
# Each service issues its own tokens
# Auth Service
ISSUER_ID="issuer:auth:v1"
TOKEN_FORMAT=signature

# Payment Service
ISSUER_ID="issuer:pay:v1"
TOKEN_FORMAT=signature

# Content Service
ISSUER_ID="issuer:cdn:v1"
TOKEN_FORMAT=signature

# API Gateway (verifier)
# Maintains public key registry for all services
# No service secret keys in gateway!
```

## Testing

### Integration Tests

Run the comprehensive federation test suite:

```bash
# Test signature-based token flow
cargo test --package integration_tests --test signature_based_tokens

# Should see:
# ✅ test_signature_based_token_generation ... ok
# ✅ test_mac_vs_signature_token_sizes ... ok
# ✅ test_signature_determinism ... ok
# ✅ test_signature_tampering_detection ... ok
# ✅ test_federation_scenario ... ok
```

### Manual Testing

#### Issue a Signature-Based Token

```bash
# Configure issuer for V2 tokens
export TOKEN_FORMAT=signature

# Start issuer
cargo run --bin issuer

# Request token (from client)
curl -X POST http://localhost:8081/v1/oprf/issue \
  -H "Content-Type: application/json" \
  -d '{
    "blinded_b64": "<blinded-element>"
  }'

# Response includes 195-byte token
```

#### Verify in Federation Mode

```bash
# Start verifier WITHOUT secret key
unset ISSUER_SECRET_KEY
cargo run --bin verifier

# Verify token
curl -X POST http://localhost:8082/v1/verify \
  -H "Content-Type: application/json" \
  -d '{
    "token_b64": "<195-byte-token>",
    "issuer_id": "issuer:example:v1",
    "epoch": 12345,
    "exp": 1234567890
  }'

# Should succeed with only public key!
```

## Future Work: Layer 2 Federation

Layer 1 provides the cryptographic foundation. Layer 2 (planned) will add:

- **Issuer Discovery Protocol**: ActivityPub-style `.well-known/federation` endpoints
- **Cryptographic Vouching**: Issuers sign vouches for other issuers
- **Trust Graph**: Build and traverse issuer trust networks
- **Revocation**: Distributed revocation of compromised issuers
- **Federation Policies**: Configurable trust requirements

Stay tuned for Layer 2 implementation!

## References

- [RFC 6979](https://tools.ietf.org/html/rfc6979) - Deterministic ECDSA
- [SEC 1](https://www.secg.org/sec1-v2.pdf) - Elliptic Curve Cryptography
- [NIST SP 800-186](https://csrc.nist.gov/publications/detail/sp/800-186/final) - Discrete Log Crypto (P-256)
- [ActivityPub](https://www.w3.org/TR/activitypub/) - Federated Social Networks (inspiration for Layer 2)

## Support

For questions or issues related to federation:
- GitHub Issues: https://github.com/flammafex/freebird/issues
- Documentation: `docs/`
- Security: See `SECURITY.md`
