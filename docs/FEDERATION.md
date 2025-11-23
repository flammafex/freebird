# Multi-Issuer Federation

Freebird is designed from the ground up for multi-issuer federation. Verifiers authenticate tokens using only issuer public keys - no shared secrets required.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Token Format](#token-format)
4. [Configuration](#configuration)
5. [Security Considerations](#security-considerations)
6. [Example Scenarios](#example-scenarios)

## Overview

### What is Multi-Issuer Federation?

Multi-issuer federation allows verifiers to authenticate tokens from multiple independent issuers using only public keys. This eliminates the need for shared secrets between issuers and verifiers, making true multi-issuer scenarios possible.

### Key Benefits

- **No Shared Secrets**: Verifiers only need issuer public keys
- **Multi-Issuer Support**: Authenticate tokens from multiple independent issuers
- **Simple Architecture**: One token format, one authentication method
- **Federation-Ready**: Foundation for ActivityPub-style trust networks (Layer 2, coming soon)

### Use Cases

1. **Federated Networks**: Multiple independent issuers serve a common verifier pool
2. **Microservices**: Different services issue tokens for different purposes
3. **Geographic Distribution**: Regional issuers with global verifiers
4. **Trust Networks**: Issuers vouch for each other (Layer 2, coming soon)

## Architecture

### Signature-Based Authentication

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
- Clean, simple design

## Token Format

### Signature-Based Token (195 bytes)

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

**Components**:
- **VOPRF Token** (131 bytes): Cryptographic proof from blind signature protocol
- **ECDSA Signature** (64 bytes): Metadata authentication using P-256

## Configuration

### Issuer Configuration

Issuers automatically generate signature-based tokens. No configuration required beyond standard setup.

#### Example Configuration

```bash
# Standard issuer configuration
ISSUER_ID="issuer:example:v1"
BIND_ADDR="0.0.0.0:8081"
TOKEN_TTL_MIN=10
EPOCH_DURATION_SEC=86400
EPOCH_RETENTION=2
```

### Verifier Configuration

Verifiers automatically verify signature-based tokens using issuer public keys.

#### Example Configuration

```bash
# Standard verifier configuration
BIND_ADDR="0.0.0.0:8082"
MAX_CLOCK_SKEW_SECS=300
EPOCH_DURATION_SEC=86400
EPOCH_RETENTION=2
```

**Note**: No secret key required! Verifier operates entirely with public keys.

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

### Scenario 1: Single Issuer

**Architecture**:
```
Issuer A (PK_A) ──┐
                  ├─→ Verifier (has PK_A)
                  │
Clients ──────────┘
```

**Configuration**:
```bash
# Issuer A
ISSUER_ID="issuer:a:v1"

# Verifier (no secrets!)
# Verifier maintains registry of (issuer_id → public_key) mappings
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

# Issuer B
ISSUER_ID="issuer:b:v1"

# Issuer C
ISSUER_ID="issuer:c:v1"

# Verifier (no secrets!)
# Verifier maintains registry of (issuer_id → public_key) mappings
# Fetched from /.well-known/issuer endpoints
```

**Token Verification**:
```rust
// Verifier detects issuer and verifies with correct public key
let issuer = lookup_issuer(&req.issuer_id)?;
let valid = verify_token_signature(
    &issuer.pubkey,
    &token_data,
    &signature,
    &issuer.kid,
    exp,
    &req.issuer_id
);
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

# Payment Service
ISSUER_ID="issuer:pay:v1"

# Content Service
ISSUER_ID="issuer:cdn:v1"

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

#### Issue a Token

```bash
# Start issuer
cargo run --bin issuer

# Request token (from client)
curl -X POST http://localhost:8081/v1/oprf/issue \
  -H "Content-Type: application/json" \
  -d '{
    "blinded_element_b64": "<blinded-element>"
  }'

# Response includes 195-byte token
```

#### Verify in Federation Mode

```bash
# Start verifier (no secret key required!)
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

Layer 1 (current implementation) provides the cryptographic foundation. Layer 2 (planned) will add:

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
