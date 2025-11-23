# Multi-Issuer Federation

Freebird implements a two-layer federation architecture that enables true multi-issuer scenarios without shared secrets.

## Table of Contents

1. [Overview](#overview)
2. [Layer 1: Signature-Based Authentication](#layer-1-signature-based-authentication)
3. [Layer 2: Trust Graph Federation](#layer-2-trust-graph-federation)
4. [Configuration](#configuration)
5. [Security](#security)
6. [Use Cases](#use-cases)

## Overview

### What is Multi-Issuer Federation?

Multi-issuer federation allows verifiers to authenticate tokens from multiple independent issuers. Freebird implements this through two layers:

- **Layer 1**: Signature-based authentication using public keys (no shared secrets)
- **Layer 2**: ActivityPub-style trust graphs for distributed trust

### Key Benefits

- **No Shared Secrets**: Verifiers only need issuer public keys
- **True Multi-Issuer**: Authenticate tokens from multiple independent issuers
- **Trust Networks**: Issuers vouch for each other cryptographically
- **Decentralized**: No central authority required
- **Scalable**: Trust graph traversal with configurable policies

---

## Layer 1: Signature-Based Authentication

Layer 1 provides the cryptographic foundation for multi-issuer federation using ECDSA signatures.

### Architecture

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
- Foundation for Layer 2 trust networks
- Clean, simple design

### Token Format

#### Signature-Based Token (195 bytes)

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

### Public Key Discovery

Verifiers obtain issuer public keys through:

#### 1. Manual Configuration
Pre-configured trusted issuers in verifier config.

#### 2. HTTPS Discovery
```bash
# Fetch issuer metadata
curl https://issuer.example.com/.well-known/issuer

# Response
{
  "issuer_id": "issuer:example:v1",
  "voprf": {
    "suite": "OPRF(P-256, SHA-256)-verifiable",
    "pubkey": "<base64-encoded-public-key>",
    "kid": "exmpl-2025-01-15",
    "exp_sec": 600
  }
}
```

#### 3. Layer 2 Trust Graph
Automatic discovery through cryptographic vouching (see below).

### Example: Multi-Issuer Verification

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

---

## Layer 2: Trust Graph Federation

Layer 2 enables ActivityPub-style federation where issuers vouch for each other, creating a decentralized trust network.

### Key Concepts

#### 1. Vouches

A **vouch** is a cryptographically signed statement from one issuer (voucher) asserting trust in another issuer (vouchee).

**Structure**:
```rust
pub struct Vouch {
    pub voucher_issuer_id: String,      // "issuer:mozilla:v1"
    pub vouched_issuer_id: String,      // "issuer:eff:v1"
    pub vouched_pubkey: Vec<u8>,        // EFF's public key
    pub expires_at: i64,                // Unix timestamp
    pub created_at: i64,                // Unix timestamp
    pub trust_level: Option<u8>,        // 0-100 (optional)
    pub signature: [u8; 64],            // ECDSA signature
}
```

**Signature covers**: `voucher_issuer_id || vouched_issuer_id || vouched_pubkey || expires_at || created_at`

**Example JSON**:
```json
{
  "voucher_issuer_id": "issuer:mozilla:v1",
  "vouched_issuer_id": "issuer:eff:v1",
  "vouched_pubkey": "AzQ1...base64...",
  "expires_at": 1735689600,
  "created_at": 1704067200,
  "trust_level": 90,
  "signature": "r7K9...base64..."
}
```

#### 2. Revocations

A **revocation** removes trust from an issuer.

**Structure**:
```rust
pub struct Revocation {
    pub revoker_issuer_id: String,
    pub revoked_issuer_id: String,
    pub revoked_at: i64,
    pub reason: Option<String>,
    pub signature: [u8; 64],
}
```

#### 3. Federation Metadata

Issuers publish their trust graph at `/.well-known/federation`:

```bash
curl https://issuer:mozilla:v1/.well-known/federation
```

```json
{
  "issuer_id": "issuer:mozilla:v1",
  "vouches": [
    {
      "voucher_issuer_id": "issuer:mozilla:v1",
      "vouched_issuer_id": "issuer:eff:v1",
      "vouched_pubkey": "AzQ1...",
      "expires_at": 1735689600,
      "created_at": 1704067200,
      "trust_level": 90,
      "signature": "r7K9..."
    }
  ],
  "revocations": [],
  "updated_at": 1704067200,
  "cache_ttl_secs": 3600
}
```

#### 4. Trust Policy

Verifiers configure trust policies to control federation behavior:

```rust
pub struct TrustPolicy {
    pub enabled: bool,                  // Enable/disable federation
    pub max_trust_depth: u32,           // Max graph traversal depth (default: 2)
    pub min_trust_paths: u32,           // Min independent paths required (default: 1)
    pub require_direct_trust: bool,     // Only accept direct vouches from roots
    pub trusted_roots: Vec<String>,     // Explicitly trusted root issuers
    pub blocked_issuers: Vec<String>,   // Explicitly blocked issuers
    pub refresh_interval_secs: u64,     // Metadata cache TTL (default: 3600)
    pub min_trust_level: u8,            // Minimum trust level (default: 50)
}
```

### Trust Graph Traversal

When a verifier receives a token from an unknown issuer, it traverses the trust graph using BFS:

1. **Check Explicit Trust**: Is the issuer a trusted root? Is it blocked?
2. **Fetch Metadata**: Get `/.well-known/federation` from trusted roots
3. **Build Trust Paths**: Follow vouches up to `max_trust_depth` hops
4. **Verify Signatures**: Validate all vouch and revocation signatures
5. **Make Decision**: Accept if `trust_paths >= min_trust_paths`

**Example Trust Graph**:
```
Mozilla (root) ───vouches──→ EFF ───vouches──→ Alice
       │
       └─────vouches──→ Bob
```

With policy `{trusted_roots: ["issuer:mozilla:v1"], max_trust_depth: 2, min_trust_paths: 1}`:
- **EFF**: ✅ Trusted (1 path via Mozilla, depth=1)
- **Alice**: ✅ Trusted (1 path via Mozilla→EFF, depth=2)
- **Bob**: ✅ Trusted (1 path via Mozilla, depth=1)
- **Charlie**: ❌ Not trusted (no paths found)

### Creating Vouches

#### Step 1: Create Vouch Structure

```rust
use common::federation::Vouch;
use crypto::Server;

let ctx = b"freebird:v1";
let voucher_sk = [0x42u8; 32]; // Voucher's secret key

// Get vouchee's public key
let vouchee_pubkey = fetch_issuer_pubkey("issuer:eff:v1").await?;

let mut vouch = Vouch {
    voucher_issuer_id: "issuer:mozilla:v1".to_string(),
    vouched_issuer_id: "issuer:eff:v1".to_string(),
    vouched_pubkey: vouchee_pubkey,
    expires_at: now + (365 * 24 * 3600),  // 1 year
    created_at: now,
    trust_level: Some(90),
    signature: [0u8; 64],  // Will be filled
};
```

#### Step 2: Sign the Vouch

```rust
let signature = vouch.sign(&voucher_sk)?;
vouch.signature = signature;
```

#### Step 3: Publish via Admin API

```bash
curl -X POST \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"vouch": {...}}' \
  http://localhost:8080/admin/federation/vouches
```

### Admin API

Layer 2 includes REST endpoints for managing federation:

```bash
# List vouches
GET /admin/federation/vouches

# Add vouch
POST /admin/federation/vouches
{
  "vouch": {
    "voucher_issuer_id": "issuer:a:v1",
    "vouched_issuer_id": "issuer:b:v1",
    "vouched_pubkey": "...",
    "expires_at": 1735689600,
    "created_at": 1704067200,
    "trust_level": 80,
    "signature": "..."
  }
}

# Remove vouch
DELETE /admin/federation/vouches/:issuer_id

# List revocations
GET /admin/federation/revocations

# Add revocation
POST /admin/federation/revocations

# Remove revocation
DELETE /admin/federation/revocations/:issuer_id
```

All endpoints require `X-Admin-Key` header authentication.

### Persistent Storage

Vouches and revocations are stored in `./data/federation/`:
- `vouches.json` - All active vouches
- `revocations.json` - All active revocations

Files are pretty-printed JSON for easy inspection and manual editing.

---

## Configuration

### Issuer Configuration (Layer 1)

```bash
# Standard issuer configuration
ISSUER_ID="issuer:example:v1"
BIND_ADDR="0.0.0.0:8081"
TOKEN_TTL_MIN=10
EPOCH_DURATION_SEC=86400
EPOCH_RETENTION=2
```

No additional configuration needed - signature-based tokens are automatic.

### Issuer Configuration (Layer 2)

```bash
# Enable admin API for federation management
ADMIN_API_KEY="<64-character-key>"

# Federation data stored in ./data/federation/
```

### Verifier Configuration (Layer 1)

```bash
# Standard verifier configuration
BIND_ADDR="0.0.0.0:8082"
MAX_CLOCK_SKEW_SECS=300
EPOCH_DURATION_SEC=86400
EPOCH_RETENTION=2
```

**Note**: No secret key required! Verifier operates entirely with public keys.

### Verifier Configuration (Layer 2)

```rust
use verifier::federation::TrustGraph;
use common::federation::TrustPolicy;

let policy = TrustPolicy {
    enabled: true,
    max_trust_depth: 2,
    min_trust_paths: 1,
    trusted_roots: vec![
        "issuer:mozilla:v1".to_string(),
        "issuer:eff:v1".to_string(),
    ],
    blocked_issuers: vec![
        "issuer:compromised:v1".to_string(),
    ],
    refresh_interval_secs: 3600,
    min_trust_level: 50,
    ..Default::default()
};

let trust_graph = TrustGraph::new(policy);

// Check trust before accepting tokens
if !trust_graph.is_trusted(&issuer_id, &issuer_pubkey).await {
    return Err("Issuer not trusted");
}
```

---

## Security

### Layer 1 Security

#### ECDSA Signatures
- **Algorithm**: P-256 (secp256r1) ECDSA
- **Determinism**: RFC 6979 (deterministic k generation)
- **Hash**: SHA-256
- **Security Level**: ~128-bit

#### Attack Resistance
- ✅ **Token Modification**: Signature becomes invalid
- ✅ **Metadata Forgery**: Signature covers `kid`, `exp`, `issuer_id`
- ✅ **Replay Protection**: Nullifier system
- ✅ **Double Spending**: Nullifier system

### Layer 2 Security

#### Signature Verification
All vouches and revocations are cryptographically verified:

```rust
// Verify vouch signature with voucher's public key
let voucher_pubkey = fetch_pubkey(&vouch.voucher_issuer_id).await?;
assert!(vouch.verify(&voucher_pubkey));

// Verify revocation signature with revoker's public key
let revoker_pubkey = fetch_pubkey(&revocation.revoker_issuer_id).await?;
assert!(revocation.verify(&revoker_pubkey));
```

#### Time Validation
Vouches have expiration times with clock skew tolerance (5 minutes):

```rust
let now = current_timestamp();
assert!(vouch.is_valid_at(now, MAX_CLOCK_SKEW_SECS));
```

#### Trust Level Enforcement
Vouches below `min_trust_level` are ignored:

```rust
if let Some(level) = vouch.trust_level {
    assert!(level >= policy.min_trust_level);
}
```

#### Revocation Checking
Always check revocations before trusting vouches:

```rust
if is_revoked(&issuer_id, &metadata.revocations, now).await {
    return false;  // Don't trust revoked issuer
}
```

#### Metadata Caching
- Federation metadata cached with TTL (default: 1 hour)
- Public keys cached with TTL
- Prevents DoS attacks via rate limiting

### Best Practices

1. **HTTPS Only**: Always fetch metadata over HTTPS
2. **Key Rotation**: Use epoch-based rotation
3. **Public Key Pinning**: Validate on first use
4. **Audit Logs**: Monitor federation operations
5. **Clock Sync**: Keep clocks synchronized (NTP)
6. **Trust Roots**: Carefully select trusted root issuers
7. **Review Vouches**: Regularly audit trust graph

---

## Use Cases

### Scenario 1: Single Issuer (Layer 1)

**Architecture**:
```
Issuer A (PK_A) ──┐
                  ├─→ Verifier (has PK_A)
Clients ──────────┘
```

**Benefits**: Simple, no shared secrets, verifier only needs public key.

### Scenario 2: Multi-Issuer Federation (Layer 1)

**Architecture**:
```
Issuer A (PK_A) ──┐
Issuer B (PK_B) ──┼─→ Verifier (has PK_A, PK_B, PK_C)
Issuer C (PK_C) ──┘
```

**Benefits**: Multiple independent issuers, verifier maintains public key registry.

### Scenario 3: University Consortium (Layer 2)

**Trust Graph**:
```
UC Berkeley (root) ───vouches──→ Stanford ───vouches──→ MIT
       │
       └─────vouches──→ UCLA
```

**Policy**:
```rust
TrustPolicy {
    trusted_roots: ["issuer:berkeley:v1"],
    max_trust_depth: 2,
    min_trust_paths: 1,
    min_trust_level: 80,
    ..Default::default()
}
```

**Benefits**: Consortium members vouch for each other, automated trust propagation.

### Scenario 4: Geographic Federation (Layer 2)

**Trust Graph**:
```
USA Gov (root) ───vouches──→ California DMV
                        └──→ New York DMV

EU Commission (root) ───vouches──→ Germany eID
                               └──→ France eID
```

**Policy**:
```rust
TrustPolicy {
    trusted_roots: vec![
        "issuer:usa-gov:v1",
        "issuer:eu-commission:v1",
    ],
    max_trust_depth: 1,  // Only direct vouches
    require_direct_trust: true,
    min_trust_level: 95,
    ..Default::default()
}
```

**Benefits**: Government-level trust anchors, regional issuers, strict trust policy.

### Scenario 5: Web of Trust (Layer 2)

**Trust Graph**:
```
Alice ───vouches──→ Bob ───vouches──→ Charlie
  │                   │
  └─────────vouches───┘
```

**Policy**:
```rust
TrustPolicy {
    trusted_roots: vec!["issuer:alice:v1"],
    max_trust_depth: 2,
    min_trust_paths: 2,  // Require 2 independent paths
    min_trust_level: 70,
    ..Default::default()
}
```

**Result**: Charlie trusted (2 paths: Alice→Bob→Charlie and Alice→Charlie)

### Scenario 6: Microservices (Layer 1)

**Architecture**:
```
Auth Service    (issuer:auth:v1)  ──┐
Payment Service (issuer:pay:v1)   ──┼─→ API Gateway
Content Service (issuer:cdn:v1)   ──┘   (verifies all)
```

**Benefits**: Different services issue tokens, gateway verifies with public keys only.

---

## Testing

### Layer 1 Tests

```bash
# Test signature-based token flow
cargo test --package integration_tests --test signature_based_tokens

# Should see:
# ✅ test_signature_based_token_generation ... ok
# ✅ test_signature_determinism ... ok
# ✅ test_signature_tampering_detection ... ok
# ✅ test_federation_scenario ... ok
```

### Layer 2 Tests

```bash
# Test federation metadata
cargo test --test federation_metadata

# Test trust graph
cargo test --package verifier federation::

# Test federation store
cargo test --package issuer federation_store::
```

### Manual Testing

#### Layer 1: Issue and Verify Token

```bash
# Start issuer
cargo run --bin issuer

# Request token
curl -X POST http://localhost:8081/v1/oprf/issue \
  -H "Content-Type: application/json" \
  -d '{"blinded_element_b64": "<blinded-element>"}'

# Start verifier
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
```

#### Layer 2: Manage Federation

```bash
# List vouches
curl -H "X-Admin-Key: $KEY" \
  http://localhost:8080/admin/federation/vouches

# Add vouch
curl -X POST \
  -H "X-Admin-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"vouch": {...}}' \
  http://localhost:8080/admin/federation/vouches

# Check federation metadata
curl http://localhost:8080/.well-known/federation
```

---

## References

### Standards
- [RFC 6979](https://tools.ietf.org/html/rfc6979) - Deterministic ECDSA
- [SEC 1](https://www.secg.org/sec1-v2.pdf) - Elliptic Curve Cryptography
- [NIST SP 800-186](https://csrc.nist.gov/publications/detail/sp/800-186/final) - P-256
- [ActivityPub](https://www.w3.org/TR/activitypub/) - Federated Networks (inspiration)

### Documentation
- [How It Works](./HOW_IT_WORKS.md) - VOPRF protocol details
- [Security](./SECURITY.md) - Security architecture
- [API Reference](./API.md) - HTTP endpoints
- [Configuration](./CONFIGURATION.md) - Configuration reference

---

## Support

For questions or issues:
- **GitHub Issues**: https://github.com/flammafex/freebird/issues
- **Documentation**: `docs/`
- **Security**: See `SECURITY.md`
