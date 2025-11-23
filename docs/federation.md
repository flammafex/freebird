# Layer 2 Federation: Multi-Issuer Trust Graph

## Overview

Layer 2 Federation enables ActivityPub-style trust networks for Freebird, allowing issuers to vouch for each other and verifiers to make authorization decisions based on trust graphs.

This builds on top of Layer 1 (signature-based token authentication) to enable true multi-issuer federation without requiring verifiers to have prior relationships with every issuer.

## Key Concepts

### 1. Vouches

A **vouch** is a cryptographically signed statement from one issuer (the "voucher") asserting trust in another issuer (the "vouchee").

**Structure:**
```rust
pub struct Vouch {
    pub voucher_issuer_id: String,      // "issuer:a:v1"
    pub vouched_issuer_id: String,      // "issuer:b:v1"
    pub vouched_pubkey: Vec<u8>,        // Public key of issuer B
    pub expires_at: i64,                // Unix timestamp
    pub created_at: i64,                // Unix timestamp
    pub trust_level: Option<u8>,        // 0-100, where 100 = full trust
    pub signature: [u8; 64],            // ECDSA signature
}
```

**Signature covers:**
```
voucher_issuer_id || vouched_issuer_id || vouched_pubkey || expires_at || created_at
```

**Example:**
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

### 2. Revocations

A **revocation** is a signed statement removing trust from an issuer.

**Structure:**
```rust
pub struct Revocation {
    pub revoker_issuer_id: String,
    pub revoked_issuer_id: String,
    pub revoked_at: i64,
    pub reason: Option<String>,
    pub signature: [u8; 64],
}
```

**Example:**
```json
{
  "revoker_issuer_id": "issuer:mozilla:v1",
  "revoked_issuer_id": "issuer:compromised:v1",
  "revoked_at": 1704067200,
  "reason": "Private key compromise detected",
  "signature": "m9N2...base64..."
}
```

### 3. Federation Metadata

Issuers publish their trust graph at `/.well-known/federation`:

**Structure:**
```rust
pub struct FederationMetadata {
    pub issuer_id: String,
    pub vouches: Vec<Vouch>,
    pub revocations: Vec<Revocation>,
    pub updated_at: i64,
    pub cache_ttl_secs: Option<u64>,
}
```

**Example:**
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

### 4. Trust Policy

Verifiers configure trust policies to control federation behavior:

**Structure:**
```rust
pub struct TrustPolicy {
    pub enabled: bool,                  // Enable/disable federation
    pub max_trust_depth: u32,           // Max graph traversal depth (default: 2)
    pub min_trust_paths: u32,           // Min independent paths required (default: 1)
    pub require_direct_trust: bool,     // Only accept direct vouches from roots
    pub trusted_roots: Vec<String>,     // Explicitly trusted root issuers
    pub blocked_issuers: Vec<String>,   // Explicitly blocked issuers
    pub refresh_interval_secs: u64,     // Metadata cache TTL (default: 3600)
    pub min_trust_level: u8,            // Minimum trust level for vouches (default: 50)
}
```

**Example Configuration:**
```rust
let policy = TrustPolicy {
    enabled: true,
    max_trust_depth: 2,          // Explore 2 hops: A vouches B, B vouches C
    min_trust_paths: 1,          // Require at least 1 trust path
    require_direct_trust: false, // Allow transitive trust
    trusted_roots: vec![
        "issuer:mozilla:v1".to_string(),
        "issuer:eff:v1".to_string(),
    ],
    blocked_issuers: vec![
        "issuer:compromised:v1".to_string(),
    ],
    refresh_interval_secs: 3600, // 1 hour cache
    min_trust_level: 50,         // Require trust_level >= 50
};
```

## How It Works

### Trust Graph Traversal

When a verifier receives a token from an unknown issuer, it traverses the trust graph using BFS:

1. **Check Explicit Trust:**
   - Is the issuer a trusted root? → **Accept**
   - Is the issuer explicitly blocked? → **Reject**

2. **Fetch Metadata:**
   - Fetch `/.well-known/federation` from trusted roots
   - Cache metadata according to `cache_ttl_secs`

3. **Build Trust Paths:**
   - Start from trusted roots
   - Follow vouches up to `max_trust_depth` hops
   - Skip revoked issuers
   - Skip vouches below `min_trust_level`
   - Verify vouch signatures and expiration

4. **Make Decision:**
   - Count independent trust paths
   - Accept if `count >= min_trust_paths`

### Example Scenario

**Trust Graph:**
```
Mozilla (root) ---vouches---> EFF ---vouches---> Alice
       |
       +----------vouches---> Bob
```

**Policy:**
```rust
TrustPolicy {
    trusted_roots: ["issuer:mozilla:v1"],
    max_trust_depth: 2,
    min_trust_paths: 1,
    ..Default::default()
}
```

**Results:**
- **EFF**: ✅ Trusted (1 path via Mozilla, depth=1)
- **Alice**: ✅ Trusted (1 path via Mozilla→EFF, depth=2)
- **Bob**: ✅ Trusted (1 path via Mozilla, depth=1)
- **Charlie**: ❌ Not trusted (no paths found)

## Creating Vouches

### Step 1: Create Vouch Structure

```rust
use common::federation::Vouch;
use crypto::Server;

let ctx = b"freebird:v1";
let voucher_sk = [0x42u8; 32]; // Voucher's secret key

// Get vouchee's public key (from their /.well-known/issuer endpoint)
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

### Step 2: Sign the Vouch

```rust
let signature = vouch.sign(&voucher_sk)?;
vouch.signature = signature;
```

### Step 3: Publish to Federation Metadata

Add the vouch to your `/.well-known/federation` endpoint:

```rust
let metadata = FederationMetadata {
    issuer_id: "issuer:mozilla:v1".to_string(),
    vouches: vec![vouch],
    revocations: vec![],
    updated_at: now,
    cache_ttl_secs: Some(3600),
};

// Serve at /.well-known/federation
```

## Revoking Trust

### Step 1: Create Revocation

```rust
use common::federation::Revocation;

let mut revocation = Revocation {
    revoker_issuer_id: "issuer:mozilla:v1".to_string(),
    revoked_issuer_id: "issuer:compromised:v1".to_string(),
    revoked_at: now,
    reason: Some("Private key compromise".to_string()),
    signature: [0u8; 64],
};
```

### Step 2: Sign the Revocation

```rust
let signature = revocation.sign(&revoker_sk)?;
revocation.signature = signature;
```

### Step 3: Publish Revocation

Add to your `/.well-known/federation` endpoint:

```rust
let metadata = FederationMetadata {
    issuer_id: "issuer:mozilla:v1".to_string(),
    vouches: vec![],  // Optionally remove the original vouch
    revocations: vec![revocation],
    updated_at: now,
    cache_ttl_secs: Some(3600),
};
```

## Verifier Integration

### Step 1: Create Trust Graph

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
    ..Default::default()
};

let trust_graph = TrustGraph::new(policy);
```

### Step 2: Check Trust Before Accepting Tokens

```rust
// Extract issuer_id and public key from token
let issuer_id = extract_issuer_id(&token)?;
let issuer_pubkey = fetch_issuer_pubkey(&issuer_id).await?;

// Check trust
if !trust_graph.is_trusted(&issuer_id, &issuer_pubkey).await {
    return Err("Issuer not trusted");
}

// Verify token...
```

## Security Considerations

### 1. Signature Verification

All vouches and revocations MUST be verified with the issuer's public key:

```rust
// Verify vouch signature
assert!(vouch.verify(&voucher_pubkey));

// Verify revocation signature
assert!(revocation.verify(&revoker_pubkey));
```

**Current Status:** ⚠️ Signature verification is partially implemented. Vouch and revocation structures have `sign()` and `verify()` methods, but the trust graph currently trusts metadata endpoints to only return valid signatures. Full signature verification with public key lookup will be added in a future update.

### 2. Time Validation

Vouches have expiration times and creation times that MUST be validated:

```rust
let now = current_timestamp();
assert!(vouch.is_valid_at(now, MAX_CLOCK_SKEW_SECS));
```

Clock skew tolerance: **5 minutes**

### 3. Trust Level Enforcement

Vouches below `min_trust_level` are ignored:

```rust
if let Some(level) = vouch.trust_level {
    assert!(level >= policy.min_trust_level);
}
```

### 4. Revocation Checking

Always check revocations before trusting vouches:

```rust
if is_revoked(&issuer_id, &metadata.revocations, now) {
    return false;  // Don't trust revoked issuer
}
```

### 5. Metadata Caching

Cache federation metadata with appropriate TTL to prevent:
- **DoS attacks** (rate limiting fetches)
- **Stale data** (respect `cache_ttl_secs`)

### 6. HTTPS Required

Federation metadata MUST be fetched over HTTPS to prevent MITM attacks.

## Performance Considerations

### 1. Caching

The trust graph caches federation metadata in memory:

```rust
// Cache hit (fast)
let metadata = trust_graph.fetch_metadata("issuer:mozilla:v1").await?;

// Cache miss (HTTP fetch)
let metadata = trust_graph.fetch_metadata("issuer:new:v1").await?;
```

Default TTL: **1 hour**

### 2. BFS Complexity

Trust graph traversal is O(V + E) where:
- V = number of issuers visited
- E = number of vouches traversed

Bounded by `max_trust_depth` to prevent infinite loops.

### 3. Parallel Fetching

Metadata fetches are async and can be parallelized:

```rust
// Fetch metadata for multiple issuers in parallel
let futures: Vec<_> = issuers
    .iter()
    .map(|id| trust_graph.fetch_metadata(id))
    .collect();

let results = futures::future::join_all(futures).await;
```

## Use Cases

### 1. University Consortium

**Scenario:** Universities vouch for each other's student issuers.

```
UC Berkeley (root) ---vouches---> Stanford ---vouches---> MIT
       |
       +----------vouches---> UCLA
```

**Policy:**
```rust
TrustPolicy {
    trusted_roots: ["issuer:berkeley:v1"],
    max_trust_depth: 2,
    min_trust_paths: 1,
    min_trust_level: 80,
    ..Default::default()
}
```

### 2. Geographic Federation

**Scenario:** Country-level trust anchors vouch for regional issuers.

```
USA Gov (root) ---vouches---> California DMV
                         +---> New York DMV

EU Commission (root) ---vouches---> Germany eID
                                +---> France eID
```

**Policy:**
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

### 3. Web of Trust

**Scenario:** Decentralized trust with multiple paths required.

```
Alice ---vouches---> Bob ---vouches---> Charlie
  |                    |
  +-----------------vouches---> Charlie
```

**Policy:**
```rust
TrustPolicy {
    trusted_roots: vec!["issuer:alice:v1"],
    max_trust_depth: 2,
    min_trust_paths: 2,  // Require 2 independent paths
    min_trust_level: 70,
    ..Default::default()
}
```

**Result:** Charlie is trusted (2 paths: Alice→Bob→Charlie and Alice→Charlie)

## Testing

### Unit Tests

Run federation tests:

```bash
cargo test --package verifier federation::
cargo test --package common federation::
```

### Integration Tests

Run federation metadata tests:

```bash
cargo test --test federation_metadata
```

### Manual Testing

1. **Start Issuer:**
   ```bash
   cargo run --bin issuer
   ```

2. **Fetch Federation Metadata:**
   ```bash
   curl http://localhost:8080/.well-known/federation | jq
   ```

3. **Check Trust:**
   ```rust
   let trusted = trust_graph.is_trusted("issuer:test:v1", &pubkey).await;
   println!("Trusted: {}", trusted);
   ```

## Roadmap

### ✅ Completed (Layer 2)
- [x] Vouch and Revocation data structures
- [x] Cryptographic signing (ECDSA, RFC 6979)
- [x] Federation metadata endpoint (/.well-known/federation)
- [x] Trust graph traversal (BFS)
- [x] Trust policy configuration
- [x] Revocation support
- [x] Metadata caching
- [x] Basic tests

### 🚧 In Progress
- [ ] Full signature verification with public key lookup
- [ ] Persistent storage for vouches/revocations
- [ ] Admin API for managing vouches/revocations

### 📋 Future Work
- [ ] Trust path visualization
- [ ] Reputation scoring
- [ ] Delegation chains
- [ ] Federation analytics
- [ ] Cross-protocol bridges (ActivityPub, DIDComm)

## References

- [ActivityPub Specification](https://www.w3.org/TR/activitypub/)
- [Web of Trust](https://en.wikipedia.org/wiki/Web_of_trust)
- [RFC 6979: Deterministic ECDSA](https://datatracker.ietf.org/doc/html/rfc6979)
- [P-256 (secp256r1)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
