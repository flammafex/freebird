# 🌐 Proof of Diversity - Sybil Resistance

**Detect botnets through behavioral diversity analysis.**

Proof of Diversity is an anti-botnet Sybil resistance mechanism that analyzes network and device diversity patterns to distinguish legitimate users from automated attacks.

---

## Overview

### The Problem

Botnets exhibit uniform patterns:
- **Same datacenter IPs** - All requests from identical ASNs
- **Identical User-Agents** - Copy-pasted browser fingerprints
- **No temporal diversity** - Recently created, no historical patterns

Real users exhibit natural diversity:
- **Multiple networks** - Home, work, mobile data, coffee shops
- **Multiple devices** - Phone, laptop, tablet
- **Time-based patterns** - Accounts age naturally

### The Solution

**Proof of Diversity** detects botnets by:
1. **Tracking network diversity** - Count of unique ASNs/networks accessed from
2. **Tracking device diversity** - Count of unique browser/device fingerprints
3. **Rewarding longevity** - Older accounts score higher
4. **Privacy-preserving** - All fingerprints are hashed with per-user salts

**Result**: Botnets fail on all three dimensions (uniform networks, uniform devices, new accounts)

---

## How It Works

### Diversity Scoring

Users accumulate diversity scores based on observed behavior:

```
diversity_score = (unique_networks × 30) + (unique_devices × 20) + min(time_span_days, 50)

Maximum score: ~100
- 3 networks = 90 points
- 3 devices = 60 points
- 50+ days = 50 points
```

### Example User Journey

```
Day 1:    Alice accesses from home WiFi (192.168.1.1) on iPhone
          → 1 network, 1 device
          → Score: 50 (30 + 20 + 0)

Day 5:    Alice accesses from work (10.0.0.1) on MacBook
          → 2 networks, 2 devices
          → Score: 100 (60 + 40 + 0)

Day 50:   Alice accesses from mobile data on iPad
          → 3 networks, 3 devices
          → Score: 150 (90 + 60 + 0)
          → Capped at minimum score requirement
```

### Privacy Model

- **No raw IPs stored** - Network identifiers are hashed (Blake3 + per-user salt)
- **No raw User-Agents stored** - Device fingerprints are hashed (Blake3 + per-user salt)
- **Pseudonymous** - User IDs are hashed (Blake3 + global salt)
- **No cross-user correlation** - Different users have different salts
- **Unforgeable proofs** - HMAC-signed to prevent client tampering

---

## Configuration

### Environment Variables

```bash
# Enable Proof of Diversity
export SYBIL_RESISTANCE=proof_of_diversity

# Minimum diversity score required (0-255)
export SYBIL_PROOF_OF_DIVERSITY_MIN_SCORE=40  # Default

# Persistence
export SYBIL_PROOF_OF_DIVERSITY_PERSISTENCE_PATH="proof_of_diversity.json"
export SYBIL_PROOF_OF_DIVERSITY_AUTOSAVE_SECS=300  # Auto-save every 5 minutes

# Security (RECOMMENDED for production)
export SYBIL_PROOF_OF_DIVERSITY_SECRET="$(openssl rand -base64 32)"
export SYBIL_PROOF_OF_DIVERSITY_SALT="$(openssl rand -hex 16)"
```

### Configuration Examples

#### Strict Anti-Botnet

```bash
export SYBIL_RESISTANCE=proof_of_diversity
export SYBIL_PROOF_OF_DIVERSITY_MIN_SCORE=80
# Requires 2+ networks (60 pts) + 1+ device (20 pts) = 80 minimum
# Botnets with uniform IPs fail instantly
```

#### Balanced Security

```bash
export SYBIL_RESISTANCE=proof_of_diversity
export SYBIL_PROOF_OF_DIVERSITY_MIN_SCORE=40  # Default
# Requires 1+ network (30 pts) + 1+ device (20 pts) = 50 minimum
# Or wait for time-based scoring
```

#### Lenient (Testing)

```bash
export SYBIL_RESISTANCE=proof_of_diversity
export SYBIL_PROOF_OF_DIVERSITY_MIN_SCORE=20
# Very permissive - mostly for development/testing
```

---

## API Integration

### Server-Side Observation

The server automatically observes diversity when configured:

```rust
// In your issuance handler (happens automatically)
let network_info = extract_network_identifier(&req);  // ASN or IP
let device_info = extract_user_agent(&req);           // User-Agent header
let username = extract_username(&req);                // From auth

system.observe_access(username, network_info, device_info).await?;
```

### Client-Side Flow

#### 1. **Generate Proof** (Client requests proof)

```bash
# Client generates proof for token request
curl -X POST https://issuer.example.com/v1/diversity/proof \
  -H "Authorization: Bearer <auth_token>" \
  -d '{"username": "alice"}'
```

**Server Response**:
```json
{
  "user_id_hash": "blake3_hash_of_alice",
  "diversity_score": 100,
  "unique_networks": 2,
  "unique_devices": 2,
  "first_seen": 1699454445,
  "hmac_proof": "base64url_hmac_signature"
}
```

#### 2. **Token Request** (Include proof)

```bash
curl -X POST https://issuer.example.com/v1/oprf/issue \
  -H "Content-Type: application/json" \
  -d '{
    "blinded_element_b64": "...",
    "sybil_proof": {
      "type": "proof_of_diversity",
      "user_id_hash": "blake3_hash_of_alice",
      "diversity_score": 100,
      "unique_networks": 2,
      "unique_devices": 2,
      "first_seen": 1699454445,
      "hmac_proof": "base64url_hmac_signature"
    }
  }'
```

**Server Response**:
```json
{
  "token": "base64url-voprf-token",
  "kid": "freebird-2024-11-17",
  "exp": 1699458045,
  "sybil_info": {
    "required": true,
    "passed": true,
    "cost": 0
  }
}
```

---

## Combinability

Proof of Diversity works excellently with other mechanisms for defense-in-depth:

### Example 1: WebAuthn + Proof of Diversity

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_COMBINED_MECHANISMS=webauthn,proof_of_diversity

# User must:
# 1. Authenticate with hardware key (WebAuthn)
# 2. Have sufficient diversity score (Proof of Diversity)
```

**Use Case**: High-security applications requiring both device binding and behavioral validation

### Example 2: Progressive Trust + Proof of Diversity

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_COMBINED_MECHANISMS=progressive_trust,proof_of_diversity

# User must:
# 1. Have sufficient account age (Progressive Trust)
# 2. Demonstrate natural diversity (Proof of Diversity)
```

**Use Case**: Maximum anti-botnet protection - time-based + behavioral analysis

### Example 3: Rate Limit + Proof of Diversity

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_COMBINED_MECHANISMS=rate_limit,proof_of_diversity

# User must:
# 1. Pass IP-based rate limiting
# 2. Have natural diversity patterns
```

**Use Case**: Defense against both DDoS and sophisticated Sybil attacks

---

## Security Analysis

### Strengths

✅ **Behavioral detection**
- Botnets naturally fail diversity checks
- No false negatives for real users with diverse behavior

✅ **Privacy-preserving**
- No raw IPs or User-Agents stored
- Per-user salts prevent cross-user correlation
- HMAC proofs prevent forgery

✅ **Unforgeable**
- Cryptographically signed proofs (Blake3 HMAC)
- Server-controlled observations

✅ **Persistent across restarts**
- State saved to disk (JSON)
- No data loss on server restart

### Weaknesses

⚠️ **Sophisticated attackers**
- Can simulate diversity with VPNs and browser spoofing
- Mitigation: Combine with Progressive Trust or WebAuthn

⚠️ **New legitimate users**
- Fresh accounts start with low scores
- Mitigation: Set reasonable minimum score (40 is balanced)

⚠️ **Privacy trade-off**
- Requires tracking network/device observations
- Mitigation: All data is hashed, no raw fingerprints stored

### Attack Scenarios

| Attack Type | Difficulty | Mitigation |
|-------------|-----------|------------|
| **Single-IP botnet** | ❌ Fails instantly | Min score = 40+ requires diversity |
| **VPN rotation** | ⚠️ Medium | Combine with Progressive Trust (time-based) |
| **Browser fingerprint spoofing** | ⚠️ Medium | Combine with WebAuthn (hardware binding) |
| **Patient diverse botnet** | ✅ Very hard | Combine with all three (WebAuthn + Progressive Trust + Diversity) |

---

## Use Cases

### ✅ Ideal For

1. **Public APIs** vulnerable to botnet abuse
2. **Content platforms** fighting spam farms
3. **Token-gated services** requiring human behavior validation
4. **Anti-fraud systems** detecting automated attacks
5. **Rate limiting bypass** for legitimate diverse users

### ⚠️ Not Ideal For

1. **VPN-heavy user bases** (false positives for privacy-conscious users)
2. **Single-device services** (mobile-only apps)
3. **Short-lived sessions** (no time to build diversity)
4. **Strict privacy requirements** (tracking observations)

---

## Monitoring & Analytics

### Useful Metrics

Monitor `proof_of_diversity.json` for insights:

```bash
# Average diversity score
jq '[.[] | .score] | add / length' proof_of_diversity.json

# Users by score range
jq '[.[] | .score] | group_by(. / 10 | floor * 10) | map({range: .[0], count: length})' proof_of_diversity.json

# Network diversity distribution
jq '[.[] | .unique_networks.length] | group_by(.) | map({networks: .[0], count: length})' proof_of_diversity.json
```

### Red Flags

Monitor for suspicious patterns:
- **Many users with score < 30**: Possible botnet attack
- **Identical diversity scores**: Automated proof generation
- **Sudden spike in new users**: Account farming preparation

---

## Data Format

### Stored Record Example

```json
{
  "blake3_user_hash_abc123": {
    "user_id_hash": "blake3_user_hash_abc123",
    "first_seen": 1699454445,
    "last_seen": 1707890445,
    "unique_networks": [
      "blake3_hash_of_network_1",
      "blake3_hash_of_network_2",
      "blake3_hash_of_network_3"
    ],
    "unique_devices": [
      "blake3_hash_of_device_1",
      "blake3_hash_of_device_2"
    ],
    "score": 110
  }
}
```

**Privacy Note**: All hashes are per-user salted - no raw IPs, User-Agents, or usernames stored.

---

## Comparison to Alternatives

| Mechanism | Botnet Detection | Privacy | False Positives | Deployment Complexity |
|-----------|-----------------|---------|-----------------|----------------------|
| **None** | ❌ None | ✅ Perfect | None | Trivial |
| **Rate Limit** | ⚠️ Weak | ✅ High | Medium | Low |
| **Proof-of-Work** | ⚠️ Medium | ✅ High | Low | Low |
| **Invitation** | ✅ Strong | ✅ High | Low | Medium |
| **Progressive Trust** | ✅ Strong | ✅ High | Low | Low |
| **WebAuthn** | ⚠️ Weak* | ✅ High | Low | High |
| **Proof of Diversity** | ✅ **Strong** | ⚠️ **Medium** | **Medium** | **Low** |

*WebAuthn detects credential stuffing, not botnets

**Why Proof of Diversity Excels at Botnet Detection**:
- Directly targets botnet behavioral patterns
- Low deployment complexity (just environment variables)
- Strong detection without biometric requirements
- Privacy trade-off is acceptable (hashed fingerprints)

---

## Related Documentation

- [Sybil Resistance Overview](SYBIL_RESISTANCE.md)
- [Progressive Trust](PROGRESSIVE_TRUST.md) - Combine for time-based + behavioral validation
- [WebAuthn Integration](WEBAUTHN.md) - Combine for hardware binding
- [Configuration Guide](CONFIGURATION.md)

---

**Proof of Diversity: Behavioral Sybil resistance through natural diversity patterns.**
