# 🤝 Multi-Party Vouching - Sybil Resistance

**Social consensus-based Sybil resistance through collective accountability.**

Multi-Party Vouching requires multiple existing users to vouch for a new user before they can access the system, creating a web of trust through collective endorsement.

---

## Overview

### The Problem

Single-user invitation systems have weaknesses:
- **One compromised account** can invite unlimited Sybil identities
- **No collective accountability** - individual decisions, individual risk
- **Trust concentration** - single point of failure per invitation

Social consensus provides stronger guarantees:
- **Multiple vouchers required** - No single point of failure
- **Collective accountability** - Multiple users stake their reputation
- **Higher attack cost** - Must compromise N users, not 1

### The Solution

**Multi-Party Vouching** requires N existing users to vouch for each new user:
1. **New user requests access** - Provides their identity
2. **Existing users vouch** - Multiple trusted users endorse the request
3. **Threshold verification** - System checks N vouchers are present
4. **Reputation tracking** - Vouchers build positive/negative reputation
5. **Collective accountability** - All vouchers affected if vouchee misbehaves

**Result**: Sybil attacks require compromising multiple independent accounts, dramatically increasing attack cost.

---

## How It Works

### Vouching Process

```
Day 0:    Alice (existing user) vouches for Charlie
          Bob (existing user) vouches for Charlie
          David (existing user) vouches for Charlie

          → Charlie now has 3 vouches (meets threshold)
          → Charlie can request tokens

Day 30:   Charlie has been a good user
          → Alice, Bob, David earn +1 successful_vouch reputation

Day 60:   Charlie can now vouch for others (waiting period passed)
```

### Voucher Requirements

To vouch for a new user, you must:
- Be an existing voucher in the system
- Have passed the waiting period (default: 30 days)
- Not be in cooldown (default: 1 hour between vouches)
- Not have already vouched for this specific user

### Reputation System

Each voucher accumulates reputation:

```rust
VoucherRecord {
    successful_vouches: 5,   // Vouched users are in good standing
    problematic_vouches: 1,  // Vouched users were flagged/banned
    reputation_score: 83%    // 5/(5+1) = 83% success rate
}
```

**Future enhancements** could:
- Require minimum reputation to vouch
- Weight vouches by voucher reputation
- Auto-ban vouchers with low reputation

---

## Configuration

### Environment Variables

```bash
# Enable Multi-Party Vouching
export SYBIL_RESISTANCE=multi_party_vouching

# Threshold Configuration
export SYBIL_MULTI_PARTY_VOUCHING_REQUIRED=3  # Number of vouchers required (default: 3)

# Timing Configuration
export SYBIL_MULTI_PARTY_VOUCHING_COOLDOWN_SECS=3600  # 1 hour between vouches (default)
export SYBIL_MULTI_PARTY_VOUCHING_EXPIRES_SECS=2592000  # 30 days vouch validity (default)
export SYBIL_MULTI_PARTY_VOUCHING_NEW_USER_WAIT_SECS=2592000  # 30 days before vouching (default)

# Persistence
export SYBIL_MULTI_PARTY_VOUCHING_PERSISTENCE_PATH="multi_party_vouching.json"
export SYBIL_MULTI_PARTY_VOUCHING_AUTOSAVE_SECS=300  # Auto-save every 5 minutes

# Security (RECOMMENDED for production)
export SYBIL_MULTI_PARTY_VOUCHING_SECRET="$(openssl rand -base64 32)"
export SYBIL_MULTI_PARTY_VOUCHING_SALT="$(openssl rand -hex 16)"
```

### Configuration Examples

#### Strict Consensus

```bash
export SYBIL_RESISTANCE=multi_party_vouching
export SYBIL_MULTI_PARTY_VOUCHING_REQUIRED=5  # Require 5 vouchers
export SYBIL_MULTI_PARTY_VOUCHING_NEW_USER_WAIT_SECS=7776000  # 90 days before vouching
# Very strong Sybil resistance - hard to coordinate 5 compromised accounts
```

#### Moderate Consensus

```bash
export SYBIL_RESISTANCE=multi_party_vouching
export SYBIL_MULTI_PARTY_VOUCHING_REQUIRED=3  # Default: 3 vouchers
export SYBIL_MULTI_PARTY_VOUCHING_NEW_USER_WAIT_SECS=2592000  # 30 days
# Balanced security and usability
```

#### Lenient Consensus

```bash
export SYBIL_RESISTANCE=multi_party_vouching
export SYBIL_MULTI_PARTY_VOUCHING_REQUIRED=2  # Only 2 vouchers needed
export SYBIL_MULTI_PARTY_VOUCHING_NEW_USER_WAIT_SECS=604800  # 7 days
# Easier onboarding, lower security
```

---

## API Integration

### Server-Side: Bootstrap Initial Vouchers

```rust
// Bootstrap admin users who can vouch
let system = MultiPartyVouchingSystem::new(config).await?;

// Add initial vouchers with their public keys
let alice_sk = SigningKey::random(&mut OsRng);
let alice_pk = VerifyingKey::from(&alice_sk);
system.add_voucher("alice".to_string(), alice_pk).await?;

let bob_sk = SigningKey::random(&mut OsRng);
let bob_pk = VerifyingKey::from(&bob_sk);
system.add_voucher("bob".to_string(), bob_pk).await?;
```

### Client-Side: Submit Vouch

#### 1. **Voucher Signs Endorsement**

```javascript
// Voucher (Alice) signs endorsement for Charlie
const voucheeId = "charlie";
const timestamp = Math.floor(Date.now() / 1000);
const message = `vouch:${hash(voucheeId)}:${timestamp}`;

const signature = await alicePrivateKey.sign(message);

// Submit to server
const response = await fetch('/admin/vouch', {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${aliceToken}` },
  body: JSON.stringify({
    voucher_id: 'alice',
    vouchee_id: 'charlie',
    signature: base64url(signature),
  }),
});
```

#### 2. **Repeat for N Vouchers**

```javascript
// Bob vouches for Charlie
const bobVouch = await submitVouch('bob', 'charlie', bobSignature);

// David vouches for Charlie
const davidVouch = await submitVouch('david', 'charlie', davidSignature);

// Now Charlie has 3 vouches (Alice, Bob, David)
```

#### 3. **Generate Proof for Token Request**

```bash
# Charlie generates proof (server-side endpoint)
curl -X POST https://issuer.example.com/admin/multi-party-vouching/proof \
  -H "Authorization: Bearer <charlie_auth>" \
  -d '{"vouchee_id": "charlie"}'
```

**Server Response**:
```json
{
  "vouchee_id_hash": "blake3_hash_of_charlie",
  "vouches": [
    {
      "voucher_id": "blake3_hash_of_alice",
      "vouchee_id": "blake3_hash_of_charlie",
      "timestamp": 1699454445,
      "signature": "base64url_ecdsa_signature"
    },
    {
      "voucher_id": "blake3_hash_of_bob",
      "vouchee_id": "blake3_hash_of_charlie",
      "timestamp": 1699454450,
      "signature": "base64url_ecdsa_signature"
    },
    {
      "voucher_id": "blake3_hash_of_david",
      "vouchee_id": "blake3_hash_of_charlie",
      "timestamp": 1699454455,
      "signature": "base64url_ecdsa_signature"
    }
  ],
  "hmac_proof": "base64url_hmac",
  "timestamp": 1699454460
}
```

#### 4. **Token Request with Proof**

```bash
curl -X POST https://issuer.example.com/v1/oprf/issue \
  -H "Content-Type: application/json" \
  -d '{
    "blinded_element_b64": "...",
    "sybil_proof": {
      "type": "multi_party_vouching",
      "vouchee_id_hash": "blake3_hash_of_charlie",
      "vouches": [...],
      "hmac_proof": "base64url_hmac",
      "timestamp": 1699454460
    }
  }'
```

---

## Combinability

Multi-Party Vouching works excellently with other mechanisms:

### Example 1: Multi-Party Vouching + Progressive Trust

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_COMBINED_MECHANISMS=multi_party_vouching,progressive_trust

# New users must:
# 1. Get 3 vouches from existing users
# 2. Build progressive trust over time
# Result: Social accountability + time-based verification
```

**Use Case**: Community platforms where both social trust and consistent usage matter

### Example 2: Multi-Party Vouching + Proof of Diversity

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_COMBINED_MECHANISMS=multi_party_vouching,proof_of_diversity

# New users must:
# 1. Get 3 vouches from existing users
# 2. Demonstrate diverse network/device patterns
# Result: Social accountability + botnet detection
```

**Use Case**: Maximum anti-Sybil defense for high-value systems

### Example 3: Multi-Party Vouching + WebAuthn

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_COMBINED_MECHANISMS=multi_party_vouching,webauthn

# New users must:
# 1. Get 3 vouches from existing users
# 2. Authenticate with hardware key (Face ID, Touch ID)
# Result: Social accountability + hardware binding
```

**Use Case**: Enterprise or high-security applications

---

## Security Analysis

### Strengths

✅ **Strong Sybil resistance**
- Requires compromising N independent accounts
- Attack cost scales linearly with threshold

✅ **Collective accountability**
- All vouchers affected if vouchee misbehaves
- Natural social enforcement mechanism

✅ **Reputation tracking**
- Vouchers build trust through successful vouches
- Bad vouchers identified through problematic vouches

✅ **Unforgeable proofs**
- ECDSA P-256 signatures (256-bit security)
- HMAC-signed proof prevents tampering

✅ **Privacy-preserving**
- User IDs are hashed with salt
- No surveillance or biometrics required

### Weaknesses

⚠️ **Coordinated attack**
- Attackers could coordinate N compromised accounts
- Mitigation: High threshold (5+), long waiting periods

⚠️ **Social engineering**
- Malicious actors could deceive legitimate vouchers
- Mitigation: Reputation system, voucher education

⚠️ **Slow growth**
- New users must wait for multiple vouches
- Mitigation: Lower threshold for low-stakes systems

⚠️ **Bootstrap dependency**
- Requires initial trusted vouchers
- Mitigation: Admin-controlled bootstrap process

### Attack Scenarios

| Attack Type | Difficulty | Mitigation |
|-------------|-----------|------------|
| **Single compromised account** | ✅ Blocked | Requires N accounts, not 1 |
| **N compromised accounts** | ⚠️ Medium | Use high threshold (5+) |
| **Social engineering** | ⚠️ Medium | Reputation tracking identifies bad vouchers |
| **Sybil ring (coordinated)** | ❌ Hard | Combine with Proof of Diversity |
| **Patient Sybil** | ❌ Very hard | Combine with Progressive Trust |

---

## Use Cases

### ✅ Ideal For

1. **Community platforms** requiring trusted membership
2. **High-value applications** needing strong Sybil resistance
3. **Decentralized systems** without central authority
4. **Privacy-conscious platforms** (no biometrics/surveillance)
5. **Organic growth networks** with social accountability

### ⚠️ Not Ideal For

1. **Public APIs** with anonymous users (no vouchers)
2. **High-churn systems** (users come and go frequently)
3. **Low-trust environments** (vouchers don't know each other)
4. **Rapid onboarding** required (vouching takes time)

---

## Monitoring & Analytics

### Useful Metrics

Monitor `multi_party_vouching.json` for insights:

```bash
# Total vouchers
jq 'keys | length' multi_party_vouching.json

# Voucher reputation distribution
jq '[.[] | .successful_vouches / (.successful_vouches + .problematic_vouches)] |
    group_by(. * 10 | floor / 10) |
    map({reputation: .[0], count: length})' multi_party_vouching.json

# Average vouches per vouchee
jq '[.pending | to_entries[] | .value | length] | add / length' multi_party_vouching.json

# Top vouchers by successful vouches
jq 'to_entries | sort_by(-.value.successful_vouches) | .[0:10] |
    map({id: .key, successful: .value.successful_vouches})' multi_party_vouching.json
```

### Red Flags

Monitor for suspicious patterns:
- **Many problematic vouches from same voucher**: Compromised or malicious voucher
- **Coordinated vouching patterns**: Same N users always vouching together (Sybil ring)
- **Rapid vouching**: Voucher vouching for many users in short time
- **Expired vouches accumulating**: System configuration issue or attack

---

## Data Format

### Stored Voucher Record

```json
{
  "blake3_hash_of_alice": {
    "voucher_id": "blake3_hash_of_alice",
    "vouched_for": [
      "blake3_hash_of_charlie",
      "blake3_hash_of_eve"
    ],
    "last_vouch_time": 1699454445,
    "successful_vouches": 2,
    "problematic_vouches": 0,
    "first_seen": 1696862445,
    "public_key_b64": "base64url_encoded_p256_public_key"
  }
}
```

### Pending Vouches

```json
{
  "blake3_hash_of_charlie": [
    {
      "voucher_id": "blake3_hash_of_alice",
      "vouchee_id": "blake3_hash_of_charlie",
      "timestamp": 1699454445,
      "signature": "base64url_ecdsa_signature"
    },
    {
      "voucher_id": "blake3_hash_of_bob",
      "vouchee_id": "blake3_hash_of_charlie",
      "timestamp": 1699454450,
      "signature": "base64url_ecdsa_signature"
    },
    {
      "voucher_id": "blake3_hash_of_david",
      "vouchee_id": "blake3_hash_of_charlie",
      "timestamp": 1699454455,
      "signature": "base64url_ecdsa_signature"
    }
  ]
}
```

**Privacy Note**: All user IDs are hashed with salt - no raw usernames stored.

---

## Comparison to Single-User Invitation

| Feature | Single Invitation | Multi-Party Vouching |
|---------|------------------|---------------------|
| **Vouchers Required** | 1 | N (configurable) |
| **Attack Difficulty** | ⚠️ Low | ✅ High |
| **Collective Accountability** | ❌ No | ✅ Yes |
| **Reputation Tracking** | ⚠️ Limited | ✅ Comprehensive |
| **Sybil Resistance** | ⚠️ Moderate | ✅✅ Strong |
| **Onboarding Speed** | ✅ Fast | ⚠️ Slower |
| **Bootstrap Complexity** | ✅ Simple | ⚠️ Moderate |

**When to use Multi-Party Vouching over Invitation**:
- Need stronger Sybil resistance
- Collective accountability is important
- Can afford slower onboarding
- Have sufficient trusted initial vouchers

**When to use Invitation over Multi-Party Vouching**:
- Need fast onboarding
- Trust individual vouchers highly
- Small community (hard to find N vouchers)

---

## Relationship to Invitation System

Multi-Party Vouching and Invitation are:
- **Mutually exclusive** by default (can't use both simultaneously)
- **Complementary** in concept (both social trust-based)
- **Substitutable** based on security requirements

**User specification**: "Invitation should be able to be combined with Multi-Party Vouching and if they can not be, they should be mutually exclusive options."

**Current implementation**: Mutually exclusive (separate `SYBIL_RESISTANCE` modes)

**Future enhancement**: Could combine by requiring both:
1. Single invitation code (fast bootstrap)
2. N additional vouches (verification layer)

---

## Related Documentation

- [Sybil Resistance Overview](SYBIL_RESISTANCE.md)
- [Invitation System](INVITATION_SYSTEM.md) - Single-user vouching alternative
- [Progressive Trust](PROGRESSIVE_TRUST.md) - Combine for time-based + social verification
- [Proof of Diversity](PROOF_OF_DIVERSITY.md) - Combine for behavioral + social verification
- [WebAuthn Integration](WEBAUTHN.md) - Combine for hardware + social verification

---

**Multi-Party Vouching: Social consensus-based Sybil resistance through collective accountability.**
