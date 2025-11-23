# 🌱 Progressive Trust - Sybil Resistance

**Build trust over time, not through surveillance.**

Progressive Trust is a time-based Sybil resistance mechanism that rewards consistent, legitimate usage without requiring biometrics, external services, or invasive tracking.

---

## Overview

### The Problem

Traditional Sybil resistance mechanisms face a dilemma:
- **Too permissive**: No protection (unlimited bot accounts)
- **Too restrictive**: High friction (biometric ID, payment, social vouching)

### The Solution

**Progressive Trust** solves this by:
1. **Start lenient**: New users get limited access (e.g., 1 token/day)
2. **Build gradually**: Consistent usage over time unlocks higher tiers
3. **Reward loyalty**: Long-term users earn significantly more tokens

**Result**: Natural bot defense (time is unforgeable) + Low friction (no identity requirements)

---

## How It Works

### Trust Levels

Users progress through configurable trust tiers based on **account age**:

| Level | Account Age | Tokens/Period | Cooldown | Use Case |
|-------|-------------|---------------|----------|----------|
| **0** (New) | 0 days | 1 | 24 hours | New users, testing |
| **1** (Trusted) | 30 days | 10 | 1 hour | Regular users |
| **2** (Veteran) | 90 days | 100 | 1 minute | Power users |

### User Journey

```
Day 1:    Alice requests first token
          → Creates account, gets Level 0 (1 token/day)

Day 2:    Alice requests another token
          → Still Level 0, must wait 24h cooldown

Day 31:   Alice requests token
          → Promoted to Level 1! (10 tokens/hour)

Day 91:   Alice requests token
          → Promoted to Level 2! (100 tokens/minute)
```

### Privacy Model

- **No raw usernames stored** - User IDs are hashed (Blake3 + salt)
- **No surveillance** - Only tracks: first seen, token count, last issuance
- **Unforgeable proofs** - HMAC-signed to prevent client-side tampering
- **Pseudonymous** - Different deployments use different salts (no cross-issuer linking)

---

## Configuration

### Environment Variables

```bash
# Enable Progressive Trust
export SYBIL_RESISTANCE=progressive_trust

# Define trust levels: "min_age_secs:max_tokens:cooldown_secs"
export SYBIL_PROGRESSIVE_TRUST_LEVELS="0:1:86400,2592000:10:3600,7776000:100:60"
# Level 0: 0 days,  1 token,  24h cooldown
# Level 1: 30 days, 10 tokens, 1h cooldown
# Level 2: 90 days, 100 tokens, 1min cooldown

# Persistence
export SYBIL_PROGRESSIVE_TRUST_PERSISTENCE_PATH="progressive_trust.json"
export SYBIL_PROGRESSIVE_TRUST_AUTOSAVE_SECS=300  # Auto-save every 5 minutes

# Security (RECOMMENDED for production)
export SYBIL_PROGRESSIVE_TRUST_SECRET="$(openssl rand -base64 32)"
export SYBIL_PROGRESSIVE_TRUST_SALT="$(openssl rand -hex 16)"
```

### Simple Example (3-Tier System)

```bash
export SYBIL_RESISTANCE=progressive_trust
export SYBIL_PROGRESSIVE_TRUST_LEVELS="0:5:3600,604800:50:600,2592000:500:60"
# Level 0: New users    - 5 tokens/hour
# Level 1: 1 week old   - 50 tokens every 10 minutes
# Level 2: 30 days old  - 500 tokens/minute
```

### Aggressive Anti-Bot

```bash
export SYBIL_PROGRESSIVE_TRUST_LEVELS="0:1:86400,7776000:10:3600"
# Level 0: New users  - 1 token/day (very restrictive)
# Level 1: 90 days    - 10 tokens/hour
# Bots can't scale because they need 90 days to reach useful volume
```

### Generous for Humans

```bash
export SYBIL_PROGRESSIVE_TRUST_LEVELS="0:10:600,86400:100:60,604800:1000:10"
# Level 0: New users   - 10 tokens every 10 minutes
# Level 1: 1 day old   - 100 tokens/minute
# Level 2: 7 days old  - 1000 tokens every 10 seconds
# Good for trusted communities where Sybil risk is low
```

---

## API Integration

### Client-Side Flow

#### 1. **First Token Request** (New User)

```bash
# Client makes normal token request
curl -X POST https://issuer.example.com/v1/oprf/issue \
  -H "Content-Type: application/json" \
  -d '{
    "blinded_element_b64": "...",
    "sybil_proof": {
      "type": "progressive_trust",
      "user_id_hash": "blake3_hash_of_username",
      "first_seen": 1699454445,
      "tokens_issued": 0,
      "last_issuance": 0,
      "hmac_proof": "server_generated_proof"
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

#### 2. **Subsequent Requests** (Building Trust)

Same format, but values update:
- `tokens_issued` increments
- `last_issuance` updates to most recent timestamp
- `hmac_proof` must match server calculation

---

## Combinability

Progressive Trust can be combined with other mechanisms for defense-in-depth:

### Example 1: WebAuthn + Progressive Trust

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_COMBINED_MECHANISMS=webauthn,progressive_trust

# User must:
# 1. Authenticate with Face ID/Touch ID (WebAuthn)
# 2. Have sufficient account age (Progressive Trust)
```

**Use Case**: Maximum security - hardware key + time-based verification

### Example 2: Invitation + Progressive Trust

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_COMBINED_MECHANISMS=invitation,progressive_trust

# User must:
# 1. Have a valid invitation code
# 2. Meet Progressive Trust cooldown requirements
```

**Use Case**: High-value communities with controlled growth

### Example 3: Rate Limit + Progressive Trust

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_COMBINED_MECHANISMS=rate_limit,progressive_trust

# User must:
# 1. Pass IP-based rate limiting
# 2. Meet Progressive Trust tier requirements
```

**Use Case**: Defense against both Sybil attacks and distributed abuse

---

## Security Analysis

### Strengths

✅ **Time is unforgeable**
- Server controls timestamps
- Can't be faked by clients
- Natural Sybil defense (attackers need to wait months)

✅ **HMAC-signed proofs**
- Clients can't forge higher trust levels
- Cryptographically secure (Blake3 keyed hash)

✅ **Privacy-preserving**
- No biometrics
- No real names
- User IDs are salted hashes

✅ **Persistent across restarts**
- State saved to disk (JSON)
- No data loss on server restart

### Weaknesses

⚠️ **Patient attackers**
- Determined adversary can wait 90 days
- Mitigation: Combine with other mechanisms

⚠️ **Account farming**
- Create many accounts and wait
- Mitigation: Use Proof of Diversity or Multi-Party Vouching

⚠️ **Stolen accounts**
- High-trust accounts have value
- Mitigation: Combine with WebAuthn (hardware binding)

### Mitigations

**Best Practice**: Never use Progressive Trust alone for high-security applications. Combine with:
- **WebAuthn**: Hardware binding prevents account theft
- **Invitation**: Social graph limits account creation
- **Proof of Diversity**: Detects botnet behavior

---

## Use Cases

### ✅ Ideal For

1. **Public APIs** with gradual access ramp-up
2. **Community platforms** rewarding long-term members
3. **Content platforms** limiting spam from new accounts
4. **Token-gated services** with tiered membership
5. **Beta testing** programs with phased rollout

### ⚠️ Not Ideal For

1. **High-value targets** without additional mechanisms
2. **Instant access** requirements (new users start limited)
3. **Anonymous usage** where accounts can't build history
4. **Short-lived services** where 30-90 day wait is impractical

---

## Monitoring & Analytics

### Useful Metrics

Monitor `progressive_trust.json` for insights:

```bash
# Total users by trust level
jq '[.[] | .current_level] | group_by(.) | map({level: .[0], count: length})' progressive_trust.json

# Average account age
jq '[.[] | .first_seen] | add / length' progressive_trust.json

# Token distribution
jq '[.[] | .tokens_issued] | add' progressive_trust.json
```

### Red Flags

Monitor for suspicious patterns:
- **Spike in Level 0 accounts**: Possible Sybil attack preparation
- **Identical timestamps**: Batch account creation
- **Linear progression**: Automated farming

---

## Data Format

### Stored Record Example

```json
{
  "blake3_user_hash_abc123": {
    "user_id_hash": "blake3_user_hash_abc123",
    "first_seen": 1699454445,
    "tokens_issued": 127,
    "last_issuance": 1707890445,
    "current_level": 2
  }
}
```

**Privacy Note**: Raw usernames are never stored. Only salted Blake3 hashes.

---

## Roadmap

Future enhancements:

- [ ] **Decay mechanism**: Trust decreases if unused (anti-account farming)
- [ ] **Reputation scores**: More nuanced than binary levels
- [ ] **Dynamic thresholds**: Adjust based on server load
- [ ] **Account recovery**: Merge trust from verified old accounts
- [ ] **Trust transfer**: Move trust between devices (with proof)

---

## Comparison to Alternatives

| Mechanism | Initial Friction | Long-Term Friction | Sybil Resistance | Privacy |
|-----------|------------------|-------------------|------------------|---------|
| **None** | None | None | ❌ None | ✅ Perfect |
| **Captcha** | High | High | ⚠️ Weak | ⚠️ Medium |
| **Proof-of-Work** | Medium | Medium | ⚠️ Medium | ✅ High |
| **Invitation** | High | None | ✅ Strong | ✅ High |
| **WebAuthn** | Medium | Low | ✅ Strong | ✅ High |
| **Progressive Trust** | **Low** | **None** | ✅ **Strong** | ✅ **High** |

**Why Progressive Trust Wins**:
- Low initial friction (anyone can start)
- No long-term friction (veterans get unlimited)
- Strong Sybil resistance (time-based)
- High privacy (no biometrics or external services)

---

## Related Documentation

- [Sybil Resistance Overview](SYBIL_RESISTANCE.md)
- [WebAuthn Integration](WEBAUTHN.md) - Combine for hardware binding
- [Invitation System](INVITATION_SYSTEM.md) - Combine for social trust
- [Configuration Guide](CONFIGURATION.md)

---

**Progressive Trust: Privacy-preserving Sybil resistance through earned reputation.**
