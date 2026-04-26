# Sybil Resistance Guide

Comprehensive comparison of all Sybil resistance mechanisms in Freebird.

---

## What is Sybil Resistance?

**Sybil Attack:** An adversary creates multiple fake identities to gain disproportionate influence or resources.

**In Freebird Context:** Without Sybil resistance, an attacker can request unlimited tokens, defeating the purpose of rate limiting or access control.

**Goal:** Ensure one token per legitimate user (or rate-limit token acquisition) without requiring biometric identification or surveillance.

---

## Available Mechanisms

| Mechanism | Status | Strength | Cost | Privacy | Best For |
|-----------|--------|----------|------|---------|----------|
| **None** | ✅ Default | ❌ None | Free | ✅ High | Testing, low-stakes |
| **Invitation** | ✅ Production | ✅✅✅ Strong | Social | ✅✅ Good | Communities, high-value |
| **Proof-of-Work** | ✅ Production | ✅✅ Moderate | Computation | ✅ High | Public services |
| **Rate Limiting** | ✅ Production | ✅ Weak | Time | ✅✅ Good | Simple throttling |
| **Progressive Trust** | ✅ Production | ✅✅ Strong | Time | ✅✅✅ Excellent | Gradual access, loyalty rewards |
| **Proof of Diversity** | ✅ Production | ✅✅✅ Strong | Behavioral | ✅✅ Good | Anti-botnet, diversity analysis |
| **Multi-Party Vouching** | ✅ Production | ✅✅✅ Strong | Social | ✅✅ Good | Collective accountability, consensus |
| **WebAuthn** | ✅ Production | ✅✅✅ Strong | Zero | ✅✅ Good | Hardware-backed, biometric |
| **Combined** | ✅ Production | ✅✅✅ Strong | Multiple | ✅✅ Good | Defense-in-depth |

---

## 1. No Sybil Resistance (Permissive Mode)

### Configuration

```bash
export SYBIL_RESISTANCE=none
# Or omit SYBIL_RESISTANCE entirely
./target/release/freebird-issuer
```

### How It Works

Tokens are issued freely to anyone who requests them. No verification, no proof required.

### Properties

**Advantages:**
- ✅ No friction for users
- ✅ Perfect privacy (no data collection)
- ✅ Fast (no verification overhead)
- ✅ Simple to implement

**Disadvantages:**
- ❌ No Sybil protection (unlimited tokens)
- ❌ Vulnerable to abuse
- ❌ Not suitable for production (most cases)

### Use Cases

- **Development and testing**
- **Low-stakes applications** (no abuse incentive)
- **When Sybil resistance is handled elsewhere** (external auth)
- **Public resources** where unlimited access is acceptable

---

## 2. Invitation System ⭐ (Recommended)

### Configuration

```bash
export SYBIL_RESISTANCE=invitation
export SYBIL_INVITE_PER_USER=5
export SYBIL_INVITE_COOLDOWN=1h
export SYBIL_INVITE_EXPIRES=30d
export SYBIL_INVITE_NEW_USER_WAIT=30d
export SYBIL_INVITE_PERSISTENCE_PATH=invitations.json
export SYBIL_INVITE_AUTOSAVE_INTERVAL=5m
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:100
./target/release/freebird-issuer
```

### How It Works

1. **Bootstrap:** Admin creates initial users with invite quotas
2. **Generate:** Existing users create cryptographically signed invitations
3. **Share:** Invitations shared out-of-band (email, Signal, etc.)
4. **Redeem:** New users provide invitation code + signature when requesting token
5. **Verify:** Issuer validates signature and marks invitation as used
6. **Growth:** After waiting period, new users earn invites and can invite others

### Properties

**Advantages:**
- ✅✅✅ **Strong Sybil resistance** (social accountability)
- ✅ **No biometrics** (trust-based, not surveillance)
- ✅ **Self-policing** (ban trees enable community enforcement)
- ✅ **Privacy-preserving** (verifier never sees invitation history)
- ✅ **Persistent state** (survives restarts)
- ✅ **Flexible configuration** (quotas, cooldowns, waiting periods)

**Disadvantages:**
- ⚠️ **Social engineering risk** (malicious inviters)
- ⚠️ **Growth rate limited** (by invite quotas)
- ⚠️ **Requires out-of-band communication** (email, messaging)
- ⚠️ **Bootstrap dependency** (needs initial trusted users)

### Security

**Attack Vectors:**
1. **Compromised Inviter:** Attacker compromises user account → uses invites for Sybil identities
   - **Mitigation:** Ban tree (banning inviter bans all invitees)
2. **Invitation Theft:** Attacker intercepts invitation in transit
   - **Mitigation:** Share over encrypted channels (Signal, encrypted email)
3. **Invitation Market:** Users sell invitations
   - **Mitigation:** Reputation tracking, ban sellers and buyers

**Strengths:**
- 192 bits of entropy in invitee IDs (collision-resistant)
- ECDSA P-256 signatures (unforgeable)
- Single-use enforcement (can't reuse invitations)

### Use Cases

- ✅ **Trust-based communities** (members vouch for each other)
- ✅ **High-value applications** (need strong Sybil resistance)
- ✅ **Privacy-conscious platforms** (no biometrics or surveillance)
- ✅ **Organic growth networks** (natural expansion rate)

### Detailed Guide

See [Configuration Reference](CONFIGURATION.md#invitation-system) for detailed settings.

---

## 3. Proof-of-Work

### Configuration

```bash
export SYBIL_RESISTANCE=proof_of_work
export SYBIL_POW_DIFFICULTY=20  # Leading zero bits required
./target/release/freebird-issuer
```

### How It Works

1. Client generates random nonce
2. Client computes `SHA-256(input || nonce)`
3. If hash has N leading zero bits, submit to issuer
4. Issuer verifies hash has required difficulty
5. If valid, issue token

### Properties

**Advantages:**
- ✅ **No identity required** (pure computational proof)
- ✅ **Scalable difficulty** (adjust based on threat level)
- ✅ **Privacy-preserving** (no personal data)
- ✅ **Permissionless** (anyone can participate)

**Disadvantages:**
- ❌ **Favors wealthy** (better hardware = more tokens)
- ❌ **Energy wasteful** (electricity cost)
- ❌ **Not true Sybil resistance** (just expensive, not one-per-human)
- ❌ **ASICs can dominate** (specialized hardware advantage)

### Difficulty Guide

| Bits | Avg Hashes | Time (Typical CPU) | Cost | Use Case |
|------|------------|-------------------|------|----------|
| 16 | ~65k | Instant | None | Testing |
| 20 | ~1M | ~1 second | ~$0.000001 | Light protection |
| 24 | ~16M | ~10-30 seconds | ~$0.00001 | Moderate protection |
| 28 | ~268M | ~5-10 minutes | ~$0.0001 | Strong protection |
| 32 | ~4B | ~hours | ~$0.01 | Very strong |

**Cost calculation:** Based on ~$0.10/kWh electricity, ~100W CPU, ~5 GH/s.

### Use Cases

- ✅ **Public APIs** (rate limiting without accounts)
- ✅ **Anonymous content submission** (prevent spam)
- ✅ **Bot prevention** (humans can compute, bots cost money)
- ❌ **High-value applications** (wealthy can still Sybil attack)

---

## 4. Rate Limiting

### Configuration

```bash
export SYBIL_RESISTANCE=rate_limit
export SYBIL_RATE_LIMIT=1h  # One token per hour per client
./target/release/freebird-issuer
```

### How It Works

1. Client identifier derived from IP address (hashed)
2. Optionally include User-Agent fingerprint
3. Issuer tracks last issuance time per client ID
4. If `current_time - last_issuance < rate_limit`, reject
5. Otherwise, issue token and update timestamp

### Properties

**Advantages:**
- ✅ **Simple to implement** (no complex verification)
- ✅ **Low overhead** (just timestamp tracking)
- ✅ **Privacy-preserving** (IP hashed before storage)
- ✅ **No computation required** (fast)

**Disadvantages:**
- ❌ **Easily bypassable** (VPNs, Tor, residential proxies)
- ❌ **False positives** (shared IPs, NAT, public WiFi)
- ❌ **Not true Sybil resistance** (just throttling)
- ❌ **State storage required** (track client IDs)

### Client ID Derivation

```rust
SHA-256("freebird:client:" || ip_address || user_agent_hash)[0..16]
```

**Privacy:** Raw IP and User-Agent never stored, only hashes.

### Use Cases

- ✅ **Simple throttling** (prevent rapid-fire requests)
- ✅ **Supplement to other mechanisms** (defense-in-depth)
- ❌ **Primary Sybil resistance** (too weak on its own)

---

## 5. Progressive Trust ⭐ (Recommended)

### Configuration

```bash
export SYBIL_RESISTANCE=progressive_trust
export SYBIL_PROGRESSIVE_TRUST_LEVELS="0:1:1d,30d:10:1h,90d:100:1m"
export SYBIL_PROGRESSIVE_TRUST_PERSISTENCE_PATH="progressive_trust.json"
export SYBIL_PROGRESSIVE_TRUST_AUTOSAVE=5m
export SYBIL_PROGRESSIVE_TRUST_SECRET="$(openssl rand -base64 32)"
export SYBIL_PROGRESSIVE_TRUST_SALT="$(openssl rand -hex 16)"
./target/release/freebird-issuer
```

### How It Works

1. **New users** start at Level 0 with limited access (e.g., 1 token/day)
2. **Consistent usage** over time unlocks higher trust levels
3. **Veteran users** (90+ days) get significantly higher limits
4. **Server tracks**: first seen, tokens issued, last issuance
5. **HMAC-signed proofs** prevent forgery

### Trust Levels (Default)

| Level | Min Age | Tokens | Cooldown | Description |
|-------|---------|--------|----------|-------------|
| 0 | 0 days | 1 | 24 hours | New users |
| 1 | 30 days | 10 | 1 hour | Trusted users |
| 2 | 90 days | 100 | 1 minute | Veterans |

**Format**: `min_age:max_tokens:cooldown`, where durations can be raw seconds
or values such as `1h`, `30d`, and `90d`.

### Properties

**Advantages:**
- ✅✅✅ **Low friction** (anyone can start)
- ✅✅✅ **Strong Sybil resistance** (time is unforgeable)
- ✅✅✅ **Privacy-preserving** (no biometrics, only hashed user IDs)
- ✅✅ **Rewards loyalty** (long-term users get more)
- ✅✅ **Natural bot defense** (bots can't scale fast)
- ✅ **Configurable** (adjust levels for your use case)

**Disadvantages:**
- ⚠️ **Patient attackers** (can wait 90 days)
- ⚠️ **Account farming** (create many accounts and wait)
- ⚠️ **Initial limits** (new legitimate users start restricted)

### Security

**Attack Vectors:**
1. **Account farming:** Create many accounts and wait
   - **Mitigation:** Combine with Proof of Diversity or Multi-Party Vouching
2. **Stolen accounts:** High-trust accounts have value
   - **Mitigation:** Combine with WebAuthn (hardware binding)
3. **Patient Sybil:** Wait months to reach high tier
   - **Mitigation:** Acceptable (significantly raises attack cost)

**Strengths:**
- Time cannot be faked (server-controlled timestamps)
- HMAC-based proofs (unforgeable)
- Privacy-preserving (salted Blake3 hashes)
- Persistent state (survives restarts)

### Use Cases

- ✅ **Public APIs** (gradual access ramp-up)
- ✅ **Content platforms** (limit spam from new accounts)
- ✅ **Community platforms** (reward long-term members)
- ✅ **Token-gated services** (tiered membership)
- ✅ **Freemium apps** (free tier with trust-based limits)

### Detailed Guide

See [Configuration Reference](CONFIGURATION.md#progressive-trust) for detailed settings.

---

## 6. Proof of Diversity ⭐ (Anti-Botnet)

### Configuration

```bash
export SYBIL_RESISTANCE=proof_of_diversity
export SYBIL_PROOF_OF_DIVERSITY_MIN_SCORE=40  # Default
export SYBIL_PROOF_OF_DIVERSITY_PERSISTENCE_PATH="proof_of_diversity.json"
export SYBIL_PROOF_OF_DIVERSITY_AUTOSAVE=5m
export SYBIL_PROOF_OF_DIVERSITY_SECRET="$(openssl rand -base64 32)"
export SYBIL_PROOF_OF_DIVERSITY_SALT="$(openssl rand -hex 16)"
./target/release/freebird-issuer
```

### How It Works

1. **Server observes** network diversity (unique ASNs/IPs) and device diversity (unique User-Agents)
2. **Privacy-preserving** - All fingerprints are hashed with per-user salts
3. **Diversity score** calculated: `(networks × 30) + (devices × 20) + min(days, 50)`
4. **Minimum score** required to pass verification
5. **HMAC-signed proofs** prevent forgery

### Diversity Scoring (Default)

```
Max score: ~100
- 3 unique networks = 90 points
- 3 unique devices = 60 points
- 50+ days active = 50 points

Example:
- Home WiFi + Work WiFi + Mobile Data = 90 pts
- iPhone + MacBook = 40 pts
- Total: 130 pts (well above 40 minimum)
```

### Properties

**Advantages:**
- ✅✅✅ **Strong botnet detection** (uniform IPs/devices fail)
- ✅✅ **Privacy-preserving** (all fingerprints hashed)
- ✅✅ **Natural user behavior** (real users naturally diverse)
- ✅ **Unforgeable** (HMAC-signed proofs)
- ✅ **Persistent state** (survives restarts)

**Disadvantages:**
- ⚠️ **VPN users** (may appear less diverse)
- ⚠️ **Single-device users** (lower scores)
- ⚠️ **Requires observation** (tracks network/device patterns)

### Security

**Attack Vectors:**
1. **VPN rotation:** Simulate diversity with VPN switching
   - **Mitigation:** Combine with Progressive Trust (time-based)
2. **Browser fingerprint spoofing:** Fake diverse User-Agents
   - **Mitigation:** Combine with WebAuthn (hardware binding)
3. **Patient diverse botnet:** Very sophisticated attack
   - **Mitigation:** Very difficult and expensive to execute

**Strengths:**
- Directly targets botnet behavioral patterns
- Privacy-preserving (no raw IPs/User-Agents stored)
- HMAC proofs prevent forgery
- Works well with other mechanisms

### Use Cases

- ✅ **Public APIs** (vulnerable to botnet abuse)
- ✅ **Content platforms** (fighting spam farms)
- ✅ **Anti-fraud systems** (detecting automated attacks)
- ✅ **Rate limiting bypass** (legitimate diverse users)
- ⚠️ **VPN-heavy user bases** (may need lower minimum score)

### Detailed Guide

See [Configuration Reference](CONFIGURATION.md#proof-of-diversity) for detailed settings.

---

## 7. Multi-Party Vouching ⭐ (Social Consensus)

### Configuration

```bash
export SYBIL_RESISTANCE=multi_party_vouching
export SYBIL_MULTI_PARTY_VOUCHING_REQUIRED=3  # Number of vouchers required
export SYBIL_MULTI_PARTY_VOUCHING_COOLDOWN=1h
export SYBIL_MULTI_PARTY_VOUCHING_EXPIRES=30d
export SYBIL_MULTI_PARTY_VOUCHING_NEW_USER_WAIT=30d
export SYBIL_MULTI_PARTY_VOUCHING_SECRET="$(openssl rand -base64 32)"
export SYBIL_MULTI_PARTY_VOUCHING_SALT="$(openssl rand -hex 16)"
./target/release/freebird-issuer
```

### How It Works

1. **New user requests access** - Provides their identity
2. **Multiple existing users vouch** - N trusted users endorse (ECDSA-signed)
3. **Threshold verification** - System checks N vouches are present and valid
4. **Reputation tracking** - Vouchers build positive/negative reputation over time
5. **HMAC-signed proofs** prevent forgery

### Vouching Workflow

```
Day 0:    Alice vouches for Charlie (ECDSA signature)
          Bob vouches for Charlie (ECDSA signature)
          David vouches for Charlie (ECDSA signature)
          → Charlie has 3 vouches (meets threshold)
          → Charlie can request tokens

Day 30:   Charlie is in good standing
          → Alice, Bob, David: +1 successful_vouch

Day 60:   Charlie can now vouch for others (waiting period passed)
```

### Properties

**Advantages:**
- ✅✅✅ **Strong Sybil resistance** (requires compromising N accounts)
- ✅✅✅ **Collective accountability** (all vouchers affected if vouchee misbehaves)
- ✅✅ **Reputation tracking** (vouchers build trust over time)
- ✅✅ **Privacy-preserving** (hashed user IDs, no surveillance)
- ✅ **Unforgeable** (ECDSA P-256 signatures + HMAC proofs)

**Disadvantages:**
- ⚠️ **Coordinated attack** (N colluding accounts can vouch for Sybils)
- ⚠️ **Slower onboarding** (must collect N vouches)
- ⚠️ **Bootstrap dependency** (needs initial trusted vouchers)

### Security

**Attack Vectors:**
1. **N compromised accounts:** Coordinate to vouch for Sybil
   - **Mitigation:** High threshold (5+), combine with Proof of Diversity
2. **Social engineering:** Deceive legitimate vouchers
   - **Mitigation:** Reputation tracking identifies bad vouchers
3. **Sybil ring:** Create circular vouching network
   - **Mitigation:** Combine with Progressive Trust (time-based)

**Strengths:**
- ECDSA P-256 signatures (unforgeable)
- Collective accountability (distributed risk)
- Reputation system (bad vouchers identified)
- Privacy-preserving (hashed IDs)

### Use Cases

- ✅ **Community platforms** (trusted membership)
- ✅ **High-value applications** (strong Sybil resistance)
- ✅ **Decentralized systems** (no central authority)
- ✅ **Privacy-conscious platforms** (no biometrics)
- ⚠️ **Public APIs** (requires existing voucher network)

### Detailed Guide

See [Configuration Reference](CONFIGURATION.md#multi-party-vouching) for detailed settings.

---

## 8. WebAuthn (Hardware Authenticators)

*For full WebAuthn documentation, see [WEBAUTHN.md](WEBAUTHN.md)*

### Quick Overview

**What**: Biometric authentication (Face ID, Touch ID, security keys)
**Strength**: ✅✅✅ Very Strong
**Cost**: Zero (no computation)
**Privacy**: ✅✅ Good (hardware-backed, no surveillance)

**Best for**: Hardware-backed Sybil resistance without computational cost

---

## 9. Combined Resistance (Defense-in-Depth)

Combine multiple Sybil resistance mechanisms with flexible logic modes.

### Configuration

#### Basic Configuration (OR mode - default)

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_COMBINED_MECHANISMS=pow,rate_limit
export SYBIL_COMBINED_MODE=or  # Default
export SYBIL_POW_DIFFICULTY=20
export SYBIL_RATE_LIMIT=1h
./target/release/freebird-issuer
```

#### Advanced Configuration (Custom Mechanism List)

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_COMBINED_MECHANISMS=pow,progressive_trust,invitation
export SYBIL_COMBINED_MODE=or
# Configure each mechanism as needed
export SYBIL_POW_DIFFICULTY=24
export SYBIL_PROGRESSIVE_TRUST_LEVELS="0:1:1d,30d:10:1h"
export SYBIL_INVITE_PER_USER=5
./target/release/freebird-issuer
```

### Available Combination Modes

#### 1. OR Mode (Flexible Choice)

**Configuration:**
```bash
export SYBIL_COMBINED_MODE=or
export SYBIL_COMBINED_MECHANISMS=pow,rate_limit,invitation
```

**How It Works:**
- Client provides **ONE** proof
- Proof must satisfy **ANY** configured mechanism
- Client chooses which mechanism to use

**Example Proof (PoW):**
```json
{
  "sybil_proof": {
    "type": "proof_of_work",
    "nonce": 123456,
    "input": "...",
    "timestamp": 1699454445
  }
}
```

**Example Proof (Invitation):**
```json
{
  "sybil_proof": {
    "type": "invitation",
    "code": "inv_abc123",
    "signature": "base64_signature"
  }
}
```

**Use Cases:**
- ✅ **Graceful degradation** (fallback mechanisms)
- ✅ **User choice** (different user preferences)
- ✅ **Transition periods** (migrate between mechanisms)

#### 2. AND Mode (Maximum Security)

**Configuration:**
```bash
export SYBIL_COMBINED_MODE=and
export SYBIL_COMBINED_MECHANISMS=pow,rate_limit,progressive_trust
```

**How It Works:**
- Client provides **MULTIPLE** proofs (one for each mechanism)
- **ALL** mechanisms must verify successfully
- True defense-in-depth

**Example Proof:**
```json
{
  "sybil_proof": {
    "type": "multi",
    "proofs": [
      {
        "type": "proof_of_work",
        "nonce": 123456,
        "input": "...",
        "timestamp": 1699454445
      },
      {
        "type": "rate_limit",
        "client_id": "hashed_id",
        "timestamp": 1699454445
      },
      {
        "type": "progressive_trust",
        "user_id_hash": "...",
        "first_seen": 1699454445,
        "tokens_issued": 10,
        "last_issuance": 1699454445,
        "hmac_proof": "..."
      }
    ]
  }
}
```

**Use Cases:**
- ✅ **Maximum security** (multiple independent barriers)
- ✅ **High-value resources** (critical infrastructure)
- ✅ **Regulated environments** (compliance requirements)

**Trade-offs:**
- ⚠️ **Higher friction** (more proofs to generate)
- ⚠️ **Slower** (multiple verifications)
- ⚠️ **More complex client implementation**

#### 3. Threshold Mode (Flexible Security)

**Configuration:**
```bash
export SYBIL_COMBINED_MODE=threshold
export SYBIL_COMBINED_THRESHOLD=2
export SYBIL_COMBINED_MECHANISMS=pow,rate_limit,progressive_trust,invitation
```

**How It Works:**
- Client provides **MULTIPLE** proofs
- At least **N** mechanisms must verify successfully
- Balances security and flexibility

**Example (2 out of 4 required):**
```json
{
  "sybil_proof": {
    "type": "multi",
    "proofs": [
      {
        "type": "proof_of_work",
        "nonce": 123456,
        "input": "...",
        "timestamp": 1699454445
      },
      {
        "type": "progressive_trust",
        "user_id_hash": "...",
        "first_seen": 1699454445,
        "tokens_issued": 10,
        "last_issuance": 1699454445,
        "hmac_proof": "..."
      }
    ]
  }
}
```

**Use Cases:**
- ✅ **Adaptive security** (client chooses strongest proofs)
- ✅ **Partial failures** (some mechanisms may be unavailable)
- ✅ **Progressive hardening** (increase threshold over time)

**Common Configurations:**
- **2 of 3:** Moderate security, good availability
- **3 of 5:** High security, flexible proof selection
- **4 of 6:** Maximum security, still allows some failures

### Supported Mechanisms in Combined Mode

All mechanisms can be combined:

| Mechanism | Config Name | Requirements |
|-----------|-------------|--------------|
| Proof of Work | `pow` | SYBIL_POW_DIFFICULTY |
| Rate Limiting | `rate_limit` | SYBIL_RATE_LIMIT |
| Invitation | `invitation` | SYBIL_INVITE_* configs |
| Progressive Trust | `progressive_trust` | SYBIL_PROGRESSIVE_TRUST_* configs |
| Proof of Diversity | `proof_of_diversity` | SYBIL_PROOF_OF_DIVERSITY_* configs |
| Multi-Party Vouching | `multi_party_vouching` | SYBIL_MULTI_PARTY_VOUCHING_* configs |
| WebAuthn | `webauthn` | WEBAUTHN_* configs |

### Example Configurations

#### Light Security (Public API)
```bash
export SYBIL_COMBINED_MODE=or
export SYBIL_COMBINED_MECHANISMS=pow,rate_limit
export SYBIL_POW_DIFFICULTY=20
export SYBIL_RATE_LIMIT=1h
```

#### Medium Security (Community Service)
```bash
export SYBIL_COMBINED_MODE=threshold
export SYBIL_COMBINED_THRESHOLD=2
export SYBIL_COMBINED_MECHANISMS=pow,progressive_trust,invitation
export SYBIL_POW_DIFFICULTY=24
export SYBIL_INVITE_PER_USER=3
```

#### Maximum Security (Critical Infrastructure)
```bash
export SYBIL_COMBINED_MODE=and
export SYBIL_COMBINED_MECHANISMS=invitation,progressive_trust,proof_of_diversity
export SYBIL_INVITE_PER_USER=1
export SYBIL_PROGRESSIVE_TRUST_LEVELS="90d:1:1d"
export SYBIL_PROOF_OF_DIVERSITY_MIN_SCORE=70
```

#### Defense-in-Depth (Enterprise)
```bash
export SYBIL_COMBINED_MODE=threshold
export SYBIL_COMBINED_THRESHOLD=3
export SYBIL_COMBINED_MECHANISMS=pow,progressive_trust,proof_of_diversity,multi_party_vouching,webauthn
export SYBIL_POW_DIFFICULTY=24
export SYBIL_PROGRESSIVE_TRUST_LEVELS="0:1:1d,30d:10:1h"
export SYBIL_PROOF_OF_DIVERSITY_MIN_SCORE=50
export SYBIL_MULTI_PARTY_VOUCHING_REQUIRED=3
# WebAuthn config...
```

### Properties

**Advantages:**
- ✅✅✅ **Maximum flexibility** (choose mode and mechanisms)
- ✅✅✅ **True defense-in-depth** (AND/Threshold modes)
- ✅✅ **Graceful degradation** (OR/Threshold modes)
- ✅ **Adaptive security** (adjust threshold dynamically)
- ✅ **Mix complementary mechanisms** (computational + social + temporal)

**Disadvantages:**
- ⚠️ **Increased complexity** (multiple verification paths)
- ⚠️ **Higher overhead** (AND/Threshold modes)
- ⚠️ **More configuration** (each mechanism needs setup)
- ⚠️ **Client complexity** (multi-proof generation for AND/Threshold)

### Use Cases

- ✅ **High-security applications** (need multiple independent barriers)
- ✅ **Critical infrastructure** (AND mode with strong mechanisms)
- ✅ **Gradual hardening** (start with OR, move to Threshold, then AND)
- ✅ **Hybrid environments** (different user classes with different requirements)
- ✅ **Regulatory compliance** (meet multiple security standards)

---

## Comparison Matrix

### Security Strength

| Mechanism | Against Bots | Against Humans | Against Wealthy | Against VPNs |
|-----------|--------------|----------------|-----------------|--------------|
| None | ❌ | ❌ | ❌ | ❌ |
| Invitation | ✅✅✅ | ✅✅✅ | ✅✅✅ | ✅✅✅ |
| Proof-of-Work | ✅✅✅ | ✅✅ | ❌ | ✅✅✅ |
| Rate Limiting | ✅✅ | ❌ | ❌ | ❌ |
| Progressive Trust | ✅✅✅ | ✅✅ | ✅✅ | ✅✅ |
| Proof of Diversity | ✅✅✅ | ✅✅ | ✅✅ | ✅ |
| Multi-Party Vouching | ✅✅✅ | ✅✅✅ | ✅✅✅ | ✅✅✅ |
| WebAuthn | ✅✅✅ | ✅✅✅ | ✅✅✅ | ✅✅✅ |
| Combined | ✅✅✅ | ✅✅✅ | ✅✅ | ✅✅ |

### Privacy Impact

| Mechanism | Data Collected | Linkability | Surveillance Risk |
|-----------|----------------|-------------|-------------------|
| None | None | None | None |
| Invitation | Invite graph (pseudonymous) | Low | Low |
| Proof-of-Work | None | None | None |
| Rate Limiting | IP hash, timestamp | Medium | Low |
| Progressive Trust | Hashed user ID, timestamps | Low | Very Low |
| Proof of Diversity | Hashed networks/devices | Low | Very Low |
| Multi-Party Vouching | Vouch graph (pseudonymous) | Low | Low |
| WebAuthn | Credential ID, public key | Low | Low |
| Combined | Varies | Varies | Low |

### User Experience

| Mechanism | Friction | Speed | Accessibility |
|-----------|----------|-------|---------------|
| None | None | Instant | ✅ Universal |
| Invitation | Medium | Instant (after invite) | ⚠️ Requires inviter |
| Proof-of-Work | Low | ~1-30 seconds | ⚠️ Requires computation |
| Rate Limiting | None | Instant | ✅ Universal |
| Progressive Trust | Very Low | Instant | ✅ Universal (starts limited) |
| Proof of Diversity | Very Low | Instant | ✅ Universal (starts limited) |
| Multi-Party Vouching | Medium | Instant (after vouches) | ⚠️ Requires vouchers |
| WebAuthn | Low | ~1-3 seconds | ⚠️ Requires hardware |
| Combined | Varies | Varies | ⚠️ Most restrictive |

---

## Decision Matrix

### Choose Invitation If:

✅ Building a community or platform  
✅ Need strong Sybil resistance  
✅ Users willing to trust each other  
✅ Growth rate can be controlled  
✅ Privacy is paramount (no biometrics)  

### Choose Proof-of-Work If:

✅ Need permissionless access  
✅ Moderate Sybil resistance sufficient  
✅ Users have computational resources  
✅ Energy cost acceptable  
✅ Public service (no identity required)  

### Choose Rate Limiting If:

✅ Just need basic throttling  
✅ Supplementing another mechanism  
✅ Very low friction required  
✅ Don't need strong Sybil resistance  

### Choose Combined If:

✅ Need defense-in-depth
✅ High-security application
✅ Can tolerate multiple proofs
✅ Want flexibility (users choose mechanism)

---

## Configuration Examples

### High-Security Community

```bash
export SYBIL_RESISTANCE=invitation
export SYBIL_INVITE_PER_USER=3
export SYBIL_INVITE_COOLDOWN=1d
export SYBIL_INVITE_NEW_USER_WAIT=90d
export SYBIL_INVITE_EXPIRES=7d
```

### Public API (Moderate Protection)

```bash
export SYBIL_RESISTANCE=proof_of_work
export SYBIL_POW_DIFFICULTY=24  # ~10-30 seconds
```

### Simple Throttling

```bash
export SYBIL_RESISTANCE=rate_limit
export SYBIL_RATE_LIMIT=1h
```

### Layered Defense

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_POW_DIFFICULTY=20  # Light PoW
export SYBIL_RATE_LIMIT=1h  # Plus rate limiting
```

---

## Related Documentation

- [Configuration](CONFIGURATION.md) - Environment variables for all mechanisms
- [WebAuthn](WEBAUTHN.md) - Hardware-backed authentication
- [Security Model](SECURITY.md) - Threat model and guarantees
- [API Reference](API.md) - Sybil proof formats

---

**Choose the right mechanism for your threat model and user base. When in doubt, use the invitation system.**
