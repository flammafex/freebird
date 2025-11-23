# 🛡️ Sybil Resistance Guide

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
| **WebAuthn** | ✅ Production | ✅✅✅ Strong | Zero | ✅✅ Good | Hardware-backed, biometric |
| **Combined** | ✅ Production | ✅✅✅ Strong | Multiple | ✅✅ Good | Defense-in-depth |

---

## 1. No Sybil Resistance (Permissive Mode)

### Configuration

```bash
export SYBIL_RESISTANCE=none
# Or omit SYBIL_RESISTANCE entirely
./target/release/issuer
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
export SYBIL_INVITE_COOLDOWN_SECS=3600
export SYBIL_INVITE_EXPIRES_SECS=2592000
export SYBIL_INVITE_NEW_USER_WAIT_SECS=2592000
export SYBIL_INVITE_PERSISTENCE_PATH=invitations.json
export SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS=300
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:100
./target/release/issuer
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

See [Invitation System Guide](INVITATION_SYSTEM.md) for complete documentation.

---

## 3. Proof-of-Work

### Configuration

```bash
export SYBIL_RESISTANCE=proof_of_work
export SYBIL_POW_DIFFICULTY=20  # Leading zero bits required
./target/release/issuer
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
export SYBIL_RATE_LIMIT_SECS=3600  # One token per hour per client
./target/release/issuer
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
export SYBIL_PROGRESSIVE_TRUST_LEVELS="0:1:86400,2592000:10:3600,7776000:100:60"
export SYBIL_PROGRESSIVE_TRUST_PERSISTENCE_PATH="progressive_trust.json"
export SYBIL_PROGRESSIVE_TRUST_AUTOSAVE_SECS=300
export SYBIL_PROGRESSIVE_TRUST_SECRET="$(openssl rand -base64 32)"
export SYBIL_PROGRESSIVE_TRUST_SALT="$(openssl rand -hex 16)"
./target/release/issuer
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

**Format**: `min_age_secs:max_tokens:cooldown_secs`

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

See [Progressive Trust Guide](PROGRESSIVE_TRUST.md) for complete documentation.

---

## 6. Proof of Diversity ⭐ (Anti-Botnet)

### Configuration

```bash
export SYBIL_RESISTANCE=proof_of_diversity
export SYBIL_PROOF_OF_DIVERSITY_MIN_SCORE=40  # Default
export SYBIL_PROOF_OF_DIVERSITY_PERSISTENCE_PATH="proof_of_diversity.json"
export SYBIL_PROOF_OF_DIVERSITY_AUTOSAVE_SECS=300
export SYBIL_PROOF_OF_DIVERSITY_SECRET="$(openssl rand -base64 32)"
export SYBIL_PROOF_OF_DIVERSITY_SALT="$(openssl rand -hex 16)"
./target/release/issuer
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

See [Proof of Diversity Guide](PROOF_OF_DIVERSITY.md) for complete documentation.

---

## 7. WebAuthn (Hardware Authenticators)

*For full WebAuthn documentation, see [WEBAUTHN.md](WEBAUTHN.md)*

### Quick Overview

**What**: Biometric authentication (Face ID, Touch ID, security keys)
**Strength**: ✅✅✅ Very Strong
**Cost**: Zero (no computation)
**Privacy**: ✅✅ Good (hardware-backed, no surveillance)

**Best for**: Hardware-backed Sybil resistance without computational cost

---

## 8. Combined Resistance (Defense-in-Depth)

### Configuration

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_POW_DIFFICULTY=20
export SYBIL_RATE_LIMIT_SECS=3600
./target/release/issuer
```

### How It Works

Client must provide proof satisfying **at least one** configured mechanism:

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

**OR**

```json
{
  "sybil_proof": {
    "type": "rate_limit",
    "client_id": "hashed_id",
    "timestamp": 1699454445
  }
}
```

### Current Implementation

**Accepts ANY valid proof type** (OR logic).

**Future Enhancement:** Require ALL configured mechanisms (AND logic):
- Must have valid PoW AND pass rate limit
- Stronger defense but more friction

### Properties

**Advantages:**
- ✅✅✅ **Layered defense** (multiple barriers)
- ✅ **Flexibility** (clients choose mechanism)
- ✅ **Adaptive security** (add/remove mechanisms)

**Disadvantages:**
- ⚠️ **Increased complexity** (multiple verification paths)
- ⚠️ **Current OR logic** (not true defense-in-depth)

### Use Cases

- ✅ **High-security applications** (need multiple barriers)
- ✅ **Graceful degradation** (if one mechanism fails, others work)
- ✅ **Transition periods** (introduce new mechanism while keeping old)

---

## Comparison Matrix

### Security Strength

| Mechanism | Against Bots | Against Humans | Against Wealthy | Against VPNs |
|-----------|--------------|----------------|-----------------|--------------|
| None | ❌ | ❌ | ❌ | ❌ |
| Invitation | ✅✅✅ | ✅✅✅ | ✅✅✅ | ✅✅✅ |
| Proof-of-Work | ✅✅✅ | ✅✅ | ❌ | ✅✅✅ |
| Rate Limiting | ✅✅ | ❌ | ❌ | ❌ |
| Combined | ✅✅✅ | ✅✅ | ✅ | ✅✅ |

### Privacy Impact

| Mechanism | Data Collected | Linkability | Surveillance Risk |
|-----------|----------------|-------------|-------------------|
| None | None | None | None |
| Invitation | Invite graph (pseudonymous) | Low | Low |
| Proof-of-Work | None | None | None |
| Rate Limiting | IP hash, timestamp | Medium | Low |
| Combined | Varies | Varies | Low |

### User Experience

| Mechanism | Friction | Speed | Accessibility |
|-----------|----------|-------|---------------|
| None | None | Instant | ✅ Universal |
| Invitation | Medium | Instant (after invite) | ⚠️ Requires inviter |
| Proof-of-Work | Low | ~1-30 seconds | ⚠️ Requires computation |
| Rate Limiting | None | Instant | ✅ Universal |
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
export SYBIL_INVITE_COOLDOWN_SECS=86400  # 24 hours
export SYBIL_INVITE_NEW_USER_WAIT_SECS=7776000  # 90 days
export SYBIL_INVITE_EXPIRES_SECS=604800  # 7 days (must use quickly)
```

### Public API (Moderate Protection)

```bash
export SYBIL_RESISTANCE=proof_of_work
export SYBIL_POW_DIFFICULTY=24  # ~10-30 seconds
```

### Simple Throttling

```bash
export SYBIL_RESISTANCE=rate_limit
export SYBIL_RATE_LIMIT_SECS=3600  # One token per hour
```

### Layered Defense

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_POW_DIFFICULTY=20  # Light PoW
export SYBIL_RATE_LIMIT_SECS=3600  # Plus rate limiting
```

---

## Future Mechanisms

**Roadmap:**
- [ ] WebAuthn (hardware keys)
- [ ] Email verification (one-time codes)
- [ ] Phone verification (SMS codes)
- [ ] Proof of humanity (hCaptcha, reCAPTCHA)
- [ ] Social proof (Twitter, GitHub verification)
- [ ] Economic bonds (stake tokens)

---

## Related Documentation

- [Invitation System](INVITATION_SYSTEM.md) - Complete invitation guide
- [Configuration](CONFIGURATION.md) - Environment variables
- [Security Model](SECURITY.md) - Threat model and guarantees
- [API Reference](API.md) - Sybil proof formats

---

**Choose the right mechanism for your threat model and user base. When in doubt, use the invitation system.**