# 🔒 Security Model

Complete security analysis, threat model, and guarantees for Freebird.

---

## Table of Contents

1. [Security Guarantees](#security-guarantees)
2. [Threat Model](#threat-model)
3. [Attack Scenarios](#attack-scenarios)
4. [Limitations](#limitations)
5. [Best Practices](#best-practices)
6. [Cryptographic Assumptions](#cryptographic-assumptions)

---

## Security Guarantees

### What Freebird Guarantees

✅ **Unlinkability**
- **Property:** Issuer cannot link token issuance to redemption
- **Mechanism:** Random blinding factors make each issuance unique
- **Strength:** Computational (requires breaking elliptic curve discrete log)

✅ **Anonymity**
- **Property:** Verifier cannot identify token holder
- **Mechanism:** No identity information in tokens
- **Strength:** Information-theoretic (no identity = no way to recover it)

✅ **Unforgeability**
- **Property:** Cannot create valid tokens without issuer's secret key
- **Mechanism:** ECDLP hardness assumption
- **Strength:** 128-bit security (P-256)

✅ **Replay Protection**
- **Property:** Each token can only be verified once
- **Mechanism:** Nullifier-based detection with persistent storage
- **Strength:** Deterministic (same token = same nullifier)

✅ **Time-Bound Validity**
- **Property:** Tokens expire automatically
- **Mechanism:** Timestamp validation with clock skew tolerance
- **Strength:** Time-based (requires synchronized clocks ±5 minutes)

✅ **Verifiability**
- **Property:** Clients can verify server computed correctly
- **Mechanism:** DLEQ proof (Schnorr-style zero-knowledge proof)
- **Strength:** Cryptographic (soundness based on discrete log)

✅ **Multi-Issuer Trust Distribution**
- **Property:** Verifiers can accept tokens from multiple independent issuers
- **Mechanism:** Signature-based token authentication with issuer key rotation
- **Strength:** Cryptographic (ECDSA signatures)
- **Note:** See [FEDERATION.md](FEDERATION.md) for details

✅ **Sybil Resistance** (with appropriate mechanism)
- **Property:** One token per human without biometrics
- **Mechanism:** Trust-based social graph with ban trees (invitation system)
- **Strength:** Social (depends on community enforcement)

---

## Threat Model

### Trusted Components

**We Trust:**
- Issuers keep secret keys secure (not compromised)
- Verifier doesn't collude with specific issuer for timing correlation
- System clocks are reasonably synchronized (within ±5 minutes)
- Redis (if used) doesn't lose data unexpectedly
- HSM/PKCS11 modules (if used) protect keys correctly

**We Don't Trust:**
- Network (assume passive eavesdropping)
- Clients (may try to forge tokens, replay, etc.)
- External parties (may try to steal tokens)
- Any single issuer (multi-issuer federation distributes trust)

### Adversary Capabilities

**Adversary CAN:**
- Observe all network traffic (passive attack)
- Request tokens if they have valid Sybil proofs
- Attempt replays (will be detected and blocked)
- Try to forge tokens (will fail cryptographic verification)
- Steal tokens in transit (front-running attack)
- Manipulate clocks within tolerance (±5 minutes)
- Compromise one issuer in a federation (others remain trusted)

**Adversary CANNOT:**
- Break elliptic curve discrete logarithm (ECDLP)
- Forge valid DLEQ proofs or ECDSA signatures
- Link issuance to redemption (blinding protects)
- Reuse tokens (nullifier tracking prevents)
- Bypass invitation system without valid invitation
- Predict invitee IDs (192 bits of entropy)
- Extract keys from properly configured HSMs

---

## Attack Scenarios

### 1. Token Theft (Front-Running)

**Attack:**
```
1. Alice requests token from issuer
2. Eve intercepts token in transit (man-in-the-middle)
3. Eve submits token to verifier before Alice
4. Alice's token is now marked as "already used"
```

**Impact:** HIGH - Denial of service for legitimate user

**Mitigation:**
- ✅ Use TLS/HTTPS for all communications
- ✅ Deploy issuer/verifier on trusted network
- ⚠️ Consider binding tokens to client IP (reduces privacy)
- ⚠️ Implement client-side token storage (use token immediately)

**Status:** ❌ **Not protected by protocol** - Requires network security

---

### 2. Replay Attack

**Attack:**
```
1. Alice verifies token successfully
2. Alice tries to verify same token again
3. Verifier checks nullifier database
4. Nullifier exists → Reject
```

**Impact:** NONE (protected)

**Protection:**
- ✅ Nullifier-based replay detection
- ✅ Persistent storage (Redis or in-memory)
- ✅ Automatic cleanup after expiration

**Status:** ✅ **Fully protected**

---

### 3. Token Forgery

**Attack:**
```
1. Eve tries to create valid token without issuer secret key
2. Eve must compute H(input)^sk
3. Requires solving discrete logarithm problem
4. Computationally infeasible (2^128 operations)
```

**Impact:** NONE (protected)

**Protection:**
- ✅ ECDLP hardness assumption
- ✅ 128-bit security level (P-256)
- ✅ DLEQ proof verification

**Status:** ✅ **Fully protected**

---

### 4. Malicious Issuer (Tagging Attack)

**Attack:**
```
1. Malicious issuer uses different secret keys per user
2. Each user gets unique key → unique token signature
3. Issuer can link issuance to redemption
```

**Impact:** HIGH - Breaks unlinkability

**Protection:**
- ✅ DLEQ proof ensures issuer uses correct key
- ✅ Public key verification
- ✅ Client crypto layer verifies proofs automatically

**Status:** ✅ **Protected** - Clients verify DLEQ proofs

---

### 5. Issuer-Verifier Collusion

**Attack:**
```
1. Issuer logs all issuance timestamps
2. Verifier logs all verification timestamps
3. Issuer and verifier compare logs
4. Timing correlation links issuance to redemption
```

**Impact:** HIGH - Breaks anonymity

**Protection:**
- ✅ Deploy issuer and verifier on separate infrastructure
- ✅ Different administrative access controls
- ✅ Use multi-issuer federation (distributes trust)
- ⚠️ Use anonymous communication networks (Tor, VPN)
- ⚠️ Batch issuance/verification (timing obfuscation)

**Status:** ⚠️ **Operational security** - Requires proper deployment

---

### 6. Single Issuer Compromise (Federation Scenario)

**Attack:**
```
1. Adversary compromises one issuer in federation
2. Adversary tries to issue fraudulent tokens
3. Other issuers remain uncompromised
```

**Impact:** MEDIUM - Limited to compromised issuer's tokens

**Protection:**
- ✅ Verifier maintains separate trust roots per issuer
- ✅ Compromised issuer can be removed from trusted list
- ✅ Other issuers continue operating normally
- ✅ Users can request tokens from alternative issuers

**Status:** ✅ **Mitigated via federation** - Trust distributed across issuers

---

### 7. Clock Manipulation

**Attack:**
```
1. Adversary sets token expiration far in future
2. Token remains valid indefinitely
3. Verifier rejects (checks issuer default TTL)
```

**Impact:** LOW (protected with limits)

**Protection:**
- ✅ Verifier checks: `exp > current + default_ttl + skew`
- ✅ Clock skew tolerance limited (default: 5 minutes)
- ✅ NTP synchronization recommended

**Status:** ✅ **Protected with reasonable limits**

---

### 8. Sybil Attack (Without Resistance)

**Attack:**
```
1. Adversary creates multiple identities
2. Requests unlimited tokens
3. Overwhelms system or abuses service
```

**Impact:** HIGH (if no Sybil resistance)

**Protection:**
- ✅ Invitation system (trust-based)
- ✅ Proof-of-Work (computational cost)
- ✅ Rate limiting (IP-based throttling)
- ✅ WebAuthn/FIDO2 (hardware-backed proof of humanity)
- ⚠️ All have trade-offs (see [Sybil Resistance](SYBIL_RESISTANCE.md))

**Status:** ✅ **Protected with appropriate mechanism**

---

### 9. Invitation System Attacks

**9a. Invitation Stealing**

**Attack:**
```
1. Eve intercepts Alice's invitation code
2. Eve redeems invitation before Alice
3. Alice's invitation marked as used
```

**Impact:** MEDIUM - Denial of service

**Protection:**
- ✅ Share invitations over encrypted channels (Signal, etc.)
- ✅ Single-use enforcement prevents double redemption
- ⚠️ No way to distinguish legitimate redeemer from thief

**Status:** ⚠️ **Social/operational security**

**9b. Sybil via Compromised Inviter**

**Attack:**
```
1. Eve compromises Alice's account
2. Eve uses Alice's invites to create Sybil identities
3. Eve bypasses one-per-human restriction
```

**Impact:** MEDIUM - Sybil attack

**Protection:**
- ✅ Ban tree (banning Alice bans all her invitees)
- ✅ Reputation tracking (detect unusual invitation patterns)
- ✅ Cooldown periods (limit invitation rate)

**Status:** ✅ **Mitigated via ban system**

---

### 10. HSM/PKCS11 Attacks

**Attack:**
```
1. Adversary attempts to extract keys from HSM
2. Adversary tries timing attacks on HSM operations
3. Adversary attempts firmware manipulation
```

**Impact:** CRITICAL - If successful, issuer key compromise

**Protection:**
- ✅ HSMs provide tamper-resistant key storage
- ✅ Freebird uses hybrid mode (key storage only)
- ✅ PKCS11 interface prevents key extraction
- ⚠️ Physical security of HSM required
- ⚠️ Firmware updates must be verified

**Status:** ✅ **Protected with proper HSM deployment**

See [HSM_HYBRID_MODE.md](HSM_HYBRID_MODE.md) for implementation details.

---

## Limitations

### What Freebird Does NOT Protect

❌ **Front-Running / Token Theft**
- **Problem:** Tokens can be stolen in transit
- **Mitigation:** Use TLS, secure channels, immediate use
- **Future:** Consider IP binding (trade-off with privacy)

❌ **Network Anonymity**
- **Problem:** IP addresses visible to issuer/verifier
- **Mitigation:** Use Tor, VPN, anonymous proxies
- **Note:** Freebird provides *credential* anonymity, not *network* anonymity

❌ **Quantum Resistance**
- **Problem:** P-256 vulnerable to Shor's algorithm
- **Timeline:** Not a practical concern for 10-20 years
- **Mitigation:** Quantum-resistant curves (roadmap)

❌ **Perfect Sybil Resistance**
- **Problem:** All mechanisms have weaknesses
  - Invitation: Social engineering
  - PoW: Favors wealthy (better hardware)
  - Rate limiting: Bypassable (VPNs, proxies)
  - WebAuthn: Requires hardware tokens
- **Mitigation:** Defense-in-depth (combine mechanisms)

❌ **Issuer-Verifier Collusion**
- **Problem:** Timing correlation can break anonymity
- **Mitigation:** Separate infrastructure, batch operations, multi-issuer federation
- **Note:** Requires operational security, not just cryptography

---

## Best Practices

### Production Deployment

**Infrastructure:**
```
✅ Deploy issuer and verifier on separate infrastructure
✅ Use different cloud accounts or VPCs
✅ Implement network segmentation (firewalls)
✅ Enable TLS/HTTPS for all communications
✅ Use reverse proxy for rate limiting
✅ Consider multi-issuer federation for trust distribution
```

**Key Management:**
```
✅ Use HSM with PKCS11 interface (YubiHSM, Nitrokey HSM, etc.)
✅ Alternative: Cloud KMS (AWS KMS, Google Cloud KMS, Azure Key Vault)
✅ Hybrid mode: HSM for storage, software for VOPRF operations
✅ Use separate keys per environment (dev/staging/prod)
✅ Rotate keys quarterly
✅ Restrict key access (least privilege)
✅ Monitor key usage (audit logs)
```

**Monitoring:**
```
✅ Track token issuance rate (detect abuse)
✅ Monitor nullifier database size (cleanup issues)
✅ Alert on replay attempts (security events)
✅ Log Sybil proof failures (attack detection)
✅ Monitor clock skew (timing issues)
✅ Track issuer health in federation scenarios
```

**Invitation System:**
```
✅ Back up state daily
✅ Use strong invitee ID generation (192 bits entropy)
✅ Monitor invitation usage patterns (detect Sybil attacks)
✅ Implement ban trees (social accountability)
✅ Set appropriate cooldowns (prevent spam)
```

---

## Cryptographic Assumptions

### Hardness Assumptions

**1. Elliptic Curve Discrete Logarithm Problem (ECDLP)**

**Statement:** Given `P` and `Q = k*P`, finding `k` is hard.

**Security Level:** 128 bits (P-256)

**Broken If:**
- Quantum computers with sufficient qubits (Shor's algorithm)
- Breakthrough in classical discrete log algorithms

**Impact on Freebird:**
- Unforgeability relies on ECDLP
- DLEQ proof security relies on ECDLP
- ECDSA signatures (federation) rely on ECDLP
- P-256 compromise = complete protocol break

**2. Hash Function Security (SHA-256)**

**Properties:**
- Collision resistance: Finding `x ≠ y` where `H(x) = H(y)` is hard
- Preimage resistance: Given `y`, finding `x` where `H(x) = y` is hard

**Security Level:** 128 bits (birthday bound)

**Impact on Freebird:**
- Hash-to-curve security (deterministic point mapping)
- Nullifier uniqueness (collision = double-spend)
- HMAC security (token metadata binding in federation)

### Standard Model vs Random Oracle Model

**Freebird uses the Random Oracle Model:**
- Hash functions treated as truly random oracles
- Fiat-Shamir transform (DLEQ proof non-interactivity)
- Hash-to-curve (RFC 9380)

**Implications:**
- Proofs are heuristic (not proven in standard model)
- Practical security is strong (SHA-256 well-analyzed)
- Acceptable for real-world deployment

---

## Security Levels

| Component | Algorithm | Security Level | Quantum Resistance |
|-----------|-----------|----------------|-------------------|
| VOPRF | P-256 ECDLP | 128 bits | ❌ No |
| DLEQ Proof | Schnorr | 128 bits | ❌ No |
| Signatures (Federation) | ECDSA P-256 | 128 bits | ❌ No |
| Hash | SHA-256 | 128 bits | ✅ Yes |
| Nullifiers | SHA-256 | 128 bits | ✅ Yes |
| Invitee IDs | SHA-256 (192 bits) | 128 bits | ✅ Yes |
| HSM Storage | Hardware-dependent | Varies | Depends on HSM |

**Overall Security:** 128 bits (limited by ECDLP)

**128-bit security means:**
- ~2^128 operations to break
- ~10^38 operations
- ~1 billion years on all computers on Earth
- **Sufficient for decades** (pre-quantum)

---

## Formal Security Analysis

### Proven Properties

**Unlinkability (Computational):**
- Adversary cannot distinguish between:
  - (blinded_1, evaluated_1) and (blinded_2, evaluated_2)
  - Without breaking ECDLP

**Unforgeability (Computational):**
- Adversary cannot produce valid token without:
  - Issuer secret key OR
  - Solving discrete logarithm

**Verifiability (Soundness):**
- Cheating issuer cannot convince client that:
  - Incorrect evaluation is correct
  - With probability > 1/2^128

### Unproven Properties

**Anonymity Against Timing:**
- Timing correlation between issuance/verification
- Requires operational security (separate infrastructure)
- No cryptographic proof
- Multi-issuer federation reduces single point of failure

**Sybil Resistance:**
- Social/economic properties (invitation system, PoW)
- Not cryptographically proven
- Depends on mechanism choice

---

## Comparison to Standards

### NIST Guidelines

**P-256 (NIST P-256):**
- ✅ FIPS 186-5 approved
- ✅ Suite B cryptography
- ✅ Approved for US government use

**SHA-256:**
- ✅ FIPS 180-4 approved
- ✅ Widely used and analyzed

**ECDSA:**
- ✅ FIPS 186-5 approved
- ✅ Standard signature scheme

**Freebird is NIST-compliant** for cryptographic primitives.

### Privacy Pass Comparison

| Security Property | Privacy Pass | Freebird |
|-------------------|-------------|----------|
| Unlinkability | ✅ Yes | ✅ Yes |
| Unforgeability | ✅ Yes | ✅ Yes |
| Verifiability | ✅ Yes (DLEQ) | ✅ Yes (DLEQ) |
| Replay Protection | ✅ Yes | ✅ Yes |
| Sybil Resistance | CAPTCHA | Multiple options |
| Multi-Issuer | Limited | ✅ Yes (federation) |
| HSM Support | Unknown | ✅ Yes (PKCS11) |
| Deployment | Centralized | Self-hosted |

**Freebird provides equivalent cryptographic security with more deployment flexibility.**

---

## Audit Status

**Current Status:** ⚠️ **Not yet audited**

**Planned:**
- Security audit by reputable cryptography firm
- Focus on VOPRF implementation
- Invitation system security review
- Code review for common vulnerabilities

**Self-Assessment:**
- Code follows RustCrypto best practices
- No unsafe Rust in cryptographic code
- Comprehensive test coverage
- Based on well-studied protocols (VOPRF, Schnorr)
- Constant-time operations verified (see SECURITY_AUDIT_CONSTANT_TIME.md)

**Use in Production:**
- ⚠️ Understand risks before deployment
- ✅ Crypto primitives are standard (P-256, SHA-256)
- ✅ Protocol design is sound
- ⚠️ Implementation has not been independently verified

---

## Responsible Disclosure

**Found a security vulnerability?**

Please report privately via:
- GitHub Security Advisories
- Email: security@yourproject.com (encrypted PGP preferred)

**Do NOT:**
- Open public GitHub issues for vulnerabilities
- Disclose vulnerabilities before patch is available
- Exploit vulnerabilities maliciously

**We will:**
- Respond within 48 hours
- Provide credit in security advisory (if desired)
- Fix critical issues ASAP
- Coordinate disclosure timeline

---

## Related Documentation

- [How It Works](HOW_IT_WORKS.md) - Cryptographic protocol details
- [Multi-Issuer Federation](FEDERATION.md) - Trust distribution across issuers
- [HSM Hybrid Mode](HSM_HYBRID_MODE.md) - Hardware key storage implementation
- [Production Deployment](PRODUCTION.md) - Security hardening checklist
- [Configuration](CONFIGURATION.md) - Security-related settings
- [Sybil Resistance](SYBIL_RESISTANCE.md) - Mechanism comparison

---

**Security is a continuous process. Stay updated, monitor systems, and follow best practices.**
