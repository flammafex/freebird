# 🔐 How Freebird Works

Complete technical explanation of the VOPRF protocol and Freebird's implementation.

---

## Overview

Freebird uses **VOPRF (Verifiable Oblivious Pseudorandom Function)**, a cryptographic protocol that enables anonymous authentication without surveillance.

**The Magic:** A server can sign your data without ever seeing what it is, and you can prove the server signed correctly without revealing your original input.

---

## Table of Contents

1. [The Problem Freebird Solves](#the-problem-freebird-solves)
2. [VOPRF Protocol Basics](#voprf-protocol-basics)
3. [Complete Flow Diagram](#complete-flow-diagram)
4. [Cryptographic Details](#cryptographic-details)
5. [Security Properties](#security-properties)
6. [Why This Matters](#why-this-matters)

---

## The Problem Freebird Solves

### Traditional Authentication

```
┌────────┐                    ┌────────┐
│  User  │────── token ──────▶│ Server │
└────────┘                    └────────┘

Server sees:
✗ Who you are
✗ When you accessed
✗ What you accessed
✗ Your usage patterns
```

**Problems:**
- Server can track all user activity
- Privacy breach if server is compromised
- No way to prove authorization without identity
- Rate limiting requires tracking users

### Freebird's Solution

```
┌────────┐  blind   ┌─────────┐  anon   ┌──────────┐
│  User  │─────────▶│ Issuer  │         │ Verifier │
└────────┘          └─────────┘         └──────────┘
    │                                         ▲
    └──── unblind & finalize ────────────────┘

Issuer sees:
✓ Someone requested a token
✗ Cannot see original input
✗ Cannot link issuance to usage

Verifier sees:
✓ Valid token from authorized issuer
✗ Cannot identify user
✗ Cannot link multiple uses (unless double-spend)
```

**Benefits:**
- Issuer can't track where tokens are used
- Verifier can't identify token holders
- Replay protection prevents double-spending
- Sybil resistance prevents unlimited token acquisition

---

## VOPRF Protocol Basics

### What is VOPRF?

**VOPRF = Verifiable Oblivious Pseudorandom Function**

Breaking it down:

- **Pseudorandom Function (PRF):** Deterministic function that produces random-looking output
  - Input: Any data
  - Output: Fixed-size random-looking bytes
  - Property: Same input always produces same output

- **Oblivious (OPRF):** Server computes PRF without seeing the input
  - Client "blinds" (hides) their input
  - Server computes on blinded input
  - Client "unblinds" to recover result

- **Verifiable (VOPRF):** Client can verify server computed correctly
  - Server provides DLEQ proof
  - Client checks proof before accepting result
  - Prevents malicious servers from cheating

### The Three Properties

#### 1. **Obliviousness**

```
Client has: "secret_input"
Server has: secret_key

Client → [blinded_input] → Server
                           Server computes on blinded input
Client ← [blinded_output] ← Server

Client unblinds to get: PRF(secret_key, "secret_input")

Server NEVER sees "secret_input"
```

#### 2. **Pseudorandomness**

```
PRF(key, input1) = random-looking-bytes-1
PRF(key, input2) = random-looking-bytes-2

Properties:
- Deterministic (same input = same output)
- Unpredictable (can't guess output without key)
- Unlinkable (can't tell if two outputs came from same key)
```

#### 3. **Verifiability**

```
Server provides DLEQ proof:
"I computed this correctly using my secret key"

Client verifies:
✓ Proof is valid
✓ Server used the correct key
✓ Computation was honest

Without proof, client rejects the output
```

---

## Complete Flow Diagram

### Full Protocol Execution

```
┌─────────┐                 ┌─────────┐                 ┌──────────┐
│ Client  │                 │ Issuer  │                 │ Verifier │
└────┬────┘                 └────┬────┘                 └────┬─────┘
     │                           │                           │
     │ 1. Generate input         │                           │
     │    (random 32 bytes)      │                           │
     │                           │                           │
     │ 2. Blind input            │                           │
     │    blinded = H(input) * r │                           │
     │    (r = random scalar)    │                           │
     │                           │                           │
     │ 3. Send blinded ──────────▶                           │
     │    + Sybil proof (opt)    │                           │
     │                           │                           │
     │                           │ 4. Verify Sybil proof     │
     │                           │    (if configured)        │
     │                           │                           │
     │                           │ 5. Evaluate VOPRF         │
     │                           │    evaluated = blinded^sk │
     │                           │    (sk = secret key)      │
     │                           │                           │
     │                           │ 6. Create DLEQ proof      │
     │                           │    proof: "I used key sk" │
     │                           │                           │
     │ 7. Return signed ◀────────┤                           │
     │    + DLEQ proof           │                           │
     │    + expiration           │                           │
     │    + key ID               │                           │
     │                           │                           │
     │ 8. Verify DLEQ proof      │                           │
     │    (check server honesty) │                           │
     │                           │                           │
     │ 9. Unblind                │                           │
     │    token = evaluated / r  │                           │
     │                           │                           │
     │ 10. Send token ───────────┼──────────────────────────▶
     │     + expiration          │                           │
     │     + issuer_id           │                           │
     │                           │                           │
     │                           │                           │ 11. Check expiration
     │                           │                           │     (time-bound validity)
     │                           │                           │
     │                           │                           │ 12. Verify signature
     │                           │                           │     (DLEQ proof check)
     │                           │                           │
     │                           │                           │ 13. Compute nullifier
     │                           │                           │     (replay detection)
     │                           │                           │
     │                           │                           │ 14. Check nullifier DB
     │                           │                           │     (prevent double-spend)
     │                           │                           │
     │ 15. Success ◀─────────────┼───────────────────────────┤
     │                           │                           │
```

---

## Cryptographic Details

### Elliptic Curve: P-256 (NIST secp256r1)

**Parameters:**
- **Curve:** `y² = x³ - 3x + b (mod p)`
- **Prime:** `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`
- **Order:** `n = 2^256 - 432420386565659656852420866394968145599`
- **Generator:** `G` (standard base point)

**Why P-256?**
- ✅ Widely supported (hardware acceleration, RustCrypto)
- ✅ NIST standard (regulatory compliance)
- ✅ 128-bit security level (sufficient for decades)
- ✅ Fast operations (secp256k1 is slightly faster, but P-256 is more available)

### Hash Function: SHA-256

- **Output:** 256 bits (32 bytes)
- **Security:** Collision-resistant, preimage-resistant
- **Usage:** Hash-to-curve, nullifier derivation

### Hash-to-Curve: RFC 9380 (SSWU_RO)

**Purpose:** Convert arbitrary bytes to a curve point

**Algorithm:** Simplified SWU (SSWU) with Random Oracle (RO)

```rust
fn hash_to_curve(input: &[u8]) -> Point {
    // 1. Expand input using SHA-256
    let hash = SHA256(domain_separator || input);

    // 2. Map to curve point using SSWU
    let point = sswu_map(hash);

    // 3. Clear cofactor (P-256 has cofactor 1, so this is a no-op)
    point
}
```

**Properties:**
- Deterministic (same input = same point)
- Uniform distribution (indistinguishable from random points)
- One-way (can't reverse to find input)

### VOPRF Evaluation

**Blinding:**
```rust
// Client-side
let input = [random 32 bytes];
let input_point = hash_to_curve(&input);  // H(input)
let blind_scalar = random_scalar();        // r
let blinded = input_point * blind_scalar;  // H(input) * r
```

**Evaluation:**
```rust
// Server-side
let evaluated = blinded ^ secret_key;      // (H(input) * r)^sk
```

**Finalization:**
```rust
// Client-side
let blind_inverse = blind_scalar.invert(); // 1/r
let token = evaluated * blind_inverse;      // (H(input) * r)^sk * (1/r)
                                            // = H(input)^sk
```

**Result:** Client obtains `H(input)^sk` without server seeing `input`.

### DLEQ Proof (Discrete Logarithm Equality Proof)

**Purpose:** Prove that `evaluated = blinded^sk` without revealing `sk`

**Prover (Server) knows:**
- `sk` (secret key)
- `G` (generator)
- `pk = G^sk` (public key)
- `blinded` (from client)
- `evaluated = blinded^sk`

**Prover wants to prove:**
- `log_G(pk) = log_blinded(evaluated)`
- I.e., the same `sk` was used for both

**Schnorr-style proof:**

```rust
// 1. Server picks random scalar k
let k = random_scalar();

// 2. Compute commitments
let c1 = G * k;
let c2 = blinded * k;

// 3. Compute challenge (Fiat-Shamir)
let challenge = SHA256(G || blinded || pk || evaluated || c1 || c2);

// 4. Compute response
let response = k - challenge * sk;

// Proof = (challenge, response)
```

**Verifier (Client) checks:**

```rust
// 1. Recompute commitments
let c1_check = G * response + pk * challenge;
let c2_check = blinded * response + evaluated * challenge;

// 2. Recompute challenge
let challenge_check = SHA256(G || blinded || pk || evaluated || c1_check || c2_check);

// 3. Verify
assert_eq!(challenge, challenge_check);
```

**If verification passes:** Server honestly computed `evaluated = blinded^sk`.

### Nullifier Construction

**Purpose:** Detect token replay without linking to identity

```rust
nullifier = SHA256("freebird:nullifier:v1" || issuer_id || token_output);
```

**Properties:**
- Deterministic (same token = same nullifier)
- Unlinkable to input (can't reverse to find original input)
- Issuer-bound (different issuers = different nullifiers)
- Collision-resistant (different tokens = different nullifiers)

**Storage:**
```rust
// Verifier stores:
nullifier_db.insert(nullifier, expiration_timestamp);

// On verification:
if nullifier_db.contains(nullifier) {
    return Err("Token already used (replay attack)");
}
```

**Cleanup:**
```rust
// Automatically remove expired nullifiers
for (nullifier, exp) in nullifier_db {
    if current_time > exp {
        nullifier_db.remove(nullifier);
    }
}
```

---

## Security Properties

### What Freebird Guarantees

✅ **Unlinkability**
- Issuer cannot link token issuance to redemption
- Different blinding factors make each issuance unique
- Even with same input, outputs appear unrelated

✅ **Anonymity**
- Verifier cannot identify token holder
- No identity information in token
- Nullifier reveals nothing about input

✅ **Unforgeability**
- Cannot create valid token without issuer's secret key
- DLEQ proof ensures issuer cooperation
- Elliptic curve discrete logarithm assumption

✅ **Replay Protection**
- Each token can only be verified once
- Nullifier-based detection
- Automatic cleanup after expiration

✅ **Time-Bound Validity**
- Tokens expire automatically
- Clock skew tolerance prevents false rejections
- Expired tokens are rejected

✅ **Verifiability**
- Client can verify server computed correctly
- DLEQ proof provides cryptographic assurance
- Detects malicious issuers

### What Freebird Does NOT Guarantee

❌ **Front-Running Protection**
- Tokens can be stolen and used by others
- Network interception can capture tokens
- **Mitigation:** Use TLS/HTTPS for all communications

❌ **Network Anonymity**
- IP addresses visible to issuer and verifier
- **Mitigation:** Use Tor or VPN for network-level privacy

❌ **Quantum Resistance**
- P-256 vulnerable to Shor's algorithm on quantum computers
- **Timeline:** Not a practical concern for 10-20 years
- **Mitigation:** Future roadmap includes post-quantum curves

❌ **Perfect Sybil Resistance**
- All mechanisms have trade-offs (see [Sybil Resistance Guide](SYBIL_RESISTANCE.md))
- Invitation system is strongest but not perfect
- **Mitigation:** Combine multiple mechanisms (defense-in-depth)

---

## Why This Matters

### For Users

**Privacy:**
- Service providers can't build profiles of your behavior
- No tracking across sessions
- Anonymous participation in communities

**Control:**
- You decide when and where to use tokens
- No forced identity verification
- Pseudonymous by default

### For Developers

**Regulatory Compliance:**
- Less PII = less GDPR/CCPA liability
- No user tracking infrastructure required
- Simplified data retention policies

**Trust:**
- Users trust services that don't surveil
- Privacy as a competitive advantage
- Community self-policing (invitation system)

**Technical Benefits:**
- No centralized identity database
- Scalable verification (stateless except nullifiers)
- Flexible Sybil resistance (pluggable mechanisms)

### For Society

**Human Dignity:**
- Participate without being watched
- Speak truth without fear of retaliation
- Build communities based on trust, not surveillance

**Decentralization:**
- Self-hostable (no dependency on Cloudflare, Google, etc.)
- Community-controlled authentication
- Resistance to censorship

---

## Mathematical Proof Sketch

### Correctness

**Claim:** Client obtains `H(input)^sk` without server seeing `input`.

**Proof:**
```
1. Client computes:
   blinded = H(input) * r         (r = random scalar)

2. Server computes:
   evaluated = blinded^sk
             = (H(input) * r)^sk
             = H(input)^sk * r^sk  (scalar exponentiation distributes)

3. Client unblinds:
   token = evaluated * (1/r)
         = (H(input)^sk * r^sk) * (1/r)
         = H(input)^sk * r^sk * r^(-sk)  (invert exponent)
         = H(input)^sk * r^(sk - sk)
         = H(input)^sk * r^0
         = H(input)^sk * 1
         = H(input)^sk                    ✓

∴ Client obtains H(input)^sk without server learning input.
```

### Security (Informal)

**Obliviousness:**
- Server sees `blinded = H(input) * r`
- Without knowing `r`, server cannot recover `H(input)`
- Random `r` acts as one-time pad

**Unforgeability:**
- Creating valid token requires computing `H(input)^sk`
- Without `sk`, this requires solving discrete logarithm problem
- Discrete log is computationally hard (assumed)

**Unlinkability:**
- Each issuance uses different random `r`
- `blinded` appears uniformly random on curve
- Cannot link `blinded` values to same `input`

**Verifiability:**
- DLEQ proof binds `evaluated` to public key `pk = G^sk`
- Fiat-Shamir transform makes proof non-interactive
- Soundness: Cheating prover cannot fake proof (with high probability)

---

## Comparison to Other Protocols

### vs. Blind Signatures (Chaum 1983)

| Property | Blind Signatures | VOPRF |
|----------|------------------|-------|
| Obliviousness | ✅ Yes | ✅ Yes |
| Unlinkability | ✅ Yes | ✅ Yes |
| Verifiability | ❌ No (trust server) | ✅ Yes (DLEQ proof) |
| Efficiency | Moderate (RSA) | Fast (ECC) |
| Standard | Classic | Modern (IETF draft) |

**Freebird uses VOPRF for verifiability and efficiency.**

### vs. Coconut Credentials

| Property | Coconut | Freebird |
|----------|---------|----------|
| Threshold Issuance | ✅ Yes (distributed key) | ❌ No |
| Multi-Issuer Support | ❌ No | ✅ Yes (federation) |
| Attribute-Based | ✅ Yes | ❌ No (binary yes/no) |
| Complexity | High | Low |
| Maturity | Research | Standardizing |

**Freebird supports multi-issuer federation (not threshold) where a single verifier can accept tokens from multiple independent issuers.** See [FEDERATION.md](FEDERATION.md) for details.

### vs. Privacy Pass (Cloudflare)

| Property | Privacy Pass | Freebird |
|----------|-------------|----------|
| Protocol | VOPRF (draft RFC) | VOPRF (P-256) |
| Deployment | Centralized (Cloudflare) | Self-hostable |
| Control | Cloudflare policy | Your policy |
| Sybil Resistance | CAPTCHA | Multiple options |

**Freebird gives you complete control and deployment flexibility.**

---

## Implementation Notes

### Why Rust?

**Memory Safety:**
- No buffer overflows (cryptographic implementations are vulnerable)
- Safe concurrency (important for high-throughput servers)

**Performance:**
- Zero-cost abstractions (high-level code with low-level performance)
- Compiler optimizations (LLVM backend)

**Ecosystem:**
- RustCrypto provides high-quality P-256 implementation
- Tokio/Axum for async HTTP (production-ready)

### Why P-256 Specifically?

**Hardware Support:**
- Intel CPUs have AES-NI (used in hash-to-curve)
- ARM TrustZone supports P-256
- TPMs and HSMs widely support P-256

**Regulatory Acceptance:**
- NIST-approved (required for US government use)
- FIPS 186-4 compliant
- Industry standard (TLS, JWT, etc.)

**Practical Speed:**
- ~200µs per VOPRF evaluation on modern CPU
- ~5,000 ops/sec per core
- Good enough for most deployments

### Why Not secp256k1 (Bitcoin's Curve)?

- **Slightly faster:** ~10-20% in some operations
- **Less widely supported:** Fewer hardware implementations
- **No technical advantage:** Both are 128-bit security level
- **RustCrypto ecosystem:** Better P-256 support

**Decision:** P-256 offers better compatibility with minimal performance cost.

---

## Related Documentation

- [Multi-Issuer Federation](FEDERATION.md) - How verifiers accept tokens from multiple issuers
- [Security Model](SECURITY.md) - Threat model and assumptions
- [API Reference](API.md) - HTTP endpoints and data formats
- [Configuration Guide](CONFIGURATION.md) - Tuning cryptographic parameters

---

## Further Reading

**VOPRF Specification:**
- [IETF CFRG VOPRF Draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/)

**Hash-to-Curve:**
- [RFC 9380: Hashing to Elliptic Curves](https://datatracker.ietf.org/doc/rfc9380/)

**P-256 Curve:**
- [FIPS 186-5: Digital Signature Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)

**Blind Signatures:**
- [Chaum 1983: Blind Signatures for Untraceable Payments](https://link.springer.com/chapter/10.1007/978-1-4757-0602-4_18)

**Privacy Pass:**
- [Privacy Pass Protocol (IETF Draft)](https://datatracker.ietf.org/doc/draft-ietf-privacypass-protocol/)

---

**Questions or want to dive deeper? Check [SECURITY.md](SECURITY.md) or open a GitHub issue for clarification.**
