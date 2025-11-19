[<div align=center><img src="freebird.webp">](https://carpocratian.org/en/church/)
[<div align=center><br><img src="church.png" width=72 height=72>](https://carpocratian.org/en/church/)

_A mission of [The Carpocratian Church of Commonality and Equality](https://carpocratian.org/en/church/)_.</div>
<div align=center><img src="mission.png" width=256 height=200></div></div>

# 🕊️ Freebird

**Anonymous credential system using VOPRF cryptography**

Freebird is a self-hostable anonymous token system that allows users to prove authorization without revealing their identity. Think of it as anonymous digital cash for the internet—users get cryptographic tokens that prove "I'm authorized" without revealing "who I am."

**Current Version: 0.1.0** (Pre-release)

**Core Features:**
- 🔒 **Cryptographic Unlinkability** – Issuer can't track where tokens are used (P-256 VOPRF)
- 🛡️ **Multiple Sybil Resistance Options** – Invitations, proof-of-work, rate limiting, WebAuthn
- 🏠 **Self-Hostable** – No central authority required
- ♻️ **Replay Protection** – Nullifier-based double-spend prevention
- ⏱️ **Token Expiration** – Time-bound validity with clock skew tolerance
- ⚡ **Batch Issuance** – Process multiple tokens in parallel with Rayon
- 🔑 **Key Rotation** – Multi-key support with graceful rotation via admin API

---

## 🚧 Project Status

**This is a working prototype undergoing stabilization.** Core cryptography works, but expect:
- API changes before 1.0
- Limited production testing
- Documentation gaps
- No formal security audit yet

### ✅ Implemented & Working

**Core Protocol:**
- ✅ P-256 VOPRF implementation (custom, not using external crate)
- ✅ DLEQ proof verification
- ✅ Token issuance and verification
- ✅ Nullifier-based replay protection
- ✅ Token expiration with clock skew tolerance

**Sybil Resistance:**
- ✅ Invitation system with Ed25519 signatures
- ✅ Proof-of-work (configurable difficulty)
- ✅ Rate limiting (IP-based)
- ✅ WebAuthn/FIDO2 support (feature flag: `human-gate-webauthn`)
- ✅ Combined mechanisms (multiple checks)

**Infrastructure:**
- ✅ Redis backend for verifier storage
- ✅ In-memory storage option
- ✅ Admin API with API key authentication
- ✅ Key rotation with grace periods
- ✅ Batch token issuance (Rayon parallelization)
- ✅ Basic CLI testing interface

**WebAuthn (Experimental):**
- ✅ Registration and authentication flows
- ✅ Redis credential storage
- ✅ Attestation policy modes (none/strict/log_only)
- ⚠️ Using heuristics for hardware detection (library limitations)

### 🚧 In Progress / Partially Implemented

- 🚧 Comprehensive test coverage (~70% currently)
- 🚧 Performance optimization (functional but not optimized)
- 🚧 Documentation (basic docs exist, needs expansion)
- 🚧 Docker/Kubernetes manifests (not started)

### ❌ Not Yet Implemented

- ❌ Client libraries (JavaScript, Python, Go)
- ❌ Metrics/monitoring endpoints
- ❌ HSM integration
- ❌ Mobile SDKs
- ❌ Formal security audit
- ❌ Production deployment guides

---

## Quick Start

### Prerequisites

- Rust 1.70+ ([rustup.rs](https://rustup.rs))
- Optional: Redis 6+ (for production storage)

### Build & Run

```bash
# Clone repository
git clone https://github.com/yourusername/freebird.git
cd freebird

# Build all components
cargo build --release

# Build with WebAuthn support
cargo build --release --features human-gate-webauthn

# Run tests
cargo test

# Terminal 1 - Start the issuer (permissive mode)
./target/release/issuer

# Terminal 2 - Start the verifier  
./target/release/verifier

# Terminal 3 - Test with CLI
./target/release/interface
```

---

## Architecture Overview

```
┌─────────┐                    ┌─────────┐                    ┌──────────┐
│  User   │                    │ Issuer  │                    │ Verifier │
└────┬────┘                    └────┬────┘                    └────┬─────┘
     │                              │                              │
     │  1. Blind(input)             │                              │
     ├──────────────────────────────►                              │
     │                              │                              │
     │  2. Evaluate(blinded)        │                              │
     │◄──────────────────────────────                              │
     │                              │                              │
     │  3. Finalize → token         │                              │
     │                              │                              │
     │  4. Verify(token)            │                              │
     ├──────────────────────────────┼──────────────────────────────►
     │                              │                              │
     │  5. ✓ or ✗                   │                              │
     ◄──────────────────────────────┼───────────────────────────────
```

---

## Configuration

### Environment Variables

```bash
# Issuer Configuration
export ISSUER_ID="issuer:freebird:v1"      # Unique issuer identifier
export ISSUER_PORT=8081                     # Listen port
export TOKEN_TTL_MIN=10                     # Token lifetime in minutes
export SYBIL_RESISTANCE=invitation          # none|invitation|pow|rate_limit|webauthn|combined

# Verifier Configuration  
export VERIFIER_PORT=8082                   # Listen port
export ISSUER_URL=http://localhost:8081/.well-known/issuer
export REDIS_URL=redis://localhost:6379     # Optional: Redis for production
export MAX_CLOCK_SKEW_SECS=300             # Clock tolerance (5 minutes)

# Admin API (Issuer)
export ADMIN_API_KEY=your-secret-key-here   # Required for admin endpoints
export ADMIN_PORT=8090                      # Admin API port

# WebAuthn (if enabled)
export WEBAUTHN_RP_ID=localhost             # Relying party ID
export WEBAUTHN_RP_NAME="Freebird"         # Display name
export WEBAUTHN_RP_ORIGIN=http://localhost:8081
export WEBAUTHN_REDIS_URL=redis://localhost:6379
```

---

## API Endpoints

### Issuer

```bash
# Issue single token
POST /v1/oprf/issue
{
  "blinded_element_b64": "...",
  "sybil_proof": { /* optional */ }
}

# Batch issue (multiple tokens)
POST /v1/oprf/issue/batch
{
  "blinded_elements_b64": ["...", "..."],
  "sybil_proof": { /* optional */ }
}

# Get issuer metadata
GET /.well-known/issuer
```

### Verifier

```bash
# Verify token
POST /v1/verify
{
  "token_b64": "...",
  "issuer_id": "...",
  "exp": 1234567890  // Unix timestamp
}
```

### Admin API (Issuer)

```bash
# Key rotation
POST /admin/rotate-key
Authorization: Bearer {ADMIN_API_KEY}
{
  "new_kid": "key-2024-11",
  "grace_period_secs": 2592000  // 30 days
}

# List keys
GET /admin/keys
Authorization: Bearer {ADMIN_API_KEY}
```

---

## Performance Characteristics

**Current (Unoptimized):**
- Single token issuance: ~5-20ms
- Batch issuance: ~50-200ms for 100 tokens (Rayon parallel)
- Verification: ~2-10ms (with Redis)
- Memory usage: < 50MB per service

**Hardware:** Tested on 4-core consumer CPU

**Note:** No systematic performance optimization has been done yet. These are baseline numbers.

---

## Security Considerations

### What Freebird Provides

✅ **Unlinkability** – Mathematical guarantee via VOPRF  
✅ **Unforgeability** – Only issuer with private key can create tokens  
✅ **Replay Protection** – Nullifier-based single-use enforcement  
✅ **Expiration** – Time-bound token validity  

### Current Limitations

⚠️ **No formal audit** – Cryptography not professionally reviewed  
⚠️ **Side channels** – No systematic protection against timing attacks  
⚠️ **WebAuthn limitations** – Using webauthn-rs 0.5.3 (can't access AAGUIDs)  
⚠️ **Single issuer** – No threshold/distributed trust model  

### Not Protected Against

❌ **Token theft** – Stolen tokens can be used (use TLS!)  
❌ **Network privacy** – Does not provide network anonymity  
❌ **Quantum attacks** – P-256 vulnerable to future quantum computers  

---

## Testing

```bash
# Run all tests
cargo test

# Run integration tests
cargo test -p integration_tests

# CLI test modes
./target/release/interface              # Normal flow
./target/release/interface --replay     # Test replay protection
./target/release/interface --expired    # Test expiration
./target/release/interface --stress 100 # Stress test
```

---

## Documentation

- `docs/CONFIGURATION.md` - Environment variables reference
- `docs/SYBIL_RESISTANCE.md` - Anti-Sybil mechanisms
- `docs/WEBAUTHN.md` - WebAuthn integration guide
- `docs/HOW_IT_WORKS.md` - Protocol deep dive
- `docs/TESTING.md` - Testing guide

---

## Contributing

We welcome contributions! Priority areas:

1. **Testing** - Increase test coverage
2. **Documentation** - Improve guides and examples
3. **Client libraries** - JavaScript, Python, Go
4. **Performance** - Optimization and benchmarking
5. **Security** - Review and hardening

Please open an issue before starting major work.

---

## License

**Apache License 2.0**

Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.

---

## Acknowledgments

- VOPRF protocol: [IETF draft-irtf-cfrg-voprf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/)
- P-256 implementation: [RustCrypto](https://github.com/RustCrypto/elliptic-curves)
- WebAuthn: [webauthn-rs](https://github.com/kanidm/webauthn-rs)
- Inspired by [Privacy Pass](https://privacypass.github.io/)

---

## Roadmap to 1.0

- [ ] Complete test coverage (>90%)
- [ ] Security audit of crypto implementation
- [ ] Production deployment guide
- [ ] Performance optimization (<5ms verification)
- [ ] Client library (at least JavaScript)
- [ ] API stability guarantee
- [ ] Docker images
- [ ] Comprehensive documentation

---

_Built with ❤️ for privacy by Marcellina II for The Carpocratian Church