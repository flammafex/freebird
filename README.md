[<div align=center><img src="freebird.webp">](https://carpocratian.org/en/church/)
[<div align=center><br><img src="church.png" width=72 height=72>](https://carpocratian.org/en/church/)

_A mission of [The Carpocratian Church of Commonality and Equality](https://carpocratian.org/en/church/)_.</div>
<div align=center><img src="mission.png" width=256 height=200></div></div>

# 🕊️ Freebird

**Anonymous credential system using VOPRF cryptography**

Freebird is a self-hostable anonymous token system that allows users to prove authorization without revealing their identity. Think of it as anonymous digital cash for the internet—users get cryptographic tokens that prove "I'm authorized" without revealing "who I am."

**Key Features:**
- 🔒 **Cryptographic Unlinkability** – Issuer can't track where tokens are used
- 🛡️ **Multiple Sybil Resistance Options** – Invitations, proof-of-work, rate limiting, WebAuthn
- 🏠 **Self-Hostable** – No central authority required
- ♻️ **Replay Protection** – Nullifier-based double-spend prevention
- ⏱️ **Token Expiration** – Time-bound validity with clock skew tolerance
- ⚡ **High Performance** – Batch issuance up to 2000+ tokens/second
- 🔐 **Hardware Authentication** – Optional WebAuthn/FIDO2 support
- 📦 **Production-Ready** – ~6,000 lines of robust Rust with comprehensive tests

---

## Quick Start

### Prerequisites

- Rust 1.70+ ([rustup.rs](https://rustup.rs))
- Optional: Redis (for production verifier storage)

### Build & Run

```bash
# Build all components
cargo build --release

# Terminal 1 - Start the issuer (permissive mode)
./target/release/issuer

# Terminal 2 - Start the verifier
./target/release/verifier

# Terminal 3 - Test with CLI
./target/release/interface
```

**See full documentation:**
- [Installation Guide](docs/INSTALLATION.md) - Detailed setup instructions
- [Quick Start Guide](docs/QUICKSTART.md) - Step-by-step tutorials
- [Configuration Reference](docs/CONFIGURATION.md) - All environment variables

---

## What Problem Does This Solve?

**The Problem:** Traditional authentication links every action to an identity. Rate limiting requires tracking users. Privacy and access control are at odds.

**The Solution:** Freebird uses **VOPRF (Verifiable Oblivious Pseudorandom Function)** cryptography to create anonymous tokens. Users can prove "I'm authorized" without revealing "who I am."

**Use Cases:**
- Anonymous voting in private communities
- Privacy-preserving content access (paywalls without tracking)
- Rate limiting without user surveillance
- Whistleblower platforms with abuse protection
- Anonymous service access (APIs, downloads, etc.)

---

## How It Works

```
┌─────────┐                    ┌─────────┐                    ┌──────────┐
│  User   │                    │ Issuer  │                    │ Verifier │
└────┬────┘                    └────┬────┘                    └────┬─────┘
     │                              │                              │
     │  1. Blind token request      │                              │
     │────────────────────────────> │                              │
     │                              │                              │
     │  2. Check Sybil proof        │                              │
     │     (invitation/PoW/WebAuthn)│                              │
     │                              │                              │
     │  3. Sign blinded token       │                              │
     │ <──────────────────────────── │                              │
     │                              │                              │
     │  4. Unblind token            │                              │
     │     (client-side)            │                              │
     │                              │                              │
     │  5. Present token            │                              │
     │────────────────────────────────────────────────────────────>│
     │                              │                              │
     │                              │  6. Verify signature         │
     │                              │ <────────────────────────────│
     │                              │                              │
     │                              │  7. Check nullifier (replay) │
     │                              │                              │
     │  8. Access granted           │                              │
     │ <────────────────────────────────────────────────────────────│
```

**Key Properties:**
- Issuer never sees the final token (blind signature)
- Verifier can't link token to issuance (unlinkability)
- Each token can only be used once (replay protection)
- Tokens expire after configured time (time-bound)

[Read more in How It Works](docs/HOW_IT_WORKS.md)

---

## Documentation

### Getting Started
- [Installation Guide](docs/INSTALLATION.md) - Build, configure, deploy
- [Quick Start](docs/QUICKSTART.md) - 3 scenarios to get running fast
- [How It Works](docs/HOW_IT_WORKS.md) - VOPRF protocol explained

### Configuration & Deployment
- [Configuration Reference](docs/CONFIGURATION.md) - All environment variables
- [Production Deployment](docs/PRODUCTION.md) - Security hardening checklist
- [Key Management](docs/KEY_MANAGEMENT.md) - Key rotation and lifecycle

### Features
- [Sybil Resistance](docs/SYBIL_RESISTANCE.md) - All 5 mechanisms explained
- [Invitation System](docs/INVITATION_SYSTEM.md) - Trust-based Sybil resistance
- [WebAuthn Integration](docs/WEBAUTHN.md) - Hardware authentication (NEW!)
- [Admin API](docs/ADMIN_API.md) - 14 management endpoints

### Reference
- [API Documentation](docs/API.md) - Complete HTTP API reference
- [CLI Reference](docs/CLI.md) - Interface tool modes
- [Architecture](docs/ARCHITECTURE.md) - System design and components
- [Security Model](docs/SECURITY.md) - Threat model and guarantees
- [Testing Guide](docs/TESTING.md) - Unit, integration, stress tests

### Use Cases
- [Government & Community Use Cases](USE_CASES.md) - 10+ real-world examples
- [Enterprise Use Cases](ENTERPRISE_USE_CASES.md) - Business applications

### Advanced
- [Cryptographic Details](docs/CRYPTOGRAPHY.md) - VOPRF mathematics
- [Performance Tuning](docs/PERFORMANCE.md) - Optimization guide
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions

---

## Roadmap

### ✅ Completed Features

- ✅ **Core VOPRF protocol** (P-256, SHA-256)
- ✅ **Invitation system** with persistence and admin API
- ✅ **Admin API** for invitation management (14 endpoints)
- ✅ **Key rotation** with grace periods and multi-key support
- ✅ **Multiple Sybil resistance mechanisms**:
  - Invitation-based (trust network)
  - Proof-of-Work (computational cost)
  - Rate limiting (IP/fingerprint-based)
  - WebAuthn (FIDO2/passkeys) **← NEW!**
  - Combined (multiple mechanisms)
- ✅ **Redis backend** for verifier storage with replay protection
- ✅ **Batch issuance** optimization (up to 10k tokens, 2000+ tok/s) **← NEW!**
- ✅ **Attestation** (experimental hardware verification for WebAuthn authenticators)

### 🚀 Planned Features

- [ ] **Client libraries** (JavaScript, Python, Go, Rust SDK)
- [ ] **Docker images** and Kubernetes manifests
- [ ] **Metrics and monitoring** endpoints (Prometheus)
- [ ] **HSM integration** for key storage
- [ ] **Mobile SDKs** (iOS, Android)

### Hardware Attestation Support (NEW!)

Freebird now includes **experimental attestation verification** for WebAuthn authenticators, providing enhanced Sybil resistance through hardware verification.

**Features:**
- 🔐 **Policy-Based Enforcement** - Configure attestation requirements
- 📊 **Heuristic Detection** - Identify likely software authenticators
- 📈 **Metadata Tracking** - Monitor registration patterns
- ⚙️ **Three Policy Modes**:
  - `none` - No enforcement (default)
  - `strict` - Reject likely software keys
  - `log_only` - Monitor without enforcement

**Configuration:**
```bash
# Enable strict hardware policy
export WEBAUTHN_REQUIRE_ATTESTATION=true
export WEBAUTHN_ATTESTATION_POLICY=strict

# Or just monitor
export WEBAUTHN_ATTESTATION_POLICY=log_only
```

**Limitations (webauthn-rs 0.5.3):**
- Cannot access authenticator AAGUIDs directly
- Cannot verify attestation certificates
- Uses size-based heuristics for detection

Despite these limitations, the implementation still provides value through policy enforcement and monitoring capabilities.



---

## Testing

```bash
# Run all tests
cargo test

# CLI test modes
./target/release/interface              # Normal flow
./target/release/interface --replay     # Replay protection test
./target/release/interface --expired    # Expiration validation test
./target/release/interface --stress 100 # Performance test (100 tokens)
```

**Documentation:**
- [Testing Guide](docs/TESTING.md) - Unit, integration, performance tests
- [CLI Reference](docs/CLI.md) - All interface modes

---

## Performance

### Single Token Issuance
- **Latency**: 5-15ms (P-256 ECDSA signing)
- **Throughput**: 200-500 tokens/second (single core)
- **Memory**: < 1KB per token

### Batch Token Issuance (NEW!)
- **Latency**: 50-200ms (for 1000 tokens)
- **Throughput**: 2000+ tokens/second (8+ cores)
- **Batch size**: Up to 10,000 tokens per request
- **Speedup**: 40x faster than individual requests

### Verification
- **Latency**: 1-5ms (signature verification + nullifier check)
- **Throughput**: 1000+ verifications/second
- **Storage**: Redis with automatic cleanup

[Performance Tuning Guide](docs/PERFORMANCE.md)

---

## Comparison to Privacy Pass

Freebird is inspired by Cloudflare's [Privacy Pass](https://privacypass.github.io/) but designed for self-hosting:

| Feature | Privacy Pass | Freebird |
|---------|-------------|----------|
| Deployment | Centralized (Cloudflare) | Self-hostable |
| Source Code | Partially open | Fully open source |
| Backend | Cloudflare infrastructure | Your infrastructure |
| Issuance Control | Cloudflare policy | You control everything |
| Sybil Resistance | CAPTCHA-based | 5 options (invitation, PoW, rate limit, WebAuthn, combined) |
| Batch Issuance | Limited | Up to 10k tokens, 2000+ tok/s |
| Hardware Auth | No | WebAuthn/FIDO2 support |

**When to use Freebird:**
- Need self-hosted solution (data sovereignty)
- Want custom Sybil resistance mechanisms
- Building privacy-preserving applications beyond bot detection
- Require full control over token issuance policy
- Need high-throughput batch issuance

---

## Security

### What Freebird Guarantees

✅ **Unlinkability** – Issuer can't track token usage  
✅ **Unforgeability** – Only issuer can create valid tokens  
✅ **Replay Protection** – Tokens are single-use  
✅ **Expiration** – Time-bound validity  
✅ **Verifiability** – DLEQ proofs ensure correct issuance  

### What Freebird Does NOT Protect

❌ **Token Theft** – Tokens can be stolen in transit (use TLS)  
❌ **Front-Running** – Attacker can use token before the legitimate holder  
❌ **Network Anonymity** – Use Tor or VPNs if you need network-level privacy  
❌ **Quantum Resistance** – P-256 ECDLP is vulnerable to quantum computers  

**Full security documentation:**
- [Security Model](docs/SECURITY.md) - Threat model, guarantees, limitations
- [Production Checklist](docs/PRODUCTION.md) - Hardening guide

---

## Support & Community

### Getting Help
- **Documentation**: See [docs/](docs/) directory ([Index](docs/INDEX.md))
- **GitHub Issues**: [Report bugs and request features](https://github.com/yourusername/freebird/issues)
- **GitHub Discussions**: Ask questions and share use cases
- **Security Issues**: Report vulnerabilities privately via GitHub Security Advisories

### Contributing
We welcome contributions! Areas of interest:
- Client libraries (JavaScript, Python, Go)
- Docker/Kubernetes deployments
- Performance optimizations
- New Sybil resistance mechanisms
- WebAuthn enhancements

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

**Apache License 2.0**

Copyright 2025 The Carpocratian Church of Commonality and Equality

See [LICENSE](LICENSE) and [NOTICE](NOTICE) for full license text.

---

## Acknowledgments

- Inspired by [Privacy Pass](https://privacypass.github.io/)
- Built on [RustCrypto](https://github.com/RustCrypto) elliptic curve implementations
- VOPRF protocol based on [IETF CFRG draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/)
- WebAuthn support via [webauthn-rs](https://github.com/kanidm/webauthn-rs)

---

**Built with ❤️ for privacy**

*Freebird: Prove you're authorized without revealing who you are.*

---

## Recent Updates

### Version 0.2.0 (Latest)

**New Features:**
- 🎉 **WebAuthn Integration** - Hardware authentication with FIDO2/passkeys
  - Touch ID, Windows Hello, YubiKey support
  - Redis-backed credential storage
  - Zero computational cost Sybil resistance
  - [Full documentation](docs/WEBAUTHN.md)

- ⚡ **Batch Issuance Optimization** - High-performance token issuance
  - Up to 10,000 tokens per request
  - 2000+ tokens/second throughput
  - Parallel processing with Rayon
  - 40x faster than individual requests

**Improvements:**
- Enhanced error messages and logging
- Performance metrics for batch operations
- Comprehensive WebAuthn documentation

See [CHANGELOG.md](CHANGELOG.md) for full release history.