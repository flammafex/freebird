[<div align=center><img src="freebird.webp">](https://carpocratian.org/en/church/)
[<div align=center><br><img src="church.png" width=72 height=72>](https://carpocratian.org/en/church/)

_A mission of [The Carpocratian Church of Commonality and Equality](https://carpocratian.org/en/church/)_.</div>
<div align=center><img src="mission.png" width=256 height=200></div></div>

# 🕊️ Freebird

**Anonymous credential system using VOPRF cryptography**

Freebird is a self-hostable anonymous token system that allows users to prove authorization without revealing their identity. Think of it as anonymous digital cash for the internet—users get cryptographic tokens that prove "I'm authorized" without revealing "who I am."

**Key Features:**
- 🔒 **Cryptographic Unlinkability** – Issuer can't track where tokens are used
- 🛡️ **Multiple Sybil Resistance Options** – Invitations, proof-of-work, rate limiting
- 🏠 **Self-Hostable** – No central authority required
- ♻️ **Replay Protection** – Nullifier-based double-spend prevention
- ⏱️ **Token Expiration** – Time-bound validity with clock skew tolerance
- ⚡ **Production-Ready** – ~5,000 lines of robust Rust with comprehensive tests

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

**The Solution:** Freebird issues anonymous tokens that prove authorization without surveillance:
- ✅ The issuer can't track where tokens are used
- ✅ The verifier can't link uses to identities  
- ✅ Double-spending is prevented (replay protection)
- ✅ One-per-human enforcement without biometrics (invitation system)

**Use Cases:**
- Anonymous rate limiting (verify "human-ness" without tracking)
- Privacy-preserving access control (prove membership without revealing identity)
- Anonymous voting or polling
- Private content access (paywalls, subscriptions)
- Bot prevention without surveillance
- Trust-based community building (invitation networks)

**Learn more:**
- [How It Works](docs/HOW_IT_WORKS.md) - VOPRF protocol explained
- [Use Cases](USE_CASES.md) - Real-world applications for governments & communities
- [Enterprise Use Cases](ENTERPRISE_USE_CASES.md) - Commercial applications

---

## Architecture

Freebird consists of three components:

```
┌─────────────┐          ┌──────────────┐          ┌──────────────┐
│   Client    │          │    Issuer    │          │   Verifier   │
│   (CLI)     │ ◄─────► │   (Axum)     │          │   (Axum)     │
│             │          │              │          │              │
│ - Blind     │          │ - Evaluate   │          │ - Verify     │
│ - Finalize  │          │ - DLEQ proof │          │ - Check exp  │
│             │          │ - Sybil      │          │ - Replay     │
└─────────────┘          └──────────────┘          └──────────────┘
                                                            │
                                                    ┌───────▼───────┐
                                                    │  Redis/Memory │
                                                    │  (Nullifiers) │
                                                    └───────────────┘
```

**Detailed documentation:**
- [Architecture Overview](docs/ARCHITECTURE.md) - System design & components
- [API Reference](docs/API.md) - Complete HTTP API documentation
- [Security Model](docs/SECURITY.md) - Threat model & guarantees

---

## Sybil Resistance

Freebird prevents users from obtaining unlimited tokens through multiple mechanisms:

| Mechanism | Status | Best For | Configuration |
|-----------|--------|----------|---------------|
| **Invitation System** | ✅ Production | Trust-based communities | `SYBIL_RESISTANCE=invitation` |
| **Proof-of-Work** | ✅ Implemented | Computational cost | `SYBIL_RESISTANCE=proof_of_work` |
| **Rate Limiting** | ✅ Implemented | Simple throttling | `SYBIL_RESISTANCE=rate_limit` |
| **Combined** | ✅ Implemented | Defense-in-depth | `SYBIL_RESISTANCE=combined` |

### Invitation System (Recommended)

The **invitation system** is a production-ready trust-based approach where existing users invite new users, creating social accountability without surveillance.

**Key features:**
- Cryptographically signed invitations (ECDSA P-256)
- Full state persistence (survives restarts)
- Strong invitee ID generation (192 bits of entropy)
- Admin API for management
- Ban tree propagation (self-policing communities)

```bash
# Quick start with invitations
SYBIL_RESISTANCE=invitation \
SYBIL_INVITE_BOOTSTRAP_USERS=admin:100 \
ADMIN_API_KEY=your-secure-random-key-at-least-32-chars \
./target/release/issuer
```

**Full documentation:**
- [Sybil Resistance Guide](docs/SYBIL_RESISTANCE.md) - All mechanisms explained
- [Invitation System](docs/INVITATION_SYSTEM.md) - Complete invitation guide
- [Admin API](docs/ADMIN_API.md) - HTTP API for invitation management

---

## Key Management & Rotation

Freebird supports cryptographic key rotation with grace periods for seamless transitions:

```bash
# Rotate keys via Admin API
curl -X POST http://localhost:8081/admin/keys/rotate \
  -H "X-Admin-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{"new_kid": "freebird-2024-11-15", "grace_period_secs": 604800}'
```

Both old and new keys remain valid during the grace period, allowing smooth transitions without service disruption.

**Documentation:**
- [Key Management](docs/KEY_MANAGEMENT.md) - Generation, rotation, security
- [Admin API](docs/ADMIN_API.md) - Key rotation endpoints

---

## Configuration

Essential environment variables:

```bash
# Issuer
ISSUER_ID=issuer:myservice:v1
TOKEN_TTL_MIN=60                        # Token lifetime (minutes)
SYBIL_RESISTANCE=invitation             # Sybil mechanism
ADMIN_API_KEY=min-32-char-secret        # Enable admin API

# Verifier
ISSUER_URL=http://issuer:8081/.well-known/issuer
REDIS_URL=redis://localhost:6379       # Optional: production storage
MAX_CLOCK_SKEW_SECS=300                # Expiration tolerance

# Invitation System
SYBIL_INVITE_PER_USER=5
SYBIL_INVITE_COOLDOWN_SECS=3600
SYBIL_INVITE_PERSISTENCE_PATH=invitations.json
SYBIL_INVITE_BOOTSTRAP_USERS=admin:100,alice:50
```

**Complete reference:**
- [Configuration Guide](docs/CONFIGURATION.md) - All environment variables
- [Production Deployment](docs/PRODUCTION.md) - Best practices

---

## Security

### What Freebird Guarantees

✅ **Unlinkability** – Issuer cannot link token issuance to redemption  
✅ **Anonymity** – Verifier cannot identify the token holder  
✅ **Replay Protection** – Each token can only be verified once  
✅ **Unforgeability** – Tokens cannot be created without the issuer's secret key  
✅ **Time-Bound Validity** – Tokens expire automatically with clock skew tolerance  
✅ **Sybil Resistance** – Invitation system prevents one person from obtaining unlimited tokens

### What Freebird Does NOT Guarantee

❌ **Front-running** – Tokens can be stolen and used by others before the legitimate holder  
❌ **Network Anonymity** – Use Tor or VPNs if you need network-level privacy  
❌ **Quantum Resistance** – P-256 ECDLP is vulnerable to quantum computers  

**Full security documentation:**
- [Security Model](docs/SECURITY.md) - Threat model, guarantees, limitations
- [Production Checklist](docs/PRODUCTION.md) - Hardening guide

---

## Testing

```bash
# Run all tests
cargo test

# CLI test modes
./target/release/interface              # Normal flow
./target/release/interface --replay     # Replay protection test
./target/release/interface --expired    # Expiration validation test
./target/release/interface --stress 100 # Performance test
```

**Documentation:**
- [Testing Guide](docs/TESTING.md) - Unit, integration, performance tests
- [CLI Reference](docs/CLI.md) - All interface modes

---

## Comparison to Privacy Pass

Freebird is inspired by Cloudflare's [Privacy Pass](https://privacypass.github.io/) but designed for self-hosting:

| Feature | Privacy Pass | Freebird |
|---------|-------------|----------|
| Deployment | Centralized (Cloudflare) | Self-hostable |
| Source Code | Partially open | Fully open source |
| Backend | Cloudflare infrastructure | Your infrastructure |
| Issuance Control | Cloudflare policy | You control everything |
| Sybil Resistance | CAPTCHA-based | Multiple options (invitation, PoW, rate limit) |

**When to use Freebird:**
- Need self-hosted solution (data sovereignty)
- Want custom Sybil resistance mechanisms
- Building privacy-preserving applications beyond bot detection
- Require full control over token issuance policy

---

## Documentation

### Getting Started
- [Installation Guide](docs/INSTALLATION.md)
- [Quick Start](docs/QUICKSTART.md)
- [How It Works](docs/HOW_IT_WORKS.md)

### Configuration & Deployment
- [Configuration Reference](docs/CONFIGURATION.md)
- [Production Deployment](docs/PRODUCTION.md)
- [Key Management](docs/KEY_MANAGEMENT.md)

### Features
- [Sybil Resistance](docs/SYBIL_RESISTANCE.md)
- [Invitation System](docs/INVITATION_SYSTEM.md)
- [Admin API](docs/ADMIN_API.md)

### Reference
- [API Documentation](docs/API.md)
- [CLI Reference](docs/CLI.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security Model](docs/SECURITY.md)
- [Testing Guide](docs/TESTING.md)

### Use Cases
- [Government & Community Use Cases](USE_CASES.md)
- [Enterprise Use Cases](ENTERPRISE_USE_CASES.md)

### Advanced
- [Cryptographic Details](docs/CRYPTOGRAPHY.md)
- [Performance Tuning](docs/PERFORMANCE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

---

## Roadmap

**Completed:**
- ✅ Core VOPRF protocol (P-256, SHA-256)
- ✅ Invitation system with persistence
- ✅ Admin API for invitation management
- ✅ Key rotation with grace periods
- ✅ Multiple Sybil resistance mechanisms
- ✅ Redis backend for verifier storage

**In Progress:**
- 🚧 WebAuthn integration (optional feature)
- 🚧 Batch issuance optimization

**Planned:**
- [ ] Client libraries (JavaScript, Python, Go, Rust SDK)
- [ ] Docker images and Kubernetes manifests
- [ ] Metrics and monitoring endpoints (Prometheus)
- [ ] HSM integration for key storage

See [ROADMAP.md](docs/ROADMAP.md) for details.

---

## Support & Community

### Getting Help
- **Documentation**: See [docs/](docs/) directory
- **GitHub Issues**: [Report bugs and request features](https://github.com/yourusername/freebird/issues)
- **GitHub Discussions**: Ask questions and share use cases
- **Security Issues**: Report vulnerabilities privately via GitHub Security Advisories

### Contributing
We welcome contributions! Areas of interest:
- Client libraries (JavaScript, Python, Go)
- Docker/Kubernetes deployments
- Performance optimizations
- New Sybil resistance mechanisms

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

---

**Built with ❤️ for privacy**

*Freebird: Prove you're authorized without revealing who you are.*