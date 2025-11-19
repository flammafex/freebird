[<div align=center><img src="freebird.webp">](https://carpocratian.org/en/church/)
[<div align=center><br><img src="church.png" width=72 height=72>](https://carpocratian.org/en/church/)

_A mission of [The Carpocratian Church of Commonality and Equality](https://carpocratian.org/en/church/)_.</div>
<div align=center><img src="mission.png" width=256 height=200></div></div>

# 🕊️ Freebird

**Authorization without identity. Privacy without compromise.**

Freebird is infrastructure for a world without surveillance. It provides cryptographic proof of authorization without revealing identity - separating "can you?" from "who are you?" for the first time in a practical, deployable way.

Think of it as anonymous digital cash for the internet. Users receive unforgeable, unlinkable tokens that prove authorization while revealing nothing about identity.

---

## The Problem

Every online interaction today demands identity:
- **Rate limiting requires tracking users**
- **Access control requires accounts**  
- **Spam prevention requires surveillance**
- **Resource allocation requires registration**

We've accepted total surveillance as the price of functional systems. This is a false choice.

## The Solution

Freebird uses **VOPRF (Verifiable Oblivious Pseudorandom Function)** cryptography to enable:

✅ **Prove you're authorized without revealing who you are**  
✅ **Rate limiting without tracking**  
✅ **Access control without accounts**  
✅ **Spam prevention without surveillance**  
✅ **One person, one vote - anonymously**  

This isn't just "privacy-preserving rate limiting." It's a new primitive for authorization that makes identity optional rather than mandatory.

---

## Use Cases

**Anonymous Authorization:**
- Access community resources without accounts
- Prove membership without revealing which member
- Whistleblower platforms with spam protection
- Anonymous voting with Sybil resistance

**Privacy-Preserving Services:**
- Share your Jellyfin/Plex server anonymously
- API access without tracking
- Paywalls without surveillance
- Downloads without registration

**Censorship Resistance:**
- Participate without permanent records
- Access without attribution
- Contribute without consequences

**Anti-Spam Without Surveillance:**
- Nostr relay protection
- Comment systems without accounts
- Contact forms without CAPTCHAs
- Rate limiting for Tor users

---

## Technical Implementation

### Architecture

```
┌─────────┐                    ┌─────────┐                    ┌──────────┐
│  User   │                    │ Issuer  │                    │ Verifier │
└────┬────┘                    └────┬────┘                    └────┬─────┘
     │                              │                              │
     │  1. Blind(input)             │                              │
     ├──────────────────────────────►                              │
     │                              │                              │
     │  2. Evaluate(blinded) + DLEQ │                              │
     │◄──────────────────────────────                              │
     │                              │                              │
     │  3. Finalize → token         │                              │
     │                              │                              │
     │  4. Present anonymous token  │                              │
     ├──────────────────────────────┼──────────────────────────────►
     │                              │                              │
     │  5. ✓ Authorized (or ✗)      │                              │
     ◄──────────────────────────────┼───────────────────────────────
```

### Cryptographic Properties

- **Unlinkability**: Mathematical guarantee via VOPRF - issuer cannot correlate token issuance with usage
- **Unforgeability**: Only the issuer's private key can create valid tokens
- **Verifiability**: DLEQ proofs ensure correct token generation
- **Single-Use**: Nullifier-based replay protection

### Implementation Status

**Working Core (v0.1.0):**
- ✅ P-256 VOPRF with DLEQ proofs
- ✅ Token issuance and verification  
- ✅ Nullifier-based replay protection
- ✅ Multiple Sybil resistance mechanisms
- ✅ Redis and in-memory storage backends
- ✅ Batch issuance with parallelization
- ✅ Key rotation with grace periods
- ✅ WebAuthn/FIDO2 integration (experimental)

**Sybil Resistance Options:**
- **Invitation System** - Ed25519 signed invites for trust networks
- **Proof of Work** - Configurable computational cost
- **Rate Limiting** - IP or fingerprint-based throttling
- **WebAuthn** - Hardware authenticator verification
- **Combined** - Stack multiple mechanisms

---

## Quick Start

```bash
# Prerequisites: Rust 1.70+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/yourusername/freebird.git
cd freebird
cargo build --release

# Terminal 1: Start issuer
./target/release/issuer

# Terminal 2: Start verifier
./target/release/verifier

# Terminal 3: Test the flow
./target/release/interface
```

### Docker Deployment (Coming Soon)

```yaml
version: '3'
services:
  freebird-issuer:
    image: freebird/issuer:latest
    environment:
      - SYBIL_RESISTANCE=rate_limit
      - TOKEN_TTL_MIN=10
  
  freebird-verifier:
    image: freebird/verifier:latest
    environment:
      - ISSUER_URL=http://freebird-issuer:8081/.well-known/issuer
      - REDIS_URL=redis://redis:6379
```

---

## Configuration

```bash
# Core
export ISSUER_ID="issuer:freebird:v1"       # Unique identifier
export TOKEN_TTL_MIN=10                     # Token lifetime

# Sybil Resistance (choose one or combined)
export SYBIL_RESISTANCE=invitation          # none|invitation|pow|rate_limit|webauthn|combined
export SYBIL_POW_DIFFICULTY=20              # For PoW
export SYBIL_RATE_LIMIT_SECS=60            # For rate limiting

# Storage
export REDIS_URL=redis://localhost:6379     # Optional persistent storage

# WebAuthn (if using hardware auth)
export WEBAUTHN_RP_ID=example.com
export WEBAUTHN_RP_ORIGIN=https://example.com
```

---

## Security Model

### Guarantees

✅ **Cryptographic unlinkability** - Token usage cannot be traced to issuance  
✅ **Forward privacy** - Past tokens remain secure even if keys are compromised  
✅ **Replay protection** - Each token can only be used once  
✅ **No phone-home** - Fully self-contained, no external dependencies  

### Assumptions

- Issuer's private key remains secret
- Users protect their tokens (like cash - if lost, anyone can use)
- TLS protects tokens in transit
- Verifier trusts the issuer (federated trust model)

### Not Protected Against

- Token theft (use TLS!)
- Network-level correlation (use Tor for network anonymity)
- Quantum computers (P-256 ECDLP vulnerable)

---

## Philosophy

Freebird embodies a belief: **humans deserve dignity, privacy, and agency**.

Current systems assume humans are threats to be monitored. Every interaction requires identity because the default assumption is malfeasance. This architecture of distrust creates the surveillance infrastructure that defines the modern internet.

Freebird inverts this: it assumes humans are trustworthy enough to interact anonymously. Bad actors are handled through cryptographic rate limiting, not universal surveillance.

This is not naive - it's necessary. Privacy-preserving systems aren't just technically superior; they're ethically mandatory for human flourishing.

---

## Roadmap

### Phase 1: Core Stabilization (Current)
- [x] VOPRF implementation
- [x] Basic Sybil resistance
- [x] Redis backend
- [ ] 90% test coverage
- [ ] Security audit

### Phase 2: Adoption
- [ ] JavaScript client library
- [ ] Docker images
- [ ] Nostr integration (NIP)
- [ ] Production deployment guide
- [ ] Prometheus metrics

### Phase 3: Ecosystem
- [ ] Python/Go clients
- [ ] Kubernetes operators
- [ ] OAuth2/OIDC bridge
- [ ] Mobile SDKs
- [ ] HSM support

---

## Contributing

We need help with:
- **Security review** - Cryptographic implementation audit
- **Client libraries** - JavaScript, Python, Go, Rust
- **Integrations** - Nostr, ActivityPub, Matrix
- **Documentation** - Deployment guides, tutorials
- **Activism** - Spread the word about surveillance-free alternatives

---

## FAQ

**Q: How is this different from Privacy Pass?**  
A: Privacy Pass is centralized (Cloudflare controls it). Freebird is fully self-hostable. You control the entire stack.

**Q: Why not just use Tor?**  
A: Tor provides network anonymity. Freebird provides application-layer authorization. They're complementary - use both.

**Q: Can this be used for evil?**  
A: Any privacy tool can be misused. We believe the benefits of human dignity outweigh the risks of bad actors.

**Q: Is this production-ready?**  
A: The cryptography works. The system needs hardening, audit, and battle-testing. Early adopters welcome.

**Q: Why the religious connection?**  
A: Building surveillance-free systems is an act of faith in humanity. The Carpocratian Church shares this belief.

---

## Support

- **Documentation**: [docs/](docs/) directory
- **Issues**: [GitHub Issues](https://github.com/yourusername/freebird/issues)
- **Discussion**: [GitHub Discussions](https://github.com/yourusername/freebird/discussions)
- **Security**: Report vulnerabilities via GitHub Security Advisories

---

## License

**Apache License 2.0**

Copyright 2025 The Carpocratian Church of Commonality and Equality

Free as in freedom. Free as in Freebird.

---

## Acknowledgments

Standing on the shoulders of giants:
- David Chaum's blind signatures (1983)
- The cypherpunks who fought for cryptographic freedom
- Privacy Pass team for proving this approach works
- Everyone who believes privacy is a human right

---

**"Surveillance is not safety. Privacy is not crime. Authorization is not identity."**

Join us in building infrastructure for human dignity.

🕊️