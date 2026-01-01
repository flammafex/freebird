# 📚 Freebird Documentation

Complete guide to deploying and using Freebird's anonymous credential system.

---

## 🚀 Getting Started

**New to Freebird?**

1. [README](../README.md) - Overview and quick start
2. [Quick Start Guide](QUICKSTART.md) - Hands-on tutorials
3. [How It Works](HOW_IT_WORKS.md) - Protocol deep dive

---

## 📖 Core Documentation

### Understanding Freebird

| Document | Purpose |
|----------|---------|
| [How It Works](HOW_IT_WORKS.md) | VOPRF protocol and cryptography |
| [Multi-Issuer Federation](FEDERATION.md) | Signature-based tokens & federation |
| [Security Model](SECURITY.md) | Threat model and guarantees |
| [Sybil Resistance](SYBIL_RESISTANCE.md) | Compare all mechanisms |

### Configuration & Deployment

| Document | Purpose |
|----------|---------|
| [Quick Start Guide](QUICKSTART.md) | Three deployment scenarios |
| [Configuration Reference](CONFIGURATION.md) | Environment variables |
| [Production Guide](PRODUCTION.md) | Deployment checklist |
| [Key Management](KEY_MANAGEMENT.md) | Key lifecycle and rotation |
| [Troubleshooting](TROUBLESHOOTING.md) | Common issues |

### API Reference

| Document | Purpose |
|----------|---------|
| [API Reference](API.md) | HTTP endpoints |
| [Admin API](ADMIN_API.md) | Management endpoints |
| [SDK](SDK.md) | Client libraries |

---

## 🎯 Feature-Specific Guides

| Document | Purpose |
|----------|---------|
| [Invitation System](INVITATION_SYSTEM.md) | Trust-based Sybil resistance |
| [WebAuthn](WEBAUTHN.md) | Hardware-backed authentication |
| [HSM Hybrid Mode](HSM_HYBRID_MODE.md) | Hardware security modules |
| [NIP-VOPRF](NIP-VOPRF.md) | Nostr integration |

---

## 📋 By Role

### Developers
Integrating Freebird into your application:
1. [Quick Start](QUICKSTART.md) → [API Reference](API.md) → [How It Works](HOW_IT_WORKS.md)

### System Administrators
Deploying and maintaining Freebird:
1. [Production Guide](PRODUCTION.md) → [Configuration](CONFIGURATION.md) → [Key Management](KEY_MANAGEMENT.md)

### Security Engineers
Evaluating Freebird's security:
1. [Security Model](SECURITY.md) → [How It Works](HOW_IT_WORKS.md) → [Sybil Resistance](SYBIL_RESISTANCE.md)

### Community Managers
Managing invitation-based communities:
1. [Invitation System](INVITATION_SYSTEM.md) → [Admin API](ADMIN_API.md)

---

## 🔍 By Topic

**Installation & Setup**: [Quick Start](QUICKSTART.md) • [Configuration](CONFIGURATION.md) • [Production](PRODUCTION.md)

**Cryptography**: [How It Works](HOW_IT_WORKS.md) • [Security Model](SECURITY.md) • [Key Management](KEY_MANAGEMENT.md) • [Federation](FEDERATION.md)

**Sybil Resistance**: [Overview](SYBIL_RESISTANCE.md) • [Invitation System](INVITATION_SYSTEM.md) • [WebAuthn](WEBAUTHN.md)

**APIs**: [API Reference](API.md) • [Admin API](ADMIN_API.md) • [SDK](SDK.md)

**Operations**: [Production](PRODUCTION.md) • [Troubleshooting](TROUBLESHOOTING.md) • [Key Management](KEY_MANAGEMENT.md)

**Use Cases**: [Local Government](USE_CASES.md) • [Enterprise](ENTERPRISE_USE_CASES.md)

---

## 🔗 External Resources

**Standards:**
- [VOPRF RFC Draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/)
- [Privacy Pass Protocol](https://datatracker.ietf.org/doc/draft-ietf-privacypass-protocol/)
- [RFC 9380: Hash-to-Curve](https://datatracker.ietf.org/doc/rfc9380/)

**Related Projects:**
- [Privacy Pass](https://privacypass.github.io/)
- [RustCrypto](https://github.com/RustCrypto)

---

## 💬 Getting Help

**Documentation issues?** Open a GitHub issue with the `documentation` label.

**Using Freebird?** Check [Troubleshooting](TROUBLESHOOTING.md) first, then search GitHub issues.

---

**Start with the [README](../README.md) to get oriented.**
