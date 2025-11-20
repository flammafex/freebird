[<div align=center><img src="freebird.webp">](https://carpocratian.org/en/church/)
[<div align=center><br><img src="church.png" width=72 height=72>](https://carpocratian.org/en/church/)

_A mission of [The Carpocratian Church of Commonality and Equality](https://carpocratian.org/en/church/)_.</div>
<div align=center><img src="mission.png" width=256 height=200></div></div>

# 🕊️ Freebird

**Authorization without identity. Privacy without compromise.**

Freebird is infrastructure for a world without surveillance. It provides cryptographic proof of authorization without revealing identity—separating "can you?" from "who are you?" for the first time in a practical, deployable way.

Think of it as anonymous digital cash for the internet. Users receive unforgeable, unlinkable tokens that prove authorization while revealing nothing about their identity.

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

- ✅ **Prove you're authorized without revealing who you are**
- ✅ **Rate limiting without tracking**
- ✅ **Access control without accounts**
- ✅ **Spam prevention without surveillance**
- ✅ **One person, one vote—anonymously**

This isn't just "privacy-preserving rate limiting." It's a new primitive for authorization that makes identity optional rather than mandatory.

---
## 🖥️ System Requirements

Freebird is lightweight but has specific architectural requirements for security in production environments.

### Hardware Sizing

Resources depend on your anticipated user base and Sybil resistance complexity.

| Deployment Size | Users | CPU | RAM | Disk |
|-----------------|-------|-----|-----|------|
| **Small** | < 1k | 2 vCPU | 1.5 GB | 10 GB SSD |
| **Medium** | 10k | 4 vCPU | 3 GB | 20 GB SSD |
| **Large** | 10k+ | 8+ vCPU | 6 GB+ | High-Perf SSD |

* **CPU:** Primary bottleneck is cryptographic operations (P-256 scalar multiplication).
* **RAM:** Includes overhead for Issuer, Verifier, and Redis.
* **Disk:** State files are small (~1KB/user), but SSDs are recommended for database latency.

### Network Architecture

* **Development:** Issuer and Verifier can run on the same host (e.g., via Docker Compose).
* **Production:** Issuer and Verifier **MUST** be deployed on separate infrastructure (different servers or VPCs) to prevent timing attacks and ensure user anonymity.
* **Time Sync:** System clocks must be synchronized via NTP. The default skew tolerance is 300 seconds (5 minutes).

### Software Environment

* **Container Runtime:** Docker & Docker Compose (Recommended).
* **Operating System:** Linux (Debian Bookworm is the reference OS).
* **Dependencies:**
    * **Redis:** Required for the Verifier (replay protection) and WebAuthn storage in production.
    * **Reverse Proxy:** Nginx, Caddy, or Cloud LB required for TLS termination.
    * **Entropy:** System must provide sufficient entropy (>1000 available) for key generation.

### Checking System Entropy

To ensure sufficient randomness for cryptographic operations, verify your system's available entropy:

```bash
cat /proc/sys/kernel/random/entropy_avail
```

* **Target Value:** > 1000
* **Action:** If the value is low (< 1000), install a daemon like `haveged` to replenish the pool.

### Build Requirements (Manual)

If building from source instead of using Docker:

* **Language:** Rust **1.70+**
* **System Packages:** `pkg-config`, `libssl-dev` (OpenSSL is required for `reqwest`)
---

## Technical Implementation

### Architecture

```text
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

- **Unlinkability**: Mathematical guarantee via VOPRF—issuer cannot correlate token issuance with usage.
- **Unforgeability**: Only the issuer's private key can create valid tokens.
- **Verifiability**: DLEQ proofs ensure correct token generation using the committed key.
- **Single-Use**: Nullifier-based replay protection ensures tokens are spent exactly once.

### Implementation Status (v0.1.0)

**Core Features:**
- ✅ **P-256 VOPRF** with DLEQ proofs
- ✅ **Batch Issuance**: High-throughput parallel issuance using `rayon`
- ✅ **Key Rotation**: Zero-downtime rotation with grace periods for deprecated keys
- ✅ **Storage Backends**: In-memory (dev) and Redis (prod) support
- ✅ **Admin API**: HTTP endpoints for user management, key rotation, and stats

**Sybil Resistance Mechanisms:**
- ✅ **Invitation System**: Cryptographically signed invites with ban-trees and reputation tracking
- ✅ **Proof of Work**: Configurable computational cost
- ✅ **Rate Limiting**: IP or fingerprint-based throttling
- ✅ **WebAuthn/FIDO2**: Hardware-backed "Proof of Humanity" (Feature flagged)
- ✅ **Combined**: Stack multiple mechanisms for defense-in-depth

---

## 📦 Client SDKs

Freebird includes a fully typed TypeScript/JavaScript SDK for browser and Node.js environments.

### JavaScript / TypeScript

```bash
npm install @freebird/sdk
```

```typescript
import { FreebirdClient } from '@freebird/sdk';

const client = new FreebirdClient({
  issuerUrl: 'https://issuer.example.com',
  verifierUrl: 'https://verifier.example.com'
});

// 1. Initialize (fetch keys)
await client.init();

// 2. Issue an anonymous token
const token = await client.issueToken();
console.log('Got token:', token.tokenValue);

// 3. Verify (or send to third-party)
const isValid = await client.verifyToken(token);
```

---

## Quick Start

### 1. Run with Docker

The fastest way to spin up the entire stack (Issuer, Verifier, Redis):

```bash
git clone https://github.com/yourusername/freebird.git
cd freebird
docker-compose up --build
```

### 2. Build from Source

```bash
# Prerequisites: Rust 1.70+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build all components
cargo build --release

# Terminal 1: Start Issuer
./target/release/issuer

# Terminal 2: Start Verifier
./target/release/verifier

# Terminal 3: Run the CLI Interface to test the flow
./target/release/interface --stress 5
```

---

## Configuration

Configuration is handled via environment variables.

### Issuer Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ISSUER_ID` | `issuer:freebird:v1` | Unique identifier for this issuer |
| `BIND_ADDR` | `0.0.0.0:8081` | Listening address |
| `SYBIL_RESISTANCE` | `none` | `invitation`, `pow`, `rate_limit`, `webauthn`, or `combined` |
| `ADMIN_API_KEY` | (None) | Required for Admin API (min 32 chars) |
| `WEBAUTHN_RP_ID` | (None) | Relying Party ID (required if using WebAuthn) |

### Verifier Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ISSUER_URL` | `http://localhost:8081` | URL to fetch issuer public keys |
| `REDIS_URL` | (None) | If set, uses Redis for nullifier storage (Persistence) |
| `MAX_CLOCKS_SKEW_SECS` | `300` | Tolerance for timestamp validation |

---

## Security Model

### Guarantees

- ✅ **Cryptographic Unlinkability**: The issuer creates a blind signature. Even if the issuer and verifier collude, they cannot mathematically link the issuance request to the verification request.
- ✅ **Forward Privacy**: Key rotation ensures that if a key is eventually compromised, past sessions remain secure.
- ✅ **Replay Protection**: The verifier maintains a nullifier set (in Redis or memory) to prevent double-spending.
- ✅ **No Phone-Home**: The system is fully self-contained.

### Not Protected Against

- **Token Theft**: Bearer tokens can be stolen if sent over insecure channels (use TLS!).
- **Network Correlation**: An observer seeing a request enter the issuer and immediately exit to the verifier might correlate them via timing (use Tor/mixnets for network anonymity).
- **Quantum Adversaries**: Relies on the hardness of the Discrete Log Problem on P-256.

---

## Roadmap

### Phase 1: Core Stabilization (Completed)
- [x] VOPRF implementation (P-256)
- [x] Sybil resistance (Invitation, PoW, Rate Limit)
- [x] Redis backend & Persistence
- [x] Key Rotation & Admin API

### Phase 2: Ecosystem (Current)
- [x] JavaScript/TypeScript SDK
- [x] Docker support
- [ ] Nostr NIP-VOPRF Integration
- [ ] Python & Go Clients
- [ ] Prometheus Metrics

### Phase 3: Expansion
- [ ] HSM / Cloud KMS support for key storage
- [ ] Privacy Pass IETF Standardization compliance
- [ ] Mobile SDKs (iOS/Android)

---

## Contributing

We need help with:
- **Security Review**: Auditing the VOPRF and DLEQ implementation.
- **Integrations**: Plugins for Matrix, Mastodon, and Nostr.
- **Documentation**: Deployment guides for Kubernetes and specialized use cases.

---

## License

**Apache License 2.0**

Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

---

**"Surveillance is not safety. Privacy is not crime. Authorization is not identity."**


🕊️

