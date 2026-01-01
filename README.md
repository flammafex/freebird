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

### Build Requirements

* **Docker:** Recommended for deployment
* **Rust 1.70+:** If building from source
* **System Entropy:** > 1000 (check with `cat /proc/sys/kernel/random/entropy_avail`)
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

### Implementation Status

**Core Features:**
- ✅ **P-256 VOPRF** with DLEQ proofs
- ✅ **Batch Issuance**: High-throughput parallel issuance using `rayon`
- ✅ **Key Rotation**: Zero-downtime rotation with grace periods for deprecated keys
- ✅ **Storage Backends**: In-memory (dev) and Redis (prod) support
- ✅ **Multi-Issuer Federation**: Signature-based tokens enable verifiers to authenticate tokens from multiple issuers (see [`FEDERATION.md`](docs/FEDERATION.md))
- ✅ **Unified Admin Dashboard**: Single-page UI for both issuer and verifier management
- ✅ **Admin CLI**: `freebird-cli` command-line tool for scripting and automation
- ✅ **Admin API**: HTTP endpoints for user management, key rotation, and stats
- ✅ **Prometheus Metrics**: `/admin/metrics` endpoint for monitoring and alerting
- ✅ **Config Validation**: Pre-flight configuration checker

**Sybil Resistance Mechanisms:**
- ✅ **Invitation System**: Cryptographically signed invites with ban-trees and reputation tracking
- ✅ **Proof of Work**: Configurable computational cost
- ✅ **Rate Limiting**: IP or fingerprint-based throttling
- ✅ **WebAuthn/FIDO2**: Hardware-backed "Proof of Humanity" with attestation policies, discoverable credentials, and credential management
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

## 🖥️ Command-Line Interface

Freebird includes `freebird-cli`, a command-line tool for managing your deployment programmatically.

### Installation

```bash
# From source
cargo install --path issuer --bin freebird-cli

# Or use the Docker image
docker run --rm freebird/cli --help
```

### Configuration

```bash
# Set connection details via environment
export FREEBIRD_ISSUER_URL=http://localhost:8081
export FREEBIRD_ADMIN_KEY=your-admin-key

# Or pass via CLI flags
freebird-cli --url http://localhost:8081 --key your-admin-key <command>
```

### Commands

```bash
# System
freebird-cli health              # Check issuer health
freebird-cli stats               # Show statistics
freebird-cli config              # Show configuration
freebird-cli metrics             # Show Prometheus metrics
freebird-cli audit               # View audit log

# User Management
freebird-cli users list          # List all users
freebird-cli users get <id>      # Get user details
freebird-cli users ban <id>      # Ban a user
freebird-cli users ban <id> --tree  # Ban user and their invite tree

# Invitations
freebird-cli invites list        # List invitations
freebird-cli invites create <user> --count 5  # Create invitations
freebird-cli invites grant <user> --count 3   # Grant invite slots

# Key Management
freebird-cli keys list           # List signing keys
freebird-cli keys rotate         # Rotate signing key
freebird-cli keys cleanup        # Remove expired keys

# Federation
freebird-cli federation vouches  # List federation vouches
freebird-cli federation vouch <issuer> --level 5  # Add vouch
freebird-cli federation revocations  # List revocations

# Data Export
freebird-cli export users        # Export users to JSON
freebird-cli export invitations  # Export invitations to JSON
freebird-cli export audit        # Export audit log to JSON
```

### Output Formats

```bash
# Table output (default)
freebird-cli users list

# JSON output (for scripting)
freebird-cli --format json users list

# Compact output
freebird-cli --format compact stats
```

---

## 🖥️ Unified Admin Dashboard

Freebird includes a modern, single-page web interface for managing your deployment. The UI automatically detects which service it's connected to (issuer or verifier) and shows the appropriate features.

### Issuer Features

**📊 Dashboard Tab:**
- Real-time system statistics (users, invitations, redemptions)
- Interactive activity charts with Canvas visualization
- Monitor banned users and system health

**👥 User Management Tab:**
- Search and filter users
- View detailed user profiles with reputation scores
- Interactive invitation tree visualization
- Ban users individually or recursively (entire invite tree)

**🎫 Invitations Tab:**
- Create cryptographically signed invitation codes
- Grant invitation quota to users
- Track redemption status and expiration

**🔑 Key Management Tab:**
- View active and deprecated cryptographic keys
- Rotate keys with configurable grace periods
- Clean up expired keys

**⚙️ Sybil Configuration Tab:**
- View current Sybil resistance mode and settings
- Monitor resistance mechanism statistics

**📋 Audit Logs Tab:**
- Comprehensive system activity logs
- Filter by level (info, warning, error, success)
- Search logs by keyword

**🤝 Federation Tab:**
- Manage federation relationships with other issuers
- View trusted peers and cross-issuer policies

**🔐 WebAuthn Tab:**
- Register FIDO2 credentials and security keys
- Manage biometric authentication

### Verifier Features

**📊 Dashboard Tab:**
- Verification statistics and epoch information
- Uptime and store backend status
- Trusted issuer count

**🔗 Trusted Issuers Tab:**
- View all configured trusted issuers
- Inspect issuer details (public key, context, expiration)
- Trigger issuer metadata refresh

**💾 Cache Tab:**
- Replay cache statistics
- Cache backend status
- Cache management operations

### Access

```
# Issuer Admin
http://localhost:8081/admin

# Verifier Admin
http://localhost:8082/admin
```

**Authentication:** Requires the `ADMIN_API_KEY` from your `.env` file (minimum 32 characters).

### Architecture

- **Zero dependencies**: Single HTML file with embedded CSS and JavaScript
- **No build step**: Served directly from the binary
- **Service detection**: Automatically adapts to issuer or verifier
- **Modern UI**: Clean, responsive design with dark mode support
- **Secure**: API key stored in browser localStorage only

📖 **[Complete Admin Dashboard Documentation →](admin-ui/README.md)**

---

## 📊 Prometheus Metrics

Freebird exposes metrics in Prometheus text exposition format for monitoring and alerting integration.

### Endpoint

```bash
curl -H "X-Admin-Key: $ADMIN_API_KEY" http://localhost:8081/admin/metrics
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `freebird_users_total` | Gauge | Total registered users |
| `freebird_users_banned` | Gauge | Number of banned users |
| `freebird_invitations_total` | Gauge | Total invitations created |
| `freebird_invitations_redeemed` | Gauge | Total invitations redeemed |
| `freebird_invitations_pending` | Gauge | Pending invitations |
| `freebird_keys_total` | Gauge | Total signing keys |
| `freebird_keys_active` | Gauge | Active signing keys |
| `freebird_keys_deprecated` | Gauge | Deprecated signing keys |
| `freebird_keys_expiring_soon` | Gauge | Keys expiring within 7 days |
| `freebird_info` | Info | Instance metadata with `sybil_mode` label |

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'freebird'
    static_configs:
      - targets: ['localhost:8081']
    metrics_path: /admin/metrics
    authorization:
      type: 'Bearer'
      credentials: 'your-admin-api-key'
```

---

## Quick Start

### 🐳 Docker (Recommended)

The fastest way to get Freebird running is with Docker:

```bash
git clone https://github.com/yourusername/freebird.git
cd freebird

# Copy and optionally customize the environment configuration
cp .env.example .env

# Start all services (Issuer, Verifier, Redis)
docker compose up --build
```

**That's it!** Freebird is now running:
- **Issuer:** http://localhost:8081
- **Verifier:** http://localhost:8082
- **🖥️ Web Admin Dashboard:** http://localhost:8081/admin (Full-featured UI for system management)
- **Admin API:** http://localhost:8081/admin/* (REST API, requires `ADMIN_API_KEY`)

**Verify deployment:**
```bash
curl http://localhost:8081/.well-known/issuer
```

📖 **[Read the complete Docker Quickstart Guide →](DOCKER_QUICKSTART.md)**

The guide includes:
- Detailed configuration options
- API examples (cURL, TypeScript SDK, Rust CLI)
- Troubleshooting common issues
- Production deployment checklist

### 🦀 Build from Source

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

Freebird is configured via environment variables. For Docker deployments, use the `.env` file.

### Quick Configuration

```bash
# Copy the example configuration
cp .env.example .env

# Edit with your preferred editor
nano .env

# Validate configuration before starting
freebird-validate-config
```

The `.env.example` file contains **all** available configuration options with detailed comments and sensible defaults.

### Configuration Validation

Before starting Freebird, validate your configuration:

```bash
source .env && freebird-validate-config
```

This checks for:
- Missing required variables
- Invalid duration formats
- Missing key files
- Common configuration errors

### Human-Readable Duration Format

Duration fields support human-readable formats:

| Format | Example | Description |
|--------|---------|-------------|
| Days | `30d` | 30 days |
| Hours | `24h` | 24 hours |
| Minutes | `30m` | 30 minutes |
| Seconds | `45s` | 45 seconds |
| Combined | `1d12h` | 1 day and 12 hours |
| Raw | `3600` | Seconds (backward compatible) |

### Key Configuration Variables

**Issuer:**
| Variable | Default | Description |
|----------|---------|-------------|
| `ISSUER_ID` | `issuer:freebird:v1` | Unique identifier for this issuer |
| `BIND_ADDR` | `0.0.0.0:8081` | Listening address |
| `SYBIL_RESISTANCE` | `none` | `invitation`, `pow`, `rate_limit`, `webauthn`, `combined`, etc. |
| `ADMIN_API_KEY` | (None) | Required for Admin API (min 32 chars) |
| `EPOCH_DURATION` | `1d` | Key rotation epoch duration |

**Verifier:**
| Variable | Default | Description |
|----------|---------|-------------|
| `ISSUER_URL` | `http://localhost:8081/.well-known/issuer` | Issuer metadata URL (comma-separated for multiple) |
| `REDIS_URL` | (None) | Redis URL for persistent nullifier storage |
| `MAX_CLOCK_SKEW_SECS` | `300` | Clock skew tolerance (seconds) |

**Trust Policy (Federation):**
| Variable | Default | Description |
|----------|---------|-------------|
| `TRUST_POLICY_ENABLED` | `true` | Enable federation trust graph traversal |
| `TRUST_POLICY_MAX_DEPTH` | `2` | Maximum hops in trust graph (0 = direct only) |
| `TRUST_POLICY_MIN_PATHS` | `1` | Minimum independent trust paths required |
| `TRUST_POLICY_REQUIRE_DIRECT` | `false` | Only accept issuers with direct vouches |
| `TRUST_POLICY_TRUSTED_ROOTS` | (None) | Comma-separated list of always-trusted issuer IDs |
| `TRUST_POLICY_BLOCKED_ISSUERS` | (None) | Comma-separated list of blocked issuer IDs |

📖 **See [.env.example](.env.example) for the complete configuration reference** with all 60+ available options.

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

## License

**Apache License 2.0**

Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

---

**"Surveillance is not safety. Privacy is not crime. Authorization is not identity."**


🕊️

