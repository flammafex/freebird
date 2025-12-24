# ⚙️ Configuration Reference

Complete reference for all Freebird environment variables and configuration options.

---

## Table of Contents

1. [Duration Format](#duration-format)
2. [Configuration Validation](#configuration-validation)
3. [Issuer Configuration](#issuer-configuration)
4. [Verifier Configuration](#verifier-configuration)
5. [Epoch Configuration](#epoch-configuration)
6. [Sybil Resistance](#sybil-resistance)
7. [WebAuthn Configuration](#webauthn-configuration)
8. [Federation & Trust Policy](#federation--trust-policy)
9. [Admin API & CLI](#admin-api--cli)
10. [Logging Configuration](#logging-configuration)
11. [Environment-Specific Configs](#environment-specific-configs)

---

## Duration Format

Duration fields support human-readable formats throughout the configuration:

| Format | Example | Description |
|--------|---------|-------------|
| Days | `30d` | 30 days |
| Hours | `24h` | 24 hours |
| Minutes | `30m` | 30 minutes |
| Seconds | `45s` | 45 seconds |
| Combined | `1d12h` | 1 day and 12 hours |
| Raw | `3600` | Seconds (backward compatible) |

**Examples:**
```bash
EPOCH_DURATION=1d                    # 1 day
SYBIL_INVITE_COOLDOWN=1h             # 1 hour
SYBIL_INVITE_EXPIRES=30d             # 30 days
WEBAUTHN_MAX_PROOF_AGE=5m            # 5 minutes
TRUST_POLICY_REFRESH_INTERVAL=1h     # 1 hour
```

---

## Configuration Validation

Validate your configuration before starting Freebird:

```bash
# Load and validate
source .env && freebird-validate-config
```

This checks for:
- Missing required variables
- Invalid duration formats
- Missing key files and directories
- Common configuration errors
- Security warnings (weak keys, missing TLS)

---

## Issuer Configuration

### Core Settings

```bash
# Unique issuer identifier (appears in tokens)
export ISSUER_ID=issuer:myservice:v1

# Network binding
export BIND_ADDR=0.0.0.0:8081

# Token time-to-live (minutes)
export TOKEN_TTL_MIN=60

# Enforce HTTPS (production: true)
export REQUIRE_TLS=false

# Trust X-Forwarded-* headers when behind proxy
export BEHIND_PROXY=false
```

| Variable | Default | Description | Production Value |
|----------|---------|-------------|------------------|
| `ISSUER_ID` | `issuer:freebird:v1` | Unique identifier for this issuer | `issuer:yourcompany:prod` |
| `BIND_ADDR` | `0.0.0.0:8081` | IP:PORT to listen on | `127.0.0.1:8081` (with reverse proxy) |
| `TOKEN_TTL_MIN` | `10` | Token expiration time in minutes | `60` (1 hour) typical |
| `REQUIRE_TLS` | `false` | Reject non-HTTPS requests | `true` in production |
| `BEHIND_PROXY` | `false` | Trust X-Forwarded-For/Proto headers | `true` with nginx/Caddy |

### Key & Data Storage

```bash
# Path to secret key file
export ISSUER_SK_PATH=/data/keys/issuer_sk.bin

# Key rotation state persistence
export KEY_ROTATION_STATE_PATH=/data/keys/key_rotation_state.json

# Federation data directory
export FEDERATION_DATA_PATH=/data/federation
```

| Variable | Default | Description |
|----------|---------|-------------|
| `ISSUER_SK_PATH` | `issuer_sk.bin` | Path to 32-byte P-256 secret key |
| `KEY_ROTATION_STATE_PATH` | `key_rotation_state.json` | Key rotation metadata storage |
| `FEDERATION_DATA_PATH` | `/data/federation` | Directory for federation store data |

**Key Format:** Raw 32-byte scalar or PKCS#8 DER format

---

## Verifier Configuration

```bash
# Network binding
export VERIFIER_BIND_ADDR=0.0.0.0:8082

# Issuer metadata URL (comma-separated for multiple issuers)
export ISSUER_URL=http://issuer:8081/.well-known/issuer

# How often to refresh issuer metadata (minutes)
export REFRESH_INTERVAL_MIN=10

# Clock skew tolerance (seconds)
export MAX_CLOCK_SKEW_SECS=300

# Redis for production storage
export REDIS_URL=redis://localhost:6379

# Epoch configuration (should match issuer)
export VERIFIER_EPOCH_DURATION=1d
export VERIFIER_EPOCH_RETENTION=2
```

| Variable | Default | Description | Production Value |
|----------|---------|-------------|------------------|
| `VERIFIER_BIND_ADDR` | `0.0.0.0:8082` | IP:PORT to listen on | `127.0.0.1:8082` |
| `ISSUER_URL` | `http://localhost:8081/.well-known/issuer` | Issuer metadata URL(s), comma-separated | HTTPS URL(s) |
| `REFRESH_INTERVAL_MIN` | `10` | Metadata refresh interval | `5-10` minutes |
| `MAX_CLOCK_SKEW_SECS` | `300` | Tolerance for time differences | `300` (5 minutes) |
| `REDIS_URL` | None (in-memory) | Redis connection string | `redis://redis:6379` |
| `VERIFIER_EPOCH_DURATION` | `1d` | Epoch duration (match issuer) | `1d` |
| `VERIFIER_EPOCH_RETENTION` | `2` | Previous epochs to accept | `2` |

**Storage Options:**
- **In-Memory:** Fast, no persistence (dev/testing)
- **Redis:** Persistent, distributed (production)

---

## Epoch Configuration

Epochs control key rotation timing. Issuer and verifier settings should match.

```bash
# Issuer epoch settings
export EPOCH_DURATION=1d      # Duration of each epoch
export EPOCH_RETENTION=2      # Previous epochs to honor

# Verifier epoch settings (should match issuer)
export VERIFIER_EPOCH_DURATION=1d
export VERIFIER_EPOCH_RETENTION=2
```

| Variable | Default | Description |
|----------|---------|-------------|
| `EPOCH_DURATION` | `1d` | How long each cryptographic epoch lasts |
| `EPOCH_RETENTION` | `2` | Number of previous epochs to accept tokens from |

**Key Rotation:**
- Keys rotate automatically at epoch boundaries
- Old keys remain valid during the retention window
- Recommended: `1d` epoch with `2` retention (3-day validity window)

---

## Sybil Resistance

### Available Mechanisms

```bash
# Sybil resistance mechanism
# Options: none, invitation, pow, rate_limit, progressive_trust,
#          proof_of_diversity, multi_party_vouching, federated_trust,
#          webauthn, combined
export SYBIL_RESISTANCE=invitation
```

| Mode | Description | Use Case |
|------|-------------|----------|
| `none` | No resistance | Development only |
| `invitation` | Cryptographic invite codes | Communities, controlled growth |
| `pow` | Proof of work | Resource-based limiting |
| `rate_limit` | Time-based throttling | Simple rate limiting |
| `progressive_trust` | Reputation-based access | Long-term communities |
| `proof_of_diversity` | Multi-signal verification | High-security apps |
| `multi_party_vouching` | Peer vouching system | Decentralized trust |
| `federated_trust` | Cross-issuer trust | Federated deployments |
| `webauthn` | Hardware authentication | Proof of humanity |
| `combined` | Multiple mechanisms | Defense in depth |

### Invitation System

```bash
export SYBIL_RESISTANCE=invitation

# Invites per user
export SYBIL_INVITE_PER_USER=5

# Cooldown between invitations
export SYBIL_INVITE_COOLDOWN=1h

# Invitation validity period
export SYBIL_INVITE_EXPIRES=30d

# Wait time before new users can invite
export SYBIL_INVITE_NEW_USER_WAIT=30d

# State persistence
export SYBIL_INVITE_PERSISTENCE_PATH=/data/state/invitations.json
export SYBIL_INVITE_AUTOSAVE_INTERVAL=5m

# Bootstrap users (format: user1:count1,user2:count2)
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:100
```

| Variable | Default | Description |
|----------|---------|-------------|
| `SYBIL_INVITE_PER_USER` | `5` | Invites per user |
| `SYBIL_INVITE_COOLDOWN` | `1h` | Cooldown between invitations |
| `SYBIL_INVITE_EXPIRES` | `30d` | How long invitations remain valid |
| `SYBIL_INVITE_NEW_USER_WAIT` | `30d` | Wait before new users can invite |
| `SYBIL_INVITE_PERSISTENCE_PATH` | `invitations.json` | State file path |
| `SYBIL_INVITE_AUTOSAVE_INTERVAL` | `5m` | Auto-save interval |
| `SYBIL_INVITE_BOOTSTRAP_USERS` | None | Initial users with invites |

See [Invitation System Guide](INVITATION_SYSTEM.md) for detailed strategies.

### Proof of Work

```bash
export SYBIL_RESISTANCE=pow
export SYBIL_POW_DIFFICULTY=20
```

| Difficulty | Hashes | Time (Avg) | Use Case |
|------------|--------|------------|----------|
| 16 | ~65k | Instant | Testing |
| 20 | ~1M | ~1 second | Light protection |
| 24 | ~16M | ~10-30 seconds | Moderate protection |
| 28 | ~268M | ~5-10 minutes | Strong protection |

### Rate Limiting

```bash
export SYBIL_RESISTANCE=rate_limit
export SYBIL_RATE_LIMIT=1h
```

| Interval | Description | Use Case |
|----------|-------------|----------|
| `5m` | Aggressive | High-frequency APIs |
| `1h` | Moderate | General applications |
| `24h` | Conservative | Voting, surveys |

### Progressive Trust

Reputation-based access that increases with account age:

```bash
export SYBIL_RESISTANCE=progressive_trust

# Format: "min_age:max_tokens:cooldown"
export SYBIL_PROGRESSIVE_TRUST_LEVELS=0:1:1d,30d:10:1h,90d:100:1m
export SYBIL_PROGRESSIVE_TRUST_PERSISTENCE_PATH=/data/state/progressive_trust.json
export SYBIL_PROGRESSIVE_TRUST_AUTOSAVE=5m
export SYBIL_PROGRESSIVE_TRUST_SALT=change-in-production
```

### Proof of Diversity

Multi-signal verification requiring diverse proof sources:

```bash
export SYBIL_RESISTANCE=proof_of_diversity

export SYBIL_PROOF_OF_DIVERSITY_MIN_SCORE=40
export SYBIL_PROOF_OF_DIVERSITY_PERSISTENCE_PATH=/data/state/proof_of_diversity.json
export SYBIL_PROOF_OF_DIVERSITY_AUTOSAVE=5m
export SYBIL_PROOF_OF_DIVERSITY_SALT=change-in-production
```

### Multi-Party Vouching

Peer-based vouching requiring multiple endorsements:

```bash
export SYBIL_RESISTANCE=multi_party_vouching

export SYBIL_MULTI_PARTY_VOUCHING_REQUIRED=3
export SYBIL_MULTI_PARTY_VOUCHING_COOLDOWN=1h
export SYBIL_MULTI_PARTY_VOUCHING_EXPIRES=30d
export SYBIL_MULTI_PARTY_VOUCHING_NEW_USER_WAIT=30d
export SYBIL_MULTI_PARTY_VOUCHING_PERSISTENCE_PATH=/data/state/multi_party_vouching.json
export SYBIL_MULTI_PARTY_VOUCHING_AUTOSAVE=5m
export SYBIL_MULTI_PARTY_VOUCHING_SALT=change-in-production
```

### Federated Trust

Cross-issuer trust verification:

```bash
export SYBIL_RESISTANCE=federated_trust

export SYBIL_FEDERATED_TRUST_ENABLED=true
export SYBIL_FEDERATED_TRUST_MAX_DEPTH=2
export SYBIL_FEDERATED_TRUST_MIN_PATHS=1
export SYBIL_FEDERATED_TRUST_REQUIRE_DIRECT=false
export SYBIL_FEDERATED_TRUST_MIN_TRUST_LEVEL=50
export SYBIL_FEDERATED_TRUST_CACHE_TTL=1h
export SYBIL_FEDERATED_TRUST_MAX_TOKEN_AGE=10m
```

### Combined Resistance

Stack multiple mechanisms for defense in depth:

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_POW_DIFFICULTY=20
export SYBIL_RATE_LIMIT=1h
# Add other mechanism configs as needed
```

---

## WebAuthn Configuration

Hardware-backed authentication for proof of humanity. See [WebAuthn Guide](WEBAUTHN.md) for complete documentation.

### Core Settings

```bash
export SYBIL_RESISTANCE=webauthn

# Relying Party configuration
export WEBAUTHN_RP_ID=example.com
export WEBAUTHN_RP_NAME="Freebird"
export WEBAUTHN_RP_ORIGIN=https://example.com

# Credential storage
export WEBAUTHN_REDIS_URL=redis://localhost:6379
export WEBAUTHN_CRED_TTL=1y

# Proof settings
export WEBAUTHN_MAX_PROOF_AGE=5m
export WEBAUTHN_PROOF_SECRET=your-random-secret-here
```

### Attestation Policy

```bash
# Policy level: none, indirect, direct, enterprise
export WEBAUTHN_ATTESTATION_POLICY=direct
export WEBAUTHN_REQUIRE_ATTESTATION=true

# AAGUID allowlist (comma-separated)
export WEBAUTHN_ALLOWED_AAGUIDS=fa2b99dc-9e39-4257-8f92-4a30d23c4118

# Audit logging
export WEBAUTHN_AUDIT_LOGGING=true
```

### Credential Management

```bash
export WEBAUTHN_MAX_CREDENTIALS_PER_USER=10
export WEBAUTHN_ALLOW_CREDENTIAL_REVOCATION=true
export WEBAUTHN_REQUIRE_RESIDENT_KEY=false
```

### Rate Limiting

```bash
export WEBAUTHN_MAX_REGISTRATION_ATTEMPTS=10
export WEBAUTHN_MAX_AUTH_ATTEMPTS=20
export WEBAUTHN_RATE_LIMIT_WINDOW=5m
export WEBAUTHN_BLOCK_DURATION=15m
export WEBAUTHN_MAX_SESSIONS_PER_IP=50
export WEBAUTHN_MAX_TOTAL_SESSIONS=10000
```

---

## Federation & Trust Policy

Configure trust relationships between issuers for multi-issuer deployments.

### Verifier Trust Policy

```bash
# Enable federation trust graph traversal
export TRUST_POLICY_ENABLED=true

# Maximum depth in trust graph (0 = direct only)
export TRUST_POLICY_MAX_DEPTH=2

# Minimum independent trust paths required
export TRUST_POLICY_MIN_PATHS=1

# Only accept issuers with direct vouches
export TRUST_POLICY_REQUIRE_DIRECT=false

# Trusted root issuers (comma-separated)
export TRUST_POLICY_TRUSTED_ROOTS=issuer:mozilla:v1,issuer:eff:v1

# Blocked issuers (comma-separated)
export TRUST_POLICY_BLOCKED_ISSUERS=issuer:compromised:v1

# Refresh interval for federation metadata
export TRUST_POLICY_REFRESH_INTERVAL=1h

# Minimum trust level for vouches (0-100)
export TRUST_POLICY_MIN_TRUST_LEVEL=50
```

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUST_POLICY_ENABLED` | `true` | Enable federation trust |
| `TRUST_POLICY_MAX_DEPTH` | `2` | Maximum trust graph hops |
| `TRUST_POLICY_MIN_PATHS` | `1` | Required independent paths |
| `TRUST_POLICY_REQUIRE_DIRECT` | `false` | Require direct vouches |
| `TRUST_POLICY_TRUSTED_ROOTS` | None | Always-trusted issuers |
| `TRUST_POLICY_BLOCKED_ISSUERS` | None | Never-trusted issuers |
| `TRUST_POLICY_REFRESH_INTERVAL` | `1h` | Metadata refresh interval |
| `TRUST_POLICY_MIN_TRUST_LEVEL` | `50` | Minimum vouch trust level |

See [Federation Guide](FEDERATION.md) for detailed documentation.

---

## Admin API & CLI

### Admin API

```bash
# API key (minimum 32 characters)
export ADMIN_API_KEY=your-secure-random-key-at-least-32-characters
```

**Security Requirements:**
- API key must be ≥32 characters
- All requests require `X-Admin-Key` header
- Store in secret manager (Vault, AWS Secrets Manager, etc.)
- Rotate quarterly
- Never commit to version control

See [Admin API Reference](ADMIN_API.md) for endpoint documentation.

### Admin CLI (freebird-cli)

```bash
# CLI configuration via environment
export FREEBIRD_ISSUER_URL=http://localhost:8081
export FREEBIRD_ADMIN_KEY=your-admin-key

# Or via command-line flags
freebird-cli --url http://localhost:8081 --key your-admin-key <command>
```

| Variable | Default | Description |
|----------|---------|-------------|
| `FREEBIRD_ISSUER_URL` | `http://localhost:8081` | Issuer URL |
| `FREEBIRD_ADMIN_KEY` | (Required) | Admin API key |

See the [CLI documentation](../README.md#command-line-interface) for available commands.

---

## Logging Configuration

```bash
# Log level (trace, debug, info, warn, error)
export RUST_LOG=info,freebird=debug

# Log format (plain, json)
export LOG_FORMAT=plain
```

### Log Level Examples

```bash
# Production (minimal)
RUST_LOG=info

# Development (verbose)
RUST_LOG=debug

# Freebird debug, others quiet
RUST_LOG=info,freebird=debug

# Fine-grained control
RUST_LOG=info,axum=warn,tower_http=off
```

| Level | Description |
|-------|-------------|
| `trace` | Very verbose, includes all internal details |
| `debug` | Detailed information for debugging |
| `info` | General operational messages |
| `warn` | Warning conditions |
| `error` | Error conditions only |

---

## Environment-Specific Configs

### Development

```bash
# Issuer (permissive)
export ISSUER_ID=issuer:dev
export ISSUER_BIND_ADDR=127.0.0.1:8081
export TOKEN_TTL_MIN=10
export REQUIRE_TLS=false
export SYBIL_RESISTANCE=none
export EPOCH_DURATION=1d

# Verifier (in-memory)
export VERIFIER_BIND_ADDR=127.0.0.1:8082
export ISSUER_URL=http://127.0.0.1:8081/.well-known/issuer
export MAX_CLOCK_SKEW_SECS=300
```

### Staging

```bash
# Issuer
export ISSUER_ID=issuer:staging:v1
export ISSUER_BIND_ADDR=0.0.0.0:8081
export TOKEN_TTL_MIN=60
export REQUIRE_TLS=true
export BEHIND_PROXY=true
export EPOCH_DURATION=1d

# Sybil resistance
export SYBIL_RESISTANCE=invitation
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:100,test1:50
export SYBIL_INVITE_PERSISTENCE_PATH=/var/lib/freebird/invitations.staging.json

# Admin
export ADMIN_API_KEY=${VAULT_STAGING_ADMIN_KEY}

# Verifier
export VERIFIER_BIND_ADDR=0.0.0.0:8082
export ISSUER_URL=https://issuer-staging.example.com/.well-known/issuer
export REDIS_URL=redis://redis-staging:6379
export REFRESH_INTERVAL_MIN=5

# Logging
export RUST_LOG=info,freebird=debug
```

### Production

```bash
# Issuer (strict configuration)
export ISSUER_ID=issuer:production:v1
export ISSUER_BIND_ADDR=127.0.0.1:8081  # Behind reverse proxy
export TOKEN_TTL_MIN=60
export REQUIRE_TLS=true
export BEHIND_PROXY=true
export EPOCH_DURATION=1d
export EPOCH_RETENTION=2

# Sybil resistance
export SYBIL_RESISTANCE=invitation
export SYBIL_INVITE_PER_USER=5
export SYBIL_INVITE_COOLDOWN=1h
export SYBIL_INVITE_EXPIRES=30d
export SYBIL_INVITE_NEW_USER_WAIT=30d
export SYBIL_INVITE_PERSISTENCE_PATH=/var/lib/freebird/invitations.json
export SYBIL_INVITE_AUTOSAVE_INTERVAL=5m
export SYBIL_INVITE_BOOTSTRAP_USERS=${VAULT_BOOTSTRAP_USERS}

# Key management
export ISSUER_SK_PATH=/var/lib/freebird/keys/issuer_sk.bin
export KEY_ROTATION_STATE_PATH=/var/lib/freebird/keys/rotation_state.json
export FEDERATION_DATA_PATH=/var/lib/freebird/federation

# Admin
export ADMIN_API_KEY=${VAULT_ADMIN_API_KEY}

# Verifier
export VERIFIER_BIND_ADDR=127.0.0.1:8082
export ISSUER_URL=https://issuer.example.com/.well-known/issuer
export REDIS_URL=redis://redis.internal:6379
export REFRESH_INTERVAL_MIN=10
export MAX_CLOCK_SKEW_SECS=300
export VERIFIER_EPOCH_DURATION=1d
export VERIFIER_EPOCH_RETENTION=2

# Logging
export RUST_LOG=info
export LOG_FORMAT=json
```

---

## Common Errors

**"ADMIN_API_KEY too short"**
```bash
# Bad
export ADMIN_API_KEY=admin123

# Good
export ADMIN_API_KEY=$(openssl rand -base64 48)
```

**"Failed to load issuer metadata"**
```bash
# Check issuer URL is accessible
curl https://issuer.example.com/.well-known/issuer

# Verify TLS certificate
openssl s_client -connect issuer.example.com:443
```

**"Invalid duration format"**
```bash
# Bad
export EPOCH_DURATION=1 day

# Good
export EPOCH_DURATION=1d
```

---

## Best Practices

### Security

✅ **DO:**
- Use HTTPS in production (`REQUIRE_TLS=true`)
- Run behind reverse proxy (`BEHIND_PROXY=true`)
- Store keys in secure locations (0600 permissions)
- Use strong admin API keys (≥48 characters)
- Rotate keys quarterly

❌ **DON'T:**
- Expose issuer directly to internet
- Commit secrets to version control
- Reuse keys across environments
- Use predictable key IDs

### Performance

✅ **DO:**
- Use Redis for verifier storage in production
- Set appropriate token TTL (balance security vs. performance)
- Monitor nullifier database size
- Configure autosave interval based on I/O capacity

❌ **DON'T:**
- Use in-memory storage for production verifier
- Set excessive token TTLs (increases nullifier DB size)
- Disable autosave (risk data loss)

### Reliability

✅ **DO:**
- Back up invitation state daily
- Monitor issuer metadata refresh failures
- Set up health checks
- Use systemd for automatic restarts

❌ **DON'T:**
- Rely on manual backups
- Ignore refresh failures
- Run without process supervision

---

## Quick Reference

### Issuer Variables

```bash
# Core
ISSUER_ID=issuer:myservice:v1
ISSUER_BIND_ADDR=0.0.0.0:8081
TOKEN_TTL_MIN=60
REQUIRE_TLS=true
BEHIND_PROXY=true
EPOCH_DURATION=1d
EPOCH_RETENTION=2

# Storage
ISSUER_SK_PATH=/data/keys/issuer_sk.bin
KEY_ROTATION_STATE_PATH=/data/keys/key_rotation_state.json
FEDERATION_DATA_PATH=/data/federation

# Admin
ADMIN_API_KEY=your-32-char-min-secret

# Sybil (choose one mode)
SYBIL_RESISTANCE=invitation
SYBIL_INVITE_PER_USER=5
SYBIL_INVITE_COOLDOWN=1h
SYBIL_INVITE_EXPIRES=30d
SYBIL_INVITE_NEW_USER_WAIT=30d
SYBIL_INVITE_PERSISTENCE_PATH=/data/state/invitations.json
SYBIL_INVITE_AUTOSAVE_INTERVAL=5m
SYBIL_INVITE_BOOTSTRAP_USERS=admin:100

# Logging
RUST_LOG=info,freebird=debug
LOG_FORMAT=plain
```

### Verifier Variables

```bash
# Core
VERIFIER_BIND_ADDR=0.0.0.0:8082
ISSUER_URL=http://issuer:8081/.well-known/issuer
REFRESH_INTERVAL_MIN=10
MAX_CLOCK_SKEW_SECS=300
VERIFIER_EPOCH_DURATION=1d
VERIFIER_EPOCH_RETENTION=2

# Storage
REDIS_URL=redis://localhost:6379

# Trust Policy
TRUST_POLICY_ENABLED=true
TRUST_POLICY_MAX_DEPTH=2
TRUST_POLICY_TRUSTED_ROOTS=issuer:trusted:v1
```

---

## Related Documentation

- [Production Deployment](PRODUCTION.md) - Best practices and hardening
- [Invitation System](INVITATION_SYSTEM.md) - Detailed invitation configuration
- [WebAuthn Guide](WEBAUTHN.md) - Hardware-backed authentication
- [Federation Guide](FEDERATION.md) - Multi-issuer deployments
- [Admin API Reference](ADMIN_API.md) - HTTP API documentation
- [Troubleshooting](TROUBLESHOOTING.md) - Common configuration issues

---

**Need Help?**

Check the [Troubleshooting Guide](TROUBLESHOOTING.md) or open a GitHub issue.