# ⚙️ Configuration Reference

Complete reference for all Freebird environment variables and configuration options.

---

## Table of Contents

1. [Issuer Configuration](#issuer-configuration)
2. [Verifier Configuration](#verifier-configuration)
3. [Sybil Resistance](#sybil-resistance)
4. [Invitation System](#invitation-system)
5. [Key Management](#key-management)
6. [Admin API](#admin-api)
7. [Environment-Specific Configs](#environment-specific-configs)

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

### Key Management

```bash
# Path to secret key file
export ISSUER_SK_PATH=issuer_sk.bin

# Optional: Override auto-generated key ID
export KID=custom-key-id-2024-11-17

# Key rotation state persistence
export KEY_ROTATION_STATE_PATH=key_rotation_state.json
```

| Variable | Default | Description |
|----------|---------|-------------|
| `ISSUER_SK_PATH` | `issuer_sk.bin` | Path to 32-byte P-256 secret key |
| `KID` | Auto-generated | Key identifier (SHA-256 hash of pubkey) |
| `KEY_ROTATION_STATE_PATH` | `key_rotation_state.json` | Key rotation metadata storage |

**Key Format:** Raw 32-byte scalar or PKCS#8 DER format

---

## Verifier Configuration

```bash
# Network binding
export BIND_ADDR=0.0.0.0:8082

# Issuer metadata URL
export ISSUER_URL=http://issuer:8081/.well-known/issuer

# How often to refresh issuer metadata (minutes)
export REFRESH_INTERVAL_MIN=10

# Clock skew tolerance (seconds)
export MAX_CLOCK_SKEW_SECS=300

# Optional: Redis for production storage
export REDIS_URL=redis://localhost:6379
```

| Variable | Default | Description | Production Value |
|----------|---------|-------------|------------------|
| `BIND_ADDR` | `0.0.0.0:8082` | IP:PORT to listen on | `127.0.0.1:8082` |
| `ISSUER_URL` | `http://localhost:8081/.well-known/issuer` | Where to fetch issuer public key | HTTPS URL |
| `REFRESH_INTERVAL_MIN` | `10` | Metadata refresh interval | `5-10` minutes |
| `MAX_CLOCK_SKEW_SECS` | `300` | Tolerance for time differences | `300` (5 minutes) |
| `REDIS_URL` | None (in-memory) | Redis connection string | `redis://redis:6379` |

**Storage Options:**
- **In-Memory:** Fast, no persistence (dev/testing)
- **Redis:** Persistent, distributed (production)

---

## Sybil Resistance

### General

```bash
# Sybil resistance mechanism
# Options: none, invitation, proof_of_work, rate_limit, combined
export SYBIL_RESISTANCE=none
```

### Invitation System

```bash
export SYBIL_RESISTANCE=invitation

# How many invites each user gets
export SYBIL_INVITE_PER_USER=5

# Minimum time between sending invites (seconds)
export SYBIL_INVITE_COOLDOWN_SECS=3600

# How long invitations remain valid (seconds)
export SYBIL_INVITE_EXPIRES_SECS=2592000

# Wait time before new users can invite (seconds)
export SYBIL_INVITE_NEW_USER_WAIT_SECS=2592000

# State persistence path
export SYBIL_INVITE_PERSISTENCE_PATH=invitations.json

# Auto-save interval (seconds, 0 = only on shutdown)
export SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS=300

# Bootstrap users (format: user1:count1,user2:count2)
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:100,alice:50
```

| Variable | Default | Recommended | Description |
|----------|---------|-------------|-------------|
| `SYBIL_INVITE_PER_USER` | `5` | `3-10` | Invites per user |
| `SYBIL_INVITE_COOLDOWN_SECS` | `3600` | `3600-86400` | Cooldown (1-24 hours) |
| `SYBIL_INVITE_EXPIRES_SECS` | `2592000` | `604800-7776000` | Validity (7-90 days) |
| `SYBIL_INVITE_NEW_USER_WAIT_SECS` | `2592000` | `2592000-7776000` | Wait (30-90 days) |
| `SYBIL_INVITE_PERSISTENCE_PATH` | `invitations.json` | Absolute path | Storage location |
| `SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS` | `300` | `300-900` | Auto-save (5-15 min) |
| `SYBIL_INVITE_BOOTSTRAP_USERS` | None | `admin:100` | Initial users |

See [Invitation System Guide](INVITATION_SYSTEM.md) for detailed configuration strategies.

### Proof-of-Work

```bash
export SYBIL_RESISTANCE=proof_of_work

# Difficulty (leading zero bits required)
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

# Minimum time between token issuance per client (seconds)
export SYBIL_RATE_LIMIT_SECS=3600
```

| Interval | Description | Use Case |
|----------|-------------|----------|
| 300 (5 min) | Aggressive | High-frequency APIs |
| 3600 (1 hour) | Moderate | General applications |
| 86400 (24 hours) | Conservative | Voting, surveys |

### Combined Resistance

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_POW_DIFFICULTY=20
export SYBIL_RATE_LIMIT_SECS=3600
```

**Note:** Current implementation accepts proof satisfying ANY configured mechanism. Future enhancement: require ALL mechanisms.

---

## Admin API

```bash
# Enable admin API (minimum 32 characters)
export ADMIN_API_KEY=your-secure-random-key-at-least-32-characters
```

**Requirements:**
- API key must be ≥32 characters
- Only available with invitation-based Sybil resistance
- All requests require `X-Admin-Key` header

**Security:**
- Store in secret manager (Vault, AWS Secrets Manager, etc.)
- Rotate quarterly
- Never commit to version control
- Restrict network access

See [Admin API Reference](ADMIN_API.md) for endpoint documentation.

---

## Environment-Specific Configs

### Development

```bash
# Issuer (permissive)
export ISSUER_ID=issuer:dev
export BIND_ADDR=127.0.0.1:8081
export TOKEN_TTL_MIN=10
export REQUIRE_TLS=false
export SYBIL_RESISTANCE=none

# Verifier (in-memory)
export BIND_ADDR=127.0.0.1:8082
export ISSUER_URL=http://127.0.0.1:8081/.well-known/issuer
export MAX_CLOCK_SKEW_SECS=300
```

### Staging

```bash
# Issuer (invitation system, test data)
export ISSUER_ID=issuer:staging:v1
export BIND_ADDR=0.0.0.0:8081
export TOKEN_TTL_MIN=60
export REQUIRE_TLS=true
export BEHIND_PROXY=true
export SYBIL_RESISTANCE=invitation
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:100,test1:50,test2:50
export SYBIL_INVITE_PERSISTENCE_PATH=/var/lib/freebird/invitations.staging.json
export ADMIN_API_KEY=${VAULT_STAGING_ADMIN_KEY}

# Verifier (Redis)
export BIND_ADDR=0.0.0.0:8082
export ISSUER_URL=https://issuer-staging.example.com/.well-known/issuer
export REDIS_URL=redis://redis-staging:6379
export REFRESH_INTERVAL_MIN=5
```

### Production

```bash
# Issuer (strict configuration)
export ISSUER_ID=issuer:production:v1
export BIND_ADDR=127.0.0.1:8081  # Behind reverse proxy
export TOKEN_TTL_MIN=60
export REQUIRE_TLS=true
export BEHIND_PROXY=true

# Sybil resistance (invitation)
export SYBIL_RESISTANCE=invitation
export SYBIL_INVITE_PER_USER=5
export SYBIL_INVITE_COOLDOWN_SECS=3600
export SYBIL_INVITE_EXPIRES_SECS=2592000
export SYBIL_INVITE_NEW_USER_WAIT_SECS=2592000
export SYBIL_INVITE_PERSISTENCE_PATH=/var/lib/freebird/invitations.json
export SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS=300
export SYBIL_INVITE_BOOTSTRAP_USERS=${VAULT_BOOTSTRAP_USERS}

# Key management
export ISSUER_SK_PATH=/var/lib/freebird/keys/issuer_sk.bin
export KEY_ROTATION_STATE_PATH=/var/lib/freebird/keys/rotation_state.json

# Admin API
export ADMIN_API_KEY=${VAULT_ADMIN_API_KEY}

# Verifier (Redis, strict timing)
export BIND_ADDR=127.0.0.1:8082
export ISSUER_URL=https://issuer.example.com/.well-known/issuer
export REDIS_URL=redis://redis.internal:6379
export REFRESH_INTERVAL_MIN=10
export MAX_CLOCK_SKEW_SECS=300
```

---

## Configuration Validation

### Startup Checks

Freebird validates configuration on startup:

```
✅ Issuer starting...
   ├─ ISSUER_ID: issuer:production:v1
   ├─ Bind address: 127.0.0.1:8081
   ├─ Token TTL: 60 minutes
   ├─ TLS required: true
   ├─ Behind proxy: true
   ├─ Sybil resistance: invitation
   ├─ Admin API: enabled
   └─ Key ID: freebird-2024-11-17

✅ Verifier starting...
   ├─ Bind address: 127.0.0.1:8082
   ├─ Issuer URL: https://issuer.example.com/.well-known/issuer
   ├─ Storage: Redis (redis://redis:6379)
   ├─ Refresh interval: 10 minutes
   └─ Clock skew tolerance: 300 seconds
```

### Common Validation Errors

**"ADMIN_API_KEY too short"**
```bash
# Bad
export ADMIN_API_KEY=admin123

# Good
export ADMIN_API_KEY=$(openssl rand -base64 48)
```

**"Admin API requires invitation-based Sybil resistance"**
```bash
# Bad
export SYBIL_RESISTANCE=proof_of_work
export ADMIN_API_KEY=...

# Good
export SYBIL_RESISTANCE=invitation
export ADMIN_API_KEY=...
```

**"Failed to load issuer metadata"**
```bash
# Check issuer URL is accessible
curl https://issuer.example.com/.well-known/issuer

# Verify TLS certificate
openssl s_client -connect issuer.example.com:443
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

## Environment Variables Summary

### Issuer

```bash
# Core
ISSUER_ID=issuer:myservice:v1
BIND_ADDR=0.0.0.0:8081
TOKEN_TTL_MIN=60
REQUIRE_TLS=false
BEHIND_PROXY=false

# Keys
ISSUER_SK_PATH=issuer_sk.bin
KID=auto-generated
KEY_ROTATION_STATE_PATH=key_rotation_state.json

# Sybil
SYBIL_RESISTANCE=none|invitation|proof_of_work|rate_limit|combined

# Invitation (if SYBIL_RESISTANCE=invitation)
SYBIL_INVITE_PER_USER=5
SYBIL_INVITE_COOLDOWN_SECS=3600
SYBIL_INVITE_EXPIRES_SECS=2592000
SYBIL_INVITE_NEW_USER_WAIT_SECS=2592000
SYBIL_INVITE_PERSISTENCE_PATH=invitations.json
SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS=300
SYBIL_INVITE_BOOTSTRAP_USERS=user1:count1,user2:count2

# PoW (if SYBIL_RESISTANCE=proof_of_work)
SYBIL_POW_DIFFICULTY=20

# Rate Limit (if SYBIL_RESISTANCE=rate_limit)
SYBIL_RATE_LIMIT_SECS=3600

# Admin API (optional)
ADMIN_API_KEY=min-32-char-secret
```

### Verifier

```bash
# Core
BIND_ADDR=0.0.0.0:8082
ISSUER_URL=http://issuer:8081/.well-known/issuer
REFRESH_INTERVAL_MIN=10
MAX_CLOCK_SKEW_SECS=300

# Storage (optional)
REDIS_URL=redis://localhost:6379
```

---

## Related Documentation

- [Installation Guide](INSTALLATION.md) - Setup instructions
- [Production Deployment](PRODUCTION.md) - Best practices and hardening
- [Invitation System](INVITATION_SYSTEM.md) - Detailed invitation configuration
- [Admin API](ADMIN_API.md) - HTTP API reference
- [Troubleshooting](TROUBLESHOOTING.md) - Common configuration issues

---

**Need Help?**

Check the [Troubleshooting Guide](TROUBLESHOOTING.md) or open a GitHub issue.