# 🚀 Quick Start Guide

Get Freebird running in 5 minutes with step-by-step tutorials.

---

## Prerequisites

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify installation
rustc --version  # Should be 1.70+

# Optional: Install Redis for production
# macOS: brew install redis
# Ubuntu: apt-get install redis-server
# Run: redis-server
```

---

## Scenario 1: Basic Testing (No Sybil Resistance)

**Goal:** Issue and verify a token in under 2 minutes.

### Step 1: Build Freebird

```bash
# Clone repository
git clone https://github.com/your username/freebird.git
cd freebird

# Build all components
cargo build --release

# Binaries will be in target/release/
ls target/release/
# issuer  verifier  interface
```

### Step 2: Start the Issuer

```bash
# Terminal 1
./target/release/issuer
```

**Expected output:**
```
✅ Issuer starting...
   ├─ ISSUER_ID: issuer:freebird:v1
   ├─ Bind address: 0.0.0.0:8081
   ├─ Token TTL: 10 minutes
   ├─ Sybil resistance: none
   └─ Key ID: 2b8d5f3a-2024-11-17

🚀 Issuer running at http://0.0.0.0:8081
```

### Step 3: Start the Verifier

```bash
# Terminal 2
./target/release/verifier
```

**Expected output:**
```
✅ Verifier starting...
   ├─ Bind address: 0.0.0.0:8082
   ├─ Issuer URL: http://localhost:8081/.well-known/issuer
   ├─ Storage: in-memory
   └─ Refresh interval: 10 minutes

🚀 Verifier running at http://0.0.0.0:8082
```

### Step 4: Test with CLI

```bash
# Terminal 3
./target/release/interface
```

**Expected output:**
```
🕊️ NORMAL MODE - Fresh token issuance and verification

🔐 Step 1: Issuing token from http://127.0.0.1:8081
   ├─ Generated random input (32 bytes)
   ├─ Blinded input with random factor
   ├─ Sent blinded element to issuer
   ├─ Received evaluation + DLEQ proof
   ├─ Verified DLEQ proof
   └─ Finalized token
✅ Token issued: exp=1699454445 (600s from now)

✅ Step 2: Verifying token at http://127.0.0.1:8082
   ├─ Expiration checked (595s remaining)
   ├─ Token cryptographically verified
   ├─ Nullifier checked (first use)
   └─ Verified at: 2024-11-17T15:30:45Z

✅ SUCCESS! Token verified
```

**Congratulations!** 🎉 You just issued and verified an anonymous token.

---

## Scenario 2: With Invitation System

**Goal:** Set up trust-based Sybil resistance in 5 minutes.

### Step 1: Configure Invitation System

```bash
# Terminal 1 - Stop previous issuer (Ctrl+C)

# Start issuer with invitation system
SYBIL_RESISTANCE=invitation \
SYBIL_INVITE_BOOTSTRAP_USERS=admin:100 \
ADMIN_API_KEY=my-super-secure-admin-key-at-least-32-chars \
./target/release/issuer
```

**Expected output:**
```
✅ Issuer starting...
   ├─ Sybil resistance: invitation
   ├─ Bootstrap users: admin (100 invites)
   ├─ Admin API: enabled
   └─ Persistence: invitations.json

📋 Invitation system initialized:
   ├─ Total users: 1
   ├─ Total invitations: 0
   └─ State file: invitations.json

✅ Admin API enabled at /admin/*
```

### Step 2: Generate an Invitation

```bash
# Terminal 3
# Note: In production, this would be done via Admin API
# For this quickstart, we'll simulate it

# The issuer creates invitation for 'admin' user internally
# Let's use the Admin API to check stats

curl http://localhost:8081/admin/stats \
  -H "X-Admin-Key: my-super-secure-admin-key-at-least-32-chars"
```

**Expected output:**
```json
{
  "stats": {
    "total_invitations": 0,
    "redeemed_invitations": 0,
    "pending_invitations": 0,
    "total_users": 1,
    "banned_users": 0
  },
  "timestamp": 1699454445
}
```

### Step 3: Request Token (Will Fail Without Invitation)

```bash
./target/release/interface
```

**Expected output:**
```
❌ Token issuance failed: Sybil resistance proof required

💡 TIP: This issuer requires Sybil resistance proof.
   Set up an invitation or use other proof mechanism.
```

**This is expected!** The issuer now requires a valid invitation.

---

## Scenario 3: Production-Like Setup

**Goal:** Deploy with Redis, TLS, and proper configuration.

### Step 1: Start Redis

```bash
# Terminal 1
redis-server
```

### Step 2: Configure for Production

```bash
# Create environment file
cat > .env.production << 'ENVFILE'
# Issuer
ISSUER_ID=issuer:production:v1
BIND_ADDR=127.0.0.1:8081
TOKEN_TTL_MIN=60
REQUIRE_TLS=false  # Set to true with reverse proxy
BEHIND_PROXY=true

# Sybil Resistance
SYBIL_RESISTANCE=invitation
SYBIL_INVITE_PER_USER=5
SYBIL_INVITE_COOLDOWN_SECS=3600
SYBIL_INVITE_PERSISTENCE_PATH=/var/lib/freebird/invitations.json
SYBIL_INVITE_BOOTSTRAP_USERS=admin:100

# Admin API
ADMIN_API_KEY=generate-secure-key-with-openssl-rand-base64-48

# Verifier
REDIS_URL=redis://localhost:6379
ISSUER_URL=http://localhost:8081/.well-known/issuer
MAX_CLOCK_SKEW_SECS=300
ENVFILE

# Source environment
source .env.production
```

### Step 3: Start Services

```bash
# Terminal 2 - Issuer
./target/release/issuer

# Terminal 3 - Verifier
./target/release/verifier
```

### Step 4: Verify Production Setup

```bash
# Check issuer metadata
curl http://localhost:8081/.well-known/issuer | jq

# Check admin API
curl http://localhost:8081/admin/health \
  -H "X-Admin-Key: ${ADMIN_API_KEY}"

# Should return: {"status": "ok", ...}
```

---

## Testing Different Scenarios

### Test Replay Protection

```bash
./target/release/interface --replay
```

**Output:**
```
🔁 REPLAY ATTACK TEST MODE

📥 Step 1: Issuing fresh token...
✅ Token issued

✅ Step 2: First verification attempt...
✅ First verification: SUCCESS

⏱️  Waiting 2 seconds...

🔁 Step 3: Replay attack - reusing the same token...
✅ REPLAY PROTECTION WORKING! Token was rejected on second use.
```

### Test Expiration Validation

```bash
./target/release/interface --expired
```

**Output:**
```
⏰ EXPIRED TOKEN TEST MODE

📥 Step 1: Issuing token...
✅ Token issued with exp=1699454445

⏰ Step 2: Attempting verification with expired timestamp...
✅ EXPIRATION VALIDATION WORKING! Expired token was rejected.
```

### Stress Test

```bash
./target/release/interface --stress 100
```

**Output:**
```
⚡ STRESS TEST MODE (n=100)

🔄 Issuing 100 tokens...
████████████████████████████████████████ 100/100

📊 RESULTS:
   Successes: 100/100
   Failures:  0/100
   
⏱️ Performance:
   Total time: 2.5s
   Throughput: 40 tokens/sec
```

---

## Common Issues

### "Address already in use"

**Problem:** Port 8081 or 8082 is occupied.

**Solution:**
```bash
# Find process using port
lsof -i :8081
lsof -i :8082

# Kill process or use different port
BIND_ADDR=127.0.0.1:9081 ./target/release/issuer
```

### "Failed to load issuer metadata"

**Problem:** Verifier can't reach issuer.

**Solution:**
```bash
# Check issuer is running
curl http://localhost:8081/.well-known/issuer

# Check ISSUER_URL is correct
echo $ISSUER_URL
```

### "Sybil resistance proof required"

**Problem:** Issuer has Sybil resistance enabled.

**Solution:**
- Use permissive mode: `SYBIL_RESISTANCE=none ./target/release/issuer`
- Or provide valid Sybil proof (invitation, PoW, etc.)

### "Admin API disabled"

**Problem:** ADMIN_API_KEY not set or too short.

**Solution:**
```bash
# Generate secure key
export ADMIN_API_KEY=$(openssl rand -base64 48)

# Restart issuer
./target/release/issuer
```

---

## Next Steps

**Explore Features:**
- [Invitation System](INVITATION_SYSTEM.md) - Trust-based Sybil resistance
- [Admin API](ADMIN_API.md) - Manage users and invitations
- [Configuration](CONFIGURATION.md) - All environment variables

**Deploy to Production:**
- [Production Guide](PRODUCTION.md) - Security hardening checklist
- [Key Management](KEY_MANAGEMENT.md) - Secure key storage

**Learn the Protocol:**
- [How It Works](HOW_IT_WORKS.md) - VOPRF deep dive
- [Security Model](SECURITY.md) - Threat model and guarantees

---

**You're ready to build privacy-preserving applications with Freebird!** 🕊️