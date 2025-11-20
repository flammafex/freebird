# 🚀 Quick Start Guide

Get Freebird running in 5 minutes.

---

## Prerequisites

**Recommended:**
- **Docker** & **Docker Compose** (for instant deployment)

**For Manual Build / Development:**
- **Rust 1.70+** (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **Redis** (optional, for production persistence)

---

## ⚡ Scenario 0: Docker Quick Start (Recommended)

**Goal:** Launch the complete stack (Issuer, Verifier, Redis) instantly without installing Rust.

### Step 1: Start Services

```bash
# Clone repository
git clone [https://github.com/yourusername/freebird.git](https://github.com/yourusername/freebird.git)
cd freebird

# Start everything
docker-compose up --build
```

**Expected output:**
```
[+] Running 4/4
 ✔ Network freebird-net       Created
 ✔ Container freebird-redis   Started
 ✔ Container freebird-issuer  Started
 ✔ Container freebird-verifier Started
...
freebird-issuer  | 🚀 Server ready at 0.0.0.0:8081
freebird-verifier | 🕊️ Freebird verifier listening on [http://0.0.0.0:8082](http://0.0.0.0:8082)
```

### Step 2: Verify Health

```bash
# Check Issuer Metadata
curl http://localhost:8081/.well-known/issuer
```

### Step 3: Client Integration

Since the CLI tool (`interface`) is a development utility, you can build it locally to test the Dockerized services:

```bash
# In a new terminal window
cargo run --release --bin interface
```

---

## 🛠️ Scenario 1: Manual Build (Basic Testing)

**Goal:** Build from source and run a minimal setup (in-memory, no Sybil resistance).

### Step 1: Build Freebird

```bash
cargo build --release
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
   ├─ Sybil resistance: none
```

### Step 3: Start the Verifier

```bash
# Terminal 2
./target/release/verifier
```

### Step 4: Test with CLI

```bash
# Terminal 3
./target/release/interface
```

**Expected output:**
```
✅ Token issued
✅ SUCCESS! Token verified
```

---

## 🎟️ Scenario 2: With Invitation System

**Goal:** Set up trust-based Sybil resistance where users need an invite to get tokens.

### Step 1: Configure & Start Issuer

```bash
# Terminal 1 - Stop previous issuer first
export SYBIL_RESISTANCE=invitation
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:100
export ADMIN_API_KEY=my-super-secure-admin-key-at-least-32-chars

./target/release/issuer
```

### Step 2: Check Admin Stats

```bash
# Terminal 2
curl http://localhost:8081/admin/stats \
  -H "X-Admin-Key: my-super-secure-admin-key-at-least-32-chars"
```

### Step 3: Attempt Issuance (Expected Failure)

```bash
./target/release/interface
```

**Expected output:**
```
❌ Token issuance failed: Sybil resistance proof required
```

---

## 🏭 Scenario 3: Manual Production-Like Setup

**Goal:** Run the binaries manually but with Redis and stricter security settings, simulating a non-Docker production deploy.

### Step 1: Start Redis

```bash
# Terminal 1
redis-server
```

### Step 2: Configure Environment

```bash
cat > .env.production << 'ENVFILE'
# Issuer
ISSUER_ID=issuer:production:v1
BIND_ADDR=127.0.0.1:8081
TOKEN_TTL_MIN=60
SYBIL_RESISTANCE=invitation
SYBIL_INVITE_PERSISTENCE_PATH=invitations.json
SYBIL_INVITE_BOOTSTRAP_USERS=admin:100
ADMIN_API_KEY=generate-secure-key-with-openssl-rand-base64-48

# Verifier
BIND_ADDR=127.0.0.1:8082
REDIS_URL=redis://localhost:6379
ISSUER_URL=http://localhost:8081/.well-known/issuer
ENVFILE

source .env.production
```

### Step 3: Start Services

```bash
# Terminal 2
./target/release/issuer

# Terminal 3
./target/release/verifier
```

---

## Common Issues

### "Address already in use"
**Solution:** Ensure no other `issuer` or `verifier` processes are running, and check that Docker containers are stopped (`docker-compose down`) if switching between Docker and manual modes.

### "Connection refused"
**Solution:** If running `interface` from your host machine against Docker, ensure ports `8081` and `8082` are exposed (the default `docker-compose.yaml` does this).

### "Sybil resistance proof required"
**Solution:** The issuer is configured to require a proof (Invitation, PoW, etc.). Use the SDK to provide one, or switch `SYBIL_RESISTANCE` to `none` for testing.

---

**Next Steps:**
- [Configuration Reference](CONFIGURATION.md) - Tweak settings
- [Invitation System](INVITATION_SYSTEM.md) - Manage users
- [Production Guide](PRODUCTION.md) - Security hardening