# 🎟️ Invitation System Guide

Complete guide to Freebird's trust-based Sybil resistance mechanism.

---

## Overview

The **Invitation System** is a production-ready, trust-based Sybil resistance mechanism where existing users invite new users, creating social accountability without surveillance or biometric identification.

**Key Properties:**
- ✅ No biometrics or identity verification required
- ✅ Social accountability (reputation staking)
- ✅ Cryptographically secure (ECDSA P-256 signatures)
- ✅ Persistent state (survives restarts)
- ✅ Strong invitee ID generation (192 bits of entropy)
- ✅ Self-policing communities (ban trees)

**Best For:**
- Trust-based communities
- High-value applications requiring human verification
- Systems where social reputation matters
- When proof-of-work or rate limiting is insufficient

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Configuration](#configuration)
3. [User Workflow](#user-workflow)
4. [Invitee ID Security](#invitee-id-security)
5. [Administrative Operations](#administrative-operations)
6. [Ban System](#ban-system)
7. [State Persistence](#state-persistence)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)

---

## How It Works

### Lifecycle Overview

```
┌──────────────┐
│   Bootstrap  │  Admin creates initial users with invites
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Generate   │  User generates cryptographically signed invitation
└──────┬───────┘
       │
       ▼
┌──────────────┐
│     Share    │  Share code + signature out-of-band (email, Signal, etc.)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│    Redeem    │  Invitee uses code when requesting token
└──────┬───────┘
       │
       ▼
┌──────────────┐
│    Verify    │  Issuer validates signature and marks invitation used
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Create User │  New user created with 0 invites (must wait)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Wait Period │  After 30 days, user earns invites and can invite others
└──────────────┘
```

### Trust Network Growth

```
admin (100 invites)
  ├─► alice (5 invites, after 30 days)
  │     ├─► bob (5 invites, after 30 days)
  │     │     ├─► charlie
  │     │     └─► david
  │     └─► eve
  └─► frank (5 invites, after 30 days)
        └─► grace
```

**Properties:**
- Growth is organic and rate-limited
- Each level of the tree has accountability to the level above
- Banning a node can cascade down the tree (optional)
- Reputation flows up the tree (good invitees boost inviter reputation)

---

## Configuration

### Basic Setup

```bash
# Enable invitation system
export SYBIL_RESISTANCE=invitation

# Core settings
export SYBIL_INVITE_PER_USER=5                  # Invites each user gets
export SYBIL_INVITE_COOLDOWN_SECS=3600          # 1 hour between invites
export SYBIL_INVITE_EXPIRES_SECS=2592000        # 30 days validity
export SYBIL_INVITE_NEW_USER_WAIT_SECS=2592000  # 30 days before new users can invite

# Persistence
export SYBIL_INVITE_PERSISTENCE_PATH=invitations.json
export SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS=300  # Auto-save every 5 minutes

# Bootstrap initial users (format: username:invite_count,...)
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:100,alice:50
```

### Configuration Parameters Explained

| Parameter | Default | Description | Recommended Values |
|-----------|---------|-------------|-------------------|
| `SYBIL_INVITE_PER_USER` | 5 | Invites each user receives | 3-10 depending on community size |
| `SYBIL_INVITE_COOLDOWN_SECS` | 3600 | Minimum time between sending invites | 3600 (1 hour) for spam prevention |
| `SYBIL_INVITE_EXPIRES_SECS` | 2592000 | How long invitations remain valid | 2592000 (30 days) typical |
| `SYBIL_INVITE_NEW_USER_WAIT_SECS` | 2592000 | Wait before new users can invite | 2592000 (30 days) to prevent rapid expansion |
| `SYBIL_INVITE_PERSISTENCE_PATH` | invitations.json | Where to store state | Absolute path recommended for production |
| `SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS` | 300 | How often to auto-save state | 300 (5 minutes) balances safety and I/O |
| `SYBIL_INVITE_BOOTSTRAP_USERS` | None | Initial users | Format: `user1:invites1,user2:invites2` |

### Advanced Configuration

#### High-Security Communities

For communities requiring strong trust:

```bash
export SYBIL_INVITE_PER_USER=3                      # Fewer invites = more selective
export SYBIL_INVITE_COOLDOWN_SECS=86400             # 24 hours between invites
export SYBIL_INVITE_NEW_USER_WAIT_SECS=7776000      # 90 days (3 months) waiting period
export SYBIL_INVITE_EXPIRES_SECS=604800             # 7 days (must use quickly)
```

#### Rapid Growth Communities

For communities prioritizing growth:

```bash
export SYBIL_INVITE_PER_USER=10                     # More invites per user
export SYBIL_INVITE_COOLDOWN_SECS=300               # 5 minutes between invites
export SYBIL_INVITE_NEW_USER_WAIT_SECS=604800       # 7 days waiting period
export SYBIL_INVITE_EXPIRES_SECS=7776000            # 90 days validity
```

#### Testing/Development

For local testing:

```bash
export SYBIL_INVITE_PER_USER=100                    # Unlimited for testing
export SYBIL_INVITE_COOLDOWN_SECS=0                 # No cooldown
export SYBIL_INVITE_NEW_USER_WAIT_SECS=0            # Immediate invite ability
export SYBIL_INVITE_EXPIRES_SECS=31536000           # 1 year
```

---

## User Workflow

### Step 1: Generate an Invitation

**Via Programmatic API** (requires access to invitation system):

```rust
use freebird::InvitationSystem;

let (code, signature, expires_at) = invitation_system
    .generate_invite("alice")
    .await?;

println!("Invitation Code: {}", code);      // e.g., "Abc123XyZ456..."
println!("Signature: {}", signature);        // e.g., "3045022100..."
println!("Expires: {}", expires_at);         // Unix timestamp
```

**Via Admin API** (recommended for production):

```bash
# TODO: This endpoint doesn't exist yet but should be added
curl -X POST http://localhost:8081/admin/invites/generate \
  -H "X-Admin-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice"}'
```

**Response:**
```json
{
  "code": "Abc123XyZ456PqRsTuVw",
  "signature": "3045022100d7f2e8c9a1b3f4e5d6c7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f502201a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7",
  "expires_at": 1702046445
}
```

### Step 2: Share the Invitation

Share both the **code** and **signature** with the invitee through a secure, out-of-band channel:

**Good channels:**
- ✅ Email (if encrypted)
- ✅ Signal / WhatsApp / Telegram (encrypted messaging)
- ✅ In-person (QR code or written down)
- ✅ Encrypted file sharing (Keybase, etc.)

**Bad channels:**
- ❌ Public forums (anyone can redeem)
- ❌ Unencrypted email (vulnerable to interception)
- ❌ Social media DMs (platform can see)
- ❌ SMS (unencrypted, carrier can see)

**Example message:**

```
Welcome to [Community]!

Here's your invitation:

Code:      Abc123XyZ456PqRsTuVw
Signature: 3045022100d7f2e8c9...

This invitation expires on: 2024-12-08

To redeem:
1. Visit https://example.com/register
2. Enter the code and signature when requesting a token
3. Complete the registration process

Questions? Reply to this message.
```

### Step 3: Redeem the Invitation

The invitee includes the invitation proof when requesting a token from the issuer:

**HTTP Request:**

```bash
POST /v1/oprf/issue
Content-Type: application/json

{
  "blinded_element_b64": "A1b2c3d...",
  "sybil_proof": {
    "type": "invitation",
    "code": "Abc123XyZ456PqRsTuVw",
    "signature": "3045022100d7f2e8c9..."
  }
}
```

**Client-side (Rust example):**

```rust
use freebird_client::{Client, SybilProof};

let mut client = Client::new(b"freebird:v1");
let input = rand::random::<[u8; 32]>();

// Blind the input
let (blinded, blind_state) = client.blind(&input)?;

// Create Sybil proof
let proof = SybilProof::Invitation {
    code: "Abc123XyZ456PqRsTuVw".to_string(),
    signature: "3045022100d7f2e8c9...".to_string(),
};

// Request token with proof
let response = http_client
    .post("http://issuer:8081/v1/oprf/issue")
    .json(&IssueRequest {
        blinded_element_b64: base64::encode(&blinded),
        sybil_proof: Some(proof),
    })
    .send()
    .await?;

// Finalize token
let token = client.finalize(blind_state, &response.token, &issuer_pubkey)?;
```

### Step 4: Issuer Verification

The issuer automatically:

1. **Verifies signature** - ECDSA P-256 verification against inviter's public key
2. **Checks invitation exists** - Code present in invitation database
3. **Validates expiration** - Current time < expiration timestamp
4. **Checks redemption status** - Invitation not already used
5. **Verifies inviter status** - Inviter not banned
6. **Generates invitee ID** - Strong 192-bit ID with random nonce
7. **Marks as redeemed** - Single-use enforcement
8. **Creates new user** - User record with 0 invites initially
9. **Issues token** - VOPRF token generation
10. **Persists state** - Saves to disk

**Success Response:**

```json
{
  "token": "Q9w8x7y6v5u4t3s2r1q0p9o8n7m6l5k4j3h2g1f0e9d8c7b6a5",
  "proof": "",
  "kid": "freebird-2024-11-15",
  "exp": 1699458045,
  "sybil_info": {
    "required": true,
    "passed": true,
    "cost": 0
  }
}
```

**Error Responses:**

```json
// Invalid signature
{
  "error": "Sybil resistance verification failed",
  "details": "invitation signature verification failed"
}

// Expired invitation
{
  "error": "Sybil resistance verification failed",
  "details": "invitation expired"
}

// Already redeemed
{
  "error": "Sybil resistance verification failed",
  "details": "invitation already used"
}

// Inviter banned
{
  "error": "Sybil resistance verification failed",
  "details": "inviter is banned"
}
```

---

## Invitee ID Security

### Generation Algorithm

Each redeemed invitation generates a unique **invitee ID** through cryptographic hashing:

```rust
SHA-256(
    "freebird:invitee:v2:" ||
    invitation_code ||
    redemption_timestamp ||
    hash(client_ip_address) ||
    hash(client_user_agent) ||
    random_nonce_16_bytes
)[0..24]  // First 192 bits, base64url-encoded
```

### Entropy Sources

| Source | Bits | Purpose |
|--------|------|---------|
| Invitation code | ~128 | Unique per invitation |
| Redemption timestamp | ~32 | Prevents pre-computation |
| Client IP hash | ~24 | Adds environmental entropy |
| User-Agent hash | ~24 | Browser/client differentiation |
| Random nonce | **128** | **Guarantees uniqueness** |
| **Total** | **~336 bits input** → **192 bits output** | **Collision resistance** |

### Security Properties

**Prevents:**
- ❌ **ID Collisions** - Random nonce ensures mathematical uniqueness
- ❌ **Pre-computation Attacks** - Timestamp binding prevents pre-generation
- ❌ **Linkability** - Each redemption produces different ID even with same code
- ❌ **Prediction** - Multiple entropy sources make IDs unpredictable
- ❌ **Brute Force** - 192 bits = 2^192 possibilities (computationally infeasible)

**Properties:**
- ✅ **Deterministic for replay detection** - Same exact redemption = same ID (within millisecond)
- ✅ **Privacy-preserving** - IP and User-Agent are hashed, never stored raw
- ✅ **Unique per invitation** - Different codes always produce different IDs
- ✅ **Time-bound** - Timestamp makes IDs unique even if all other inputs match

### Client Data Extraction

The issuer automatically extracts client information from HTTP requests:

**IP Address:**
- Behind proxy: Reads `X-Forwarded-For` header (first IP)
- Direct connection: Uses socket IP address
- Hashed before use: `SHA-256("freebird:client:" || ip)[0..16]`

**User-Agent Fingerprint:**
- Extracted from `User-Agent` HTTP header
- Hashed: `SHA-256("freebird:ua:" || user_agent)[0..16]`
- Never stored in plaintext

**Configuration:**

```bash
# Trust X-Forwarded-For when behind reverse proxy
export BEHIND_PROXY=true
```

**Example extraction:**

```http
POST /v1/oprf/issue HTTP/1.1
Host: issuer:8081
X-Forwarded-For: 203.0.113.42, 10.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

Results in:
```rust
ClientData {
    ip_addr: Some("203.0.113.42"),           // First IP from X-Forwarded-For
    fingerprint: Some("A3x5Y2z8B4w7..."),    // SHA-256(UA)[0..16] base64url
    extra: None
}
```

---

## Administrative Operations

See [Admin API Reference](ADMIN_API.md) for complete HTTP API documentation.

### Common Operations

#### Grant Additional Invites (Reputation Reward)

```bash
curl -X POST http://localhost:8081/admin/invites/grant \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice", "count": 10}'
```

**Use cases:**
- Reward trusted community members
- Compensate for accidentally used invites
- Bootstrap moderators or ambassadors

#### Check User Status

```bash
curl http://localhost:8081/admin/users/alice \
  -H "X-Admin-Key: ${ADMIN_KEY}"
```

**Response:**
```json
{
  "user_id": "alice",
  "invites_remaining": 3,
  "invites_sent": 5,
  "invites_used": 5,
  "joined_at": 1699000000,
  "last_invite_at": 1699400000,
  "reputation": 1.0,
  "banned": false,
  "invitees": ["bob", "charlie", "david", "eve", "frank"]
}
```

#### Get System Statistics

```bash
curl http://localhost:8081/admin/stats \
  -H "X-Admin-Key: ${ADMIN_KEY}"
```

**Response:**
```json
{
  "stats": {
    "total_invitations": 150,
    "redeemed_invitations": 120,
    "pending_invitations": 30,
    "total_users": 120,
    "banned_users": 5
  },
  "timestamp": 1699454445
}
```

---

## Ban System

### Simple Ban (Single User)

```bash
curl -X POST http://localhost:8081/admin/users/ban \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "spammer", "ban_tree": false}'
```

**Effect:**
- User cannot issue new tokens
- User cannot generate new invitations
- Existing invitations remain valid (unless expired)
- Invitees are unaffected

### Ban Tree (Cascade Ban)

```bash
curl -X POST http://localhost:8081/admin/users/ban \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "spammer", "ban_tree": true}'
```

**Effect:**
- Bans target user AND all users they invited (recursively)
- Entire subtree of the invite graph is banned
- Prevents compromised accounts from polluting the network

**Example:**

```
admin
  ├─► alice
  │     ├─► bob
  │     │     ├─► charlie  ← Ban with tree
  │     │     │     ├─► david    ✗ Banned
  │     │     │     └─► eve      ✗ Banned
  │     │     └─► frank          ✗ Banned
  │     └─► grace                ✗ Banned
  └─► henry                      ✓ Unaffected
```

Banning `charlie` with `ban_tree: true` bans: charlie, david, eve (3 users).

**Use Cases:**
- **Sybil attack detected** - Ban entire attack subtree
- **Compromised account** - Prevent all downstream damage
- **Policy violation** - Remove violator and those they vouched for
- **Community purge** - Remove entire toxic branch

**⚠️ Warning:** Ban trees are **permanent** and **irreversible**. Use with caution.

### Checking Ban Tree Size

Before executing a ban tree, check impact:

```bash
# Via Admin API (programmatic)
curl http://localhost:8081/admin/users/charlie \
  -H "X-Admin-Key: ${ADMIN_KEY}"

# Count invitees recursively
# (This endpoint would need to be added to show tree size)
```

**Future enhancement:** Add `POST /admin/users/ban/preview` endpoint to show affected users before banning.

---

## State Persistence

### Automatic Persistence

State is automatically saved:
- On invitation generation
- On invitation redemption
- On user ban/unban
- On invite grant
- Every N seconds (configurable via `SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS`)

**Configuration:**

```bash
export SYBIL_INVITE_PERSISTENCE_PATH=/var/lib/freebird/invitations.json
export SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS=300  # 5 minutes
```

### Manual Persistence

Trigger immediate save via Admin API:

```bash
curl -X POST http://localhost:8081/admin/save \
  -H "X-Admin-Key: ${ADMIN_KEY}"
```

**Use cases:**
- Before system maintenance
- After bulk administrative operations
- Before backups
- After critical changes

### State File Format

```json
{
  "invitations": {
    "Abc123XyZ456": {
      "code": "Abc123XyZ456",
      "inviter_id": "alice",
      "invitee_id": "bob",
      "created_at": 1699000000,
      "expires_at": 1701592000,
      "signature": "3045022100...",
      "redeemed": true
    }
  },
  "inviters": {
    "alice": {
      "user_id": "alice",
      "invites_remaining": 3,
      "invites_sent": ["Abc123XyZ456", "Def789GhI012"],
      "invites_used": ["Abc123XyZ456"],
      "joined_at": 1698000000,
      "last_invite_at": 1699400000,
      "reputation": 1.0,
      "banned": false
    }
  },
  "version": 1
}
```

### Backup Strategy

**Recommended:**

```bash
# Daily backups
0 2 * * * cp /var/lib/freebird/invitations.json \
             /var/lib/freebird/backups/invitations.$(date +\%Y\%m\%d).json

# Keep last 30 days
0 3 * * * find /var/lib/freebird/backups/ -name "invitations.*.json" \
             -mtime +30 -delete
```

**Before major operations:**

```bash
# Manual backup before risky operations
cp invitations.json invitations.backup.$(date +%Y%m%d-%H%M%S).json

# Perform operation
curl -X POST http://localhost:8081/admin/users/ban \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -d '{"user_id": "suspect", "ban_tree": true}'

# Verify
curl http://localhost:8081/admin/stats -H "X-Admin-Key: ${ADMIN_KEY}"

# Restore if needed
# mv invitations.backup.20241115-143022.json invitations.json
# systemctl restart freebird-issuer
```

### Recovery from Corruption

If state file is corrupted:

```bash
# 1. Stop issuer
systemctl stop freebird-issuer

# 2. Validate JSON
jq . invitations.json

# 3. If invalid, restore from backup
cp /var/lib/freebird/backups/invitations.20241115.json invitations.json

# 4. Restart issuer
systemctl start freebird-issuer

# 5. Verify
curl http://localhost:8081/admin/stats -H "X-Admin-Key: ${ADMIN_KEY}"
```

---

## Best Practices

### Invitation Management

**DO:**
- ✅ Start with small invite quotas (3-5) and increase based on reputation
- ✅ Use longer waiting periods (30+ days) for high-security communities
- ✅ Monitor invitation usage patterns for abuse
- ✅ Reward good inviters with additional invites
- ✅ Set invitation expiration to prevent hoarding

**DON'T:**
- ❌ Give unlimited invites to untested users
- ❌ Allow immediate inviting for new users (waiting period important)
- ❌ Ignore invitation usage patterns (detect abuse early)
- ❌ Make invitations too short-lived (users need time to use them)

### Bootstrap Strategy

**Small Communities (<100 users):**
```bash
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:50,moderator1:25,moderator2:25
```
- Start with 2-3 trusted bootstraps
- Monitor growth carefully
- Adjust quotas based on usage

**Medium Communities (100-1000 users):**
```bash
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:100,mod1:50,mod2:50,mod3:50
```
- Multiple moderators with invite power
- Stagger invite distribution
- Implement reputation tracking

**Large Communities (1000+ users):**
```bash
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:500,regional_admins:100x5
```
- Hierarchical structure with regional admins
- Automated monitoring and alerting
- Reputation-based invite allocation

### Security Hardening

**Network Security:**
```bash
# Restrict issuer to internal network only
iptables -A INPUT -p tcp --dport 8081 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8081 -j DROP

# Or use application-level controls
export BIND_ADDR=127.0.0.1:8081  # Localhost only
```

**State Protection:**
```bash
# Secure file permissions
chmod 600 /var/lib/freebird/invitations.json
chown freebird:freebird /var/lib/freebird/invitations.json

# Enable automatic backups
export SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS=300

# Monitor file integrity
tripwire --init /var/lib/freebird/invitations.json
```

**Monitoring:**
```bash
# Track invitation patterns
watch -n 60 "curl -s http://localhost:8081/admin/stats \
  -H 'X-Admin-Key: ${ADMIN_KEY}' | jq '.stats'"

# Alert on suspicious activity
# - Spike in invitation generation
# - Unusual redemption patterns  
# - Ban rate increases
```

### Reputation Management

**Track invite success rate:**

```bash
# Get user details
curl http://localhost:8081/admin/users/alice \
  -H "X-Admin-Key: ${ADMIN_KEY}" | jq '
  {
    user: .user_id,
    success_rate: (.invites_used / .invites_sent),
    reputation: .reputation
  }'
```

**Reward calculation:**

- Success rate > 90% → Grant +5 invites
- Success rate 70-90% → Grant +2 invites
- Success rate < 70% → No additional invites
- Success rate < 50% → Investigate for abuse

**Automated rewards (cron job):**

```bash
#!/bin/bash
# reward-good-inviters.sh

ADMIN_KEY="your-key"
THRESHOLD=0.9

# Get all users
users=$(curl -s http://localhost:8081/admin/users \
  -H "X-Admin-Key: ${ADMIN_KEY}")

# Filter high performers and reward
echo "$users" | jq -r '.[] | select(.success_rate > '$THRESHOLD') | .user_id' | while read user; do
  curl -X POST http://localhost:8081/admin/invites/grant \
    -H "X-Admin-Key: ${ADMIN_KEY}" \
    -d "{\"user_id\": \"$user\", \"count\": 5}"
  echo "Rewarded $user with 5 invites"
done
```

---

## Troubleshooting

### Common Issues

#### "Invitation not found"

**Causes:**
1. Wrong invitation code (typo)
2. Invitation expired and cleaned up
3. State file not loaded properly

**Solution:**
```bash
# Check invitation exists
curl http://localhost:8081/admin/invitations/CODE \
  -H "X-Admin-Key: ${ADMIN_KEY}"

# Check issuer logs
journalctl -u freebird-issuer | grep -i "invitation"

# Verify state file loaded
curl http://localhost:8081/admin/stats -H "X-Admin-Key: ${ADMIN_KEY}"
```

#### "Invitation already used"

**Cause:** Someone already redeemed this invitation (single-use enforcement).

**Solution:**
- Invitation codes are single-use by design
- Inviter must generate a new invitation
- Check who redeemed: `curl http://localhost:8081/admin/invitations/CODE`

#### "Invitation expired"

**Causes:**
1. Too much time passed since generation
2. System clock drift

**Solutions:**
```bash
# Check expiration settings
echo $SYBIL_INVITE_EXPIRES_SECS

# Increase validity period if needed
export SYBIL_INVITE_EXPIRES_SECS=7776000  # 90 days

# Check system time
timedatectl status
ntpdate -q pool.ntp.org

# Generate new invitation
curl -X POST http://localhost:8081/admin/invites/generate \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -d '{"user_id": "alice"}'
```

#### "Inviter is banned"

**Cause:** The person who created the invitation has been banned.

**Solution:**
- Invitation is invalid (security feature)
- User needs invitation from a non-banned member
- Contact admin to check ban status

#### State file not loading on restart

**Causes:**
1. Wrong file path
2. Corrupted JSON
3. Permission issues

**Solutions:**
```bash
# Check file exists
ls -la invitations.json

# Validate JSON
jq . invitations.json

# Check permissions
chmod 600 invitations.json
chown freebird:freebird invitations.json

# Check issuer logs for load errors
journalctl -u freebird-issuer -n 100 | grep -i "load"

# Restore from backup if corrupted
cp /path/to/backup/invitations.20241115.json invitations.json
systemctl restart freebird-issuer
```

#### Invitee IDs colliding (very rare)

**Cause:** Cosmic ray bit flip or catastrophic RNG failure (theoretical only).

**Check:**
```bash
# This should never happen with 192-bit IDs
# If it does, check system entropy
cat /proc/sys/kernel/random/entropy_avail

# Should be > 1000. If low, install haveged:
apt-get install haveged
systemctl enable haveged
systemctl start haveged
```

---

## Performance Considerations

### Invitation Generation

- **Cost:** ECDSA P-256 signature generation (~1ms per invitation)
- **Throughput:** ~1000 invitations/second per core
- **Bottleneck:** Disk I/O for persistence (async writes mitigate)

### Invitation Verification

- **Cost:** ECDSA P-256 signature verification (~2ms per redemption)
- **Throughput:** ~500 redemptions/second per core
- **Bottleneck:** Database lookups (in-memory HashMap is fast)

### State Persistence

- **File size:** ~1KB per user + ~500 bytes per invitation
- **10,000 users:** ~15MB state file
- **100,000 users:** ~150MB state file
- **Write frequency:** Configurable (default: 5 minutes)

**Optimization tips:**
- Use SSDs for state file
- Increase autosave interval for high-traffic (e.g., 10-15 minutes)
- Monitor disk I/O during peak invitation activity

---

## Migration Guide

### From Permissive Mode to Invitation System

**Step 1: Plan Bootstrap Strategy**

Identify initial trusted users:
```bash
# Example: Start with 3 admins
export SYBIL_INVITE_BOOTSTRAP_USERS=admin1:100,admin2:50,admin3:50
```

**Step 2: Enable Invitation System**

```bash
# Update configuration
export SYBIL_RESISTANCE=invitation
export SYBIL_INVITE_PER_USER=5
export SYBIL_INVITE_PERSISTENCE_PATH=/var/lib/freebird/invitations.json

# Restart issuer
systemctl restart freebird-issuer
```

**Step 3: Notify Users**

```
IMPORTANT: Authentication Update

We're transitioning to an invitation-based system to improve
community quality and prevent abuse.

What this means:
- Existing users are unaffected
- New users need an invitation from existing members
- Each member gets 5 invitations to share

Contact @admin if you need help getting invitations for friends.
```

**Step 4: Monitor Transition**

```bash
# Track adoption
watch -n 300 "curl -s http://localhost:8081/admin/stats \
  -H 'X-Admin-Key: ${ADMIN_KEY}' | jq '.stats'"

# Adjust invite quotas based on demand
curl -X POST http://localhost:8081/admin/invites/grant \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -d '{"user_id": "active_user", "count": 10}'
```

### From Other Sybil Mechanisms

**From Proof-of-Work:**
- Users accustomed to computational cost
- Transition: Offer free invitations to existing PoW users
- Benefit: No more electricity waste

**From Rate Limiting:**
- Users accustomed to time-based limits
- Transition: Convert rate-limited IPs to invitation-based users
- Benefit: True Sybil resistance instead of IP-based throttling

---

## Related Documentation

- [Admin API Reference](ADMIN_API.md) - Complete HTTP API for invitation management
- [Sybil Resistance Overview](SYBIL_RESISTANCE.md) - Comparison of all mechanisms
- [Configuration Guide](CONFIGURATION.md) - All environment variables
- [Security Model](SECURITY.md) - Threat model and guarantees
- [Production Deployment](PRODUCTION.md) - Best practices and checklist

---

## FAQ

**Q: Can I migrate invitation state between environments?**

A: Yes, the state file is portable:
```bash
# Copy from production to staging
scp prod:/var/lib/freebird/invitations.json \
    staging:/var/lib/freebird/invitations.json
```

**Q: What happens if I lose the state file?**

A: All invitation history is lost. Users will need new invitations. **Always maintain backups**.

**Q: Can users transfer invitations to others?**

A: No. Invitations are tied to the inviter cryptographically. They cannot be reassigned.

**Q: How do I prevent invitation hoarding?**

A: Set appropriate expiration times and cooldown periods. Monitor unused invitations and reduce quotas for hoarders.

**Q: Can I integrate this with external identity systems?**

A: Yes, but it defeats the purpose. The power of Freebird is **not** requiring external identity. You can use invitations as a supplementary verification step alongside traditional auth.

**Q: What if a user's private key is compromised?**

A: Invitations signed by that key remain valid (they were legitimately created). Ban the user to prevent future invitations. Consider ban tree if suspicious.

---

**Questions or Issues?**

Open a GitHub issue or check the [Troubleshooting Guide](TROUBLESHOOTING.md) for more help.