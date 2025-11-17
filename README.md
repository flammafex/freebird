[<div align=center><img src="freebird.webp">](https://carpocratian.org/en/church/)
[<div align=center><br><img src="church.png" width=72 height=72>](https://carpocratian.org/en/church/)

_A mission of [The Carpocratian Church of Commonality and Equality](https://carpocratian.org/en/church/)_.</div>
<div align=center><img src="mission.png" width=256 height=200></div></div>

# What is 🕊️ Freebird?
**Anonymous credential system using VOPRF cryptography**

Freebird is a self-hostable anonymous token system that allows users to prove authorization without revealing their identity or linking multiple uses. Think of it as anonymous digital cash for the internet—users get cryptographic tokens that prove "I'm authorized" without revealing "who I am."

Built with production-ready Rust, Freebird provides cryptographic unlinkability and replay protection through VOPRF (Verifiable Oblivious Pseudorandom Function) with DLEQ proofs on the P-256 elliptic curve.

## Why 🕊️ Freebird?

**The Problem:** Traditional authentication links every action to an identity. Rate limiting requires tracking users. Privacy and access control are at odds.

**The Solution:** Freebird issues anonymous tokens that prove authorization without surveillance. The issuer can't track where tokens are used. The verifier can't link uses to identities. Yet double-spending is prevented through nullifier-based replay protection. Multiple Sybil resistance mechanisms—including a production-ready invitation system—ensure one-per-human without biometrics or surveillance infrastructure.

**Use Cases:**
- Anonymous rate limiting (verify "human-ness" without tracking users)
- Privacy-preserving access control (prove membership without revealing identity)
- Unlinkable proof-of-work systems
- Anonymous voting or polling
- Private content access (paywalls, subscriptions)
- Bot prevention without surveillance
- Trust-based community building (invitation networks)

## Key Features

- **Cryptographic Unlinkability** – Issuer can't track where tokens are used
- **Multiple Sybil Resistance Options** – Choose invitation system, proof-of-work, rate limiting, or combine them
- **Production-Ready Invitation System** – Trust-based Sybil resistance with persistence and strong cryptographic properties
- **Self-Hostable** – No central authority required
- **Replay Protection** – Nullifier-based double-spend prevention with automatic cleanup
- **Token Expiration** – Time-bound validity with clock skew tolerance
- **Flexible Storage** – In-memory or Redis backend for spent token tracking
- **Standards-Based** – P-256 VOPRF with DLEQ proofs
- **Battle-Tested** – ~5,000 lines of robust Rust with comprehensive tests

## How 🕊️ Freebird Works

### The Cryptography: VOPRF in Plain Terms

Freebird uses **VOPRF (Verifiable Oblivious Pseudorandom Function)**, a cryptographic protocol with three magical properties:

1. **Oblivious**: The server computes a function on your input without seeing what that input is
2. **Pseudorandom**: The output looks random and is unique to your input
3. **Verifiable**: You can prove the server computed correctly without revealing your input

Here's the flow:

```
┌─────────┐                 ┌─────────┐                 ┌──────────┐
│ Client  │                 │ Issuer  │                 │ Verifier │
└────┬────┘                 └────┬────┘                 └────┬─────┘
     │                           │                           │
     │  1. Generate input        │                           │
     │     (random 32 bytes)     │                           │
     │                           │                           │
     │  2. Blind input           │                           │
     │     (multiply by random)  │                           │
     │                           │                           │
     │  3. Send blinded ─────────▶                           │
     │     + Sybil proof (opt)   │                           │
     │                           │                           │
     │                           │  4. Verify Sybil proof    │
     │                           │     (if configured)       │
     │                           │                           │
     │                           │  5. Evaluate VOPRF        │
     │                           │     (sign with key)       │
     │                           │                           │
     │                           │  6. Create DLEQ proof     │
     │                           │     (prove correctness)   │
     │                           │                           │
     │  7. Return signed ◀───────┤                           │
     │     + expiration          │                           │
     │                           │                           │
     │  8. Unblind & verify      │                           │
     │     (remove random,       │                           │
     │      check DLEQ proof)    │                           │
     │                           │                           │
     │  9. Send token ───────────┼──────────────────────────▶
     │     + expiration          │                           │
     │                           │                           │
     │                           │                           │ 10. Check expiration
     │                           │                           │     (with clock skew)
     │                           │                           │
     │                           │                           │ 11. Verify signature
     │                           │                           │     (DLEQ proof)
     │                           │                           │
     │                           │                           │ 12. Check nullifier
     │                           │                           │     (prevent replay)
     │                           │                           │
     │ 13. Success ◀─────────────┼───────────────────────────┤
     │                           │                           │
```

**Why This Matters:**

- The issuer **never sees your original input** (blinding protects it)
- The issuer **can't link issuance to redemption** (different blinding each time)
- The verifier **can't tell which issuer session** produced a token
- Tokens **can't be reused** (nullifiers prevent double-spending)
- Tokens **expire automatically** (time-bound validity prevents abuse)
- Sybil attacks **are prevented** (via invitations, PoW, or rate limiting)

### Technical Details

**VOPRF Protocol (P-256, SHA-256):**

1. **Blinding**: Client computes `blinded = H(input) * r` where `r` is random
2. **Evaluation**: Issuer computes `evaluated = blinded ^ sk` with secret key
3. **Proof**: Issuer creates DLEQ proof that `evaluated` is correctly computed
4. **Finalization**: Client verifies proof and unblinds: `token = evaluated * r^-1`
5. **Verification**: Verifier checks `H(input) ^ sk == PRF_output` using public key

**Nullifier Construction:**

```
nullifier = SHA-256(issuer_id || token_output)
```

This binds the token to a specific issuer and allows deterministic replay detection without revealing the original input.

**Expiration Validation:**

Tokens include an expiration timestamp (`exp`) set by the issuer. The verifier checks:
- Token has not expired (current time ≤ exp + clock skew tolerance)
- Expiration is not suspiciously far in the future
- Default clock skew tolerance: 5 minutes (configurable)

## Architecture

Freebird consists of three components:

### 1. Issuer Service (`issuer/`)

Issues anonymous tokens via VOPRF evaluation with optional Sybil resistance.

- **Tech**: Axum/Rust web service
- **Port**: 8081 (configurable)
- **Key Endpoint**: `POST /v1/oprf/issue` (adaptive: accepts optional Sybil proofs)
- **Metadata**: `GET /.well-known/issuer` (returns public key, key ID, expiration)
- **Sybil Options**: Invitation system, proof-of-work, rate limiting, or combined

### 2. Verifier Service (`verifier/`)

Verifies tokens with expiration checking and replay protection.

- **Tech**: Axum/Rust web service  
- **Port**: 8082 (configurable)
- **Key Endpoint**: `POST /v1/verify`
- **Features**: Expiration validation, nullifier tracking, automatic cleanup
- **Storage**: In-memory HashMap or Redis
- **Refresh**: Auto-fetches issuer metadata on interval

### 3. CLI Client (`interface/`)

Command-line tool for testing and demonstrations.

**Test Modes:**
- Normal flow (issue + verify)
- Replay attack testing
- Expiration validation testing
- Token persistence (save/load)
- Stress testing (batch operations)

## Quick Start

### Prerequisites

- Rust 1.70+ ([rustup.rs](https://rustup.rs))
- Optional: Redis (for production verifier storage)

### Build

```bash
# Build all components
cargo build --release

# Binaries will be in target/release/
```

### Running Locally (Permissive Mode)

**Terminal 1 - Start the issuer:**

```bash
./target/release/issuer

# Or with custom config:
BIND_ADDR=0.0.0.0:8081 \
ISSUER_ID=issuer:myapp:v1 \
TOKEN_TTL_MIN=60 \
./target/release/issuer
```

**Terminal 2 - Start the verifier:**

```bash
./target/release/verifier

# Or with Redis:
REDIS_URL=redis://localhost:6379 \
ISSUER_URL=http://localhost:8081/.well-known/issuer \
./target/release/verifier
```

**Terminal 3 - Test with the CLI:**

```bash
# Normal flow (issue and verify)
./target/release/interface

# Test replay protection
./target/release/interface --replay

# Test expiration validation
./target/release/interface --expired

# Stress test
./target/release/interface --stress 100
```

### Example Output

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
   └─ Verified at: 2024-11-08T15:30:45Z

✅ SUCCESS! Token verified
```

## Sybil Resistance

Freebird supports multiple Sybil resistance mechanisms to prevent users from obtaining unlimited tokens. Choose the approach that best fits your use case.

### 1. Invitation System (Recommended for Production)

**Status**: ✅ Production-ready with full persistence

A trust-based system where existing users invite new users, creating social accountability without surveillance.

#### Key Features

- **Cryptographically Signed Invitations** (ECDSA P-256)
- **JSON-Based Persistence** (survives restarts, automatic backups)
- **Strong Invitee ID Generation** (192 bits of entropy from multiple sources)
- **Invite Quotas & Cooldowns** (prevent invitation spam)
- **Reputation Tracking** (trust scores, ban trees)
- **Automatic State Persistence** (configurable auto-save intervals)
- **Bootstrap Support** (seed initial users)

#### Configuration

```bash
export SYBIL_RESISTANCE=invitation

# Invitation system settings
export SYBIL_INVITE_PER_USER=5                      # Default invites per user
export SYBIL_INVITE_COOLDOWN_SECS=3600              # 1 hour between invites
export SYBIL_INVITE_EXPIRES_SECS=2592000            # 30 days validity
export SYBIL_INVITE_NEW_USER_WAIT_SECS=2592000      # 30 days before new users can invite
export SYBIL_INVITE_PERSISTENCE_PATH=invitations.json
export SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS=300      # Auto-save every 5 minutes

# Bootstrap users (format: username:invite_count,...)
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:100,alice:50
```

#### How It Works

**1. Generate an invitation** (existing user):

```rust
use freebird::InvitationSystem;

let (code, signature, expires_at) = invitation_system
    .generate_invite("admin")
    .await?;

// Returns:
// code:       "Abc123XyZ456..."  (random 16 bytes, base64url)
// signature:  "MEUCIQDx..."      (ECDSA P-256 signature, hex-encoded)
// expires_at: 1734567890         (Unix timestamp)
```

**2. Share invitation** out-of-band:
- Email, Signal, in-person, etc.
- Provide both `code` and `signature` to invitee

**3. Invitee redeems invitation** when requesting a token:

```bash
POST /v1/oprf/issue
{
  "blinded_element_b64": "...",
  "sybil_proof": {
    "type": "invitation",
    "code": "Abc123XyZ456...",
    "signature": "3045022100..."
  }
}
```

**4. Issuer verifies and redeems**:
- ✓ Signature is cryptographically valid
- ✓ Invitation exists in persistent storage
- ✓ Not expired (within 30 days by default)
- ✓ Not already redeemed (single-use enforcement)
- ✓ Inviter is not banned

**5. On successful redemption**:
- Generate unique invitee ID (see security details below)
- Mark invitation as redeemed
- Create new user record (0 invites initially)
- Issue anonymous token
- Persist state to disk

**6. Growth**:
- After waiting period (default: 30 days), new user earns invites
- Can then invite others, growing the network organically

#### Invitee ID Security

The system generates cryptographically strong invitee IDs by hashing:

1. **Invitation code** (ensures uniqueness per code)
2. **Redemption timestamp** (prevents pre-computation attacks)
3. **Client IP address** (hashed, adds entropy)
4. **Client fingerprint** (User-Agent hash, prevents linkability)
5. **Cryptographic random nonce** (16 bytes, guarantees uniqueness)

This provides **~192 bits of entropy** and prevents:
- ❌ ID collisions (random nonce ensures uniqueness)
- ❌ Pre-computation attacks (timestamp binding)
- ❌ Linkability across sessions (each redemption is unique)
- ❌ Prediction (multiple entropy sources)

Example ID generation:
```rust
SHA-256(
    "freebird:invitee:v2:" ||
    invitation_code ||
    timestamp ||
    client_ip_hash ||
    user_agent_hash ||
    random_nonce_16_bytes
)[0..24] // First 192 bits, base64url-encoded
```

#### Properties

- **Single-use enforcement**: Each invitation can only be redeemed once
- **Social accountability**: Inviters stake reputation on invitees (ban trees)
- **Privacy preserved**: Verifier never sees invitation history
- **No biometrics**: Trust-based without surveillance infrastructure
- **Survives restarts**: Full state persistence with automatic backups
- **Ban tree propagation**: Banning a user can recursively ban their invitees

#### Administrative Operations

```rust
// Grant additional invites (reputation rewards)
invitation_system.grant_invites("user123", 10).await?;

// Ban a user and their invite tree
invitation_system.ban_user("malicious_user", ban_tree = true).await;

// Get system statistics
let stats = invitation_system.get_stats().await;
println!("Total users: {}", stats.total_users);
println!("Banned users: {}", stats.banned_users);
```

### 2. Proof-of-Work

**Status**: ✅ Implemented and tested

Requires clients to compute a hash with N leading zero bits, making token acquisition computationally expensive.

```bash
export SYBIL_RESISTANCE=proof_of_work
export SYBIL_POW_DIFFICULTY=20  # ~1M hashes (~1 second on modern CPU)
```

**Difficulty Guide:**
- 16 bits: ~65k hashes (instant)
- 20 bits: ~1M hashes (~1 second)
- 24 bits: ~16M hashes (~10-30 seconds)
- 28 bits: ~268M hashes (~5-10 minutes)

**Properties:**
- ✓ No identity required
- ✓ Scalable cost (adjust difficulty)
- ✗ Favors wealthy (better hardware)
- ✗ Energy wasteful
- ✗ Not true Sybil resistance (just expensive)

### 3. Rate Limiting

**Status**: ✅ Implemented with IP/fingerprint tracking

Limits token issuance by client identifier (IP hash, fingerprint).

```bash
export SYBIL_RESISTANCE=rate_limit
export SYBIL_RATE_LIMIT_SECS=3600  # One token per hour per client
```

**Properties:**
- ✓ Simple to implement
- ✓ No computation required
- ✗ Bypassable (VPNs, Tor, residential proxies)
- ✗ Can block legitimate users (shared IPs, NAT)
- ✗ Requires state storage

### 4. Combined Resistance (Defense in Depth)

**Status**: ✅ Implemented with multi-mechanism support

Combine multiple mechanisms for stronger protection:

```bash
export SYBIL_RESISTANCE=combined
export SYBIL_POW_DIFFICULTY=20
export SYBIL_RATE_LIMIT_SECS=3600
```

**Note**: Current implementation requires a proof that satisfies at least one configured mechanism. For true defense-in-depth requiring multiple proof types simultaneously, extend the `SybilProof` enum to support composite proofs.

### 5. No Sybil Resistance (Permissive Mode)

**Status**: ✅ Default mode

```bash
export SYBIL_RESISTANCE=none
# Or omit SYBIL_RESISTANCE entirely
```

Tokens are issued freely without any Sybil checks. Use for:
- Testing and development
- Low-stakes applications
- When Sybil resistance is handled elsewhere

### Unified Endpoint Behavior

The `/v1/oprf/issue` endpoint adapts automatically based on configuration and request:

| Sybil Config | Proof Provided | Result |
|--------------|----------------|--------|
| None         | None           | ✅ Issue (backward compatible) |
| None         | Some           | ⚠️ Issue + warn (proof ignored) |
| Some         | None           | ❌ Reject (proof required) |
| Some         | Valid          | ✅ Issue (after verification) |
| Some         | Invalid        | ❌ Reject (failed verification) |

This design provides:
- **Backward compatibility** (works without proofs when Sybil resistance is disabled)
- **Forward compatibility** (supports new proof types via the `SybilProof` enum)
- **Clear semantics** (behavior is predictable and well-documented)

## Configuration

### Environment Variables

**Issuer:**
```bash
# Core settings
ISSUER_ID=issuer:myservice:v1   # Unique issuer identifier
BIND_ADDR=0.0.0.0:8081          # Listen address
TOKEN_TTL_MIN=60                # Token expiration (minutes, default: 10)
REQUIRE_TLS=false               # Enforce HTTPS (production: true)
BEHIND_PROXY=false              # Trust X-Forwarded-* headers

# Key management
ISSUER_SK_PATH=issuer_sk.bin    # Path to secret key file
KID=custom-key-id-2024-11-08    # Optional: override key ID

# Sybil resistance (choose one or combine)
SYBIL_RESISTANCE=none           # Options: none, invitation, proof_of_work, rate_limit, combined

# Invitation system (if SYBIL_RESISTANCE=invitation)
SYBIL_INVITE_PER_USER=5
SYBIL_INVITE_COOLDOWN_SECS=3600
SYBIL_INVITE_EXPIRES_SECS=2592000
SYBIL_INVITE_NEW_USER_WAIT_SECS=2592000
SYBIL_INVITE_PERSISTENCE_PATH=invitations.json
SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS=300
SYBIL_INVITE_BOOTSTRAP_USERS=admin:100,alice:50

# Proof-of-work (if SYBIL_RESISTANCE=proof_of_work or combined)
SYBIL_POW_DIFFICULTY=20

# Rate limiting (if SYBIL_RESISTANCE=rate_limit or combined)
SYBIL_RATE_LIMIT_SECS=3600
```

**Verifier:**
```bash
# Core settings
BIND_ADDR=0.0.0.0:8082                              # Listen address
ISSUER_URL=http://issuer:8081/.well-known/issuer   # Issuer metadata URL
REFRESH_INTERVAL_MIN=10                             # Metadata refresh interval (minutes)

# Storage backend
REDIS_URL=redis://localhost:6379                    # Optional: Redis for production

# Expiration validation
MAX_CLOCK_SKEW_SECS=300                             # Clock skew tolerance (default: 5 minutes)
```

### Key Management

**Automatic Generation:**

Keys are automatically generated on first run and stored in:
```
issuer_sk.bin    # KEEP SECRET! 32-byte P-256 scalar
```

The file is created with restrictive permissions (0o600 on Unix) and uses atomic writes to prevent corruption.

**Key Formats Supported:**
- Raw 32-byte scalar (default, used for new keys)
- PKCS#8 DER format (for imported keys)

**Production Recommendations:**

1. **Use environment variables for key injection:**
   ```bash
   ISSUER_SK_PATH=/secure/path/to/key.bin
   ```

2. **Store keys in secure key management systems:**
   - HashiCorp Vault
   - AWS KMS
   - Google Cloud KMS
   - Azure Key Vault

3. **Key rotation strategy:**
   - Rotate keys periodically (e.g., quarterly)
   - Publish new `kid` (key ID) in metadata
   - Support multiple active keys simultaneously (roadmap item)

4. **Security checklist:**
   - ✓ Never commit keys to version control
   - ✓ Restrict file permissions (0o600)
   - ✓ Use separate keys per environment (dev/staging/prod)
   - ✓ Monitor key access logs
   - ✓ Have a key revocation plan

## API Reference

### Issuer API

#### `GET /.well-known/issuer`

Returns issuer metadata for verifier configuration.

**Response:**
```json
{
  "issuer_id": "issuer:freebird:v1",
  "voprf": {
    "suite": "OPRF(P-256, SHA-256)-verifiable",
    "kid": "2b8d5f3a-2024-11-08",
    "pubkey": "A3x5Y2z...",
    "exp_sec": 600
  }
}
```

**Fields:**
- `issuer_id`: Unique identifier for this issuer
- `suite`: Cryptographic suite identifier
- `kid`: Key ID for signature verification
- `pubkey`: Base64url-encoded SEC1 compressed public key (33 bytes)
- `exp_sec`: Default token expiration time in seconds

#### `POST /v1/oprf/issue`

Issues an anonymous token via VOPRF evaluation. Adapts automatically based on Sybil resistance configuration.

**Request (without Sybil resistance):**
```json
{
  "blinded_element_b64": "A1b2c3d..."
}
```

**Request (with Sybil proof):**
```json
{
  "blinded_element_b64": "A1b2c3d...",
  "sybil_proof": {
    "type": "invitation",
    "code": "Abc123XyZ456...",
    "signature": "3045022100..."
  }
}
```

**Supported Sybil Proof Types:**
```typescript
// Invitation-based
{
  "type": "invitation",
  "code": string,      // Base64url invitation code
  "signature": string  // Hex-encoded ECDSA signature
}

// Proof-of-work
{
  "type": "proof_of_work",
  "nonce": number,     // Nonce that produces valid hash
  "input": string,     // Client input
  "timestamp": number  // Unix timestamp
}

// Rate limiting
{
  "type": "rate_limit",
  "client_id": string, // Hashed client identifier
  "timestamp": number  // Unix timestamp
}
```

**Response:**
```json
{
  "token": "Q9w8x7y...",
  "proof": "",
  "kid": "2b8d5f3a-2024-11-08",
  "exp": 1699454445,
  "sybil_info": {
    "required": true,
    "passed": true,
    "cost": 3600
  }
}
```

**Fields:**
- `token`: Base64url-encoded evaluation token (130 bytes)
- `proof`: Reserved for future DLEQ proof inclusion
- `kid`: Key ID used for signing
- `exp`: Expiration timestamp (Unix seconds)
- `sybil_info`: Optional Sybil verification details
  - `required`: Was Sybil resistance required?
  - `passed`: Did the proof pass verification?
  - `cost`: Computational or time cost of the proof

**Error Responses:**
```
400 Bad Request
- "Sybil resistance proof required" (if configured but not provided)
- "invalid base64 encoding" (malformed blinded_element_b64)
- "blinded_element must be 33 bytes" (wrong point size)

403 Forbidden
- "Sybil resistance verification failed" (invalid proof)

500 Internal Server Error
- "VOPRF evaluation failed" (cryptographic error)
```

### Verifier API

#### `POST /v1/verify`

Verifies a token, checks expiration, and enforces replay protection.

**Request:**
```json
{
  "token_b64": "Q9w8x7y...",
  "issuer_id": "issuer:freebird:v1",
  "exp": 1699454445
}
```

**Fields:**
- `token_b64`: Base64url-encoded token from issuer (130 bytes)
- `issuer_id`: Issuer identifier (must match loaded metadata)
- `exp`: Token expiration timestamp (Unix seconds)

**Response (Success):**
```json
{
  "ok": true,
  "verified_at": 1699454445
}
```

**Response (Failure):**
```
401 Unauthorized
{
  "ok": false,
  "error": "verification failed"
}
```

**Failure Reasons:**
- Token expired (beyond `exp` + clock skew tolerance)
- Token already used (nullifier replay detected)
- Invalid cryptographic signature (DLEQ proof verification failed)
- Unknown issuer (no metadata loaded)
- Expiration too far in future (potential forgery)

**Expiration Checking:**

The verifier performs time-bound validation:

1. **Check if expired:**
   ```
   current_time > exp + MAX_CLOCK_SKEW_SECS
   ```

2. **Check if suspiciously future:**
   ```
   exp > current_time + issuer_default_ttl + MAX_CLOCK_SKEW_SECS
   ```

3. **Clock skew tolerance:**
   - Default: 5 minutes (300 seconds)
   - Configurable via `MAX_CLOCK_SKEW_SECS`
   - Prevents false rejections due to time synchronization issues

**Nullifier Tracking:**

After successful cryptographic verification and expiration check:

1. Derive nullifier: `SHA-256(issuer_id || token_output)`
2. Check if nullifier exists in storage
3. If first use: store nullifier with TTL = token expiration
4. If replay: reject with 401 Unauthorized

## Security Model

### What Freebird Guarantees

✅ **Unlinkability**: Issuer cannot link token issuance to redemption  
✅ **Anonymity**: Verifier cannot identify the token holder  
✅ **Replay Protection**: Each token can only be verified once  
✅ **Unforgeability**: Tokens cannot be created without the issuer's secret key  
✅ **Verifiability**: DLEQ proofs ensure issuer computed correctly  
✅ **Time-Bound Validity**: Tokens expire automatically with clock skew tolerance  

### What Freebird Provides (with Sybil Resistance)

✅ **Invitation System**: One token per human via trust networks (no biometrics)  
✅ **Strong Invitee IDs**: 192 bits of entropy prevents collisions and attacks  
✅ **Social Accountability**: Ban trees enable self-policing communities  
✅ **Persistent State**: Full state survival across restarts  
✅ **Proof-of-Work**: Computational cost limits token acquisition rate  
✅ **Rate Limiting**: IP/fingerprint-based throttling (weak but simple)  

### What Freebird Does NOT Guarantee

❌ **Front-running**: Tokens can be stolen and used by others before the legitimate holder  
❌ **Network Anonymity**: Use Tor or VPNs if you need network-level privacy  
❌ **Quantum Resistance**: P-256 ECDLP is vulnerable to quantum computers  
❌ **Perfect Sybil Resistance**: All mechanisms have trade-offs (see comparison above)  

### Threat Model

**Trusted:**
- Issuer keeps secret key secure
- Verifier doesn't collude with issuer
- System clocks are reasonably synchronized (within clock skew tolerance)

**Adversary Can:**
- Observe all network traffic (assuming no TLS, which should be used in production)
- Request tokens (if they have valid invitations or satisfy Sybil proofs)
- Attempt replays (will be detected and blocked)
- Try to forge tokens (will fail cryptographic verification)
- Attempt clock manipulation (limited by clock skew tolerance)

**Adversary Cannot:**
- Link tokens to identities (unlinkability via blinding)
- Reuse tokens (replay protection via nullifiers)
- Forge valid tokens (requires issuer secret key)
- Bypass invitation system without valid invitation
- Predict invitee IDs (192 bits of entropy with random nonces)
- Fool DLEQ verification (cryptographic soundness)
- Use expired tokens (expiration validation)

### Production Security Checklist

#### 1. **Use HTTPS/TLS for all communications**
```bash
REQUIRE_TLS=true
```
- Prevents token theft via man-in-the-middle attacks
- Protects invitation codes and signatures during transmission
- Essential for production deployments

#### 2. **Deploy issuer and verifier on separate infrastructure**
- Different cloud accounts or VPCs
- Different administrative access controls
- Different logging and monitoring systems
- Prevents collusion attacks where verifier learns issuance patterns

#### 3. **Configure appropriate rate limiting**
- Add reverse proxy rate limiting (nginx, Caddy, Cloudflare)
- Prevent token stockpiling attacks
- Protect against DoS on issuance endpoint

#### 4. **Use Redis for verifier storage (production)**
```bash
REDIS_URL=redis://localhost:6379
```
- Persistent storage survives restarts
- Better performance at scale
- Supports distributed verifier deployments

#### 5. **Monitor nullifier database size**
```bash
# Set appropriate token TTL
TOKEN_TTL_MIN=60  # Tokens expire after 1 hour

# Nullifiers are automatically cleaned up after TTL
# Monitor Redis memory usage
```

#### 6. **Implement key rotation strategy**
- Rotate issuer keys quarterly
- Publish new `kid` in metadata before rotation
- Support overlapping key validity periods (roadmap item)
- Have emergency revocation procedures

#### 7. **Configure Sybil resistance appropriately**

For high-value applications:
```bash
SYBIL_RESISTANCE=invitation
SYBIL_INVITE_PER_USER=3
SYBIL_INVITE_COOLDOWN_SECS=86400  # 24 hours
```

For moderate protection:
```bash
SYBIL_RESISTANCE=combined
SYBIL_POW_DIFFICULTY=24  # ~10-30 seconds
SYBIL_RATE_LIMIT_SECS=3600
```

#### 8. **Clock synchronization**
```bash
# Ensure NTP is configured
MAX_CLOCK_SKEW_SECS=300  # 5 minutes tolerance

# Monitor clock drift
# Alert if clocks diverge beyond tolerance
```

#### 9. **Logging and monitoring**
```bash
# Enable structured logging
LOG_FORMAT=json
RUST_LOG=info,axum=info,tower_http=info

# Monitor key metrics:
# - Token issuance rate
# - Replay attempt rate
# - Expired token rejection rate
# - Sybil proof verification failures
# - Nullifier storage size
```

#### 10. **Backup and disaster recovery**
```bash
# Backup invitation system state
SYBIL_INVITE_PERSISTENCE_PATH=/data/invitations.json
SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS=300

# Regular backups of:
# - Issuer secret keys
# - Invitation system state
# - Redis nullifier database (if using persistence)
```

## Testing

Freebird includes comprehensive testing at multiple levels:

### Unit Tests

```bash
# Run all unit tests
cargo test

# Run tests for specific component
cargo test --package crypto
cargo test --package issuer
cargo test --package verifier

# Run with logging output
RUST_LOG=debug cargo test -- --nocapture
```

### Integration Tests

```bash
# Run end-to-end integration tests
cargo test --package integration_tests

# Specific test suites
cargo test --package integration_tests smoke_voprf_roundtrip
cargo test --package integration_tests e2e_issue_verify
```

### CLI Test Modes

The `interface` binary provides interactive testing:

```bash
# Normal flow (issue and verify)
./target/release/interface

# Test replay protection
./target/release/interface --replay

# Test expiration validation
./target/release/interface --expired

# Save token for later testing
./target/release/interface --save

# Load and attempt to reuse saved token
./target/release/interface --load

# Stress test (batch operations)
./target/release/interface --stress 100
```

**Example: Replay Attack Test**

```bash
$ ./target/release/interface --replay

🔁 REPLAY ATTACK TEST MODE

📥 Step 1: Issuing fresh token...
✅ Token issued: exp=1699454445

✅ Step 2: First verification attempt...
✅ First verification: SUCCESS

⏱️  Waiting 2 seconds...

🔁 Step 3: Replay attack - reusing the same token...
✅ REPLAY PROTECTION WORKING! Token was rejected on second use.
   This proves the nullifier system prevents double-spending.
```

**Example: Expiration Test**

```bash
$ ./target/release/interface --expired

⏰ EXPIRED TOKEN TEST MODE

📥 Step 1: Issuing token...
✅ Token issued with exp=1699454445

⏰ Step 2: Attempting verification with expired timestamp...
   Fake exp: 1699453845 (600s ago)
✅ EXPIRATION VALIDATION WORKING! Expired token was rejected.
   This prevents using tokens beyond their validity period.
```

### Performance Testing

```bash
# Stress test with timing
time ./target/release/interface --stress 1000

# Typical results (local, no network overhead):
# - Issuance: ~5-10ms per token
# - Verification: ~2-5ms per token
# - Total throughput: ~100-200 tokens/second single-threaded
```

## Project Structure

```
freebird/
├── crypto/              # VOPRF cryptographic primitives
│   └── src/
│       ├── lib.rs       # High-level API (Client, Server, Verifier)
│       └── vendor/      # P-256 VOPRF implementation
│           └── voprf_p256/
│               ├── dleq.rs    # DLEQ proof generation and verification
│               ├── mod.rs     # Module exports
│               └── oprf.rs    # Core VOPRF protocol implementation
│
├── issuer/              # Token issuing service
│   ├── Cargo.toml       # Dependencies and features
│   └── src/
│       ├── main.rs      # HTTP server and configuration
│       ├── keys.rs      # Key management (generation, loading, persistence)
│       ├── voprf_core.rs # VOPRF evaluation with panic protection
│       ├── routes/      # API endpoints
│       │   ├── mod.rs
│       │   ├── issue.rs      # Unified issuance handler (adaptive)
│       │   └── register.rs   # WebAuthn registration (optional feature)
│       └── sybil_resistance/  # Sybil resistance mechanisms
│           ├── mod.rs         # Trait definition and shared utilities
│           ├── invitation.rs  # Trust-based invitation system
│           ├── proof_of_work.rs # Computational cost proof
│           └── rate_limit.rs  # IP/fingerprint-based limiting
│
├── verifier/            # Token verification service
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs      # HTTP server with expiration checking
│       └── store.rs     # Replay protection storage (in-memory/Redis)
│
├── interface/           # CLI testing tool
│   ├── Cargo.toml
│   └── src/
│       └── main.rs      # Interactive test modes
│
├── common/              # Shared utilities
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs       # Logging configuration
│
├── integration_tests/   # End-to-end tests
│   ├── Cargo.toml
│   └── tests/
│       ├── smoke_voprf_roundtrip.rs  # Basic VOPRF protocol test
│       └── e2e_issue_verify.rs       # Full system integration test
│
├── Cargo.toml           # Workspace configuration
├── README.md            # This file
└── NOTICE               # Apache 2.0 license notice
```

### Key Design Decisions

**Workspace Structure:**
- Monorepo with separate crates for clear separation of concerns
- Shared `crypto` crate prevents duplication
- `common` crate for cross-cutting concerns (logging, utilities)

**Crypto Implementation:**
- Vendored P-256 VOPRF in `crypto/src/vendor/voprf_p256/`
- Custom implementation for full control and auditability
- Based on RustCrypto `p256` and `elliptic-curve` crates
- RFC 9380-compliant hash-to-curve (SSWU_RO)

**Sybil Resistance Architecture:**
- `SybilResistance` trait for pluggable mechanisms
- `SybilProof` enum for extensibility
- Each mechanism in separate module for clarity
- Combined resistance via `CombinedSybilResistance` wrapper

**Storage Strategy:**
- Trait-based storage abstraction (`SpendStore`)
- In-memory for development (`InMemoryStore`)
- Redis for production (`RedisStore`)
- Automatic cleanup based on token TTL

## Comparison to Privacy Pass

Freebird is inspired by Cloudflare's [Privacy Pass](https://privacypass.github.io/) but differs in key ways:

| Feature | Privacy Pass | Freebird |
|---------|-------------|----------|
| **Deployment** | Centralized (Cloudflare) | Self-hostable |
| **Protocol** | VOPRF (Draft RFC) | VOPRF (P-256, SHA-256) |
| **Source Code** | Partially open | Fully open source |
| **Backend** | Closed infrastructure | Your infrastructure |
| **Use Case** | Bot detection (CAPTCHA bypass) | General purpose anonymous auth |
| **Issuance Control** | Cloudflare determines policy | You control everything |
| **Sybil Resistance** | CAPTCHA-based | Multiple options (invitation, PoW, rate limit) |
| **Storage** | Cloudflare manages | In-memory or Redis (your choice) |
| **Customization** | Limited client integration | Full API control |

**When to use Freebird over Privacy Pass:**
- Need self-hosted solution (data sovereignty)
- Want custom Sybil resistance (invitation system, PoW, etc.)
- Building privacy-preserving application beyond bot detection
- Require audit trail of cryptographic implementation
- Want to integrate with existing authentication systems

**When Privacy Pass might be better:**
- Just need CAPTCHA bypass for web scraping
- Don't want to manage infrastructure
- Already integrated with Cloudflare
- Need massive scale (Cloudflare's CDN)

Freebird gives you **complete control** over:
- Token issuance policy
- Sybil resistance mechanisms
- Key management
- Storage backend
- Network deployment
- Privacy guarantees

## Roadmap

**Completed:**
- ✅ Core VOPRF protocol (P-256, SHA-256)
- ✅ DLEQ proof generation and verification
- ✅ Nullifier-based replay protection
- ✅ Token expiration validation
- ✅ Invitation system with persistence
- ✅ Proof-of-work Sybil resistance
- ✅ Rate limiting Sybil resistance
- ✅ Combined Sybil resistance mechanisms
- ✅ Redis backend for nullifier storage
- ✅ Comprehensive test suite
- ✅ CLI testing tool with multiple modes

**In Progress:**
- 🚧 WebAuthn integration (partially implemented, optional feature)
- 🚧 Admin API for invitation system management

**Planned:**
- [ ] Batch issuance (multiple tokens in one request)
- [ ] Key rotation support (multiple active keys with graceful transition)
- [ ] Client libraries (JavaScript, Python, Go, Rust SDK)
- [ ] Token format versioning (backward compatibility support)
- [ ] Metrics and monitoring endpoints (Prometheus format)
- [ ] Docker images and Kubernetes manifests
- [ ] mTLS support for issuer-verifier communication
- [ ] Hardware security module (HSM) integration for key storage
- [ ] Rate limiting improvements (distributed rate limiting with Redis)
- [ ] Invitation system enhancements (reputation algorithms, tree visualization)

**Research:**
- [ ] Post-quantum cryptography exploration (VOPRF on post-quantum curves)
- [ ] Zero-knowledge proof integration (private set membership)
- [ ] Threshold VOPRF (distributed issuer trust)
- [ ] Blind signature schemes (alternative to VOPRF)

**Community Requests:**
- [ ] GraphQL API option
- [ ] WebSocket support for real-time token streaming
- [ ] Mobile SDK (iOS, Android)
- [ ] Browser extension for seamless integration

Want to contribute? See our [GitHub repository] for open issues and contribution guidelines.

## Relevant Papers & References

### Core Cryptography

**VOPRF Protocol:**
- [VOPRF Draft RFC](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/) - Verifiable Oblivious Pseudorandom Functions
- [Privacy Pass Protocol (IETF Draft)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-privacypass/) - Application of VOPRF to anonymous credentials

**Elliptic Curve Cryptography:**
- [RFC 9380: Hashing to Elliptic Curves](https://datatracker.ietf.org/doc/rfc9380/) - Hash-to-curve construction used by Freebird
- [SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf) - Point encoding and signature schemes

### Nullifier Construction

**Zcash Research:**
- [Zcash Protocol Specification](https://github.com/zcash/zips) - Nullifier construction in Sapling and Orchard
- Zerocoin Paper (2013) - Miers et al., "Zerocoin: Anonymous Distributed E-Cash from Bitcoin" - Original academic work on nullifiers

### Related Systems

**Anonymous Credentials:**
- Chaum, D. (1983) - "Blind signatures for untraceable payments" - Foundational work on anonymous credentials
- Camenisch, J., & Lysyanskaya, A. (2001) - "An efficient system for non-transferable anonymous credentials" - Modern credential systems

**Privacy-Preserving Authentication:**
- BLS Signatures - Boneh, Lynn, Shacham (2001) - Short signatures from bilinear pairings
- Coconut - Sonnino et al. (2019) - Distributed credential issuance

### Sybil Resistance

**Social Trust:**
- SybilGuard - Yu et al. (2006) - Social network-based Sybil defense
- SybilLimit - Yu et al. (2008) - Near-optimal social network defense

**Proof Systems:**
- Proof of Work - Dwork & Naor (1992) - Original pricing function concept
- Hashcash - Back (2002) - Email spam prevention via PoW

### Implementation References

**RustCrypto:**
- [p256 crate](https://crates.io/crates/p256) - NIST P-256 elliptic curve
- [elliptic-curve crate](https://crates.io/crates/elliptic-curve) - Generic elliptic curve traits

**Cryptographic Standards:**
- FIPS 186-5 - Digital Signature Standard (DSS) - ECDSA specification
- NIST SP 800-186 - Discrete Logarithm-Based Cryptography - P-256 curve parameters

## License

**Apache License 2.0**

Copyright 2025 The Carpocratian Church of Commonality and Equality

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See [NOTICE](NOTICE) for full license text.

## Support & Community

### Documentation
- **This README**: Comprehensive guide to installation, configuration, and usage
- **Inline Code Comments**: Detailed explanations throughout the codebase
- **Protocol Reference**: [VOPRF RFC Draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/)

### Getting Help
- **GitHub Issues**: [Report bugs and request features](https://github.com/yourusername/freebird/issues)
- **GitHub Discussions**: Ask questions and share use cases
- **Security Issues**: Report vulnerabilities privately via GitHub Security Advisories

### Contributing
We welcome contributions! Areas of interest:
- Client libraries (JavaScript, Python, Go)
- Docker/Kubernetes deployments
- Performance optimizations
- Documentation improvements
- Test coverage expansion
- New Sybil resistance mechanisms

See `CONTRIBUTING.md` for guidelines (coming soon).

### Acknowledgments
- Inspired by [Privacy Pass](https://privacypass.github.io/)
- Built on [RustCrypto](https://github.com/RustCrypto) elliptic curve implementations
- VOPRF protocol based on [IETF CFRG draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/)

---

**Built with ❤️ for privacy**

*Freebird: Prove you're authorized without revealing who you are.*