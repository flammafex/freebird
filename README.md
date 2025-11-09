[<div align=center><img src="freebird.webp">](https://carpocratian.org/en/church/)
[<div align=center><br><img src="church.png" width=72 height=72>](https://carpocratian.org/en/church/)

_A mission of [The Carpocratian Church of Commonality and Equality](https://carpocratian.org/en/church/)_.</div>
<div align=center><img src="mission.png" width=256 height=200></div></div>

# What is 🕊️ Freebird?
**Anonymous credential system using VOPRF cryptography**

Freebird is a self-hostable anonymous token system that allows users to prove authorization without revealing their identity or linking multiple uses. Think of it as anonymous digital cash for the internet—users get cryptographic tokens that prove "I'm authorized" without revealing "who I am."

Built with production-ready Rust, Freebird provides cryptographic unlinkability and replay protection through VOPRF (Verifiable Oblivious Pseudorandom Function) with DLEQ proofs on the P-256 elliptic curve.

## Why is 🕊️ Freebird?

**The Problem:** Traditional authentication links every action to an identity. Rate limiting requires tracking users. Privacy and access control are at odds.

**The Solution:** Freebird issues anonymous tokens that prove authorization without surveillance. The issuer can't track where tokens are used. The verifier can't link uses to identities. Yet double-spending is prevented.

**Use Cases:**
- Anonymous rate limiting (verify "human-ness" without tracking users)
- Privacy-preserving access control (prove membership without revealing identity)
- Unlinkable proof-of-work systems
- Anonymous voting or polling
- Private content access (paywalls, subscriptions)
- Bot prevention without surveillance

## Key Features

- **Cryptographic Unlinkability** – Issuer can't track where tokens are used
- **Self-Hostable** – No central authority required
- **Replay Protection** – Nullifier-based double-spend prevention
- **Production Ready** – ~2,400 lines of robust Rust with comprehensive tests
- **Standards-Based** – P-256 VOPRF with DLEQ proofs
- **Flexible Storage** – In-memory or Redis backend for spent token tracking

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
     │                           │                           │
     │                           │  4. Evaluate VOPRF        │
     │                           │     (sign with key)       │
     │                           │                           │
     │                           │  5. Create DLEQ proof     │
     │                           │     (prove correctness)   │
     │                           │                           │
     │  6. Return signed ◀───────┤                           │
     │                           │                           │
     │  7. Unblind & verify      │                           │
     │     (remove random,       │                           │
     │      check DLEQ proof)    │                           │
     │                           │                           │
     │  8. Send token ───────────┼──────────────────────────▶
     │                           │                           │
     │                           │                           │  9. Verify token
     │                           │                           │     (check signature)
     │                           │                           │
     │                           │                           │ 10. Check nullifier
     │                           │                           │     (prevent replay)
     │                           │                           │
     │  11. Success ◀────────────┼───────────────────────────┤
     │                           │                           │
```

**Why This Matters:**

- The issuer **never sees your original input** (blinding protects it)
- The issuer **can't link issuance to redemption** (different blinding each time)
- The verifier **can't tell which issuer session** produced a token
- Tokens **can't be reused** (nullifiers prevent double-spending)

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

## Architecture

Freebird consists of three components:

### 1. Issuer Service (`issuer/`)

Issues anonymous tokens via VOPRF evaluation.

- **Tech**: Axum/Rust web service
- **Port**: 8081 (configurable)
- **Key Endpoint**: `POST /v1/oprf/issue`
- **Metadata**: `GET /.well-known/issuer` (returns public key, key ID, expiration)

### 2. Verifier Service (`verifier/`)

Verifies tokens with replay protection.

- **Tech**: Axum/Rust web service
- **Port**: 8082 (configurable)
- **Key Endpoint**: `POST /v1/verify`
- **Storage**: In-memory HashMap or Redis
- **Refresh**: Auto-fetches issuer metadata on interval

### 3. CLI Client (`interface/`)

Command-line tool for testing and demonstrations.

**Modes:**
- Normal flow (issue + verify)
- Replay attack testing
- Token persistence (save/load)
- Stress testing

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

### Running Locally

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

✅ Step 2: Verifying token at http://127.0.0.1:8082
   ├─ Token cryptographically verified
   ├─ Nullifier checked (first use)
   └─ Verified at: 2024-11-08T15:30:45Z

✅ SUCCESS! Token verified
```

## Configuration

### Environment Variables

**Issuer:**
```bash
ISSUER_ID=issuer:myservice:v1   # Unique issuer identifier
BIND_ADDR=0.0.0.0:8081          # Listen address
TOKEN_TTL_MIN=60                # Token expiration (minutes, default: 10)
REQUIRE_TLS=false               # Enforce HTTPS (production: true)
BEHIND_PROXY=false              # Trust X-Forwarded-* headers
```

**Verifier:**
```bash
BIND_ADDR=0.0.0.0:8082                              # Listen address
ISSUER_URL=http://issuer:8081/.well-known/issuer   # Issuer metadata URL
REDIS_URL=redis://localhost:6379                   # Optional Redis backend
REFRESH_INTERVAL_MIN=10                            # Metadata refresh interval
```

### Key Management

Keys are automatically generated on first run and stored in:
```
issuer-secret.key    # KEEP SECRET! 32-byte P-256 scalar
```

**Production recommendations:**
- Use environment variables for key injection
- Store keys in secure key management systems (HashiCorp Vault, AWS KMS, etc.)
- Rotate keys periodically and publish new `kid` (key ID)
- Never commit keys to version control

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

#### `POST /v1/oprf/issue`

Issues an anonymous token via VOPRF evaluation.

**Request:**
```json
{
  "blinded_element_b64": "A1b2c3d..."
}
```

**Response:**
```json
{
  "token": "Q9w8x7y...",
  "proof": "",
  "kid": "2b8d5f3a-2024-11-08",
  "exp": 1699454445
}
```

### Verifier API

#### `POST /v1/verify`

Verifies a token and checks for replay.

**Request:**
```json
{
  "token_b64": "Q9w8x7y...",
  "issuer_id": "issuer:freebird:v1"
}
```

**Response (Success):**
```json
{
  "ok": true,
  "verified_at": 1699454445
}
```

**Response (Failure):**
```
HTTP 401 Unauthorized
{"ok": false, "error": "verification failed"}
```

## Security Model

### What Freebird Guarantees

✅ **Unlinkability**: Issuer cannot link token issuance to redemption  
✅ **Anonymity**: Verifier cannot identify the token holder  
✅ **Replay Protection**: Each token can only be verified once  
✅ **Unforgeability**: Tokens cannot be created without the issuer's secret key  
✅ **Verifiability**: DLEQ proofs ensure issuer computed correctly  

### What Freebird Does NOT Guarantee

❌ **Sybil Resistance**: Freebird doesn't prevent users from getting multiple tokens  
❌ **Front-running**: Tokens can be stolen and used by others before the legitimate holder  
❌ **Network Anonymity**: Use Tor or VPNs if you need network-level privacy  
❌ **Quantum Resistance**: P-256 ECDLP is vulnerable to quantum computers  

### Threat Model

**Trusted:**
- Issuer keeps secret key secure
- Verifier doesn't collude with issuer

**Adversary Can:**
- Observe all network traffic
- Request unlimited tokens
- Attempt replays
- Try to forge tokens

**Adversary Cannot:**
- Link tokens to identities (unlinkability)
- Reuse tokens (replay protection)
- Forge valid tokens (unforgeability)
- Fool DLEQ verification (soundness)

### Production Recommendations

1. **Use HTTPS/TLS for all communications**
   ```bash
   REQUIRE_TLS=true
   ```

2. **Deploy issuer and verifier on separate infrastructure**
   - Different cloud accounts
   - Different administrative access
   - Different logging systems

3. **Add rate limiting before the issuer**
   - Prevent token stockpiling
   - Use IP-based or challenge-based rate limits

4. **Use Redis for verifier storage (production)**
   ```bash
   REDIS_URL=redis://localhost:6379
   ```

5. **Monitor nullifier database size**
   - Expired tokens are cleaned up automatically
   - Set appropriate `TOKEN_TTL_MIN`

6. **Key rotation**
   - Rotate issuer keys periodically
   - Publish new `kid` in metadata
   - Support multiple active keys simultaneously

7. **Add authorization to issuance**
   - Integrate with your auth system
   - Only issue tokens to verified users
   - Consider proof-of-work or CAPTCHAs

## Integration Guide

### Step 1: Deploy Services

```bash
# Deploy issuer
docker run -e ISSUER_ID=myapp \
           -e TOKEN_TTL_MIN=60 \
           -p 8081:8081 \
           freebird-issuer

# Deploy verifier with Redis
docker run -e REDIS_URL=redis://redis:6379 \
           -e ISSUER_URL=http://issuer:8081/.well-known/issuer \
           -p 8082:8082 \
           freebird-verifier
```

### Step 2: Add to Your Application

**Python Client Example:**

```python
import requests
import secrets
from hashlib import sha256

# 1. Get issuer metadata
meta = requests.get("http://issuer:8081/.well-known/issuer").json()
issuer_id = meta["issuer_id"]

# 2. Request token (implement VOPRF blinding)
# See crypto/ module for reference implementation

# 3. Verify token before granting access
response = requests.post("http://verifier:8082/v1/verify", json={
    "token_b64": token,
    "issuer_id": issuer_id
})

if response.status_code == 200 and response.json()["ok"]:
    # Grant access
    print("✅ Token verified - user authorized")
else:
    # Deny access
    print("❌ Invalid or replayed token")
```

### Step 3: Add Authorization to Issuance

Freebird intentionally doesn't include authorization logic—you add it:

```rust
// Example: Require JWT before issuing tokens
async fn issue_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IssueReq>
) -> Result<Json<IssueResp>, StatusCode> {
    // 1. Verify JWT from Authorization header
    let jwt = extract_jwt(&headers)?;
    verify_jwt(&jwt)?;
    
    // 2. Check rate limit
    rate_limit(&jwt.sub)?;
    
    // 3. Issue token
    issue_token(state, req).await
}
```

## Performance

Benchmarks on Apple M1 Pro:

| Operation | Throughput | Latency (p50) | Latency (p99) |
|-----------|------------|---------------|---------------|
| Issue     | ~8,000/sec | 0.12 ms       | 0.35 ms       |
| Verify    | ~12,000/sec| 0.08 ms       | 0.20 ms       |

**Bottlenecks:**
- Issuer: ECDH scalar multiplication (P-256)
- Verifier: Redis/network RTT (if using Redis)

**Scaling:**
- Issuer: Horizontally scalable (stateless)
- Verifier: Shared Redis backend for replay protection

## Testing

```bash
# Run all tests
cargo test

# Run integration tests
cargo test --package integration_tests

# Run with logging
RUST_LOG=debug cargo test -- --nocapture

# Test replay protection
./target/release/interface --replay

# Stress test
./target/release/interface --stress 1000
```

## Project Structure

```
freebird/
├── crypto/              # VOPRF cryptographic primitives
│   └── src/
│       ├── lib.rs       # High-level API
│       └── vendor/      # P-256 VOPRF implementation
├── issuer/              # Token issuing service
│   └── src/
│       ├── main.rs      # HTTP server
│       ├── routes/      # API endpoints
│       └── voprf_core.rs
├── verifier/            # Token verification service
│   └── src/
│       ├── main.rs      # HTTP server
│       └── store.rs     # Replay protection storage
├── interface/           # CLI testing tool
│   └── src/main.rs
├── common/              # Shared utilities
├── integration_tests/   # End-to-end tests
└── Cargo.toml           # Workspace configuration
```

## Comparison to Privacy Pass

Freebird is inspired by Cloudflare's [Privacy Pass](https://privacypass.github.io/) but differs in key ways:

| Feature | Privacy Pass | Freebird |
|---------|-------------|----------|
| Deployment | Centralized (Cloudflare) | Self-hostable |
| Protocol | VOPRF (Draft) | VOPRF (P-256) |
| Backend | Closed source | Open source |
| Use case | Bot detection | General purpose |
| Issuance control | Cloudflare CAPTCHA | Your custom logic |

Freebird gives you complete control over token issuance and verification.

## Roadmap

- [ ] Batch issuance (multiple tokens in one request)
- [ ] Key rotation support (multiple active keys)
- [ ] Client libraries (JavaScript, Python, Go)
- [ ] Token format versioning
- [ ] Metrics and monitoring endpoints
- [ ] Docker images and Kubernetes manifests
- [ ] mTLS support for issuer-verifier communication
- [ ] Hardware security module (HSM) integration
- [ ] Post-quantum cryptography exploration

## Relevant Papers

[Zcash Protocol Specification (Sapling or later)](https://github.com/zcash/zips)
Shows nullifier construction

[Privacy Pass Protocol (IETF Draft)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/)
VOPRF specification

Zerocoin Paper (2013) Miers et al., "Zerocoin: Anonymous Distributed E-Cash from Bitcoin"
The original academic work on nullifiers

[VOPRF Draft RFC](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/)

## License

[Apache 2.0](LICENSE-APACHE).

## Acknowledgments

- Built on [RustCrypto](https://github.com/RustCrypto) primitives
- Inspired by [Privacy Pass](https://privacypass.github.io/)
- VOPRF protocol from [draft-irtf-cfrg-voprf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/)

## Support

- GitHub Issues: [Report bugs and request features](https://github.com/yourusername/freebird/issues)
- Documentation: This README and inline code comments
- Protocol: [VOPRF RFC Draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/)

---

**Built with ❤️ for privacy**

*Freebird: Prove you're authorized without revealing who you are.*