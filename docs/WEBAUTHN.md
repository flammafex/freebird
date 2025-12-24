# WebAuthn Integration for Freebird

## Overview

Freebird supports **WebAuthn/FIDO2** as a Sybil resistance mechanism. This provides "proof of humanity" through hardware-backed authentication without computational cost or energy consumption.

## Features

### Core Features
- **Hardware-Backed Security**: Credentials protected by TPM, Secure Enclave, or security keys
- **Phishing Resistant**: Origin-bound credentials prevent phishing attacks
- **Zero Computational Cost**: No proof-of-work needed, instant verification
- **User-Friendly**: Biometric unlock (Touch ID, Windows Hello, Face ID)
- **Redis-Backed Storage**: Production-ready persistent credential storage
- **Multi-Device Support**: Users can register multiple authenticators

### Advanced Features
- **Attestation Policy Enforcement**: Verify authenticator models via AAGUID allowlists
- **Discoverable Credentials**: True passwordless/usernameless authentication (resident keys)
- **Multi-Device Credential Management**: Track backup eligibility, sync status, device types
- **Credential Revocation**: Admin endpoints to list and revoke credentials
- **Audit Logging**: Comprehensive registration and authentication audit trail
- **Rate Limiting**: Per-IP protection against brute force and DoS attacks

---

## Architecture

```
┌─────────────┐
│   Browser   │
│  (WebAuthn  │
│     API)    │
└──────┬──────┘
       │ 1. Registration/Auth Flow
       ▼
┌─────────────────────────────────┐
│   Freebird Issuer (Rust)       │
│                                 │
│  ┌─────────────────────────┐  │
│  │ WebAuthn Routes         │  │
│  │ Standard:               │  │
│  │ - /register/start       │  │
│  │ - /register/finish      │  │
│  │ - /authenticate/start   │  │
│  │ - /authenticate/finish  │  │
│  │                         │  │
│  │ Discoverable:           │  │
│  │ - /register/resident/*  │  │
│  │ - /authenticate/        │  │
│  │     discoverable/*      │  │
│  │                         │  │
│  │ Admin:                  │  │
│  │ - /credentials/:user    │  │
│  │ - /admin/credentials    │  │
│  └─────────────────────────┘  │
│            │                    │
│            ▼                    │
│  ┌─────────────────────────┐  │
│  │ Attestation Policy      │  │
│  │ (AAGUID validation)     │  │
│  └─────────────────────────┘  │
│            │                    │
│            ▼                    │
│  ┌─────────────────────────┐  │
│  │ Redis Credential Store  │  │
│  │ (with device metadata)  │  │
│  └─────────────────────────┘  │
└─────────────────────────────────┘
```

---

## Configuration

### Core Environment Variables

```bash
# WebAuthn Configuration (Required)
export WEBAUTHN_RP_ID=localhost                    # Relying Party ID (domain)
export WEBAUTHN_RP_NAME="Freebird"                 # Display name
export WEBAUTHN_RP_ORIGIN=http://localhost:8081    # Origin URL

# WebAuthn Credential Storage
export WEBAUTHN_REDIS_URL=redis://localhost:6379   # Redis for credentials
export WEBAUTHN_CRED_TTL=1y                        # Credential TTL (optional)

# Sybil Resistance
export SYBIL_RESISTANCE=webauthn                   # Enable WebAuthn gate
export WEBAUTHN_MAX_PROOF_AGE=5m                   # Proof validity window

# Security: Proof Secret (RECOMMENDED for production)
export WEBAUTHN_PROOF_SECRET="your-random-secret-here"
```

### Attestation Policy Configuration

```bash
# Attestation Policy Level
# Options: none, indirect, direct, enterprise
export WEBAUTHN_ATTESTATION_POLICY=direct

# Enable attestation enforcement
export WEBAUTHN_REQUIRE_ATTESTATION=true

# AAGUID Allowlist (comma-separated)
# Only allow specific authenticators (e.g., YubiKeys, Apple Secure Enclave)
export WEBAUTHN_ALLOWED_AAGUIDS=fa2b99dc-9e39-4257-8f92-4a30d23c4118,c5ef55ff-ad9a-4b9f-b580-adebafe026d0

# Enable audit logging for compliance
export WEBAUTHN_AUDIT_LOGGING=true
```

### Credential Management Configuration

```bash
# Maximum credentials per user (prevent device farming)
export WEBAUTHN_MAX_CREDENTIALS_PER_USER=10

# Enable credential revocation endpoint
export WEBAUTHN_ALLOW_CREDENTIAL_REVOCATION=true

# Force resident key registration (discoverable credentials)
export WEBAUTHN_REQUIRE_RESIDENT_KEY=false
```

### Rate Limiting Configuration

```bash
# Maximum registration attempts per IP per window (default: 10)
export WEBAUTHN_MAX_REGISTRATION_ATTEMPTS=10

# Maximum authentication attempts per IP per window (default: 20)
export WEBAUTHN_MAX_AUTH_ATTEMPTS=20

# Rate limit window duration (default: 5m)
export WEBAUTHN_RATE_LIMIT_WINDOW=5m

# Block duration after exceeding limit (default: 15m)
export WEBAUTHN_BLOCK_DURATION=15m

# Maximum concurrent sessions per IP (default: 50)
export WEBAUTHN_MAX_SESSIONS_PER_IP=50

# Maximum total active sessions system-wide (default: 10000)
export WEBAUTHN_MAX_TOTAL_SESSIONS=10000
```

### Well-Known AAGUIDs

| Authenticator | AAGUID |
|---------------|--------|
| YubiKey 5 Series | `fa2b99dc-9e39-4257-8f92-4a30d23c4118` |
| YubiKey 5Ci | `c5ef55ff-ad9a-4b9f-b580-adebafe026d0` |
| YubiKey Bio | `d8522d9f-575b-4866-88a9-ba99fa02f35b` |
| Google Titan | `42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3` |
| Apple Secure Enclave | `00000000-0000-0000-0000-000000000000` |
| SoloKeys Solo 2 | `8876631b-d4a0-427f-5773-0ec71c9e0279` |
| Feitian ePass | `833b721a-ff5f-4d00-bb2e-bdda3ec01e29` |

---

## API Endpoints

### Standard Registration

**POST /webauthn/register/start**
```json
{
  "username": "alice",
  "display_name": "Alice Smith"
}
```

**POST /webauthn/register/finish**
```json
{
  "session_id": "uuid-from-start",
  "credential": { /* PublicKeyCredential */ }
}
```

### Resident Key Registration

Enables true passwordless authentication with credentials stored on the authenticator.

**POST /webauthn/register/resident/start**
```json
{
  "username": "alice",
  "display_name": "Alice Smith",
  "credential_name": "MacBook Pro Touch ID"
}
```

**Response:**
```json
{
  "options": { /* CreationChallengeResponse */ },
  "session_id": "uuid",
  "user_handle": "base64url-user-handle"
}
```

**POST /webauthn/register/resident/finish**
```json
{
  "session_id": "uuid",
  "credential": { /* PublicKeyCredential */ },
  "user_handle": "base64url-from-start",
  "credential_name": "MacBook Pro Touch ID"
}
```

**Response:**
```json
{
  "ok": true,
  "cred_id": "base64url-cred-id",
  "user_id_hash": "blake3-hash",
  "registered_at": 1699454445,
  "device_type": "platform",
  "backup_eligible": true,
  "is_discoverable": true
}
```

### Discoverable Authentication (Usernameless)

No username required—the authenticator provides the credential.

**POST /webauthn/authenticate/discoverable/start**

No request body needed.

**Response:**
```json
{
  "options": {
    "publicKey": {
      "challenge": "base64url-challenge",
      "rpId": "example.com",
      "allowCredentials": [],
      "userVerification": "required"
    }
  },
  "session_id": "uuid"
}
```

**POST /webauthn/authenticate/discoverable/finish**
```json
{
  "session_id": "uuid",
  "credential": { /* PublicKeyCredential with userHandle */ }
}
```

### Standard Authentication

**POST /webauthn/authenticate/start**
```json
{
  "username": "alice"
}
```

**POST /webauthn/authenticate/finish**
```json
{
  "session_id": "uuid",
  "credential": { /* PublicKeyCredential */ }
}
```

### Credential Management

**GET /webauthn/credentials/:username**

List all credentials for a user with sync status.

**Response:**
```json
{
  "credentials": [
    {
      "cred_id": "base64url",
      "device_type": "platform",
      "backup_eligible": true,
      "backup_state": true,
      "is_discoverable": true,
      "registered_at": 1699454445,
      "last_used_at": 1699458045,
      "transports": ["internal", "hybrid"],
      "aaguid": "00000000-0000-0000-0000-000000000000",
      "friendly_name": "MacBook Pro Touch ID"
    }
  ],
  "total": 1
}
```

**GET /webauthn/admin/credentials**

Admin endpoint to list all credentials with statistics.

**Response:**
```json
{
  "credentials": [ /* array of CredentialSummary */ ],
  "total": 150,
  "by_device_type": {
    "platform": 100,
    "cross-platform": 40,
    "hybrid": 10
  },
  "backup_stats": {
    "total_backup_eligible": 110,
    "total_backed_up": 95,
    "hardware_bound": 40
  }
}
```

**DELETE /webauthn/credentials/:cred_id**

Revoke a credential.

**Response:**
```json
{
  "ok": true,
  "message": "Credential revoked successfully"
}
```

---

## Redis Schema

### Credential Storage

```
Key:   webauthn:cred:{cred_id_base64}
Value: JSON StoredCredential
TTL:   Optional (WEBAUTHN_CRED_TTL_SECS)

{
  "cred_id": [1, 2, 3, ...],
  "credential": { /* Passkey data */ },
  "user_id_hash": "blake3-hash",
  "registered_at": 1699454445,
  "last_used_at": 1699458045,
  "device_type": "platform",
  "backup_eligible": true,
  "backup_state": true,
  "transports": ["internal", "hybrid"],
  "attestation_format": "apple",
  "aaguid": "00000000-0000-0000-0000-000000000000",
  "is_discoverable": true,
  "user_handle": "base64url-user-handle",
  "friendly_name": "MacBook Pro Touch ID"
}
```

### User Credential Index

```
Key:   webauthn:user:{user_id_hash}
Type:  SET
Value: Set of credential keys
```

### User Handle Mapping

```
Key:   webauthn:handle:{user_handle_base64}
Value: username (string)
TTL:   Optional (matches cred TTL)
```

### Discoverable Credentials Index

```
Key:   webauthn:discoverable:{user_handle_base64}
Type:  SET
Value: Set of credential keys for discoverable lookup
```

### Audit Metadata

```
Key:   webauthn:audit:{cred_id_base64}
Value: JSON audit data
TTL:   30 days

{
  "username": "alice",
  "registered_at": 1699454445,
  "policy": "Direct",
  "attestation_format": "packed",
  "aaguid": "fa2b99dc-...",
  "self_attestation": false,
  "backup_eligible": true,
  "backup_state": false,
  "client_ip": "192.168.1.1",
  "user_agent": null
}
```

---

## Security Considerations

### Attestation Policy Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `none` | Accept any attestation | Development, low-security |
| `indirect` | Accept self/indirect attestation | General use |
| `direct` | Require verifiable attestation | Enterprise |
| `enterprise` | Require certificate chain | Managed devices |

### Backup-Eligible vs Hardware-Bound Credentials

**Backup-Eligible (BE flag = true):**
- Can be synced across devices (iCloud Keychain, Google Password Manager)
- More convenient for users
- Different threat model (credential may exist on multiple devices)

**Hardware-Bound (BE flag = false):**
- Cannot be exported or synced
- Stronger security guarantee
- Lost device = lost credential

### Rate Limiting

WebAuthn endpoints include built-in rate limiting to prevent abuse:

| Protection | Default | Description |
|------------|---------|-------------|
| Registration attempts | 10/5min | Per-IP limit on registration starts |
| Authentication attempts | 20/5min | Per-IP limit on authentication starts |
| Block duration | 15 min | Lockout period after exceeding limits |
| Sessions per IP | 50 | Maximum concurrent challenge sessions |
| Total sessions | 10,000 | System-wide session limit |

When rate limited, endpoints return HTTP 429 with a `Retry-After` header.

### Threat Model

**Protects Against:**
- Bot networks (no physical authenticators)
- Mass token requests from VMs/cloud instances
- Credential stuffing (origin-bound)
- Phishing (challenge-response)
- Brute force attacks (rate limiting)
- Memory exhaustion attacks (session limits)

**Does NOT Protect Against:**
- Users with multiple physical devices
- Borrowed/shared security keys
- Social engineering (willing participants)

---

## Client-Side Integration

### Discoverable Credential Registration

```javascript
// Start resident key registration
const startResp = await fetch('/webauthn/register/resident/start', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'alice',
    credential_name: 'My MacBook'
  })
});
const { options, session_id, user_handle } = await startResp.json();

// Create credential (browser prompts user)
const credential = await navigator.credentials.create({
  publicKey: options.publicKey
});

// Finish registration
const finishResp = await fetch('/webauthn/register/resident/finish', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    session_id,
    user_handle,
    credential_name: 'My MacBook',
    credential: serializeCredential(credential)
  })
});
```

### Usernameless Authentication

```javascript
// Start discoverable auth (no username needed!)
const startResp = await fetch('/webauthn/authenticate/discoverable/start', {
  method: 'POST'
});
const { options, session_id } = await startResp.json();

// Get assertion (authenticator shows available credentials)
const assertion = await navigator.credentials.get({
  publicKey: options.publicKey,
  mediation: 'conditional' // For autofill UI
});

// Finish auth
const finishResp = await fetch('/webauthn/authenticate/discoverable/finish', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    session_id,
    credential: serializeAssertion(assertion)
  })
});

// Response includes username resolved from userHandle
const { username, proof } = await finishResp.json();
```

---

## Testing

### Manual Testing

```bash
# Build with WebAuthn feature
cargo build --release --features human-gate-webauthn

# Set test environment
export WEBAUTHN_RP_ID=localhost
export WEBAUTHN_RP_NAME="Freebird Test"
export WEBAUTHN_RP_ORIGIN=http://localhost:8081
export WEBAUTHN_REDIS_URL=redis://localhost:6379
export SYBIL_RESISTANCE=webauthn
export WEBAUTHN_REQUIRE_ATTESTATION=true
export WEBAUTHN_ATTESTATION_POLICY=direct

# Run issuer
./target/release/issuer
```

### Testing with Different Authenticators

| Authenticator | Transport | Type | Notes |
|---------------|-----------|------|-------|
| macOS Touch ID | internal | Platform | Uses Apple Secure Enclave |
| Windows Hello | internal | Platform | TPM-based |
| YubiKey | usb, nfc | Cross-platform | Hardware security key |
| iPhone via QR | hybrid | Cross-platform | BLE + QR pairing |
| Android Phone | hybrid | Cross-platform | Google Password Manager |

---

## Troubleshooting

### "AAGUID not in allowlist"

Your authenticator's AAGUID isn't in `WEBAUTHN_ALLOWED_AAGUIDS`.

**Solution:** Add the AAGUID or disable the allowlist.

### "Maximum credentials per user reached"

User has reached `WEBAUTHN_MAX_CREDENTIALS_PER_USER` limit.

**Solution:** Revoke unused credentials or increase the limit.

### "Hardware authenticator required"

Policy requires attestation but a software/self-attested credential was provided.

**Solution:** Use a hardware security key or change policy to `indirect`.

### "User handle required for discoverable authentication"

The credential assertion doesn't include a userHandle.

**Solution:** The credential must be registered as a resident key (discoverable).

### "Rate limited" / HTTP 429

Too many requests from your IP address.

**Solution:** Wait for the `Retry-After` period (default 15 minutes) or adjust rate limit configuration.

### "Service temporarily unavailable" / HTTP 503

System has reached maximum concurrent sessions.

**Solution:** Wait for sessions to expire or increase `WEBAUTHN_MAX_TOTAL_SESSIONS`.

---

## Related Documentation

- [Sybil Resistance Mechanisms](SYBIL_RESISTANCE.md)
- [Production Deployment](PRODUCTION.md)
- [Security Model](SECURITY.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-3/)
- [Passkeys Developer Guide](https://passkeys.dev)

---

**WebAuthn + Freebird = Privacy-Preserving Proof of Humanity**
