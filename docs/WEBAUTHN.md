# WebAuthn Integration for Freebird

## Overview

Freebird now supports **WebAuthn/FIDO2** as a Sybil resistance mechanism. This provides "proof of humanity" through hardware-backed authentication without computational cost or energy consumption.

## Features

✅ **Hardware-Backed Security**: Credentials protected by TPM, Secure Enclave, or security keys  
✅ **Phishing Resistant**: Origin-bound credentials prevent phishing attacks  
✅ **Zero Computational Cost**: No proof-of-work needed, instant verification  
✅ **User-Friendly**: Biometric unlock (Touch ID, Windows Hello, Face ID)  
✅ **Redis-Backed Storage**: Production-ready persistent credential storage  
✅ **Multi-Device Support**: Users can register multiple authenticators  

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
│  │ - POST /webauthn/       │  │
│  │        register/start   │  │
│  │ - POST /webauthn/       │  │
│  │        register/finish  │  │
│  │ - POST /webauthn/       │  │
│  │        authenticate/    │  │
│  │        start            │  │
│  │ - POST /webauthn/       │  │
│  │        authenticate/    │  │
│  │        finish           │  │
│  └─────────────────────────┘  │
│            │                    │
│            ▼                    │
│  ┌─────────────────────────┐  │
│  │ WebAuthn Sybil Gate     │  │
│  │ (verifies auth proofs)  │  │
│  └─────────────────────────┘  │
│            │                    │
│            ▼                    │
│  ┌─────────────────────────┐  │
│  │ Redis Credential Store  │  │
│  └─────────────────────────┘  │
└─────────────┬───────────────────┘
              │ 2. Token Issuance
              │    with WebAuthn proof
              ▼
       ┌─────────────┐
       │ VOPRF Token │
       └─────────────┘
```

---

## Configuration

### Environment Variables

```bash
# WebAuthn Configuration
export WEBAUTHN_RP_ID=localhost                    # Relying Party ID (domain)
export WEBAUTHN_RP_NAME="Freebird"                 # Display name
export WEBAUTHN_RP_ORIGIN=http://localhost:8081    # Origin URL

# WebAuthn Credential Storage
export WEBAUTHN_REDIS_URL=redis://localhost:6379   # Redis for credentials
export WEBAUTHN_CRED_TTL_SECS=31536000             # 1 year (optional)

# Sybil Resistance
export SYBIL_RESISTANCE=webauthn                   # Enable WebAuthn gate
export WEBAUTHN_MAX_PROOF_AGE=300                  # 5 minutes

# Optional: Combine with other mechanisms
export SYBIL_RESISTANCE=combined
export SYBIL_COMBINED_MECHANISMS=webauthn,rate_limit
```

### Production Example

```bash
# Issuer with WebAuthn + Rate Limiting
export WEBAUTHN_RP_ID=issuer.example.com
export WEBAUTHN_RP_NAME="Example Corp Freebird"
export WEBAUTHN_RP_ORIGIN=https://issuer.example.com
export WEBAUTHN_REDIS_URL=redis://redis.internal:6379
export SYBIL_RESISTANCE=combined
export SYBIL_COMBINED_MECHANISMS=webauthn,rate_limit
export SYBIL_RATE_LIMIT_SECS=3600
```

---

## Usage

### 1. Registration Flow

**Step 1: Start Registration**

```bash
curl -X POST https://issuer.example.com/webauthn/register/start \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "display_name": "Alice Smith"
  }'
```

**Response:**
```json
{
  "options": {
    "publicKey": {
      "challenge": "base64url-encoded-challenge",
      "rp": { "name": "Freebird", "id": "issuer.example.com" },
      "user": {
        "id": "base64url-user-id",
        "name": "alice",
        "displayName": "Alice Smith"
      },
      "pubKeyCredParams": [
        { "type": "public-key", "alg": -7 },   // ES256
        { "type": "public-key", "alg": -257 }  // RS256
      ],
      "authenticatorSelection": {
        "residentKey": "required",
        "userVerification": "required"
      },
      "attestation": "none"
    }
  },
  "session_id": "uuid-v4-session-id"
}
```

**Step 2: Browser Creates Credential**

```javascript
// Client-side JavaScript
const options = response.options;

const credential = await navigator.credentials.create({
  publicKey: options.publicKey
});

// Credential is now in `credential` variable
```

**Step 3: Finish Registration**

```bash
curl -X POST https://issuer.example.com/webauthn/register/finish \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "uuid-from-start-response",
    "credential": { /* PublicKeyCredential from browser */ }
  }'
```

**Response:**
```json
{
  "ok": true,
  "cred_id": "base64url-credential-id",
  "user_id_hash": "blake3-hash-of-username",
  "registered_at": 1699454445
}
```

---

### 2. Authentication Flow

**Step 1: Start Authentication**

```bash
curl -X POST https://issuer.example.com/webauthn/authenticate/start \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice"
  }'
```

**Response:**
```json
{
  "options": {
    "publicKey": {
      "challenge": "base64url-encoded-challenge",
      "rpId": "issuer.example.com",
      "allowCredentials": [
        {
          "type": "public-key",
          "id": "base64url-credential-id"
        }
      ],
      "userVerification": "required"
    }
  },
  "session_id": "uuid-v4-session-id"
}
```

**Step 2: Browser Signs Challenge**

```javascript
const options = response.options;

const assertion = await navigator.credentials.get({
  publicKey: options.publicKey
});
```

**Step 3: Finish Authentication**

```bash
curl -X POST https://issuer.example.com/webauthn/authenticate/finish \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "uuid-from-start-response",
    "credential": { /* PublicKeyCredential from browser */ }
  }'
```

**Response:**
```json
{
  "ok": true,
  "cred_id": "base64url-credential-id",
  "username": "alice",
  "authenticated_at": 1699454445,
  "proof": "base64url-encoded-auth-proof"
}
```

---

### 3. Token Issuance with WebAuthn Proof

After successful authentication, use the `proof` to request a token:

```bash
curl -X POST https://issuer.example.com/v1/oprf/issue \
  -H "Content-Type: application/json" \
  -d '{
    "blinded_element_b64": "base64url-blinded-element",
    "sybil_proof": {
      "type": "webauthn",
      "username": "alice",
      "auth_proof": "proof-from-authenticate-finish",
      "timestamp": 1699454445
    }
  }'
```

**Response:**
```json
{
  "token": "base64url-voprf-token",
  "kid": "freebird-2024-11-17",
  "exp": 1699458045
}
```

---

## Security Considerations

### Advantages Over Other Mechanisms

| Mechanism | Energy Cost | User Friction | Sybil Resistance | Privacy |
|-----------|-------------|---------------|------------------|---------|
| Proof-of-Work | High | Medium | Medium | High |
| Rate Limiting | Zero | Low | Low | Medium |
| Invitation | Zero | Medium | High | High |
| **WebAuthn** | **Zero** | **Low** | **High** | **High** |

### Threat Model

**Protects Against:**
- ✅ Bot networks (no physical authenticators)
- ✅ Mass token requests from VMs/cloud instances
- ✅ Credential stuffing (origin-bound)
- ✅ Phishing (challenge-response)

**Does NOT Protect Against:**
- ❌ Users with multiple physical devices
- ❌ Borrowed/shared security keys
- ❌ Social engineering (willing participants)

### Best Practices

1. **Combine with Rate Limiting**
   ```bash
   export SYBIL_RESISTANCE=combined
   export SYBIL_COMBINED_MECHANISMS=webauthn,rate_limit
   ```

2. **Short Proof Validity**
   ```bash
   export WEBAUTHN_MAX_PROOF_AGE=300  # 5 minutes
   ```

3. **Credential Lifecycle Management**
   ```bash
   export WEBAUTHN_CRED_TTL_SECS=31536000  # Expire after 1 year
   ```

4. **Monitor Registration Patterns**
   - Alert on unusual registration spikes
   - Track credentials per user (prevent device farming)

---

## Redis Schema

### Credential Storage

```
Key:   webauthn:cred:{cred_id_base64}
Value: JSON StoredCredential
TTL:   Optional (WEBAUTHN_CRED_TTL_SECS)

Example:
{
  "cred_id": [1, 2, 3, ...],
  "credential": { /* Passkey data */ },
  "user_id_hash": "blake3-hash",
  "registered_at": 1699454445,
  "last_used_at": 1699458045
}
```

### User Credential Index

```
Key:   webauthn:user:{user_id_hash}
Type:  SET
Value: Set of credential keys
TTL:   Optional (matches cred TTL)

Example:
SMEMBERS webauthn:user:abc123
-> ["webauthn:cred:xyz789", "webauthn:cred:def456"]
```

---

## Client-Side Integration

### HTML/JavaScript Example

```html
<!DOCTYPE html>
<html>
<head>
  <title>Freebird WebAuthn Demo</title>
</head>
<body>
  <h1>WebAuthn Registration</h1>
  <button id="register">Register Passkey</button>
  <button id="authenticate">Authenticate</button>
  <div id="status"></div>

  <script>
    const API_BASE = 'http://localhost:8081';

    // Registration
    document.getElementById('register').onclick = async () => {
      const username = prompt('Enter username:');
      
      // Start registration
      const startResp = await fetch(`${API_BASE}/webauthn/register/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });
      const { options, session_id } = await startResp.json();

      // Create credential
      const credential = await navigator.credentials.create({
        publicKey: options.publicKey
      });

      // Finish registration
      const finishResp = await fetch(`${API_BASE}/webauthn/register/finish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id,
          credential: {
            id: credential.id,
            rawId: arrayBufferToBase64(credential.rawId),
            response: {
              attestationObject: arrayBufferToBase64(
                credential.response.attestationObject
              ),
              clientDataJSON: arrayBufferToBase64(
                credential.response.clientDataJSON
              )
            },
            type: credential.type
          }
        })
      });

      const result = await finishResp.json();
      document.getElementById('status').textContent = 
        `Registered! Credential ID: ${result.cred_id}`;
    };

    // Authentication
    document.getElementById('authenticate').onclick = async () => {
      const username = prompt('Enter username:');
      
      // Start authentication
      const startResp = await fetch(`${API_BASE}/webauthn/authenticate/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });
      const { options, session_id } = await startResp.json();

      // Get assertion
      const assertion = await navigator.credentials.get({
        publicKey: options.publicKey
      });

      // Finish authentication
      const finishResp = await fetch(`${API_BASE}/webauthn/authenticate/finish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id,
          credential: {
            id: assertion.id,
            rawId: arrayBufferToBase64(assertion.rawId),
            response: {
              authenticatorData: arrayBufferToBase64(
                assertion.response.authenticatorData
              ),
              clientDataJSON: arrayBufferToBase64(
                assertion.response.clientDataJSON
              ),
              signature: arrayBufferToBase64(
                assertion.response.signature
              ),
              userHandle: assertion.response.userHandle ? 
                arrayBufferToBase64(assertion.response.userHandle) : null
            },
            type: assertion.type
          }
        })
      });

      const result = await finishResp.json();
      document.getElementById('status').textContent = 
        `Authenticated! Proof: ${result.proof}`;
      
      // Now use result.proof for token issuance
      console.log('Auth proof for token issuance:', result.proof);
    };

    function arrayBufferToBase64(buffer) {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    }
  </script>
</body>
</html>
```

---

## Troubleshooting

### "WEBAUTHN_RP_ID not set"

```bash
# Fix: Set required environment variables
export WEBAUTHN_RP_ID=localhost
export WEBAUTHN_RP_ORIGIN=http://localhost:8081
```

### "Invalid origin URL"

**Problem:** RP_ORIGIN doesn't match RP_ID

```bash
# Bad
export WEBAUTHN_RP_ID=example.com
export WEBAUTHN_RP_ORIGIN=http://localhost:8081  # Mismatch!

# Good
export WEBAUTHN_RP_ID=localhost
export WEBAUTHN_RP_ORIGIN=http://localhost:8081
```

### "User has no registered credentials"

**Problem:** Trying to authenticate before registration

**Solution:**
1. Complete registration flow first
2. Verify credential was saved: `redis-cli KEYS "webauthn:cred:*"`

### "Authentication proof expired"

**Problem:** Proof too old (default: 5 minutes)

**Solution:**
- Request tokens immediately after authentication
- Or increase timeout: `export WEBAUTHN_MAX_PROOF_AGE=600`

---

## Testing

```bash
# Build with WebAuthn feature
cargo build --release --features human-gate-webauthn

# Set test environment
export WEBAUTHN_RP_ID=localhost
export WEBAUTHN_RP_NAME="Freebird Test"
export WEBAUTHN_RP_ORIGIN=http://localhost:8081
export WEBAUTHN_REDIS_URL=redis://localhost:6379
export SYBIL_RESISTANCE=webauthn

# Run issuer
./target/release/issuer

# Test with browser (open HTML demo)
# Or use Postman/curl with WebAuthn simulator
```

---

## Comparison to Other Systems

| System | Mechanism | User Experience | Sybil Resistance |
|--------|-----------|-----------------|------------------|
| Privacy Pass | CAPTCHA | Annoying | Medium |
| Cloudflare Turnstile | hCaptcha | Moderate | Medium |
| reCAPTCHA | Image challenges | Frustrating | Medium |
| **Freebird WebAuthn** | **Biometric/PIN** | **Seamless** | **High** |

---

## Future Enhancements

- [ ] Attestation verification (verify authenticator models)
- [ ] Credential management UI (list/revoke credentials)
- [ ] Multi-instance session storage (Redis-backed sessions)
- [ ] Credential usage analytics (track device usage patterns)
- [ ] Integration with mobile apps (platform authenticators)

---

## Related Documentation

- [Sybil Resistance Mechanisms](../docs/SYBIL_RESISTANCE.md)
- [Production Deployment](../docs/PRODUCTION.md)
- [Security Model](../docs/SECURITY.md)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)

---

**WebAuthn + Freebird = Privacy-Preserving Proof of Humanity** 🕊️✨