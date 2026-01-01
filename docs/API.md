# 🌐 API Reference

Complete HTTP API reference for Freebird issuer and verifier services.

---

## Table of Contents

1. [Overview](#overview)
2. [Issuer API](#issuer-api)
3. [WebAuthn API](#webauthn-api)
4. [Verifier API](#verifier-api)
5. [Admin API](#admin-api)
6. [Error Handling](#error-handling)
7. [Authentication](#authentication)

---

## Overview

Freebird consists of three HTTP services:

| Service | Port | Purpose | Authentication |
|---------|------|---------|----------------|
| **Issuer** | 8081 | Issue anonymous tokens via VOPRF | Optional Sybil proof |
| **Verifier** | 8082 | Verify tokens from one or more issuers | None (public) |
| **Admin** | 8081 | Manage invitation system | API key required |

**Base URLs:**
- Issuer: `http://localhost:8081` (default)
- Verifier: `http://localhost:8082` (default)
- Admin: `http://localhost:8081/admin` (optional)

**Federation Support:**
- Verifiers can accept tokens from multiple independent issuers
- See [FEDERATION.md](FEDERATION.md) for multi-issuer configuration

---

## Issuer API

### Get Issuer Metadata

**GET /.well-known/issuer**

Returns public metadata about the issuer for verifier configuration and federation.

**Request:**
```bash
curl http://localhost:8081/.well-known/issuer
```

**Response (200 OK):**
```json
{
  "issuer_id": "issuer:freebird:v1",
  "voprf": {
    "suite": "OPRF(P-256, SHA-256)-verifiable",
    "kid": "2b8d5f3a-2024-11-08",
    "pubkey": "A3x5Y2z8B4w7C6v5D4u3E2t1F0s9G8h7I6j5K4l3M2n1",
    "exp_sec": 600
  }
}
```

**Fields:**
- `issuer_id`: Unique identifier for this issuer
- `voprf.suite`: Cryptographic suite identifier
- `voprf.kid`: Key identifier for current active key
- `voprf.pubkey`: Base64-encoded P-256 public key
- `voprf.exp_sec`: Default token expiration in seconds

**Federation Note:** Verifiers use this endpoint to discover and verify issuer public keys.

---

### Issue Token (Single)

**POST /v1/oprf/issue**

Issues a single anonymous token via VOPRF evaluation.

**Request (With WebAuthn Proof):**
```json
{
  "blinded_element_b64": "A1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6...",
  "sybil_proof": {
    "type": "webauthn",
    "username": "alice",
    "auth_proof": "base64url_proof_string_from_auth_finish",
    "timestamp": 1699454445
  }
}
```

**Request (With Invitation):**
```json
{
  "blinded_element_b64": "A1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6...",
  "sybil_proof": {
    "type": "invitation",
    "code": "Abc123XyZ456PqRsTuVw",
    "signature": "3045022100d7f2e8c9a1b3f4e5d6c7a8b9..."
  }
}
```

**Request (No Sybil Resistance):**
```json
{
  "blinded_element_b64": "A1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6..."
}
```

**Response (200 OK):**
```json
{
  "token": "Q9w8x7y6v5u4t3s2r1q0p9o8n7m6l5k4...",
  "proof": "",
  "kid": "2b8d5f3a-2024-11-08",
  "exp": 1699454445,
  "sybil_info": {
    "required": true,
    "passed": true,
    "cost": 0
  }
}
```

**Token Formats:**

- **Basic Token (131 bytes):** VOPRF evaluation result with DLEQ proof
- **Signature-Based Token (195 bytes):** Includes ECDSA signature for federation support

The token format depends on issuer configuration. Federation-enabled issuers return signature-based tokens that can be verified by any verifier with the issuer's public key.

---

### Issue Token (Batch)

**POST /v1/oprf/issue/batch**

Issues multiple tokens in parallel (1000+ tokens/sec).

**Request:**
```json
{
  "blinded_elements": [
    "A1b2c3d4e5f6...",
    "B2c3d4e5f6g7...",
    "C3d4e5f6g7h8..."
  ],
  "sybil_proof": {
    "type": "invitation",
    "code": "Abc123XyZ456",
    "signature": "3045022100..."
  }
}
```

**Response:**
```json
{
  "results": [
    {"Success": {"token": "Q9w8x7y6...", "exp": 1699454445}},
    {"Success": {"token": "P8o7n6m5...", "exp": 1699454445}},
    {"Error": {"message": "invalid base64", "code": "validation_failed"}}
  ],
  "successful": 2,
  "failed": 1,
  "processing_time_ms": 156,
  "throughput": 1282.05
}
```

---

## WebAuthn API

Endpoints for hardware-backed registration and authentication. These are available when the `webauthn` feature is enabled.

### Registration

**POST /webauthn/register/start**

Start a new registration ceremony.

**Request:**
```json
{
  "username": "alice",
  "display_name": "Alice Smith"
}
```

**Response (200 OK):**
```json
{
  "options": { /* WebAuthn PublicKeyCredentialCreationOptions */ },
  "session_id": "uuid-session-id"
}
```

**POST /webauthn/register/finish**

Complete registration and store credential.

**Request:**
```json
{
  "session_id": "uuid-session-id",
  "credential": { /* WebAuthn RegisterPublicKeyCredential */ }
}
```

**Response (200 OK):**
```json
{
  "ok": true,
  "cred_id": "base64url_credential_id",
  "user_id_hash": "hashed_user_id",
  "registered_at": 1699454445
}
```

### Authentication

**POST /webauthn/authenticate/start**

Start an authentication ceremony.

**Request:**
```json
{
  "username": "alice"
}
```

**Response (200 OK):**
```json
{
  "options": { /* WebAuthn PublicKeyCredentialRequestOptions */ },
  "session_id": "uuid-session-id"
}
```

**POST /webauthn/authenticate/finish**

Complete authentication and receive a proof for token issuance.

**Request:**
```json
{
  "session_id": "uuid-session-id",
  "credential": { /* WebAuthn PublicKeyCredential */ }
}
```

**Response (200 OK):**
```json
{
  "ok": true,
  "cred_id": "base64url_credential_id",
  "username": "alice",
  "authenticated_at": 1699454445,
  "proof": "base64url_proof_string"
}
```
**Note:** The `proof` string returned here is what you send in the `sybil_proof.auth_proof` field when issuing a token.

### Info

**GET /webauthn/info**

Get Relying Party configuration.

**Response:**
```json
{
  "rp_id": "example.com",
  "rp_name": "Freebird Service",
  "origin": "https://example.com"
}
```

---

## Verifier API

### Verify Token

**POST /v1/verify**

Verifies a token with expiration checking and replay protection. Supports tokens from multiple issuers in federation scenarios.

**Request:**
```json
{
  "token_b64": "Q9w8x7y6v5u4t3s2r1q0p9o8n7m6l5k4...",
  "issuer_id": "issuer:freebird:v1",
  "exp": 1699454445
}
```

**Fields:**
- `token_b64`: Base64-encoded token (131 or 195 bytes depending on format)
- `issuer_id`: Identifier of the issuer that created the token
- `exp`: Unix timestamp when token expires

**Response (200 OK - Success):**
```json
{
  "ok": true,
  "verified_at": 1699454445
}
```

**Response (401 Unauthorized - Failure):**
```json
{
  "ok": false,
  "error": "verification failed"
}
```

**Error Reasons:**
- Token expired (`exp < current_time`)
- Token already used (replay attack)
- Invalid signature or DLEQ proof
- Unknown issuer (not in trusted issuer list)
- Nullifier already exists in database

**Federation Support:**

In multi-issuer scenarios, the verifier:
1. Looks up the issuer's public key using `issuer_id`
2. Verifies the token's ECDSA signature (for signature-based tokens)
3. Verifies the DLEQ proof
4. Checks expiration and replay protection
5. Records the nullifier to prevent reuse

See [FEDERATION.md](FEDERATION.md) for configuration details.

---

### Check Token (Non-Consuming)

**POST /v1/check**

Validates a token's cryptographic proof and expiration **without** recording the nullifier. The token remains valid for future use with `/v1/verify` or other services.

**Use Cases:**
- Verifying a user holds a valid Day Pass before granting access
- Rate-limiting based on token possession without consumption
- Multi-service scenarios where the same token is used across services (e.g., Witness + Clout)

**Request:**
```json
{
  "token_b64": "Q9w8x7y6v5u4t3s2r1q0p9o8n7m6l5k4...",
  "issuer_id": "issuer:freebird:v1",
  "exp": 1699454445,
  "epoch": 42
}
```

**Response (200 OK - Valid):**
```json
{
  "ok": true,
  "verified_at": 1699454445
}
```

**Response (401 Unauthorized - Invalid):**
```json
{
  "ok": false,
  "error": "check failed"
}
```

**Differences from `/v1/verify`:**

| Aspect | `/v1/verify` | `/v1/check` |
|--------|-------------|-------------|
| Records nullifier | ✅ Yes | ❌ No |
| Prevents token reuse | ✅ Yes | ❌ No |
| Token consumed | ✅ Yes | ❌ No |
| Use case | One-time redemption | Proof of possession |

**⚠️ Security Note:** Since `/v1/check` doesn't consume tokens, the same token can be validated repeatedly. **Reverse proxy rate limiting is essential** to prevent DoS attacks where an attacker replays a single valid token to exhaust server CPU with cryptographic verification. See [Production Deployment](PRODUCTION.md) for nginx/Caddy rate limiting configuration.

---

## Admin API

See [Admin API Reference](ADMIN_API.md) for complete documentation.

**Authentication:** All require `X-Admin-Key` header.

**Available Endpoints:**
- User management (invitation system)
- Key rotation
- Statistics and monitoring
- Invitation generation and revocation

---

## Error Handling

**HTTP Status Codes:**

| Code | Meaning | Example |
|------|---------|---------|
| 200 | OK | Successful request |
| 400 | Bad Request | Invalid blinded element or malformed JSON |
| 401 | Unauthorized | Invalid admin key or token verification failed |
| 403 | Forbidden | Sybil proof failed or required but missing |
| 404 | Not Found | Unknown issuer in federation |
| 500 | Internal Error | VOPRF evaluation failed or database error |

**Error Response Format:**
```json
{
  "error": "descriptive error message",
  "code": "error_code",
  "details": { /* optional additional context */ }
}
```

---

## Authentication

**Issuer:**
- Public: `GET /.well-known/issuer`
- Optional Sybil proof: `POST /v1/oprf/issue`
- Proof type depends on issuer configuration

**WebAuthn:**
- Public: Registration/Auth start endpoints
- Session-bound: Finish endpoints require valid session ID

**Verifier:**
- All endpoints public (token verification is the authentication)
- Multi-issuer: Verifier maintains list of trusted issuers

**Admin:**
- All endpoints require `X-Admin-Key` header
- Key must be at least 32 characters
- Set via `ADMIN_API_KEY` environment variable

---

## Federation Configuration

**Verifier Configuration:**

To accept tokens from multiple issuers, configure the verifier with trusted issuer public keys:

```bash
# Environment variable (single issuer)
ISSUER_URL=http://localhost:8081

# Multi-issuer configuration (config file)
# See FEDERATION.md for complete details
```

**Dynamic Issuer Discovery:**

Verifiers can dynamically discover issuers via:
1. Manual configuration (static list)
2. HTTPS discovery (fetch from `.well-known/issuer`)
3. Trust graph (Layer 2 federation with cryptographic vouching)

See [FEDERATION.md](FEDERATION.md) for complete federation documentation.

---

## Related Documentation

- [Multi-Issuer Federation](FEDERATION.md) - Federation architecture and configuration
- [Admin API Reference](ADMIN_API.md) - Complete admin endpoint documentation
- [Configuration Guide](CONFIGURATION.md) - Environment variables and settings
- [How It Works](HOW_IT_WORKS.md) - VOPRF protocol details
