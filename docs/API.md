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
| **Verifier** | 8082 | Verify tokens and check replay | None (public) |
| **Admin** | 8081 | Manage invitation system | API key required |

**Base URLs:**
- Issuer: `http://localhost:8081` (default)
- Verifier: `http://localhost:8082` (default)
- Admin: `http://localhost:8081/admin` (optional)

---

## Issuer API

### Get Issuer Metadata

**GET /.well-known/issuer**

Returns public metadata about the issuer for verifier configuration.

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
  "origin": "[https://example.com](https://example.com)"
}
```

---

## Verifier API

### Verify Token

**POST /v1/verify**

Verifies a token with expiration checking and replay protection.

**Request:**
```json
{
  "token_b64": "Q9w8x7y6v5u4t3s2r1q0p9o8n7m6l5k4...",
  "issuer_id": "issuer:freebird:v1",
  "exp": 1699454445
}
```

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

---

## Admin API

See [Admin API Reference](ADMIN_API.md) for complete documentation.

**Authentication:** All require `X-Admin-Key` header.

---

## Error Handling

**HTTP Status Codes:**

| Code | Meaning | Example |
|------|---------|---------|
| 200 | OK | Successful request |
| 400 | Bad Request | Invalid blinded element |
| 403 | Forbidden | Sybil proof failed |
| 401 | Unauthorized | Invalid admin key |
| 500 | Internal Error | VOPRF evaluation failed |

---

## Authentication

**Issuer:**
- Public: `GET /.well-known/issuer`
- Optional Sybil proof: `POST /v1/oprf/issue`

**WebAuthn:**
- Public: Registration/Auth start endpoints
- Session-bound: Finish endpoints require valid session ID

**Verifier:**
- All endpoints public (verification is the auth)

**Admin:**
- All endpoints require `X-Admin-Key` header