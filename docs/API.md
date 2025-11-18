# 🌐 API Reference

Complete HTTP API reference for Freebird issuer and verifier services.

---

## Table of Contents

1. [Overview](#overview)
2. [Issuer API](#issuer-api)
3. [Verifier API](#verifier-api)
4. [Admin API](#admin-api)
5. [Error Handling](#error-handling)
6. [Authentication](#authentication)
7. [Rate Limiting](#rate-limiting)

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

**Request (Without Sybil Resistance):**
```json
{
  "blinded_element_b64": "A1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6..."
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
    "cost": 3600
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

**Failure reasons:**
- Token expired
- Token already used (replay)
- Invalid signature
- Unknown issuer

---

## Admin API

See [Admin API Reference](ADMIN_API.md) for complete documentation.

**Key endpoints:**
- `GET /admin/stats` - System statistics
- `POST /admin/invites/grant` - Grant invites
- `POST /admin/users/ban` - Ban users
- `POST /admin/keys/rotate` - Rotate keys

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

**Verifier:**
- All endpoints public (verification is the auth)

**Admin:**
- All endpoints require `X-Admin-Key` header

---

## Rate Limiting

**Recommendation:** Use reverse proxy (nginx, Caddy) for rate limiting.

**Example (nginx):**
```nginx
limit_req_zone $binary_remote_addr zone=issue:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=verify:10m rate=100r/s;
```

---

## Testing

**Issuer metadata:**
```bash
curl http://localhost:8081/.well-known/issuer | jq
```

**Issue token:**
```bash
curl -X POST http://localhost:8081/v1/oprf/issue \
  -H "Content-Type: application/json" \
  -d '{"blinded_element_b64": "A3x5Y2z8..."}'
```

**Verify token:**
```bash
curl -X POST http://localhost:8082/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"token_b64": "Q9w8x7...", "issuer_id": "issuer:freebird:v1", "exp": 1699454445}'
```

---

## Related Documentation

- [Admin API Reference](ADMIN_API.md) - Complete admin endpoints
- [How It Works](HOW_IT_WORKS.md) - VOPRF protocol
- [Configuration](CONFIGURATION.md) - Environment variables
- [Security Model](SECURITY.md) - Threat model

---

**Full API documentation including all request/response formats, error codes, and examples available in the sections above.**