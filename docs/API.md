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

### Get Key Discovery Metadata

**GET /.well-known/keys**

Returns epoch and key rotation information for epoch-aware clients. Verifiers call this to retrieve the full epoch range and valid key set.

**Request:**
```bash
curl http://localhost:8081/.well-known/keys
```

**Response (200 OK):**
```json
{
  "issuer_id": "issuer:freebird:v1",
  "current_epoch": 42,
  "valid_epochs": [40, 41, 42],
  "epoch_duration_sec": 86400,
  "voprf": {
    "suite": "OPRF(P-256, SHA-256)-verifiable",
    "kid": "2b8d5f3a-2024-11-08",
    "pubkey": "A3x5Y2z8B4w7C6v5D4u3E2t1F0s9G8h7I6j5K4l3M2n1",
    "exp_sec": 600
  }
}
```

**Additional Fields (beyond `/.well-known/issuer`):**
- `current_epoch`: Current epoch number
- `valid_epochs`: List of epochs whose tokens the issuer currently accepts
- `epoch_duration_sec`: Duration of each epoch in seconds

---

### Get Federation Metadata

**GET /.well-known/federation**

Returns this issuer's trust graph: the list of issuers it vouches for and any revocations. Used by verifiers implementing Layer 2 trust graph federation.

**Request:**
```bash
curl http://localhost:8081/.well-known/federation
```

**Response (200 OK):**
```json
{
  "issuer_id": "issuer:example:v1",
  "vouches": [
    {
      "voucher_issuer_id": "issuer:example:v1",
      "vouched_issuer_id": "issuer:partner:v1",
      "vouched_pubkey": "AzQ1...base64...",
      "expires_at": 1735689600,
      "created_at": 1704067200,
      "trust_level": 90,
      "signature": "r7K9...base64..."
    }
  ],
  "revocations": [],
  "updated_at": 1704067200,
  "cache_ttl_secs": 3600
}
```

See [FEDERATION.md](FEDERATION.md) for trust graph architecture and configuration.

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

**Request (Registered User — bypasses invitation requirement for existing users):**
```json
{
  "blinded_element_b64": "A1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6...",
  "sybil_proof": {
    "type": "registered_user",
    "user_id": "alice"
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
  "sig": "Base64url-encoded-ECDSA-signature...",
  "kid": "2b8d5f3a-2024-11-08",
  "exp": 1699454445,
  "issuer_id": "issuer:freebird:v1",
  "sybil_info": {
    "required": true,
    "passed": true,
    "cost": 0
  }
}
```

**Response Fields:**

- `token`: Base64url-encoded VOPRF evaluation `[VERSION|A|B|DLEQ_proof]` (131 bytes). Used by the client to verify the DLEQ proof and unblind the result. Ephemeral — discarded after client-side finalization.
- `sig`: Base64url-encoded ECDSA signature (64 bytes) over `SHA256("freebird:token-metadata:v3" || kid_len || kid || exp || issuer_id_len || issuer_id)`. Included in the V3 redemption token sent to verifiers.
- `kid`: Key identifier for the signing key used.
- `exp`: Token expiration (Unix timestamp, seconds).
- `issuer_id`: Issuer identifier. Needed by the client to build the V3 redemption token.

The client uses these fields to build a **V3 redemption token** — a self-contained binary format containing the unblinded PRF output, metadata, and ECDSA signature. See [How It Works](HOW_IT_WORKS.md) for protocol details.

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
    {"status": "success", "token": "Q9w8x7y6...", "sig": "...", "kid": "2b8d5f3a", "exp": 1699454445, "issuer_id": "issuer:freebird:v1"},
    {"status": "success", "token": "P8o7n6m5...", "sig": "...", "kid": "2b8d5f3a", "exp": 1699454445, "issuer_id": "issuer:freebird:v1"},
    {"status": "error", "message": "invalid base64", "code": "validation_failed"}
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

Verifies a V3 redemption token with expiration checking and replay protection. Supports tokens from multiple issuers in federation scenarios.

**Request:**
```json
{
  "token_b64": "AwAAAA...base64url-encoded-V3-redemption-token..."
}
```

**Fields:**
- `token_b64`: Base64url-encoded V3 redemption token. The token is self-contained — it includes the PRF output, key ID, expiration, issuer ID, and ECDSA signature.

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
- Invalid ECDSA signature
- Unknown issuer (not in trusted issuer list)
- Nullifier already exists in database
- Invalid V3 token format

**Verification Flow:**

The verifier processes V3 redemption tokens:
1. Parses the self-contained V3 token (extracts output, kid, exp, issuer_id, ECDSA sig)
2. Checks expiration with clock skew tolerance
3. Looks up the issuer's public key using `(kid, issuer_id)`
4. Verifies the ECDSA signature over the metadata
5. Derives the nullifier from the PRF output
6. Checks and records the nullifier to prevent reuse

See [FEDERATION.md](FEDERATION.md) for configuration details.

---

### Verify Token Batch

**POST /v1/verify/batch**

Verifies multiple V3 redemption tokens in a single request. Each token is checked independently; failures do not affect other tokens in the batch.

**Request:**
```json
{
  "tokens": [
    {"token_b64": "AwAAAA...first-token..."},
    {"token_b64": "AwAAAA...second-token..."},
    {"token_b64": "AwAAAA...third-token..."}
  ]
}
```

**Response (200 OK):**
```json
{
  "results": [
    {"status": "success", "verified_at": 1699454445},
    {"status": "error", "message": "token expired", "code": "token_expired"},
    {"status": "success", "verified_at": 1699454445}
  ],
  "successful": 2,
  "failed": 1,
  "processing_time_ms": 12,
  "throughput": 250.0
}
```

**Notes:**
- Each result corresponds positionally to the input token.
- Successfully verified tokens are recorded as spent (replay-protected).
- HTTP 200 is returned even if some tokens fail; check each `status` field.

---

### Check Token (Non-Consuming)

**POST /v1/check**

Validates a V3 token's format, expiration, and ECDSA signature **without** recording the nullifier. The token remains valid for future use with `/v1/verify` or other services.

**Use Cases:**
- Verifying a user holds a valid Day Pass before granting access
- Rate-limiting based on token possession without consumption
- Multi-service scenarios where the same token is used across services (e.g., Witness + Clout)

**Request:**
```json
{
  "token_b64": "AwAAAA...base64url-encoded-V3-redemption-token..."
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

**Authentication:** All endpoints require either the `X-Admin-Key` header with the API key, or a valid `freebird_session` cookie set by `POST /admin/login`.

### Session Authentication

**POST /admin/login**

Verifies the API key and sets an HttpOnly session cookie for browser-based admin UI access.

**Request:**
```json
{
  "api_key": "your-admin-api-key"
}
```

**Response (200 OK):**
```json
{"status": "ok"}
```
Sets `freebird_session` cookie (HttpOnly, SameSite=Strict, Max-Age=86400).

**Rate limiting:** Login attempts are rate-limited per IP (5 failures in 5 minutes triggers a 15-minute block).

---

**POST /admin/logout**

Clears the session cookie.

**Request:** No body required.

**Response (200 OK):**
```json
{"status": "ok"}
```
Sets `freebird_session` cookie with `Max-Age=0` to clear it.

---

### Bootstrap: Register Instance Owner

**POST /admin/register-owner**

Registers a user as the owner of this Freebird instance. Only the first registration succeeds; subsequent calls return an error. Used by applications like Clout to tie the instance to its founding user.

**Request:**
```json
{
  "user_id": "alice"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "owner": "alice"
}
```

**Error (400 Bad Request):** If an owner is already registered.

---

### Bootstrap: Add Bootstrap User

**POST /admin/bootstrap/add**

Grants a user a starting allocation of invitations without requiring them to be invited first. Useful for seeding a new instance.

**Request:**
```json
{
  "user_id": "alice",
  "invite_count": 10
}
```

**Response (200 OK):**
```json
{
  "ok": true,
  "user_id": "alice",
  "invites_granted": 10
}
```

---

**Available Endpoints (summary):**
- Session: `POST /admin/login`, `POST /admin/logout`
- Health: `GET /admin/health`
- Stats: `GET /admin/stats`
- Config: `GET /admin/config`
- Metrics: `GET /admin/metrics` (Prometheus format, issuer only)
- Users: `GET /admin/users`, `GET /admin/users/:user_id`, `POST /admin/users/ban`
- Invitations: `GET /admin/invitations`, `POST /admin/invitations/create`, `GET /admin/invitations/:code`
- Invite grants: `POST /admin/invites/grant`
- Bootstrap: `POST /admin/bootstrap/add`, `POST /admin/register-owner`
- Keys: `GET /admin/keys`, `POST /admin/keys/rotate`, `POST /admin/keys/cleanup`, `DELETE /admin/keys/:kid`
- Audit: `GET /admin/audit`
- Exports: `GET /admin/export/invitations`, `GET /admin/export/users`, `GET /admin/export/audit`
- Federation: `GET /admin/federation/vouches`, `POST /admin/federation/vouches`, `DELETE /admin/federation/vouches/:issuer_id`, `GET /admin/federation/revocations`, `POST /admin/federation/revocations`
- Save state: `POST /admin/save`

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
