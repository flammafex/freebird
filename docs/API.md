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
8. [Rate Limiting](#rate-limiting)

---

## Overview

Freebird consists of three HTTP services:

| Service | Port | Purpose | Authentication |
|---------|------|---------|----------------|
| **Issuer** | 8081 | Issue V4 private tokens and V5 public bearer passes | Optional Sybil proof |
| **Verifier** | 8082 | Verify V4 or V5 tokens from trusted issuers | None (public) |
| **Admin** | 8081 | Manage invitation system | API key required |

**Base URLs:**
- Issuer: `http://localhost:8081` (default)
- Verifier: `http://localhost:8082` (default)
- Admin: `http://localhost:8081/admin` (optional)

**Issuer Trust:**
- Verifiers accept tokens only from explicitly configured issuer metadata URLs.
- V4 private verification also requires verifier-side key authority for each
  trusted issuer key.
- Clients fetch verifier metadata before issuance and bind the verifier scope
  into the V4 token.
- V5 public bearer passes are verified with issuer-published RFC 9474 public
  keys. Verifiers accept only immutable `single_use` public-key metadata.

---

## Issuer API

### Get Issuer Metadata

**GET /.well-known/issuer**

Returns public metadata about the issuer for client issuance and verifier configuration.

**Request:**
```bash
curl http://localhost:8081/.well-known/issuer
```

**Response (200 OK):**
```json
{
  "issuer_id": "issuer:freebird:v4",
  "voprf": {
    "suite": "OPRF(P-256, SHA-256)-verifiable",
    "kid": "2b8d5f3a-2024-11-08",
    "pubkey": "A3x5Y2z8B4w7C6v5D4u3E2t1F0s9G8h7I6j5K4l3M2n1"
  },
  "public": {
    "token_type": "public_bearer_pass",
    "token_key_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "rfc9474_variant": "RSABSSA-SHA384-PSS-Deterministic",
    "modulus_bits": 2048,
    "spend_policy": "single_use"
  }
}
```

**Fields:**
- `issuer_id`: Unique identifier for this issuer
- `voprf.suite`: Cryptographic suite identifier
- `voprf.kid`: Key identifier for current active key
- `voprf.pubkey`: Base64-encoded P-256 public key
- `public`: Active V5 public bearer pass summary, when enabled

**Verifier Note:** V4 private verification also requires verifier-side evaluation authority for the issuer key.

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
  "issuer_id": "issuer:freebird:v4",
  "current_epoch": 42,
  "valid_epochs": [40, 41, 42],
  "epoch_duration_sec": 86400,
  "voprf": {
    "suite": "OPRF(P-256, SHA-256)-verifiable",
    "kid": "2b8d5f3a-2024-11-08",
    "pubkey": "A3x5Y2z8B4w7C6v5D4u3E2t1F0s9G8h7I6j5K4l3M2n1"
  },
  "public": [
    {
      "token_key_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "token_type": "public_bearer_pass",
      "rfc9474_variant": "RSABSSA-SHA384-PSS-Deterministic",
      "modulus_bits": 2048,
      "pubkey_spki_b64": "MIIB...",
      "issuer_id": "issuer:freebird:v4",
      "valid_from": 1760000000,
      "valid_until": 1762592000,
      "audience": "community.example",
      "spend_policy": "single_use"
    }
  ]
}
```

**Additional Fields (beyond `/.well-known/issuer`):**
- `current_epoch`: Current epoch number
- `valid_epochs`: List of epochs whose tokens the issuer currently accepts
- `epoch_duration_sec`: Duration of each epoch in seconds
- `public`: Immutable V5 public bearer pass keys. Verifiers drop entries whose
  `spend_policy` is not `single_use` or whose `token_key_id` does not match the
  SHA-256 digest of `pubkey_spki_b64`.

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
  "kid": "2b8d5f3a-2024-11-08",
  "issuer_id": "issuer:freebird:v4",
  "sybil_info": {
    "required": true,
    "passed": true,
    "cost": 0
  }
}
```

**Response Fields:**

- `token`: Base64url-encoded VOPRF evaluation `[VERSION|A|B|DLEQ_proof]` (131 bytes). Used by the client to verify the DLEQ proof and unblind the result. Ephemeral — discarded after client-side finalization.
- `kid`: Key identifier for the VOPRF key used.
- `issuer_id`: Issuer identifier. Needed by the client to build the V4 redemption token.

The client combines these fields with verifier metadata from
`/.well-known/verifier` to build a **V4 redemption token** containing nonce,
verifier scope digest, issuer metadata, and a private-verifiable authenticator.

---

### Issue Public Bearer Pass (Single)

**POST /v1/public/issue**

Issues a V5 public bearer pass blind signature. The client builds the V5
message from `(nonce, token_key_id, issuer_id)`, blinds it with the public key
from `/.well-known/keys`, and finalizes the returned blind signature locally.

**Request:**
```json
{
  "blinded_msg_b64": "A1b2c3d4e5f6...",
  "token_key_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

**Response (200 OK):**
```json
{
  "blind_signature_b64": "m7T8w9x0...",
  "token_key_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "issuer_id": "issuer:freebird:v4"
}
```

The finalized V5 token wire format is:

```text
[VERSION=0x05][nonce(32)][token_key_id(32)][issuer_id_len(1)|issuer_id][sig_len(2,BE)|signature]
```

---

### Issue Public Bearer Pass (Batch)

**POST /v1/public/issue/batch**

**Request:**
```json
{
  "blinded_msgs": [
    "A1b2c3d4e5f6...",
    "B2c3d4e5f6g7..."
  ],
  "token_key_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

**Response:**
```json
{
  "blind_signatures": ["m7T8w9x0...", "n8U9x0y1..."],
  "token_key_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "issuer_id": "issuer:freebird:v4",
  "successful": 2,
  "failed": 0,
  "processing_time_ms": 24,
  "throughput": 83.33
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
    {"status": "success", "token": "Q9w8x7y6...", "kid": "2b8d5f3a", "issuer_id": "issuer:freebird:v4"},
    {"status": "success", "token": "P8o7n6m5...", "kid": "2b8d5f3a", "issuer_id": "issuer:freebird:v4"},
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

### Get Verifier Metadata

**GET /.well-known/verifier**

Returns the verifier scope clients must bind into V4 tokens before issuance.

**Request:**
```bash
curl http://localhost:8082/.well-known/verifier
```

**Response (200 OK):**
```json
{
  "verifier_id": "verifier:example:v4",
  "audience": "example-api",
  "scope_digest_b64": "jm7eGvTH1xt_QpVg4Y48kylFWC8h6Xb6sULa7ppv3jE"
}
```

**Fields:**
- `verifier_id`: Stable identifier for this verifier.
- `audience`: Application or API audience accepted by this verifier.
- `scope_digest_b64`: Base64url-encoded SHA-256 digest of the verifier ID and audience. Clients recompute it locally and place it in the V4 token input.

### Health Check

**GET /health**

Returns the verifier service health status. No authentication required.

**Request:**
```bash
curl http://localhost:8082/health
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

### Verify Token

**POST /v1/verify**

Verifies a V4 redemption token with private authenticator checking and replay protection.

**Request:**
```json
{
  "token_b64": "BAAAAA...base64url-encoded-V4-redemption-token..."
}
```

**Fields:**
- `token_b64`: Base64url-encoded V4 redemption token. The token includes nonce, scope digest, key ID, issuer ID, and a private-verifiable authenticator.

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
- Token already used (replay attack)
- Invalid private authenticator
- Unknown issuer (not in trusted issuer list)
- Missing verifier-side private verification key
- Token scope does not match this verifier
- Nullifier already exists in database
- Invalid V4 token format

**Verification Flow:**

The verifier processes V4 redemption tokens:
1. Parses nonce, scope digest, kid, issuer_id, and authenticator.
2. Constant-time checks the token scope digest against this verifier's configured scope.
3. Looks up the issuer-trusted private verification key for `(issuer_id, kid)`.
4. Recomputes the VOPRF output over the V4 token input.
5. Constant-time compares the recomputed output with the authenticator.
6. Derives and records a verifier-scoped nullifier to prevent reuse.

---

### Verify Token Batch

**POST /v1/verify/batch**

Verifies multiple V4 redemption tokens in a single request. Each token is checked independently; failures do not affect other tokens in the batch.

**Request:**
```json
{
  "tokens": [
    {"token_b64": "BAAAAA...first-token..."},
    {"token_b64": "BAAAAA...second-token..."},
    {"token_b64": "BAAAAA...third-token..."}
  ]
}
```

**Response (200 OK):**
```json
{
  "results": [
    {"status": "success", "verified_at": 1699454445},
    {"status": "error", "message": "verification failed", "code": "verification_failed"},
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

Validates a V4 token's format and private authenticator **without** recording the nullifier. The token remains valid for future use with `/v1/verify` or other services.

**Use Cases:**
- Verifying a user holds a valid Day Pass before granting access
- Rate-limiting based on token possession without consumption
- Multi-service scenarios where the same token is used across services (e.g., Witness + Clout)

**Request:**
```json
{
  "token_b64": "BAAAAA...base64url-encoded-V4-redemption-token..."
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

### Health Check

**GET /admin/health**

Returns the service health status. Requires admin API key.

**Issuer Response (200 OK):**
```json
{
  "service": "issuer",
  "status": "ok",
  "uptime_seconds": 0,
  "invitation_system_status": "operational"
}
```

**Verifier Response (200 OK):**
```json
{
  "service": "verifier",
  "status": "ok",
  "uptime_seconds": 42,
  "store_backend": "redis",
  "issuers_loaded": 1
}
```

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
| 404 | Not Found | Unknown resource |
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

## Rate Limiting

Public endpoints are rate-limited to **30 requests per second per IP address**.
Exceeding this limit returns HTTP 429 with a `Retry-After: 1` header.

Admin endpoints have separate rate limiting; see [Admin API Reference](ADMIN_API.md).

---

## Issuer Trust

**Verifier Configuration:**

To accept tokens from issuers, configure the verifier with trusted issuer
metadata URLs. V4 additionally needs matching private verification keys:

```bash
ISSUER_URL=http://localhost:8081/.well-known/issuer
VERIFIER_SK_PATH=/data/keys/issuer_sk.bin
```

For rotated keys, use `VERIFIER_KEYRING_B64` to provide a JSON map from `kid`
to raw 32-byte key material.

V5 public bearer verification uses public key metadata from the trusted issuer's
`/.well-known/keys` endpoint and does not need verifier-side private key
material.

---

## Related Documentation

- [Issuer Trust](FEDERATION.md) - Verifier trust and key configuration
- [Admin API Reference](ADMIN_API.md) - Complete admin endpoint documentation
- [Configuration Guide](CONFIGURATION.md) - Environment variables and settings
- [How It Works](HOW_IT_WORKS.md) - V4 private and V5 public token flows
