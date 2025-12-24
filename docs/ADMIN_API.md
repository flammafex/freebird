# Admin API Reference

Complete HTTP API for managing Freebird issuer and verifier services. The Admin API provides endpoints for user management, invitation handling, key rotation, Sybil configuration, audit logs, and system monitoring.

---

## Overview

The Admin API provides administrative endpoints for both issuer and verifier services:

**Shared Endpoints:**
- Health checks and system statistics
- Configuration inspection
- Prometheus metrics

**Issuer-Only Endpoints:**
- User management (list, inspect, ban)
- Invitation management (create, grant, list)
- Key rotation and lifecycle
- Sybil resistance configuration
- Audit logs
- WebAuthn credential management

**Verifier-Only Endpoints:**
- Trusted issuer management
- Replay cache operations

**Requirements:**
- `ADMIN_API_KEY` environment variable must be set (minimum 32 characters)
- All requests (except health check) require `X-Admin-Key` header for authentication

---

## Configuration

```bash
# Enable Admin API
export ADMIN_API_KEY=your-secure-random-key-at-least-32-characters

# Optional: Configure admin port (default: same as service port)
export ADMIN_PORT=8081
```

**Security Notes:**
- API key must be cryptographically random and at least 32 characters
- Rotate keys regularly (quarterly recommended)
- Restrict admin endpoints to internal networks only (firewall rules)
- Enable TLS/HTTPS for admin traffic in production
- Never commit `ADMIN_API_KEY` to version control

---

## Authentication

All Admin API endpoints require the `X-Admin-Key` header:

```bash
curl http://localhost:8081/admin/stats \
  -H "X-Admin-Key: your-admin-api-key"
```

**Error Response (401 Unauthorized):**
```json
{
  "error": "unauthorized"
}
```

---

## Endpoints

### Health Check

**GET /admin/health**

Check admin API availability and detect service type (no authentication required).

**Response:**
```json
{
  "status": "ok",
  "service": "issuer",
  "uptime_seconds": 3600,
  "version": "0.1.0"
}
```

The `service` field indicates which service is running (`issuer` or `verifier`). The admin UI uses this to show appropriate tabs and features.

---

### System Statistics

**GET /admin/stats**

Get system statistics. Response varies based on service type and Sybil mechanism.

**Example:**
```bash
curl http://localhost:8081/admin/stats \
  -H "X-Admin-Key: your-admin-api-key"
```

**Issuer Response (invitation mode):**
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

**Verifier Response:**
```json
{
  "stats": {
    "verifications_total": 50000,
    "verifications_success": 49500,
    "trusted_issuers": 3,
    "cache_size": 12500
  },
  "epoch": 1699454445,
  "uptime_seconds": 86400
}
```

---

### Configuration

**GET /admin/config**

Get current configuration values (sensitive values are redacted).

**Example:**
```bash
curl http://localhost:8081/admin/config \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response:**
```json
{
  "sybil_resistance": "invitation",
  "epoch_length_seconds": 86400,
  "invite_per_user": 5,
  "invite_cooldown": "24h",
  "invite_expiration": "30d"
}
```

---

### Prometheus Metrics

**GET /admin/metrics**

Get Prometheus-format metrics for monitoring systems.

**Example:**
```bash
curl http://localhost:8081/admin/metrics \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response:**
```
# HELP freebird_tokens_issued_total Total tokens issued
# TYPE freebird_tokens_issued_total counter
freebird_tokens_issued_total 12500

# HELP freebird_verifications_total Total verifications
# TYPE freebird_verifications_total counter
freebird_verifications_total{result="success"} 49500
freebird_verifications_total{result="failure"} 500

# HELP freebird_active_users Current active users
# TYPE freebird_active_users gauge
freebird_active_users 120
```

---

## Issuer Endpoints

### Grant Invites

**POST /admin/invites/grant**

Grant additional invitations to a user (reputation rewards).

**Request Body:**
```json
{
  "user_id": "user123",
  "count": 10
}
```

**Example:**
```bash
curl -X POST http://localhost:8081/admin/invites/grant \
  -H "X-Admin-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user123",
    "count": 10
  }'
```

**Response (200 OK):**
```json
{
  "ok": true,
  "user_id": "user123",
  "invites_granted": 10,
  "new_total": 15
}
```

**Error Responses:**

*404 Not Found - User doesn't exist:*
```json
{
  "error": "user not found: user123"
}
```

*400 Bad Request - User is banned:*
```json
{
  "error": "cannot grant invites to banned user"
}
```

*400 Bad Request - Invalid count:*
```json
{
  "error": "invalid request: count must be greater than 0"
}
```

---

### Ban User

**POST /admin/users/ban**

Ban a user and optionally their entire invite tree.

**Request Body:**
```json
{
  "user_id": "malicious_user",
  "ban_tree": true
}
```

**Parameters:**
- `user_id` (required): User to ban
- `ban_tree` (optional, default: false): Recursively ban all users they invited

**Example:**
```bash
curl -X POST http://localhost:8081/admin/users/ban \
  -H "X-Admin-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "malicious_user",
    "ban_tree": true
  }'
```

**Response (200 OK):**
```json
{
  "ok": true,
  "user_id": "malicious_user",
  "banned_count": 7
}
```

**Fields:**
- `banned_count`: Number of users banned (including the target and their invite tree)

**Ban Tree Example:**

```
admin → alice → bob → charlie
              → david
```

Banning `alice` with `ban_tree: true` will ban: alice, bob, charlie, david (4 users total).

---

### Add Bootstrap User

**POST /admin/bootstrap/add**

Add a new bootstrap user with initial invitations.

**Request Body:**
```json
{
  "user_id": "newadmin",
  "invite_count": 50
}
```

**Example:**
```bash
curl -X POST http://localhost:8081/admin/bootstrap/add \
  -H "X-Admin-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "newadmin",
    "invite_count": 50
  }'
```

**Response (200 OK):**
```json
{
  "ok": true,
  "user_id": "newadmin",
  "invites_granted": 50
}
```

**Note:** Bootstrap users bypass the normal waiting period and can immediately invite others.

---

### List Users

**GET /admin/users**

List all users with optional filtering and pagination.

**Query Parameters:**
- `limit` (optional): Maximum results to return (default: 100)
- `offset` (optional): Pagination offset (default: 0)
- `filter` (optional): Filter by status (`active`, `banned`, `all`)

**Example:**
```bash
curl "http://localhost:8081/admin/users?limit=50&filter=active" \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response:**
```json
{
  "users": [
    {
      "user_id": "alice",
      "invites_remaining": 3,
      "reputation": 1.0,
      "banned": false,
      "joined_at": 1699000000
    },
    {
      "user_id": "bob",
      "invites_remaining": 5,
      "reputation": 0.8,
      "banned": false,
      "joined_at": 1699100000
    }
  ],
  "total": 120,
  "limit": 50,
  "offset": 0
}
```

---

### Get User Details

**GET /admin/users/:user_id**

Get detailed information about a user and their invite tree.

**Example:**
```bash
curl http://localhost:8081/admin/users/alice \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response (200 OK):**
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

**Error Response (404 Not Found):**
```json
{
  "error": "user not found: nonexistent_user"
}
```

---

### Create Invitations

**POST /admin/invitations/create**

Create cryptographically signed invitation codes for a user.

**Request Body:**
```json
{
  "user_id": "alice",
  "count": 5
}
```

**Example:**
```bash
curl -X POST http://localhost:8081/admin/invitations/create \
  -H "X-Admin-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "alice",
    "count": 5
  }'
```

**Response (200 OK):**
```json
{
  "ok": true,
  "invitations": [
    {
      "code": "Abc123XyZ456",
      "expires_at": 1701592000
    },
    {
      "code": "Def789UvW012",
      "expires_at": 1701592000
    }
  ]
}
```

---

### List Invitations

**GET /admin/invitations**

List all invitations with optional filtering.

**Query Parameters:**
- `status` (optional): Filter by status (`pending`, `redeemed`, `expired`, `all`)
- `user_id` (optional): Filter by inviter
- `limit` (optional): Maximum results (default: 100)

**Example:**
```bash
curl "http://localhost:8081/admin/invitations?status=pending&limit=50" \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response:**
```json
{
  "invitations": [
    {
      "code": "Abc123XyZ456",
      "inviter_id": "alice",
      "created_at": 1699000000,
      "expires_at": 1701592000,
      "redeemed": false
    },
    {
      "code": "Xyz789Abc123",
      "inviter_id": "bob",
      "created_at": 1699100000,
      "expires_at": 1701692000,
      "redeemed": true,
      "invitee_id": "charlie"
    }
  ],
  "total": 150
}
```

---

### Get Invitation Details

**GET /admin/invitations/:code**

Get detailed information about a specific invitation.

**Example:**
```bash
curl http://localhost:8081/admin/invitations/Abc123XyZ456 \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response (200 OK):**
```json
{
  "code": "Abc123XyZ456",
  "inviter_id": "alice",
  "invitee_id": "bob",
  "created_at": 1699000000,
  "expires_at": 1701592000,
  "signature": "3045022100...",
  "redeemed": true
}
```

**Fields:**
- `invitee_id`: Present only if invitation has been redeemed
- `redeemed`: Boolean indicating redemption status

**Error Response (404 Not Found):**
```json
{
  "error": "invitation not found: InvalidCode"
}
```

---

### Manual State Persistence

**POST /admin/save**

Manually trigger state persistence to disk.

**Example:**
```bash
curl -X POST http://localhost:8081/admin/save \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response (200 OK):**
```json
{
  "ok": true,
  "message": "State saved successfully"
}
```

**Note:** State is automatically saved at configured intervals (`SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS`). This endpoint is for manual backups or before maintenance windows.

---

## Key Management Endpoints

### List Keys

**GET /admin/keys**

List all VOPRF keys (active and deprecated) with statistics.

**Example:**
```bash
curl http://localhost:8081/admin/keys \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response (200 OK):**
```json
{
  "keys": [
    {
      "kid": "freebird-2024-11-15",
      "created_at": 1699454445,
      "expires_at": null,
      "is_active": true
    },
    {
      "kid": "freebird-2024-11-08",
      "created_at": 1698849645,
      "expires_at": 1700059245,
      "is_active": false
    }
  ],
  "stats": {
    "total_keys": 2,
    "active_keys": 1,
    "grace_period_keys": 1,
    "expired_keys": 0
  }
}
```

**Key States:**
- `is_active: true` → Currently issuing tokens with this key
- `is_active: false, expires_at: <future>` → In grace period (still verifying old tokens)
- `is_active: false, expires_at: <past>` → Expired (should be cleaned up)

---

### Rotate Key

**POST /admin/keys/rotate**

Rotate to a new VOPRF key with a grace period.

**Request Body:**
```json
{
  "new_kid": "freebird-2024-11-15",
  "grace_period_secs": 604800
}
```

**Parameters:**
- `new_kid` (required): Key identifier for the new key
- `grace_period_secs` (optional): How long old key remains valid (default: 7 days)

**Example:**
```bash
curl -X POST http://localhost:8081/admin/keys/rotate \
  -H "X-Admin-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "new_kid": "freebird-2024-11-15",
    "grace_period_secs": 604800
  }'
```

**Response (200 OK):**
```json
{
  "ok": true,
  "old_kid": "freebird-2024-11-08",
  "new_kid": "freebird-2024-11-15",
  "grace_period_secs": 604800,
  "expires_at": 1700661245
}
```

**Workflow:**
1. New key is generated and becomes active
2. Old key enters grace period (still verifies existing tokens)
3. After grace period expires, old key can be cleaned up
4. Verifiers automatically fetch new key metadata

**Best Practices:**
- Rotate keys quarterly
- Use 7-14 day grace periods for smooth transitions
- Monitor verification metrics during rotation
- Test key rotation in staging first

---

### Cleanup Expired Keys

**POST /admin/keys/cleanup**

Remove all expired deprecated keys.

**Example:**
```bash
curl -X POST http://localhost:8081/admin/keys/cleanup \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response (200 OK):**
```json
{
  "ok": true,
  "removed_count": 2,
  "removed_kids": ["freebird-2024-09-01", "freebird-2024-10-01"]
}
```

**Note:** This endpoint is safe to call anytime. It only removes keys whose grace period has fully expired. Active keys and keys in grace period are never removed.

**Automatic Cleanup:**

Freebird runs daily automatic cleanup:
```
[2024-11-17T10:00:00Z INFO freebird] Automatic cleanup removed 2 expired keys
```

---

### Force Remove Key

**DELETE /admin/keys/:kid**

Immediately remove a specific key, even if still in grace period.

**⚠️ Warning:** This invalidates ALL tokens issued with this key, potentially disrupting users.

**Example:**
```bash
curl -X DELETE http://localhost:8081/admin/keys/compromised-key \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response (200 OK):**
```json
{
  "ok": true,
  "kid": "compromised-key",
  "message": "Key forcibly removed. Tokens issued with this key are now invalid."
}
```

**Use Cases:**
- Key compromise (private key leaked)
- Emergency revocation
- Testing key revocation procedures

**Error Response (404 Not Found):**
```json
{
  "error": "key not found: nonexistent-key"
}
```

---

### Audit Logs

**GET /admin/audit**

Retrieve system audit logs with filtering.

**Query Parameters:**
- `level` (optional): Filter by level (`info`, `warning`, `error`, `success`)
- `search` (optional): Search logs by keyword
- `limit` (optional): Maximum results (default: 100)
- `since` (optional): Unix timestamp for earliest log entry

**Example:**
```bash
curl "http://localhost:8081/admin/audit?level=error&limit=50" \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response:**
```json
{
  "logs": [
    {
      "timestamp": 1699454445,
      "level": "error",
      "action": "ban_user",
      "message": "User banned: spammer",
      "details": {
        "user_id": "spammer",
        "ban_tree": true,
        "banned_count": 7
      }
    },
    {
      "timestamp": 1699454400,
      "level": "info",
      "action": "key_rotate",
      "message": "Key rotated: freebird-2024-Q4"
    }
  ],
  "total": 1250
}
```

---

### Sybil Configuration

**GET /admin/sybil/config**

Get current Sybil resistance configuration.

**Example:**
```bash
curl http://localhost:8081/admin/sybil/config \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response:**
```json
{
  "mechanism": "invitation",
  "invite_per_user": 5,
  "invite_cooldown_seconds": 86400,
  "invite_expiration_seconds": 2592000,
  "pow_difficulty": 20,
  "rate_limit_requests": 100,
  "rate_limit_window_seconds": 3600
}
```

---

**PUT /admin/sybil/config**

Update Sybil resistance configuration. Changes take effect immediately.

**Request Body:**
```json
{
  "invite_per_user": 10,
  "invite_cooldown_seconds": 43200
}
```

**Example:**
```bash
curl -X PUT http://localhost:8081/admin/sybil/config \
  -H "X-Admin-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "invite_per_user": 10,
    "invite_cooldown_seconds": 43200
  }'
```

**Response:**
```json
{
  "ok": true,
  "updated_fields": ["invite_per_user", "invite_cooldown_seconds"],
  "config": {
    "mechanism": "invitation",
    "invite_per_user": 10,
    "invite_cooldown_seconds": 43200,
    "invite_expiration_seconds": 2592000
  }
}
```

---

### WebAuthn Endpoints

**POST /admin/webauthn/register**

Begin WebAuthn credential registration.

**Request Body:**
```json
{
  "user_id": "alice",
  "display_name": "Alice's YubiKey"
}
```

**Response:**
```json
{
  "challenge": "base64-encoded-challenge",
  "rp": {
    "name": "Freebird",
    "id": "example.com"
  },
  "user": {
    "id": "base64-user-id",
    "name": "alice",
    "displayName": "Alice's YubiKey"
  },
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -7}
  ]
}
```

---

**GET /admin/webauthn/credentials**

List all registered WebAuthn credentials.

**Example:**
```bash
curl http://localhost:8081/admin/webauthn/credentials \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response:**
```json
{
  "credentials": [
    {
      "credential_id": "base64-credential-id",
      "user_id": "alice",
      "display_name": "Alice's YubiKey",
      "created_at": 1699000000,
      "last_used": 1699400000,
      "sign_count": 42
    }
  ]
}
```

---

**POST /admin/webauthn/credentials/remove**

Remove a WebAuthn credential.

**Request Body:**
```json
{
  "credential_id": "base64-credential-id"
}
```

**Response:**
```json
{
  "ok": true,
  "credential_id": "base64-credential-id"
}
```

---

## Verifier Endpoints

These endpoints are only available on verifier services.

### List Trusted Issuers

**GET /admin/issuers**

List all configured trusted issuers.

**Example:**
```bash
curl http://localhost:8082/admin/issuers \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response:**
```json
{
  "issuers": [
    {
      "id": "primary",
      "url": "https://issuer.example.com",
      "public_key": "base64-public-key",
      "context": "example.com",
      "last_refresh": 1699454445,
      "status": "active"
    }
  ]
}
```

---

### Get Issuer Details

**GET /admin/issuers/:id**

Get detailed information about a trusted issuer.

**Response:**
```json
{
  "id": "primary",
  "url": "https://issuer.example.com",
  "public_key": "base64-public-key",
  "context": "example.com",
  "expires_at": 1704067200,
  "last_refresh": 1699454445,
  "refresh_interval_seconds": 3600,
  "status": "active",
  "verification_stats": {
    "total": 50000,
    "success": 49500,
    "failure": 500
  }
}
```

---

### Refresh Issuer Metadata

**POST /admin/issuers/:id/refresh**

Manually trigger a metadata refresh for an issuer.

**Example:**
```bash
curl -X POST http://localhost:8082/admin/issuers/primary/refresh \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response:**
```json
{
  "ok": true,
  "issuer_id": "primary",
  "public_key_updated": true,
  "new_expiration": 1704067200
}
```

---

### Cache Statistics

**GET /admin/cache/stats**

Get replay cache statistics.

**Example:**
```bash
curl http://localhost:8082/admin/cache/stats \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response:**
```json
{
  "backend": "redis",
  "entries": 125000,
  "memory_bytes": 15000000,
  "hit_rate": 0.95,
  "evictions": 500,
  "oldest_entry": 1699368045
}
```

---

### Clear Cache

**POST /admin/cache/clear**

Clear the replay cache. Use with caution—allows token replay until new entries accumulate.

**Example:**
```bash
curl -X POST http://localhost:8082/admin/cache/clear \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response:**
```json
{
  "ok": true,
  "entries_cleared": 125000
}
```

---

## Error Handling

All admin endpoints return structured JSON errors:

### Common Error Codes

**401 Unauthorized:**
```json
{
  "error": "unauthorized"
}
```
- Cause: Missing or invalid `X-Admin-Key` header
- Solution: Check API key matches `ADMIN_API_KEY` environment variable

**404 Not Found:**
```json
{
  "error": "user not found: username"
}
```
- Cause: Requested resource doesn't exist
- Solution: Verify user/invitation/key ID is correct

**400 Bad Request:**
```json
{
  "error": "invalid request: count must be greater than 0"
}
```
- Cause: Invalid request parameters
- Solution: Check request body matches API spec

**500 Internal Server Error:**
```json
{
  "error": "internal server error"
}
```
- Cause: Server-side error (e.g., failed to save state)
- Solution: Check server logs for details

---

## Complete Example Workflow

### 1. Bootstrap Initial Users

```bash
# Add admin user
curl -X POST http://localhost:8081/admin/bootstrap/add \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "admin", "invite_count": 100}'

# Add secondary admins
curl -X POST http://localhost:8081/admin/bootstrap/add \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice", "invite_count": 50}'
```

### 2. Monitor System Health

```bash
# Check statistics
curl http://localhost:8081/admin/stats \
  -H "X-Admin-Key: ${ADMIN_KEY}"

# Inspect specific user
curl http://localhost:8081/admin/users/alice \
  -H "X-Admin-Key: ${ADMIN_KEY}"
```

### 3. Handle Abuse

```bash
# Ban malicious user and their invite tree
curl -X POST http://localhost:8081/admin/users/ban \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "spammer", "ban_tree": true}'

# Check impact
curl http://localhost:8081/admin/stats \
  -H "X-Admin-Key: ${ADMIN_KEY}"
```

### 4. Reward Good Users

```bash
# Grant extra invites for reputation
curl -X POST http://localhost:8081/admin/invites/grant \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "trusted_user", "count": 20}'
```

### 5. Rotate Keys (Quarterly)

```bash
# List current keys
curl http://localhost:8081/admin/keys \
  -H "X-Admin-Key: ${ADMIN_KEY}"

# Rotate to new key
curl -X POST http://localhost:8081/admin/keys/rotate \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"new_kid": "freebird-2024-Q4", "grace_period_secs": 1209600}'

# After grace period, clean up
curl -X POST http://localhost:8081/admin/keys/cleanup \
  -H "X-Admin-Key: ${ADMIN_KEY}"
```

### 6. Manual Backup Before Maintenance

```bash
# Trigger state save
curl -X POST http://localhost:8081/admin/save \
  -H "X-Admin-Key: ${ADMIN_KEY}"

# Backup files
cp invitations.json invitations.backup.$(date +%Y%m%d).json
cp key_rotation_state.json keys.backup.$(date +%Y%m%d).json
```

---

## Security Best Practices

### API Key Management

✅ **DO:**
- Generate keys with cryptographically secure random sources
- Use at least 32 characters (ideally 64+)
- Store in environment variables or secret managers
- Rotate keys quarterly
- Use separate keys per environment (dev/staging/prod)
- Monitor failed authentication attempts

❌ **DON'T:**
- Commit keys to version control
- Share keys via email/Slack/unencrypted channels
- Reuse keys across services
- Use predictable patterns (e.g., "admin-password-123")
- Log keys in application logs

### Network Security

✅ **DO:**
- Restrict admin endpoints to internal networks only
- Use firewall rules to block public access
- Enable TLS/HTTPS for all admin traffic
- Use VPN or bastion hosts for remote admin access
- Implement rate limiting on admin endpoints

❌ **DON'T:**
- Expose admin API to public internet
- Rely solely on API key for security (defense in depth)
- Allow admin access over unencrypted connections

### Operational Security

✅ **DO:**
- Log all admin API access with request details
- Monitor for suspicious patterns (mass bans, excessive grants)
- Set up alerting for unusual admin activity
- Review admin logs regularly
- Have incident response procedures for compromised keys

❌ **DON'T:**
- Ignore failed authentication attempts
- Share admin access credentials
- Skip logging for "internal" operations

---

## Troubleshooting

### "Admin API disabled" on startup

**Causes:**
1. `ADMIN_API_KEY` not set
2. API key is too short (< 32 characters)
3. Invitation-based Sybil resistance not enabled

**Solution:**
```bash
export ADMIN_API_KEY=your-secure-key-at-least-32-characters
export SYBIL_RESISTANCE=invitation
./target/release/issuer
```

### 401 Unauthorized on all requests

**Causes:**
1. Missing `X-Admin-Key` header
2. Wrong API key value
3. Extra whitespace in header

**Solution:**
```bash
# Check header is present
curl -v http://localhost:8081/admin/stats \
  -H "X-Admin-Key: ${ADMIN_KEY}"

# Verify environment variable
echo $ADMIN_KEY
```

### "User not found" after restart

**Cause:** State persistence file not loading

**Solution:**
```bash
# Check persistence path
ls -la invitations.json

# Verify file permissions
chmod 600 invitations.json

# Check issuer logs for load errors
./target/release/issuer 2>&1 | grep -i "invitation"
```

### Key rotation breaks token verification

**Causes:**
1. Verifier not refreshing issuer metadata
2. Grace period too short
3. Clock skew between issuer and verifier

**Solution:**
```bash
# Check verifier refresh interval
export REFRESH_INTERVAL_MIN=5  # Refresh every 5 minutes

# Extend grace period
# Use 7-14 days for production
curl -X POST http://localhost:8081/admin/keys/rotate \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -d '{"new_kid": "new-key", "grace_period_secs": 1209600}'

# Check clock synchronization
ntpdate -q pool.ntp.org
```

---

## Related Documentation

- [Configuration Reference](CONFIGURATION.md) - All environment variables
- [Sybil Resistance](SYBIL_RESISTANCE.md) - Sybil mechanism comparison
- [Key Management](KEY_MANAGEMENT.md) - Key generation, rotation, security
- [WebAuthn](WEBAUTHN.md) - Hardware authenticator integration
- [Federation](FEDERATION.md) - Multi-issuer trust
- [Production Deployment](PRODUCTION.md) - Security hardening checklist
- [Troubleshooting Guide](TROUBLESHOOTING.md) - Common issues and solutions
- [Admin UI](../admin-ui/README.md) - Web dashboard documentation