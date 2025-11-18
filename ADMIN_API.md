# 🔧 Admin API Reference

Complete HTTP API for managing the Freebird invitation system and key rotation.

---

## Overview

The Admin API provides administrative endpoints for:
- Managing invitations (grant, inspect)
- User management (ban, bootstrap)
- System statistics
- Key rotation
- State persistence

**Requirements:**
- Invitation-based Sybil resistance must be enabled
- `ADMIN_API_KEY` environment variable must be set (minimum 32 characters)
- All requests require `X-Admin-Key` header for authentication

---

## Configuration

```bash
# Enable Admin API (requires invitation system)
export SYBIL_RESISTANCE=invitation
export ADMIN_API_KEY=your-secure-random-key-at-least-32-characters

# Optionally configure invitation system
export SYBIL_INVITE_PER_USER=5
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:100,alice:50
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

Check admin API availability (no authentication required).

**Response:**
```json
{
  "status": "ok",
  "uptime_seconds": 3600,
  "invitation_system_status": "operational"
}
```

---

### System Statistics

**GET /admin/stats**

Get invitation system statistics.

**Example:**
```bash
curl http://localhost:8081/admin/stats \
  -H "X-Admin-Key: your-admin-api-key"
```

**Response:**
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

---

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
  "error": "user not found: nonexistent-key"
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

- [Invitation System Guide](INVITATION_SYSTEM.md) - Deep dive into invitation mechanics
- [Key Management](KEY_MANAGEMENT.md) - Key generation, rotation, security
- [Configuration Reference](CONFIGURATION.md) - All environment variables
- [Production Deployment](PRODUCTION.md) - Best practices and security checklist
- [Troubleshooting Guide](TROUBLESHOOTING.md) - Common issues and solutions

---

**Questions or Issues?**

Open a GitHub issue or check our [troubleshooting guide](TROUBLESHOOTING.md) for common problems.