# 🔑 Key Management Guide

Complete guide to cryptographic key lifecycle, rotation, and security.

---

## Overview

Freebird uses **ECDSA P-256** keys for:
- VOPRF evaluation (issuer secret key)
- Invitation signatures (invitation system)
- DLEQ proofs (verifying issuer behavior)

---

## Key Generation

### Automatic Generation

Keys are automatically generated on first run:

```bash
./target/release/issuer
```

**Output:**
```
🔑 No existing key found, generating new P-256 key...
✅ Generated new issuer key
   └─ Saved to: issuer_sk.bin (permissions: 0600)
   └─ Key ID: 2b8d5f3a-2024-11-17
```

**File created:**
- `issuer_sk.bin` - 32-byte P-256 secret key (raw scalar)
- Permissions: 0600 (owner read/write only)
- Atomic writes prevent corruption

### Manual Generation

```bash
# Generate key with OpenSSL
openssl ecparam -genkey -name prime256v1 -noout -out key.pem

# Convert to PKCS#8 DER (Freebird supports this format)
openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER -out issuer_sk.bin

# Set restrictive permissions
chmod 600 issuer_sk.bin
```

---

## Key Storage

### Development

```bash
# Default location
export ISSUER_SK_PATH=issuer_sk.bin

# Start issuer
./target/release/issuer
```

### Production Options

**1. File System (Encrypted Disk)**

```bash
export ISSUER_SK_PATH=/var/lib/freebird/keys/issuer_sk.bin

# Ensure permissions
chmod 600 /var/lib/freebird/keys/issuer_sk.bin
chown freebird:freebird /var/lib/freebird/keys/issuer_sk.bin
```

**2. HashiCorp Vault**

```bash
# Store key in Vault
vault kv put secret/freebird/issuer-key \
  key=@issuer_sk.bin

# Fetch on startup (script)
vault kv get -field=key secret/freebird/issuer-key > /tmp/issuer_sk.bin
export ISSUER_SK_PATH=/tmp/issuer_sk.bin
./target/release/issuer

# Clean up
shred -u /tmp/issuer_sk.bin
```

**3. AWS Secrets Manager**

```bash
# Store key
aws secretsmanager create-secret \
  --name freebird/issuer-key \
  --secret-binary fileb://issuer_sk.bin

# Fetch on startup
aws secretsmanager get-secret-value \
  --secret-id freebird/issuer-key \
  --query SecretBinary \
  --output text | base64 -d > /tmp/issuer_sk.bin
```

**4. Google Cloud Secret Manager**

```bash
# Store key
gcloud secrets create freebird-issuer-key \
  --data-file=issuer_sk.bin

# Fetch on startup
gcloud secrets versions access latest \
  --secret=freebird-issuer-key > /tmp/issuer_sk.bin
```

**5. Hardware Security Module (HSM)** - Roadmap

Future support for:
- AWS CloudHSM
- Google Cloud HSM
- YubiHSM
- PKCS#11 interface

---

## Key Rotation

### Why Rotate Keys?

✅ Limit impact of key compromise  
✅ Meet compliance requirements (PCI-DSS, etc.)  
✅ Best practice for long-lived systems  
✅ Enable key revocation  

**Recommended:** Rotate quarterly (every 90 days)

### Rotation Process

**Step 1: Generate New Key**

```bash
# New key is generated automatically during rotation
curl -X POST http://localhost:8081/admin/keys/rotate \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "new_kid": "freebird-2024-11-17",
    "grace_period_secs": 604800
  }'
```

**Response:**
```json
{
  "ok": true,
  "old_kid": "freebird-2024-08-17",
  "new_kid": "freebird-2024-11-17",
  "grace_period_secs": 604800,
  "expires_at": 1700661245
}
```

**Step 2: Grace Period**

- Old key remains valid for 7 days (604800 seconds)
- New tokens issued with new key
- Old tokens still verify with old key
- Verifiers automatically fetch new metadata

**Step 3: Monitor Transition**

```bash
# Check active keys
curl http://localhost:8081/admin/keys \
  -H "X-Admin-Key: ${ADMIN_KEY}"
```

**Response:**
```json
{
  "keys": [
    {
      "kid": "freebird-2024-11-17",
      "created_at": 1699454445,
      "expires_at": null,
      "is_active": true
    },
    {
      "kid": "freebird-2024-08-17",
      "created_at": 1692118445,
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

**Step 4: Cleanup**

After grace period expires:

```bash
curl -X POST http://localhost:8081/admin/keys/cleanup \
  -H "X-Admin-Key: ${ADMIN_KEY}"
```

---

## Key Backup & Recovery

### Backup Strategy

```bash
#!/bin/bash
# backup-keys.sh

BACKUP_DIR="/var/backups/freebird/keys"
DATE=$(date +%Y%m%d-%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup issuer key
cp /var/lib/freebird/keys/issuer_sk.bin \
   "$BACKUP_DIR/issuer_sk_$DATE.bin"

# Backup key rotation state
cp /var/lib/freebird/keys/key_rotation_state.json \
   "$BACKUP_DIR/rotation_state_$DATE.json"

# Encrypt backups
gpg --encrypt --recipient admin@example.com \
    "$BACKUP_DIR/issuer_sk_$DATE.bin"

gpg --encrypt --recipient admin@example.com \
    "$BACKUP_DIR/rotation_state_$DATE.json"

# Remove unencrypted backups
shred -u "$BACKUP_DIR/issuer_sk_$DATE.bin"
rm "$BACKUP_DIR/rotation_state_$DATE.json"

# Keep last 30 days
find "$BACKUP_DIR" -name "*.gpg" -mtime +30 -delete

echo "✅ Keys backed up to $BACKUP_DIR"
```

**Cron job:**
```bash
# Daily backups at 2 AM
0 2 * * * /usr/local/bin/backup-keys.sh
```

### Recovery Process

**Scenario: Lost issuer key**

```bash
# 1. Stop issuer
systemctl stop freebird-issuer

# 2. Restore from encrypted backup
gpg --decrypt /var/backups/freebird/keys/issuer_sk_20241115-020000.bin.gpg > \
    /var/lib/freebird/keys/issuer_sk.bin

# 3. Set correct permissions
chmod 600 /var/lib/freebird/keys/issuer_sk.bin
chown freebird:freebird /var/lib/freebird/keys/issuer_sk.bin

# 4. Restart issuer
systemctl start freebird-issuer

# 5. Verify
curl http://localhost:8081/.well-known/issuer | jq '.voprf.kid'
```

---

## Key Security

### File Permissions

```bash
# Issuer key
chmod 600 /var/lib/freebird/keys/issuer_sk.bin
chown freebird:freebird /var/lib/freebird/keys/issuer_sk.bin

# Rotation state
chmod 600 /var/lib/freebird/keys/key_rotation_state.json
chown freebird:freebird /var/lib/freebird/keys/key_rotation_state.json
```

### Disk Encryption

```bash
# Enable LUKS encryption (Linux)
cryptsetup luksFormat /dev/sdb
cryptsetup open /dev/sdb freebird_keys

# Create filesystem
mkfs.ext4 /dev/mapper/freebird_keys

# Mount
mkdir -p /var/lib/freebird/keys
mount /dev/mapper/freebird_keys /var/lib/freebird/keys
```

### SELinux / AppArmor

**SELinux:**
```bash
# Create policy for freebird
semanage fcontext -a -t freebird_key_t "/var/lib/freebird/keys(/.*)?"
restorecon -Rv /var/lib/freebird/keys
```

**AppArmor:**
```bash
# /etc/apparmor.d/usr.local.bin.freebird-issuer
/var/lib/freebird/keys/issuer_sk.bin r,
/var/lib/freebird/keys/key_rotation_state.json rw,
```

---

## Emergency Key Revocation

**Scenario: Key compromise detected**

**Step 1: Force remove compromised key**

```bash
curl -X DELETE http://localhost:8081/admin/keys/compromised-key-id \
  -H "X-Admin-Key: ${ADMIN_KEY}"
```

**⚠️ Warning:** This immediately invalidates ALL tokens issued with this key.

**Step 2: Rotate to new key immediately**

```bash
curl -X POST http://localhost:8081/admin/keys/rotate \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -d '{
    "new_kid": "emergency-key-$(date +%Y%m%d)",
    "grace_period_secs": 0
  }'
```

**Step 3: Notify users**

```
SECURITY ALERT: Key Rotation

We have rotated our cryptographic keys as a precautionary measure.

Action Required:
- All existing tokens are now invalid
- Please request new tokens
- No action needed for future tokens

Timeline: Immediate effect
Impact: All active tokens invalidated

Questions? Contact security@example.com
```

---

## Monitoring & Auditing

### Key Usage Metrics

```bash
# Prometheus metrics (future)
freebird_issuer_key_rotations_total
freebird_issuer_active_keys
freebird_issuer_grace_period_keys
freebird_issuer_key_age_seconds
```

### Audit Logs

```bash
# Track key operations
2024-11-17T10:00:00Z [INFO] Key rotation initiated: freebird-2024-11-17
2024-11-17T10:00:01Z [INFO] Old key deprecated: freebird-2024-08-17
2024-11-17T10:00:01Z [INFO] Grace period: 604800 seconds
2024-11-17T10:00:01Z [INFO] Key rotation complete

2024-11-17T10:15:00Z [WARN] Key access: issuer_sk.bin by user:freebird
2024-11-17T10:15:00Z [INFO] Issuer started with kid: freebird-2024-11-17
```

---

## Best Practices

### Development

✅ Use separate keys per environment  
✅ Commit `.gitignore` for key files  
✅ Never commit keys to version control  
✅ Use test keys for CI/CD  

### Staging

✅ Use production-like key management  
✅ Practice rotation procedures  
✅ Test backup/recovery processes  
✅ Separate keys from production  

### Production

✅ Use HSM or secret manager  
✅ Rotate keys quarterly  
✅ Monitor key access  
✅ Encrypt backups  
✅ Test recovery procedures  
✅ Have emergency revocation plan  

---

## Related Documentation

- [Configuration](CONFIGURATION.md) - Key-related environment variables
- [Admin API](ADMIN_API.md) - Key rotation endpoints
- [Security Model](SECURITY.md) - Cryptographic assumptions
- [Production Guide](PRODUCTION.md) - Deployment best practices

---

**Key management is critical. Follow best practices and test recovery procedures regularly.**