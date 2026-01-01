# 🏭 Production Deployment Guide

Complete checklist and best practices for deploying Freebird in production.

---

## Pre-Deployment Checklist

### Infrastructure

```
□ Separate servers for issuer and verifier
□ Different VPCs or cloud accounts
□ Firewall rules configured
□ Load balancer setup (if needed)
□ Monitoring and alerting configured
□ Log aggregation enabled
□ Backup strategy implemented
□ Disaster recovery plan documented
```

### Security

```
□ TLS/HTTPS enabled for all communications
□ Keys stored in HSM or secret manager
□ File permissions set correctly (0600 for keys)
□ SELinux/AppArmor policies configured
□ Admin API restricted to internal network
□ Strong admin API key generated (48+ characters)
□ Environment variables secured (no .env files in public)
□ Security audit completed (if applicable)
```

### Configuration

```
□ ISSUER_ID unique and versioned
□ TOKEN_TTL_MIN appropriate for use case
□ REQUIRE_TLS=true
□ BEHIND_PROXY=true (if using reverse proxy)
□ SYBIL_RESISTANCE configured
□ REDIS_URL set for verifier
□ MAX_CLOCK_SKEW_SECS reasonable (300s default)
□ Key rotation schedule established
```

---

## Deployment Architecture

### Recommended Setup

```
┌─────────────────────────────────────────────────┐
│              Load Balancer (TLS)                │
│         (nginx, Caddy, or cloud LB)             │
└─────┬──────────────────────────┬────────────────┘
      │                          │
      │ /v1/oprf/* │ /v1/verify
      ▼                          ▼
┌─────────────┐            ┌──────────────┐
│   Issuer    │            │   Verifier   │
│  (8081)     │            │   (8082)     │
│             │            │              │
│ - VOPRF     │            │ - Verify     │
│ - Sybil     │            │ - Nullifiers │
│ - Admin API │            └──────┬───────┘
└─────┬───────┘                   │
      │                           │
      │ State                     │ Nullifiers
      ▼                           ▼
┌──────────────┐           ┌──────────────┐
│ Persistence  │           │    Redis     │
│ invitations  │           │              │
│  .json       │           │              │
└──────────────┘           └──────────────┘
```

---

## Container Deployment (Docker)

Freebird provides official Docker images for containerized deployments. This is the recommended approach for Kubernetes, ECS, or Docker Swarm.

### Docker Compose (Production Base)

```yaml
services:
  issuer:
    image: freebird/issuer:latest
    restart: always
    ports:
      - "127.0.0.1:8081:8081"  # Bind to localhost, use Nginx for TLS
    volumes:
      - ./data/keys:/data/keys           # Persist VOPRF keys
      - ./data/state:/data/state         # Persist invitations
    environment:
      - ISSUER_ID=issuer:prod:v1
      - BIND_ADDR=0.0.0.0:8081
      - REQUIRE_TLS=true
      - BEHIND_PROXY=true
      - SYBIL_RESISTANCE=invitation
      - ADMIN_API_KEY=${ADMIN_API_KEY}   # Pass via secrets
      # Paths inside container
      - ISSUER_SK_PATH=/data/keys/issuer_sk.bin
      - KEY_ROTATION_STATE_PATH=/data/keys/key_rotation_state.json
      - SYBIL_INVITE_PERSISTENCE_PATH=/data/state/invitations.json

  verifier:
    image: freebird/verifier:latest
    restart: always
    ports:
      - "127.0.0.1:8082:8082"
    environment:
      - BIND_ADDR=0.0.0.0:8082
      - ISSUER_URL=[https://issuer.example.com/.well-known/issuer](https://issuer.example.com/.well-known/issuer)
      - REDIS_URL=redis://redis.internal:6379
    depends_on:
      - redis

  redis:
    image: redis:alpine
    restart: always
    volumes:
      - ./data/redis:/data
    command: redis-server --appendonly yes
```

### Kubernetes Considerations

1.  **Secrets Management:**
    * Mount the issuer's secret key (`issuer_sk.bin`) via a Kubernetes Secret or Vault sidecar. Do not generate it inside the ephemeral container unless you have a persistent volume.
    * Pass `ADMIN_API_KEY` as an environment variable from a Secret.

2.  **Networking:**
    * **Issuer:** Expose publicly via Ingress (TLS termination).
    * **Verifier:** Can be internal-only if verifying services run in the same cluster. If external clients verify, expose via Ingress.
    * **Redis:** Keep strictly internal.

3.  **Volume Mounts:**
    * The Issuer requires a **PersistentVolume (PV)** for:
        * `/data/keys` (if not using Vault)
        * `/data/state` (for invitation system)

---

## Systemd Service Files

If running on bare metal without Docker:

### Issuer Service

```ini
# /etc/systemd/system/freebird-issuer.service

[Unit]
Description=Freebird Anonymous Token Issuer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=freebird
Group=freebird
WorkingDirectory=/opt/freebird
EnvironmentFile=/etc/freebird/issuer.env
ExecStart=/opt/freebird/issuer
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/freebird

[Install]
WantedBy=multi-user.target
```

### Verifier Service

```ini
# /etc/systemd/system/freebird-verifier.service

[Unit]
Description=Freebird Anonymous Token Verifier
After=network-online.target redis.service
Wants=network-online.target
Requires=redis.service

[Service]
Type=simple
User=freebird
Group=freebird
WorkingDirectory=/opt/freebird
EnvironmentFile=/etc/freebird/verifier.env
ExecStart=/opt/freebird/verifier
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable services
sudo systemctl enable freebird-issuer
sudo systemctl enable freebird-verifier

# Start services
sudo systemctl start freebird-issuer
sudo systemctl start freebird-verifier

# Check status
sudo systemctl status freebird-issuer
sudo systemctl status freebird-verifier

# View logs
sudo journalctl -u freebird-issuer -f
sudo journalctl -u freebird-verifier -f
```

---

## Reverse Proxy Configuration

### Nginx

```nginx
# /etc/nginx/sites-available/freebird

# Rate limiting
limit_req_zone $binary_remote_addr zone=issue:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=verify:10m rate=100r/s;
limit_req_zone $binary_remote_addr zone=admin:10m rate=5r/s;

# Issuer
server {
    listen 443 ssl http2;
    server_name issuer.example.com;

    ssl_certificate /etc/letsencrypt/live/[issuer.example.com/fullchain.pem](https://issuer.example.com/fullchain.pem);
    ssl_certificate_key /etc/letsencrypt/live/[issuer.example.com/privkey.pem](https://issuer.example.com/privkey.pem);
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Public endpoints
    location /.well-known/issuer {
        proxy_pass [http://127.0.0.1:8081](http://127.0.0.1:8081);
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /v1/oprf/issue {
        limit_req zone=issue burst=20 nodelay;
        
        proxy_pass [http://127.0.0.1:8081](http://127.0.0.1:8081);
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Admin API (restrict to internal network)
    location /admin/ {
        allow 10.0.0.0/8;    # Internal network
        deny all;
        
        limit_req zone=admin burst=10 nodelay;
        
        proxy_pass [http://127.0.0.1:8081](http://127.0.0.1:8081);
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Verifier
server {
    listen 443 ssl http2;
    server_name verifier.example.com;

    ssl_certificate /etc/letsencrypt/live/[verifier.example.com/fullchain.pem](https://verifier.example.com/fullchain.pem);
    ssl_certificate_key /etc/letsencrypt/live/[verifier.example.com/privkey.pem](https://verifier.example.com/privkey.pem);
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location /v1/verify {
        limit_req zone=verify burst=200 nodelay;

        proxy_pass [http://127.0.0.1:8082](http://127.0.0.1:8082);
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Check endpoint (validates without consuming token)
    # IMPORTANT: Rate limiting is critical here since tokens can be checked
    # repeatedly without consumption. Without rate limiting, a single valid
    # token could be used to DoS the verifier with crypto verification requests.
    location /v1/check {
        limit_req zone=verify burst=200 nodelay;

        proxy_pass [http://127.0.0.1:8082](http://127.0.0.1:8082);
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Caddy

```caddyfile
# Issuer
issuer.example.com {
    rate_limit {
        zone issue {
            key {remote_host}
            events 10
            window 1s
        }
        zone admin {
            key {remote_host}
            events 5
            window 1s
        }
    }

    # Public endpoints
    reverse_proxy /.well-known/issuer localhost:8081
    reverse_proxy /v1/oprf/issue localhost:8081 {
        rate_limit issue
    }

    # Admin API (restrict to internal network)
    @admin {
        path /admin/*
        remote_ip 10.0.0.0/8
    }
    reverse_proxy @admin localhost:8081 {
        rate_limit admin
    }
}

# Verifier
verifier.example.com {
    rate_limit {
        zone verify {
            key {remote_host}
            events 100
            window 1s
        }
    }

    reverse_proxy /v1/verify localhost:8082 {
        rate_limit verify
    }

    # Check endpoint - validates without consuming token
    # Rate limiting is critical to prevent replay-based DoS
    reverse_proxy /v1/check localhost:8082 {
        rate_limit verify
    }
}
```

---

## Monitoring & Alerting

### Health Checks

```bash
# Issuer health
curl [https://issuer.example.com/.well-known/issuer](https://issuer.example.com/.well-known/issuer)

# Admin API health
curl [https://issuer.example.com/admin/health](https://issuer.example.com/admin/health) \
  -H "X-Admin-Key: ${ADMIN_KEY}"

# Verifier implicit health (attempt verification)
```

### Prometheus Metrics (Future)

```
# Issuer metrics
freebird_issuer_requests_total{endpoint="/v1/oprf/issue", status="success"}
freebird_issuer_sybil_checks_total{type="invitation", result="pass"}
freebird_issuer_token_issuance_duration_seconds

# Verifier metrics
freebird_verifier_requests_total{endpoint="/v1/verify", status="success"}
freebird_verifier_nullifier_hits_total{reason="replay"}
freebird_verifier_verification_duration_seconds

# Invitation system metrics
freebird_invitation_total_users
freebird_invitation_total_invitations
freebird_invitation_banned_users
```

### Log Monitoring

```bash
# Track critical events
journalctl -u freebird-issuer | grep -E "ERROR|WARN|Key rotation|Ban user"

# Monitor replay attempts
journalctl -u freebird-verifier | grep "replay"

# Track admin API access
journalctl -u freebird-issuer | grep "Admin:"
```

---

## Backup & Recovery

### Automated Backups

```bash
#!/bin/bash
# /usr/local/bin/backup-freebird.sh

BACKUP_DIR="/var/backups/freebird"
DATE=$(date +%Y%m%d-%H%M%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup invitation state
cp /var/lib/freebird/invitations.json \
   "$BACKUP_DIR/invitations_$DATE.json"

# Backup key rotation state
cp /var/lib/freebird/key_rotation_state.json \
   "$BACKUP_DIR/rotation_state_$DATE.json"

# Backup keys (encrypted)
tar -czf - /var/lib/freebird/keys/ | \
  gpg --encrypt --recipient backup@example.com \
  > "$BACKUP_DIR/keys_$DATE.tar.gz.gpg"

# Upload to S3 (optional)
aws s3 cp "$BACKUP_DIR/" \
  s3://freebird-backups/$(hostname)/ \
  --recursive \
  --exclude "*" \
  --include "*$DATE*"

# Clean up old backups
find "$BACKUP_DIR" -mtime +$RETENTION_DAYS -delete

echo "✅ Backup completed: $DATE"
```

**Cron:**
```bash
# Daily backups at 2 AM
0 2 * * * /usr/local/bin/backup-freebird.sh >> /var/log/freebird-backup.log 2>&1
```

---

## Disaster Recovery

### Recovery Time Objectives (RTO)

- **Issuer failure:** < 5 minutes (auto-restart, load balancer failover)
- **Verifier failure:** < 5 minutes (stateless except nullifiers)
- **Redis failure:** < 30 minutes (restore from backup)
- **Complete datacenter failure:** < 4 hours (provision new infrastructure)

### Recovery Procedures

**Issuer Failure:**
```bash
# 1. Check service status
systemctl status freebird-issuer

# 2. Review logs
journalctl -u freebird-issuer -n 100

# 3. Restart service
systemctl restart freebird-issuer

# 4. Verify
curl [https://issuer.example.com/.well-known/issuer](https://issuer.example.com/.well-known/issuer)
```

**Data Corruption:**
```bash
# 1. Stop services
systemctl stop freebird-issuer

# 2. Restore from backup
cp /var/backups/freebird/invitations_20241115-020000.json \
   /var/lib/freebird/invitations.json

cp /var/backups/freebird/rotation_state_20241115-020000.json \
   /var/lib/freebird/key_rotation_state.json

# 3. Verify integrity
jq . /var/lib/freebird/invitations.json

# 4. Restart services
systemctl start freebird-issuer

# 5. Verify
curl [https://issuer.example.com/admin/stats](https://issuer.example.com/admin/stats) \
  -H "X-Admin-Key: ${ADMIN_KEY}"
```

---

## Performance Tuning

### Issuer

```bash
# Increase file descriptor limits
# /etc/security/limits.conf
freebird soft nofile 65536
freebird hard nofile 65536

# Optimize Tokio runtime
export TOKIO_WORKER_THREADS=8  # Number of CPU cores

# Tune invitation autosave (balance safety vs I/O)
export SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS=600  # 10 minutes
```

### Verifier

```bash
# Redis connection pool
export REDIS_POOL_SIZE=32

# Increase Redis memory
# /etc/redis/redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru

# Optimize verifier refresh
export REFRESH_INTERVAL_MIN=15  # Less frequent metadata fetches
```

---

## Security Hardening

See [Security Model](SECURITY.md) for complete threat model.

**Quick Checklist:**

```
□ TLS 1.2+ only (disable SSLv3, TLS 1.0, TLS 1.1)
□ Strong cipher suites configured
□ HSTS headers enabled
□ Admin API restricted to internal network
□ Keys stored securely (HSM or encrypted disk)
□ File permissions strict (0600 for sensitive files)
□ SELinux/AppArmor enabled
□ Automatic security updates enabled
□ Intrusion detection configured (fail2ban, OSSEC)
□ Log monitoring and alerting active
□ Regular security audits scheduled
```

---

## Cost Optimization

### Infrastructure Sizing

**Small Deployment (< 1000 users):**
- Issuer: 1 vCPU, 1GB RAM
- Verifier: 1 vCPU, 512MB RAM
- Redis: 256MB memory

**Medium Deployment (1000-10000 users):**
- Issuer: 2 vCPU, 2GB RAM
- Verifier: 2 vCPU, 1GB RAM
- Redis: 1GB memory

**Large Deployment (10000+ users):**
- Issuer: 4 vCPU, 4GB RAM (with load balancing)
- Verifier: 4 vCPU, 2GB RAM (with load balancing)
- Redis: 4GB memory (with persistence)

### Cloud Costs (Estimated)

**AWS (us-east-1):**
- Small: ~$20-30/month
- Medium: ~$60-80/month
- Large: ~$200-300/month

**GCP (us-central1):**
- Similar to AWS (5-10% cheaper)

**Optimization tips:**
- Use reserved instances (30-50% savings)
- Enable auto-scaling for peak loads
- Use spot instances for non-critical verifiers

---

## Compliance

### GDPR / CCPA

✅ **Advantages of Freebird:**
- Minimal PII collected (no identity required)
- No user tracking or profiling
- Anonymous credential system
- Right to erasure simplified (no identity = no data to erase)

**Data Inventory:**
- Issuer: Invitation graph (pseudonymous IDs)
- Verifier: Nullifiers (cryptographic hashes, time-limited)
- Logs: Access logs (can be anonymized)

### PCI-DSS

If handling payments:
- Deploy in PCI-compliant environment
- Encrypt data at rest and in transit
- Regular security audits
- Access logging and monitoring

---

## Related Documentation

- [Configuration](CONFIGURATION.md) - Environment variables
- [Security Model](SECURITY.md) - Threat model and guarantees
- [Key Management](KEY_MANAGEMENT.md) - Secure key storage
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues

---

**Production deployment requires careful planning. Test thoroughly in staging before going live.**