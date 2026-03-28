# Freebird Deployment Guide

Complete end-to-end deployment guide for Freebird in development, staging, and production environments.

---

## Table of Contents

1. [Deployment Overview](#deployment-overview)
2. [Docker Deployment](#docker-deployment)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Cloud Platforms](#cloud-platforms)
5. [Security Configuration](#security-configuration)
6. [Monitoring & Observability](#monitoring--observability)
7. [Backup & Recovery](#backup--recovery)
8. [Troubleshooting](#troubleshooting)

---

## Deployment Overview

### Architecture Diagram

```
                    ┌─────────────────────────┐
                    │   Reverse Proxy/LB      │
                    │   (TLS Termination)     │
                    └────┬────────────┬────────┘
                         │            │
          VOPRF Endpoints │            │ Verification Endpoints
                    ┌────▼──┐    ┌───▼────┐
                    │ Issuer│    │Verifier│
                    │ (8081)│    │ (8082) │
                    └────┬──┘    └───┬────┘
                         │           │
                    ┌────▼───────────▼────┐
                    │   Shared Redis      │
                    │   (Nullifier Cache) │
                    └────────────────────┘
```

### Key Architecture Decisions

- **Separate Issuer & Verifier**: Deployed on different infrastructure to prevent timing attacks
- **Stateless Verifiers**: Multiple verifier replicas share nullifier state via Redis
- **Single Issuer**: Ensures key consistency and prevents inconsistent state
- **Redis Persistence**: Mandatory for verifier nullifier state in production
- **TLS Termination**: Always use reverse proxy (Nginx/Caddy) for TLS

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|------------|
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4+ GB |
| Disk | 20 GB SSD | 50+ GB SSD |
| Entropy | 1000 bits | 2000+ bits |
| Network | 100 Mbps | 1 Gbps |

---

## Docker Deployment

### Quick Start (Development)

For local development and testing:

```bash
# 1. Clone repository
git clone https://github.com/flammafex/freebird.git
cd freebird

# 2. Configure environment
cp .env.example .env
# Edit .env as needed

# 3. Validate configuration
./scripts/validate-deployment.sh --mode docker

# 4. Start services
docker-compose up --build

# 5. Verify deployment
curl http://localhost:8081/.well-known/issuer
curl http://localhost:8082/v1/check
```

**URLs:**
- Issuer: http://localhost:8081
- Verifier: http://localhost:8082
- Admin (Issuer): http://localhost:8081/admin
- Admin (Verifier): http://localhost:8082/admin

### Production Docker Deployment

For production Docker deployments:

#### 1. Prepare Host

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker & Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Create data directories
sudo mkdir -p /var/lib/freebird/{issuer,redis}
sudo chmod 755 /var/lib/freebird

# Create backup directory
sudo mkdir -p /backups/freebird
sudo chmod 755 /backups/freebird
```

#### 2. Configure Environment

```bash
# Copy to production location
sudo cp -r /path/to/freebird /opt/freebird
cd /opt/freebird

# Configure environment with strong values
cat > .env << 'EOF'
# Security
REQUIRE_TLS=true
BEHIND_PROXY=true

# Issuer Configuration
ISSUER_ID=issuer:prod:v1
ADMIN_API_KEY=$(openssl rand -base64 32)
EPOCH_DURATION_SEC=86400
SYBIL_RESISTANCE=invitation

# Verifier Configuration
ISSUER_URL=http://issuer:8081/.well-known/issuer
REDIS_URL=redis://redis:6379

# Logging
RUST_LOG=info,freebird=debug
LOG_FORMAT=json
EOF

# Secure permissions
chmod 600 .env
```

#### 3. Configure Reverse Proxy (Nginx)

```bash
# Copy Nginx configuration
sudo cp server-configs/freebird-issuer.conf /etc/nginx/sites-available/
sudo cp server-configs/freebird-verifier.conf /etc/nginx/sites-available/

# Edit configurations
sudo nano /etc/nginx/sites-available/freebird-issuer.conf
# Replace YOUR_DOMAIN with your domain
# Configure SSL certificates

# Enable sites
sudo ln -s /etc/nginx/sites-available/freebird-issuer.conf /etc/nginx/sites-enabled/
sudo ln -s /etc/nginx/sites-available/freebird-verifier.conf /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

#### 4. Configure TLS (Let's Encrypt)

```bash
# Install Certbot
sudo apt-get install -y certbot python3-certbot-nginx

# Generate certificates
sudo certbot certonly --standalone \
  -d issuer.example.com \
  -d verifier.example.com \
  -m admin@example.com

# Auto-renewal
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

#### 5. Start Services

```bash
# Use systemd service file
sudo cp docker-compose.yaml /opt/freebird/
cd /opt/freebird

# Create systemd service
sudo tee /etc/systemd/system/freebird.service << 'EOF'
[Unit]
Description=Freebird VOPRF Authorization Service
Requires=docker.service
After=docker.service

[Service]
Type=simple
User=docker
WorkingDirectory=/opt/freebird
ExecStart=/usr/bin/docker-compose up
ExecStop=/usr/bin/docker-compose down
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable freebird
sudo systemctl start freebird

# Check status
sudo systemctl status freebird
docker-compose logs -f
```

#### 6. Configure Monitoring

```bash
# Enable Prometheus scraping
cat > prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'freebird-issuer'
    static_configs:
      - targets: ['127.0.0.1:8081']
    metrics_path: /admin/metrics
    authorization:
      type: Bearer
      credentials: 'YOUR_ADMIN_API_KEY'

  - job_name: 'freebird-verifier'
    static_configs:
      - targets: ['127.0.0.1:8082']
    metrics_path: /admin/metrics
    authorization:
      type: Bearer
      credentials: 'YOUR_ADMIN_API_KEY'
EOF

# Start Prometheus
docker run -d --name prometheus \
  -p 9090:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus
```

### Docker Compose Configuration

Key environment variables in `.env`:

```bash
# Issuer
ISSUER_ID=issuer:prod:v1              # Unique issuer identifier
BIND_ADDR=0.0.0.0:8081                # Issuer listening address
ADMIN_API_KEY=<32+ char random key>   # Admin API authentication
REQUIRE_TLS=true                       # Enforce TLS in production
EPOCH_DURATION_SEC=86400              # 24 hour key rotation
SYBIL_RESISTANCE=invitation           # Sybil resistance mode

# Verifier
ISSUER_URL=http://issuer:8081/...     # Issuer metadata endpoint
REDIS_URL=redis://redis:6379          # Redis connection
MAX_CLOCK_SKEW_SECS=300               # Clock tolerance
```

### Scaling Docker Deployments

```bash
# Scale verifier instances
docker-compose up -d --scale verifier=3

# Monitor logs
docker-compose logs -f verifier

# Health check
curl http://localhost:8082/v1/check
```

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes 1.20+
- kubectl configured to access cluster
- Persistent Volume provisioner (local, EBS, GCE, etc.)
- Ingress controller (Nginx recommended)
- Secrets management (sealed-secrets or External Secrets Operator)

### Quick Start

```bash
# 1. Create namespace and secrets
kubectl create namespace freebird

# 2. Create admin credentials
kubectl create secret generic admin-credentials \
  --from-literal=admin-api-key="$(openssl rand -base64 32)" \
  -n freebird

# 3. Create Redis credentials
kubectl create secret generic redis-credentials \
  --from-literal=password="$(openssl rand -base64 32)" \
  -n freebird

# 4. Apply manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/network-policy.yaml
kubectl apply -f k8s/redis-deployment.yaml
kubectl apply -f k8s/issuer-deployment.yaml
kubectl apply -f k8s/verifier-deployment.yaml

# 5. Configure ingress
kubectl apply -f k8s/ingress.yaml

# 6. Monitor rollout
kubectl rollout status deployment/issuer -n freebird
kubectl rollout status deployment/verifier -n freebird

# 7. Verify deployment
kubectl get pods -n freebird
kubectl logs -f deployment/issuer -n freebird
```

### Kubernetes Manifests

The `k8s/` directory contains production-ready manifests:

- **namespace.yaml**: Kubernetes namespace configuration
- **rbac.yaml**: Service accounts and role bindings
- **network-policy.yaml**: Network isolation policies
- **issuer-deployment.yaml**: Issuer deployment with PVC
- **verifier-deployment.yaml**: Stateless verifier deployment
- **redis-deployment.yaml**: Redis persistence layer
- **ingress.yaml**: Ingress configuration for TLS
- **secrets-template.yaml**: Secrets template (DO NOT COMMIT)

### Secrets Management

**Do not commit secrets to Git!** Use one of:

#### Option 1: Sealed Secrets (Recommended)

```bash
# Install sealed-secrets controller
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.18.0/controller.yaml

# Create and seal secret
kubectl create secret generic admin-credentials \
  --from-literal=admin-api-key="$(openssl rand -base64 32)" \
  -n freebird \
  --dry-run=client -o yaml | \
  kubeseal -f - > k8s/admin-credentials-sealed.yaml

# Apply sealed secret
kubectl apply -f k8s/admin-credentials-sealed.yaml
```

#### Option 2: External Secrets Operator

```bash
# Install ESO
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets-system --create-namespace

# Reference AWS Secrets Manager, Vault, etc.
kubectl apply -f k8s/external-secret.yaml
```

### Scaling Verifiers

```bash
# Scale to 3 replicas
kubectl scale deployment verifier --replicas=3 -n freebird

# Monitor scaling
kubectl get pods -n freebird -w

# View logs
kubectl logs -f -l app=freebird,component=verifier -n freebird
```

### Rolling Updates

```bash
# Update image
kubectl set image deployment/verifier \
  verifier=ghcr.io/flammafex/freebird-verifier:v1.0.0 \
  -n freebird

# Monitor rollout
kubectl rollout status deployment/verifier -n freebird

# Rollback if needed
kubectl rollout undo deployment/verifier -n freebird
```

---

## Cloud Platforms

### AWS ECS Fargate

```bash
# Create cluster
aws ecs create-cluster --cluster-name freebird

# Register task definition
aws ecs register-task-definition \
  --cli-input-json file://task-definition.json

# Create service
aws ecs create-service \
  --cluster freebird \
  --service-name issuer \
  --task-definition freebird-issuer:1 \
  --desired-count 1

# Create load balancer
aws elbv2 create-load-balancer \
  --name freebird-issuer-lb \
  --subnets subnet-xxx subnet-yyy \
  --security-groups sg-xxx
```

### Google Cloud Run

```bash
# Build and push image
gcloud builds submit --tag gcr.io/PROJECT/freebird-issuer

# Deploy issuer
gcloud run deploy freebird-issuer \
  --image gcr.io/PROJECT/freebird-issuer \
  --memory 1Gi \
  --cpu 2 \
  --port 8081

# Deploy verifier
gcloud run deploy freebird-verifier \
  --image gcr.io/PROJECT/freebird-verifier \
  --memory 1Gi \
  --cpu 2 \
  --port 8082
```

### Azure Container Instances

```bash
# Create resource group
az group create --name freebird --location eastus

# Deploy issuer
az container create \
  --resource-group freebird \
  --name issuer \
  --image ghcr.io/flammafex/freebird-issuer:latest \
  --port 8081 \
  --cpu 2 \
  --memory 1 \
  --environment-variables BIND_ADDR=0.0.0.0:8081
```

---

## Security Configuration

### TLS/HTTPS Setup

**Critical**: Always enable TLS in production.

```bash
# Using Let's Encrypt with Certbot
sudo certbot certonly --standalone -d issuer.example.com

# Update Nginx configuration
server {
  listen 443 ssl http2;
  ssl_certificate /etc/letsencrypt/live/issuer.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/issuer.example.com/privkey.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5;
}
```

### Admin API Security

```bash
# Generate strong API key
ADMIN_API_KEY=$(openssl rand -base64 32)

# Restrict admin access by IP
location /admin {
  allow 10.0.0.0/8;      # Private network
  deny all;
}

# Example request with API key
curl -H "X-Admin-Key: $ADMIN_API_KEY" \
  https://issuer.example.com/admin/stats
```

### Network Isolation

**Production Architecture:**

```
┌──────────────────────────────────────────┐
│         Public Internet (TLS)             │
└────────────────────┬─────────────────────┘
                     │
        ┌────────────▼────────────┐
        │ Reverse Proxy (Nginx)   │
        │ (TLS Termination)       │
        └────┬─────────────┬──────┘
             │             │
    ┌────────▼───┐  ┌─────▼───────┐
    │   Issuer   │  │   Verifier   │
    │ (Private)  │  │  (Private)   │
    └────────┬───┘  └─────┬────────┘
             │            │
             └────┬───────┘
                  │
          ┌───────▼────────┐
          │    Redis       │
          │   (Private)    │
          └────────────────┘
```

- Issuer and Verifier on separate subnets
- Admin API restricted to internal IP ranges
- Redis only accessible from Verifier
- All external communication through reverse proxy

---

## Monitoring & Observability

### Prometheus Metrics

Enable metrics scraping:

```bash
# Configure Prometheus
cat > prometheus.yml << 'EOF'
scrape_configs:
  - job_name: 'freebird'
    static_configs:
      - targets: ['localhost:8081']
    metrics_path: /admin/metrics
    authorization:
      type: Bearer
      credentials: 'YOUR_ADMIN_API_KEY'
EOF

# Scrape issuer metrics
curl -H "X-Admin-Key: $ADMIN_API_KEY" \
  http://localhost:8081/admin/metrics
```

### Key Metrics to Monitor

```
freebird_users_total          # Total registered users
freebird_users_banned         # Number of banned users
freebird_invitations_total    # Total invitations created
freebird_invitations_redeemed # Invitations redeemed
freebird_keys_total           # Cryptographic keys
freebird_keys_active          # Active signing keys
```

### Alerting Rules

```yaml
groups:
  - name: freebird
    rules:
      - alert: IssuerDown
        expr: up{job="freebird-issuer"} == 0
        for: 5m
        annotations:
          summary: "Issuer is down"

      - alert: VerifierDown
        expr: up{job="freebird-verifier"} == 0
        for: 5m
        annotations:
          summary: "Verifier is down"

      - alert: RedisDown
        expr: redis_up == 0
        for: 5m
        annotations:
          summary: "Redis is down"
```

### Structured Logging

Enable JSON logging for ELK/Datadog integration:

```bash
# In .env
LOG_FORMAT=json

# Parse in ELK
{
  "timestamp": "2024-01-01T00:00:00Z",
  "level": "info",
  "message": "Token verified",
  "target": "freebird",
  "fields": {
    "user_id": "...",
    "token_hash": "..."
  }
}
```

---

## Backup & Recovery

### Backup Strategy

**Critical data to backup:**

1. **Issuer Keys** (`/data/keys/`)
   - `issuer_sk.bin` — Private signing key (CRITICAL)
   - `key_rotation_state.json` — Key rotation state

2. **Issuer State** (`/data/state/`)
   - `invitations.json` — Sybil resistance state

3. **Redis Data**
   - Nullifier set (for preventing double-spending)

### Automated Backup

```bash
#!/bin/bash
# backup-freebird.sh

BACKUP_DIR=/backups/freebird
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Backup issuer data
docker exec freebird-issuer tar czf - /data | \
  gzip > $BACKUP_DIR/issuer-$TIMESTAMP.tar.gz

# Backup Redis
redis-cli BGSAVE
cp /var/lib/redis/dump.rdb $BACKUP_DIR/redis-$TIMESTAMP.rdb

# Keep last 30 days
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
find $BACKUP_DIR -name "*.rdb" -mtime +30 -delete

echo "Backup completed: $TIMESTAMP"
```

**Schedule with cron:**

```bash
# Backup daily at 2 AM
0 2 * * * /opt/freebird/backup-freebird.sh >> /var/log/freebird-backup.log 2>&1
```

### Recovery Procedure

```bash
# 1. Stop services
docker-compose down

# 2. Restore issuer data
docker run --rm -v issuer-data:/data \
  -v /backups/freebird:/backup \
  alpine tar xzf /backup/issuer-YYYYMMDD-HHMMSS.tar.gz -C /

# 3. Restore Redis
docker run --rm -v redis-data:/data \
  -v /backups/freebird:/backup \
  alpine cp /backup/redis-YYYYMMDD-HHMMSS.rdb /data/dump.rdb

# 4. Start services
docker-compose up -d

# 5. Verify
docker-compose logs -f
curl http://localhost:8081/.well-known/issuer
```

---

## Troubleshooting

### Common Issues

#### 1. Low Entropy

```bash
# Check entropy
cat /proc/sys/kernel/random/entropy_avail

# Fix: Install and start haveged
sudo apt-get install -y haveged
sudo systemctl start haveged

# Or use scripts/validate-deployment.sh --fix-entropy
```

#### 2. Clock Skew

```bash
# Check time sync
timedatectl

# Sync with NTP
sudo ntpdate -s time.nist.gov

# Verify with verifier
curl http://localhost:8082/v1/check
```

#### 3. Redis Connection Issues

```bash
# Test Redis connectivity
redis-cli -u redis://localhost:6379 ping

# Check Redis logs
docker logs freebird-redis

# Verify environment
docker exec freebird-verifier env | grep REDIS
```

#### 4. Port Already in Use

```bash
# Find process using port
lsof -i :8081
sudo kill -9 <PID>

# Or change port in .env
ISSUER_BIND_ADDR=127.0.0.1:9081
```

#### 5. Permission Denied on /data

```bash
# Fix permissions
sudo chown -R 1000:1000 /data
sudo chmod 750 /data
sudo chmod 600 /data/keys/*
```

### Debugging Commands

```bash
# View logs
docker-compose logs -f issuer
docker-compose logs -f verifier

# Inspect containers
docker inspect freebird-issuer

# Access shell
docker-compose exec issuer /bin/bash

# Test endpoints
curl -v http://localhost:8081/.well-known/issuer
curl -v -X POST http://localhost:8082/v1/check

# Check admin API
curl -H "X-Admin-Key: $ADMIN_API_KEY" \
  http://localhost:8081/admin/stats
```

---

## Pre-Deployment Checklist

Before deploying to production:

```bash
# Run validation script
./scripts/validate-deployment.sh --mode docker

# Verify configuration
grep -E "REQUIRE_TLS|ADMIN_API_KEY|ISSUER_ID" .env

# Test Docker build
docker-compose build

# Test Docker Compose
docker-compose up
sleep 5
curl http://localhost:8081/.well-known/issuer
docker-compose down

# Security checklist
- [ ] REQUIRE_TLS=true in production
- [ ] ADMIN_API_KEY is 32+ characters
- [ ] .env file has 600 permissions
- [ ] Nginx TLS configured with valid certificate
- [ ] Redis password configured and stored securely
- [ ] Backup strategy implemented and tested
- [ ] Monitoring and alerting configured
- [ ] Network isolation implemented
- [ ] Firewall rules configured
- [ ] DNS/domain records updated
```

---

## Additional Resources

- [Production Guide](docs/PRODUCTION.md)
- [Configuration Reference](docs/CONFIGURATION.md)
- [Admin API Documentation](docs/ADMIN_API.md)
- [Security Model](docs/SECURITY.md)
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md)

---

**Last Updated**: 2026-03-28
