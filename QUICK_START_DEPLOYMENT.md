# Freebird Quick Start Deployment

Fast-track deployment guide for getting Freebird running in production.

---

## 5-Minute Docker Deployment

```bash
# 1. Clone & configure
git clone https://github.com/flammafex/freebird.git
cd freebird
cp .env.example .env

# 2. Edit .env for your environment
nano .env
# Set: REQUIRE_TLS=true, ADMIN_API_KEY=<strong_key>, ISSUER_ID=<unique_id>

# 3. Validate
./scripts/validate-deployment.sh --mode docker

# 4. Deploy
docker-compose up -d

# 5. Verify
curl http://localhost:8081/.well-known/issuer
curl http://localhost:8082/v1/check

# Done! Access admin at http://localhost:8081/admin
```

---

## 10-Minute Kubernetes Deployment

```bash
# 1. Prerequisites
kubectl create namespace freebird

# 2. Create secrets
kubectl create secret generic admin-credentials \
  --from-literal=admin-api-key="$(openssl rand -base64 32)" \
  -n freebird

kubectl create secret generic redis-credentials \
  --from-literal=password="$(openssl rand -base64 32)" \
  -n freebird

# 3. Deploy
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/network-policy.yaml
kubectl apply -f k8s/redis-deployment.yaml
kubectl apply -f k8s/issuer-deployment.yaml
kubectl apply -f k8s/verifier-deployment.yaml
kubectl apply -f k8s/ingress.yaml

# 4. Verify
kubectl get pods -n freebird
kubectl logs -f deployment/issuer -n freebird

# 5. Access
kubectl port-forward service/issuer 8081:8081 -n freebird
# Visit http://localhost:8081/admin
```

---

## Pre-Deployment Checklist

- [ ] System entropy: `cat /proc/sys/kernel/random/entropy_avail` ≥ 1000
- [ ] NTP sync: `timedatectl | grep synchronized` = yes
- [ ] Disk space: ≥ 20GB available
- [ ] Ports available: 8081 (issuer), 8082 (verifier), 6379 (redis)
- [ ] Docker/Kubernetes installed
- [ ] `.env` configured with strong ADMIN_API_KEY
- [ ] TLS certificate ready (production)

---

## Post-Deployment Verification

```bash
# 1. Service health
curl http://localhost:8081/.well-known/issuer
curl http://localhost:8082/v1/check

# 2. Admin access
ADMIN_KEY=$(grep ADMIN_API_KEY .env | cut -d= -f2)
curl -H "X-Admin-Key: $ADMIN_KEY" http://localhost:8081/admin/stats

# 3. Backup
./scripts/backup-restore.sh backup

# 4. List backups
./scripts/backup-restore.sh list
```

---

## Common Commands

### Docker Compose

```bash
# Start
docker-compose up -d

# Stop
docker-compose down

# View logs
docker-compose logs -f issuer
docker-compose logs -f verifier

# Restart
docker-compose restart issuer
docker-compose restart verifier
```

### Kubernetes

```bash
# Get status
kubectl get pods -n freebird
kubectl describe pod <pod-name> -n freebird

# View logs
kubectl logs -f deployment/issuer -n freebird

# Scale verifier
kubectl scale deployment verifier --replicas=5 -n freebird

# Rolling update
kubectl set image deployment/verifier \
  verifier=ghcr.io/flammafex/freebird-verifier:v0.5.0 -n freebird
```

---

## Environment Configuration

**Critical variables** (must set):

```bash
ADMIN_API_KEY=<32+ char random string>   # Generate: openssl rand -base64 32
REQUIRE_TLS=true                          # ALWAYS true in production
ISSUER_ID=issuer:prod:v1                  # Unique identifier
```

**Optional but recommended:**

```bash
SYBIL_RESISTANCE=invitation               # invitation, pow, webauthn
EPOCH_DURATION_SEC=86400                  # 24 hour key rotation
MAX_CLOCK_SKEW_SECS=300                   # 5 minute tolerance
REDIS_URL=redis://redis:6379              # Redis connection
```

See `.env.example` for all 60+ options.

---

## Backup & Recovery

```bash
# Create backup (daily recommended)
./scripts/backup-restore.sh backup

# List backups
./scripts/backup-restore.sh list

# Verify backup
./scripts/backup-restore.sh verify <backup-file>

# Restore from backup
./scripts/backup-restore.sh restore <backup-file>
```

---

## Monitoring

### Access Metrics

```bash
# Prometheus format
curl -H "X-Admin-Key: $ADMIN_KEY" \
  http://localhost:8081/admin/metrics
```

### Setup Monitoring

1. Deploy Prometheus:
   ```bash
   docker run -d -p 9090:9090 \
     -v $(pwd)/monitoring/prometheus-config.yml:/etc/prometheus/prometheus.yml \
     prom/prometheus
   ```

2. Configure alerts: See `monitoring/alert-rules.yml`

3. View at: http://localhost:9090

---

## Troubleshooting

### Services won't start

```bash
# Check Docker logs
docker-compose logs issuer

# Validate configuration
./scripts/validate-deployment.sh --mode docker

# Check ports aren't in use
lsof -i :8081
```

### Low entropy

```bash
# Check
cat /proc/sys/kernel/random/entropy_avail

# Fix
./scripts/validate-deployment.sh --mode docker --fix-entropy
```

### Clock skew

```bash
# Check time sync
timedatectl

# Sync time
sudo ntpdate -s time.nist.gov
```

### Verify connection to issuer

```bash
# From verifier container
docker exec freebird-verifier curl http://issuer:8081/.well-known/issuer

# Check ISSUER_URL
docker-compose exec verifier env | grep ISSUER_URL
```

---

## Security Hardening

After deployment, verify:

```bash
# 1. TLS enabled
grep "REQUIRE_TLS=true" .env

# 2. Strong API key
ADMIN_KEY=$(grep ADMIN_API_KEY .env | cut -d= -f2)
echo "Length: ${#ADMIN_KEY}"  # Should be 32+

# 3. File permissions
ls -la .env          # Should be rw------- (600)

# 4. Admin restricted by IP
# In production Nginx, verify admin IP allowlist is configured

# 5. Redis password set
grep REDIS_URL .env  # Should have password in URL
```

---

## Scaling

### Horizontal Scaling (Verifier)

Verifiers are stateless and can scale:

```bash
# Docker
docker-compose up -d --scale verifier=5

# Kubernetes
kubectl scale deployment verifier --replicas=10 -n freebird
```

### Note on Issuer

Issuer **must be singleton** (1 replica) to maintain key consistency.

---

## Next Steps

1. Read `DEPLOYMENT.md` for detailed procedures
2. Configure reverse proxy (Nginx/Caddy) for TLS
3. Set up monitoring (Prometheus + Grafana)
4. Implement backup schedule (daily recommended)
5. Document runbooks for your team
6. Test disaster recovery procedures

---

## Support

- **Documentation**: See `docs/` directory
- **Issues**: https://github.com/flammafex/freebird/issues
- **Troubleshooting**: See `docs/TROUBLESHOOTING.md`

---

**Ready to deploy?** Start with the 5-minute Docker deployment above!
