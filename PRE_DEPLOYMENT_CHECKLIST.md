# Pre-Deployment Checklist

Complete checklist before deploying Freebird to production.

---

## System Readiness

### Hardware & Environment
- [ ] Entropy available: `cat /proc/sys/kernel/random/entropy_avail` >= 1000
- [ ] NTP synchronized: `timedatectl | grep synchronized` = yes
- [ ] Disk space: >= 20GB available in deployment location
- [ ] CPU: >= 2 cores (4+ recommended)
- [ ] RAM: >= 2GB (4+ recommended)
- [ ] Network: >= 100 Mbps (1Gbps recommended)

### Docker (if using Docker Compose)
- [ ] Docker installed: `docker --version`
- [ ] Docker running: `docker ps` works
- [ ] Docker Compose installed: `docker-compose --version`
- [ ] Disk space for images: >= 5GB available

### Kubernetes (if using Kubernetes)
- [ ] kubectl installed: `kubectl version`
- [ ] Cluster accessible: `kubectl cluster-info`
- [ ] Current context correct: `kubectl config current-context`
- [ ] Default namespace set or will use freebird namespace
- [ ] Persistent volume provisioner available
- [ ] Ingress controller installed (nginx recommended)

---

## Configuration

### Environment File
- [ ] `.env` created: `cp .env.example .env`
- [ ] ADMIN_API_KEY set: >= 32 characters, strongly random
  ```bash
  ADMIN_API_KEY=$(openssl rand -base64 32)
  ```
- [ ] REQUIRE_TLS=true (production only)
- [ ] ISSUER_ID set to unique, versioned identifier
- [ ] SYBIL_RESISTANCE configured (invitation, pow, webauthn, etc.)

### Redis
- [ ] Redis password set (production)
- [ ] Redis persistence enabled
- [ ] Redis reachable from verifier network

### TLS/HTTPS (Production)
- [ ] SSL certificate obtained (Let's Encrypt or other)
- [ ] Certificate path: `/etc/letsencrypt/live/<domain>/fullchain.pem`
- [ ] Private key path: `/etc/letsencrypt/live/<domain>/privkey.pem`
- [ ] Certificate valid for: issuer.example.com, verifier.example.com
- [ ] Auto-renewal configured (certbot timer for Let's Encrypt)

### Reverse Proxy (Production)
- [ ] Nginx/Caddy installed and running
- [ ] Server blocks configured for issuer and verifier
- [ ] TLS certificates configured
- [ ] Rate limiting configured
- [ ] Admin API restricted by IP
- [ ] Security headers added (HSTS, CSP, X-Frame-Options)

---

## Security

### File Permissions
- [ ] `.env` file permissions: 600 (`chmod 600 .env`)
- [ ] Private key files: 600 (`chmod 600 /etc/letsencrypt/live/*/privkey.pem`)
- [ ] Data directories: 750 (`chmod 750 /data /data/keys`)

### Secrets Management
- [ ] No hardcoded secrets in code or configs
- [ ] Secrets not in .env.example
- [ ] Secrets not in docker-compose.yaml (use env_file or secrets)
- [ ] For Kubernetes: Using sealed-secrets or External Secrets Operator
- [ ] Secrets rotation plan documented

### Docker Security
- [ ] Building from Dockerfile: `docker build -f Dockerfile -t freebird .`
- [ ] Running as non-root user verified
- [ ] Resource limits set
- [ ] Security options enabled (no-new-privileges)
- [ ] Images scanned for vulnerabilities

### Network Security
- [ ] Firewall rules configured
- [ ] Issuer and verifier on separate networks/subnets (production)
- [ ] Admin API restricted to internal IP ranges only
- [ ] Redis only accessible from verifier
- [ ] Inbound firewall: only ports 443 (TLS), 80 (redirect)
- [ ] Outbound: only to required services

### Kubernetes Security
- [ ] Network policies applied
- [ ] RBAC roles minimal (least privilege)
- [ ] Service accounts created
- [ ] Secrets not in manifests (use sealed-secrets)
- [ ] Security context enforced (non-root, capabilities dropped)

---

## Deployment

### Pre-Deployment Validation
- [ ] Run validation script: `./scripts/validate-deployment.sh`
- [ ] All validation checks pass
- [ ] No critical warnings remain

### Docker Compose Deployment
- [ ] Services start without errors: `docker-compose up -d`
- [ ] Health checks passing: `docker-compose ps` shows healthy
- [ ] Issuer responding: `curl http://localhost:8081/.well-known/issuer`
- [ ] Verifier responding: `curl http://localhost:8082/v1/check`
- [ ] Logs clean: `docker-compose logs | grep ERROR` = empty

### Kubernetes Deployment
- [ ] Namespace created: `kubectl get namespace freebird`
- [ ] All pods running: `kubectl get pods -n freebird`
- [ ] Issuer ready: `kubectl rollout status deployment/issuer -n freebird`
- [ ] Verifier ready: `kubectl rollout status deployment/verifier -n freebird`
- [ ] Redis ready: `kubectl rollout status deployment/redis -n freebird`
- [ ] Services accessible: `kubectl get svc -n freebird`

### Post-Deployment Verification
- [ ] Issuer metadata endpoint responds
  ```bash
  curl https://issuer.example.com/.well-known/issuer
  ```
- [ ] Verifier check endpoint responds
  ```bash
  curl https://verifier.example.com/v1/check
  ```
- [ ] Admin API reachable (internal only)
  ```bash
  curl -H "X-Admin-Key: $ADMIN_KEY" https://issuer.example.com/admin/stats
  ```

---

## Data & Persistence

### Storage
- [ ] Persistent storage provisioned for issuer
- [ ] Persistent storage provisioned for redis
- [ ] Backup storage location prepared (>= 1TB for 30 days)
- [ ] Backup retention policy set (minimum 30 days)

### Initial Backup
- [ ] Create initial backup: `./scripts/backup-restore.sh backup`
- [ ] Backup verified: `./scripts/backup-restore.sh verify <backup-file>`
- [ ] Backup location documented
- [ ] Backup encryption planned (if required)

### Backup Schedule
- [ ] Cron job created for daily backups
  ```bash
  0 2 * * * /opt/freebird/scripts/backup-restore.sh backup
  ```
- [ ] Backup location has sufficient space
- [ ] Automatic cleanup configured (retention days)
- [ ] Off-site backup planned (AWS S3, GCS, etc.)

---

## Monitoring & Observability

### Prometheus
- [ ] Prometheus installed and running
- [ ] Configuration file created: `monitoring/prometheus-config.yml`
- [ ] Scrape targets added:
  - [ ] Issuer (:8081/admin/metrics)
  - [ ] Verifier (:8082/admin/metrics)
  - [ ] Redis (if using redis_exporter)
  - [ ] Node (if using node_exporter)
- [ ] Bearer token authorization configured
- [ ] Alert rules loaded: `monitoring/alert-rules.yml`

### Grafana
- [ ] Grafana installed and connected to Prometheus
- [ ] Dashboard created with key metrics:
  - [ ] Token issuance rate
  - [ ] Token verification rate
  - [ ] Verification success rate
  - [ ] API latency (p50, p95, p99)
  - [ ] Error rate
  - [ ] System resource usage

### Alerting
- [ ] Alert manager configured
- [ ] On-call rotation established
- [ ] Alerts routed to correct team (PagerDuty, Opsgenie, Slack)
- [ ] Critical alerts tested and acknowledged

### Logging
- [ ] Log aggregation configured (ELK, Datadog, CloudWatch, Loki)
- [ ] JSON logging enabled in .env
- [ ] Log retention policy set
- [ ] Log parsing rules configured
- [ ] Log dashboards created

---

## Testing & Validation

### Functional Testing
- [ ] Token issuance works
- [ ] Token verification works
- [ ] Batch operations work
- [ ] Key rotation works (test with manual rotation)
- [ ] User management works
- [ ] Sybil resistance mode works
- [ ] Admin API endpoints functional

### Performance Testing
- [ ] Load testing completed
- [ ] API latency acceptable (< 100ms p95)
- [ ] Throughput meets requirements
- [ ] No memory leaks detected
- [ ] CPU usage reasonable under load

### Security Testing
- [ ] No known CVEs in dependencies
- [ ] Container images scanned
- [ ] TLS configuration tested (SSL Labs A+ grade)
- [ ] SQL injection impossible (using parameterized queries)
- [ ] No hardcoded secrets
- [ ] Admin API properly secured

### Disaster Recovery Testing
- [ ] Backup created and verified
- [ ] Restore procedure tested
- [ ] Recovery time acceptable (< 1 hour)
- [ ] RTO/RPO requirements met

---

## Documentation

### Deployment Docs
- [ ] DEPLOYMENT.md reviewed
- [ ] QUICK_START_DEPLOYMENT.md available
- [ ] Cloud platform guides reviewed (if applicable)

### Operational Docs
- [ ] Runbooks created for common issues
- [ ] Troubleshooting guide available
- [ ] Escalation procedures documented
- [ ] Emergency contacts documented

### Configuration Docs
- [ ] Configuration documented and version controlled
- [ ] Environment variables documented
- [ ] Secrets management documented
- [ ] Network topology documented
- [ ] Backup procedures documented

---

## Team & Training

### Operations Team
- [ ] Ops team trained on deployment
- [ ] Team familiar with monitoring
- [ ] On-call procedures established
- [ ] Escalation procedures clear
- [ ] Runbooks accessible

### Development Team
- [ ] Developers know how to access logs
- [ ] Developers know how to check metrics
- [ ] Developers know deployment procedures
- [ ] Developers know how to create backups

### Security Team
- [ ] Security reviewed deployment
- [ ] Security aware of monitoring
- [ ] Incident response plan in place
- [ ] Security audit completed

---

## Compliance & Governance

### Regulatory
- [ ] GDPR compliant (if applicable)
- [ ] HIPAA compliant (if applicable)
- [ ] SOX compliant (if applicable)
- [ ] PCI DSS compliant (if handling payments)

### Internal Policies
- [ ] Data retention policy followed
- [ ] Backup policy complied with
- [ ] Change management followed
- [ ] Access control complied with

### Audit Trail
- [ ] Audit logging enabled
- [ ] Audit logs persisted
- [ ] Audit log access restricted
- [ ] Audit log retention policy set

---

## Production Launch

### Go/No-Go Decision
- [ ] All infrastructure checks passed
- [ ] All security checks passed
- [ ] All deployment checks passed
- [ ] All testing completed
- [ ] Team ready for launch
- [ ] Management approval obtained

### Launch Plan
- [ ] Deployment window scheduled
- [ ] Team assembled for launch
- [ ] Communication channels open (Slack, war room, etc.)
- [ ] Rollback plan documented
- [ ] Health monitoring active

### Post-Launch
- [ ] Monitor for 24 hours continuously
- [ ] Daily health checks for 1 week
- [ ] Weekly review for 1 month
- [ ] Monthly review thereafter
- [ ] Metrics trending correctly

---

## Post-Deployment

### Monitoring Ongoing
- [ ] Daily log review for errors
- [ ] Weekly metric review
- [ ] Monthly performance analysis
- [ ] Quarterly security review
- [ ] Annual disaster recovery drill

### Maintenance Schedule
- [ ] Dependency updates planned (monthly)
- [ ] Security patches applied immediately
- [ ] TLS certificate renewal automated
- [ ] Backup restoration tested (quarterly)

### Continuous Improvement
- [ ] Incident postmortems conducted
- [ ] Lessons learned documented
- [ ] Runbooks updated based on incidents
- [ ] Metrics dashboards refined
- [ ] Alert rules tuned (reduce false positives)

---

## Sign-Off

**Project:** Freebird Authorization
**Deployment Date:** _______________
**Environment:** Production / Staging / Development

### Approvals

| Role | Name | Signature | Date |
|------|------|-----------|------|
| DevOps Lead | _____________ | _____________ | ______ |
| Security Lead | _____________ | _____________ | ______ |
| Operations Lead | _____________ | _____________ | ______ |
| Project Manager | _____________ | _____________ | ______ |

---

## Notes

Use this section to document any deviations from standard procedures or special considerations:

```
_________________________________________________________________

_________________________________________________________________

_________________________________________________________________

_________________________________________________________________
```

---

**Last Updated:** 2026-03-28
**Version:** 1.0
**Status:** Ready for Production Deployment
