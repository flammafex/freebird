# Freebird Deployment Documentation Index

Complete reference guide to all deployment resources for Freebird.

---

## Quick Navigation

### For First-Time Deployers
1. Start here: **[QUICK_START_DEPLOYMENT.md](QUICK_START_DEPLOYMENT.md)** (5-minute read)
2. Run validation: `./scripts/validate-deployment.sh --mode docker`
3. Choose platform and follow instructions

### For Production Deployment
1. Review: **[DEPLOYMENT.md](DEPLOYMENT.md)** (comprehensive guide)
2. Review: **[PRE_DEPLOYMENT_CHECKLIST.md](PRE_DEPLOYMENT_CHECKLIST.md)** (200+ items)
3. Execute deployment step-by-step
4. Monitor using **[monitoring/LOGGING.md](monitoring/LOGGING.md)**

### For Operations Teams
1. Setup monitoring: **[monitoring/prometheus-config.yml](monitoring/prometheus-config.yml)**
2. Configure alerts: **[monitoring/alert-rules.yml](monitoring/alert-rules.yml)**
3. Manage logs: **[monitoring/LOGGING.md](monitoring/LOGGING.md)**
4. Backup routine: `./scripts/backup-restore.sh`

---

## Documentation Map

### Core Deployment Guides

| Document | Purpose | Audience | Length |
|----------|---------|----------|--------|
| [QUICK_START_DEPLOYMENT.md](QUICK_START_DEPLOYMENT.md) | Fast-track deployment | Developers, DevOps | 200 lines |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Complete procedures | DevOps, SRE | 500+ lines |
| [DEPLOYMENT_READY.md](DEPLOYMENT_READY.md) | Readiness summary | Management, Team Leads | 400 lines |
| [PRE_DEPLOYMENT_CHECKLIST.md](PRE_DEPLOYMENT_CHECKLIST.md) | Launch validation | DevOps, Security | 200 items |

### Infrastructure Files

#### Docker
| File | Purpose | Notes |
|------|---------|-------|
| [Dockerfile](Dockerfile) | Container image build | Multi-stage, optimized |
| [docker-compose.yaml](docker-compose.yaml) | Local development/single server | v3.8, enhanced |

#### Kubernetes (k8s/)
| File | Purpose | Replicas | Storage |
|------|---------|----------|---------|
| [k8s/namespace.yaml](k8s/namespace.yaml) | Namespace creation | - | - |
| [k8s/issuer-deployment.yaml](k8s/issuer-deployment.yaml) | Issuer service | 1 (singleton) | 20Gi |
| [k8s/verifier-deployment.yaml](k8s/verifier-deployment.yaml) | Verifier service | 3 (scalable) | No |
| [k8s/redis-deployment.yaml](k8s/redis-deployment.yaml) | Redis cache | 1 (singleton) | 10Gi |
| [k8s/rbac.yaml](k8s/rbac.yaml) | Role-based access | - | - |
| [k8s/network-policy.yaml](k8s/network-policy.yaml) | Zero-trust network | - | - |
| [k8s/ingress.yaml](k8s/ingress.yaml) | TLS ingress | - | - |
| [k8s/secrets-template.yaml](k8s/secrets-template.yaml) | Secrets template | - | - |

### Operational Tools

#### Scripts
| Script | Purpose | Usage |
|--------|---------|-------|
| [scripts/validate-deployment.sh](scripts/validate-deployment.sh) | Pre-deployment checks | `./scripts/validate-deployment.sh --mode docker` |
| [scripts/backup-restore.sh](scripts/backup-restore.sh) | Backup/recovery | `./scripts/backup-restore.sh backup\|restore\|list\|verify` |

#### Monitoring
| File | Purpose | Audience |
|------|---------|----------|
| [monitoring/prometheus-config.yml](monitoring/prometheus-config.yml) | Prometheus setup | SRE, DevOps |
| [monitoring/alert-rules.yml](monitoring/alert-rules.yml) | Alert definitions | SRE, On-call |
| [monitoring/LOGGING.md](monitoring/LOGGING.md) | Logging guide | SRE, DevOps |

---

## Deployment Paths

### Path 1: Docker Compose (Fastest)
```
QUICK_START_DEPLOYMENT.md
  ↓
scripts/validate-deployment.sh
  ↓
docker-compose up -d
  ↓
Verify endpoints
```
**Time: 5 minutes**

### Path 2: Kubernetes (Recommended)
```
DEPLOYMENT.md (Kubernetes section)
  ↓
k8s/ manifests
  ↓
kubectl apply -f k8s/
  ↓
Monitor with kubectl logs
```
**Time: 10 minutes**

### Path 3: Cloud Platform
```
DEPLOYMENT.md (Cloud section)
  ↓
Platform-specific guide
  ↓
Deploy via cloud CLI
  ↓
Configure monitoring
```
**Time: 15-30 minutes**

### Path 4: Production (Full Stack)
```
PRE_DEPLOYMENT_CHECKLIST.md
  ↓
Choose deployment platform
  ↓
DEPLOYMENT.md (full reference)
  ↓
Deploy infrastructure
  ↓
Setup monitoring/LOGGING.md
  ↓
Create backup: scripts/backup-restore.sh backup
  ↓
Go live
```
**Time: 1-2 hours**

---

## Feature Breakdown

### CI/CD Pipeline
**File:** `.github/workflows/docker.yml`

Features:
- Multi-platform builds (amd64, arm64)
- Automated security scanning (Trivy)
- SARIF report upload
- Build caching

Triggers:
- Push to main
- Version tags (v*)
- Manual workflow dispatch

### Container Security
**Files:** `Dockerfile`, `docker-compose.yaml`

Features:
- Non-root users (1000:1000)
- Minimal base images
- Dropped capabilities
- Health checks
- Graceful shutdown
- Resource limits
- Security options

### Kubernetes Orchestration
**Directory:** `k8s/`

Features:
- Enterprise-grade manifests
- High availability setup
- Zero-trust networking
- RBAC configuration
- Pod disruption budgets
- Auto-scaling (verifier)
- TLS ingress

### Monitoring & Alerting
**Directory:** `monitoring/`

Features:
- 25+ alert rules
- Prometheus integration
- Multi-log-system support
- Real-time dashboards
- Performance metrics

### Backup & Recovery
**File:** `scripts/backup-restore.sh`

Features:
- Automated backups
- Compression
- Verification
- Restoration
- Retention cleanup

---

## Configuration Reference

### Environment Variables

**Critical (Must Set)**
```bash
ADMIN_API_KEY=<32+ char random>    # Admin authentication
REQUIRE_TLS=true                   # TLS requirement
ISSUER_ID=issuer:prod:v4          # Unique identifier
```

**Recommended**
```bash
SYBIL_RESISTANCE=invitation        # Sybil resistance mode
EPOCH_DURATION_SEC=86400           # Key rotation period
```

See **[.env.example](.env.example)** for 60+ options.

### Network Ports

| Service | Port | Visibility |
|---------|------|------------|
| Issuer | 8081 | Internal, behind reverse proxy |
| Verifier | 8082 | Internal, behind reverse proxy |
| Redis | 6379 | Internal only |
| Admin API | 8081/admin | Internal IP only |

### Storage Requirements

| Component | Minimum | Recommended |
|-----------|---------|------------|
| Issuer keys | 10 MB | 100 MB |
| Invitation state | 100 MB | 1 GB |
| Redis | 1 GB | 5+ GB |
| Backup (30 days) | 30 GB | 100 GB |

---

## Security Checklist

### Pre-Deployment
- [ ] `.env` has 600 permissions
- [ ] ADMIN_API_KEY is 32+ characters
- [ ] REQUIRE_TLS=true
- [ ] TLS certificate obtained
- [ ] Network isolation planned

### Deployment
- [ ] Non-root users enforced
- [ ] Capabilities dropped
- [ ] Network policies applied
- [ ] RBAC roles minimal
- [ ] Secrets not in version control

### Post-Deployment
- [ ] Monitoring active
- [ ] Alerting configured
- [ ] Backup tested
- [ ] Security scanning enabled
- [ ] Audit logging enabled

---

## Troubleshooting

### Common Issues

**Low Entropy**
```bash
./scripts/validate-deployment.sh --mode docker --fix-entropy
```

**Services Won't Start**
```bash
# Validate
./scripts/validate-deployment.sh

# Check logs
docker-compose logs issuer
kubectl logs deployment/issuer -n freebird
```

**Port Already in Use**
```bash
# Find process
lsof -i :8081

# Kill if needed
sudo kill -9 <PID>
```

See **[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)** for more.

---

## Operations Guide

### Daily Tasks
- [ ] Review error logs
- [ ] Check alert status
- [ ] Verify backup completed

### Weekly Tasks
- [ ] Review performance metrics
- [ ] Check capacity trends
- [ ] Validate all services healthy

### Monthly Tasks
- [ ] Apply security updates
- [ ] Review and rotate secrets
- [ ] Test disaster recovery

### Quarterly Tasks
- [ ] Full backup/restore test
- [ ] Security audit
- [ ] Capacity planning review

### Annually
- [ ] Comprehensive security audit
- [ ] Disaster recovery drill
- [ ] Documentation review

---

## Getting Help

### Documentation
- **Quick questions**: [QUICK_START_DEPLOYMENT.md](QUICK_START_DEPLOYMENT.md)
- **Detailed info**: [DEPLOYMENT.md](DEPLOYMENT.md)
- **Troubleshooting**: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- **Security**: [docs/SECURITY.md](docs/SECURITY.md)
- **Configuration**: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)

### Community
- **GitHub Issues**: https://github.com/flammafex/freebird/issues
- **GitHub Discussions**: https://github.com/flammafex/freebird/discussions
- **Repository**: https://github.com/flammafex/freebird

### Support
- Report bugs on GitHub
- Ask questions in Discussions
- Review existing documentation
- Check troubleshooting guide

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-03-28 | Initial production-ready release |
| 0.4.0 | 2026-01-01 | VOPRF V3 migration |
| 0.3.0 | 2025-11-01 | Federation support |

---

## Document Map Summary

```
Deployment (Start Here)
├── QUICK_START_DEPLOYMENT.md ← 5-minute guide
├── DEPLOYMENT.md ← Complete reference
├── DEPLOYMENT_READY.md ← Summary
└── PRE_DEPLOYMENT_CHECKLIST.md ← Launch checklist

Infrastructure
├── Dockerfile
├── docker-compose.yaml
└── k8s/
    ├── namespace.yaml
    ├── issuer-deployment.yaml
    ├── verifier-deployment.yaml
    ├── redis-deployment.yaml
    ├── rbac.yaml
    ├── network-policy.yaml
    ├── ingress.yaml
    └── secrets-template.yaml

Operations
├── scripts/
│   ├── validate-deployment.sh
│   └── backup-restore.sh
└── monitoring/
    ├── prometheus-config.yml
    ├── alert-rules.yml
    └── LOGGING.md

Documentation (Reference)
├── docs/PRODUCTION.md
├── docs/SECURITY.md
├── docs/CONFIGURATION.md
├── docs/TROUBLESHOOTING.md
├── docs/API.md
├── docs/ADMIN_API.md
└── docs/FEDERATION.md
```

---

## Status

**Project:** Freebird Authorization Service
**Version:** 0.4.0+
**Status:** ✅ PRODUCTION-READY
**Last Updated:** 2026-03-28

All components are security-hardened, tested, and documented.
The project is ready for immediate production deployment.

**Next Step:** Start with [QUICK_START_DEPLOYMENT.md](QUICK_START_DEPLOYMENT.md)
