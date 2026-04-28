
## WEBAUTHN_PROOF_SECRET Documentation Fix (2026-04-28)

### What was fixed
- `docs/WEBAUTHN.md` line 92: Changed comment from "(RECOMMENDED for production)" to "(REQUIRED when WebAuthn is enabled - startup fails without it)"

### Source of truth
- `issuer/src/startup.rs:268-271` — startup bails with "WEBAUTHN_PROOF_SECRET must be set when WebAuthn is enabled" if unset
- The secret is used for HMAC key derivation via BLAKE3 with domain separation

### Approach
- Simple documentation fix to accurately reflect code behavior
- No restructure, no version-specific claims added

## CONFIGURATION.md ADMIN_API_KEY fix (2026-04-28)

**Task:** Fix docs/CONFIGURATION.md line 38 - ADMIN_API_KEY was documented as "unset" (optional) but code requires it.

**Source of truth:** `issuer/src/startup.rs:189-196` and `verifier/src/main.rs:316-323` both bail with `"ADMIN_API_KEY must be set (minimum 32 characters)"`.

**Change made:**
- Before: `| ADMIN_API_KEY | unset | Enables issuer admin endpoints when at least 32 characters. |`
- After: `| ADMIN_API_KEY | REQUIRED | Required for admin endpoints (≥32 characters). Both issuer and verifier fail to start without it. |`

**Verification:** `grep -i 'ADMIN_API_KEY' docs/CONFIGURATION.md` shows "REQUIRED" in the table entry.

## docker-compose.yaml T0 Fixes (2026-04-28)

### What was fixed

1. **Issuer healthcheck** — Changed from `http://localhost:8081/.well-known/issuer` (metadata endpoint) to `http://localhost:8081/admin/health` with admin key header
   - Before: `test: ["CMD", "curl", "-f", "http://localhost:8081/.well-known/issuer"]`
   - After: `test: ["CMD", "curl", "-f", "-H", "X-Admin-Key: ${ADMIN_API_KEY}", "http://localhost:8081/admin/health"]`
   - Rationale: The `/.well-known/issuer` endpoint is a metadata/JWK endpoint, not a health check. The issuer has `/admin/health` (requires API key) for actual health monitoring.

2. **Verifier missing ADMIN_API_KEY** — Added `ADMIN_API_KEY=${ADMIN_API_KEY}` to verifier service environment
   - Location: docker-compose.yaml lines 114-126 (verifier environment block)
   - Source: `verifier/src/main.rs:316-323` requires ADMIN_API_KEY ≥32 chars

3. **Issuer entrypoint** — Added `validate-env.sh` entrypoint reference
   - Before: No entrypoint on issuer (only verifier had it)
   - After: `entrypoint: ["/bin/sh", "-c", "scripts/validate-env.sh && exec freebird-issuer"]`
   - Consistent with verifier entrypoint pattern

## .env.example ADMIN_API_KEY and salt documentation (2026-04-28)

### Issues found (T0 audit)
1. ADMIN_API_KEY appeared only in ISSUER section, NOT in VERIFIER section
2. Salt values were commented out with `change-in-production` — code auto-generates random salts if not provided, but this wasn't documented

### Changes made
1. Added ADMIN_API_KEY to VERIFIER CONFIGURATION section (line 202)
   - With same value as issuer section: `dev-admin-key-must-be-at-least-32-characters-long`
   - Placed after V4 verification key material, before LOGGING CONFIGURATION
   - Same REQUIRED comment block as issuer section

2. Added salt auto-generation documentation in Sybil Resistance Configuration section (lines 64-65)
   - Added: `# Salts are auto-generated with secure random values if not explicitly set.`
   - Added: `# For production, set explicit salts to ensure consistency across restarts.`

### Source of truth
- `verifier/src/main.rs:316-323` — Verifier bails if ADMIN_API_KEY missing or < 32 chars
- `issuer/src/config.rs` — Random salt generation if not provided

### Verification
```
grep 'ADMIN_API_KEY' .env.example
# Shows ADMIN_API_KEY at lines 43 (issuer) and 202 (verifier)
```

## PRODUCTION.md Operational Concerns Update (2026-04-28)

### What was added
1. **validate-env.sh startup validation** — Added "Startup Validation" subsection under Systemd Service Files. Documents that the script checks ADMIN_API_KEY length/default, REQUIRE_TLS=true, and REDIS_URL presence. Exits code 1 on failure.
2. **HTTPS-only metadata refresh** — Added note in Container Deployment (verifier config) that ISSUER_URL must use HTTPS or verifier logs "issuer metadata URL must use HTTPS" and skips refresh. Links to FEDERATION.md.
3. **Health endpoints** — Updated Monitoring & Alerting > Health Checks section. Documents:
   - Verifier public `/health` (no auth)
   - Issuer `/admin/health` (requires API key)
   - Verifier `/admin/health` (requires API key)
4. **Runtime security features** — Added "Runtime Security Features" subsection under Security Hardening. Brief 1-2 sentence notes on:
   - TLS enforcement (REQUIRE_TLS, BEHIND_PROXY, HTTP 400)
   - CORS (public endpoints only)
   - Public rate limiting (30 req/sec per IP, HTTP 429)
   - Atomic state writes (temp file + rename, mode 0600)
   - Prometheus metrics middleware (/admin/metrics)

### Source of truth
- `scripts/validate-env.sh` — ADMIN_API_KEY, REQUIRE_TLS, REDIS_URL checks
- `verifier/src/main.rs:461-466` — HTTPS-only metadata refresh enforcement
- `verifier/src/main.rs:886-891` — Public `/health` handler
- `common/src/tls_enforcement.rs:68-88` — TLS enforcement returning 400 on HTTP
- `common/src/rate_limit.rs` — PublicRateLimitLayer: 30 req/sec per IP
- `issuer/src/sybil_resistance/progressive_trust.rs:290-319` — Atomic writes pattern
- `common/src/metrics.rs` — Prometheus metrics middleware

### Verification
- `grep -c 'validate.env\|validate-env' docs/PRODUCTION.md` → 1
- `grep -c 'HTTPS\|must use HTTPS' docs/PRODUCTION.md` → 3
- `grep -c '/health\|health.*endpoint' docs/PRODUCTION.md` → 3
- `grep -c 'TLS enforcement\|CORS\|rate limiting\|atomic.*write\|Prometheus metrics' docs/PRODUCTION.md` → 5

## TROUBLESHOOTING.md Startup Failures Section (2026-04-28)

### What was added
Added a new **Startup Failures** section after "Quick Diagnostics" with 5 exact startup errors:
1. `ADMIN_API_KEY must be set (minimum 32 characters)` — issuer + verifier
2. `ADMIN_API_KEY must be at least 32 characters, got N` — issuer + verifier
3. `WEBAUTHN_PROOF_SECRET must be set when WebAuthn is enabled` — issuer
4. `grace period must be at least 3600 seconds (got N)` — issuer key rotation
5. `issuer metadata URL must use HTTPS: {url}` — verifier

Each entry follows the existing TROUBLESHOOTING.md style: ### heading, bold Error with backticks, Cause paragraph, Resolution with bash code block.

### Source of truth
- `issuer/src/startup.rs:189-196` — ADMIN_API_KEY missing / too short
- `issuer/src/startup.rs:268-271` — WEBAUTHN_PROOF_SECRET missing
- `issuer/src/multi_key_voprf.rs:304-321` — grace period minimum 3600
- `verifier/src/main.rs:316-323` — ADMIN_API_KEY missing / too short
- `verifier/src/main.rs:461-466` — HTTPS-only issuer metadata

### Verification
- `grep -c 'ADMIN_API_KEY must be set' docs/TROUBLESHOOTING.md` → 1
- `grep -c 'ADMIN_API_KEY must be at least' docs/TROUBLESHOOTING.md` → 1
- `grep -c 'WEBAUTHN_PROOF_SECRET must be set' docs/TROUBLESHOOTING.md` → 1
- `grep -c 'grace period must be at least 3600' docs/TROUBLESHOOTING.md` → 1
- `grep -c 'issuer metadata URL must use HTTPS' docs/TROUBLESHOOTING.md` → 1
