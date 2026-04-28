# F4: Scope Fidelity Check

## Date
2026-04-27

## Methodology
- `git diff --stat` to assess total change scope
- `git diff --name-status` to check for deleted/renamed files
- `git status --short` to identify untracked new files
- Manual review of all Cargo.toml, Cargo.lock, Dockerfile, and docker-compose.yaml changes
- Manual review of all modified .rs files for public API surface changes

## Findings

### 1. Total Change Scope
- **19 files modified**, **0 files deleted**, **0 files renamed**
- **3 new untracked files** (all expected per fix list)
- Rust files only: 13 files changed, 135 insertions(+), 20 deletions(-)

### 2. New Files (All Expected)
| File | Fix # | Purpose |
|------|-------|---------|
| `common/src/metrics.rs` | #21 | Prometheus request latency + error metrics registry |
| `.github/workflows/ci.yml` | #17 | GitHub Actions CI workflow (build/test/lint/audit) |
| `scripts/validate-env.sh` | #22 | Pre-flight .env validation script for Docker |

### 3. Cargo.toml / Dependency Changes
- **No crate version bumps** (all crates remain at 0.5.0)
- **No crate restructuring** (no renames, no path changes, no workspace reorganization)
- **New dependencies added** (all required by identified fixes):
  - `prometheus = "0.13"` — fix #21 (metrics)
  - `lazy_static = "1.4"` — fix #21 (metrics registry)
  - `axum = "0.7"` — fix #21 (metrics middleware in common)
  - `tower = "0.4"` — fix #21 (metrics middleware in common)
  - `futures-util = "0.3"` — fix #21 (metrics middleware)
- **Existing dependency feature addition**:
  - `tower-http` gained `"cors"` feature in both `issuer/` and `verifier/` — fix #14 (CORS headers)
- **No major version upgrades** of existing dependencies
- **No security-driven upgrades** were needed

### 4. Deleted / Renamed Files
- **Zero files deleted**
- **Zero modules renamed**
- **Zero crate restructuring**

### 5. Public API Changes (All Required by Identified Fixes)
| Change | File | Fix # | Justification |
|--------|------|-------|---------------|
| `pub mod metrics` added | `common/src/lib.rs` | #21 | Required to share metrics registry across crates |
| `/health` route added | `verifier/src/main.rs` | #18 | Verifier health check endpoint + Docker HEALTHCHECK |
| `/admin/metrics` route added | `verifier/src/routes/admin.rs` | #21 | Prometheus metrics endpoint on verifier admin router |
| `StoreBackend::build()` returns `Result<_, StoreError>` | `verifier/src/store.rs` | #19 | Make RedisStore::build() return Result instead of panic |
| `CorsLayer` on public router | `issuer/src/startup.rs`, `verifier/src/main.rs` | #14 | Add CORS headers for public endpoints |
| `MetricsMiddleware` layer added | `issuer/src/startup.rs`, `verifier/src/main.rs` | #21 | Prometheus request latency + error recording |

### 6. Minor Incidental Changes (Clippy Fixes)
Several files contain trivial clippy-driven cleanups with **zero behavioral change**:
- `common/src/duration.rs`: `let mut chars` → `let chars` (remove unnecessary mut)
- `issuer/src/bin/validate_config.rs`: `.last()` → `.next_back()`
- `issuer/src/config.rs`: remove redundant match arm `"storage" | _`
- `issuer/src/routes/issue.rs`: remove unnecessary `&` in `.record()`
- `issuer/src/routes/admin.rs`: `.ok_or_else(|| ...)` → `.ok_or(...)`
- `issuer/src/sybil_resistance/multi_party_vouching.rs`: remove unnecessary `&`
- `issuer/src/sybil_resistance/progressive_trust.rs`: remove redundant `return` keywords
- `verifier/src/routes/admin_rate_limit.rs`: remove `#[allow(dead_code)]` from `cleanup_expired()` (enables fix #20)

These are not new features, not architectural refactoring, and do not change public APIs. They are trivial lint cleanups incidental to the CI workflow fix (#17) which enforces `cargo clippy -- -D warnings`.

### 7. Docker Changes
- `Dockerfile`: added `curl` package — fix #22
- `Dockerfile`: added `HEALTHCHECK` instruction — fix #18
- `docker-compose.yaml`: changed healthcheck URL to `/health` — fix #18
- `docker-compose.yaml`: added `entrypoint` with `validate-env.sh` — fix #22
- **No new base images**, **no sidecars**, **no Docker architecture changes**

## Verdict: APPROVE

No feature creep detected. All changes are directly attributable to the 22 identified production fixes. No new public APIs were added beyond those required by fixes #18, #19, #21. No crate restructuring occurred. No dependency major version upgrades occurred. No files were deleted or renamed. New files are limited to `metrics.rs`, `ci.yml`, and `validate-env.sh` — all explicitly expected.
