# F1 Plan Compliance Audit Report

**Auditor:** Sisyphus-Junior  
**Date:** 2026-04-27  
**Scope:** All 22 implementation tasks (T0–T22) from `.sisyphus/plans/production-fixes.md`  
**Method:** Direct code inspection with file/line citations. No trust in checkboxes.

---

## Summary

| Task | Status | Notes |
|------|--------|-------|
| T0 | **PASS** | Test baseline verified |
| T1 | **FAIL** | Default admin key still present in docker-compose; missing key does not fail startup |
| T2 | **PASS** | Session key derived via HKDF-SHA256 from ADMIN_API_KEY |
| T3 | **FAIL** | Insecure default salts still present; no startup failure enforcement |
| T4 | **FAIL** | No minimum grace period enforcement in rotate_key |
| T5 | **FAIL** | ban_user only bans direct children, not recursive BFS |
| T6 | **PASS** | All 4 state writes use temp-file-then-rename |
| T7 | **FAIL** | No HTTPS enforcement or public key pinning in verifier metadata refresh |
| T8 | **FAIL** | WebAuthn still falls back to deterministic key; no startup failure |
| T9 | **FAIL** | Short/missing ADMIN_API_KEY disables admin API but does not fail startup |
| T10 | **FAIL** | batch_issue.rs still uses rayon + block_on |
| T11 | **FAIL** | No IP-based rate limiting on public token endpoints |
| T12 | **FAIL** | Periodic cleanup exists but no LRU eviction |
| T13 | **FAIL** | No TLS enforcement middleware or X-Forwarded-Proto handling in Rust code |
| T14 | **PASS** | CORS layers present on public endpoints |
| T15 | **PASS** | Graceful shutdown via axum::serve::with_graceful_shutdown |
| T16 | **FAIL** | RedisStore creates a new connection per call; no pooling |
| T17 | **PASS** | GitHub Actions CI workflow present |
| T18 | **PASS** | Verifier health endpoint + Docker HEALTHCHECK configured |
| T19 | **PASS** | RedisStore::build() returns Result instead of panicking |
| T20 | **FAIL** | Periodic cleanup task only in verifier, not in issuer admin rate limiter |
| T21 | **PASS** | Prometheus request latency + error metrics implemented |
| T22 | **PASS** | curl in verifier image; .env validation script present and invoked |

**Final Verdict: REJECT** — 11 of 22 tasks are not fully implemented.

---

## Detailed Findings

### T0 — Verify Existing Test Baseline
**Status: PASS**
- `cargo test --workspace` executed successfully.
- All unit tests, integration tests, and doc tests passed.
- No regressions detected.

---

### T1 — Remove Default Admin Key from docker-compose + Fail on Missing Key
**Status: FAIL**
- **docker-compose.yaml:35** still contains a default fallback:
  ```yaml
  ADMIN_API_KEY=${ADMIN_API_KEY:-dev-admin-key-must-be-at-least-32-characters-long}
  ```
  The default value `"dev-admin-key-must-be-at-least-32-characters-long"` is still present.
- **issuer/src/startup.rs:723–767**: If `admin_api_key` is `None` or `< 32` chars, the admin router is simply skipped. Startup does **not** fail.
- **verifier/src/main.rs:380–423**: Same behavior — warns and disables admin API, but does not fail startup.

**Required fix:** Remove the `:-...` default from docker-compose.yaml and change startup logic to `bail!("ADMIN_API_KEY is required and must be >= 32 characters")`.

---

### T2 — Derive HMAC Comparison Key from ADMIN_API_KEY
**Status: PASS**
- **issuer/src/routes/admin.rs:68–76**: `derive_session_key(api_key: &str)` uses HKDF-SHA256 with salt `b"freebird-session-salt"` to derive a 32-byte session key.
- **verifier/src/routes/admin.rs:104–112**: Identical implementation.

---

### T3 — Fail Startup on Insecure Default Salts + Generate Random Fallbacks
**Status: FAIL**
- **issuer/src/config.rs:291**: `progressive_trust_salt` defaults to `"default-salt-change-in-production"`.
- **issuer/src/config.rs:309**: `proof_of_diversity_fingerprint_salt` defaults to `"default-salt-change-in-production"`.
- **issuer/src/config.rs:344**: `multi_party_vouching_salt` defaults to `"default-salt-change-in-production"`.
- **issuer/src/startup.rs**: No startup validation that fails if these defaults are in use.
- **issuer/src/bin/validate_config.rs:410–449**: The standalone validator flags these as errors, but it is a separate CLI tool and is **not** invoked during `Application::build()`.
- The HMAC secrets *are* generated randomly (progressive_trust.rs, proof_of_diversity.rs, multi_party_vouching.rs), but the **salts** still have insecure string defaults.

**Required fix:** Add a startup check in `Application::build()` that `bail!()` if any salt matches the default pattern.

---

### T4 — Add Minimum Grace Period Enforcement for Key Rotation
**Status: FAIL**
- **issuer/src/multi_key_voprf.rs:185**: `default_grace_period_secs` is `30 * 24 * 3600` (30 days).
- **issuer/src/multi_key_voprf.rs:298**: `rotate_key` uses `grace_period_secs.unwrap_or(self.default_grace_period_secs)` with **no minimum bound**.
- Test at **multi_key_voprf.rs:617** confirms `Some(1)` is accepted.

**Required fix:** Enforce a minimum grace period (e.g., `grace_period.max(MIN_GRACE_PERIOD_SECS)`).

---

### T5 — Fix Invitation Tree Ban to Use Recursive BFS with Depth Cap
**Status: FAIL**
- **issuer/src/sybil_resistance/invitation.rs:826–859**: `ban_user` with `ban_tree=true` only bans **direct invitees** (single level):
  ```rust
  for invitation in state.invitations.values() {
      if invitation.inviter_id == user_id {
          if let Some(ref invitee_id) = invitation.invitee_id {
              to_ban.push(invitee_id.clone());
          }
      }
  }
  ```
- **issuer/src/sybil_resistance/invitation.rs:1048–1073**: `count_ban_tree_size` **does** implement recursive BFS with a `checked` HashSet, but this logic is **not reused** by `ban_user`.

**Required fix:** Extract the BFS loop from `count_ban_tree_size` into a shared helper and call it from `ban_user`, adding a depth cap.

---

### T6 — Convert 4 Non-Atomic State Writes to Temp-File-Then-Rename Pattern
**Status: PASS**
1. **progressive_trust.rs:291–318** — `atomic_write_secure` writes to `.tmp` then `fs::rename`.
2. **proof_of_diversity.rs:222–248** — `atomic_write_secure` writes to `.tmp` then `fs::rename`.
3. **multi_party_vouching.rs:169–196** — `atomic_write_secure` writes to `.tmp` then `fs::rename`.
4. **invitation.rs:514–527** — `save_to_file` writes to `.tmp` then `tokio::fs::rename`.

---

### T7 — Require HTTPS for Verifier Issuer Metadata Refresh + Add Public Key Pinning
**Status: FAIL**
- **verifier/src/main.rs:162**: `reqwest::get(&keys_url)` — uses the default reqwest client, no HTTPS enforcement.
- **verifier/src/main.rs:456**: `reqwest::get(issuer_url)` — same issue; HTTP URLs are accepted.
- No public key pinning (no `reqwest::ClientBuilder::add_root_certificate` or pinned SPKI logic).

**Required fix:** Build a reqwest client that rejects non-HTTPS URLs for issuer metadata, and optionally pin the issuer's public key.

---

### T8 — Fail WebAuthn Startup if PROOF_SECRET Not Set + Remove Insecure Fallback
**Status: FAIL**
- **issuer/src/webauthn/handlers.rs:31–58**: `derive_proof_key` checks `WEBAUTHN_PROOF_SECRET`.
  - If set: derives key from secret (secure).
  - If **not set**: falls back to deterministic derivation from `rp_id` (lines 40–47), marked with `:insecure-fallback`.
- No startup failure occurs when `WEBAUTHN_PROOF_SECRET` is missing.

**Required fix:** In startup.rs WebAuthn initialization, `bail!("WEBAUTHN_PROOF_SECRET must be set")` if the env var is absent.

---

### T9 — Enforce ADMIN_API_KEY Minimum Length as Startup Error
**Status: FAIL**
- **issuer/src/startup.rs:723–724**: `if let Some(key) = config.admin_api_key { if key.len() >= 32 { ... } }`
  - Missing or short key → admin router omitted, startup continues.
- **verifier/src/main.rs:381**: `if api_key.len() >= 32 { ... }`
  - Short key → warning log, admin router omitted, startup continues.

**Required fix:** Change both to `bail!("ADMIN_API_KEY must be at least 32 characters")`.

---

### T10 — Replace rayon+block_on with tokio JoinSet for Batch Operations
**Status: FAIL**
- **issuer/src/routes/batch_issue.rs:36**: `use rayon::prelude::*;`
- **issuer/src/routes/batch_issue.rs:322**: `let runtime_handle = tokio::runtime::Handle::current();`
- **issuer/src/routes/batch_issue.rs:331**: `runtime_handle.block_on(async { evaluate_token(...) })` — still bridges rayon and tokio via `block_on`.

**Required fix:** Replace rayon parallel iteration with `tokio::task::JoinSet` for async evaluation.

---

### T11 — Add IP-Based Rate Limiting on Public Token Endpoints
**Status: FAIL**
- Existing rate limiters:
  - `issuer/src/routes/admin_rate_limit.rs` — admin API only.
  - `verifier/src/routes/admin_rate_limit.rs` — admin API only.
  - `issuer/src/webauthn/rate_limit.rs` — WebAuthn endpoints only.
  - `issuer/src/sybil_resistance/rate_limit.rs` — Sybil proof verification, not HTTP-layer IP throttling.
- **No** IP-based rate limiting middleware or handler logic on `/v1/oprf/issue`, `/v1/oprf/issue/batch`, `/v1/public/issue`, or `/v1/verify`.

**Required fix:** Add a Tower middleware or handler-level check that tracks requests per IP on public endpoints.

---

### T12 — Add LRU Eviction + Periodic Cleanup to Unbounded HashMaps
**Status: FAIL**
- Periodic cleanup **does** exist:
  - `sybil_resistance/rate_limit.rs:84–85` — `state.retain(...)` inside `check_rate_limit`.
  - `webauthn/rate_limit.rs:226–233` — `cleanup_expired()` method.
  - `admin_rate_limit.rs:156–169` — `cleanup_expired()` method.
- However, all structures are standard `HashMap`, not LRU caches. There is **no size-based eviction**; unbounded growth is only mitigated by time-based retention.

**Required fix:** Replace with an LRU cache (e.g., `lru` crate) or add a hard capacity limit with eviction.

---

### T13 — Enforce REQUIRE_TLS at HTTP Layer + Add X-Forwarded-Proto Middleware
**Status: FAIL**
- `require_tls` is parsed into config and stored in `AppStateWithSybil` (**issuer/src/lib.rs:27**) and `AdminState` (**verifier/src/routes/admin.rs:96**), but:
  - No Tower middleware rejects plain-HTTP requests.
  - No middleware inspects `X-Forwarded-Proto` to upgrade scheme detection behind a proxy.
- The only place `X-Forwarded-Proto` appears is in nginx server configs (`server-configs/`).

**Required fix:** Add a Tower layer that checks `req.uri().scheme()` or `X-Forwarded-Proto` header and returns 400/403 when `REQUIRE_TLS=true` and the request is HTTP.

---

### T14 — Add CORS Headers for Public Endpoints
**Status: PASS**
- **issuer/src/startup.rs:699–709**: `CorsLayer::new().allow_origin(Any).allow_methods(...)` applied before stateful routes.
- **verifier/src/main.rs:366–376**: Identical CORS layer on verifier public routes.

---

### T15 — Add Graceful Shutdown with Connection Drain Period
**Status: PASS**
- **issuer/src/startup.rs:798**: `axum::serve(...).with_graceful_shutdown(shutdown_signal())`
- **verifier/src/main.rs:447**: Same pattern.
- axum's `with_graceful_shutdown` natively drains active connections before terminating.

---

### T16 — Add Redis Connection Pooling to Verifier Store
**Status: FAIL**
- **verifier/src/store.rs:127–136**: `RedisStore` holds a single `redis::Client`.
- **verifier/src/store.rs:138–155**: `get_conn()` calls `client.get_async_connection()` on **every** `mark_spent` call with retry logic, but no pool.
- No `bb8-redis`, `deadpool-redis`, or `redis::aio::MultiplexedConnection` pooling.

**Required fix:** Integrate a connection pool (e.g., `deadpool-redis`) or use `MultiplexedConnection`.

---

### T17 — Add GitHub Actions CI Workflow
**Status: PASS**
- **.github/workflows/ci.yml**: Build, test (with Redis service), lint (`cargo fmt --check`, `cargo clippy`), and security (`cargo audit`) jobs present.

---

### T18 — Fix Verifier Health Check Endpoint + Add Docker HEALTHCHECK
**Status: PASS**
- **verifier/src/main.rs:869–874**: `health_handler` returns `{"status": "ok", "version": ...}`.
- **docker-compose.yaml:135**: Verifier healthcheck configured.
- **Dockerfile:125**: `HEALTHCHECK CMD curl -f http://localhost:8082/health || exit 1`.

---

### T19 — Make RedisStore::build() Return Result Instead of Panic
**Status: PASS**
- **verifier/src/store.rs:183**: `pub async fn build(self) -> Result<Arc<dyn SpendStore>, StoreError>`
- Returns `StoreError::Connection(...)` on Redis connection failure (line 192).

---

### T20 — Add Periodic Cleanup Task for Admin Rate Limiter
**Status: FAIL**
- **verifier/src/main.rs:407–413**: Cleanup task spawned for verifier admin rate limiter (300s interval).
- **issuer/src/startup.rs**: No equivalent cleanup task spawned for the issuer admin rate limiter.

**Required fix:** Spawn a background cleanup task for the issuer's `AdminRateLimiter` in `Application::build()`.

---

### T21 — Add Prometheus Request Latency + Error Metrics
**Status: PASS**
- **common/src/metrics.rs:12–27**: `REQUEST_DURATION` histogram and `REQUEST_ERRORS` counter defined.
- **common/src/metrics.rs:82–96**: `MetricsMiddleware` records duration and errors per request.
- Applied in **issuer/src/startup.rs:776** and **verifier/src/main.rs:431**.

---

### T22 — Add curl to Verifier Docker Image + Add .env Validation Script
**Status: PASS**
- **Dockerfile:101–105**: `curl` installed in verifier runtime stage.
- **scripts/validate-env.sh**: Validates `ADMIN_API_KEY` length, `REQUIRE_TLS`, and `REDIS_URL`.
- **docker-compose.yaml:100**: Verifier entrypoint runs `scripts/validate-env.sh && exec freebird-verifier`.

---

## Issues Requiring Fix

1. **T1** — Remove default admin key from docker-compose; fail startup on missing/short key.
2. **T3** — Enforce startup failure when insecure default salts are detected.
3. **T4** — Enforce minimum grace period in `rotate_key()`.
4. **T5** — Make `ban_user` recursive with BFS and depth cap.
5. **T7** — Require HTTPS and add public key pinning for verifier issuer refresh.
6. **T8** — Fail WebAuthn startup if `WEBAUTHN_PROOF_SECRET` is unset; remove deterministic fallback.
7. **T9** — Convert ADMIN_API_KEY length check into a startup error.
8. **T10** — Replace rayon+block_on with `tokio::task::JoinSet` in batch_issue.rs.
9. **T11** — Add IP-based rate limiting middleware on public token endpoints.
10. **T12** — Add LRU eviction (not just time-based cleanup) to unbounded maps.
11. **T13** — Implement TLS enforcement middleware and X-Forwarded-Proto handling.
12. **T16** — Add Redis connection pooling to verifier store.
13. **T20** — Add periodic cleanup task for issuer admin rate limiter.

**Total: 13 fixes required across 11 tasks (T1, T3, T4, T5, T7, T8, T9, T10, T11, T12, T13, T16, T20).**

---

*Report generated by direct code inspection. All line numbers refer to the codebase state at audit time.*
