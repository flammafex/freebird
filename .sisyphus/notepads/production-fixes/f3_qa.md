# F3 QA Report — Production Fixes Verification

**Date:** 2026-04-27
**Tester:** Sisyphus-Junior
**Scope:** Rust workspace build, Docker Compose config, env documentation, CI validity, health checks

---

## 1. Build Verification

**Command:** `cargo build --workspace`
**Result:** ✅ PASS

- All workspace crates compiled successfully:
  - `freebird-common v0.5.0`
  - `freebird-issuer v0.5.0`
  - `freebird-verifier v0.5.0`
  - `freebird-interface v0.5.0`
- Warnings observed (non-blocking):
  - `redis v0.24.0` triggers a future-incompatibility warning from the Rust compiler.
  - Admin UI copy warnings (`Copied admin UI from ../admin-ui/index.html`) for issuer and verifier.

---

## 2. Docker Compose Config Validation

**Command:** `docker compose config` ( attempted )
**Result:** ⚠️ Docker CLI unavailable on host; YAML syntax validated via `ruby -ryaml`

- `docker-compose.yaml`: YAML structure is **VALID**.
- `.github/workflows/ci.yml`: YAML structure is **VALID**.

### Critical Issues Found

#### 2.1 Verifier Entrypoint References Missing Script (BLOCKER)
- **Location:** `docker-compose.yaml` line 100
- **Issue:** Verifier `entrypoint` runs `scripts/validate-env.sh && exec freebird-verifier`
- **Problem:** The verifier Docker image (`Dockerfile` stage `verifier`) does **NOT** copy `scripts/validate-env.sh` into the image. Only the binary `/usr/local/bin/freebird-verifier` is copied.
- **Impact:** Verifier container will fail to start with:
  ```
  /bin/sh: 1: scripts/validate-env.sh: not found
  ```
- **Fix Options:**
  1. Add `COPY scripts/validate-env.sh /app/scripts/validate-env.sh` to the verifier stage in `Dockerfile`
  2. Mount `scripts/validate-env.sh` as a bind volume in `docker-compose.yaml`
  3. Remove the entrypoint override and let the Dockerfile `CMD` run directly

#### 2.2 `.env.example` / `docker-compose.yaml` Variable Mismatches

| Variable in docker-compose | Documented in .env.example? | Notes |
|----------------------------|----------------------------|-------|
| `ISSUER_BIND_ADDR` | ❌ NO | Only `BIND_ADDR` is documented (issuer section). Used for host port mapping. |
| `VERIFIER_BIND_ADDR` | ❌ NO | Only `BIND_ADDR` is documented (verifier section). Used for host port mapping. |
| `ISSUER_IMAGE` | ❌ NO | Image override variable; has default in docker-compose. |
| `VERIFIER_IMAGE` | ❌ NO | Image override variable; has default in docker-compose. |
| `VERIFIER_EPOCH_DURATION_SEC` | ❌ NO | `.env.example` has `EPOCH_DURATION_SEC` but docker-compose reads `VERIFIER_EPOCH_DURATION_SEC` |
| `VERIFIER_EPOCH_RETENTION` | ❌ NO | `.env.example` has `EPOCH_RETENTION` but docker-compose reads `VERIFIER_EPOCH_RETENTION` |

#### 2.3 `VERIFIER_SK_PATH` Path Mismatch
- **`.env.example` value:** `/data/keys/issuer_sk.bin`
- **docker-compose default:** `/issuer-data/keys/issuer_sk.bin`
- **Issue:** The verifier container mounts `issuer-data:/issuer-data:ro`, not `/data`. If a user copies `.env.example` verbatim, the verifier will look for the key at `/data/keys/issuer_sk.bin`, which does not exist in the verifier container.
- **Impact:** Verifier will fail to load the V4 private verification key.

#### 2.4 `.env.example` Variable Naming Inconsistency
- `.env.example` uses base names (e.g., `SYBIL_INVITE_COOLDOWN`) while `docker-compose.yaml` maps them to `_SECS` variants (e.g., `SYBIL_INVITE_COOLDOWN_SECS`).
- This translation is handled by docker-compose defaults and is functional, but it can confuse operators who expect 1:1 parity.

---

## 3. `scripts/validate-env.sh` Verification

**File:** `scripts/validate-env.sh`
**Result:** ✅ EXISTS and is EXECUTABLE (`-rwxr-xr-x`)

**Checks performed by script:**
- `ADMIN_API_KEY` length >= 32
- `ADMIN_API_KEY` is not the insecure default
- `REQUIRE_TLS` is enabled
- `REDIS_URL` is set

**Note:** Script exits with code 1 if any warnings are found. Since the verifier `entrypoint` runs this script before starting, the verifier will refuse to start with the default `.env` values (which is intentional for production safety).

---

## 4. CI Workflow Validity

**File:** `.github/workflows/ci.yml`
**Result:** ✅ VALID YAML

**Jobs defined:**
- `build`: `cargo build --release`
- `test`: `cargo test --workspace` (with Redis service)
- `lint`: `cargo fmt --check` + `cargo clippy --workspace -- -D warnings`
- `security`: `cargo audit`

**Observations:**
- No `docker-compose config` validation step in CI.
- No `.env.example` drift check in CI.
- Build job uses `--release` while this QA used debug build; both passed.

---

## 5. Health Check Endpoints

**Result:** ✅ CONFIGURED

### Issuer
- **Docker Compose:** `http://localhost:8081/.well-known/issuer`
- **Dockerfile:** `curl -f http://localhost:8081/.well-known/issuer`
- **Code:** `/.well-known/issuer` route exists in `issuer/src/startup.rs`
- **Also available:** `/health` route exists in `issuer/src/routes/admin.rs`

### Verifier
- **Docker Compose:** `http://localhost:8082/health`
- **Dockerfile:** `curl -f http://localhost:8082/health`
- **Code:** `/health` route exists in `verifier/src/main.rs` and `verifier/src/routes/admin.rs`

### Redis
- **Docker Compose:** `redis-cli ping`
- **Standard Redis health check; valid.**

**Note:** `curl` is installed in both runtime images (`debian:bookworm-slim` stages install `curl`), so health check commands will execute successfully.

---

## 6. Other Observations

- **Admin UI:** Both issuer and verifier embed the admin UI; build logs confirm successful copy.
- **Non-root user:** Both containers run as `freebird` user (UID 1000) — good security practice.
- **Capability dropping:** Both services drop all capabilities and only add `NET_BIND_SERVICE`.
- **Resource limits:** CPU and memory limits are defined for all services.
- **Log rotation:** `json-file` driver with `max-size` and `max-file` limits configured.

---

## Final Verdict

**REJECT**

### Must Fix Before Approval

1. **Verifier entrypoint references missing `scripts/validate-env.sh`** — The script is not copied into the verifier Docker image. The container will fail to start.
2. **`VERIFIER_SK_PATH` in `.env.example` is incorrect for Docker** — Points to `/data/keys/issuer_sk.bin` but verifier container only has `/issuer-data` mounted.
3. **Missing environment variables in `.env.example`** — `ISSUER_BIND_ADDR`, `VERIFIER_BIND_ADDR`, `ISSUER_IMAGE`, `VERIFIER_IMAGE`, `VERIFIER_EPOCH_DURATION_SEC`, and `VERIFIER_EPOCH_RETENTION` are used by `docker-compose.yaml` but not documented.

### Non-blocking Suggestions

- Add `docker compose config` validation to CI pipeline.
- Add an `.env.example` drift test to CI (ensure all `${VAR}` references in docker-compose are documented).
- Consider using `/health` instead of `/.well-known/issuer` for the issuer Docker Compose healthcheck to align with the dedicated health endpoint.

---
