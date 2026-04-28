# Documentation Accuracy Fixes

## TL;DR

> **Quick Summary**: Fix 12 documentation inaccuracies and gaps across 13 files, making docs match the actual code behavior from the recent production hardening work.
> 
> **Deliverables**:
> - 5 critical doc fixes (wrong info → correct info)
> - 5 moderate doc additions (missing feature documentation)
> - 2 low-severity stale reference fixes
> - Cross-reference audit to catch any remaining stale references
> 
> **Estimated Effort**: Medium
> **Parallel Execution**: YES - 3 waves
> **Critical Path**: T0 (grep audit) → T1-T5 (critical fixes) → T6-T12 (moderate/low fixes)

---

## Context

### Original Request
Fix all documentation issues identified in the production audit — 5 critical (wrong info causing confusion/failures), 5 moderate (missing new features), 2 low (stale references).

### Interview Summary
**Key Discussions**:
- User approved fixing all severity levels
- Scope limited to documentation accuracy only — no code changes, no new features, no doc restructuring
- All source-of-truth behavior verified from actual code (exact line numbers and quotes available)

**Research Findings**:
- ADMIN_API_KEY: REQUIRED (≥32 chars) for both issuer and verifier, startup bails if missing
- WEBAUTHN_PROOF_SECRET: REQUIRED when WebAuthn is enabled, startup bails without it
- MIN_GRACE_PERIOD_SECS: 3600 in prod, 1 in test; rotation rejects below minimum
- Rate limiting: 30 req/sec per IP (public), LruCache 10k entries (admin)
- TLS enforcement: Rejects non-HTTPS with 400 JSON error `{"error": "tls_required"}`
- HTTPS metadata: Verifier refuses non-HTTPS issuer URLs
- Atomic writes: temp file (0600 perms) + rename pattern
- JoinSet: Concurrent batch ≥10 items, sequential <10
- validate-env.sh: Checks ADMIN_API_KEY length/defaults, REQUIRE_TLS, REDIS_URL
- Health endpoints: Public `/health` on verifier only, admin `/admin/health` on both

### Metis Review
**Identified Gaps** (addressed):
- Cross-reference audit: Added pre-flight grep task (T0)
- README feature bloat risk: Guardrail — 1-line summaries + deep links only
- Rate limiting duplication: Guardrail — public in API.md, admin in ADMIN_API.md, cross-reference only
- Test vs prod mode divergences: Must document both (e.g., MIN_GRACE_PERIOD_SECS)
- .env.example defaults: Document what code requires, don't choose new defaults arbitrarily
- docker-compose.yaml scope: Treated as documentation (config accuracy)
- Auto-generated docs: No auto-generated docs detected; all hand-written Markdown

---

## Work Objectives

### Core Objective
Make all documentation accurately reflect the current code behavior — no wrong info, no missing features, no stale references.

### Concrete Deliverables
- `docs/CONFIGURATION.md` — ADMIN_API_KEY described as REQUIRED (≥32 chars)
- `docs/WEBAUTHN.md` — WEBAUTHN_PROOF_SECRET described as REQUIRED
- `docs/KEY_MANAGEMENT.md` — Emergency rotation example uses grace_period_secs ≥ 3600 (or explicit 3600)
- `docker-compose.yaml` — Correct healthcheck path, add verifier ADMIN_API_KEY, add validate-env.sh entrypoint
- `.env.example` — Add verifier ADMIN_API_KEY, document startup validation requirements
- `README.md` — Update features list with ~15 new features (1-line summaries), fix "rayon" → "tokio JoinSet"
- `docs/PRODUCTION.md` — Add validate-env.sh, HTTPS-only metadata, /health endpoint, new features
- `docs/API.md` — Add `/health` endpoint documentation, add rate limiting section
- `docs/TROUBLESHOOTING.md` — Add startup failure troubleshooting section
- `docs/ADMIN_API.md` — Document tree ban depth cap (100) and public rate limiting
- `CONTRIBUTING.md` — Fix "x86_64" → "multi-arch"
- `docs/FEDERATION.md` — Add HTTPS-only metadata refresh note

### Definition of Done
- [ ] All 12 specific issues resolved
- [ ] `grep -ri 'optional' docs/CONFIGURATION.md` only appears for truly optional settings
- [ ] `grep -ri 'recommended' docs/WEBAUTHN.md` no longer labels WEBAUTHN_PROOF_SECRET as recommended
- [ ] `grep 'grace_period_secs.*0\|grace_period_secs.*: 0' docs/KEY_MANAGEMENT.md` returns nothing
- [ ] `grep -ri 'rayon' docs/ README.md CONTRIBUTING.md` returns nothing
- [ ] `grep 'x86_64' CONTRIBUTING.md` returns nothing
- [ ] `docker compose -f docker-compose.yaml config` exits 0
- [ ] All new feature descriptions trace back to source code

### Must Have
- Every factual claim in docs matches actual code behavior
- ADMIN_API_KEY and WEBAUTHN_PROOF_SECRET documented as REQUIRED
- MIN_GRACE_PERIOD_SECS minimum documented correctly
- Health endpoint paths documented accurately
- Rate limiting parameters documented accurately

### Must NOT Have (Guardrails)
- NO code changes (this is documentation-only)
- NO doc restructuring (in-place edits only)
- NO new features documented beyond what already exists in code
- NO deep-dive feature explanations in README (1-line summaries + links only)
- NO duplicating rate limiting docs across multiple files (single source of truth + cross-references)
- NO changing .env.example default values arbitrarily (document what code requires)
- NO adding version-specific claims like "Required since vX.Y.Z" (version not known)

---

## Verification Strategy (MANDATORY)

> **ZERO HUMAN INTERVENTION** - ALL verification is agent-executed. No exceptions.

### Test Decision
- **Infrastructure exists**: NA (documentation-only task)
- **Automated tests**: None needed
- **Framework**: NA

### QA Policy
Every task MUST include agent-executed QA scenarios.
Evidence saved to `.sisyphus/evidence/task-{N}-{scenario-slug}.{ext}`.

- **Documentation accuracy**: Use `grep` and `read` to verify exact content
- **YAML validation**: Use `docker compose config` for docker-compose.yaml
- **Cross-reference integrity**: Use `grep -r` across all docs for stale references

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 0 (Pre-flight — grep audit):
└── Task 0: Cross-reference grep audit to find ALL stale references [quick]

Wave 1 (Critical fixes — wrong info → correct info):
├── Task 1: CONFIGURATION.md — ADMIN_API_KEY optional → REQUIRED [quick]
├── Task 2: WEBAUTHN.md — WEBAUTHN_PROOF_SECRET recommended → REQUIRED [quick]
├── Task 3: KEY_MANAGEMENT.md — grace_period_secs: 0 → ≥3600 [quick]
├── Task 4: docker-compose.yaml — healthcheck, env vars, entrypoint [quick]
├── Task 5: .env.example — verifier ADMIN_API_KEY, salt documentation [quick]

Wave 2 (Moderate fixes — missing features):
├── Task 6: API.md — /health endpoint + rate limiting section [unspecified-low]
├── Task 7: ADMIN_API.md — tree ban depth cap + public rate limiting [unspecified-low]
├── Task 8: TROUBLESHOOTING.md — startup failure section [unspecified-low]
├── Task 9: PRODUCTION.md — new features + operational concerns [unspecified-low]
├── Task 10: README.md — feature list updates + rayon→JoinSet [unspecified-low]

Wave 3 (Low fixes — stale references):
├── Task 11: CONTRIBUTING.md — x86_64 → multi-arch [quick]
└── Task 12: FEDERATION.md — HTTPS-only metadata refresh note [quick]

Wave FINAL (Verification):
├── Task F1: Plan compliance audit [oracle]
├── Task F2: Cross-reference integrity check [unspecified-low]
├── Task F3: Stale keyword grep [unspecified-low]
└── Task F4: docker-compose validation [quick]

Critical Path: T0 → T1-T5 → T6-T10 → T11-T12 → F1-F4
Max Concurrent: 5 (Wave 1)
```

### Dependency Matrix

| Task | Depends On | Blocks |
|------|-----------|--------|
| 0 | - | 1-12 |
| 1 | 0 | F1-F4 |
| 2 | 0 | F1-F4 |
| 3 | 0 | F1-F4 |
| 4 | 0 | F1-F4 |
| 5 | 0 | F1-F4 |
| 6 | 0 | F1-F4 |
| 7 | 0 | F1-F4 |
| 8 | 0 | F1-F4 |
| 9 | 0 | F1-F4 |
| 10 | 0 | F1-F4 |
| 11 | 0 | F1-F4 |
| 12 | 0 | F1-F4 |
| F1 | 1-12 | - |
| F2 | 1-12 | - |
| F3 | 1-12 | - |
| F4 | 4 | - |

### Agent Dispatch Summary

- **Wave 0**: 1 — T0 → `quick`
- **Wave 1**: 5 — T1-T5 → `quick`
- **Wave 2**: 5 — T6 → `unspecified-low`, T7 → `unspecified-low`, T8 → `unspecified-low`, T9 → `unspecified-low`, T10 → `unspecified-low`
- **Wave 3**: 2 — T11-T12 → `quick`
- **Final**: 4 — F1 → `oracle`, F2 → `unspecified-low`, F3 → `unspecified-low`, F4 → `quick`

---

## TODOs

- [x] 0. Cross-Reference Grep Audit (Pre-flight)

  **What to do**:
  - Run comprehensive grep across all documentation files for stale references that the audit may have missed
  - Search for: `rayon`, `x86_64`, `optional.*admin`, `recommended.*proof`, `grace_period_secs.*: 0`, `/.well-known/issuer` (in healthcheck context), change-in-production (salt defaults)
  - Search for cross-references between docs that will break when sections change (e.g., CONFIGURATION.md → KEY_MANAGEMENT.md references)
  - Document all findings in a report with file:line references
  - This report informs all subsequent tasks — if additional stale references are found, they must be added to the relevant task

  **Must NOT do**:
  - Do not edit any files — this is a read-only audit
  - Do not restructure docs
  - Do not add new sections

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO (all other tasks depend on its findings)
  - **Parallel Group**: Wave 0 (sequential)
  - **Blocks**: Tasks 1-12
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `docs/` — All documentation files in this directory
  - `README.md` — Root readme
  - `CONTRIBUTING.md` — Contribution guide
  - `.env.example` — Example environment file
  - `docker-compose.yaml` — Docker compose config

  **WHY Each Reference Matters**:
  - The entire docs/ directory plus root markdown files need to be scanned for stale references that the focused audit may have missed

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Stale reference audit complete
    Tool: Bash (grep)
    Preconditions: Repository is clean
    Steps:
      1. Run: grep -ri 'rayon' README.md docs/ CONTRIBUTING.md
      2. Run: grep -ri 'x86_64' CONTRIBUTING.md
      3. Run: grep 'grace_period_secs.*: 0' docs/KEY_MANAGEMENT.md
      4. Run: grep -ri 'optional.*admin.*key' docs/
      5. Run: grep -ri 'recommended.*proof.*secret' docs/WEBAUTHN.md
      6. Run: grep -ri 'change-in-production' .env.example
    Expected Result: All commands execute and results are captured for use by subsequent tasks
    Failure Indicators: Any command fails to execute
    Evidence: .sisyphus/evidence/task-0-stale-reference-audit.txt
  ```

  **Commit**: NO (informational only)

- [x] 1. Fix CONFIGURATION.md — ADMIN_API_KEY optional → REQUIRED

  **What to do**:
  - Change the ADMIN_API_KEY entry from describing it as optional/enabling to REQUIRED (minimum 32 characters)
  - Update the description to reflect that both issuer and verifier require this key
  - Update the default column from "unset" to "REQUIRED" or similar
  - Add a note that the application will fail to start without it
  - Ensure any cross-references to CONFIGURATION.md from other docs remain valid

  **Must NOT do**:
  - Do not add version-specific claims like "Required since vX.Y.Z"
  - Do not restructure the document
  - Do not change any code files

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []
  - **Reason**: Single-file documentation edit with clear instructions

  **Parallelization**:
  - **Can Run In Parallel**: YES (with T2-T5)
  - **Parallel Group**: Wave 1
  - **Blocks**: F1-F4
  - **Blocked By**: T0

  **References**:

  **Pattern References**:
  - `docs/CONFIGURATION.md:29,38` — Current ADMIN_API_KEY entries showing "unset" default and "enables" language

  **API/Type References**:
  - `issuer/src/startup.rs:189-196` — Admin key validation: `bail!("ADMIN_API_KEY must be set (minimum 32 characters)")` if missing or short
  - `verifier/src/main.rs:316-323` — Same validation for verifier: `bail!("ADMIN_API_KEY must be set (minimum 32 characters)")`

  **WHY Each Reference Matters**:
  - The CONFIGURATION.md entries at lines 29 and 38 need to be updated to match what the code actually enforces — that ADMIN_API_KEY is REQUIRED and must be ≥32 chars

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: ADMIN_API_KEY documented as required
    Tool: Bash (grep)
    Preconditions: T0 audit complete, T1 edit applied
    Steps:
      1. grep -i 'ADMIN_API_KEY' docs/CONFIGURATION.md
      2. Verify the section says REQUIRED (not optional, not "enables when set")
      3. Verify minimum 32 characters is documented
      4. Verify both issuer and verifier are mentioned
    Expected Result: ADMIN_API_KEY is described as REQUIRED for both issuer and verifier, minimum 32 characters
    Failure Indicators: Description still says "optional", "enables", or "unset"; minimum length not mentioned
    Evidence: .sisyphus/evidence/task-1-config-admin-key.txt

  Scenario: No stale "optional" language for admin key
    Tool: Bash (grep)
    Preconditions: T1 edit applied
    Steps:
      1. grep -i 'optional.*admin.*key\|admin.*key.*optional\|unset.*admin\|admin.*unset' docs/CONFIGURATION.md
    Expected Result: Returns 0 matches (no "optional" or "unset" associated with ADMIN_API_KEY)
    Failure Indicators: Any match found
    Evidence: .sisyphus/evidence/task-1-stale-check.txt
  ```

  **Commit**: YES (grouped with T2-T5)
  - Message: `docs: fix critical inaccuracies in configuration and deployment docs`
  - Files: `docs/CONFIGURATION.md`, `docs/WEBAUTHN.md`, `docs/KEY_MANAGEMENT.md`, `docker-compose.yaml`, `.env.example`
  - Pre-commit: None (docs only)

- [x] 2. Fix WEBAUTHN.md — WEBAUTHN_PROOF_SECRET recommended → REQUIRED

  **What to do**:
  - Change WEBAUTHN_PROOF_SECRET from "RECOMMENDED for production" to "REQUIRED when WebAuthn is enabled"
  - Update the comment in the code example from `# Security: Proof Secret (RECOMMENDED for production)` to `# Security: Proof Secret (REQUIRED when WebAuthn is enabled)`
  - Add a note that the application will fail to start if this variable is not set when WebAuthn is enabled
  - Document that it's used for HMAC key derivation with BLAKE3

  **Must NOT do**:
  - Do not add version-specific claims
  - Do not restructure the document
  - Do not change any code files

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with T1, T3-T5)
  - **Parallel Group**: Wave 1
  - **Blocks**: F1-F4
  - **Blocked By**: T0

  **References**:

  **Pattern References**:
  - `docs/WEBAUTHN.md:92-93` — Current RECOMMENDED labeling: `# Security: Proof Secret (RECOMMENDED for production)`

  **API/Type References**:
  - `issuer/src/startup.rs:268-271` — Startup enforcement: `bail!("WEBAUTHN_PROOF_SECRET must be set when WebAuthn is enabled")` if unset
  - `issuer/src/webauthn/handlers.rs:30-45` — Proof key derivation using BLAKE3 with domain separation

  **WHY Each Reference Matters**:
  - The WEBAUTHN.md docs say RECOMMENDED but the code says REQUIRED (startup bails). Must document actual behavior.

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: WEBAUTHN_PROOF_SECRET documented as required
    Tool: Bash (grep)
    Preconditions: T2 edit applied
    Steps:
      1. grep -i 'WEBAUTHN_PROOF_SECRET' docs/WEBAUTHN.md
      2. Verify it says REQUIRED (not RECOMMENDED)
      3. Verify it mentions "when WebAuthn is enabled" as the condition
    Expected Result: WEBAUTHN_PROOF_SECRET described as REQUIRED when WebAuthn is enabled
    Failure Indicators: Still says RECOMMENDED; doesn't mention the conditional requirement
    Evidence: .sisyphus/evidence/task-2-webauthn-required.txt

  Scenario: No stale RECOMMENDED language for proof secret
    Tool: Bash (grep)
    Preconditions: T2 edit applied
    Steps:
      1. grep -i 'recommended.*proof.*secret\|proof.*secret.*recommended' docs/WEBAUTHN.md
    Expected Result: Returns 0 matches
    Failure Indicators: Any match found
    Evidence: .sisyphus/evidence/task-2-stale-check.txt
  ```

  **Commit**: YES (grouped with T1, T3-T5)
  - Message: `docs: fix critical inaccuracies in configuration and deployment docs`
  - Files: `docs/WEBAUTHN.md`
  - Pre-commit: None (docs only)

- [x] 3. Fix KEY_MANAGEMENT.md — grace_period_secs: 0 → minimum 3600

  **What to do**:
  - Change the emergency rotation example from `grace_period_secs: 0` to `grace_period_secs: 3600` (or a clearly documented minimum)
  - Add a NOTE or WARNING that the minimum grace period is 3600 seconds (1 hour) in production and grace periods below this will be rejected
  - Document that the test environment uses a minimum of 1 second
  - Add the exact error message: `"grace period must be at least 3600 seconds (got N)"`

  **Must NOT do**:
  - Do not document test-only behavior as the default without clarification
  - Do not restructure the document
  - Do not change any code files

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with T1-T2, T4-T5)
  - **Parallel Group**: Wave 1
  - **Blocks**: F1-F4
  - **Blocked By**: T0

  **References**:

  **Pattern References**:
  - `docs/KEY_MANAGEMENT.md:383-390` — Current emergency rotation example with `grace_period_secs: 0`

  **API/Type References**:
  - `issuer/src/multi_key_voprf.rs:168-173` — `MIN_GRACE_PERIOD_SECS: u64 = 3600` (prod) / `1` (test)
  - `issuer/src/multi_key_voprf.rs:304-321` — Validation logic that rejects below minimum

  **WHY Each Reference Matters**:
  - The example with grace_period_secs: 0 will cause a runtime error. Must show the actual minimum (3600) and include the validation error.

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: grace_period_secs example uses valid minimum
    Tool: Bash (grep)
    Preconditions: T3 edit applied
    Steps:
      1. grep 'grace_period_secs' docs/KEY_MANAGEMENT.md
      2. Verify example uses 3600 or higher (not 0)
      3. Verify minimum is documented as 3600 seconds (1 hour) in production
    Expected Result: All grace_period_secs values are ≥ 3600; minimum documented
    Failure Indicators: Any example still shows 0; minimum not documented
    Evidence: .sisyphus/evidence/task-3-grace-period.txt

  Scenario: No stale grace_period_secs: 0
    Tool: Bash (grep)
    Preconditions: T3 edit applied
    Steps:
      1. grep 'grace_period_secs.*: 0\|grace_period_secs.*:0' docs/KEY_MANAGEMENT.md
    Expected Result: Returns 0 matches
    Failure Indicators: Any match found
    Evidence: .sisyphus/evidence/task-3-stale-check.txt
  ```

  **Commit**: YES (grouped with T1-T2, T4-T5)
  - Message: `docs: fix critical inaccuracies in configuration and deployment docs`
  - Files: `docs/KEY_MANAGEMENT.md`
  - Pre-commit: None (docs only)

- [x] 4. Fix docker-compose.yaml — healthcheck, env vars, entrypoint

  **What to do**:
  - Change issuer healthcheck from `/.well-known/issuer` to `/admin/health` (requires admin API key — OR document that this is the issuer healthcheck pattern)
  - Actually, issuer has: public no auth health → research shows issuer has `/admin/health` (requires auth). Change issuer healthcheck to use a simpler endpoint or document the auth requirement
  - Add `ADMIN_API_KEY` environment variable to the verifier service section
  - Document the `ADMIN_API_KEY` as required in the compose comments or env vars
  - For the verifier service: update healthcheck to `curl -f http://localhost:8082/health` (which is correct already)
  - For the issuer: the healthcheck should use `/admin/health` but that requires API key; consider adding `validate-env.sh` entrypoint for the issuer as well
  - Add `VALIDATE_ENV=true` or note about the validate-env.sh entrypoint for verifier
  - Verify `VERIFIER_SK_PATH` points to correct location

  **Must NOT do**:
  - Do not add new services or change Docker architecture
  - Do not change base images
  - Do not make the healthcheck fragile (auth-protected endpoints shouldn't be in healthchecks without credentials)

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with T1-T3, T5)
  - **Parallel Group**: Wave 1
  - **Blocks**: F1-F4
  - **Blocked By**: T0

  **References**:

  **Pattern References**:
  - `docker-compose.yaml:56-61` — Current issuer healthcheck using `/.well-known/issuer`
  - `docker-compose.yaml:111-122` — Verifier env vars (missing ADMIN_API_KEY)

  **API/Type References**:
  - `verifier/src/main.rs:886-891` — Public `/health` endpoint (no auth required)
  - `issuer/src/routes/admin.rs:976-990` — Issuer `/admin/health` (requires API key)
  - `scripts/validate-env.sh` — Environment validation script

  **WHY Each Reference Matters**:
  - The issuer healthcheck uses a wrong path. The verifier is missing its required ADMIN_API_KEY. The validate-env.sh script was added but not referenced in the issuer compose.

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: docker-compose.yaml validates successfully
    Tool: Bash
    Preconditions: T4 edit applied
    Steps:
      1. Run: docker compose -f docker-compose.yaml config > /dev/null
      2. Check exit code is 0
    Expected Result: Exit code 0, no validation errors
    Failure Indicators: Exit code non-zero, validation errors printed
    Evidence: .sisyphus/evidence/task-4-compose-valid.txt

  Scenario: ADMIN_API_KEY present in verifier config
    Tool: Bash (grep)
    Preconditions: T4 edit applied
    Steps:
      1. grep 'ADMIN_API_KEY' docker-compose.yaml | grep -A2 verifier
    Expected Result: ADMIN_API_KEY appears in the verifier service section
    Failure Indicators: ADMIN_API_KEY not found in verifier section
    Evidence: .sisyphus/evidence/task-4-verifier-admin-key.txt

  Scenario: Healthcheck paths are correct
    Tool: Bash (grep)
    Preconditions: T4 edit applied
    Steps:
      1. grep 'healthcheck' docker-compose.yaml -A3
      2. Verify issuer healthcheck path is valid
      3. Verify verifier healthcheck path is /health
    Expected Result: Healthcheck paths match actual endpoint implementations
    Failure Indicators: Paths don't match code endpoints
    Evidence: .sisyphus/evidence/task-4-healthcheck-paths.txt
  ```

  **Commit**: YES (grouped with T1-T3, T5)
  - Message: `docs: fix critical inaccuracies in configuration and deployment docs`
  - Files: `docker-compose.yaml`
  - Pre-commit: `docker compose -f docker-compose.yaml config > /dev/null`

- [x] 5. Fix .env.example — verifier ADMIN_API_KEY + salt documentation

  **What to do**:
  - Add `ADMIN_API_KEY` to the VERIFIER CONFIGURATION section (currently only in ISSUER CONFIGURATION)
  - Mark it as REQUIRED (minimum 32 characters)
  - Review any salt values using `change-in-production` — if the code now requires random salts at startup, document that salts are auto-generated and should not use insecure defaults
  - Ensure VERIFIER_SK_PATH is documented correctly (currently `/issuer-data/keys/issuer_sk.bin` — verify this is intentional or if it should be a verifier-specific path)

  **Must NOT do**:
  - Do not change actual default values — document what the code requires
  - Do not remove existing configuration entries
  - Do not restructure the file sections
  - Do not add version-specific claims

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with T1-T4)
  - **Parallel Group**: Wave 1
  - **Blocks**: F1-F4
  - **Blocked By**: T0

  **References**:

  **Pattern References**:
  - `.env.example:40-43` — Current ADMIN_API_KEY in ISSUER section
  - `.env.example:162-193` — VERIFIER section (missing ADMIN_API_KEY)

  **API/Type References**:
  - `issuer/src/startup.rs:189-196` — Admin key must be ≥32 chars, bails if missing
  - `verifier/src/main.rs:316-323` — Same for verifier
  - `issuer/src/config.rs` — Salt generation behavior (random if not provided)

  **WHY Each Reference Matters**:
  - The verifier section is missing ADMIN_API_KEY which is now required. Salt handling may have changed to reject insecure defaults.

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Verifier ADMIN_API_KEY documented
    Tool: Bash (grep)
    Preconditions: T5 edit applied
    Steps:
      1. grep -A2 'ADMIN_API_KEY' .env.example | grep -i verifier -A3
      2. Or: check that ADMIN_API_KEY appears in the verifier section
    Expected Result: ADMIN_API_KEY appears in both issuer and verifier sections with REQUIRED note
    Failure Indicators: ADMIN_API_KEY only in issuer section
    Evidence: .sisyphus/evidence/task-5-env-admin-key.txt

  Scenario: No insecure default salts
    Tool: Bash (grep)
    Preconditions: T5 edit applied
    Steps:
      1. grep -i 'change-in-production\|change.me\|insecure' .env.example
    Expected Result: Either 0 matches, or matches are clearly marked as auto-generated (not user-settable insecure defaults)
    Failure Indicators: Insecure default values that code would reject
    Evidence: .sisyphus/evidence/task-5-salt-check.txt
  ```

  **Commit**: YES (grouped with T1-T4)
  - Message: `docs: fix critical inaccuracies in configuration and deployment docs`
  - Files: `.env.example`
  - Pre-commit: None (env example only)

- [x] 6. Add /health endpoint and rate limiting to API.md

  **What to do**:
  - Add `/health` (public, verifier) endpoint documentation to API.md
    - Method: GET
    - Auth: None required
    - Response: `{"status": "ok", "version": "<cargo_pkg_version>"}`
    - Status code: 200
  - Add `/admin/health` (requires API key) endpoints for both issuer and verifier
    - Issuer response: `{"service": "issuer", "status": "ok", "uptime_seconds": 0, "invitation_system_status": "operational"}`
    - Verifier response: `{"service": "verifier", "status": "ok", "uptime_seconds": <elapsed>, "store_backend": "<backend>", "issuers_loaded": <count>}`
  - Add a "Rate Limiting" section documenting public rate limiting
    - Public endpoints: 30 requests/second per IP
    - Returns HTTP 429 with `Retry-After: 1` header
    - Reference ADMIN_API.md for admin rate limiting details

  **Must NOT do**:
  - Do not add rate limiting details here that belong in ADMIN_API.md (only reference)
  - Do not restructure the document
  - Do not add example responses beyond what the code actually returns

  **Recommended Agent Profile**:
  - **Category**: `writing`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with T7-T10)
  - **Parallel Group**: Wave 2
  - **Blocks**: F1-F4
  - **Blocked By**: T0

  **References**:

  **Pattern References**:
  - `docs/API.md:684-696` — Current endpoint list (has `/admin/health` but no public `/health`)

  **API/Type References**:
  - `verifier/src/main.rs:375,886-891` — Public `/health` endpoint definition and handler
  - `issuer/src/routes/admin.rs:976-990` — Issuer admin health handler
  - `verifier/src/routes/admin.rs:488-506` — Verifier admin health handler
  - `common/src/rate_limit.rs` — PublicRateLimitLayer: 30 req/sec per IP, returns 429

  **WHY Each Reference Matters**:
  - The `/health` endpoint exists in code but not in API.md. Rate limiting affects all public endpoints and must be documented.

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: /health endpoint documented
    Tool: Bash (grep)
    Preconditions: T6 edit applied
    Steps:
      1. grep -c '/health' docs/API.md
    Expected Result: Count ≥ 3 (public /health, issuer /admin/health, verifier /admin/health)
    Failure Indicators: Count < 3
    Evidence: .sisyphus/evidence/task-6-health-endpoint.txt

  Scenario: Rate limiting section exists
    Tool: Bash (grep)
    Preconditions: T6 edit applied
    Steps:
      1. grep -c 'rate.limit\|Rate.Limit\|429\|Too Many Requests' docs/API.md
    Expected Result: Count ≥ 1
    Failure Indicators: No rate limiting content found
    Evidence: .sisyphus/evidence/task-6-rate-limiting.txt
  ```

  **Commit**: YES (grouped with T7-T10)
  - Message: `docs: add missing feature documentation`
  - Files: `docs/API.md`
  - Pre-commit: None

- [x] 7. Add tree ban depth cap and public rate limiting to ADMIN_API.md

  **What to do**:
  - Add documentation for the tree ban depth cap (MAX_BAN_DEPTH = 100) to the ban user endpoint
    - `ban_tree: true` recursively bans users to a maximum depth of 100
    - If the invitation tree exceeds depth 100, remaining descendants are not banned
  - Add a "Public Endpoint Rate Limiting" section (cross-reference from API.md)
    - Document the admin rate limiting parameters: max 5 failed attempts per 5-minute window, 15-minute block duration
    - LRU cache capacity: 10,000 IP addresses
    - Reference API.md for public rate limiting (30 req/sec per IP)

  **Must NOT do**:
  - Do not duplicate public rate limiting details (just reference API.md)
  - Do not add internal implementation details beyond what operators need
  - Do not restructure the document

  **Recommended Agent Profile**:
  - **Category**: `writing`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with T6, T8-T10)
  - **Parallel Group**: Wave 2
  - **Blocks**: F1-F4
  - **Blocked By**: T0

  **References**:

  **Pattern References**:
  - `docs/ADMIN_API.md:299-343` — Current ban user endpoint documentation (missing depth cap)

  **API/Type References**:
  - `issuer/src/sybil_resistance/invitation.rs` — MAX_BAN_DEPTH = 100, BFS cycle detection
  - `verifier/src/routes/admin_rate_limit.rs:29-37,78-98` — AdminRateLimiter config: 5 failures / 5 min window / 15 min block / 10k LRU cache

  **WHY Each Reference Matters**:
  - The ban_tree feature has a depth cap that operators need to know about. Admin rate limiting affects API usability.

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Tree ban depth cap documented
    Tool: Bash (grep)
    Preconditions: T7 edit applied
    Steps:
      1. grep -c 'depth\|MAX_BAN_DEPTH\|100' docs/ADMIN_API.md
    Expected Result: Count ≥ 1 (depth cap of 100 is mentioned)
    Failure Indicators: No mention of depth cap
    Evidence: .sisyphus/evidence/task-7-tree-ban-depth.txt

  Scenario: Admin rate limiting documented
    Tool: Bash (grep)
    Preconditions: T7 edit applied
    Steps:
      1. grep -c 'rate.limit\|rate.limit' docs/ADMIN_API.md
    Expected Result: Count ≥ 1
    Failure Indicators: No rate limiting section
    Evidence: .sisyphus/evidence/task-7-admin-rate-limit.txt
  ```

  **Commit**: YES (grouped with T6, T8-T10)
  - Message: `docs: add missing feature documentation`
  - Files: `docs/ADMIN_API.md`
  - Pre-commit: None

- [x] 8. Add startup failure troubleshooting to TROUBLESHOOTING.md

  **What to do**:
  - Add a "Startup Failures" section covering:
    - `ADMIN_API_KEY must be set (minimum 32 characters)` — both issuer and verifier
    - `ADMIN_API_KEY must be at least 32 characters, got N` — key too short
    - `WEBAUTHN_PROOF_SECRET must be set when WebAuthn is enabled` — missing proof secret
    - `grace period must be at least 3600 seconds (got N)` — rotation with too-short grace period
    - `issuer metadata URL must use HTTPS` — verifier configured with HTTP issuer URL
    - Salt validation errors (if applicable)
  - For each error, include: exact error message, cause, and resolution
  - Reference CONFIGURATION.md for full configuration details

  **Must NOT do**:
  - Do not add generic advice — only exact errors from startup.rs and main.rs
  - Do not add troubleshooting for code bugs — only configuration/deployment errors
  - Do not restructure existing sections

  **Recommended Agent Profile**:
  - **Category**: `writing`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with T6-T7, T9-T10)
  - **Parallel Group**: Wave 2
  - **Blocks**: F1-F4
  - **Blocked By**: T0

  **References**:

  **API/Type References**:
  - `issuer/src/startup.rs:189-196` — `"ADMIN_API_KEY must be set (minimum 32 characters)"` and `"ADMIN_API_KEY must be at least 32 characters, got {len}"`
  - `issuer/src/startup.rs:268-271` — `"WEBAUTHN_PROOF_SECRET must be set when WebAuthn is enabled"`
  - `issuer/src/multi_key_voprf.rs:304-321` — `"grace period must be at least {MIN} seconds (got {v})"`
  - `verifier/src/main.rs:316-323` — Same ADMIN_API_KEY errors for verifier
  - `verifier/src/main.rs:461-466` — `"issuer metadata URL must use HTTPS: {url}"`

  **Pattern References**:
  - `docs/TROUBLESHOOTING.md:38-58` — Existing troubleshooting sections (for key loading failures)

  **WHY Each Reference Matters**:
  - Startup errors are the most common deployment problem. Each error message must match the exact string from the code.

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Startup failure section exists with exact error messages
    Tool: Bash (grep)
    Preconditions: T8 edit applied
    Steps:
      1. grep -c 'must be set\|must be at least\|must use HTTPS' docs/TROUBLESHOOTING.md
    Expected Result: Count ≥ 3 (at least 3 different startup error messages documented)
    Failure Indicators: Fewer than 3 error messages found
    Evidence: .sisyphus/evidence/task-8-startup-errors.txt

  Scenario: All error messages match code exactly
    Tool: Bash (grep)
    Preconditions: T8 edit applied
    Steps:
      1. grep 'must be set (minimum 32 characters)' docs/TROUBLESHOOTING.md
      2. grep 'must be at least 32 characters' docs/TROUBLESHOOTING.md
      3. grep 'must be set when WebAuthn is enabled' docs/TROUBLESHOOTING.md
      4. grep 'must be at least 3600 seconds' docs/TROUBLESHOOTING.md
      5. grep 'must use HTTPS' docs/TROUBLESHOOTING.md
    Expected Result: Each grep returns ≥ 1 match
    Failure Indicators: Any error message not found in TROUBLESHOOTING.md
    Evidence: .sisyphus/evidence/task-8-exact-errors.txt
  ```

  **Commit**: YES (grouped with T6-T7, T9-T10)
  - Message: `docs: add missing feature documentation`
  - Files: `docs/TROUBLESHOOTING.md`
  - Pre-commit: None

- [x] 9. Add new features and operational concerns to PRODUCTION.md

  **What to do**:
  - Add a "validate-env.sh" subsection explaining the startup validation script and what it checks
    - Checks: ADMIN_API_KEY ≥ 32 chars, not insecure default; REQUIRE_TLS=true; REDIS_URL set
    - Explain that the script runs before the main binary and exits with error code 1 if checks fail
  - Add HTTPS-only metadata refresh note to the deployment/operations section
    - Verifier refuses to fetch issuer metadata over HTTP
    - ISSUER_URL must use HTTPS scheme
  - Add `/health` endpoint documentation for monitoring
    - Verifier: `GET /health` (no auth, returns `{"status": "ok", "version": "..."}`)
    - Both: `GET /admin/health` (requires API key)
  - Add a brief note about new security features:
    - TLS enforcement middleware (REQUIRE_TLS env var)
    - CORS configuration
    - Public rate limiting (30 req/sec per IP)
    - Atomic state writes (temp-file-then-rename pattern)
    - Prometheus metrics middleware (`/admin/metrics`)
  - Keep all additions brief (1-2 sentences each) with links to detailed docs

  **Must NOT do**:
  - Do not write deep-dive explanations (link to detailed docs instead)
  - Do not restructure the document
  - Do not add features that don't exist in the code

  **Recommended Agent Profile**:
  - **Category**: `writing`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with T6-T8, T10)
  - **Parallel Group**: Wave 2
  - **Blocks**: F1-F4
  - **Blocked By**: T0

  **References**:

  **API/Type References**:
  - `scripts/validate-env.sh` — Env validation script (checks ADMIN_API_KEY, REQUIRE_TLS, REDIS_URL)
  - `verifier/src/main.rs:461-466` — HTTPS-only metadata refresh enforcement
  - `verifier/src/main.rs:886-891` — Public `/health` handler
  - `common/src/tls_enforcement.rs:68-88` — TLS enforcement returning 400 on HTTP
  - `common/src/rate_limit.rs` — PublicRateLimitLayer: 30 req/sec per IP
  - `issuer/src/sybil_resistance/progressive_trust.rs:290-319` — Atomic write pattern
  - `common/src/metrics.rs` — Prometheus metrics middleware

  **Pattern References**:
  - `docs/PRODUCTION.md` — Existing production documentation structure

  **WHY Each Reference Matters**:
  - Production operators need to know about validate-env.sh (it blocks startup if checks fail), HTTPS enforcement (affects issuer URL config), and the health endpoint (for monitoring).

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: validate-env.sh documented
    Tool: Bash (grep)
    Preconditions: T9 edit applied
    Steps:
      1. grep -c 'validate.env\|validate-env' docs/PRODUCTION.md
    Expected Result: Count ≥ 1
    Failure Indicators: No mention of validate-env.sh
    Evidence: .sisyphus/evidence/task-9-validate-env.txt

  Scenario: HTTPS-only metadata refresh documented
    Tool: Bash (grep)
    Preconditions: T9 edit applied
    Steps:
      1. grep -c 'HTTPS\|must use HTTPS' docs/PRODUCTION.md
    Expected Result: Count ≥ 1
    Failure Indicators: No mention of HTTPS requirement for metadata
    Evidence: .sisyphus/evidence/task-9-https-metadata.txt

  Scenario: Health endpoint documented
    Tool: Bash (grep)
    Preconditions: T9 edit applied
    Steps:
      1. grep -c '/health\|health.*endpoint' docs/PRODUCTION.md
    Expected Result: Count ≥ 1
    Failure Indicators: No mention of health endpoint
    Evidence: .sisyphus/evidence/task-9-health-endpoint.txt
  ```

  **Commit**: YES (grouped with T6-T8, T10)
  - Message: `docs: add missing feature documentation`
  - Files: `docs/PRODUCTION.md`
  - Pre-commit: None

- [x] 10. Update README.md feature list and fix rayon → JoinSet

  **What to do**:
  - Fix line ~112: Replace "rayon" with "tokio JoinSet" for batch issuance description
  - Add 1-line entries for new features with deep links to detailed docs:
    - Public rate limiting (30 req/sec per IP) → link to API.md
    - LRU eviction for admin rate limiter (10k capacity) → link to ADMIN_API.md
    - TLS enforcement middleware (REQUIRE_TLS) → link to PRODUCTION.md
    - CORS middleware → link to PRODUCTION.md
    - HTTPS-only metadata refresh → link to FEDERATION.md
    - Atomic state writes (temp-file-rename pattern) → link to PRODUCTION.md
    - Concurrent batch issuance via JoinSet (>=10 items) → link to ADMIN_API.md
    - Health endpoints (/health, /admin/health) → link to API.md
    - Prometheus metrics (/admin/metrics) → link to PRODUCTION.md
    - Environment validation (validate-env.sh) → link to PRODUCTION.md
    - Admin key HMAC derivation via HKDF → link to SECURITY.md
  - Keep all entries as 1-line summaries with links (no deep dives in README)

  **Must NOT do**:
  - Do not add deep-dive explanations (README is a landing page)
  - Do not restructure the document
  - Do not add features that don't exist in the code
  - Do not add version-specific claims

  **Recommended Agent Profile**:
  - **Category**: `writing`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with T6-T9)
  - **Parallel Group**: Wave 2
  - **Blocks**: F1-F4
  - **Blocked By**: T0

  **References**:

  **Pattern References**:
  - `README.md:107-126` — Current features list (missing ~10 features)
  - `README.md:112` — Line referencing "rayon" for batch issuance

  **API/Type References**:
  - `common/src/rate_limit.rs` — Public rate limiting
  - `verifier/src/routes/admin_rate_limit.rs:78-98` — LRU cache (10k entries)
  - `common/src/tls_enforcement.rs:68-88` — TLS enforcement
  - `common/src/metrics.rs` — Prometheus metrics
  - `verifier/src/main.rs:461-466` — HTTPS-only metadata refresh
  - `issuer/src/routes/batch_issue.rs:307-357` — JoinSet batching

  **WHY Each Reference Matters**:
  - The README is the first thing users see. The "rayon" reference is wrong (now JoinSet), and ~10 production features are undocumented.

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: No stale rayon reference
    Tool: Bash (grep)
    Preconditions: T10 edit applied
    Steps:
      1. grep -i 'rayon' README.md
    Expected Result: Returns 0 matches
    Failure Indicators: Any match containing "rayon" for batch processing
    Evidence: .sisyphus/evidence/task-10-no-rayon.txt

  Scenario: New features documented
    Tool: Bash (grep)
    Preconditions: T10 edit applied
    Steps:
      1. grep -c 'rate.limit\|Rate.Limit' README.md
      2. grep -c 'TLS\|tls.enforcement' README.md
      3. grep -c 'JoinSet\|join.set' README.md
      4. grep -c 'health.*endpoint\|/health' README.md
      5. grep -c 'validate.env\|atomic.*write' README.md
    Expected Result: Each grep returns ≥ 1 match
    Failure Indicators: Any feature not found
    Evidence: .sisyphus/evidence/task-10-new-features.txt
  ```

  **Commit**: YES (grouped with T6-T9)
  - Message: `docs: add missing feature documentation`
  - Files: `README.md`
  - Pre-commit: None

- [x] 11. Fix CONTRIBUTING.md — x86_64 → multi-arch

  **What to do**:
  - Change "x86_64 Docker image" to "multi-arch Docker image" at line ~201
  - Verify no other stale architecture references exist in the file

  **Must NOT do**:
  - Do not add new CI/build instructions
  - Do not change any architecture beyond the single-word substitution
  - Do not change any code files

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with T12)
  - **Parallel Group**: Wave 3
  - **Blocks**: F1-F4
  - **Blocked By**: T0

  **References**:

  **Pattern References**:
  - `CONTRIBUTING.md:201` — Current text: "builds an x86_64 Docker image"

  **WHY Each Reference Matters**:
  - CI now builds multi-arch images; the reference is stale

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: No stale x86_64 reference
    Tool: Bash (grep)
    Preconditions: T11 edit applied
    Steps:
      1. grep 'x86_64' CONTRIBUTING.md
    Expected Result: Returns 0 matches
    Failure Indicators: Any match found
    Evidence: .sisyphus/evidence/task-11-no-x86_64.txt

  Scenario: Multi-arch mentioned
    Tool: Bash (grep)
    Preconditions: T11 edit applied
    Steps:
      1. grep -i 'multi.arch' CONTRIBUTING.md
    Expected Result: Returns ≥ 1 match
    Failure Indicators: No match found
    Evidence: .sisyphus/evidence/task-11-multi-arch.txt
  ```

  **Commit**: YES (grouped with T12)
  - Message: `docs: fix stale references`
  - Files: `CONTRIBUTING.md`
  - Pre-commit: None

- [x] 12. Add HTTPS-only metadata refresh note to FEDERATION.md

  **What to do**:
  - Add a note or section in FEDERATION.md explaining that the verifier requires HTTPS for the issuer metadata URL
  - Document that `ISSUER_URL` must use the `https://` scheme
  - Include the exact error message: `"issuer metadata URL must use HTTPS: {url}"`
  - Add a brief note about metadata refresh failure behavior (exponential backoff, up to 5x interval)

  **Must NOT do**:
  - Do not add new conceptual sections about TLS in general
  - Do not restructure the document
  - Do not add feature descriptions beyond what the code enforces

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with T11)
  - **Parallel Group**: Wave 3
  - **Blocks**: F1-F4
  - **Blocked By**: T0

  **References**:

  **API/Type References**:
  - `verifier/src/main.rs:461-466` — HTTPS enforcement: `bail!("issuer metadata URL must use HTTPS: {}", issuer_url)`

  **Pattern References**:
  - `docs/FEDERATION.md` — Current federation documentation (no mention of HTTPS requirement)

  **WHY Each Reference Matters**:
  - Operators configuring federation will hit this error if they use HTTP URLs. The error message and behavior must be documented.

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: HTTPS enforcement for metadata documented
    Tool: Bash (grep)
    Preconditions: T12 edit applied
    Steps:
      1. grep -c 'HTTPS\|https.*required\|must use HTTPS' docs/FEDERATION.md
    Expected Result: Count ≥ 1
    Failure Indicators: No mention of HTTPS requirement
    Evidence: .sisyphus/evidence/task-12-https-enforcement.txt

  Scenario: Error message included
    Tool: Bash (grep)
    Preconditions: T12 edit applied
    Steps:
      1. grep 'must use HTTPS' docs/FEDERATION.md
    Expected Result: Returns ≥ 1 match (exact error message or clear description)
    Failure Indicators: No mention of the specific error
    Evidence: .sisyphus/evidence/task-12-error-message.txt
  ```

  **Commit**: YES (grouped with T11)
  - Message: `docs: fix stale references`
  - Files: `docs/FEDERATION.md`
  - Pre-commit: None

---

## Final Verification Wave (MANDATORY — after ALL implementation tasks)

> 4 review agents run in PARALLEL. ALL must APPROVE. Present consolidated results to user and get explicit "okay" before completing.

- [x] F1. **Plan Compliance Audit** — `oracle`
  Read this plan end-to-end. For each "Must Have": verify the fix exists (read file, grep for corrected content). For each "Must NOT Have": grep for forbidden patterns. Check evidence files exist in `.sisyphus/evidence/`. Compare deliverables against plan.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT: APPROVE/REJECT`

- [x] F2. **Cross-Reference Integrity Check** — `unspecified-low`
  Grep all .md files for references to changed sections. Verify no stale references remain: "optional" for now-required keys, "recommended" for WEBAUTHN_PROOF_SECRET, "grace_period_secs: 0", "rayon" for batch issuance, "x86_64" for Docker images. Verify all cross-references point to correct sections.
  Output: `Stale References [N found] | Broken Cross-Refs [N found] | VERDICT`

- [x] F3. **Stale Keyword Grep** — `unspecified-low`
  Run comprehensive grep: `grep -ri 'rayon' README.md docs/ CONTRIBUTING.md`, `grep -ri 'x86_64' CONTRIBUTING.md`, `grep 'grace_period_secs.*: 0' docs/KEY_MANAGEMENT.md`, `grep -i 'optional.*admin.*key' docs/`, `grep -i 'recommended.*proof.*secret' docs/WEBAUTHN.md`. All must return 0 matches for stale content.
  Output: `Keywords Checked [N] | Stale Found [N] | VERDICT`

- [x] F4. **docker-compose Validation** — `quick`
  Run `docker compose -f docker-compose.yaml config` and verify exit code 0. Verify all env vars documented in `.env.example` match compose env vars. Check healthcheck paths resolve to actual endpoints.
  Output: `Compose Valid [YES/NO] | Env Vars Match [N/N] | Healthchecks [N/N correct] | VERDICT`

---

## Commit Strategy

- **Wave 1**: `docs: fix critical inaccuracies in configuration and deployment docs` — `docs/CONFIGURATION.md`, `docs/WEBAUTHN.md`, `docs/KEY_MANAGEMENT.md`, `docker-compose.yaml`, `.env.example`
- **Wave 2**: `docs: add missing feature documentation` — `docs/API.md`, `docs/ADMIN_API.md`, `docs/TROUBLESHOOTING.md`, `docs/PRODUCTION.md`, `README.md`
- **Wave 3**: `docs: fix stale references` — `CONTRIBUTING.md`, `docs/FEDERATION.md`

---

## Success Criteria

### Verification Commands
```bash
# Critical: No wrong info remains
grep -i 'optional' docs/CONFIGURATION.md | grep -i admin   # Should return nothing (ADMIN_API_KEY no longer optional)
grep -i 'recommended' docs/WEBAUTHN.md | grep -i proof       # Should return nothing (WEBAUTHN_PROOF_SECRET no longer recommended)
grep 'grace_period_secs.*: 0' docs/KEY_MANAGEMENT.md          # Should return nothing (0 is invalid)

# Stale references eliminated
grep -ri 'rayon' README.md docs/ CONTRIBUTING.md              # Should return nothing
grep 'x86_64' CONTRIBUTING.md                                 # Should return nothing

# Structure validity
docker compose -f docker-compose.yaml config > /dev/null     # Exit code 0

# Feature coverage
grep -c 'rate.limit\|rate_limit\|Rate.Limit' docs/API.md    # ≥ 1
grep -c '/health' docs/API.md                                 # ≥ 1
grep -c 'tree.*ban.*depth\|MAX_BAN_DEPTH' docs/ADMIN_API.md  # ≥ 1
grep -c 'validate.env\|startup.*fail\|missing.*key' docs/TROUBLESHOOTING.md  # ≥ 1

# All docs edited
git diff --name-only HEAD~3 | wc -l                           # ≥ 12 (one per issue)
```

### Final Checklist
- [ ] All "Must Have" present
- [ ] All "Must NOT Have" absent
- [ ] No code files changed
- [ ] docker-compose.yaml validates
- [ ] All stale keywords eliminated