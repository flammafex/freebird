# AGENTS.md

Guidance for Codex / AI coding agents working in this repository. Read this
before making changes. The repo is a Rust workspace for privacy-preserving
token issuance/verification (Freebird). See `README.md` and `docs/` for full
context.

## Repo layout

```
issuer/          Axum issuer service + admin CLI + config validator
                 bins: freebird-issuer, freebird-cli, freebird-validate-config
verifier/        Axum verifier service (modular application, settings, state,
                  verification, discovery, metadata, replay, and route modules)
interface/       V4-only smoke-test client (freebird-interface)
attester/        Social Graph Attester service (HTTP API, scoring, JWKS)
crypto/          VOPRF, blind RSA, token wire formats, nullifier derivation,
                 provider abstraction (incl. optional PKCS#11/HSM)
common/          Shared API types, metrics, logging, rate limits, TLS enforcement
integration_tests/  Cross-crate protocol/storage regression tests (9 files in tests/)
sdk/js/          TypeScript client SDK (@freebird/sdk)
admin-ui/        Static HTML (real admin UIs are Rust-embedded under
                 issuer/src/admin_ui/ and verifier/src/admin_ui/)
webauthn-client/ Static HTML for browser passkey flow
docs/            architecture, threat-model, sybil-modes, admin-operations,
                 client-proofs, webauthn-browser-flow, production-deployment,
                 release, deployment-kubernetes, deployment-systemd, audit-logging
k8s/             Kubernetes manifests
server-configs/  Reverse-proxy examples
scripts/         validate-env.sh, validate-deployment.sh, backup-restore.sh,
                 setup-softhsm-test.sh
Dockerfile       Multi-stage (issuer + verifier targets)
docker-compose.yaml
launch.sh         Docker quickstart helper
```

Key files to know:
- `issuer/src/startup.rs` — issuer `Application::build`/`run` orchestration;
  extracted startup stages live under `issuer/src/startup/`
- `issuer/src/sybil_resistance/mod.rs` — `SybilResistance` trait + `CombinedOr/And/Threshold`
- `verifier/src/main.rs` — verifier process entry point
- `verifier/src/application.rs` — verifier application construction, metadata
  refresh, replay-authority task, and router assembly
- `verifier/src/settings.rs` — staged verifier configuration and replay-store selection
- `verifier/src/routes/public.rs` — public verification, check, and batch handlers
- `crypto/src/lib.rs` — V4/V5 token wire formats, constants, nullifier derivation
- `common/src/api.rs` — shared request/response types, `SybilProof` enum
- `.env.example` — canonical config reference

## Setup

Requires: Rust stable, Cargo. Redis optional for local source testing
(auto-skips when unreachable). Node.js only for the TS SDK.

```bash
cargo build --workspace
```

## Run (local V4 round-trip)

Three terminals, repo root:

```bash
# 1. Issuer
ADMIN_API_KEY=local-admin-key-must-be-at-least-32-chars \
BIND_ADDR=127.0.0.1:8081 ISSUER_ID=issuer:local:v4 \
ISSUER_SK_PATH=issuer_sk.bin KEY_ROTATION_STATE_PATH=key_rotation_state.json \
SYBIL_RESISTANCE=none REQUIRE_TLS=false \
cargo run -p freebird-issuer --bin freebird-issuer

# 2. Verifier (same ADMIN_API_KEY, explicit development-only memory replay)
ADMIN_API_KEY=local-admin-key-must-be-at-least-32-chars \
BIND_ADDR=127.0.0.1:8082 VERIFIER_ID=verifier:local:v4 VERIFIER_AUDIENCE=local \
ISSUER_URL=http://127.0.0.1:8081/.well-known/issuer \
VERIFIER_ACCEPTED_TOKEN_VERSIONS=v4 VERIFIER_ENV=development \
IN_MEMORY_REPLAY_STORE=true VERIFIER_SK_PATH=issuer_sk.bin \
REFRESH_INTERVAL_MIN=1 REQUIRE_TLS=false \
cargo run -p freebird-verifier --bin freebird-verifier

# 3. Interface
cargo run -p freebird-interface                 # normal issue+verify
cargo run -p freebird-interface -- --replay      # expect: 2nd use rejected
cargo run -p freebird-interface -- --double-spend
cargo run -p freebird-interface -- --stress 10
```

Docker: `./launch.sh up` (interactive pull/build) or `docker-compose up --build`.

## Test

```bash
cargo test --workspace                            # Redis tests auto-skip without REDIS_URL
cargo test -p integration_tests --test sybil_http_matrix
cargo test -p integration_tests --test admin_operator_workflows

# JS SDK
cd sdk/js && npm install && npm test
```

Redis-dependent tests (`redis_double_spend`, Sybil replay-store tests) need
`REDIS_URL=redis://127.0.0.1:6379`. The verifier local command may instead use
the explicit unsafe development pair `VERIFIER_ENV=development` and
`IN_MEMORY_REPLAY_STORE=true`; production always requires Redis.

## Lint / security

```bash
cargo fmt -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
cd sdk/js && npm run lint      # tsc --noEmit
```

CI enforces all of the above. Do not merge with clippy warnings or fmt drift.

## Build

```bash
cargo build --workspace          # dev
cargo build --release            # release (CI uses this)
# Docker images:
docker-compose build issuer verifier
```

## Coding conventions

- **Edition 2021**, workspace `resolver = "2"`, all crates versioned in
  lockstep (currently `0.9.0`). Bump all crates together for each release.
- **License header** on source files:
  `// SPDX-License-Identifier: Apache-2.0 OR MIT`
  Manifests: `license = "MIT OR Apache-2.0"`.
- **Config via `std::env::var`** directly (no config crate). Durations use
  `common::duration::parse_duration` (human-readable: `1d`, `30m`, `3600`).
- **Security hygiene is mandatory**:
  - `subtle::ConstantTimeEq` for token/authenticator comparisons
  - `hmac` for API-key verification (never `==` on secrets)
  - `zeroize` / `Zeroizing<[u8; 32]>` for key material
  - File writes for keys: tmp + `fsync` + rename, `0o600` on Unix
  - `CatchPanicLayer::custom` returns generic JSON 500 — never leak panic
    messages, stack traces, or key material to clients
- **Logging**: `tracing` with `#[instrument]`, env-driven `RUST_LOG`,
  optional JSON via `LOG_FORMAT=json`. No `println!` in library/service code.
- **Error handling**: `anyhow::Result` at service boundaries; structured
  `Error` enums in `crypto`. Return generic error strings to clients; log
  details server-side.
- **Tests**: inline `#[cfg(test)] mod tests` per module + `integration_tests`
  crate. Use `serial_test` for stateful tests. Redis tests must self-skip
  when Redis is unreachable.
- **Feature flags**: `pkcs11` (crypto), `voprf-p256` (crypto, default).
- **No `std::env::set_var` at runtime** — it is unsafe in multi-threaded
  contexts. Do not add runtime environment mutation.

## Testing expectations

- Every behavior change ships with a test. Crypto/protocol changes need
  round-trip + negative (tamper/reject) tests — see `crypto/src/lib.rs` tests
  for the pattern.
- Sybil-resistance changes need tests for each combiner (`Or`, `And`,
  `Threshold`) and the "duplicate proof only satisfies one mechanism" case
  (see `sybil_resistance/mod.rs` tests).
- Double-spend / replay protection changes belong in `integration_tests/`.
- Do not weaken existing tests to make changes pass. If a test is wrong,
  explain why in the PR.
- Run the full CI matrix locally before pushing:
  `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo audit`.

## PR / review expectations

- **Small, focused PRs.** One concern per PR. Mixed refactors + behavior
  changes are hard to review and will be rejected.
- **PR description must include:**
  - what changed and why
  - which env vars / config are affected
  - which docs need updating (and update them in the same PR)
  - security implications (does this touch key material, nullifier
    derivation, Sybil gates, admin auth, or TLS enforcement?)
- **Update docs in the same PR** when changing: HTTP API, env vars, Sybil
  modes, token wire formats, or deployment. Docs live in `docs/` and
  `README.md`.
- **Keep crate versions in lockstep.** The current release is `0.9.0`; when
  preparing a release, bump all workspace crates together and update
  `Cargo.lock`.
- **Do not introduce dependency version skew.** Currently issuer uses
  `redis = "0.24"` and verifier uses `redis = "0.25"`; `integration_tests`
  uses `tower = "0.5"` while services use `tower = "0.4"`. Do not add a
  third version; prefer aligning when you have reason to touch the manifest.
- **No secrets in commits.** `issuer_sk.bin`, `invitation_signing_key.bin`,
  `public_bearer_sk.der`, `public_bearer_metadata.json`,
  `key_rotation_state.json` are gitignored local dev artifacts — never stage
  them. If you find real-looking key material in the tree, flag it.
- **Reviewers check:** constant-time compares where required, zeroization
  of secrets, panic safety, no client-facing error detail leaks, test
  coverage for the new behavior, docs updated.

## Constraints — ask before touching

These are high-stakes or subtle. Open an issue or ask a maintainer before
changing:

- **Crypto primitives** in `crypto/src/voprf/` and `crypto/src/lib.rs` —
  VOPRF, blind RSA, token wire formats, nullifier derivation. A bug here
  breaks the core privacy or double-spend property.
- **Nullifier derivation** (`nullifier_key_v4`, `nullifier_key_v5`,
  `nullifier_key`) — changing the digest construction invalidates every
  outstanding token and every stored nullifier.
- **Token wire formats** (`build_redemption_token`, `parse_redemption_token`,
  `build_public_bearer_pass`, `parse_public_bearer_pass`) — wire
  compatibility. Bump `REDEMPTION_TOKEN_VERSION_*` for breaking changes.
- **Sybil-resistance trait semantics** (`SybilResistance`, `CombinedOr/And/
  Threshold`) — `CombinedOr` is "only as strong as the easiest mechanism"
  (`SECURITY.md:52-53`). Do not change combiner semantics without a threat
  model review.
- **`social_graph` gate semantics** involve an external attester service, and
  the `SybilProof::SocialGraph` variant is wire-format-sensitive. Do not change
  proof shape, attestation validation, or attester trust semantics without review.
- **Admin authentication** (`ADMIN_API_KEY` checks, session cookie,
  `AdminRateLimiter`) and **TLS enforcement** (`common/src/tls_enforcement.rs`).
- **Key rotation / epoch logic** (`issuer/src/multi_key_voprf.rs`,
  `issuer/src/keys.rs`).
- **Batch verify concurrency** in `verifier/src/routes/public.rs` — uses
  `runtime_handle.block_on` inside `rayon par_iter`. Known smell; do not
  refactor without confirming the deadlock/starvation story.
- **Default values** for `SYBIL_RESISTANCE`, `REQUIRE_TLS`,
  `SYBIL_REPLAY_STORE` — changing defaults can silently weaken production
  deployments.
- **`Dockerfile`, `docker-compose.yaml`, `k8s/`** — deployment-critical.
  Changes need validation via `scripts/validate-deployment.sh`.

## Definition of done

A change is done when **all** of these hold:

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo fmt -- --check` clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo test --workspace` passes (and Redis tests pass if you have
      Redis; otherwise confirm they skip, not fail)
- [ ] `cargo audit` clean (no new advisories introduced)
- [ ] Feature-gated code compiles: `cargo check -p freebird-crypto --features pkcs11`
- [ ] JS SDK touched? `cd sdk/js && npm run lint && npm test` passes
- [ ] New behavior has tests (positive + negative/tamper cases)
- [ ] No secrets, key files, or `.env` staged
- [ ] Docs updated if API, env vars, Sybil modes, token formats, or
      deployment changed
- [ ] Crate versions bumped in lockstep if any version changed
- [ ] PR description covers security impact and config changes
- [ ] No `println!`/`dbg!`/`todo!`/`unimplemented!` left in committed code
- [ ] Error responses to clients are generic; details only in server logs
