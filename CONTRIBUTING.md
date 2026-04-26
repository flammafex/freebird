# Contributing to Freebird

This document covers what you need to know to contribute to Freebird: crate relationships, the `CryptoProvider` abstraction, how to run tests, and how the admin UI is built and embedded.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Workspace Structure and Crate Relationships](#workspace-structure-and-crate-relationships)
3. [The `CryptoProvider` Trait](#the-cryptoprovider-trait)
4. [Running Tests](#running-tests)
5. [The Admin UI](#the-admin-ui)
6. [Code Style and Guidelines](#code-style-and-guidelines)
7. [Making a Change](#making-a-change)

---

## Prerequisites

- **Rust 1.70+** — install via [rustup](https://rustup.rs/)
- **Redis** (optional) — only needed for integration tests that test the Redis spend store
- **Docker / Docker Compose** — useful for running the full stack locally

```bash
# Verify Rust toolchain
rustup show

# Build everything
cargo build

# Build in release mode
cargo build --release
```

---

## Workspace Structure and Crate Relationships

The project is a Cargo workspace. Dependency relationships flow in one direction:

```
freebird-interface
    └─ freebird-common
    └─ freebird-crypto

freebird-issuer
    └─ freebird-common
    └─ freebird-crypto

freebird-verifier
    └─ freebird-common
    └─ freebird-crypto

freebird-common
    └─ freebird-crypto

integration_tests
    └─ freebird-issuer  (library)
    └─ freebird-verifier (library)
    └─ freebird-common
    └─ freebird-crypto
```

**`freebird-crypto`** has no dependencies on other Freebird crates and no HTTP/config code. Keep it that way — it should remain a pure cryptography library.

**`freebird-common`** defines all types that cross the issuer/verifier boundary
(request/response structs, `SybilProof`, metadata types). If you add a new API
field, add it here.

**`freebird-issuer`** and **`freebird-verifier`** are independent binaries. They share types through `freebird-common` but never call each other's library code directly.

### Feature Flags

- `freebird-crypto --features pkcs11` — enables PKCS#11 HSM backend via `cryptoki`
- `freebird-crypto --features voprf-p256` — enables VOPRF operations (required by issuer and verifier)
- `freebird-issuer --features human-gate-webauthn` — enables WebAuthn Sybil resistance

---

## The `CryptoProvider` Trait

All operations that touch the VOPRF secret key go through the `CryptoProvider` trait defined in `crypto/src/provider/mod.rs`. This is the primary extension point for adding new cryptographic backends.

```rust
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    /// Evaluate the VOPRF: sk * blinded_element → evaluation bytes
    async fn voprf_evaluate(&self, blinded: &[u8]) -> Result<Vec<u8>>;

    /// Return the SEC1-compressed P-256 public key (33 bytes)
    fn public_key(&self) -> &[u8];

    fn key_id(&self) -> &str;
    fn suite_id(&self) -> &str;   // default: "OPRF(P-256, SHA-256)-verifiable"
    fn context(&self) -> &[u8];
}
```

**`SoftwareCryptoProvider`** (`provider/software.rs`): Holds the P-256 secret key in a `SecretKey` from the `p256` crate. Performs all operations in software. Suitable for development and most production deployments.

**`Pkcs11CryptoProvider`** (`provider/pkcs11.rs`): Delegates key operations to a PKCS#11 hardware security module. The secret key never leaves the HSM. Enabled by `--features pkcs11`. Tested with SoftHSM2 and YubiHSM 2.

**Adding a new backend**: Implement `CryptoProvider`, add a variant to `ProviderConfig`, and update the `create_provider` factory function in `provider/mod.rs`.

---

## Running Tests

### Unit Tests

```bash
# Run all unit tests
cargo test

# Run unit tests for a specific crate
cargo test --package freebird-crypto
cargo test --package freebird-common
cargo test --package freebird-issuer
cargo test --package freebird-verifier
```

### Integration Tests

The `integration_tests` crate runs end-to-end tests that start real issuer and verifier instances in-process:

```bash
cargo test --package integration_tests
```

Notable test files:
- `smoke_voprf_roundtrip.rs` — V4 VOPRF token construction and tamper checks
- `v4_private_verification.rs` — verifier-side private authenticator verification
- `redis_double_spend.rs` — nullifier store rejects reused tokens
- `sybil_mode_matrix.rs` — all Sybil proof types are exercised
- `regressions.rs` — known-bad inputs that previously caused panics or incorrect behavior

To run tests that require Redis:

```bash
REDIS_URL=redis://localhost:6379 cargo test --package integration_tests redis
```

### Benchmarks

```bash
# Run VOPRF benchmarks
cargo bench --package freebird-crypto --bench voprf
```

See `crypto/benches/README.md` for details.

---

## The Admin UI

The admin web interface is a single-file HTML application. There are two versions — one for the issuer and one for the verifier — because they expose different data and operations.

**Source location:** `admin-ui/` at the project root (canonical source, used for development).

**Embedded locations:**
- `issuer/src/admin_ui/index.html` — embedded by the issuer at compile time
- `verifier/src/admin_ui/index.html` — embedded by the verifier at compile time

Both are embedded using Rust's `include_str!` macro, so they become part of the binary at compile time. No file system access is needed at runtime.

**To update the admin UI:**

1. Edit the HTML source in `admin-ui/` (or directly in the `src/admin_ui/` file you want to change).
2. Copy the updated file into the relevant `src/admin_ui/index.html`:
   ```bash
   cp admin-ui/index.html issuer/src/admin_ui/index.html
   # or
   cp admin-ui/index.html verifier/src/admin_ui/index.html
   ```
3. Rebuild the affected service (`cargo build --package freebird-issuer` etc.).

The admin UI communicates with its service via the same `X-Admin-Key` header used by the REST API, or via the session cookie set by `POST /admin/login`.

---

## Code Style and Guidelines

- **No `unsafe` in cryptographic code.** All crypto operations use the `p256` and `sha2` crates from the RustCrypto ecosystem, which are `#![forbid(unsafe_code)]`.
- **Zeroize sensitive values.** Secret keys and intermediate scalars should implement `Zeroize` or be held in types that do (e.g., `zeroize::Zeroizing`).
- **Structured logging.** Use `tracing::{info, warn, error, debug}` macros. Include relevant context as fields (`tracing::info!(user_id = %uid, "action")`).
- **Error handling.** Use `anyhow::Result` in binaries and `thiserror`-derived errors in library crates.
- **Constant-time comparisons.** Use `subtle::ConstantTimeEq` or the `constant_time_key_verify` helper in admin routes for any comparison that could leak timing information about secrets.

---

## Making a Change

1. **Branch**: Create a branch from `main`.
2. **Test**: Run `cargo test` and `cargo test --package integration_tests` before submitting.
3. **Clippy**: Run `cargo clippy -- -D warnings` and address any warnings.
4. **Format**: Run `cargo fmt` to format all code.
5. **Docs**: If you change an API type in `freebird-common`, update `docs/API.md` and `docs/FEDERATION.md` as appropriate. If you change env vars, update `docs/CONFIGURATION.md` and `.env.example`.
6. **Pull request**: Open a PR against `main`. Describe what changed and why.

The GitHub Actions workflow builds an x86_64 Docker image on every push to `main`. Pre-built images are published to `ghcr.io/flammafex/freebird`.
