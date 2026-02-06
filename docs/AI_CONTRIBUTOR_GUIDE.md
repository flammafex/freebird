# Contributor Guide for AI Agents

This guide helps AI agents ramp up quickly in the Freebird repo. It summarizes architecture, workflows, and safe paths to change. It is intentionally concise and anchored to existing project docs and code.

## 1) Project Overview

Freebird is an anonymous authorization infrastructure built on VOPRFs. It has two primary services plus supporting components:

- **Issuer (Rust)**: issues unlinkable tokens and exposes admin endpoints/UI.
- **Verifier (Rust)**: verifies tokens and enforces replay protection.
- **Interface (Rust CLI)**: dev/test client to issue/verify tokens.
- **SDK (TypeScript)**: client integration package for browser/Node.
- **Admin UI (static HTML)**: served by issuer/verifier binaries (embedded at build time).

## 2) Repo Map (High-Level)

```
/issuer          Rust service: token issuance + admin APIs/UI
/verifier        Rust service: token verification + replay protection
/interface       Rust CLI: dev/test client for flows
/common          Shared API/data models
/crypto          Cryptographic primitives and VOPRF logic
/admin-ui        Single HTML admin dashboard embedded in binaries
/sdk/js          TypeScript SDK package
/docs            Project documentation
/integration_tests Rust tests (workspace member)
```

Rust workspace members are defined in `Cargo.toml`. The main binaries are `issuer`, `verifier`, and `interface`.

## 3) Architecture (Request Flow Example)

Token issuance and verification flow (typical user path):

```
Client (Interface/SDK)
  └─> Issuer: /v1/oprf/issue
       └─> VOPRF evaluation + optional Sybil proof check
       └─> signed metadata (exp/epoch)
  └─> Verifier: /v1/verify
       └─> issuer metadata lookup
       └─> expiration + epoch checks
       └─> signature + VOPRF verification
       └─> replay protection (Redis or in-memory)
```

## 4) Core Domains

- **Token Issuance (Issuer)**: VOPRF evaluation and signing; optional Sybil resistance checks.
- **Token Verification (Verifier)**: signature + VOPRF checks and replay protection.
- **Shared API Models (common)**: Issue/Verify request/response types and Sybil proofs.
- **Admin Operations**: Admin UI routes, key rotation, stats, audit logs.
- **Storage**: Redis (preferred) or in-memory spend store for replay protection.

## 5) Entry Points (Where to Start Reading)

- **Issuer server bootstrap**: `issuer/src/main.rs` → `issuer/src/startup.rs`.
- **Verifier server bootstrap**: `verifier/src/main.rs`.
- **Interface CLI**: `interface/src/main.rs`.
- **Shared API structs**: `common/src/api.rs`.
- **Admin UI embedding**: `admin-ui/index.html` (copied into issuer/verifier at build).

## 6) Developer Workflow

### Local build (Rust)

```bash
cargo build --release
```

Run services (separate terminals):

```bash
./target/release/issuer
./target/release/verifier
./target/release/interface
```

### Docker (recommended)

```bash
docker compose up --build
```

This starts issuer, verifier, and redis. Admin UI is served from the issuer/verifier at `/admin`.

### SDK workflow

```bash
cd sdk/js
npm install
npm run build
npm run test
npm run lint
```

## 7) Common Change Areas

- **Protocol changes**: update `common/src/api.rs`, then adjust issuer/verifier handlers.
- **Issuer behavior**: `issuer/src/routes/*` and `issuer/src/startup.rs`.
- **Verifier behavior**: `verifier/src/main.rs` and `verifier/src/store.rs`.
- **Admin UI**: edit `admin-ui/index.html` (embedded at build time).
- **SDK**: `sdk/js/src` (use `tsup` + `vitest`).

## 8) Safety / Risk Notes

- **Replay protection**: ensure Redis is configured for production; in-memory is non-durable.
- **Key rotation / epochs**: changes here impact verifier compatibility.
- **Sybil resistance**: modes are optional but can affect issuance behavior. Read config docs before changing defaults.
- **Admin API key**: must be 32+ chars to enable admin routes.

## 9) Testing & Validation

There is no single canonical test command for all crates. Use these depending on scope:

- Rust build: `cargo build --release`
- Rust tests (workspace): `cargo test`
- SDK tests: `npm run test` (in `sdk/js`)

## 10) Notes for AI Agents

- Prefer small, isolated changes with clear citations to files.
- Use `rg` for search; avoid `ls -R` or recursive grep.
- If you change `admin-ui/index.html`, remember issuer/verifier embed it via `build.rs` and `include_str!`.
- Keep PR descriptions focused on user-visible behavior, security impact, and ops considerations.

## 11) Suggested First Steps for New Agents

1. Read `README.md` and `docs/QUICKSTART.md`.
2. Inspect `issuer/src/startup.rs` and `verifier/src/main.rs`.
3. Follow the example flow in `interface/src/main.rs`.
4. Check `common/src/api.rs` for request/response shapes.

---

If you add new major components or workflows, update this guide to keep future agents aligned.
