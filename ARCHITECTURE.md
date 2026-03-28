# Freebird Architecture

This document describes the overall system design, crate structure, and key abstractions in Freebird.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Crate Structure](#crate-structure)
3. [Protocol Flow](#protocol-flow)
4. [Key Abstractions](#key-abstractions)
5. [Token Format (V3)](#token-format-v3)
6. [Admin UI Embedding](#admin-ui-embedding)
7. [Deployment Topology](#deployment-topology)

---

## System Overview

Freebird is an anonymous token issuance and verification system built on the Verifiable Oblivious Pseudorandom Function (VOPRF) protocol over P-256. It allows users to obtain tokens that prove they passed some access check (Sybil resistance) without revealing which user they are. Verifiers can check token validity using only the issuer's public key — no shared secrets, no per-user tracking.

The system has three services:

```
┌─────────────────────────────────────────────────────────────┐
│ CLIENT (SDK / freebird-interface)                           │
│   1. blind(input) → blinded_element                        │
│   2. POST /v1/oprf/issue {blinded_element, sybil_proof}    │
│   3. finalize(evaluation) → PRF output                     │
│   4. buildRedemptionToken(output, kid, exp, issuer_id, sig) │
└────────────────────┬────────────────────────────────────────┘
                     │ token_b64
                     │ POST /v1/verify
┌────────────────────▼────────────────────────────────────────┐
│ VERIFIER (freebird-verifier)                                │
│   - Fetches issuer pubkey from /.well-known/issuer          │
│   - Verifies ECDSA sig over metadata                        │
│   - Checks expiration + nullifier (replay protection)       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ ISSUER (freebird-issuer)                                    │
│   - Verifies Sybil proof                                    │
│   - Evaluates VOPRF: evaluates blinded_element with sk      │
│   - Signs metadata: ECDSA(kid, exp, issuer_id)              │
│   - Returns evaluation + ECDSA sig + metadata               │
└─────────────────────────────────────────────────────────────┘
```

---

## Crate Structure

The workspace (`Cargo.toml`) contains six crates:

```
freebird/
├── crypto/          freebird-crypto   — cryptographic primitives
├── common/          freebird-common   — shared API types, logging, federation types
├── issuer/          freebird-issuer   — HTTP issuer service + admin API
├── verifier/        freebird-verifier — HTTP verifier service
├── interface/       freebird-interface — CLI test client
└── integration_tests/                — end-to-end test suite
```

### `freebird-crypto`

All cryptographic operations. No HTTP, no configuration. Exposes:

- `Client` — blind and finalize VOPRF operations
- `Server` — evaluate blinded elements and generate DLEQ proofs
- `Verifier` — verify DLEQ proofs (client-side verification of issuer honesty)
- `RedemptionToken` / `build_redemption_token` / `parse_redemption_token` — V3 binary token codec
- `compute_token_signature` / `verify_token_signature` — ECDSA metadata signing
- `provider::CryptoProvider` trait — abstraction over software vs. PKCS#11 HSM backends

The VOPRF implementation is in `crypto/src/voprf/` (core operations and DLEQ proof generation/verification). The provider abstraction is in `crypto/src/provider/`.

### `freebird-common`

Types shared between issuer and verifier:

- `api.rs` — all HTTP request/response structs (`IssueReq`, `IssueResp`, `VerifyReq`, `VerifyResp`, `BatchVerifyReq`, `BatchVerifyResp`, `SybilProof`, `KeyDiscoveryResp`, etc.)
- `federation.rs` — federation types (`Vouch`, `Revocation`, `FederationMetadata`, `TrustPolicy`)
- `duration.rs` — human-readable duration parsing (`1d`, `24h`, `5m`)
- `logging.rs` — structured logging initialization (supports plain and JSON output)

### `freebird-issuer`

The issuer HTTP service. Key modules:

- `config.rs` — reads all env vars, constructs `Config`
- `startup.rs` — wires together config, VOPRF core, sybil resistance, federation store, and axum router
- `multi_key_voprf.rs` — manages multiple signing keys for epoch-based key rotation; wraps `voprf_core.rs`
- `voprf_core.rs` — thin wrapper around `freebird-crypto`, uses `CryptoProvider` for signing
- `federation_store.rs` — persists vouches and revocations to JSON files
- `routes/issue.rs` — `POST /v1/oprf/issue` handler
- `routes/batch_issue.rs` — `POST /v1/oprf/issue/batch` handler
- `routes/metadata.rs` — `GET /.well-known/issuer`, `GET /.well-known/keys`, `GET /.well-known/federation`
- `routes/admin.rs` — full admin API (82 KB, all admin handlers)
- `routes/admin_rate_limit.rs` — per-IP rate limiting for login attempts
- `sybil_resistance/` — pluggable Sybil resistance backends (invitation, PoW, rate_limit, progressive_trust, proof_of_diversity, multi_party_vouching, federated_trust, webauthn)
- `admin_ui/index.html` — admin UI HTML, embedded at compile time via `include_str!`

Binaries:
- `freebird-issuer` — main server binary
- `freebird-validate-config` — pre-flight config validation tool
- `freebird-cli` — admin CLI for managing users, keys, invitations

### `freebird-verifier`

The verifier HTTP service. Key modules:

- `main.rs` — configuration, router, background issuer-metadata refresh loop
- `store.rs` — nullifier (spend) store abstraction with in-memory and Redis backends
- `routes/admin.rs` — verifier admin API (health, stats, config, issuer management, login/logout)
- `routes/admin_rate_limit.rs` — per-IP rate limiting for login attempts
- `admin_ui/index.html` — admin UI HTML, embedded at compile time via `include_str!`

Verifier routes:
- `POST /v1/verify` — single token verification (consuming; marks token spent)
- `POST /v1/verify/batch` — batch token verification
- `POST /v1/check` — non-consuming token validation (does not record nullifier)

### `freebird-interface`

CLI test client used for development and integration testing. Issues tokens against a running issuer, then verifies them against a running verifier.

### `integration_tests`

End-to-end test suite that starts real issuer and verifier instances in-process and exercises the full protocol flow, including key rotation, batch operations, double-spend detection, and Sybil mode permutations.

---

## Protocol Flow

### Token Issuance

```
Client                     Issuer
  |                           |
  | 1. random_input = rand()  |
  | blind(input) → (A, r)     |
  |                           |
  | POST /v1/oprf/issue       |
  | { blinded_element_b64: A, |
  |   sybil_proof: {...} }    |
  |-------------------------->|
  |                           | 2. verify Sybil proof
  |                           | 3. sk * A → B  (VOPRF evaluate)
  |                           | 4. DLEQ_proof(sk, A, B, pk)
  |                           | 5. sig = ECDSA(kid, exp, issuer_id)
  |                           |
  |  { token: [V|A|B|DLEQ],  |
  |    sig, kid, exp,         |
  |    issuer_id }            |
  |<--------------------------|
  |                           |
  | 6. verify DLEQ proof      |
  | 7. output = H(input, r⁻¹*B) — unblind
  | 8. buildRedemptionToken(  |
  |      output, kid, exp,    |
  |      issuer_id, sig)      |
  | → V3 token bytes          |
```

### Token Verification

```
Client                     Verifier
  |                           |
  | POST /v1/verify           |
  | { token_b64: <V3 token> } |
  |-------------------------->|
  |                           | 1. parse_redemption_token(bytes)
  |                           |    → output, kid, exp, issuer_id, sig
  |                           | 2. check exp > now (with clock skew)
  |                           | 3. lookup issuer pubkey by issuer_id
  |                           | 4. verify_token_signature(pk, sig,
  |                           |      kid, exp, issuer_id)
  |                           | 5. nullifier = hash(output)
  |                           | 6. store.try_spend(nullifier)
  |                           |    → error if already spent
  |  { ok: true,              |
  |    verified_at: <ts> }    |
  |<--------------------------|
```

---

## Key Abstractions

### `CryptoProvider` Trait

Defined in `crypto/src/provider/mod.rs`. All cryptographic operations that touch the secret key go through this trait:

```rust
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    async fn voprf_evaluate(&self, blinded: &[u8]) -> Result<Vec<u8>>;
    async fn sign_token_metadata(&self, kid: &str, exp: i64, issuer_id: &str) -> Result<[u8; 64]>;
    fn public_key(&self) -> &[u8];
    fn key_id(&self) -> &str;
    fn suite_id(&self) -> &str;
    fn context(&self) -> &[u8];
}
```

Implementations:
- `SoftwareCryptoProvider` (`provider/software.rs`) — P-256 secret key in memory
- `Pkcs11CryptoProvider` (`provider/pkcs11.rs`) — delegates to a PKCS#11 HSM (enabled by `--features pkcs11`)

The `MultiKeyVoprfCore` in the issuer holds a pool of `Arc<dyn CryptoProvider>` instances, one per active epoch key.

### `SybilProof` Enum

Defined in `common/src/api.rs`. A tagged union of all supported Sybil resistance proof types sent with issuance requests. The issuer dispatches to the appropriate `SybilResistance` implementation based on configured mode.

### `SpendStore` Trait

Defined in `verifier/src/store.rs`. Abstracts the nullifier store used for double-spend prevention:

```rust
pub trait SpendStore: Send + Sync {
    async fn try_spend(&self, key: &str) -> Result<bool, StoreError>;
}
```

Backends: `InMemoryStore` (default), `RedisStore` (production, set `REDIS_URL`).

---

## Token Format (V3)

V3 redemption tokens are variable-length binary blobs sent from client to verifier. Wire format:

```
[VERSION(1)] [output(32)] [kid_len(1)] [kid(N)] [exp(8, i64 BE)] [issuer_id_len(1)] [issuer_id(M)] [ECDSA_sig(64)]
```

- Minimum size: 109 bytes (1-byte kid and issuer_id)
- Maximum size: 512 bytes
- `output`: 32-byte unblinded VOPRF PRF output; self-authenticating via discrete log
- `kid`, `exp`, `issuer_id`: metadata bound by the ECDSA signature
- `ECDSA_sig`: P-256 signature over `"freebird:token-metadata:v3" || kid_len || kid || exp || issuer_id_len || issuer_id`

Tokens are base64url-encoded for transport.

---

## Admin UI Embedding

Both the issuer and the verifier serve a web-based admin UI at `GET /admin`. The HTML is a single self-contained file embedded at compile time using `include_str!`:

- Issuer: `issuer/src/admin_ui/index.html` (included by `issuer/src/routes/admin.rs`)
- Verifier: `verifier/src/admin_ui/index.html` (included by `verifier/src/routes/admin.rs`)

The source for these files lives in `admin-ui/` at the project root. To rebuild after editing the UI source, copy the built `index.html` into the respective `src/admin_ui/` directories.

The HTML is served with security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy). Session cookies set by `POST /admin/login` are HttpOnly, SameSite=Strict.

---

## Deployment Topology

```
Internet
    │
    ├─ issuer.example.com:8081    (freebird-issuer)
    │     ├─ /v1/oprf/issue
    │     ├─ /v1/oprf/issue/batch
    │     ├─ /.well-known/issuer
    │     ├─ /.well-known/keys
    │     ├─ /.well-known/federation
    │     ├─ /webauthn/...        (optional, --features human-gate-webauthn)
    │     └─ /admin/...           (requires ADMIN_API_KEY)
    │
    └─ verifier.example.com:8082  (freebird-verifier)
          ├─ /v1/verify
          ├─ /v1/verify/batch
          ├─ /v1/check
          └─ /admin/...           (requires ADMIN_API_KEY)
               └─ (fetches /.well-known/issuer periodically for key refresh)
```

The verifier and issuer are completely independent processes communicating only via HTTP. The verifier never needs access to the issuer's secret key; it only needs the issuer's public key (fetched from `/.well-known/issuer`).

For persistence:
- Issuer: secret key at `ISSUER_SK_PATH`, key rotation state at `KEY_ROTATION_STATE_PATH`, invitation system at `SYBIL_INVITE_PERSISTENCE_PATH`, federation data at `FEDERATION_DATA_PATH`
- Verifier: nullifier store — in-memory (default) or Redis (`REDIS_URL`)
