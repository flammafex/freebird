# Freebird implements Privacy Pass in Rust

Freebird is an **experimental, unreleased** implementation of publicly verifiable Privacy Pass tokens. Do not deploy it as a production authorization system.

Freebird uses RFC 9578 token type `0x0002`, which uses RSA-2048 blind signatures with the RFC 9474 SHA-384/PSS deterministic-message variant.
An Origin verifies tokens with the Issuer's public key and does not receive the signing key.
RFC 9577 defines the HTTP headers for challenges and redemption. Freebird limits issuance through a nonstandard, one-use operator invitation.

## Independent cryptographic review blocks release

GitHub release publishing is blocked pending independent review of the RSA backend and protocol integration, the sole release blocker.
The RFC 9474 library is pinned to a compatibility fork that uses stable RustCrypto RSA. Bidirectional tests against pinned TypeScript and Go implementations passed locally.
[SECURITY.md](SECURITY.md) records the dependency provenance and the limits of the test evidence.

The [deployment guide](docs/deployment.md) covers an experimental single-host setup with nginx terminating TLS for one loopback-only process per role.
SQLite state is exclusive and crash-durable. The setup has no automatic failover. Restoring a backup requires invalidating old invitations or challenge contexts.

Offline key staging, public-key export, activation, and retirement support one local instance per role. To rotate keys, install the Origin key first and specify the candidate key ID when scheduling the Issuer.
Freebird does not support HSMs, an online rotation API, multiple instances per role, zeroization of superseded key memory, or a multi-key directory with a not-before field.

Use this source checkout to test the protocol. The workspace crates have `publish = false`. The published `freebird-crypto` and `freebird-common` crates do not implement this protocol.

## One admission permits one signing attempt

Run `provision-live` to provision invitations while the Issuer runs. [Application servers](docs/app-admission.md) can request one-use codes under a daily cap and use their own policy to decide which users receive them.

The [integration guide](docs/integration.md) explains how to protect any application route through nginx, optionally bind tokens to one resource, and use the unpublished browser and server packages.
The optional [browser demo](docs/demo.md) lets anyone solve an ALTCHA proof-of-work puzzle for one admission, then obtain and redeem a token in JavaScript.
Proof-of-work raises the cost of collecting admissions but does not establish that a solver is a unique person.

Freebird does not support batching, renewal, a non-consuming token-check endpoint, or a token expiration extension.
It does not provide a general-purpose browser client, Docker image, Kubernetes manifest, or production authorization deployment.
The [roadmap](docs/roadmap.md) lists planned work, including batched issuance after publication of its RFC.

## Three crates separate parsing, signing, and serving

| Crate | Role |
| --- | --- |
| `freebird-common` | This crate strictly parses RFC 9577/9578 type-2 wire data and HTTP headers. |
| `freebird-crypto` | This crate adapts blind RSA for a fixed profile and tests it against independent RFC vectors. |
| `freebird-privacy-pass-service` | This experimental service runs the Issuer and Origin on loopback and stores durable records of admission and spend. |

The reference client tests obtain a challenge, submit one blinded request with an admission, finalize the token, and redeem it once.
They exercise both Axum routers and live loopback HTTP, including rejection of reuse after replay or restart. The reference client is not a general-purpose SDK.

Run these commands to test the workspace, check formatting, lint all targets, and check repository consistency:

```sh
cargo test --locked --workspace
cargo fmt -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
python3 scripts/ci-static-checks.py
```

The [protocol contract](docs/protocol/privacy-pass-phase1.md) defines the implementation profile, and the [RFC fixture provenance](common/test-fixtures/privacy-pass/README.md) identifies the source of its test vectors.
The [local runner guide](docs/quick-start.md) exercises the protocol over loopback.

## Either the MIT or Apache-2.0 license applies

Freebird is available under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE). Read [SECURITY.md](SECURITY.md) before testing or reporting a vulnerability.
