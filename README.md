# Freebird

Freebird is an **experimental, unreleased** Rust implementation of publicly
verifiable Privacy Pass tokens.

The current profile is RFC 9578 token type `0x0002`: RSA-2048 blind signatures
with the RFC 9474 SHA-384/PSS deterministic-message variant. An Origin verifies
with the Issuer's **public** key and never receives its signing key. RFC 9577
defines the HTTP challenge and redemption headers. Freebird adds an explicitly
nonstandard, one-use operator invitation to control issuance quantity.

## Status

**Do not deploy as a production authorization system.** GitHub release
publishing is blocked. The RFC 9474 library is pinned to a compatibility fork
using stable RustCrypto RSA; the fork and signing path still require independent
review. Bidirectional tests against pinned TypeScript and Go implementations
passed locally. Offline key staging, public-key export,
activation (rotation, Origin first, with an explicit candidate key ID), and
retirement are implemented for one local instance per role. **Release remains
blocked** by independent crypto review and operational backup/recovery tests.
Unsupported: no HSM, no online rotation API, no multi-instance operation, no zeroization of
superseded key memory, and no multi-key directory with a not-before field.
The experimental single-host topology uses nginx TLS in front of one
loopback-only process per role, with exclusive, crash-durable SQLite state and
no automatic failover. Backup
restoration requires deliberate invalidation of old invitations or challenge
contexts. See the [deployment guide](docs/deployment.md) and
[security status and dependency provenance](SECURITY.md).

The published `freebird-crypto` and `freebird-common` crates predate this
implementation and do **not** provide the protocol described here. Current
crates have `publish = false`; use this source checkout for experimentation,
not an older registry release.

The reference client tests exercise challenge → one admitted blinded request →
finalization → one redemption through both Axum routers and live loopback HTTP,
with replay and restart rejection. They are not a general-purpose client SDK.
There is no batch, renewal, non-consuming token-check endpoint, token
expiration extension, browser client, Docker image, Kubernetes manifest, or
production authorization deployment.

## Workspace

| Crate | Role |
| --- | --- |
| `freebird-common` | Strict RFC 9577/9578 type-2 wire codec and HTTP header parsing |
| `freebird-crypto` | Fixed-profile blind-RSA adapter and independent RFC vectors |
| `freebird-privacy-pass-service` | Experimental Issuer, Origin, durable one-use admission and spent state, loopback-only runner |

Run the focused checks:

```sh
cargo test --locked --workspace
cargo fmt -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
python3 scripts/ci-static-checks.py
```

See the [protocol contract](docs/protocol/privacy-pass-phase1.md), its
[RFC fixture provenance](common/test-fixtures/privacy-pass/README.md), and
the [local experimental runner](docs/quick-start.md), and the
[single-host deployment guide](docs/deployment.md).

## License and security

MIT OR Apache-2.0: [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE). See
[SECURITY.md](SECURITY.md) before testing or reporting a vulnerability.
