# Security status

**Experimental; no production release.** Freebird has not had an independent
security audit or an independent implementation interoperability test. Its
blind-RSA library is not independently audited for this integration. Passing
published RFC test vectors is necessary but is not a review of side-channel,
fault, parser, operational, or privacy behavior.

## Cryptographic dependency provenance

The lockfile pins `blind-rsa-signatures 0.18.0` to
[`kixel-ai/rind` commit `13f6c4565d2ac0c7a4488eba35933b2ca85ff317`](https://github.com/kixel-ai/rind/tree/13f6c4565d2ac0c7a4488eba35933b2ca85ff317/thirdparty/blind-rsa-signatures),
which adapts [upstream commit `45d0abfa829c3623389daae30bc35e9b2f3b550c`](https://github.com/jedisct1/rust-blind-rsa-signatures/tree/45d0abfa829c3623389daae30bc35e9b2f3b550c)
to stable RustCrypto `rsa 0.10.0` and `pkcs1 0.8.0`. This is a Git-pinned
third-party fork, **not** an upstream release or an independent audit. The
upstream MIT license and attribution remain in the fork. The fork adds
`RIND.md`; the only changed code, manifest, or test files are `Cargo.toml`,
`src/lib.rs`, `src/pbrsa.rs`, and `tests/vectors.rs`. `src/brsa.rs` (the
blinding implementation), `src/mgf1.rs`, and the published vector data are
byte-identical. The `src/pbrsa.rs` changes adapt
derived-key trait types and CRT parameter access to the stable RSA API;
source provenance and passing vectors do **not** establish cryptographic
equivalence, side-channel safety, or fault resistance.

Freebird maintainers own monitoring this pin, reviewing upstream changes and
advisories, and replacing it with a suitable upstream release when available.
Until then, changes to this fork or its resolved backend require a new source
diff, RFC vector and integration tests, and security review; do not silently
move the Git revision. An upstream compatibility patch has not been accepted.

On 2026-11-16, an unsuppressed `cargo audit` of this lockfile exited 0 with
**three allowed warnings**: `pin-utils` (RUSTSEC-2026-0441, unmaintained),
`rustix` (RUSTSEC-2026-0486, unsound xattr functions), and `tokio`
(RUSTSEC-2026-0386, unsound `AsyncFd` constructors). The previous
RUSTSEC-2023-0071 finding against the RSA release candidate is absent with
stable `rsa 0.10.0`. Audit success is not a security waiver or proof that the
remaining warnings and signing path are harmless.

The Origin holds only RSA public keys, never a signing secret. One
operator-issued invitation authorizes one signing attempt; the admission
database commits its consumption before signing. A lost response can burn an
invitation. The Origin validates
the signature and accepted challenge before durably recording a unique spend.
Store errors deny access. Accepted challenge windows are local policy, **not**
standardized token expiry; spent entries are retained until offline retirement
of their key, after its final acceptance deadline plus a safety margin.

One process per role and a local-loopback HTTP listener are the only supported
topology. The admission, issuer-key, and Origin stores use SQLite WAL/FULL
and separate lifetime OS locks.
Do not copy only the SQLite main file for backups: a consistent backup must
include committed WAL state. Restoring an older Origin snapshot requires
maintenance shutdown and fresh context-secret/store state, invalidating old
tokens. Restoring the admission store requires rotating its invitation
generation and invalidating old invitations before service resumes. An
unannounced rollback of both data and recovery markers cannot be detected
locally. No automatic failover or multi-replica safety is claimed.

Offline candidate staging, public-only SPKI export, activation/rotation, and
retirement are implemented, each guarded by its store's lifetime lock, for one
local instance per role.
Activation is Origin first (`install-origin-key`), then the Issuer schedule
(`activate-issuer-key`), at the same whole-hour instant `S`. A superseded Issuer
key is never used for signing after `S`. `retire-issuer-key` removes its private
material once `now >= S`; `retire-origin-key` deletes its challenge/spent rows and
marks it retired once `now >= S+420` (300-second grace plus 120-second margin).
Both operations advance high-water in the same transaction. Public key records
are retained permanently: retired IDs can never be reinstalled.

SQLite `secure_delete=ON` and the Issuer's best-effort post-retirement
`wal_checkpoint(TRUNCATE)` are **not a destruction guarantee**. A failed or busy
checkpoint does not undo the committed retirement or report it as a failure.
Journal copies, backups, snapshots, and process memory are out of scope; neither
zeroization nor forensic erasure is claimed.
Legacy `signing.pk8` state and schema-v1 key or Origin stores are refused
without migration or reset; fresh state uses private `issuer-keys.sqlite`.
Unsupported: HSM-backed keys, an online rotation API, multi-instance
operation, zeroization of superseded key memory, and multi-key directories
with a not-before field.

**Release blockers:** independent review of the selected RSA
backend and protocol integration;
independent implementation interoperability; parser fuzzing; operational
backup/recovery tests; and a supported deployment topology. The release,
container, and SDK publishers remain disabled. See the
[phase-one contract](docs/protocol/privacy-pass-phase1.md).

## Reporting vulnerabilities

Use GitHub private vulnerability reporting for this repository if available.
Otherwise open a public issue requesting a private security contact, without
posting exploit details, secrets, logs, or proof-of-concept code. Include the
affected commit, reproduction, expected and actual behavior, and whether the
issue concerns the Issuer, Origin, client flow, persistence, or cryptography.
