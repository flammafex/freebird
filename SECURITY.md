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
standardized token expiry. Admitted, committed Origin requests prune expired
challenges at `now >= deadline+120`, then spends whose challenge is absent, with
at most 256 deletions per table per request. Validation, pruning, redemption or
challenge persistence, and high-water advancement share one fail-closed
transaction. Redeemable spends are never evicted. This is not a storage quota:
a frozen clock or high request volume can accumulate unexpired rows. Pruning
does not retire keys or remove their permanent tombstones.

Origin SQLite and RSA work runs in at most two admitted blocking jobs. Saturation
returns 429 without a challenge or state change; worker/store/clock errors return
503. Cancellation does not stop an admitted job or release its permit early;
a lost response may burn a token, which must never be refunded. Offline Origin
installation/rescheduling preserves all replay rows, and retirement preserves
other keys' rows, checked with streamed canonical SHA-256 digests. These checks
rely on SHA-256 collision resistance, not literal row-by-row equality.

The single supported network topology is one Ubuntu 24.04 host with nginx
terminating TLS for distinct Issuer and Origin names, proxying only the exact
routes to one loopback HTTP process per role under separate systemd users.
See the [deployment guide](docs/deployment.md) and its real-binary nginx/TLS
test in CI. The admission, issuer-key, and Origin stores use SQLite WAL/FULL
and separate lifetime OS locks. nginx must not cache, retry, or log token or
invitation headers/bodies; its error log can still record client IP addresses.
An operator running both roles can correlate network metadata. Replicas,
shared hosts, containers, alternative proxies, CDNs, and load balancers are
not supported.
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

On 2026-11-17, a first local libFuzzer campaign ran each of the seven targets
in `fuzz/` (wire codecs, challenge, Authorization header, SPKI, PKCS#8) for
120 seconds without AddressSanitizer (see `fuzz/README.md`): about 520 million
executions in total, no panics, round-trip mismatches, or saved failures.
This campaign satisfies the parser-fuzzing release gate. Property tests for the
codec targets run in CI on every change; further fuzzing is encouraged but is
not a release requirement.

**Release blockers:** independent review of the selected RSA backend and
protocol integration; and operational backup/recovery tests. The
interoperability gate is met by the
[bidirectional harnesses](docs/protocol/interop-test-plan.md). The
deployment-topology gate is met by the
[single-host template and automated TLS proxy round trip](docs/deployment.md);
the systemd units have not yet been exercised under systemd on this macOS
development host. The release, container, and SDK publishers remain disabled.
See the
[phase-one contract](docs/protocol/privacy-pass-phase1.md).

On 2026-11-17, independent implementation interop passed locally in both
planned directions: `@cloudflare/privacypass-ts` 0.9.0 issued through Freebird
and its token passed `go.vitalvas.com/kasper` v1.1.0 verification and Freebird
redemption/replay checks; `pat-go` commit
`7e6bbd0e4fa84c51ac6a6666d33770a120e68d63` independently issued and
redeemed through Freebird. The [reproducible harness and byte-level checks](docs/protocol/interop-test-plan.md)
meet the interoperability gate, not the cryptographic review gate. The pinned
TypeScript test dependency reports the `sjcl` ECC advisory
[GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m);
its Type 2 RSA-only test use does not make that advisory safe for other uses.

## Reporting vulnerabilities

Use GitHub private vulnerability reporting for this repository if available.
Otherwise open a public issue requesting a private security contact, without
posting exploit details, secrets, logs, or proof-of-concept code. Include the
affected commit, reproduction, expected and actual behavior, and whether the
issue concerns the Issuer, Origin, client flow, persistence, or cryptography.
