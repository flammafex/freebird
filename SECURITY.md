# Independent cryptographic review blocks Freebird's release

Do not deploy Freebird in production. **Independent review of the RSA backend and protocol integration is the sole release blocker.**
Freebird and its integration of the blind-RSA library have not undergone an independent security audit. Passing published RFC vectors does not evaluate side channels, fault resistance, parser safety, operations, or privacy.

## The lockfile pins a third-party RSA compatibility fork

The lockfile pins `blind-rsa-signatures 0.18.0` to [`kixel-ai/rind` commit `13f6c4565d2ac0c7a4488eba35933b2ca85ff317`](https://github.com/kixel-ai/rind/tree/13f6c4565d2ac0c7a4488eba35933b2ca85ff317/thirdparty/blind-rsa-signatures).
This Git-pinned third-party fork adapts [upstream commit `45d0abfa829c3623389daae30bc35e9b2f3b550c`](https://github.com/jedisct1/rust-blind-rsa-signatures/tree/45d0abfa829c3623389daae30bc35e9b2f3b550c) to stable RustCrypto `rsa 0.10.0` and `pkcs1 0.8.0`. It is not an upstream release or evidence of independent review.

The fork retains the upstream MIT license and attribution, and it adds `RIND.md`.
The only changes to code, manifests, or tests are in `Cargo.toml`, `src/lib.rs`, `src/pbrsa.rs`, and `tests/vectors.rs`.
The blinding implementation in `src/brsa.rs`, `src/mgf1.rs`, and the published vector data are byte-identical to upstream.
The fork adapts the derived-key trait types and access to CRT parameters in `src/pbrsa.rs` to the stable RSA API.
Source provenance and passing vectors do not establish cryptographic equivalence, side-channel safety, or fault resistance.

Maintainers must monitor the pin, review upstream changes and advisories, and replace the fork when a suitable upstream release is available.
Changes to the fork or its resolved backend require a fresh source diff, RFC vector and integration tests, and security review before changing the pin.
There is no accepted upstream compatibility patch.

On 2026-11-16, an unsuppressed `cargo audit` of this lockfile exited 0 with three allowed warnings:

- The `pin-utils` crate is unmaintained, as recorded in `RUSTSEC-2026-0441`.
- The `rustix` crate has unsound xattr functions, as recorded in `RUSTSEC-2026-0486`.
- The `tokio` crate has unsound `AsyncFd` constructors, as recorded in `RUSTSEC-2026-0386`.

`RUSTSEC-2023-0071` affects the RSA release candidate and does not appear in the audit with stable `rsa 0.10.0`.
An exit code of 0 is not a security waiver and does not establish that the warnings or the signing path are harmless.

## Durable state limits each credential to one use

The Origin holds only RSA public keys. An operator-issued invitation permits one signing attempt. The Issuer commits consumption in the admission database before signing, so a lost response can spend the invitation.

The Origin verifies the signature and accepted challenge before committing a unique spend. Store errors deny access. Challenge acceptance windows are local policy, not standardized token expiry.

Each admitted Origin request prunes challenges at `now >= deadline+120`, then prunes expired spends whose challenge row is absent.
Each request deletes at most 256 rows per table. Validation, pruning, redemption or challenge persistence, and high-water advancement share one fail-closed transaction.
Pruning never evicts redeemable spends, retires keys, or removes permanent key tombstones. A frozen clock or high request volume can accumulate unexpired rows because pruning does not impose a storage quota.

The Origin runs SQLite and RSA work in at most two admitted blocking jobs. Saturation returns 429 without a challenge or state change. Worker, store, or clock errors return 503.
Cancelling a request does not stop an admitted job or release its permit early. A lost response can spend a token, and uncertain spends must not be refunded.

Offline installation and rescheduling at the Origin preserve all replay rows. Retirement preserves rows for other keys.
Streamed canonical SHA-256 digests check preservation. The check depends on SHA-256 collision resistance and does not compare rows for literal equality.

## One host runs both roles behind nginx

The supported setup uses one Ubuntu 24.04 host. nginx terminates TLS for distinct Issuer and Origin names and proxies only the exact routes.
Each role runs one loopback HTTP process under a separate systemd user. The [deployment guide](docs/deployment.md) describes the setup, which CI tests with nginx, TLS, and the real binaries.

The admission, Issuer key, and Origin stores use SQLite WAL/FULL and separate lifetime OS locks.
Configure nginx not to cache or retry these requests and not to log token or invitation headers or bodies. Its error log can record client IP addresses.
An operator who runs both roles can correlate network metadata. The setup does not support replicas, shared hosts, containers, alternative proxies, CDNs, or load balancers.

## Stopped recovery invalidates restored credentials

Stop the processes and back up committed WAL state with the main SQLite files and their associated generation and context files. Copying only the live main SQLite file can omit committed data.

The [manual recovery procedure](docs/recovery.md) uses an external serving-permission hold to keep both roles stopped.
The procedure checks complete key histories against an operator-held catalog outside the restore scope before rotating the Issuer admission generation and the Origin context.
The procedure rejects stale key histories rather than reconstructing them.

The Origin deletes old challenges and spends in the transaction that updates the context hash. Key tombstones and the clock high-water mark are preserved.
Old tokens and invitations become invalid before either role resumes. A crash between publishing the context and committing the database leaves a hash mismatch that prevents startup.

Local checks cannot detect an unannounced rollback of the data together with the external catalog and serving permission. The procedure does not provide automatic failover or safety for multiple replicas.

## Offline rotation requires the same activation hour at both roles

One local instance per role supports offline candidate staging, public-only SPKI export, activation, and retirement. Each operation requires the lifetime lock for its store.
Run `install-origin-key` first and then `activate-issuer-key` with the same whole-hour instant `S`. The Issuer stops using the superseded key for signing at `S`.

Run `retire-issuer-key` once `now >= S` to remove the superseded private material.
Run `retire-origin-key` once `now >= S+420`, after the 300-second grace period and 120-second margin, to delete that key's challenge and spend rows and mark it retired.
Each retirement advances the clock high-water mark in the same transaction. Permanent public key records prevent retired IDs from being reinstalled.

SQLite `secure_delete=ON` and the Issuer's best-effort `wal_checkpoint(TRUNCATE)` after retirement do not guarantee destruction.
A failed or busy checkpoint neither undoes committed retirement nor changes the reported success. Journal copies, backups, snapshots, and process memory are outside the cleanup guarantee.
Retirement does not guarantee zeroization or forensic erasure.

The services reject legacy `signing.pk8` state and schema-v1 key or Origin stores without migration or reset. Fresh state uses the private `issuer-keys.sqlite` store.
Freebird does not support HSM-backed keys, online rotation, multiple instances per role, zeroization of superseded key memory, or a multi-key directory with a not-before field.

## Tests meet the other release gates

The [phase-one contract](docs/protocol/privacy-pass-phase1.md) defines the release gates. Release, container, and SDK publishing are disabled.

On 2026-11-17, the first local libFuzzer campaign met the parser-fuzzing gate by running each of the seven targets in `fuzz/` for 120 seconds without AddressSanitizer.
The targets cover wire codecs, challenges, the `Authorization` header, SPKI, and PKCS#8. The campaign ran about 520 million executions with no panics, round-trip mismatches, or saved failures.
`fuzz/README.md` documents the fuzz targets. CI runs property tests for the codecs on every change. Further fuzzing is recommended but is not a release requirement.

The [partial and full stopped-restore drills and fault-injection tests](docs/recovery.md) meet the backup and recovery gate.
The drills back up and restore all three databases, reject old credentials, and verify that replacement credentials work once.
A test verifies rollback after a real SQLite commit rejection. Subprocess crash tests verify the state before and after admission commit.

The [single-host template and automated TLS proxy round trip](docs/deployment.md) meet the deployment-topology gate.
Local testing on the macOS development host did not exercise the units under systemd.

The [bidirectional harnesses](docs/protocol/interop-test-plan.md) meet the interoperability gate, not the cryptographic review gate. Both passed locally on 2026-11-17 against independently written implementations.
The `@cloudflare/privacypass-ts` 0.9.0 client obtained a token from Freebird. `go.vitalvas.com/kasper` v1.1.0 verified the token, and Freebird accepted redemption and rejected replay.
The independent `pat-go` client at commit `7e6bbd0e4fa84c51ac6a6666d33770a120e68d63` obtained and redeemed a token through Freebird.

The `sjcl` ECC advisory [GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m) applies to the pinned TypeScript test package through its dependencies.
Using only the Type 2 RSA path in the tests does not establish safety for other uses.

## Optional admission paths retain the one-use limit

The optional [proof-of-work admission and browser demo](docs/demo.md) use `altcha` 1.1.0 with PBKDF2/SHA-256 and HMAC-SHA-256 to sign and verify challenges.
Freebird commits a durable record of the spent challenge before provisioning, so one solved challenge yields at most one invitation.
Proof-of-work raises the cost of collecting tokens, but it is not Sybil-proof and does not establish that a solver is a unique person.
The demo ships the same pinned `@cloudflare/privacypass-ts` dependency to browsers, including the dependency with the `sjcl` advisory, and uses only its RSA path.
Proof-of-work and the demo are not release gates.

Optional [admission for application servers](docs/app-admission.md) lets a server exchange its random 256-bit secret key for one-use codes under a daily cap.
The Issuer stores only the SHA-256 hash of the secret and commits quota use before provisioning. The application can identify which user received each code, but blinding keeps the code unlinkable to the redeemed token.
Recovery revokes every application key. Application admission is not a release gate.

## An nginx-set scope binds tokens to one resource

The Origin combines the optional `Freebird-Scope` header and the hour in the HMAC that derives the redemption context under a separate domain label.
The Origin rejects a token for a different scope. This binding relies on the Origin listening only on loopback and on nginx setting the header rather than forwarding a client-supplied value.
The [integration guide](docs/integration.md) specifies the nginx configuration.

## Report vulnerabilities through a private channel

Use GitHub private vulnerability reporting for this repository if it is available. Otherwise, open a public issue that requests a private security contact.
Do not post exploit details, secrets, logs, or proof-of-concept code publicly. In the private report, include the affected commit, steps to reproduce, and expected and actual behavior.
Identify whether the issue concerns the Issuer, Origin, client flow, persistence, or cryptography.
