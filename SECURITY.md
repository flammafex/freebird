# Security status

**Experimental; no production release.** Freebird has not had an independent
security audit or an independent implementation interoperability test. Its
blind-RSA dependency (`blind-rsa-signatures =0.18.0`) uses an RSA
release-candidate backend. Passing published RFC test vectors is necessary
but is not a review of side-channel, fault, parser, operational, or privacy
behavior.

The current lockfile fails `cargo audit`: `rsa 0.10.0-rc.18` is reported under
**RUSTSEC-2023-0071** (potential timing-based key recovery; the advisory's
fixed range starts at stable 0.10.0). The audit also reports warnings for
`pin-utils`, `rustix`, and `tokio`. We have **not** established that the
advisory applies or does not apply to the exact blind-signing path; no waiver
is appropriate without a review. CI deliberately fails its security job.
The blind-signing path uses base blinding, and remote key recovery through
this exact path has **not** been demonstrated. The release candidate also
lacks private-operation hardening added in stable RSA 0.10.0, so it cannot be
treated as equivalent or cleared by a version-range argument.

The Origin holds only an RSA public key. One operator-issued invitation
authorizes one signing attempt; the admission database commits its consumption
before signing. A lost response can burn an invitation. The Origin validates
the signature and accepted challenge before durably recording a unique spend.
Store errors deny access. Accepted challenge windows are local policy, **not**
standardized token expiry; spent entries are currently retained indefinitely.

One process per role and a local-loopback HTTP listener are the only supported
topology. The two stores use SQLite WAL/FULL and separate lifetime OS locks.
Do not copy only the SQLite main file for backups: a consistent backup must
include committed WAL state. Restoring an older Origin snapshot requires
maintenance shutdown and fresh context-secret/store state, invalidating old
tokens. Restoring the admission store requires rotating its invitation
generation and invalidating old invitations before service resumes. An
unannounced rollback of both data and recovery markers cannot be detected
locally. No automatic failover or multi-replica safety is claimed.

**Release blockers:** supported key staging/rotation and retirement;
independent review of the selected RSA backend and protocol integration;
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
