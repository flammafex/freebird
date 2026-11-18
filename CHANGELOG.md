# Changelog

## Unreleased

- Introduced an experimental RFC 9578 publicly verifiable Privacy Pass
  implementation with one-use admission and durable single-instance
  redemption.
- Added independent RFC vectors, router and loopback HTTP round-trip tests.
- Added offline issuer-key staging and public-only, no-overwrite SPKI export.
- Implemented offline, single-instance key activation/rotation: install the
  Origin key first, schedule the Issuer at the same hour, and compare key status.
- Implemented offline key retirement: remove superseded Issuer private material
  and Origin challenge/spent rows after their safety boundaries; keep permanent
  public-key tombstones so retired IDs cannot be reinstalled. SQLite cleanup is
  best effort, not a destruction or zeroization guarantee.
- Pinned an RFC 9474 compatibility fork against stable RustCrypto RSA 0.10.0;
  the previous release-candidate advisory is no longer reported by
  `cargo audit`. The fork and integration have not been independently reviewed.
- Added seven parser fuzz targets and an initial clean campaign, bounded Origin
  replay-state pruning, and an independent-implementation interoperability plan.
- Added a single-host nginx/TLS and systemd deployment template, plus a
  CA-pinned local HTTPS client mode and an end-to-end proxy test.
- Ran pinned TypeScript and Go implementations bidirectionally against Freebird,
  including independent verification, redemption, replay, and negative cases.
- Added explicit stopped recovery with credential invalidation and key-history
  refusal, plus cold restore and commit/crash drills.
- Added `provision-live`: the running Issuer provisions one-use invitations
  over a UID-restricted local control socket, without downtime.
- Added optional ALTCHA proof-of-work admission (`init-issuer-pow`, six-argument
  `serve-issuer`): one solved, signed challenge yields at most one invitation,
  with a durable spent record, single-origin CORS and recovery rotation.
- Added a self-hosted browser demo (`demo/web/`) and a headless-Chrome TLS
  end-to-end test; nginx template serves it with a strict CSP and rate-limits PoW.
- Added admission for application servers: per-application secret keys
  (stored as hashes), a daily cap per application, management over the control
  socket, a server-only endpoint, and revocation of all keys on recovery.
- Release publishing remains blocked pending independent cryptographic review.
