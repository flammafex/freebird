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
- Release publishing remains blocked pending independent cryptographic review,
  independent interoperability testing, parser fuzzing, operational
  backup/recovery tests, and a supported deployment topology.
