# Changelog

## Unreleased

- Introduced an experimental RFC 9578 publicly verifiable Privacy Pass
  implementation with one-use admission and durable single-instance
  redemption.
- Added independent RFC vectors, router and loopback HTTP round-trip tests.
- Pinned an RFC 9474 compatibility fork against stable RustCrypto RSA 0.10.0;
  the previous release-candidate advisory is no longer reported by
  `cargo audit`. The fork and integration have not been independently reviewed.
- Release publishing remains blocked pending key rotation, interoperability,
  independent security review, and operational recovery evidence.
