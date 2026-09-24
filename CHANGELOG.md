# Changelog

## v0.10.4

- Carries forward the V7 multi-output exchange request/result Merkle-proof
  soundness correction, plus the patched `rustls` and `cryptoki` dependencies.
- Adds the root changelog required in release archives.
- Supports V4 and V7; V5 and V2 are retired. The JavaScript SDK requires
  Node.js 24 or newer.
- Before upgrading an issuer, ensure its V7 exchange Redis state is fresh or
  has been emptied. Pre-v0.10.3 `ResultReady` records may contain copied request
  proofs and are unsupported; no migration is provided.

## v0.10.3 release attempt

The existing v0.10.3 source/tag history is retained and its tags must not be
moved. The release archive workflow failed because the root `CHANGELOG.md` was
missing. The npm publish workflow was blocked because the protected
`npm-publish` GitHub Environment did not have its required `NPM_TOKEN` secret.
Neither failure is evidence that a release tarball or npm package was
published.
