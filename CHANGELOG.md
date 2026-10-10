# Changelog

## v0.10.5

- V7 graph-issuance policy discovery now references one exchange descriptor,
  keyset, and signer rather than reserving a duplicate graph-profile signer.
- Issuer graph issuance, startup configuration, offline validation, and
  readiness use the same exchange-profile binding; strict SDK discovery parity
  fixtures cover the shared graph/exchange role.
- V4-local holder authorization, V7 wire fields and canonical digests, and
  replay semantics remain unchanged.
- Test-only Gate 0 evidence tooling covers private fixture
  validation, replay-authority negative control, dropped-response recovery,
  verifier checking, and post-check spend-marker absence. It does not establish
  two-wallet exchange/spending or CLI/web product promotion.

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
