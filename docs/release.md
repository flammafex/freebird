# Release Packaging

Freebird releases are tag-driven. Use annotated version tags:

```bash
git tag -a v0.5.1 -m "Freebird 0.5.1"
git push origin v0.5.1
```

Pushing a `v*` tag starts two workflows:

- `Release`: builds Linux x86_64 binaries, creates a tarball, publishes
  SHA-256 checksums, and creates a GitHub release.
- `Build & Push Docker Images`: publishes issuer and verifier images to GHCR
  and signs each pushed image digest with keyless cosign.

## Release Archive

The archive contains:

- `freebird-issuer`
- `freebird-cli`
- `freebird-validate-config`
- `freebird-verifier`
- `freebird-interface`
- README, changelog, license, security policy, docs, Kubernetes manifests,
  systemd examples, and reverse-proxy examples

Verify the archive checksum before installing:

```bash
sha256sum -c freebird-0.5.1-linux-x86_64.tar.gz.sha256
```

## Container Images

Tag releases publish:

```text
ghcr.io/flammafex/freebird-issuer:0.5.1
ghcr.io/flammafex/freebird-issuer:0.5
ghcr.io/flammafex/freebird-verifier:0.5.1
ghcr.io/flammafex/freebird-verifier:0.5
```

The default branch also publishes `latest`. Production deployments should pin a
version tag or image digest instead of `latest`.

## Signature Verification

The container workflow signs image digests with GitHub OIDC keyless signing.
After installing `cosign`, verify a pinned image digest with:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/.*/.github/workflows/docker.yml@refs/tags/v0.5.1' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/flammafex/freebird-issuer@sha256:<digest>
```

Use the verifier image digest for the verifier command.

## Pre-Tag Checklist

- Update all workspace crate versions in Cargo manifests.
- Update `CHANGELOG.md`.
- Run `cargo test --workspace`.
- Run `cargo test -p freebird-issuer --features human-gate-webauthn`.
- Run `cargo clippy --workspace --all-targets -- -D warnings`.
- Build and smoke-test the Docker images if deployment assets changed.
