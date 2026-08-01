# Release Packaging

Freebird releases are tag-driven. CI runs on `main` (and pull requests targeting
`main`), so push or merge the intended commit to `origin/main` and wait for its
eight required checks before creating the tag. Do not tag a commit that has not
first landed on `main`:

```bash
git tag -a v0.9.0 -m "Freebird 0.9.0"
git push origin v0.9.0
```

Pushing a `v*` tag starts two workflows:

- `Release`: builds Linux x86_64 binaries, creates a tarball, publishes
  SHA-256 checksums, and creates a GitHub release.
- `Build & Push Docker Images`: publishes issuer and verifier images to GHCR
  and signs each pushed image digest with keyless cosign. For version tags, its
  publisher first passes the exact-SHA CI gate and main-lineage check; it does
  not log in to GHCR or build/push tag images until that gate succeeds. Main
  branch builds skip the tag-only gate and remain functional.

## Release gate and immutable deployment inputs

The release workflow resolves the dereferenced tag to its commit SHA, verifies
that the SHA is an ancestor of freshly fetched `origin/main`, and polls the
GitHub Checks API (with pagination) for that exact SHA. Missing, queued, and
in-progress checks wait; the gate polls every 15 seconds by default for a
bounded 45 minutes (the safe limits are 15–30 seconds and 45–60 minutes).
The `RELEASE_GATE_POLL_INTERVAL_SECONDS` and `RELEASE_GATE_TIMEOUT_SECONDS`
environment variables may adjust those values only within those safe limits.
It fails closed on API/malformed responses, terminal failures, missing checks
at timeout, or anything other than `completed`/`success` for the exact SHA. The
required check names are: `build`, `test`, `feature-tests`, `lint`, `security`,
`javascript-sdk`, `repository-hygiene`, and `compose-smoke`. Publishing checks
out that SHA and creates the release with `gh release create --target SHA`, so
mutable branch/tag movement cannot change the packaged source.

Tag image publishing uses version tags only as aliases. Deployment operators
must obtain the registry-returned multi-architecture manifest digest from the
release artifact and supply an immutable `image@sha256:...` reference; do not
use `latest` or a floating version tag in production. This repository does not
invent or check in GHCR digests when the release artifact is unavailable.
Images are keylessly signed with GitHub OIDC and must be verified by digest.

Tagged image builds run a bounded `kind` smoke test using unique local image
tags, checked-in manifests plus ephemeral smoke secrets/configuration, rollout
and health checks, diagnostics, and cleanup. The smoke is not a production
configuration test and no manifest is rewritten or published.

Forgejo parity is unsupported: this release gate depends on GitHub Checks,
GitHub Actions artifacts, GHCR, and GitHub OIDC until a separate implementation
is approved.

Repository configuration prerequisite: branch protection/rulesets must require
the eight exact CI check names above on the release source branch, and GitHub
Actions must permit release gates `checks: read`/`contents: read`, the release
publisher `contents: write`, and (for Docker) the publisher's `packages: write`
and `id-token: write` permissions. No release may be considered gated unless
those checks are actually reported for the tag SHA.

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
sha256sum -c freebird-0.9.0-linux-x86_64.tar.gz.sha256
```

## Container Images

Tag releases publish:

```text
ghcr.io/flammafex/freebird-issuer:0.9.0
ghcr.io/flammafex/freebird-issuer:0.9
ghcr.io/flammafex/freebird-verifier:0.9.0
ghcr.io/flammafex/freebird-verifier:0.9
```

The default branch also publishes `latest`. Production deployments must replace
the deployment example's required image markers with operator-provided verified
image digests. A version tag is not an acceptable substitute for the immutable
production prerequisite.

## Signature Verification

The container workflow signs image digests with GitHub OIDC keyless signing.
After installing `cosign`, verify a pinned image digest with:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/.*/.github/workflows/docker.yml@refs/tags/v0.9.0' \
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
