# Release Packaging

Freebird releases are tag-driven. CI runs on `main` (and pull requests targeting
`main`), so push or merge the intended commit to `origin/main` and wait for its
eight required checks before creating the tag. Do not tag a commit that has not
first landed on `main`:

```bash
git tag -a v0.10.3 -m "Freebird 0.10.3"
git push origin v0.10.3
```

Pushing a `v*` tag starts two workflows:

- `Release`: builds Linux x86_64 binaries, creates a tarball, publishes
  SHA-256 checksums, and creates a GitHub release.
- `Build & Push Docker Images`: publishes issuer and verifier images to GHCR
  and signs each pushed image digest with keyless cosign. For version tags, its
  publisher first passes the exact-SHA CI gate and main-lineage check; it does
  not log in to GHCR or build/push tag images until that gate succeeds. Main
  branch builds skip the tag-only gate and remain functional.

Pushing a dedicated `sdk-v*` tag starts the `Publish @flammafex/freebird` workflow.
It validates, packs, consumer-tests, and publishes the `@flammafex/freebird` npm
package. It uses the protected `npm-publish` GitHub Environment and a granular
npm automation token; it does not use OIDC or npm provenance.

## v0.10.3

- Strengthens V7 multi-output exchange request/result Merkle-proof soundness.
- Before upgrading an issuer to v0.10.3, ensure its V7 exchange Redis state is
  fresh or has been emptied. Pre-v0.10.3 `ResultReady` records may contain copied
  request proofs and are unsupported by this release; no migration is provided.
- V4 and V7 are supported; V5 and V2 are retired. The JavaScript SDK requires
  Node.js 24 or newer.

## v0.10.0 V7 canonical-descriptor migration

v0.10.0 derives canonical direct and exchange descriptor IDs from finalized
signer metadata and the canonical exchange descriptor transcript. Old arbitrary
descriptor IDs are rejected. The corrected exchange transcript therefore
invalidates prior exchange, keyset, transition, and graph-policy derived IDs.

Before releasing or upgrading an affected V7 deployment, operators must
regenerate and rotate the affected signer metadata, then regenerate the V7
registry and discovery/history from the canonical material. Do not reuse old V7
signer metadata, registry, discovery, keyset, transition, graph-policy, or other
derived data. For direct bootstrap, start once without
`NATIVE_BEARER_V7_DESCRIPTOR_ID`, persist the derived canonical output, and only
then optionally pin that public expected value for subsequent starts.

## npm SDK publishing

The npm package is published from the exact release tag. The workflow runs
credential-free `--ignore-scripts` install, lint, tests, build, and pack steps,
checks `package.json`/`package-lock.json` name and version parity, and inspects
the exact packed manifest and file list. It rejects the extracted packed version
if it is already present in the npm registry. That same tarball is installed
into a fresh temporary project and type-checked and executed through both its
ESM and CommonJS entry points before it can be published. The publish step is
the only step that receives `NPM_TOKEN`, and publishes only the inspected
tarball with `--ignore-scripts`.

### Maintainer setup

1. **Create the npm scope and package ownership.** An npm maintainer must create
   or control the `flammafex` npm organization/account at <https://www.npmjs.com/org>
   and ensure the maintainer account is an owner (or has publish access) for the
   `@flammafex` scope. The first publication is public and uses the package name
   `@flammafex/freebird`; do not rename the scope or package after publishing.
2. **Create a granular automation token.** In npm, open the maintainer account's
   **Access Tokens** page and create a **Granular Access Token** with the
   **Automation** token type. Grant publish access only to the `@flammafex` scope
   (or, after the first package exists, only to `@flammafex/freebird`), choose an
   explicit expiration, and use the npm organization's required 2FA/automation
   policy. Copy the token when npm shows it; it cannot be recovered later.
   Do not use an npm classic token, a developer token, or a GitHub OIDC token.
3. **Protect the GitHub secret.** In the repository, open **Settings →
   Environments → New environment**, name it exactly `npm-publish`, add required
   reviewers. If using selected branch/tag rules, allow `main` for the documented
   first-release dispatch and `sdk-v*.*.*` for future tag-triggered releases. Add
   an environment secret named exactly `NPM_TOKEN` and paste the granular
   automation token into it. Do not put this value in the repository's ordinary
   secrets, source files, `.npmrc`, or workflow text. The workflow requests only
   `contents: read`; it intentionally has no `id-token` permission and sets npm
   provenance to `false`.

### Required GitHub protections

Before creating an SDK release tag, configure all of the following:

- Protect `main`: require pull requests, prevent direct and force pushes, and
  require the exact CI checks `build`, `test`, `feature-tests`, `lint`,
  `security`, `javascript-sdk`, `repository-hygiene`, and `compose-smoke`.
- Create a GitHub repository ruleset targeting `sdk-v*.*.*`. Restrict tag
  creation to release maintainers, block tag updates and deletions, and block
  force pushes. Never retarget or recreate an SDK release tag after creation.
- Require the `npm-publish` Environment for the publishing job, with required
  reviewers and the `NPM_TOKEN` environment secret. Allow `main` only because
  manual dispatch is constrained to protected `main`; tag pushes use
  `sdk-v*.*.*`. Do not grant `id-token` permissions or enable npm provenance.

The workflow resolves the tag to one commit SHA, verifies that it is ancestral
to `origin/main`, runs `scripts/release-gate.py` for the exact SHA, and checks
out that SHA for packaging. Neither a moving branch nor a manually supplied
SHA can bypass the gate.

### SDK release (`@flammafex/freebird@0.10.3`)

SDK npm releases use dedicated immutable `sdk-vMAJOR.MINOR.PATCH` tags rather
than the Rust/container `v*` tags. After the npm organization, token, and
Environment are configured:

The SDK release requires Node.js 24 or newer.

1. In the reviewed release commit, update `sdk/js/package.json` and the root
   `sdk/js/package-lock.json` entry to `0.10.3`. Confirm that their names and
   versions match exactly, merge that commit to protected `main`, and wait for
   all required CI checks to pass.
2. Create and push the dedicated tag only after that review and gate:

   ```bash
   git tag -a sdk-v0.10.3 <reviewed-commit> -m "Publish @flammafex/freebird 0.10.3"
   git push origin sdk-v0.10.3
   ```

3. The tag push starts the workflow. Alternatively, start it manually from
   protected `main` with the exact existing tag; manual dispatch still resolves
   and gates that tag commit and cannot select a branch or SHA:

   ```bash
   gh workflow run npm-publish.yml --ref main -f tag=sdk-v0.10.3
   ```

4. Approve the `npm-publish` Environment deployment and wait for the workflow's
   pack, clean ESM/CJS consumer checks, and publish step to complete. The
   workflow rejects any package or lockfile metadata mismatch and any npm
   version that already exists; npm versions are immutable.

For every later release, update `sdk/js/package.json` and the root package entry
in `sdk/js/package-lock.json` to the release version in the release commit,
create and push the matching `sdk-vMAJOR.MINOR.PATCH` tag, and let the tag
trigger the workflow. Future tag-triggered runs do not rewrite package metadata.

### Verify a published SDK

The workflow run is the first verification. A maintainer should also confirm
the public registry record and both consumer forms after publication:

```bash
npm view @flammafex/freebird@0.10.3 version dist.tarball --registry=https://registry.npmjs.org
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
npm init --yes >/dev/null
npm install --ignore-scripts --no-audit --no-fund @flammafex/freebird@0.10.3 typescript@^5
node --input-type=module --eval "import('@flammafex/freebird').then(({FreebirdClient, crypto}) => { if (typeof FreebirdClient !== 'function' || typeof crypto.blind !== 'function') process.exit(1); })"
node --eval "const {FreebirdClient, crypto} = require('@flammafex/freebird'); if (typeof FreebirdClient !== 'function' || typeof crypto.blind !== 'function') process.exit(1)"
```

Record the npm package URL and workflow run in the release notes. Never paste
the token into an issue, log, or verification command.

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
sha256sum -c freebird-0.10.3-linux-x86_64.tar.gz.sha256
```

## Container Images

Tag releases publish:

```text
ghcr.io/flammafex/freebird-issuer:0.10.3
ghcr.io/flammafex/freebird-issuer:0.10
ghcr.io/flammafex/freebird-verifier:0.10.3
ghcr.io/flammafex/freebird-verifier:0.10
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
  --certificate-identity-regexp 'https://github.com/.*/.github/workflows/docker.yml@refs/tags/v0.10.3' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/flammafex/freebird-issuer@sha256:<digest>
```

Use the verifier image digest for the verifier command.

## Pre-Tag Checklist

- Update all workspace crate versions in Cargo manifests.
- Update `CHANGELOG.md`.
- Run `cargo test --workspace`.
- Run `cargo clippy --workspace --all-targets -- -D warnings`.
- Build and smoke-test the Docker images if deployment assets changed.
