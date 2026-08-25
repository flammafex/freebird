# Contributing

Contributions should keep Freebird's security boundaries explicit. The project
is pre-1.0, public deployments are experimental, and tests or documentation are
not substitutes for an external security audit.

## Before opening a change

- Read the root [README](https://github.com/flammafex/freebird/blob/main/README.md), [Security Policy](https://github.com/flammafex/freebird/blob/main/SECURITY.md), and
  relevant documents under `docs/`.
- Keep claims specific to implemented behavior and configured deployment.
- Do not describe Sybil modes as proof of unique humanity.
- Do not describe V4 as RFC 9497 interoperable.
- Do not include secrets, generated key material, credentials, logs containing
  sensitive data, or local deployment artifacts.

## Tests and checks

For Rust changes, run the repository's workspace checks as appropriate:

```text
cargo fmt -- --check
cargo build --workspace
cargo test --workspace
```

Redis-dependent tests may skip when Redis is unavailable; they must not be
presented as passing Redis coverage when they were skipped. For SDK changes,
run the documented checks from `sdk/js`:

```text
npm run lint
npm test
```

Add regression and negative coverage for behavior changes. Protocol, replay,
Sybil, admin, TLS, key-lifecycle, and privacy changes need especially careful
review because documentation alone cannot establish their security properties.

## Style and documentation

Keep changes focused, preserve existing source headers and repository licensing
metadata, and update documentation when changing APIs, configuration, Sybil
modes, token formats, or deployment behavior. Use the existing repository
formatting and naming conventions. Avoid weakening tests to make a change pass.

## Security reports

Do not publish exploit details, secrets, logs, or proof-of-concept code in a
public issue. Follow the reporting instructions in the root
[Security Policy](https://github.com/flammafex/freebird/blob/main/SECURITY.md): use GitHub private vulnerability reporting
when available, or ask publicly for a private security contact without exposing
the vulnerability.

Useful reports include the affected commit/release, deployment mode and feature
flags, reproduction steps, expected and actual behavior, and the affected
component.
