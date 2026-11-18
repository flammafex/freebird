# Freebird implements an experimental Privacy Pass profile

Freebird implements RFC 9578 Privacy Pass token type `0x0002` for experiments. Its production release is blocked until the release gates pass.

Each guide covers a different part of running or testing Freebird:

- The [protocol contract](protocol/privacy-pass-phase1.md) defines the token profile, state rules, and release gates.
- The [local runner](quick-start.md) exercises the protocol on loopback.
- The [deployment guide](deployment.md) sets up the experimental services on one host.
- The [recovery guide](recovery.md) covers stopped backups and restores that invalidate old credentials.
- The [browser demo](demo.md) obtains admission through proof-of-work and redeems a token in JavaScript.
- The [application admission guide](app-admission.md) shows how a server can request one-use codes under a daily cap.
- The [integration guide](integration.md) explains how nginx protects application routes through the Origin.
- The [roadmap](roadmap.md) identifies planned and proposed features.
- The [interoperability test plan](protocol/interop-test-plan.md) documents the harnesses and their results.
- The [security policy](https://github.com/flammafex/freebird/blob/main/SECURITY.md) records the limits of test evidence and explains how to report vulnerabilities.
- The [RFC fixture provenance](https://github.com/flammafex/freebird/blob/main/common/test-fixtures/privacy-pass/README.md) identifies the sources and hashes of the test vectors.
