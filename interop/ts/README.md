# Harness A uses the pinned Cloudflare client to issue tokens

Harness A uses `@cloudflare/privacypass-ts` 0.9.0 for interoperability tests
only. Use Node 20 or later. Run `npm ci` to install the dependency and
`node --test issue.test.mjs` to run the focused tests.

Create `OUTPUT_DIR` with mode `0700` and the invitation file with mode `0600`
before running the harness from the repository root.

```sh
node interop/ts/issue.mjs http://127.0.0.1:8080 http://127.0.0.1:8081 INVITATION_FILE OUTPUT_DIR
```

The Origin must advertise `origin.test`, and the directory must identify
the Issuer by an HTTPS authority. The harness connects only to numeric
loopback addresses over HTTP. It does not follow redirects or use proxy
environment variables.

The harness creates output files exclusively with mode `0600`. Use a fresh
directory for each run. Failed writes may leave partial artifacts, so discard
the private output directory before retrying. The Go verifier uses the
SPKI, challenge, and token artifacts for redemption. Harness A does not
redeem tokens. The recovery tests use the private `request.bin` to verify
that the Issuer rejects invitations from before recovery even when the
issuance request is valid.

## The harness checks the hashes in the finalized token

The harness uses the installed API in `lib/src/index.d.ts`,
`pub_verif_token.d.ts`, `auth_scheme/private_token.d.ts`, and
`pub_verif_token.js`. It creates a client with
`publicVerif.Client(publicVerif.BlindRSAMode.PSS)` and parses the challenge
with `TokenChallenge.deserialize(bytes)`. It creates the request with
`client.createTokenRequest(challenge, spki)`.

The harness parses the response with
`publicVerif.TokenResponse.deserialize(bytes)` and finalizes it with
`client.finalize(response)`. Finalization returns a `Token` with
`serialize()` and `authInput`. The client hashes the original SPKI and
serialized challenge that were supplied. The harness independently checks
these hashes against the corresponding fields in the finalized token.
It does not implement its own cryptography.

## `npm ci` reports three vulnerabilities for the pinned install

The lockfile records the required npm tarball integrity hash
`sha512-vePkwIJqZsqWUtSKlQ/pqpdSGNZzq6bktnAR81+6jV9NATVTIDEFRbdkQPYdfC+Jv55HD64shCzbPGcBqyW79g==`.
`npm ci` reports three high-severity dependency vulnerabilities. Use this
pin only for interoperability tests.
