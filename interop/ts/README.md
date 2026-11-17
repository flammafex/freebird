# Cloudflare client (Harness A)

Test-only dependency, pinned to `@cloudflare/privacypass-ts` 0.9.0.
Requires Node >=20. Install with `npm ci`; focused tests:
`node --test issue.test.mjs`.

From the repository root:

```sh
node interop/ts/issue.mjs http://127.0.0.1:8080 http://127.0.0.1:8081 INVITATION_FILE OUTPUT_DIR
```

Precreate OUTPUT_DIR with mode 0700 and the invitation file with mode 0600.
The Origin must advertise `origin.test`. Directory issuer identity must be an
HTTPS authority; transport remains strictly numeric loopback HTTP. Redirects
and proxy environment variables are not used. Files are exclusively created
with mode 0600; reruns require a fresh directory. Failed writes may leave
partial artifacts: discard the private output directory before retrying.
No redemption is performed here; the Go verifier consumes the SPKI, challenge,
and token artifacts. The private `request.bin` also supports recovery tests
that prove old invitations are refused with a valid issuance request.

Installed API confirmed in `lib/src/index.d.ts`, `pub_verif_token.d.ts`,
`auth_scheme/private_token.d.ts`, and `pub_verif_token.js`:
`publicVerif.Client(publicVerif.BlindRSAMode.PSS)`,
`TokenChallenge.deserialize(bytes)`, `client.createTokenRequest(challenge, spki)`,
`publicVerif.TokenResponse.deserialize(bytes)`, and `client.finalize(response)`.
Finalization returns a Token with `serialize()` and `authInput` fields.
The client hashes the supplied original SPKI and serialized challenge; the
harness independently checks these hashes against the finalized token fields.
There is no custom cryptographic implementation.

The lockfile includes the required npm tarball integrity:
`sha512-vePkwIJqZsqWUtSKlQ/pqpdSGNZzq6bktnAR81+6jV9NATVTIDEFRbdkQPYdfC+Jv55HD64shCzbPGcBqyW79g==`.
`npm ci` currently reports three high-severity dependency vulnerabilities;
the requested pinned version is retained for interoperability only.
