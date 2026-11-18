# Independent clients interoperate with Freebird

Both harnesses passed locally against the real Freebird binaries on 2026-11-17.
The tests establish compatibility with independently written clients and a verifier. They do not constitute an independent cryptographic audit.
Install the pinned test dependencies before running `python3 scripts/test-interop.py`. The CI `interop` job repeats the test on Ubuntu.

## Both harnesses check the RFC encodings

Freebird and the independent RFC 9578 type-`0x0002` implementations must agree on these bytes and HTTP fields:

- **The token key ID** is the SHA-256 hash of the exact advertised `id-RSASSA-PSS` SPKI bytes, not a re-encoded `rsaEncryption` SPKI.
- **The binary messages** must match in encoding and length for `TokenRequest`, `TokenResponse`, and `Token`.
- **The challenge digest** must come from the same exact serialized `TokenChallenge` bytes.
- **The HTTP headers** must use RFC 9577 syntax for `WWW-Authenticate` and `Authorization`, including padded base64url and quoted parameters.

The harnesses supply `Freebird-Admission` as an extra, Freebird-specific header outside the RFC comparisons.

## TypeScript and Go provide independent clients and a verifier

| Direction | Implementation | Role in harness |
|---|---|---|
| Freebird Issuer → independent client and verifier | [Cloudflare `privacypass-ts`](https://github.com/cloudflare/privacypass-ts) | This Type 2 client uses Freebird's challenge and SPKI to build the request and finalize the response. It uses npm, requires Node 20+, and has an Apache-2.0 license. |
| Freebird Issuer → independent client and verifier | [`go.vitalvas.com/kasper/privacypass`](https://pkg.go.dev/go.vitalvas.com/kasper/privacypass) | This Go implementation independently verifies the finalized token against the exact challenge and SPKI. It has an MIT license. |
| Independent client → Freebird Issuer and Origin | [Cloudflare `pat-go`](https://github.com/cloudflare/pat-go) | This Type 2 Go client uses CIRCL. Freebird issues the token and accepts redemption. The Go client has a BSD-3-Clause license. |

[`interop/ts/package-lock.json`](https://github.com/flammafex/freebird/blob/main/interop/ts/package-lock.json) pins `@cloudflare/privacypass-ts` **0.9.0**.
[`interop/go/go.mod`](https://github.com/flammafex/freebird/blob/main/interop/go/go.mod) and `go.sum` pin `pat-go` commit **`7e6bbd0e4fa84c51ac6a6666d33770a120e68d63`** and Kasper **v1.1.0**.
The local run used Node 26 and Go 1.27.3.

The Rust [`privacypass`](https://github.com/raphaelrobert/privacypass) crate is not a default harness because its lockfile resolves an `rsa` release candidate affected by RUSTSEC-2023-0071.
Review that dependency before adding the crate as an extra regression check. Cloudflare's Worker Issuer and Origin use the same TypeScript stack and do not count as separate implementations.

## Harness A verifies a TypeScript token with Go

This harness checks issuance through Freebird, independent verification with Kasper, and redemption at Freebird's Origin:

1. **Start fresh Issuer and Origin processes** with the local runner and provision one invitation that permits one issuance attempt.
2. **Fetch the directory and the 401 challenge** over loopback HTTP to get the advertised key and challenge bytes.
3. **Build the raw `TokenRequest`** with the lower-level TypeScript client API and Freebird's exact challenge bytes and advertised SPKI. The discovery helper requires HTTPS, so it is not used over loopback HTTP.
4. **Send the request** as a `POST` to `/private-token/issue` with `Content-Type: application/private-token-request` and `Freebird-Admission` to obtain a blind signature.
5. **Finalize the 256-byte response** with the TypeScript client to obtain a token.
6. **Verify with Kasper** against the exact challenge and SPKI. Check both the challenge digest and the signature.
7. **Redeem at Freebird's Origin** and expect 200. Replay that token and expect 401.

## Harness B redeems a Go client's token at Freebird

This harness checks issuance and redemption through Freebird using the `pat-go` client:

1. **Start fresh Issuer and Origin processes** with the local runner and provision one invitation that permits one issuance attempt.
2. **Fetch the directory and challenge** with the Go wrapper to get the advertised SPKI and challenge bytes.
3. **Build the request** with the `pat-go` Type 2 client using Freebird's SPKI and challenge. Submit it with `Freebird-Admission` through the wrapper to obtain a blind signature.
4. **Finalize the response** with `pat-go` to obtain a token.
5. **Redeem with `PrivateToken token="..."`** using the padded base64url encoding and expect 200. Replay that token and expect 401.

## Byte comparisons verify the key and challenge digests

Both harnesses check the following byte-level results:

- **Deterministic encodings** must match RFC 9578 Appendix A.2 and the type 2 vectors that `privacypass-ts` and `pat-go` ship.
- **The computed key IDs** must match when both sides hash the same SPKI bytes.
- **The computed challenge digests** must match the digest that Freebird computes.

## Invalid inputs and replays fail without granting access

The tests cover the following failures:

- **A wrong truncated key ID** returns 422 and does not consume the invitation. The TypeScript client can obtain a token with that same invitation.
- **A changed Origin in the challenge** fails Kasper verification. Kasper also rejects replay.
- **A malformed `Authorization` token** is rejected by Freebird's Origin. The Origin accepts each valid TypeScript or Go token once and rejects replay.
- **A key that is not installed at the Origin** is rejected in Freebird's own key-rotation tests. The external-client harnesses do not cover that case.

The base64url encoding of a 354-byte token requires no padding. Removing `=` cannot test noncanonical token padding for this token type.

## Mismatches fail the harness

Each harness exits with a nonzero status on a mismatch. Its output is limited to public versions, the SPKI key ID, and statuses. It does not print invitations or tokens.
The local run produced these results:

| Flow | Observed result |
|---|---|
| TypeScript client → Freebird Issuer → Kasper verifier → Freebird Origin | Issuance returned 200, and independent verification passed. Origin redemption returned 200, and replay returned 401. |
| `pat-go` client → Freebird Issuer and Origin | Issuance and redemption returned 200. Replay returned 401. |
| Wrong truncated key ID or malformed token | The wrong key ID returned 422 without consuming the invitation. The malformed token returned 401. |

Run these commands from a source checkout to build Freebird and run both harnesses:

```sh
cargo build --locked -p freebird-privacy-pass-service --bin freebird-privacy-pass-service
(cd interop/ts && npm ci --ignore-scripts && node --test)
(cd interop/go && go test ./...)
python3 scripts/test-interop.py
```

The runner uses two private one-use invitations and temporary loopback stores. It requires Node 26 and Go 1.27. It does not send requests to the advertised public HTTPS name.
Before accepting a key ID, the Go harness compares both libraries' re-encoded RSA-PSS SPKI with the original bytes that Freebird advertised. This prevents a generic Go `rsaEncryption` SPKI from being treated as equivalent.
The Go harness also compares Kasper's re-encoded challenge with the bytes that Freebird served.

`npm audit` reports three cascading high-severity entries from the `sjcl` ECC point-validation advisory [GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m) through `@cloudflare/blindrsa-ts` to the pinned TypeScript package.
The harness uses only the type-2 RSA path. Its dependencies are test-only and are not included in Freebird's service. The audit output retains the advisory, and the test does not establish that other uses of these packages are safe.

## Platform attesters and other token types fall outside the harnesses

Apple, Fastly, and Google deployments depend on platform attesters, so their coverage is limited to occasional manual smoke tests. Kagi's library implements a different token type.
