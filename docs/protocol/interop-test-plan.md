# Interoperability test and evidence

**Status:** both planned harnesses passed locally on 2026-11-17 against real
Freebird binaries. Run `python3 scripts/test-interop.py` after installing the
pinned test-only dependencies below. The CI `interop` job repeats the test on
Ubuntu. This demonstrates compatibility with independently written clients
and a verifier; it is not an independent cryptographic audit.

## Goal

Show, in both directions, that Freebird and independently written RFC 9578
type-`0x0002` implementations agree on:

- the advertised `id-RSASSA-PSS` SPKI bytes and the token key ID
  (SHA-256 over exactly those bytes, never a re-encoded `rsaEncryption` SPKI);
- `TokenRequest`, `TokenResponse`, and `Token` encodings and lengths;
- the exact serialized `TokenChallenge` bytes and their digest;
- RFC 9577 `WWW-Authenticate` and `Authorization` syntax, including padded
  base64url and quoted parameters.

`Freebird-Admission` is Freebird-specific deployment glue. Harnesses supply it
as an extra header; it is not part of any comparison.

## Selected implementations

| Direction | Implementation | Role in harness |
|---|---|---|
| Freebird Issuer → independent client and verifier | [Cloudflare `privacypass-ts`](https://github.com/cloudflare/privacypass-ts) (npm, Apache-2.0, Node 20+) | Type 2 client: consume Freebird's challenge and SPKI, build the request, finalize the response |
| | [`go.vitalvas.com/kasper/privacypass`](https://pkg.go.dev/go.vitalvas.com/kasper/privacypass) (Go, MIT) | Independent Origin-side verification of the finalized token against the exact challenge and SPKI |
| Independent client → Freebird Issuer and Origin | [Cloudflare `pat-go`](https://github.com/cloudflare/pat-go) (Go, BSD-3-Clause) | Type 2 client built on CIRCL; Freebird issues and redeems |

The harnesses pin `@cloudflare/privacypass-ts` **0.9.0** in
[`interop/ts/package-lock.json`](https://github.com/flammafex/freebird/blob/main/interop/ts/package-lock.json),
`pat-go` commit **`7e6bbd0e4fa84c51ac6a6666d33770a120e68d63`**
and Kasper **v1.1.0** in
[`interop/go/go.mod`](https://github.com/flammafex/freebird/blob/main/interop/go/go.mod)
and `go.sum`. Node 26 and Go 1.27.3 were used locally. The Rust
[`privacypass`](https://github.com/raphaelrobert/privacypass)
crate is deliberately **not** a default harness: at the time of writing its
lockfile resolves an `rsa` release candidate affected by RUSTSEC-2023-0071.
It may be added later as an extra regression check once its dependency is
reviewed. Cloudflare's Worker issuer and origin reuse the TypeScript stack and
do not count as separate implementations.

## Harness A: Freebird Issuer → TypeScript client → Go verifier → Freebird Origin

1. Start a fresh Issuer and Origin with the local runner; provision one
   invitation.
2. Fetch the Issuer directory and the Origin's 401 challenge over loopback
   HTTP.
3. TypeScript: use the lower-level client API (not its HTTPS-only discovery
   helper) with Freebird's exact challenge bytes and advertised SPKI; produce a
   raw `TokenRequest`.
4. POST it to `/private-token/issue` with
   `Content-Type: application/private-token-request` and `Freebird-Admission`.
5. TypeScript: finalize the 256-byte response into a token.
6. Go (Kasper): verify the token against the exact challenge and SPKI,
   including the challenge digest — not only the signature.
7. Redeem the token at Freebird's Origin (expect 200), then replay it
   (expect 401).

## Harness B: Go client → Freebird Issuer and Origin

1. Same fresh roles and invitation as above.
2. A small Go wrapper fetches the directory and challenge.
3. `pat-go`'s Type 2 client builds the request from Freebird's SPKI and
   challenge; the wrapper submits it with `Freebird-Admission`.
4. `pat-go` finalizes the response.
5. Redeem with a padded `PrivateToken token="..."` header (expect 200), then
   replay (expect 401).

## Byte-level checks (both harnesses)

- Cross-check deterministic encodings against RFC 9578 Appendix A.2 and the
  type 2 vectors shipped by `privacypass-ts` and `pat-go`.
- Assert both sides compute the same token key ID from the same SPKI bytes.
- Assert the challenge digest each side computes equals Freebird's.

## Negative cases

- A wrong truncated key ID → Issuer 422 without consuming the invitation;
  subsequent TypeScript issuance with that same invitation succeeds.
- Kasper rejects a changed Origin in the challenge and rejects replay.
- Freebird Origin rejects a malformed Authorization token, accepts the real
  TypeScript token once, and rejects its replay. It also accepts the Go client's
  token once and rejects replay. A 354-byte token's base64url encoding needs
  no padding; removing `=` cannot test noncanonical token padding here.
- A key not installed at the Origin remains covered by Freebird's own
  key-rotation tests, not by these external-client harnesses.

## Pass criteria and reporting

Each harness exits non-zero on a mismatch and prints only public versions,
SPKI key ID, and statuses (never invitations or tokens). The local result was:

| Flow | Observed result |
|---|---|
| TypeScript client → Freebird Issuer → Kasper verifier → Freebird Origin | Issuance 200; independent verification OK; Origin redemption 200, replay 401 |
| `pat-go` client → Freebird Issuer and Origin | Issuance 200; redemption 200, replay 401 |
| Wrong truncated key ID / malformed token | 422 without consuming invitation / 401 |

To reproduce from a source checkout:

```sh
cargo build --locked -p freebird-privacy-pass-service --bin freebird-privacy-pass-service
(cd interop/ts && npm ci --ignore-scripts && node --test)
(cd interop/go && go test ./...)
python3 scripts/test-interop.py
```

The runner uses two private one-use invitations and temporary loopback stores.
It requires Node 26 and Go 1.27; it never sends a request to the advertised
public HTTPS name. The Go harness compares both libraries' re-encoded
RSA-PSS SPKI to Freebird's **original bytes** before trusting a key ID, and
compares Kasper's re-encoded challenge with the bytes actually served. This
avoids treating Go's generic `rsaEncryption` SPKI as equivalent.

`npm audit` currently reports three cascading high-severity entries from
`sjcl`'s ECC point-validation advisory
([GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m))
through `@cloudflare/blindrsa-ts` to the pinned TypeScript package. This
interop harness exercises type-2 RSA only, uses test-only dependencies and
does not ship them in Freebird's service. The advisory is recorded, not
silently suppressed or declared harmless for every use of those packages.

## Out of scope for now

Apple, Fastly, and Google deployments depend on platform attesters and are at
most occasional manual smoke tests. Kagi's library implements a different
token type.
