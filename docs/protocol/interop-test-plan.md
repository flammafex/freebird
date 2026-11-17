# Interoperability test plan

**Status:** plan only. No external implementation has been exercised against
Freebird yet. Passing Freebird's own tests and the RFC 9578 Appendix A.2
vectors shows agreement with published bytes, not with another implementation's
client, issuer, or verifier. Independent interoperability remains a release
blocker.

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

Each harness pins an exact package version or commit and records it in its
output. The Rust [`privacypass`](https://github.com/raphaelrobert/privacypass)
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

- Wrong key ID or truncated key ID suffix → Issuer 422 without consuming the
  invitation.
- Token bound to a different challenge or Origin → Origin 401.
- A token signed under a key the Origin has not activated → 401.
- Malformed or unpadded base64url in `Authorization` → 401.

## Pass criteria and reporting

Each harness exits non-zero on any mismatch and prints the pinned versions,
the SPKI key ID, and per-step HTTP statuses (never invitations or tokens).
Results are recorded in `SECURITY.md` with the date and versions used. Both
harnesses passing removes the interoperability blocker; it does not replace
independent cryptographic review.

## Out of scope for now

Apple, Fastly, and Google deployments depend on platform attesters and are at
most occasional manual smoke tests. Kagi's library implements a different
token type.
