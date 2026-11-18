# Roadmap

Freebird remains experimental. The only release blocker is the independent
cryptographic review described in
[SECURITY.md](https://github.com/flammafex/freebird/blob/main/SECURITY.md);
nothing on this page is a release gate.

## Planned

### Generic batched issuance (after the RFC is published)

**Trigger:** publication of
[draft-ietf-privacypass-batched-tokens](https://datatracker.ietf.org/doc/draft-ietf-privacypass-batched-tokens/)
as an RFC (draft-10, November 2026, is in IESG evaluation). Nothing is built
against the draft; the wire format may still change.

**Scope:** the draft's *generic* variant only, for type `0x0002` tokens. It
bundles ordinary RFC 9578 token requests into one HTTP request
(`application/private-token-generic-batch-request`) and returns one response per
entry, with refused entries absent. It adds no new cryptography and signing cost
stays linear. The *amortized* variant applies only to VOPRF token types and is
out of scope while Freebird does not implement type 1.

**Admission change:** one admission will authorize at most **N** signing
attempts instead of one, where N is a fixed, operator-configured batch size.
The admission (invitation or solved PoW challenge) is still consumed and
committed before any signing, and a failed or lost response still burns it;
nothing is refunded. A batch larger than N, or mixing key IDs, is refused.

**Origin:** no change required. A challenge is valid until five minutes past
the end of its hour, and spends are recorded per key, challenge and nonce, so
each token from one batch redeems once within that window. Batched tokens
cannot be stockpiled beyond it.

**Privacy:** the Issuer sees which requests arrive together and how many. A
fixed batch size, rather than client-chosen sizes, keeps batches from
distinguishing clients. This will be documented with the feature.

**Before release:** fuzz the batch request/response codec like the existing
wire formats; interop-test against the pinned `@cloudflare/privacypass-ts` and
the Rust `privacypass` crate, which both implement generic batching; extend the
browser demo so one PoW yields N tokens; and include the change in the
independent review scope.

### Admission requests from app servers (available)

See [admission for application servers](app-admission.md). An application
server authenticates with its own secret key and receives
one-use admission codes, up to a fixed daily cap per server set by the
operator. The application's own policy decides which of its users get a code;
Freebird keeps no user accounts or social graph and never learns who the end
users are. The application's server then verifies the resulting tokens with
the Issuer's public key, as any Origin does.

### Application integration kit (available)

See [integrating an application](integration.md).

So an application can adopt Freebird without implementing Privacy Pass itself:

- **Token checking through nginx.** Freebird's Origin checks tokens for any
  protected application route via nginx `auth_request`. The application sees
  only requests that carried a valid, unspent token; it writes no
  cryptography or replay storage. An optional, operator-configured scope (for
  example a ballot or pool identifier) binds tokens to one resource, so a token
  obtained for one cannot be spent on another.
- **A browser client** that performs the challenge, issuance with an admission
  code, and redemption for a protected URL, packaged from the demo's code.
- **A server helper** for requesting admission codes from the Issuer.

The packages live in this repository and are not published while release
publishing is held.

## Not planned unless a real application needs them

- **Issuer-to-issuer admission**: an Issuer acting as an ordinary Origin for
  another Issuer's tokens, exchanging each for one local admission. An
  application that trusts another community can usually request admission
  codes on its behalf instead.
- **Origins trusting more than one Issuer.** One Issuer can already serve many
  independent applications.

## Under consideration (not committed)

- **A memory-hard PoW option** (Argon2id or scrypt) to narrow GPU advantage,
  at the cost of WebAssembly and a looser browser security policy.
- **Post-quantum tokens**, once a standard successor to RSA blind signatures
  exists.
