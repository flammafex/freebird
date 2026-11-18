# Freebird plans to add batched issuance after standardization

Freebird is experimental. The independent cryptographic review described in [SECURITY.md](https://github.com/flammafex/freebird/blob/main/SECURITY.md) is the sole release blocker. None of these features is a release gate.

## Generic batch support depends on publication of the RFC

Freebird plans to implement generic batching after [draft-ietf-privacypass-batched-tokens](https://datatracker.ietf.org/doc/draft-ietf-privacypass-batched-tokens/) is published as an RFC.
Draft-10 from November 2026 is in IESG evaluation. Freebird does not implement the draft because the wire format may change.

Generic batching applies to type `0x0002` tokens. It combines ordinary RFC 9578 requests in one HTTP request with media type `application/private-token-generic-batch-request`.
The Issuer returns one response per accepted entry and omits refused entries. Batching adds no cryptography, and signing cost stays linear.
Amortized batching applies only to VOPRF token types and is outside Freebird's scope because Freebird does not implement type 1.

One invitation or solved proof-of-work challenge would permit at most **N** signing attempts, where the operator sets the fixed batch size N.
The Issuer would commit admission consumption before any signing and reject batches that exceed N or mix key IDs.
A failed or lost response would consume the admission, and the Issuer would not refund it.

The Origin needs no changes because it records spends per key, challenge, and nonce. Each token from a batch can redeem once before the challenge closes five minutes past the end of its hour.
Tokens from a batch cannot be stockpiled past that window.

The Issuer can observe which requests arrive together and how many the batch contains. A fixed batch size prevents client-selected sizes from distinguishing clients. Document this privacy limit when adding batching.

Validate batching before releasing it. Apply the same fuzzing approach as for the non-batch wire codecs to both batch request and response codecs.
Test interoperability with the pinned `@cloudflare/privacypass-ts` and the Rust `privacypass` crate, which both implement generic batching.
Extend the browser demo to yield N tokens per solved proof-of-work challenge and include batching in the independent review.

## Application servers can request one-use codes

An [application server](app-admission.md) authenticates with its own secret key and requests one-use codes up to a fixed daily cap that the operator sets for that server.
The application uses its own policy to decide which users receive codes. Freebird stores no user accounts or social graph and receives no identities for end users.
The application server can act as an Origin and verify the resulting tokens with the Issuer's public key.

## The integration kit protects application routes through nginx

The [integration kit](integration.md) lets an application protect routes and request codes without implementing Privacy Pass. Each part handles a distinct job:

- **nginx `auth_request`** sends checks for any protected application route to Freebird's Origin. Only requests with a valid, unspent token reach the application. The application does not implement cryptography or replay storage.
- **An optional scope** that the operator configures binds tokens to one resource, such as a ballot or pool identifier. A token obtained for one resource cannot be spent on another.
- **The browser client** uses code from the demo to obtain a challenge, request a token with an admission code, and redeem it at the protected URL.
- **The server helper** requests admission codes from the Issuer.

The browser and server packages are in this repository. They are not published while release publishing is blocked.

## Application demand would justify other admission models

Freebird does not plan to implement these models unless an application needs them:

- **Issuer-to-issuer admission** would let one Issuer act as an Origin for another Issuer's tokens and exchange each token for one local admission. An application that trusts another community can usually request codes on its behalf.
- **Trust in multiple Issuers** would let one Origin accept tokens from more than one Issuer. A single Issuer can serve many independent applications.

## Two proposals have no implementation commitment

Neither of these options is committed:

- **Memory-hard proof-of-work** with Argon2id or scrypt would reduce the advantage of GPUs but require WebAssembly and a less restrictive browser security policy.
- **Post-quantum tokens** would require a standard successor to RSA blind signatures.
