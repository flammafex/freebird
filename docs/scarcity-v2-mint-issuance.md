# Scarcity V2 mint issuance contract

**Contract:** `scarcity/freebird-mint-issuance/v2`
**Status:** additive contract; implementation and cryptographic audit pending
**Compatibility:** this document does not change Freebird V1, V4, or V5

This contract is the Freebird-side issuance admission boundary for Scarcity V2.
Freebird authorizes an issuer mint request and returns an opaque randomized
blind-RSA credential envelope. Scarcity owns the economic note, keyset binding,
and final structural validation. Freebird MUST NOT put a credential, quota
counter, client binding, or admission assertion into a Scarcity note or receipt.

## 1. Fixed public profile

The profile identifier is exactly `scarcity/freebird-mint-issuance/v2`.

All digests use the shared Scarcity profile:

```text
H(label, bytes) = SHA-256(ASCII("scarcity/v2/" || label || "\0") || bytes)
C(value) = RFC 8949 deterministic, restricted Scarcity V2 CBOR
```

The request and response identify one published Scarcity `RSAKeyset` and never
carry an embedded asset descriptor or authority record. The keyset metadata is
public and exact:

```text
{
  issuer_id: bytes(32),
  keyset_id: bytes(32),
  asset_id: bytes(32),
  spend_domain: bytes(32),
  denomination: uint64 (> 0),
  issuance_epoch: uint64,
  expiry_epoch: uint64,
  modulus: bytes(384),
  public_exponent: 65537,
  suite: "RSABSSA-SHA384-PSS-Randomized",
  authority_key_id: bytes(32)
}
```

`keyset_id` is `H("rsa-keyset", C(RSAKeysetIdentity))`, where the identity is
the preceding map without `keyset_id` and authority signatures. The issuer
publishes the raw modulus and exponent metadata; it does not publish private
RSA factors or a signing secret.

## 2. Request and digest projections

The endpoint is:

```http
POST /v2/scarcity/mint/issue
Content-Type: application/cbor
Accept: application/cbor
```

The request body is the canonical CBOR encoding of this exact unsigned core:

```text
MintRequestCore = {
  version: 2,
  issuer_id: bytes(32),
  keyset_id: bytes(32),
  request_id: bytes(32),
  client_binding: bytes(32),
  blinded_message: bytes,
  blinded_message_digest: bytes(32),
  retry_attempt: uint64,
  requested_at_epoch: uint64,
  request_expiry_epoch: uint64
}
```

The client binding is an ephemeral public binding value, not a wallet identity.
`blinded_message` is the RFC 9474 blinded message and
`blinded_message_digest = H("mint-blinded-message", blinded_message)`.
The request carries no owner material, replay nonce, RSA blinding factor, or
prepared message. Those remain wallet-private. The request digest is exactly the
next link in the one-way chain:

```text
mint_request_digest = H("mint-request", C(MintRequestCore))
```

The admission input presented to the configured Freebird admission policy is:

```text
MintAdmissionCore = {
  profile: "scarcity/freebird-mint-issuance/v2",
  issuer_id: bytes(32),
  keyset_id: bytes(32),
  request_id: bytes(32),
  mint_request_digest: bytes(32),
  client_binding: bytes(32),
  blinded_message_digest: bytes(32),
  request_expiry_epoch: uint64,
  retry_attempt: uint64
}
```

The admission assertion binding is exactly
`admission_assertion_binding = H("mint-admission", C(MintAdmissionCore))`.
The assertion signs/binds that resulting value, but neither `MintRequestCore`
nor `MintAdmissionCore` contains it. Thus the only dependency chain is
`blinded_message -> blinded_message_digest -> mint_request_digest ->
admission_assertion_binding`; no structure contains its own resulting digest or
any circular digest reference. Admission is the issuer-configured `mint-request` scope. A deployment MAY disable this scope only
through explicit issuer policy; an absent or failed configured admission is
fail-closed. The admission credential itself is never returned as a Scarcity
credential and is never included in shared fixtures.

## 3. Response and finalized credential envelope

A successful response is canonical CBOR with this exact public response. The
only credential-bearing value returned by Freebird is the RFC 9474 blind
signature; there is no finalized credential envelope in the response:

```text
MintIssueResponse = {
  profile: "scarcity/freebird-mint-issuance/v2",
  request_id: bytes(32),
  mint_request_digest: bytes(32),
  issuer_id: bytes(32),
  keyset_id: bytes(32),
  denomination: uint64,
  issuance_epoch: uint64,
  expiry_epoch: uint64,
  modulus: bytes(384),
  public_exponent: 65537,
  suite: "RSABSSA-SHA384-PSS-Randomized",
  blind_signature: bytes(384)
}
```

The finalized credential is wallet-local and is not a Freebird response. For
public transcript vectors only, its envelope has this shape:

```text
FinalizedMintCredential = {
  version: 2,
  suite: "RSABSSA-SHA384-PSS-Randomized",
  keyset_id: bytes(32),
  message_randomizer: bytes(32),
  signature: bytes(384)
}
```

The wallet creates this envelope locally by unblinding the returned
`blind_signature` with its private RFC 9474 state. `signature` is the resulting
signature over the prepared canonical `MintSignatureInput`; `message_randomizer`
is the RFC 9474 public randomizer used for that finalized signature, and
`keyset_id` binds the envelope to the published keyset. The prepared message,
blinding factor, owner material, and replay nonce remain wallet-local. Public
transcript vectors MAY additionally carry those inputs as explicitly synthetic
test data, but they are not response fields.

The issuer signs the blinded RFC 9474 message after admission and reservation.
The wallet, not Freebird, retains the private blinding state, unblinds the blind
signature, and constructs the finalized Scarcity mint credential locally. The
wallet supplies the owner material and replay nonce only inside its private
prepared message; production request payloads never reveal either value.
Freebird returns one blind signature per accepted `request_id`; it does not
return a blinding factor, owner secret, RSA private key, quota ledger, admission
credential, prepared message, finalized signature, or unblinded wallet material.

## 4. Durable admission, quota, and retry state

Issuance admission is issuer-configured and denomination-weighted. A successful
reservation consumes `denomination` units from the keyset's durable quota, not
one unit per request. Reservation and finalization are durable and keyed by the
tuple `(issuer_id, keyset_id, request_id)`.

The state machine is:

```text
absent -> reserved -> issued
       \-> rejected
reserved -> retryable (issuer restart/transport loss)
retryable -> reserved | issued | expired
```

The same request digest and client binding MAY retry an existing reservation and
receives the same finalized response after `issued`. A different digest,
keyset, binding, or payload for an existing `request_id` is a conflict and MUST
NOT consume additional quota. Quota is released only for an expired or
explicitly rejected reservation; an `issued` reservation is never replayed into
a second credential.

The issuer clock is UTC. `issuer_epoch = floor(unix_seconds / 3600)` and all
request, keyset, and recovery comparisons use that clock rather than local wall
time. Retry reservations recover for exactly 24 hours (86,400 seconds) from the
durable reservation timestamp. After that interval the reservation becomes
`expired` and a new request ID is required. Recovery MUST be idempotent across
issuer restart and MUST commit the reservation before exposing `issued`.

Stable error codes are:

```text
invalid-cbor, non-canonical, wrong-profile, unknown-keyset,
keyset-expired, request-expired, admission-required, admission-rejected,
binding-mismatch, quota-exhausted, request-conflict, reservation-expired,
already-issued, malformed-credential, internal-retryable
```

Error responses contain the code and request ID only; they MUST NOT disclose
private issuance or quota state.

## 5. Vectors and private-material boundary

Before implementation, the V2 fixture publication MUST include public-only
vectors for:

* every keyset metadata field, keyset ID, policy/asset IDs, and all digest
  projections;
* canonical request, admission, and blind-signature response bytes;
* complete public RFC 9474 transcripts containing the 32-byte message
  randomizer, prepared message, blinded message, blind signature, finalized
  signature, and an independently recomputed verification result;
* canonical bytes for `MintIssueRequestCore`, `MintAdmissionCore`, the blind
  signature response, and `FinalizedMintCredential`, plus negative mutations of
  the randomizer, signature, keyset ID, and canonical prepared payload;
* request/client-binding mutation, keyset/denomination/domain substitution,
  expiry boundary, malformed modulus/exponent/suite, quota reservation,
  retry/idempotency/conflict, restart recovery, 24-hour expiry, and
  already-issued cases;
* exact negative stage/error pairs for canonical decoding, admission, quota,
  binding, retry, and response validation.

Shared fixtures MUST contain only public CBOR, public metadata, hashes, IDs,
nullifiers, and envelope bytes explicitly classified as opaque/data-only. They
MUST NOT contain RSA private factors, blinding factors, owner secrets,
unblinded owner material, admission credentials, quota-store contents, bearer
tokens, client private keys, or service credentials. Public RFC 9474 test
vectors MAY use synthetic owner material and replay nonces, but MUST label them
explicitly as synthetic test inputs; this exception never permits either value
in a production request or response.

## 6. Experimental blind-RSA audit exception

The existing randomized blind-RSA dependency MAY be used for this V2 profile
only as an explicitly experimental adapter. Its existing audit exception does
not constitute a Freebird or Scarcity cryptographic verification claim. The
adapter MUST be isolated from V1/V4/V5 code, pinned, covered by public
byte/transcript vectors, fail closed on suite/keyset mismatch, and remain subject
to an independent audit before production issuance. No change to the existing
`crypto` primitives is authorized by this contract document.

## 7. Later implementation paths (not changed here)

The later implementation may add only scoped V2 paths:

* `issuer/src/v2/mint_issuance.rs` — request, response, envelope, and state
  types/adapters;
* `issuer/src/v2/mint_quota.rs` — durable denomination-weighted reservation and
  24-hour recovery state machine;
* `issuer/src/routes/v2_mint.rs` and `issuer/src/routes/mod.rs` — the POST route
  registration, without changing V1/V4/V5 routes;
* `issuer/tests/v2_mint_issuance.rs` and
  `integration_tests/tests/v2_mint_issuance.rs` — public vectors, admission,
  quota, retry, conflict, and recovery tests.

Those paths are implementation targets only. This contract milestone changes no
Rust code, cryptographic primitive, service, route, fixture, or shared API.
