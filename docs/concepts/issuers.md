# Issuers

An issuer evaluates blinded client requests after applying its configured
admission policy. It publishes the public metadata that clients and verifiers
need, but it does not receive the client's unblinded V4 input.

## Implemented endpoints

The issuer currently exposes:

- `POST /v1/oprf/issue` and `/v1/oprf/issue/batch` for V4 evaluation;
- `POST /v7/native-bearer/issue` and `/v7/native-bearer/issue/batch` for V7
  blind signing;
- `GET /.well-known/issuer` for combined issuer metadata;
- `GET /.well-known/keys` for strict V7 discovery;
- `GET /.well-known/replay-authority` for V4 authority-only health metadata.

The V4 request carries a base64url blinded element and may carry a
`sybil_proof`. A configured Sybil mechanism requires a matching proof; public
issuance does not accept `RegisteredUser` as a bypass. V7 requests explicitly
select a 64-character lowercase hexadecimal `token_key_id` and carry one
canonical base64url 384-byte blinded message.

## Admission is not issuance privacy

Sybil checks run before evaluation or signing. They control access to issuance
and can use server-observed request context, such as a validated client IP and
hashed User-Agent. They do not prove global human uniqueness. See
[Sybil modes](../sybil-modes.md) for tradeoffs and replay-store configuration.

## Operator state

Issuers need persistent V4 key material and rotation state. Current V7
issuance also requires the V7 private key, metadata, and append-only registry.
Optional admission modes add their own state; WebAuthn credentials may use
Redis. Public deployments should use shared Redis for admission-proof replay
protection. See the [storage model](../architecture/storage-model.md) and
[production baseline](../production-deployment.md).

## Future / review material

Issuer discovery is a metadata trust relationship, not an interoperable
federation protocol. Cross-operator federation and standardized issuer
interchange are future work and require maintainer review.
