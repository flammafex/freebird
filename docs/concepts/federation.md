# Federation and Discovery

Freebird currently implements issuer-to-verifier metadata discovery.

## Implemented trust relationships

The verifier periodically fetches configured issuer metadata. `ISSUER_URL` or
`ISSUER_URLS` are normalized to `GET /.well-known/keys` for strict V7
discovery. The complete V7 container is validated before its direct and
retained key bindings, policies, and optional V7 exchange/graph descriptors
enter the verifier trust snapshot.

V4 has a separate authority-only metadata path,
`GET /.well-known/replay-authority`, and an operator-controlled probe at
`POST /v1/public/graph/replay-authority/probe`. A graph participant can use
these to attest that the verifier and issuer are using the intended replay
authority. These paths do not provide V7 keys.

With `REQUIRE_TLS=true`, configured issuer URLs must use HTTPS. Discovery
metadata is therefore part of the deployment trust boundary and must be
protected like other service traffic.

## Not implemented

There is no claim of cross-operator issuer discovery, common federation
membership, standardized policy exchange, or RFC-level protocol
interoperability. Such federation is future/maintainer-review material.

See [trust boundaries](../architecture/trust-boundaries.md), the [threat
model](../threat-model.md), and [production deployment](../production-deployment.md).
