# Federation and Discovery

Freebird currently implements issuer-to-verifier metadata discovery.

## Implemented trust relationships

The verifier periodically fetches configured V4 issuer metadata from
`ISSUER_URL` or `ISSUER_URLS`.

With `REQUIRE_TLS=true`, configured issuer URLs must use HTTPS. Discovery
metadata is therefore part of the deployment trust boundary and must be
protected like other service traffic.

## Not implemented

There is no claim of cross-operator issuer discovery, common federation
membership, standardized policy exchange, or RFC-level protocol
interoperability. Such federation is future/maintainer-review material.

See [trust boundaries](../architecture/trust-boundaries.md), the [threat
model](../threat-model.md), and [production deployment](../production-deployment.md).
