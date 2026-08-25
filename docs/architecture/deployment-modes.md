# Deployment Modes

## Direct development

Local source runs may use HTTP and in-memory replay only when explicitly marked
development. A representative verifier configuration is:

```bash
VERIFIER_ENV=development
IN_MEMORY_REPLAY_STORE=true
REQUIRE_TLS=false
```

This mode is not restart-safe and must not be used for public, exchange, graph,
or multi-instance deployments. Docker Compose is a direct-development probe;
it does not provide the trusted production proxy boundary.

## Production direct services behind a proxy

The expected production shape is issuer and verifier behind an independently
managed HTTPS reverse proxy, with durable Redis and persistent key/config
storage:

```bash
REQUIRE_TLS=true
BEHIND_PROXY=true
TRUSTED_PROXY_CIDRS=<reverse-proxy-CIDR>
VERIFIER_ENV=production
IN_MEMORY_REPLAY_STORE=false
REDIS_URL=redis://redis:6379
SYBIL_REPLAY_STORE=redis
```

`BEHIND_PROXY=true` is safe only when the proxy and trusted CIDRs are correctly
configured. Admin routes need network controls as well as `ADMIN_API_KEY`.

## Optional V7 durable operations

V7 exchange and graph issuance add Redis-backed operation authority, immutable
discovery/history, receipt keys, and retention obligations. Participating
services must share the exact Redis logical database and restore Redis,
discovery, signers, and history as one recovery unit.

## Not a deployment mode

There is no current interoperable federation mode. Multiple issuer URLs express
configured discovery/trust relationships; they do not establish a common
federation protocol. Future federation profiles require maintainer review.

Use the [production deployment guide](../production-deployment.md) and [threat
model](../threat-model.md) for the security checklist rather than treating this
page as a complete hardening guide.
