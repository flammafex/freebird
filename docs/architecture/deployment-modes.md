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

### Compose quickstart and Redis network

Copy `.env.example` to `.env`, configure the admin key and a fresh 64-character
lowercase hexadecimal `NATIVE_BEARER_V7_TOKEN_KEY_ID`, then run:

```bash
docker compose config --quiet
docker compose up -d --build --wait
```

Compose keeps Redis on TCP port 6379 with its existing AOF configuration and
named data volume. It assigns Redis `REDIS_IPV4` (default `172.30.84.10`) on
`FREEBIRD_SUBNET` (default `172.30.84.0/24`). Only the issuer's
`SYBIL_REPLAY_REDIS_URL` is derived from that address: replay admission rejects
hostname endpoints to avoid unbounded DNS work. Verifier `REDIS_URL`, exchange,
WebAuthn, and other Redis consumers continue using the `redis` service hostname.
This local Compose Redis remains internal and unauthenticated; this change does
not add a production authentication or proxy boundary.

If the subnet conflicts with your LAN, VPN, or another Docker network, set both
values in `.env` to an unused private range and a host address within it, for
example `FREEBIRD_SUBNET=172.30.85.0/24` and `REDIS_IPV4=172.30.85.10`. Do not use
the subnet, broadcast, or gateway address. Keep the same Compose project name
so its existing named volumes are reused.

**Existing installations:** preserve your secrets, token key ID, and other
settings; do not replace `.env` wholesale. Add the two network settings and
remove the old `SYBIL_REPLAY_REDIS_URL=redis://redis:6379` entry. Compose sets that
variable explicitly from `REDIS_IPV4`, overriding stale env-file values. Do not
rewrite other Redis URLs. When introducing or changing IPAM settings, schedule
a brief outage for all Compose consumers and recreate the network without
removing volumes:

```bash
# From the same project directory, with the same project name as before:
docker compose down          # no --volumes / -v; keep issuer-data and redis-data
# Update .env network settings as described above.
docker compose config --quiet
docker compose up -d --build --wait
```

Do not prune volumes or delete persisted keys/replay state to resolve a network
conflict. Outside Compose, explicitly set `SYBIL_REPLAY_REDIS_URL` to your
reachable numeric Redis endpoint, including its existing credentials/database;
the other Redis consumers may still use DNS.

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
SYBIL_REPLAY_REDIS_URL=redis://<numeric-Redis-address>:6379
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
