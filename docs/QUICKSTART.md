# Quick Start

Get Freebird running quickly with Docker, or build locally if you need to hack on the binaries.

## Prerequisites

- **Docker + Docker Compose** (recommended)
- **Rust 1.70+** (for local builds)
- **Redis** (optional for dev, required for production replay protection)

## Docker quick start (recommended)

```bash
git clone https://github.com/yourusername/freebird.git
cd freebird
cp .env.example .env

docker compose up --build
```

Services:

- **Issuer**: http://localhost:8081
- **Verifier**: http://localhost:8082
- **Admin UI**: http://localhost:8081/admin

Verify the issuer is healthy:

```bash
curl http://localhost:8081/.well-known/issuer
```

## Local build

```bash
cargo build --release
```

Run the issuer and verifier in separate terminals:

```bash
./target/release/issuer
./target/release/verifier
```

Use the development client to validate the flow:

```bash
./target/release/interface
```

## Invitation-backed issuance (optional)

Enable the invitation system to gate issuance:

```bash
export SYBIL_RESISTANCE=invitation
export SYBIL_INVITE_BOOTSTRAP_USERS=admin:100
export ADMIN_API_KEY=my-super-secure-admin-key-at-least-32-chars

./target/release/issuer
```

Check admin stats:

```bash
curl http://localhost:8081/admin/stats \
  -H "X-Admin-Key: my-super-secure-admin-key-at-least-32-chars"
```

## Next steps

- [Configuration reference](CONFIGURATION.md)
- [Production guide](PRODUCTION.md)
- [API reference](API.md)
- [SDK guide](SDK.md)
- [Troubleshooting](TROUBLESHOOTING.md)
