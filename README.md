# Freebird

Anonymous authorization infrastructure built on VOPRFs (Verifiable Oblivious Pseudorandom Functions). Freebird lets you prove authorization without revealing identity, enabling rate limiting, access control, and Sybil resistance without tracking users.

- **Issuer**: mints unlinkable tokens.
- **Verifier**: validates tokens and enforces replay protection.
- **SDK**: TypeScript client for browser/Node integrations.
- **Admin UI + API**: operational control for keys, users, and Sybil policies.

## Contents

- [Quick start (Docker)](#quick-start-docker)
- [Local build](#local-build)
- [Configuration](#configuration)
- [Admin UI](#admin-ui)
- [SDK usage](#sdk-usage)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [Security model](#security-model)
- [License](#license)

## Quick start (Docker)

```bash
git clone https://github.com/yourusername/freebird.git
cd freebird
cp .env.example .env

docker compose up --build
```

Freebird starts three services:

- **Issuer**: http://localhost:8081
- **Verifier**: http://localhost:8082
- **Admin UI**: http://localhost:8081/admin (uses `ADMIN_API_KEY`)

Verify the issuer is online:

```bash
curl http://localhost:8081/.well-known/issuer
```

## Local build

```bash
cargo build --release

# Terminal 1
./target/release/issuer

# Terminal 2
./target/release/verifier

# Terminal 3 (development client)
./target/release/interface
```

## Configuration

Freebird is configured through environment variables (Docker reads `.env`). The full reference lives in `.env.example` and the docs:

- [Configuration reference](docs/CONFIGURATION.md)
- [Production guide](docs/PRODUCTION.md)
- [Key management](docs/KEY_MANAGEMENT.md)

Common settings:

| Variable | Purpose |
| --- | --- |
| `ISSUER_ID` | Identifier for the issuer instance |
| `ISSUER_BIND_ADDR` / `VERIFIER_BIND_ADDR` | Listen addresses for issuer/verifier |
| `ISSUER_URL` | Issuer metadata URL for verifiers |
| `ADMIN_API_KEY` | Required for Admin UI/API access |
| `SYBIL_RESISTANCE` | Sybil mechanism (`invitation`, `pow`, `webauthn`, etc.) |
| `REDIS_URL` | Verifier replay-cache backend |

## Admin UI

The admin dashboard is a static single-page app served directly by the binaries (no build step). It auto-detects whether it is connected to an issuer or verifier.

- Issuer dashboard: `http://localhost:8081/admin`
- Verifier dashboard: `http://localhost:8082/admin`

See [admin-ui/README.md](admin-ui/README.md) for details.

## SDK usage

```bash
npm install @freebird/sdk
```

```ts
import { FreebirdClient } from '@freebird/sdk';

const client = new FreebirdClient({
  issuerUrl: 'https://issuer.example.com',
  verifierUrl: 'https://verifier.example.com',
});

await client.init();
const token = await client.issueToken();
const isValid = await client.verifyToken(token);
```

Full SDK docs live in [docs/SDK.md](docs/SDK.md).

## Architecture

```text
┌─────────┐                    ┌─────────┐                    ┌──────────┐
│  User   │                    │ Issuer  │                    │ Verifier │
└────┬────┘                    └────┬────┘                    └────┬─────┘
     │  1. Blind(input)             │                              │
     ├──────────────────────────────►                              │
     │  2. Evaluate(blinded) + DLEQ │                              │
     ◄──────────────────────────────┤                              │
     │  3. Finalize → token         │                              │
     │  4. Present token            │                              │
     ├──────────────────────────────┼──────────────────────────────►
     │  5. ✓ Authorized              │                              │
     ◄──────────────────────────────┼───────────────────────────────
```

For a protocol walkthrough, see [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

## Documentation

- [Quick start guide](docs/QUICKSTART.md)
- [API reference](docs/API.md)
- [Admin API](docs/ADMIN_API.md)
- [Sybil resistance](docs/SYBIL_RESISTANCE.md)
- [Security model](docs/SECURITY.md)
- [Full documentation index](docs/INDEX.md)

## Security model

Freebird provides unlinkability via VOPRFs, supports key rotation, and protects against replay with nullifiers. Review the threat model and operational guidance:

- [Security model](docs/SECURITY.md)
- [Production checklist](docs/PRODUCTION.md)

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
