# Quick start

This quick start runs Freebird as a local Docker Compose development deployment.
It is **not a production deployment**: Compose binds local HTTP ports and does
not provide the trusted TLS reverse-proxy boundary, durable production storage,
or operational controls required for production. See [Production
Deployment](production-deployment.md) before deploying a public service.

## Docker Compose development flow

From the repository root, install Docker with Compose support, then run:

```bash
cp .env.example .env
# For the self-contained interface smoke test, set SYBIL_RESISTANCE=none in .env.
# Replace the .env.example V7 placeholder with a real 64-character lowercase
# hexadecimal token key ID before starting Compose.
V7_TOKEN_KEY_ID="$(openssl rand -hex 32)"
sed -i.bak "s|^NATIVE_BEARER_V7_TOKEN_KEY_ID=.*|NATIVE_BEARER_V7_TOKEN_KEY_ID=${V7_TOKEN_KEY_ID}|" .env
rm -f .env.bak
./launch.sh up
```

`launch.sh` checks prerequisites, creates `.env` when needed, can generate an
admin key, starts the images, and waits for both services to become healthy.
The default host bindings are `127.0.0.1:8081` for the issuer and
`127.0.0.1:8082` for the verifier.

Check the local services:

```bash
curl http://127.0.0.1:8081/.well-known/issuer
curl http://127.0.0.1:8082/.well-known/verifier
curl http://127.0.0.1:8082/health
```

Run the source client against the Compose services:

```bash
cargo run -p freebird-interface -- \
  --issuer-url http://127.0.0.1:8081 \
  --verifier-url http://127.0.0.1:8082
```

The expected result is one successful V4 issue-and-verify round trip. To check
replay behavior, run `cargo run -p freebird-interface -- --replay`; the second
use of the token should be rejected.

Useful lifecycle commands are:

```bash
./launch.sh status
./launch.sh logs
./launch.sh stop
```

The Compose configuration is deliberately for direct local development. Do not
expose these HTTP ports to the public internet or treat an in-memory/restarted
local service as replay-safe. The example `.env` otherwise selects invitation
admission; use a client that supplies the required proof if you retain that
setting.

## Source-only local round trip

The following path is also documented and source-backed. It uses an explicitly
unsafe development verifier replay store and disables Sybil checks only to make
the local interface exercise self-contained. Use three terminals from the
repository root.

Issuer (first run in a clean directory):

```bash
V7_TOKEN_KEY_ID="$(openssl rand -hex 32)"
ADMIN_API_KEY=local-admin-key-must-be-at-least-32-chars \
FREEBIRD_ENV=development FREEBIRD_UNSAFE_DEVELOPMENT_MODE=true \
AUDIT_LOG_PATH=audit_log.json \
BIND_ADDR=127.0.0.1:8081 ISSUER_ID=issuer:local:v4 \
ISSUER_SK_PATH=issuer_sk.bin KEY_ROTATION_STATE_PATH=key_rotation_state.json \
SYBIL_RESISTANCE=none REQUIRE_TLS=false \
NATIVE_BEARER_V7_ENABLE=true \
NATIVE_BEARER_V7_SK_PATH=native_bearer_v7.der \
NATIVE_BEARER_V7_METADATA_PATH=native_bearer_v7.json \
NATIVE_BEARER_V7_REGISTRY_PATH=native_bearer_v7_registry.json \
NATIVE_BEARER_V7_TOKEN_KEY_ID="$V7_TOKEN_KEY_ID" \
NATIVE_BEARER_V7_ASSET_ID=USD NATIVE_BEARER_V7_AMOUNT_MINOR=1 \
cargo run -p freebird-issuer --bin freebird-issuer
```

The `openssl` command supplies a real 64-character lowercase hexadecimal V7
token key ID. Keep that value, along with the generated V7 files, for later
starts. On first startup the issuer supports creating and then managing
`native_bearer_v7.der`, `native_bearer_v7.json`, and
`native_bearer_v7_registry.json`; it reuses the persisted material on restart.
Do not generate a new ID for an existing set of files. These settings are
unsafe development settings only.

Verifier:

```bash
ADMIN_API_KEY=local-admin-key-must-be-at-least-32-chars \
BIND_ADDR=127.0.0.1:8082 VERIFIER_ID=verifier:local:v4 \
VERIFIER_AUDIENCE=local VERIFIER_ACCEPTED_TOKEN_VERSIONS=v4 \
VERIFIER_ENV=development IN_MEMORY_REPLAY_STORE=true \
ISSUER_URL=http://127.0.0.1:8081/.well-known/issuer \
VERIFIER_SK_PATH=issuer_sk.bin REFRESH_INTERVAL_MIN=1 REQUIRE_TLS=false \
cargo run -p freebird-verifier --bin freebird-verifier
```

Then run `cargo run -p freebird-interface`. These settings are for local
testing only; in particular, `REQUIRE_TLS=false`, `SYBIL_RESISTANCE=none`, and
`IN_MEMORY_REPLAY_STORE=true` are not production settings.
