# Gate 0 private fixture handoff (G0.2)

This document freezes the local-only handoff between the ignored Rust fixture
generator and a later G0.2 supervisor. It describes interface expectations; it
does not implement or authorize that supervisor, start services, or provide
evidence that any service is healthy. The generated `manifest.json` is public
pin input. Everything else in the retained run directory is private.

## Run directory and retained output

The caller supplies an existing, empty, absolute, nonsymlink run directory
with mode `0700`. The generator writes directly into it and does not
automatically delete it. All files/directories remain beneath that private
root: directories are `0700`, files are `0600`. Reject symlinks, unexpected
file types, permissions, paths escaping the root, duplicate JSON members,
unknown fields, and NUL-containing values. Never follow or trust a path from a
fixture file until it has been checked as a closed basename within this root.
Never `source`/shell-evaluate an environment file.

The fixed retained layout is:

```text
run-dir/
  manifest.json
  fixture.private.json
  issuer.env.json
  verifier.env.json
  v4.key
  v7-direct.der
  v7-direct.json
  v7-exchange-source.der
  v7-exchange-source.json
  v7-exchange-target.der
  v7-exchange-target.json
  v7-registry.json
  v7-extra-signers.json
  exchange.json
  graph.json
  receipt.key
  receipt.json
  runtime/
    issuer/
    verifier/
    redis/
  logs/
```

The Rust generator writes `fixture.private.json` **last**, after native signer
and registry configuration, offline config, the G0.1 public manifest, and
strict SDK validation have succeeded. Its closed v1 JSON object has exactly
these fields and values/shapes:

```json
{
  "version": "freebird/gate0-private-fixture/v1",
  "run_id": "<same public manifest run_id>",
  "manifest_file": "manifest.json",
  "manifest_sha256_hex": "<lowercase SHA-256 of exact manifest.json bytes>",
  "issuer_env_file": "issuer.env.json",
  "verifier_env_file": "verifier.env.json",
  "redis": {
    "host": "127.0.0.1",
    "port": 23456,
    "database": 0
  }
}
```

The hash is of the exact public manifest bytes, not parsed/re-serialized JSON.
The `redis` object is closed and has exactly `host`, `port`, and `database`;
the host is the literal loopback address, the port is the generator-selected
high port, and database is integer zero. Both service `REDIS_URL` values must
be derived from these fields as `redis://127.0.0.1:<port>/0`. Do not accept an
arbitrary Redis URL or any other host/database.

Each private environment file is a closed JSON envelope with exactly:

```json
{
  "version": "freebird/gate0-private-env/v1",
  "run_id": "<same run_id>",
  "role": "issuer",
  "env": { "NAME": "string value" }
}
```

The verifier file has `role: "verifier"`; filenames and roles must agree.
Every `env` member value is a JSON string, including booleans, numbers, and
serialized configuration. Reject a value of any other JSON type. Apply the
exact role-specific NAME allowlists below; reject unknown/missing required
names, duplicate members, NULs, and embedded paths outside `run-dir/`. Resolve
all private file and directory paths relative to the checked root. Keep private
files at `0600`; never print their values.

Secret-bearing `NATIVE_V7_SIGNER_CONFIG_PATHS` targets, V4 keyrings, and other
JSON-valued env settings are **JSON text** in the environment string. Raw
secret byte values inside those JSON objects use canonical base64url as
specified by their native config format. Do not base64url-encode the entire
JSON document. The secret source files and envelope remain mode `0600`.

## Exact issuer environment allowlist

The issuer `env` object may contain only the following names. Required values
are fixed where shown; all other values are generator-provided strings derived
from the run directory and local pinned config.

```text
BIND_ADDR
ISSUER_ID
ADMIN_API_KEY
FREEBIRD_ENV=production
FREEBIRD_UNSAFE_DEVELOPMENT_MODE=false
ALLOW_UNSAFE_V4_ROTATION=false
REQUIRE_TLS=false
BEHIND_PROXY=false
HSM_ENABLE=false
ISSUER_SK_PATH
KEY_ROTATION_STATE_PATH
AUDIT_LOG_PATH
NATIVE_BEARER_V7_ENABLE=true
NATIVE_BEARER_V7_SK_PATH
NATIVE_BEARER_V7_METADATA_PATH
NATIVE_BEARER_V7_REGISTRY_PATH
NATIVE_BEARER_V7_PROFILE_ID
NATIVE_BEARER_V7_DESCRIPTOR_ID
NATIVE_BEARER_V7_TOKEN_KEY_ID
NATIVE_BEARER_V7_ASSET_ID
NATIVE_BEARER_V7_AMOUNT_MINOR
NATIVE_BEARER_V7_VALIDITY
NATIVE_V7_SIGNER_CONFIG_PATHS
NATIVE_EXCHANGE_V7_ENABLE=true
NATIVE_EXCHANGE_V7_DISCOVERY_PATH
NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_KEY_PATH
NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_METADATA_PATH
NATIVE_EXCHANGE_V7_REDIS_URL
NATIVE_EXCHANGE_V7_RECEIPT_LIFETIME=2592000
NATIVE_GRAPH_ISSUANCE_V7_ENABLE=true
NATIVE_GRAPH_ISSUANCE_V7_POLICY_PATH
NATIVE_GRAPH_ISSUANCE_V7_AUTHORIZATION=v4_local
NATIVE_GRAPH_ISSUANCE_V7_VERIFIER_ID
NATIVE_GRAPH_ISSUANCE_V7_AUDIENCE
NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64
SYBIL_REPLAY_STORE=redis
SYBIL_REPLAY_REDIS_URL
SYBIL_RESISTANCE=pow
SYBIL_POW_DIFFICULTY=8
SYBIL_PROGRESSIVE_TRUST_SALT
SYBIL_PROOF_OF_DIVERSITY_SALT
SYBIL_MULTI_PARTY_VOUCHING_SALT
```

The `NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64` name is historical: its value
is JSON text, not base64 of JSON. It contains issuer → KID → base64url raw32
secret mappings. `NATIVE_V7_SIGNER_CONFIG_PATHS` is a comma-separated list of
checked JSON paths under this run root. Do not add a KID override or arbitrary
Redis URL. `SYBIL_REPLAY_STORE` must explicitly select `redis`, never its
memory default. `SYBIL_REPLAY_REDIS_URL` must be byte-for-byte identical to
`NATIVE_EXCHANGE_V7_REDIS_URL` and `REDIS_URL` in the verifier envelope: the
same generated `redis://127.0.0.1:<owned-port>/0` target. The offline generator
constructs the configured replay backend but does not connect to Redis; the
supervisor owns all service and Redis process interaction.

## Exact verifier environment allowlist

The verifier `env` object may contain only these names:

```text
BIND_ADDR
ADMIN_API_KEY
VERIFIER_ENV=production
VERIFIER_ALLOW_UNSAFE=false
IN_MEMORY_REPLAY_STORE=false
REDIS_URL
VERIFIER_ACCEPTED_TOKEN_VERSIONS=v4,v7
ISSUER_URLS
VERIFIER_KEYRING_B64
VERIFIER_ID
VERIFIER_AUDIENCE
VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS
REFRESH_INTERVAL_MIN=1
VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL=2s
VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS=10s
REQUIRE_TLS=false
BEHIND_PROXY=false
```

`VERIFIER_KEYRING_B64`, like the issuer keyring setting, carries JSON text with
base64url raw32 secret values, not base64url-encoded whole JSON. `ISSUER_URLS`
must be exactly `<issuer_origin>/.well-known/issuer`, which the verifier fetches
directly. `VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS` instead contains the bare pinned
issuer origin. The verifier, exchange, and Sybil replay Redis URLs must identify
the exact same loopback Redis DB 0 from the private marker. They are never
accepted as general-purpose external URLs.

## Public/private boundary and later supervisor scope

`manifest.json` is the only fixture file a downstream public-manifest
consumer receives. It contains public V4, V7 discovery, receipt and replay
authority pins plus origins/run metadata. It must not contain or be supplemented
with private V4/RSA/receipt keys, Redis data/credentials, admin keys, holder
seeds/credentials, wallet secrets, status capabilities, blinding inverses,
bearer artifacts, or other private material. The later Scarcity lane receives
only this public manifest and creates its own private holder/wallet workspace.

The locally provisioned replay authority ID is raw32. A later supervisor must
seed those raw32 bytes directly into the owned Redis key with `SET ... NX` and
read back/compare the bytes before either service starts; it must not seed
base64 text, permit issuer random fallback, overwrite an existing key, or use
`FLUSHDB`. After the ID is seeded, normal issuer initialization must install
and validate the pinned scope tombstone; the supervisor must not treat either
setup action as proof of shared replay health. This is supervisor behavior,
not a generator or SDK-adapter feature.

The fixture uses bounded real proof-of-work admission (`pow`, difficulty 8),
not `none`, an insecure fallback, or development mode. V4 requests must prove
genuine timestamped nonce-of-work bound to the actual request. The verifier's
replay-authority probe is required evidence that both processes observe the
same Redis-backed V4 authority and scope tombstone; matching URL strings or
discovery metadata alone are not proof. Probe only the configured issuer,
verifier, and owned loopback Redis resources, with bounded readiness/deadlines
and cleanup. These PoW and probe requirements concern the later separately
supervised live gate and do not make this offline SDK adapter a live HTTP trust
test.

The SDK adapter at `sdk/js/tests/gate0-fixture.test.ts` is explicitly opt-in via
`FREEBIRD_GATE0_DIRECTORY`. Without the variable it is skipped in the default
SDK suite. With it set, it reads only `manifest.json` from the retained private
root and must run/fail rather than skip when input is absent or invalid. It
constructs an offline strict V7 discovery envelope from the public issuer/V4
identity and the exact four `discovery_pins` projections, adding only synthetic
test epochs. Strict `parseV7KeyDiscovery` and `materializeV7Registry` validate
native identities and role links. This is offline SDK acceptance only; it does
not establish HTTP pin matching, V4 issuance, graph replay rejection, Redis
sharing, artifact verification, service health, or the no-fallback live Gate 0.
