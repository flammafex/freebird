# Native V7 bearer exchange

The optional native V7 bearer exchange atomically spends valid single-use V7
artifacts and blind-signs outputs selected by a directed transition graph. It is
disabled by default. V5 public bearer exchange is removed and rejected; V2
exchange is removed and rejected; V6 is reserved and rejected.

This is a fresh-install V7 contract. V4 private tokens remain supported
independently. The current compatibility set is V4 and V7. Do not load legacy
exchange profiles,
recover legacy operation records, or migrate legacy Redis state into the V7
authority database.

## Configuration

```bash
NATIVE_BEARER_V7_ENABLE=true
NATIVE_BEARER_V7_SK_PATH=/data/keys/native_bearer_v7.der
NATIVE_BEARER_V7_METADATA_PATH=/data/config/native_bearer_v7.json
NATIVE_BEARER_V7_REGISTRY_PATH=/data/config/native_bearer_v7_registry.json

NATIVE_EXCHANGE_V7_ENABLE=true
NATIVE_EXCHANGE_V7_REDIS_URL=redis://redis:6379/0
NATIVE_EXCHANGE_V7_DISCOVERY_PATH=/data/config/native-exchange-v7-discovery.json
NATIVE_EXCHANGE_V7_RETAINED_DISCOVERY_PATHS=/data/config/native-exchange-v7-previous.json
NATIVE_EXCHANGE_V7_PUBLIC_HISTORY_PATH=/data/config/native-exchange-v7-history.json
NATIVE_EXCHANGE_V7_DISABLED_PUBLICATION_ACK_PATHS=/data/config/native-exchange-v7-ack.json
NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_KEY_PATH=/data/keys/native-exchange-v7-receipt.key
NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_METADATA_PATH=/data/config/native-exchange-v7-receipt.json
NATIVE_EXCHANGE_V7_RETAINED_RECEIPT_KEY_PATHS=/data/keys/native-exchange-v7-previous.key
NATIVE_EXCHANGE_V7_RETAINED_RECEIPT_METADATA_PATHS=/data/config/native-exchange-v7-previous.json
NATIVE_EXCHANGE_V7_RECEIPT_LIFETIME=1d
NATIVE_EXCHANGE_V7_MAX_BODY_BYTES=3145728
NATIVE_EXCHANGE_V7_TIMEOUT=30s
```

Comma-separate retained paths. Retained receipt-key and metadata lists are
positional and must have equal counts. Discovery, history, metadata, and
acknowledgements are strict local JSON and must never be fetched at runtime.
Run `freebird-validate-config` against the same files, V7 key material, issuer
ID, and Redis database used by production.

## Directed V7 graph and lifecycle

The native V7 graph contains role-neutral descriptors, canonical ordered
keysets, directed transitions, explicit budget contracts, and admission states.
Descriptor identity commits to the V7 profile, issuer, SPKI-derived token-key
ID, suite, audience, and inclusive validity bounds. Transition and graph IDs
must be recomputed when identity-bearing content changes.

Use this lifecycle:

1. publish and review transitions as `disabled`;
2. acknowledge the reviewed graph, then move only approved transitions to
   `accepting_new`;
3. move them to `recovery_only` to stop fresh work while pending operations drain;
4. move them to `disabled` only after pending references reach zero;
5. retain public discovery/history through artifact and receipt expiry before
   retiring private signers.

Never reuse a V7 budget ID for a changed transition contract. Redis is the
authority for budgets, source spends, pending operations, committed responses,
the append-only registry, and signer-retention references.

## HTTP API

`POST /v7/public/exchange` accepts a V7 request with a public 16-byte
`public_operation_id`, canonical graph/transition/keyset selectors, V7 source
artifacts, and caller-blinded outputs. `GET
/v7/public/exchange/status?public_operation_id=...` recovers the result.

The caller generates two independent values:

- `public_operation_id`: canonical unpadded base64url for 16 random bytes; it is
  correlation only and is not authorization;
- `Exchange-Status-Capability`: canonical unpadded base64url for 32 random
  bytes, sent exactly once in the header on POST and status requests.

The capability is header-only: never put it in a body, URL, discovery document,
log, trace, or metric. Responses are `Cache-Control: no-store`. On timeout,
retry the exact POST with the same operation ID, capability, and body. A changed
body or capability is a conflict; never create a second operation after an
ambiguous response.

Receipts bind the V7 request and result digests, ordered output selectors,
receipt times, and receipt-key ID. They contain no source artifacts, body
nullifiers, spend keys, private paths, or capabilities.

## Discovery

`GET /.well-known/keys` publishes the immutable `native_bearer_v7` trust
container: active and retained V7 descriptors/keysets/transitions, active and
retained receipt verification keys, and public history. It never publishes
private signer paths or keys, receipt seeds, source artifacts, body nullifiers,
spend keys, operation records, capabilities, pending-reference counts, or live
budget counters. Consumers must validate the complete container before trusting
any V7 output.

The verifier obtains this strict V7 discovery through its configured
`ISSUER_URL` or `ISSUER_URLS`; those inputs are normalized to
`GET /.well-known/keys`. Graph-authority URLs are not an alternate key source.

The V7 verifier's replay identity is the issuer namespace plus the lowercase
hexadecimal **body nullifier**. It deliberately excludes the signature,
artifact bytes, descriptor, graph, keyset, verifier, and audience. The same body
nullifier therefore cannot be replayed under a different V7 signature.

## Redis authority and proxy

`NATIVE_EXCHANGE_V7_REDIS_URL` must reach the exact same logical database as
each participating verifier's `REDIS_URL`. The supported topology is one
standalone writable master with AOF, `appendfsync always`, and
`maxmemory-policy noeviction`; Redis Cluster, replicas as writable endpoints,
eviction, and durability that can lose acknowledged writes are unsupported.

Graph participants also require:

```bash
VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS=https://issuer.example.org
VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL=30s
VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS=60s
```

`VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS` supplies only the V4
`GET /.well-known/replay-authority` metadata used by verifier health refresh.
The fixed `POST /v1/public/graph/replay-authority/probe` route separately proves
the V4 authority relationship for participating graph verifiers. Neither graph
authority route supplies strict V7 keys; preserve the probe path and body
through the trusted HTTPS proxy and never route it through `/admin`.

Back up Redis AOF, V7 discovery/history, receipts, signers, and the V7 registry
as one recovery unit. A partial restore can resurrect spent V7 body-nullifier
identities or committed responses and is a security incident.
