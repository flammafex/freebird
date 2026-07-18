# Public bearer exchange

The optional exchange atomically spends valid single-use V5 public bearer
artifacts and produces caller-blinded V5 outputs under a locally approved rule.
It is disabled by default. Enable it only with a reviewed immutable profile,
isolated target and receipt keys, and the durable Redis topology below.

## Configuration and key isolation

```bash
PUBLIC_BEARER_EXCHANGE_ENABLE=true
PUBLIC_BEARER_EXCHANGE_REDIS_URL=redis://redis:6379
PUBLIC_BEARER_EXCHANGE_PROFILE_PATH=/data/config/public-bearer-exchange-profile.json
PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_KEY_PATH=/data/keys/exchange-receipt-active.key
PUBLIC_BEARER_EXCHANGE_RETAINED_PROFILE_PATHS=/data/config/exchange-profile-previous.json
PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_KEY_PATHS=/data/keys/exchange-receipt-previous.key
PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH=/data/config/exchange-public-history.json
PUBLIC_BEARER_EXCHANGE_RECEIPT_LIFETIME=1d
PUBLIC_BEARER_EXCHANGE_MAX_BODY_BYTES=3145728
PUBLIC_BEARER_EXCHANGE_TIMEOUT=30s
```

`PUBLIC_BEARER_EXCHANGE_RECEIPT_KEY_PATH` remains a deprecated alias for the
active receipt key. Comma-separate multiple retained profile or receipt-key
paths.

The profile is strict JSON using
`freebird/public-bearer-exchange/v1`. It contains:

- a source-descriptor allowlist;
- one ordered target keyset with one private RSA key path per target; and
- immutable rules with ordered source and output slots, classes, and quantities.

Descriptors use canonical IDs, bounded ASCII identifiers, canonical SPKI and
SHA-256 key IDs, explicit validity and audience policy, and the exact
`RSABSSA-SHA384-PSS-Deterministic` suite. The target keyset and rules also have
canonical IDs derived from their ordered members. See
[`docs/examples/public-bearer-exchange-profile.json`](examples/public-bearer-exchange-profile.json)
for the configuration shape. Its tiny placeholder SPKIs and private-key path are
documentation values, not deployable key material; replace them and recompute
all dependent IDs.

Exchange target RSA keys are separate from the legacy `/v1/public/issue` key.
Active, retained, and public-history targets may not reuse the legacy issuance
SPKI or key ID. A legacy key may appear as an exchange **source** descriptor so
existing V5 artifacts can be consumed, but source descriptors are never target
signers. The Ed25519 receipt key is separate from every RSA key. Private key
files must be regular `0600` files; symlinks, malformed keys, duplicate SPKIs,
and descriptor/key mismatches fail validation or startup.

## HTTP API and private operation capability

`POST /v1/public/exchange` accepts this shape:

```json
{
  "profile": "freebird/public-bearer-exchange/v1",
  "rule_id": "<64-lowercase-hex-rule-id>",
  "sources": [{
    "slot": {
      "descriptor_id": "<64-lowercase-hex>",
      "keyset_id": "<64-lowercase-hex>",
      "slot_id": "in",
      "quantity": 1
    },
    "artifact": "<canonical-base64url-v5-artifact>"
  }],
  "outputs": [{
    "slot": {
      "descriptor_id": "<64-lowercase-hex>",
      "keyset_id": "<64-lowercase-hex>",
      "slot_id": "out",
      "quantity": 1
    },
    "blinded_value": "<canonical-base64url-rfc9474-blinded-message>"
  }]
}
```

`GET /v1/public/exchange/status` is the only status route. It has no operation
path segment and accepts no operation query parameter. Both routes require
exactly one `Idempotency-Key` header containing canonical unpadded base64url for
16 cryptographically random bytes.

The operation ID is a private capability. Never put it in a URL, query string,
access log, tracing field, analytics event, referrer, crash report, or support
ticket. Store it with the exact request in client-protected state. Intermediaries
must preserve one header value and must not cache responses.

The TypeScript SDK exposes `client.exchange(request, operationId)` and
`client.getExchangeStatus(operationId, originalRequest)`. The original request
in the status call is used only to bind and validate a committed response; it is
not sent in the GET request.

## Results, retries, and recovery

A committed response is stored and returned byte-for-byte on later POST or
status retries:

```json
{
  "result": {
    "operation_id": "<operation-capability>",
    "profile": "freebird/public-bearer-exchange/v1",
    "target_keyset_id": "<64-lowercase-hex>",
    "outputs": [{
      "slot": { "descriptor_id": "<id>", "keyset_id": "<id>", "slot_id": "out", "quantity": 1 },
      "blinded_value": "<original-blinded-value>",
      "blind_signature": "<canonical-base64url-blind-signature>"
    }],
    "result_digest": "<canonical-base64url-32-byte-digest>"
  },
  "receipt": {
    "operation_id": "<operation-capability>",
    "profile": "freebird/public-bearer-exchange/v1",
    "target_keyset_id": "<same-keyset-id>",
    "result_digest": "<same-result-digest>",
    "created_at": 1700000000,
    "expires_at": 1700086400,
    "receipt_key_id": "<64-lowercase-hex>",
    "signature": "<canonical-base64url-64-byte-ed25519-signature>"
  }
}
```

All responses include `Cache-Control: no-store`. Outcomes are:

| Route | Status | Body or meaning |
| --- | --- | --- |
| POST/status | 200 | original stored result and receipt bytes |
| POST/status | 202 | `{"error":"exchange_retryable"}` and `Retry-After` |
| POST | 409 | `{"error":"operation_conflict"}` when the capability is reused with a different request |
| status | 404 | `{"error":"unknown_operation"}` |
| POST | 400 | generic invalid capability, request, artifact, or exchange error |
| POST/status | 503 | `{"error":"exchange_unavailable"}` |

After timeout or connection loss, retry POST with the same capability and the
exact same request. Do not generate a new operation ID: the first request may
already have spent its sources. A 202 means durable work is pending or being
recovered; wait for `Retry-After`, then retry POST or use the fixed status route.
The operation ledger recovers reserved and result-ready work and commits the
response atomically with source spends. A missing retained signer keeps recovery
retryable and never releases a source spend.

Clients must bind a 200 response back to the submitted operation ID and request:
check both operation IDs, profiles, keysets, result digests, ordered output slots
and blinded values, and all canonical encodings before finalizing signatures.

## Discovery, receipts, and public history

`/.well-known/keys` retains the legacy `public` array and optionally adds an
`exchange` object containing:

- canonical ordered `target_keysets`;
- purpose-tagged `exchange_source` and `exchange_target` descriptors; and
- `receipt_keys` with key ID, `algorithm=Ed25519`, active/retained purpose,
  canonical public key bytes, and validity bounds.

Legacy issuance continues to select only `public`; exchange targets are not
available through `/v1/public/issue`. Verifiers trust only validated
`exchange_target` descriptors.

To verify a receipt, select the discovery entry whose `key_id` exactly equals
`receipt_key_id`, require the Ed25519 algorithm, purpose, and validity interval,
reconstruct the protocol's canonical receipt payload and domain-separated
signing digest, decode the canonical 64-byte signature, and verify it with the
published Ed25519 key. Also require the receipt operation ID, profile, target
keyset, and result digest to equal the accepted result.

`PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH` is strict public-only JSON with
`target_keysets`, `target_descriptors`, and `receipt_keys`. It contains SPKIs and
verification keys only—never RSA private paths, RSA private keys, or receipt
seeds. See
[`public-bearer-exchange-public-history.schema.json`](examples/public-bearer-exchange-public-history.schema.json)
for its JSON shape. Canonical graph IDs, SPKI-derived identities, issuer binding,
key isolation, and expiry are additionally enforced by Freebird.

Private and public retention answer different questions:

1. Keep active/retained private target profiles and receipt seeds configured
   while any durable pending-reference counter names them.
2. Once counters reach zero, first copy their public target descriptors,
   keysets, and receipt verification keys into public history.
3. Only then remove the private signer.
4. Keep public history published until every corresponding output artifact and
   receipt has expired, even though no pending operation needs the private key.

## Redis durability

`PUBLIC_BEARER_EXCHANGE_REDIS_URL` must select the same Redis database used for
V5 nullifier/spend enforcement by every participating verifier. It is
authoritative security state, not a cache. The supported topology is one
standalone writable master with:

```text
role:master
appendonly yes
appendfsync always
maxmemory-policy noeviction
AOF enabled and aof_last_write_status:ok
cluster_enabled:0
```

Redis Cluster, replicas used as the writable endpoint, asynchronous AOF,
RDB-only durability, eviction, and failover that can lose acknowledged writes
are unsupported. Startup and readiness fail closed on topology, AOF health,
connectivity, or signer-pin failures. Redis or AOF rollback can resurrect spent
artifacts or lose committed responses; treat it as a security incident. Back up
and restore Redis, profiles, signer keys, and public history as one coherent
recovery unit. See [Backup and Restore](backup-restore.md).
