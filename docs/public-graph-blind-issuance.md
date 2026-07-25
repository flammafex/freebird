# Policy-authorized graph blind issuance V1

Graph blind issuance creates a new blinded V5 bearer artifact under one
explicit descriptor in the active V2 exchange graph. It is a separate protocol:
it consumes no source artifact, creates no exchange receipt, and never charges
an exchange transition budget or source spend key.

## Configuration

Enable V2 graph configuration first, then configure:

```bash
PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE=true
PUBLIC_BEARER_GRAPH_ISSUANCE_POLICY_PATH=/data/config/graph-issuance-policy-v1.json
PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION=hmac_sha256
PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64=<base64url-32-or-more-random-bytes>
```

There is no permissive production default. `development_mock` is accepted only
when all three development fences documented in `.env.example` are enabled.
The HMAC verifier is an implementation of the generic
`GraphIssuanceAuthorizer` interface; deployments may add an explicit adapter to
an admission/Sybil verifier without changing the issuance/store protocol.

The approved `v4_local` verifier accepts canonical base64url V4 token bytes in
the existing opaque `authorization` field. It locally invokes the same shared
V4 parser, scope check, private authenticator verification, nullifier derivation,
and replay-key constructor as an ordinary verifier. It never composes
`/v1/check` and `/v1/verify`.

```bash
PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION=v4_local
PUBLIC_BEARER_GRAPH_ISSUANCE_V4_REPLAY_REDIS_URL=redis://redis:6379/0
PUBLIC_BEARER_GRAPH_ISSUANCE_V4_KEYRING_B64='{"issuer:example":{"kid-example":"<base64url-secret-key>"}}'
```

The V4 replay URL must exactly equal `PUBLIC_BEARER_EXCHANGE_REDIS_URL`, and
every ordinary verifier serving the configured scope must set `REDIS_URL` to
that same authoritative URI and logical database. Startup and configuration
validation fail when the two issuer-side declarations differ. This exact
configured equality proves that both paths use the global
`freebird:spent:v4:` namespace; merely sharing a Redis server is insufficient.

The strict policy file is:

```json
{
  "version": "freebird/graph-blind-issuance-policy/v1",
  "policies": [{
    "issuance_policy_id": "bootstrap-v1",
    "graph_id": "<active-canonical-graph-id>",
    "keyset_id": "<canonical-keyset-id>",
    "descriptor_id": "<canonical-descriptor-id>",
    "budget_id": "bootstrap-lifetime-v1",
    "budget_limit": 100000,
    "quantity": 1,
    "admission_state": "accepting_new",
    "authorization_scheme": "hmac_sha256"
  }]
}
```

A `v4_local` policy additionally contains local-only scope and trust selectors:

```json
"authorization_scheme": "v4_local",
"v4_local": {
  "verifier_id": "verifier:admission:v4",
  "audience": "graph-bootstrap",
  "trusted_issuers": [{
    "issuer_id": "issuer:admission:v4",
    "key_ids": ["kid-current", "kid-retained"]
  }]
}
```

Discovery publishes only generic `authorization_scheme: "v4_local"` metadata,
never these trust selectors, private keys, or credential material.

An `accepting_new` policy must select the configured active graph and a local
signer. A retained graph policy may only be `recovery_only` or `disabled`.
Changing policy selectors, quantity, scheme, or limit requires a new policy and
budget ID. Policies do not alter graph, keyset, descriptor, or token-key IDs.

## Authorization

For `hmac_sha256`, authorization is canonical base64url for 64 bytes:

1. 32 random one-use bytes;
2. HMAC-SHA256 over the domain, policy ID, and the request's authorization
   binding digest.

The binding digest covers version, public operation ID, policy ID, graph ID,
keyset ID, descriptor ID, and canonical blinded message. The complete request
digest additionally covers the opaque authorization. Redis stores only
domain-separated authorization, status-capability, request, and policy digests.

For `v4_local`, authorization is canonical base64url V4 credential bytes. The
credential must authenticate under a configured issuer/key pair and bind to the
policy's exact verifier ID and audience. The issuance Lua transaction checks and
creates the canonical non-expiring V4 marker, charges the independent issuance
budget, and stores the exact result atomically. Existing-operation recovery is
checked first, so a crash occurs either before both spend and issuance or after
both are durable; issuance is never followed by a later verification step.

## HTTP API

`POST /v1/public/graph/issue` accepts:

```json
{
  "version": 1,
  "public_operation_id": "<base64url-16-random-bytes>",
  "issuance_policy_id": "bootstrap-v1",
  "graph_id": "<graph-id>",
  "keyset_id": "<keyset-id>",
  "descriptor_id": "<descriptor-id>",
  "blinded_message": "<canonical-rfc9474-blinded-message>",
  "authorization": "<opaque-policy-authorization>"
}
```

Send a distinct canonical 32-byte random capability only in the
`Graph-Issuance-Status-Capability` header. Status is observation-only:

```http
GET /v1/public/graph/issue/status?public_operation_id=<public-id>
Graph-Issuance-Status-Capability: <private-capability>
```

All responses have `Cache-Control: no-store`. A success result binds every
selector, signer token-key ID, quantity, request digest, blind signature, and
result digest. It never echoes authorization or blinded message. After a lost
response, recovery is an exact POST retry with the same body and capability;
GET does not perform work.

## Durability and migration

The operation, authorization claims, and lifetime counters use the dedicated
`freebird:graph-issuance:v1:` Redis namespace. Reservation atomically claims the
one-use authorization, charges the policy budget, pins selector/signer IDs, and
stores the already-produced blind signature/result. No V1/V2 exchange keys are
read or charged. Existing installations need no data migration: deploy the
policy file and secret, validate configuration, publish discovery, then enable
the feature. Back up this namespace with the exchange graph and signer files.

`v4_local` also writes the existing global
`freebird:spent:v4:<canonical-nullifier>` marker. Existing V4 markers require no
data transformation. Before enabling, configure every ordinary V4 verifier for
the policy scope to use the exact same durable Redis database.
