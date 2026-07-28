# Policy-authorized graph blind issuance V2

Graph blind issuance creates exactly one blinded V5 bearer artifact under an
explicit descriptor in the active V2 exchange graph. It is separate from
exchange: it consumes no source artifact, creates no exchange receipt, and
does not charge an exchange transition budget.

This is a breaking V2 contract. There is no V1 policy, V1 request format, V1
Redis namespace, or V1 replay-URL configuration to migrate.

## Configuration

Enable the V2 graph first, then configure the issuer authorizer:

```bash
PUBLIC_BEARER_EXCHANGE_ENABLE=true
PUBLIC_BEARER_EXCHANGE_REDIS_URL=redis://redis:6379/0
PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH=/data/config/public-bearer-exchange-graph-v2.json
PUBLIC_BEARER_EXCHANGE_RETAINED_GRAPH_PATHS=/data/config/exchange-graph-previous.json
PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH=/data/config/exchange-public-history-v2.json
PUBLIC_BEARER_EXCHANGE_DISABLED_PUBLICATION_ACK_PATHS=/data/config/exchange-publication-ack.json

PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE=true
PUBLIC_BEARER_GRAPH_ISSUANCE_POLICY_PATH=/data/config/graph-issuance-policy-v2.json
PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION=hmac_sha256
PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64=<canonical-base64url-secret>
```

The HMAC secret must be canonical unpadded base64url containing at least 32
random bytes. There is no permissive production default. `development_mock`
requires all development fences documented in `.env.example`.

The approved `v4_local` authorizer accepts canonical base64url V4 credential
bytes in the opaque `authorization` field. It performs the same scope,
authenticator, nullifier, and spend-key checks as a verifier and atomically
writes the global V4 spend marker. It never composes `/v1/check` and
`/v1/verify`.

```bash
PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION=v4_local
PUBLIC_BEARER_GRAPH_ISSUANCE_V4_KEYRING_B64='{"issuer:admission:v4":{"kid-current":"<base64url-32-byte-key>"}}'
```

The V4 keyring is issuer-local secret configuration. Discovery publishes only
the policy's public scope digest, never trusted issuer selectors or key
material.

## Redis replay authority

The graph issuer and every verifier participating in a matching V4-local scope
must use the **same Redis logical database**, including the global V4 spend
namespace. Sharing a Redis server while selecting different databases is not
sufficient. Configure each participating verifier with its ordinary spend
store and graph issuer URL:

```bash
REDIS_URL=redis://redis:6379/0
VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS=https://issuer.example.org
VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL=30s
VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS=60s
```

`VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS` is a comma-separated list. Each URL must
resolve to the issuer's public discovery and fixed probe route through the
trusted HTTPS boundary. `ISSUER_URL`/`ISSUER_URLS` still configure ordinary
issuer metadata refresh; graph authority URLs are explicit and separate.

Configuration URL equality is neither required nor proof of shared state. The
verifier writes a one-use challenge through its actual `REDIS_URL` spend-store
pool. The issuer consumes that challenge through the graph-issuance Redis
store, computes the proof, and writes an acknowledgement. The verifier checks
the HTTP proof, independently recomputed proof, and acknowledgement. A cloned,
different, or split-brain Redis database fails the probe.

The issuer creates and permanently retains a random 32-byte authority identity
at `freebird:v4-replay-authority:v1:id`. It also retains append-only scope
tombstones at `freebird:v4-replay-authority:v1:scope-tombstones` for every
V4-local scope that could have consumed a non-expiring marker. The authority
identity and tombstones remain in discovery after policies become
`recovery_only`, `disabled`, or are removed from the policy document.

Probe health is intentionally bounded:

- the verifier probes immediately and every **30 seconds**;
- an authority is unhealthy after **60 seconds** without a successful probe;
- all retained tombstone scopes are probed, not only currently accepting
  policies.

When graph authority URLs are configured, cold start, missing discovery,
authority/tombstone mismatch, failed probe, stale probe, or in-memory replay
causes V4 consuming verification (`/v1/verify` and `/v1/verify/batch`) to fail
with `503` before any replay mutation. V5 verification is unaffected. A
verifier with no graph authority URLs is not a graph participant and does not
apply this additional V4 gate.

## Policy and quantity

The strict policy document is V2 and every policy issues one artifact:

See [`public-bearer-graph-issuance-policy-v2.json`](examples/public-bearer-graph-issuance-policy-v2.json)
for a disabled, syntax-only example. It is not deployable signer material.

```json
{
  "version": "freebird/graph-blind-issuance-policy/v2",
  "policies": [{
    "issuance_policy_id": "bootstrap-v2",
    "graph_id": "<active-canonical-graph-id>",
    "keyset_id": "<canonical-keyset-id>",
    "descriptor_id": "<canonical-descriptor-id>",
    "budget_id": "bootstrap-lifetime-v2",
    "budget_limit": 100000,
    "quantity": 1,
    "admission_state": "accepting_new",
    "authorization_scheme": "hmac_sha256"
  }]
}
```

`quantity` is literally `1` in the policy, reservation, result, and all
digests. There is no batch quantity or multi-artifact graph issuance operation.
An accepting policy must select the active graph and a local private signer;
retained graph policies may only be `recovery_only` or `disabled`.

A `v4_local` policy additionally contains issuer-local scope and trust
selectors. They are not published as trust configuration:

```json
{
  "authorization_scheme": "v4_local",
  "v4_local": {
    "verifier_id": "verifier:admission:v4",
    "audience": "graph-bootstrap",
    "trusted_issuers": [{
      "issuer_id": "issuer:admission:v4",
      "key_ids": ["kid-current", "kid-retained"]
    }]
  }
}
```

## HMAC V2 contract and vector

The HMAC authorization is canonical base64url for exactly 64 raw bytes:

```text
authorization = nonce_raw[32] || tag_raw[32]
tag = HMAC-SHA256(
  secret,
  transcript_domain_raw ||
  nonce_raw[32] ||
  u32be(UTF-8 byte length(policy_id)) ||
  policy_id_utf8 ||
  authorization_binding_digest_raw[32]
)
```

`transcript_domain_raw` is the UTF-8 bytes of `freebird graph issuance hmac
authorization v2` followed by one zero byte. Its machine-readable hexadecimal
encoding is
`66726565626972642067726170682069737375616e636520686d616320617574686f72697a6174696f6e20763200`.

The nonce is random, one-use, and is decoded before framing. Base64 text,
padding, and textual representations of the nonce or digest are never part of
the transcript. The authorization-binding digest covers version, operation
ID, policy ID, graph ID, keyset ID, descriptor ID, and canonical blinded
message. The complete request digest additionally binds decoded authorization
bytes.

Fixed producer vector:

```text
secret bytes: 0123456789abcdef0123456789abcdef
nonce bytes:  32 bytes of 0x11
policy_id:    bootstrap-v2
binding:      32 bytes of 0x22
authorization:
ERERERERERERERERERERERERERERERERERERERERERHW8wrZdGGPxL-pfhnHBEGP8aET_YjjpY3VV1ClT1iLOw
```

Changing one nonce, policy, binding, tag, or encoding byte must be rejected.
The machine-readable vector is
[`public-bearer-graph-issuance-hmac-v2-vector.json`](examples/public-bearer-graph-issuance-hmac-v2-vector.json).

## Signer validity and file requirements

Graph issuance reuses the V2 output-signer checks. An accepting descriptor must
have a matching private signer in the active graph. The signer must be a
regular, non-symlink file with Unix mode `0600`, contain the expected RSA-PSS
key material, match the descriptor SPKI and token-key ID, and have a valid
inclusive validity window. The issuer uses authoritative Redis `TIME` and
requires `valid_from <= now <= valid_until`; readiness fails closed when an
accepting signer is outside that window. Keep the direct V5 issuance key
separate from graph output signers.

## HTTP API and recovery

`POST /v1/public/graph/issue` accepts a V2 request:

```json
{
  "version": 2,
  "public_operation_id": "<base64url-16-random-bytes>",
  "issuance_policy_id": "bootstrap-v2",
  "graph_id": "<graph-id>",
  "keyset_id": "<keyset-id>",
  "descriptor_id": "<descriptor-id>",
  "blinded_message": "<canonical-rfc9474-blinded-message>",
  "authorization": "<opaque-policy-authorization>"
}
```

Send one distinct canonical base64url 32-byte capability only in the
`Graph-Issuance-Status-Capability` header. Status is observation-only:

```http
GET /v1/public/graph/issue/status?public_operation_id=<public-id>
Graph-Issuance-Status-Capability: <private-capability>
```

All responses are `Cache-Control: no-store`; neither authorization nor blinded
message is echoed. A lost response is recovered by retrying the exact POST
with the same operation ID, body, and capability. GET never performs work.

The SDK must keep fresh issuance and recovery distinct:

- **Fresh:** select the current accepting policy from validated discovery,
  create a new operation ID/capability and authorization, and use the active
  graph/signer contract.
- **Recovery:** persist the exact request, operation ID, capability, blinding
  state, and expected token-key ID. Retry the exact request or status lookup;
  do not select a new policy, regenerate authorization, or create a new
  operation. Recovery validates the persisted result against the original
  request, selectors, quantity, request digest, result digest, and expected
  signer ID. It remains possible while a durable operation exists even after
  its policy becomes `recovery_only`, `disabled`, or is no longer in current
  discovery.

## Probe route and proxy exposure

The verifier must reach both `/.well-known/keys` and this fixed issuer route:

```http
POST /v1/public/graph/replay-authority/probe
```

Expose it through the same trusted HTTPS proxy as the issuer's other public
`/v1/public` routes. The proxy must allow POST and JSON, preserve the request
body and response, overwrite exactly one `X-Forwarded-Proto: https` and
`X-Forwarded-For`, disable caching and sensitive header/body logging, and not
rewrite the path. Do not expose the backend port directly or route the probe
through `/admin`. Kubernetes and nginx examples include this route under the
issuer `/v1/public` surface.

## Durability and backup

V2 graph issuance uses the dedicated `freebird:graph-issuance:v2:` namespace,
the exchange graph/history, signer files, and the shared V4 spend namespace.
Back up these as one coherent recovery unit:

- the authoritative Redis AOF, including the permanent replay authority ID,
  scope tombstones, graph-issuance operations/budgets, and V4 spend markers;
- active/retained V2 graphs and disabled-publication acknowledgements;
- active/retained RSA output signers and their metadata;
- public history and receipt verification metadata/seeds.

Never restore Redis independently from graph/history or signer configuration.
Do not delete authority tombstones, flush the logical database, or reset the
authority to make a configuration pass. Run `freebird-validate-config`, verify
discovery, wait for fresh 30-second probes, and confirm verifier readiness
before reopening traffic.
