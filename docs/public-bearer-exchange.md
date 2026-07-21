# Public bearer exchange V2

The optional public bearer exchange atomically spends valid single-use V5
artifacts and blind-signs outputs selected by a directed transition graph. It is
disabled by default.

## Scope: fresh-install, breaking V2 only

This release is a fresh-install, graph-only replacement. It does not serve V1
exchange paths, load V1 profiles, read or recover V1 operation records, or
migrate V1 Redis state. The deployment assumption is that exchange has not
previously been operated. V4 and V5 token formats and direct V5 issuance are not
changed by this replacement.

Before enabling exchange, use a dedicated Redis logical database that is empty
of prior exchange records. That database must then be shared with every V5
verifier as described under [Redis authority and durability](#redis-authority-and-durability).
Do not attempt an in-place V1 cutover.

## Configuration

```bash
PUBLIC_BEARER_EXCHANGE_ENABLE=true
PUBLIC_BEARER_EXCHANGE_REDIS_URL=redis://redis:6379
PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH=/data/config/public-bearer-exchange-graph-v2.json
PUBLIC_BEARER_EXCHANGE_RETAINED_GRAPH_PATHS=/data/config/exchange-graph-previous.json
PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH=/data/config/exchange-public-history-v2.json
PUBLIC_BEARER_EXCHANGE_DISABLED_PUBLICATION_ACK_PATHS=/data/config/exchange-publication-ack.json

PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_KEY_PATH=/data/keys/exchange-receipt-active.key
PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_METADATA_PATH=/data/config/exchange-receipt-active.json
PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_KEY_PATHS=/data/keys/exchange-receipt-previous.key
PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_METADATA_PATHS=/data/config/exchange-receipt-previous.json

PUBLIC_BEARER_EXCHANGE_RECEIPT_LIFETIME=1d
PUBLIC_BEARER_EXCHANGE_MAX_BODY_BYTES=3145728
PUBLIC_BEARER_EXCHANGE_TIMEOUT=30s
```

Comma-separate multiple retained graph, acknowledgement, receipt-key, or
receipt-metadata paths. Retained receipt key and metadata lists are positional
and must have the same number of entries. The active graph, public history,
receipt metadata, and acknowledgements are strict local JSON. Pin and review
them as deployment configuration; never fetch them at runtime.

Use only the canonical V2 environment names:
`PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH`,
`PUBLIC_BEARER_EXCHANGE_RETAINED_GRAPH_PATHS`, the separate receipt metadata
paths, and disabled-publication acknowledgement paths shown above.

Run the configuration validator against the same files, environment, direct V5
key, issuer ID, and Redis database that production will use:

```bash
source .env
freebird-validate-config
```

The validator fails closed on invalid canonical graph identities,
signer/public-metadata mismatches, direct-issuance key overlap, retained
history, publication acknowledgements, or Redis durability/topology. It does
not initialize or mutate the durable key registry. Issuer runtime startup
atomically initializes that registry on first use or byte-verifies it on later
starts; runtime readiness continues to verify registry consistency.

## Directed, role-neutral graph

The active graph has profile ID `freebird/public-bearer-exchange/v2` and four
ordered layers:

1. **Descriptors** identify V5 RFC 9474 RSASSA-PSS public keys and immutable
   acceptance metadata. The SPKI must carry the RSASSA-PSS algorithm and suite
   parameters accepted by Freebird; a generic `rsaEncryption` SPKI is invalid.
   A descriptor contains no source/target role, class, quantity, or private
   path. The same keyset can therefore be the target of one transition and the
   source of another.
2. **Keysets** are canonical ordered descriptor memberships. A local keyset
   member may include `private_key_path`; that path is not part of any public or
   stable identity. An accepting transition requires matching private signers
   for all of its output descriptors.
3. **Transitions** are directed from one explicit source keyset to a distinct
   target keyset. Ordered source/output slots declare descriptor ID, slot ID,
   class, and quantity. Each transition has an independent `budget_id`,
   `budget_limit`, and `admission_state`.
4. **The graph ID** commits to the ordered keyset IDs and transition IDs.

Canonical IDs derive in order: descriptor, keyset, stable transition contract,
then graph. All IDs must be supplied explicitly and must match the canonical
derivation. Descriptor identity commits to profile, runtime issuer, SPKI-derived
key ID, audience, suite, SPKI, and inclusive validity bounds. Transition
identity commits to both keysets, ordered slots/classes/quantities, budget ID,
and budget limit.

Admission state is deliberately excluded from transition and graph identity,
so an operator can move one stable contract through its lifecycle without
creating a new budget:

| State | Fresh requests | Pending recovery |
| --- | --- | --- |
| `accepting_new` | allowed | allowed |
| `recovery_only` | rejected | allowed |
| `disabled` | rejected | rejected; there must be no pending references |

Retained graphs cannot contain `accepting_new` transitions. Source and output
keysets must differ. Descriptor/keyset/transition order is identity-bearing;
do not reorder JSON arrays without recomputing every dependent ID.

The committed
[`public-bearer-exchange-profile.json`](examples/public-bearer-exchange-profile.json)
is a syntax and canonical-ID example of a bidirectional A→B and B→A graph. Its
public keys and private paths are documentation values, not deployable signer
material. Generate regular non-symlink RFC 9474 RSASSA-PSS private-key files
with mode `0600` using Freebird's public-bearer provider, derive their
RSASSA-PSS SPKIs/key IDs, and recompute descriptor, keyset, transition, and graph
IDs before deployment. Exchange output keys must not overlap the direct V5
issuance key.

## Capacity and transition lifecycle

Each `budget_id` names permanent, edge-scoped lifetime capacity. A successful
reservation atomically charges the checked sum of output quantities. The charge
is not released when an operation commits, an artifact expires, a transition
enters recovery, or a service restarts.

Redis pins the budget ID to the complete stable transition policy, limit,
transition ID, and `sum_output_quantities` charge kind. A budget ID is unique
within a graph and cannot be shared with another transition or reused with a
changed contract. Admission-state-only revisions retain the same transition ID,
graph ID, and cumulative charge. Capacity resets **only** when an operator
deliberately creates a new transition contract with a new budget ID and
recomputes its transition and graph IDs. Never rotate budget IDs merely to evade
an exhausted policy limit.

Use this lifecycle for an accepting transition:

1. Publish and review it as `disabled` and complete the acknowledgement process
   below.
2. Change only its state to `accepting_new`.
3. To stop new work, change it to `recovery_only`; retain graph and signer
   configuration while pending references drain.
4. Change it to `disabled` only after no pending operation references it.
5. Preserve its public graph and verification history, then retire private
   signers according to the retention procedure.

## Disabled-publication acknowledgement

Every `accepting_new` transition requires an explicit durable operator
acknowledgement that is bound to the runtime issuer ID, canonical graph ID, and
canonical transition IDs and states `acknowledged_admission_state: "disabled"`.
Startup, readiness, and the config validator fail closed when an accepting
transition is unacknowledged, duplicated, unreadable, or mismatched.

For a new graph, first publish it with the intended transitions disabled and
verify the served discovery document. Then create the acknowledgement, record a
real operator identity and Unix timestamp, configure its path, and change only
the acknowledged transitions to `accepting_new`. Admission state does not alter
their transition or graph IDs. Do not pre-sign acknowledgements for graph
content that has not been reviewed.

See
[`public-bearer-exchange-disabled-publication-ack.json`](examples/public-bearer-exchange-disabled-publication-ack.json)
for the strict shape.

## Receipt keys

Receipts use isolated Ed25519 keys, not an RSA exchange or direct-issuance key.
V2 never generates a declared receipt key on startup. The active seed must
already exist as a regular non-symlink `0600` file and must match separately
pinned public metadata. The active key validity interval must contain the full
receipt lifetime assigned using authoritative Redis time.

The example
[`public-bearer-exchange-receipt-metadata.json`](examples/public-bearer-exchange-receipt-metadata.json)
shows metadata shape only. Generate a seed and matching verification key; do not
deploy the example bytes.

For rotation, move the previous seed and matching metadata to the positional
retained lists and mark its metadata purpose `exchange_receipt_retained`.
Retained keys are used only for persisted recovery, never fresh work. Keep the
private seed until its pending-reference counter reaches zero. Before removing
it, copy its public verification metadata to public history and retain that
public key through every receipt's inclusive expiry.

## V2 HTTP API and two operation identifiers

`POST /v2/public/exchange` accepts a V2 request like:

```json
{
  "version": 2,
  "public_operation_id": "ABEiM0RVZneImaq7zN3u_w",
  "graph_id": "e7ac9a7b24d4fdab6ba77b0c5d7fca19b821fbb981de45de7a7dda0c8615efa7",
  "transition_id": "5e64111531d69f7b7e5647040a1dab95b7638a921245fe1c3ec5a883673e6e74",
  "source_keyset_id": "df657e70ea47c40e9e32718e274fe192d6c9d08a065826f42f10f5bf1819b2be",
  "target_keyset_id": "b8024c13933bb4d27930935a43182aa5d28647bdd27927daaf2f10e85d246317",
  "sources": [{
    "slot": {
      "descriptor_id": "4385af515d9768ee27cdd0e2ddfe49af2e3205c19abafdd5decea62b4a7c34b7",
      "keyset_id": "df657e70ea47c40e9e32718e274fe192d6c9d08a065826f42f10f5bf1819b2be",
      "slot_id": "input",
      "quantity": 1
    },
    "artifact": "<canonical-base64url-v5-artifact>"
  }],
  "outputs": [{
    "slot": {
      "descriptor_id": "333778b2dc1df2fbafc181cc69da20fcdabb0a2d77c4f5d8bf97e6572aa6429e",
      "keyset_id": "b8024c13933bb4d27930935a43182aa5d28647bdd27927daaf2f10e85d246317",
      "slot_id": "output",
      "quantity": 1
    },
    "blinded_value": "<canonical-base64url-rfc9474-blinded-message>"
  }]
}
```

The caller generates and retains two independent values:

- `public_operation_id` is canonical unpadded base64url for 16 random bytes. It
  is a non-secret correlation ID committed into the request, result, and
  receipt. It is not authorization.
- `Exchange-Status-Capability` is canonical unpadded base64url for 32 independent
  random bytes. Send exactly one such header on POST and status requests. It is
  a private bearer capability: never put it in a body, URL, query, discovery
  document, access log, trace, analytics event, referrer, crash report, or
  support ticket. Redis stores only its domain-separated digest.

Status is:

```http
GET /v2/public/exchange/status?public_operation_id=ABEiM0RVZneImaq7zN3u_w
Exchange-Status-Capability: <canonical-base64url-32-random-bytes>
```

The public operation ID may appear in the status URL because it has no authority
without the separate capability. Clients should nevertheless avoid unnecessary
correlation logging. Gateways must preserve exactly one capability header,
disable body/header logging, and never cache responses.

A successful response contains V2 `result` and `receipt` objects. Both bind
version, public operation ID, graph, transition, source keyset, target keyset,
and result digest. Results additionally bind ordered output slots, original
blinded values, and blind signatures. Receipts additionally bind Redis-assigned
creation/expiry times and the receipt verification-key ID. They contain no raw
source artifacts, nullifiers, status capability, private paths, or graph
history.

All responses use `Cache-Control: no-store`:

| Route | Status | Meaning |
| --- | --- | --- |
| POST/status | 200 | exact stored result and receipt bytes |
| POST/status | 202 | `exchange_retryable`; wait for `Retry-After` |
| POST | 409 | operation ID/request/capability conflict |
| status | 403 | status capability is not authorized |
| status | 404 | unknown public operation ID |
| POST | 400 | invalid capability, request, source, transition, or exchange |
| POST | 413 | request exceeds the configured body limit |
| POST/status | 503 | exchange unavailable |

After timeout or connection loss, retry POST with the same public operation ID,
the same status capability, and the exact same request. Never create a new
operation: the first request may already have spent its sources. A 202 means
durable work is pending or being recovered. Recovery uses persisted graph,
transition, keyset, signer, and receipt-key references before present admission
state. A missing retained signer keeps work retryable rather than releasing a
source spend.

Clients accepting a 200 response must recompute all canonical bindings and
digests, compare every selector and ordered output against the original request,
verify the receipt signature from validated discovery, and reject non-canonical
encodings or any mismatch.

## Discovery contains public data only

`/.well-known/keys` preserves direct V5 metadata and, when exchange is enabled,
publishes one all-or-nothing V2 `exchange` trust container with:

- one `active_graph` and zero or more `retained_graphs`;
- role-neutral descriptors and ordered keysets;
- directed transitions, slots, budget contracts, and explicit admission states;
- one active receipt verification key and retained receipt verification keys.

Consumers must validate the entire container before trusting any graph output.
Discovery never contains private signer paths or keys, receipt seeds, source
artifacts, nullifiers/spend keys, operation records, status capabilities or their
digests, pending-reference counts, or live budget counters. Admission state and
static budget limits are public; current usage is operational state and is not
published.

## Inclusive validity and immutable key registry

Descriptor `valid_from` and `valid_until` are inclusive Unix-second acceptance
bounds evaluated with authoritative Redis time: a source is valid when
`valid_from <= now <= valid_until`. Spend markers therefore expire at
`valid_until + 1`, not at `valid_until`. Verifier replay writers use the same
absolute inclusive expiry. Treat receipt `expires_at` as inclusive for public
verification-material retention.

The issuer and verifier compute one global identity for every direct or graph
alias of a V5 SPKI. Its acceptance horizon is the longest inclusive
`valid_until` among those aliases. On first enablement, Redis creates an
append-only V2 key registry whose root and per-key tombstones pin canonical
SPKI-derived key ID, SPKI, issuer, suite, audience, and that longest horizon.

Registry entries can be added but never removed or rewritten. Reusing an SPKI
with changed issuer, suite, or audience, or changing its pinned longest horizon
in either direction, fails closed. Plan the complete horizon before first
registration; use a new RSA key/descriptor identity for changed metadata or
validity. Restore registry and replay state together. Never delete registry
tombstones or reset Redis to make a configuration pass.

Every registry identity must remain represented by active/retained discovery or
public history. This release has no registry garbage collection, so do not prune
historical identities after expiry even when their public verification minimum
has elapsed.

## History, retention, and signer retirement

`PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH` is strict public-only V2 JSON with
`retained_graphs` and `retained_receipt_keys`. See
[`public-bearer-exchange-public-history.schema.json`](examples/public-bearer-exchange-public-history.schema.json).
Graph entries use discovery field names and contain no `private_key_path`.

Private recovery retention and public trust retention are separate:

1. Move an accepting transition to `recovery_only`. Keep its retained graph,
   output RSA private keys, receipt seed, and metadata configured while any
   durable pending-reference counter names them. Readiness fails closed if a
   required signer is unavailable.
2. Allow leases and pending operations to finish. Do not infer zero references
   from local memory or wall-clock time; Redis is authoritative.
3. Once pending references are zero, move the transition to `disabled`. Before
   removing private material, copy the complete public graph and receipt
   verification metadata into public history and validate discovery fleet-wide.
4. Remove the private RSA/receipt signer only after successful public-history
   publication. Securely retire private material according to local key policy.
5. Keep public verification material through the inclusive expiry of every
   output artifact and receipt. Keep all registered identities represented
   thereafter because the durable registry is append-only and has no GC.

Back up active/retained graph files, acknowledgements, public history, receipt
metadata, and all still-required private signers with Redis as one coherent
recovery unit.

## Redis authority and durability

`PUBLIC_BEARER_EXCHANGE_REDIS_URL` must identify the exact same Redis logical
database as verifier `REDIS_URL` for every verifier that accepts participating
V5 keys. Sharing only a server while selecting different database numbers is not
sufficient. This preserves one spend/replay namespace across issuer exchange,
single verification, and batch verification. Never use an in-memory verifier
replay store with exchange.

Redis is authoritative security state, not a cache. The supported topology is a
single standalone writable master with:

```text
redis_mode:standalone
role:master
appendonly yes
appendfsync always
maxmemory-policy noeviction
aof_enabled:1
aof_last_write_status:ok
```

Redis Cluster, a replica as writable endpoint, asynchronous AOF, RDB-only
durability, eviction, and failover that can lose acknowledged writes are
unsupported. Startup and readiness fail closed on topology, AOF health,
connectivity, registry, publication, or signer-reference failures.

An AOF rollback, database flush, partial restore, or verifier/issuer split-brain
can resurrect spent artifacts, reset lifetime budgets, lose registry tombstones,
or lose committed responses. Treat any such event as a security incident. Do
not restore Redis independently from graph/history/signer configuration. See
[Backup and Restore](backup-restore.md).
