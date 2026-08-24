# Policy-authorized native V7 graph blind issuance

V7 graph blind issuance creates exactly one blinded native bearer artifact under
an explicitly authorized descriptor in the active V7 graph. It is separate from
exchange: it consumes no source artifact, creates no exchange receipt, and does
not charge an exchange transition budget.

V5 graph issuance is retired and not accepted. V6 is reserved. There is no
legacy policy, request format, or replay-URL migration path; configure the V7
contract below on a fresh V7 authority database.

## Configuration

Enable the V7 exchange graph first, then configure the issuer authorizer:

```bash
NATIVE_EXCHANGE_V7_ENABLE=true
NATIVE_EXCHANGE_V7_REDIS_URL=redis://redis:6379/0
NATIVE_EXCHANGE_V7_DISCOVERY_PATH=/data/config/native-exchange-v7-discovery.json
NATIVE_EXCHANGE_V7_RETAINED_DISCOVERY_PATHS=/data/config/native-exchange-v7-previous.json
NATIVE_EXCHANGE_V7_PUBLIC_HISTORY_PATH=/data/config/native-exchange-v7-history.json
NATIVE_EXCHANGE_V7_DISABLED_PUBLICATION_ACK_PATHS=/data/config/native-exchange-v7-ack.json

NATIVE_GRAPH_ISSUANCE_V7_ENABLE=true
NATIVE_GRAPH_ISSUANCE_V7_POLICY_PATH=/data/config/native-graph-issuance-v7-discovery.json
NATIVE_GRAPH_ISSUANCE_V7_AUTHORIZATION=v4_local
NATIVE_GRAPH_ISSUANCE_V7_VERIFIER_ID=verifier:admission:v4
NATIVE_GRAPH_ISSUANCE_V7_AUDIENCE=freebird-native-graph-v7
NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64='{"issuer:admission:v4":{"kid-current":"<base64url-32-byte-key>"}}'
```

The V4 keyring is issuer-local secret configuration. Discovery publishes only
the V7 policy's public scope digest and never trusted issuer selectors or key
material. No development/mock authorizer is accepted by the V7 route.

## Replay authority

The graph issuer and each verifier participating in a matching V4-local scope
must use the same Redis logical database, including the global V4 spend
namespace:

```bash
REDIS_URL=redis://redis:6379/0
VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS=https://issuer.example.org
VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL=30s
VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS=60s
```

There are three separate deployment legs. The verifier's `ISSUER_URL` or
`ISSUER_URLS` supplies strict V7 `GET /.well-known/keys` discovery. The
graph-authority `VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS` value supplies only V4
`GET /.well-known/replay-authority` metadata for verifier health refresh; it is
not a V7 key-discovery URL. The same graph-authority origin is used for the
separate fixed `POST /v1/public/graph/replay-authority/probe` route.

URL equality is neither required nor proof. The verifier writes a one-use
challenge through its spend store, the issuer proves the authority through the
POST probe, and both sides fail closed on a cloned or split-brain database. The
metadata endpoint and probe are V4 authority plumbing, not V7 bearer issuance
routes.

V7 artifact replay is independent of that probe: the verifier records the
issuer namespace plus the lowercase hexadecimal **body nullifier**. No
signature, artifact, descriptor, graph, keyset, verifier, or audience value is
part of this replay identity.

## Policy and quantity

Each active V7 policy issues exactly one artifact and names its canonical
profile, graph, keyset, descriptor, token-key ID, issuer, asset, amount, suite,
validity interval, and signer. The policy's `quantity` is literally `1` in the
request, result, and all digests. Retained policies may only be
`recovery_only` or `disabled`.

An accepting policy must select the active graph and a matching private V7
signer. The signer must be a regular non-symlink `0600` file, match the
discovered SPKI and token-key ID, and be valid under the inclusive
`valid_from <= now <= valid_until` interval. Keep direct V7 issuance keys
separate from graph output signers.

## HTTP API and recovery

`POST /v7/public/graph/issue` accepts a V7 request containing a canonical
16-byte public operation ID, policy and graph selectors, a blinded message, and
the opaque V4-local authorization. `GET
/v7/public/graph/issue/status?public_operation_id=<public-id>` is observation-only.

Send one independent canonical base64url 32-byte capability only in the
`Graph-Issuance-Status-Capability` header. Do not place it in the body, URL,
discovery, logs, or traces. All responses are `Cache-Control: no-store`. On a
lost response retry the exact POST with the same operation ID, body, and
capability; do not select a new policy or regenerate authorization.

Fresh issuance selects the current accepting V7 policy and creates a new
operation. Recovery persists and reuses the exact request, blinding state,
operation ID, capability, and expected token-key ID. Recovery remains possible
while the durable operation exists even after a policy becomes
`recovery_only`, `disabled`, or leaves current discovery.

## Discovery, readiness, and backup

The V7 `native_bearer_v7` discovery container exposes public policy and signer
verification material only. It contains no V4 keyring, private paths, operation
state, source material, body nullifiers, replay identities, capabilities, or
live budget counters. Verifiers must validate the complete discovery document
before accepting a V7 artifact.

Back up Redis AOF, V7 active/retained discovery, disabled-publication
acknowledgements, public history, receipt verification metadata, and all
still-required V7 signers as one recovery unit. Never flush the database or
restore Redis independently to make configuration validation pass. Run
`freebird-validate-config`, verify discovery, wait for fresh authority probes,
and confirm verifier readiness before reopening traffic.
