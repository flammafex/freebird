# Gate 0 public manifest (G0.1)

This directory defines the closed, public-only `scarcity/freebird-gate0/v1`
manifest contract. It is an input contract for later fixture and driver lanes;
it does not launch Freebird, validate service health, or prove Gate 0.

## Trust and provenance

All pins must be provisioned locally by the operator **before** any HTTP
metadata is fetched. `issuer_id`, `graph_issuer_id`, the V4 credential issuer
and KID, V4 public key, V4 verifier/audience/scope, replay-authority identity
and scope tombstones, receipt keyset, and the four V7 discovery projections
are independent configuration inputs. A fetched endpoint may be compared with
these pins later; it must never create or expand the trust set. Do not accept
gateway-discovered signer, receipt, or replay-authority pins.

`discovery_pins` uses the closed wire-record layouts from Freebird's
`common/test-fixtures/v7-graph-reference.json`. The committed fixture is
public-only and is used by the parser tests. Three validation layers have
different responsibilities:

1. JSON Schema checks a closed document shape and basic JSON types/patterns.
2. The supplemental stdlib Python validator rejects duplicate JSON members,
   enforces canonical raw encodings and numeric bounds, checks public-key/KID
   and SPKI-fingerprint pins, validates issuer/asset/graph/keyset/descriptor
   and reference membership, requires `graph_policy_id` to select exactly one
   active policy, and applies cross-field/policy-of-work checks. It does **not**
   derive or authenticate native V7 descriptor, keyset, transition, graph, or
   graph-policy IDs.
3. Freebird Common and the strict released SDK are the mandatory authorities
   for native V7 canonical identities, key/SPKI cryptographic validity, and
   registry materialization in G0.2/G0.3. Passing Schema or Python validation
   alone is not native discovery validation.

The V4 `kid` must carry the native-derived identifier prefix for its public
compressed key. Native override suffixes are permitted; no private scalar is
stored in the manifest or fixture.

JSON Schema alone does not enforce canonical base64url pad bits, the maximum
u64 decimal value, validity interval ordering, hash/pin equality, or membership
across separate records. Those checks are supplemental Python/native gates.

The fixture must use separate high loopback origins in the form
`http://127.0.0.1:<port>` with distinct ports from 20000 through 65535. It
contains no dynamic epoch fields. The V7 projections contain the exact public
records that later runtime discovery must match. A service-ready G0.2 fixture
must additionally provide a nonempty exchange transition validated by native
Common/SDK code; G0.1 schema-shape validation does not claim that a service can
start from any arbitrary structurally valid projection.

The schema's `sybil` object only accepts bounded nonzero
`proof_of_work` difficulty. Later lanes must use genuine bounded PoW and must
not substitute an insecure/development admission fallback.

## Private material boundary

This manifest may contain only public V4, receipt, replay-authority and V7
discovery pins. Never add a V4 scalar, RSA or receipt private key, Redis
credential, holder seed, wallet key, exchange status capability, V4
credential, blinding inverse, bearer artifact, or admin secret. Private fixture
material belongs in separate files under a parent-owned mode-0700 run
directory; private files must be mode 0600. Do not check those files or the
G0.3 artifact into source control or print them in logs/assertions.

The V4 credential issuer, manifest issuer, and graph issuer are one pinned
issuer. The public key/KID pair does not prove possession of a matching scalar;
later native issuer/verifier setup must validate the private configuration.

## Validation

The supplemental parser uses only Python's standard library, rejects duplicate
JSON object members at every depth, rejects non-finite numbers, bounds input
size, and applies its closed-member and cross-field pin checks without
third-party packages:

```sh
python3 scripts/gate0/test_manifest.py
python3 scripts/gate0/validate_manifest.py path/to/public-manifest.json
python3 -m json.tool scripts/gate0/manifest.schema.json >/dev/null
```

Schema/Python success means only that a bounded public document conforms to
the G0.1 shape and supplemental pin checks. It does not replace native
Common/SDK validation, authenticate locally provisioned private material,
prove that HTTP services are running or mutually connected, validate Redis
health, or establish V4 issuance, graph replay, artifact verification, or any
other live-service behavior. The sample's expired keys and empty transition
are historical discovery-shape fixture data, not runnable service input.

## Release sequencing

G0 candidate manifests and reports identify locally built source and explicit
binary hashes; they are not evidence for a released version. Do not label a
candidate-source run as v0.10.5. A v0.10.5 claim requires the separately
authorized release sequence, immutable new release tags/artifacts, and a fresh
Gate 0 run against those exact release artifacts. The existing v0.10.4 tags
remain unchanged.
