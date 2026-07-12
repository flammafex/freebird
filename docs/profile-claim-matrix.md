# Profile and Claim Matrix

This is the authoritative status and claim matrix for Freebird issuance
profiles. It is a planning document, not a capability announcement. Until a
profile is implemented, validated, and documented as available, operators and
clients **MUST NOT** describe it as supported or select it in configuration.

The current issuance API is **transitional and experimental**. It is not a
profile, does not meet any planned profile by name, and remains subject to
replacement during Phase B. This document does not change token formats,
existing HTTP routes, or current deployment behavior.

## Status and permitted claims

| Name | Status | Intended admission and state boundary | Permitted claim when implemented | Not a claim |
| --- | --- | --- | --- | --- |
| Current issuance | Transitional / experimental | Current V4 and V5 issuance routes and their configured Sybil gates. Their semantics are not a named profile. | Only implementation-specific statements that are true for the deployed configuration, such as configured replay storage and token-layer behavior. | Production readiness, a profile guarantee, unique-human proof, or anonymity against correlated operational metadata. |
| `atomic-v1` | **PLANNED** | A durable, atomic admission decision and quota/replay record. Redis is required for this profile. | A token was issued only through the profile's configured, atomic admission path. | That every current route has those semantics, global proof of humanity, or anonymity beyond the token layer. |
| `ticket-v1` | **PLANNED** | Profile-controlled ticket admission and redemption semantics, with durable shared state where the profile requires it. Redis is required for this profile. | Only the ticket/profile guarantees specified by its eventual implementation and deployment guide. | That the current V4 or V5 routes issue `ticket-v1` tokens, global human uniqueness, or protection from issuer/verifier metadata correlation. |
| `enhanced-privacy-v1` | **PLANNED** | A `ticket-v1`-class (or independently reviewed equivalent) admission path plus independently operated relay/gateway paths and minimized identifying logs. Redis is required for this profile. | Carefully qualified anonymous-issuance language only after its relay, logging, and non-collusion requirements are implemented and independently operated. | Anonymity against colluding parties, a guarantee that network metadata is hidden, global proof of humanity, or an audit conclusion. |

The experimental/pre-1.0 notice in [SECURITY.md](../SECURITY.md) applies to
every row. No planned profile exists in the current source tree.

## Isolation requirements for planned profiles

A named profile is meaningful only within an isolated issuer/key trust domain.
When a trust domain offers `atomic-v1`, `ticket-v1`, or
`enhanced-privacy-v1`, every route capable of issuing tokens with that domain's
keys must enforce admission semantics at least as strong as the claimed
profile. A weaker current or compatibility route using the same issuer/key
domain would invalidate the stronger claim.

Before the `atomic-v1` cutover, a transitional route may be temporarily
isolated in a separate issuer/key trust domain. At the `atomic-v1` cutover,
every current-issuance route and consumer must be migrated or removed; it must
not remain as an isolated compatibility path. This is a planned requirement;
the current routes have not been evaluated or configured to satisfy it.

## State, transport, and lifecycle limits

### Redis and durable state

Redis is mandatory for `atomic-v1` and every limited-production planned
profile. The requirement covers the profile's durable admission, quota, and
replay state as specified when the profile ships. Redis is also the current
recommended production store for verifier nullifiers and issuer Sybil-proof
replay protection, but configuring Redis today does **not** turn current
issuance into a planned profile.

In-memory state remains suitable only for local or otherwise explicitly
accepted experimental use. Restart, failover, backup, namespace isolation, and
failure behavior are profile implementation work, not guarantees of this
document.

### Transport and metadata

All public deployments, including any future profile, assume HTTPS with
`REQUIRE_TLS=true`, correctly configured trusted proxies, and protected admin
routes. TLS protects traffic in transit; it does not prevent an issuer,
verifier, proxy, relay, hosting provider, or application from correlating IP
addresses, User-Agent data, timing, account identifiers, or logs.

`enhanced-privacy-v1` is planned to require independently operated relay or
gateway paths, log minimization, padding guidance, and no forwarded client IP
or User-Agent. Those conditions do not currently exist as a Freebird profile
or provide a claim against collusion among those parties.

### V4 lifecycle profiles

These are planned lifecycle choices for V4 deployments; neither is currently a
selectable profile or a retroactive change to deployed tokens:

| Lifecycle name | Planned meaning | Operational limit |
| --- | --- | --- |
| `v4-perpetual` | Retain old V4 verification keys and corresponding nullifier history for as long as old tokens can be accepted. | State can grow without a profile-imposed acceptance deadline; capacity planning and alerting are required. |
| `v4-key-windowed` | Define an explicit per-key-ID acceptance deadline, then retain nullifiers only through that deadline plus a safety margin. | It must be opt-in. A deadline must not silently be applied to existing deployments or invalidate outstanding tokens. |

Current epoch/key-retention configuration is not evidence that either named
lifecycle profile has been implemented.

### Fixture provenance record

The committed regression-fixture locations and their scope are recorded here so
that documentation does not imply RFC conformance:

| Fixture set | Committed location | Provenance and interpretation |
| --- | --- | --- |
| V4 wire, scope, and nullifier fixture | `crypto/src/lib.rs` (`v4_wire_scope_and_nullifier_fixture`) | Freebird regression fixture for the existing V4 wire and derivation behavior. It is not an RFC 9497 test vector or interoperability evidence. |
| V4 VOPRF known-answer fixtures | `crypto/src/voprf/core.rs` (`freebird_v4_voprf_known_answer`, `freebird_v4_dleq_blinding_proof_known_answer`) | Deterministic fixtures for the exact Freebird-specific PRF and DLEQ/blinding-proof construction. Separate negative coverage rejects wrong context/key and altered proofs. They are not RFC 9497 conformance or interoperability fixtures. |
| V5 fixed valid signature fixture | `crypto/src/lib.rs` (`v5_wire_signature_message_and_nullifier_fixture`) | Fixed externally generated RSA SPKI, message, signature, pass, key ID, and nullifier. The test verifies the valid fixed signature and rejects a tampered signature. |

[`crypto/tests/fixture-provenance.md`](../crypto/tests/fixture-provenance.md)
is the authoritative provenance record for the deterministic V4 and fixed V5
fixtures, including their inputs, domain separators, independent generation or
verification method, reviewer, and check date. RFC 9497 vectors may be retained
only as migration references, never as evidence that current V4 conforms or
interoperates.

## Claim limits: audit and non-collusion

- Freebird has not had an external security audit. A planned profile name is not
  an audit finding, certification, or production-readiness statement.
- Audit logs are operational records and are not tamper-evident. They must not
  be presented as proof of profile enforcement or privacy.
- Token-layer unlinkability does not protect against correlation by a party that
  observes both issuance and redemption, or by colluding issuer, verifier,
  proxy, relay, hosting, or application operators.
- No current or planned profile claims global proof of humanity, uniqueness of a
  person, or resistance to every real-device/account farm.
- Claims about a configured admission mechanism are local to that mechanism and
  deployment. They do not transfer to another issuer, route, key domain, or
  verifier.

## Phase B consumer inventory

The following current-issuance consumers must be migrated or removed at the
`atomic-v1` cutover. Before that cutover only, a consumer may remain in a
separate, explicitly isolated transitional issuer/key trust domain:

| Consumer | Current touchpoint | Phase B disposition needed |
| --- | --- | --- |
| Interface client | `interface/src/main.rs` posts to `/v1/oprf/issue`. | Migrate its local V4 round trip or remove it at cutover. |
| JavaScript SDK | `sdk/js/src/client.ts` posts to `/v1/oprf/issue` and `/v1/public/issue`. | Version/migrate the SDK API and examples. |
| WebAuthn browser client | `webauthn-client/index.html` participates in the current WebAuthn proof flow used before issuance. | Define how its proof is bound to a replacement admission path; it is not itself a named profile client. |
| Integration tests | `integration_tests/tests/` covers V4, V5, Sybil routes, replay, and smoke flows. | Add cutover negative-route coverage; remove or migrate transitional coverage at cutover. |
| README and examples | `README.md`, client-proof docs, and deployment examples document current routes and flows. | Update commands and labels so examples do not imply a planned profile exists. |
| Deployment smoke tests | `README.md` Docker/local smoke commands, `docs/production-deployment.md` preflight, and release/deployment smoke guidance exercise current services. | Replace with profile-specific checks or remove transitional smoke coverage at cutover. |

For the current implementation and operational limitations, see
[Architecture](architecture.md), [Threat Model](threat-model.md),
[Production Deployment](production-deployment.md), and
[Audit Logging](audit-logging.md).
