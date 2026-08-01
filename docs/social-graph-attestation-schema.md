# Social Graph Attestation Schema

> Status: **Pre-Phase 1 specification.** This document defines the
> canonical attestation format for the `social_graph` Sybil gate. It is
> the foundation for the SophiaDOS JSON Schema, the Cred adapter
> contract, and the prototype implementations.

## Signing format decision

**Canonical JSON + Ed25519.**

Rationale:
- Clout uses Ed25519 for trust edge signatures (`clout/src/crypto.ts:622-639`)
- Cred uses Ed25519 for controller signatures (`cred/Cargo.toml` deps)
- The `sophia/v1` contract uses canonical JSON with SHA-256 hashing
  and lowercase hex strings (`sophiados/contracts/README.md:31-39`)
- JWS/COSE add encoding complexity without clear benefit for this
  single-signature, single-recipient use case
- Canonical JSON is simple, auditable, and requires no external
  dependencies beyond `serde_json` + `ed25519-dalek` (both already in
  the Freebird and Cred workspaces)

## Artifact type

```
social_graph.attestation
```

This is a `sophia/v1` canonical artifact. It follows the contract
conventions:
- `contract_version: "sophia/v1"` on every artifact
- lowercase hex SHA-256 strings for hashes
- base64url strings for token bytes
- Unix seconds for timestamps
- service base URLs without trailing slashes

## Attestation fields

| Field | Type | Required | Description |
|---|---|---|---|
| `contract_version` | string | yes | `"sophia/v1"` |
| `artifact_type` | string | yes | `"social_graph.attestation"` |
| `version` | string | yes | Attestation schema version, e.g. `"1"` |
| `attester_id` | string | yes | Identifier of the attester that issued this |
| `kid` | string | yes | Key ID used to sign (maps to JWKS) |
| `policy_id` | string | yes | Which scoring policy was applied |
| `issued_at` | u64 | yes | Unix seconds when attestation was created |
| `expires_at` | u64 | yes | Unix seconds when attestation expires |
| `eligibility_level` | u8 | yes | Coarse score bucket (1-3), not exact score |
| `quota_nullifier` | string | no | Epoch-scoped nullifier for quota enforcement |
| `jti` | string | yes | Unique attestation ID (UUID or hex random) |
| `holder_commitment` | string | yes | Hex SHA-256 of Cred controller's public key |
| `signature` | string | yes | Hex Ed25519 signature over the canonical JSON |

### Field constraints

- `expires_at` must be > `issued_at`
- `expires_at` - `issued_at` should be <= 300 seconds (5 minutes)
- `eligibility_level` must be in range 1-3
- `holder_commitment` is `SHA-256(controller_public_key_bytes)` as
  lowercase hex (64 chars)
- `jti` should be unique across all attestations from the same attester
- `quota_nullifier` is optional but, when present, must be a lowercase
  hex SHA-256 string
- `signature` is 128 bytes Ed25519 signature as lowercase hex (128 chars)

### Must NOT contain

The attestation must not include:
- Clout public keys
- Raw trust edges or graph data
- Invitation paths or chains
- Exact SybilRank scores
- Wallet addresses or transfer history
- Ballot or rendezvous identifiers
- Freebird request bindings or request binding hashes
- Any stable user identifier
- Any Freebird-specific field

The attestation is **general-purpose** — it proves eligibility without
binding to a specific consumer. Cred binds it to a specific Freebird
request at presentation time.

## Canonical JSON serialization

The signature is computed over the canonical JSON form of the
attestation **without** the `signature` field.

### Canonical JSON rules

1. Object keys sorted lexicographically (ascending)
2. No whitespace between tokens (no spaces after `:` or `,`)
3. No trailing newline
4. UTF-8 encoding
5. Strings use standard JSON escaping (only escape `"`, `\`, and
   control characters `U+0000` through `U+001F`)
6. Numbers: integers are bare digits, no leading zeros, no `+` sign
7. `null`, `true`, `false` are lowercase
8. Empty arrays: `[]`, empty objects: `{}`
9. The `signature` field is excluded from the canonical form

### Example unsigned attestation (canonical form)

```json
{"artifact_type":"social_graph.attestation","attester_id":"attester:example:v1","contract_version":"sophia/v1","eligibility_level":2,"expires_at":1719000000,"holder_commitment":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2","issued_at":1718999700,"jti":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kid":"attester-key-2026-06","policy_id":"clout-trust-v1","quota_nullifier":"9e86d0818844414a0e2e5b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7","version":"1"}
```

### Signature construction

```
canonical_json = canonical_serialize(attestation_without_signature_field)
message = canonical_json.as_bytes()
signature = ed25519_sign(attester_private_key, message)
```

The signature is stored as lowercase hex in the `signature` field of
the complete attestation.

### Verification

```
canonical_json = canonical_serialize(attestation_without_signature_field)
message = canonical_json.as_bytes()
ed25519_verify(attester_public_key, message, hex_decode(signature))
```

## Cred presentation binding

When Cred presents the attestation to Freebird, it creates a
`cred.presentation` artifact containing:

| Field | Source |
|---|---|
| `contract_version` | `"sophia/v1"` |
| `artifact_type` | `"cred.presentation"` |
| `presentation_id` | Unique ID for this presentation |
| `cred_id` | Cred agent identifier |
| `request_id` | Freebird issuance request ID |
| `grant_id` | Permission grant authorizing this presentation |
| `app_id` | Freebird issuer identifier |
| `created_at` | Unix seconds |
| `artifacts` | Array containing the attestation (embedded) |
| `request_binding_hash` | Hex SHA-256 of Freebird's request binding |
| `presentation_signature` | Hex Ed25519 signature by Cred controller |

### Presentation signature

The Cred controller signs over:

```
canonical_json = canonical_serialize(presentation_without_presentation_signature_field)
message = canonical_json.as_bytes()
signature = ed25519_sign(cred_controller_private_key, message)
```

This proves the Cred controller authorized this specific presentation
to this specific Freebird issuer for this specific request.

## SybilProof mapping

When the client submits the attestation to Freebird, it sends:

```rust
SybilProof::SocialGraph {
    /// The complete cred.presentation artifact as JSON string
    attestation: String,
    /// The presentation_signature field as hex string
    presentation: String,
}
```

The Freebird issuer's `verify_with_context` then:
1. Parses the `cred.presentation` from `attestation`
2. Verifies the `presentation_signature` using the Cred controller's
   public key (recovered from `holder_commitment` in the embedded
   attestation)
3. Verifies the attester's `signature` over the attestation
4. Checks `request_binding_hash` matches `hash(ctx.request_binding)`
5. Checks `eligibility_level` >= configured minimum
6. Checks `expires_at` is in the future
7. Checks `policy_id` is in accepted list
8. Calls `mark_once("social_graph:jti", jti, ttl)` on the replay store

## Example complete attestation

```json
{
  "contract_version": "sophia/v1",
  "artifact_type": "social_graph.attestation",
  "version": "1",
  "attester_id": "attester:example:v1",
  "kid": "attester-key-2026-06",
  "policy_id": "clout-trust-v1",
  "issued_at": 1718999700,
  "expires_at": 1719000000,
  "eligibility_level": 2,
  "quota_nullifier": "9e86d0818844414a0e2e5b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7",
  "jti": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "holder_commitment": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "signature": "9b4f1c2e3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
}
```

## Example Cred presentation

```json
{
  "contract_version": "sophia/v1",
  "artifact_type": "cred.presentation",
  "presentation_id": "presentation-social-graph-1",
  "cred_id": "cred:local:example",
  "request_id": "request-freebird-issue-1",
  "grant_id": "grant-social-graph-1",
  "app_id": "issuer:freebird:example",
  "created_at": 1718999800,
  "artifacts": [
    {
      "artifact_type": "social_graph.attestation",
      "artifact_hash": "dfd3f3fe66c16b95124e9e10c15a7c9321ed3b75d0d79dc0d2e2b47dcbbdc507",
      "disclosure": "embedded",
      "artifact": {
        "contract_version": "sophia/v1",
        "artifact_type": "social_graph.attestation",
        "version": "1",
        "attester_id": "attester:example:v1",
        "kid": "attester-key-2026-06",
        "policy_id": "clout-trust-v1",
        "issued_at": 1718999700,
        "expires_at": 1719000000,
        "eligibility_level": 2,
        "quota_nullifier": "9e86d0818844414a0e2e5b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7",
        "jti": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "holder_commitment": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "signature": "9b4f1c2e3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
      }
    }
  ],
  "request_binding_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "presentation_signature": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b"
}
```

## Permission grant for social_graph presentations

```json
{
  "contract_version": "sophia/v1",
  "artifact_type": "cred.permission_grant",
  "grant_id": "grant-social-graph-1",
  "cred_id": "cred:local:example",
  "app_id": "issuer:freebird:example",
  "capabilities": [
    "social_graph.present"
  ],
  "constraints": {
    "allowed_artifact_types": [
      "social_graph.attestation"
    ],
    "allowed_audiences": [
      "issuer:freebird:example"
    ],
    "max_uses": 1,
    "expires_at": 1719000300,
    "allow_export": false
  },
  "human_approval": "per_use",
  "created_at": 1718999600
}
```

## Key distribution and rotation status

The reference attester publishes its current Ed25519 public key at a JWKS
endpoint, and `kid` in the attestation identifies that key. The current issuer
does **not** fetch or refresh `SOCIAL_GRAPH_JWKS_URL`; it loads trusted keys from
`SOCIAL_GRAPH_ATTESTERS_PATH`. Durable revocation state and automated rotation
are not implemented.

For the current runtime, operators must update the issuer's local trusted-key
file and coordinate attester key retirement manually. The following JWKS
refresh, rotation, and revocation lifecycle remains the intended future
contract:

1. Attester generates an Ed25519 keypair and publishes a new JWKS entry.
2. Issuer refreshes and caches trusted keys on
   `SOCIAL_GRAPH_KEY_REFRESH_INTERVAL` (default 1h).
3. Old keys remain valid until attestations signed with them expire.
4. Issuer checks published revoked `kid` values and local emergency
   revocations stored in `SOCIAL_GRAPH_STATE_PATH`.

## Open implementation notes

- The canonical JSON serialization must be deterministic across
  implementations (Rust `serde_json` with `BTreeMap` or sorted keys,
  TypeScript `json-stable-stringify` or equivalent)
- The `holder_commitment` is `SHA-256(controller_public_key_bytes)` —
  the issuer verifies this matches the Cred controller key that signed
  the presentation
- The `request_binding_hash` in the presentation is
  `SHA-256(request_binding_string)` where `request_binding_string` is
  the Freebird request binding (e.g.
  `freebird:issue:v1:{issuer_id}:{blinded_element_b64}`)
- The replay store key is `social_graph:jti:{attester_id}:{jti}` with
  TTL = `expires_at - current_time`
