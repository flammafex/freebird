# Client Sybil Proofs

Freebird issuance accepts an optional `sybil_proof` object on V4 and V5 issuance
requests. If the issuer is configured with a Sybil mode, issuance requires a
matching proof.

The local `freebird-interface` binary can attach proofs in two ways:

```bash
cargo run -p freebird-interface -- --pow-difficulty 20
cargo run -p freebird-interface -- --sybil-proof-json proof.json
```

Environment variables are also supported:

```bash
FREEBIRD_ISSUER_URL=http://127.0.0.1:8081 \
FREEBIRD_VERIFIER_URL=http://127.0.0.1:8082 \
FREEBIRD_POW_DIFFICULTY=20 \
cargo run -p freebird-interface
```

## Proof Of Work

For single V4 issuance, the proof input is bound to the blinded request:

```text
freebird:issue:v1:<issuer_id>:<blinded_element_b64>
```

The interface computes this automatically when `--pow-difficulty` or
`FREEBIRD_POW_DIFFICULTY` is set.

## JSON Proof Input

`--sybil-proof-json` reads one JSON object matching the common `SybilProof`
schema. Examples:

```json
{
  "type": "invitation",
  "code": "invite-code",
  "signature": "base64url-signature"
}
```

```json
{
  "type": "webauthn",
  "username": "alice",
  "auth_proof": "base64url-proof",
  "timestamp": 1777920000
}
```

```json
{
  "type": "multi_party_vouching",
  "vouchee_id_hash": "hash",
  "vouches": [],
  "hmac_proof": "base64url-proof",
  "timestamp": 1777920000
}
```

For combined `and` or `threshold` modes, wrap proofs in:

```json
{
  "type": "multi",
  "proofs": []
}
```

## WebAuthn

WebAuthn proofs are produced by the issuer WebAuthn authentication flow. A
client should authenticate through `/webauthn/authentication/start` and
`/webauthn/authentication/finish`, then pass the returned proof as the
`webauthn` Sybil proof for issuance.

## Multi-Party Vouching

Vouching proofs are generated from server-side vouching state. Operators manage
trusted vouchers and pending vouches through `/admin/vouching/*`; clients submit
the final `multi_party_vouching` proof object during issuance.

