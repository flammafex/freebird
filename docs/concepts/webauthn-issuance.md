# WebAuthn Issuance Admission

WebAuthn is an issuer admission/Sybil gate. It is not an anonymity mechanism,
and it is not proof that a person is globally unique or human.

## Implemented browser flow

When configured, the issuer serves `/webauthn/`, `/webauthn/register`, and
`/webauthn/authenticate`. Registration and authentication use the corresponding
`/start` and `/finish` endpoints. Authentication produces a short-lived proof:

```json
{
  "type": "webauthn",
  "subject_hash": "opaque-subject-hash",
  "auth_proof": "base64url-proof",
  "timestamp": 1777920000
}
```

The client supplies that object as `sybil_proof` to V4 or V7 issuance. The
proof is bound to an opaque hash of a deployment-local handle, not the label
itself, and accepted proofs are replay-protected.

## Required configuration

```bash
WEBAUTHN_RP_ID=issuer.example.org
WEBAUTHN_RP_ORIGIN=https://issuer.example.org
WEBAUTHN_PROOF_SECRET=<high-entropy-secret>
```

The origin must match the page origin and production should use HTTPS. The
issuer requires `WEBAUTHN_PROOF_SECRET` whenever WebAuthn is enabled.

Attestation is optional and policy-gated with
`WEBAUTHN_REQUIRE_ATTESTATION`, `WEBAUTHN_ATTESTATION_POLICY`, and optionally
`WEBAUTHN_ALLOWED_AAGUIDS`. Attestation can describe an authenticator or chain;
it does not establish unique-human status. See the [browser flow](../webauthn-browser-flow.md)
and [Sybil modes](../sybil-modes.md).
