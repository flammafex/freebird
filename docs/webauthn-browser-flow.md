# WebAuthn Browser Flow

When the issuer is built with `--features human-gate-webauthn`, it serves a
browser client at:

```text
/webauthn/
/webauthn/register
/webauthn/authenticate
```

The page uses the browser WebAuthn API to:

- register a passkey through `/webauthn/register/start` and
  `/webauthn/register/finish`
- authenticate through `/webauthn/authenticate/start` and
  `/webauthn/authenticate/finish`
- hand a short-lived `SybilProof::WebAuthn` object to the requesting client

## Required Origin

WebAuthn only works on a secure origin. Configure:

```bash
WEBAUTHN_RP_ID=issuer.example.org
WEBAUTHN_RP_ORIGIN=https://issuer.example.org
WEBAUTHN_PROOF_SECRET=<high-entropy-secret>
```

`WEBAUTHN_RP_ORIGIN` must exactly match the browser origin serving the page.
Localhost can work for local development, but production should use HTTPS.

## Proof Output

After authentication, the page emits:

```json
{
  "type": "webauthn",
  "subject_hash": "opaque-subject-hash",
  "auth_proof": "base64url-proof",
  "timestamp": 1777920000
}
```

Use that object as the issuance request `sybil_proof`. In the normal browser
flow the user does not see the proof. The page hands it to the requesting client
by:

- `postMessage` when opened by another window
- `return_to` callback URL fragment when provided, so proof material is not sent
  to the callback server in the HTTP request line
- developer-only proof JSON display when no requesting client is present

WebAuthn proofs are short-lived and replay-protected, so clients should
authenticate immediately before requesting a token.

## Local Labels

Registration asks for a local handle and optional passkey label. These are
usability labels for the browser/passkey manager. They should be pseudonymous
and deployment-local, not real names, email addresses, phone numbers, or public
handles.

The issuer stores and verifies against an opaque subject hash derived from the
local handle. Issuance proofs contain the subject hash, not the local label.

## Attestation Policy

Hardware/device attestation is optional and policy-driven. To require it:

```bash
WEBAUTHN_REQUIRE_ATTESTATION=true
WEBAUTHN_ATTESTATION_POLICY=direct
WEBAUTHN_ALLOWED_AAGUIDS=<comma-separated-aaguids>
```

An allowlist can restrict registration to specific authenticator models. Without
that policy, WebAuthn proves possession of a registered credential, not that the
credential lives on approved hardware.
