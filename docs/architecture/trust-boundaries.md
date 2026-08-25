# Trust Boundaries

The current architecture has these boundaries:

- **Client ↔ issuer**: the issuer sees the blinded request, admission proof,
  and HTTP metadata; it must protect keys and admission state.
- **Client ↔ verifier**: the verifier sees the presented token and redemption
  request metadata; it consumes replay state.
- **Issuer ↔ verifier discovery**: the verifier trusts fully validated issuer
  metadata according to configured URLs and TLS policy.
- **Admin client ↔ service**: admin routes require the configured admin
  credential and should have network controls in addition to the credential.
- **Service ↔ Redis/local persistence**: replay, credentials, operation records,
  and key-related state depend on storage confidentiality, integrity, and
  durability.
- **Optional attester ↔ issuer/client**: the Social Graph Attester sees graph
  evidence; the issuer trusts configured attester keys and signed presentations,
  not the raw graph analysis.

TLS termination, proxy forwarding, and log retention can change these practical
boundaries. Set `REQUIRE_TLS=true` in production and set `BEHIND_PROXY=true`
only behind a trusted proxy with correct forwarded-header configuration.

These boundaries do not guarantee anonymity against a party controlling both
issuer and verifier or correlating timing and network metadata. See the [threat
model](../threat-model.md) and [production baseline](../production-deployment.md).
