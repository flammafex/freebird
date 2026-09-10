# 🕊️ Freebird

**Self-hostable privacy-preserving token issuance and verification for civil-society web services**

From the token flow alone, a verifier cannot identify the originating blinded
issuance request. This is a token-layer property, not a claim that a verifier
cannot learn who a user is from accounts, network traffic, application data, or
operator-controlled metadata. A verifier can redeem a token once, prevent
replay, and enforce access rules without putting the issuance request in the
token presentation path.

Freebird is designed for cases where a service needs token-based admission while
keeping the issuance request separate from redemption. Identity, network,
application, and operational metadata remain outside this property and require
their own privacy controls.

## Why token-layer privacy?

Many services need to authorize an action without putting the blinded issuance
request in the verifier's token flow. Freebird separates issuance from
redemption: an issuer can enforce an admission policy, while a verifier checks a
token and rejects reuse. This does not prevent linkage through network traffic,
application accounts, timing, or operator logs.

## How it works

1. **User:** The client creates and blinds a private token request.
2. **Issuer:** The issuer checks configured admission requirements and evaluates
   the blinded request without learning the private token input.
3. **User:** The client unblinds and finalizes the result into a bearer token.
4. **Verifier:** The client presents the token; the verifier validates it and
   records its nullifier so a second presentation is rejected.

Freebird currently supports V4 private-verification tokens and V7 native bearer
tokens. The details and protocol boundaries are documented in
[Architecture](architecture/index.md).

## Quick start

For the shortest local path, use the repository's Docker Compose helper:

```bash
cp .env.example .env
V7_TOKEN_KEY_ID="$(openssl rand -hex 32)"
sed -i.bak "s|^NATIVE_BEARER_V7_TOKEN_KEY_ID=.*|NATIVE_BEARER_V7_TOKEN_KEY_ID=${V7_TOKEN_KEY_ID}|" .env
rm -f .env.bak
./launch.sh up
```

The generated ID replaces the `.env.example` placeholder with a real
64-character lowercase hexadecimal value. This is a development workflow, not
a production deployment profile.

See the [Quick Start](quick-start.md) for the complete Docker and source-build
commands.

## Current status

Freebird is **pre-1.0** and should be treated as experimental.
The project has not received an external security audit. Review the
[Security documentation](security/index.md) before making deployment or privacy
claims.

## Use cases

- Self-hosted access tokens for services that need token-based admission without
  putting issuance requests in the redemption flow.
- Admission-controlled communities using invitations, proof of work, WebAuthn,
  vouching, or other configured Sybil-resistance modes.
- Systems that need verifier-side single-use enforcement without placing the
  issuance request in the token presentation path.

These use cases do not establish proof of personhood, global bot resistance, or
protection from an operator that controls and correlates every surrounding
system.

## Security notice

Use HTTPS and production replay storage, protect issuer and verifier keys, and
read the [Threat Model](security/threat-model.md) before operating a public
service. V4 uses a Freebird-specific bespoke
P-256 VOPRF-like construction and is not RFC 9497 interoperable. Do not treat
this documentation as an audit or as a substitute for deployment review.

## Explore the documentation

- [Quick Start](quick-start.md) — run a local development deployment.
- [Architecture](architecture/index.md) — components, V4/V7 flows, metadata, and
  storage boundaries.
- [Security](security/index.md) — goals, assumptions, non-goals, and privacy
  limitations.
- [API](api/index.md) — public routes, configuration, CLI, and SDK reference.
