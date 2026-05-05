# Production Deployment

This is the recommended baseline for a public self-hosted Freebird deployment.
It is intentionally conservative.

## Required Services

- issuer
- verifier
- Redis for verifier nullifier storage
- Redis-backed issuer Sybil replay store
- reverse proxy with HTTPS
- persistent storage for issuer keys, key rotation state, invitation/vouching
  state, public bearer keys, and audit logs

## Minimum Environment

Use high-entropy secrets. Do not reuse the example values below.

```bash
ADMIN_API_KEY=<at-least-32-random-characters>
REQUIRE_TLS=true
BEHIND_PROXY=true

ISSUER_ID=issuer:example:v4
ISSUER_SK_PATH=/data/keys/issuer_sk.bin
KEY_ROTATION_STATE_PATH=/data/keys/key_rotation_state.json

VERIFIER_ID=verifier:example:v4
VERIFIER_AUDIENCE=example
ISSUER_URL=https://issuer.example.org/.well-known/issuer
VERIFIER_SK_PATH=/issuer-data/keys/issuer_sk.bin

REDIS_URL=redis://redis:6379
SYBIL_REPLAY_STORE=redis
SYBIL_REPLAY_REDIS_URL=redis://redis:6379

SYBIL_RESISTANCE=combined
SYBIL_COMBINED_MODE=and
SYBIL_COMBINED_MECHANISMS=pow,rate_limit
SYBIL_POW_DIFFICULTY=20
SYBIL_RATE_LIMIT=1h
```

For invitation-based deployments, persist the invitation state and signing key:

```bash
SYBIL_RESISTANCE=invitation
SYBIL_INVITE_PERSISTENCE_PATH=/data/state/invitations.json
SYBIL_INVITE_SIGNING_KEY_PATH=/data/keys/invitation_signing_key.bin
SYBIL_INVITE_BOOTSTRAP_USERS=admin:100
```

For multi-party vouching:

```bash
SYBIL_RESISTANCE=multi_party_vouching
SYBIL_MULTI_PARTY_VOUCHING_REQUIRED=3
SYBIL_MULTI_PARTY_VOUCHING_PERSISTENCE_PATH=/data/state/multi_party_vouching.json
SYBIL_MULTI_PARTY_VOUCHING_SECRET_PATH=/data/keys/multi_party_vouching_secret.bin
SYBIL_MULTI_PARTY_VOUCHING_SALT=<random-deployment-salt>
```

For WebAuthn:

```bash
SYBIL_RESISTANCE=webauthn
WEBAUTHN_RP_ID=issuer.example.org
WEBAUTHN_RP_ORIGIN=https://issuer.example.org
WEBAUTHN_PROOF_SECRET=<random-secret>
WEBAUTHN_ATTESTATION_POLICY=direct
WEBAUTHN_ALLOWED_AAGUIDS=<comma-separated-aaguids>
```

## Reverse Proxy

Expose public issuance and verification routes. Restrict `/admin` to an
operator VPN, private network, or trusted IP allowlist. `ADMIN_API_KEY` is still
required, but it should not be the only boundary.

Set:

```bash
REQUIRE_TLS=true
BEHIND_PROXY=true
```

The proxy must forward `X-Forwarded-Proto: https` and should forward the real
client IP only if the issuer trusts that proxy.

## Persistence

Back up:

- `issuer_sk.bin`
- `key_rotation_state.json`
- public bearer key and metadata files
- invitation signing key and state
- multi-party vouching secret and state
- audit log, if retained for operations
- Redis data or managed Redis backups

Losing verifier Redis data can allow already-spent tokens to be accepted again
until old tokens expire. Losing the issuer Sybil replay store can allow replay
of recently accepted PoW, WebAuthn, or vouching proofs. Use Redis persistence
for public deployments.

## Preflight

Run:

```bash
cargo run -p freebird-issuer --bin validate_config
cargo test --workspace
cargo test -p freebird-issuer --features human-gate-webauthn
```

Then exercise the deployed services:

```bash
freebird-cli --url https://issuer.example.org --key "$ADMIN_API_KEY" health
freebird-cli --url https://issuer.example.org --key "$ADMIN_API_KEY" config
cargo run -p freebird-interface -- \
  --issuer-url https://issuer.example.org \
  --verifier-url https://verifier.example.org \
  --pow-difficulty 20
```

