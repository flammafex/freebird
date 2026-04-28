# Configuration Reference

Freebird is configured with environment variables. The issuer and verifier are separate services and should usually have separate environment files.

---

## Duration Format

Duration fields accept compact human-readable values:

| Example | Meaning |
|---------|---------|
| `30d` | 30 days |
| `24h` | 24 hours |
| `30m` | 30 minutes |
| `45s` | 45 seconds |
| `1d12h` | 1 day and 12 hours |
| `3600` | 3600 seconds |

## Issuer

### Core

```bash
ISSUER_ID=issuer:community:v4
BIND_ADDR=0.0.0.0:8081
REQUIRE_TLS=true
BEHIND_PROXY=true
ADMIN_API_KEY=<at-least-32-characters>
```

| Variable | Default | Description |
|----------|---------|-------------|
| `ISSUER_ID` | `issuer:freebird:v4` | Stable issuer identifier embedded in V4 and V5 tokens. |
| `BIND_ADDR` | `0.0.0.0:8081` | Issuer listen address. |
| `REQUIRE_TLS` | `false` | Reject non-HTTPS requests when behind a proxy that reports scheme. |
| `BEHIND_PROXY` | `false` | Trust proxy headers for client IP and scheme. |
| `ADMIN_API_KEY` | REQUIRED | Required for admin endpoints (≥32 characters). Both issuer and verifier fail to start without it. |

### V4 Private Option Keys

```bash
ISSUER_SK_PATH=/var/lib/freebird/keys/issuer_sk.bin
KEY_ROTATION_STATE_PATH=/var/lib/freebird/keys/key_rotation_state.json
EPOCH_DURATION=1d
EPOCH_RETENTION=2
```

| Variable | Default | Description |
|----------|---------|-------------|
| `ISSUER_SK_PATH` | `issuer_sk.bin` | Raw 32-byte P-256 VOPRF issuer key. Created if missing. |
| `KEY_ROTATION_STATE_PATH` | `key_rotation_state.json` | VOPRF key rotation state. |
| `KID` | derived | Optional key ID override. |
| `EPOCH_DURATION` | `1d` | Issuer key epoch duration. |
| `EPOCH_RETENTION` | `2` | Previous VOPRF epochs retained. |

### V5 Public Option Keys

V5 public bearer issuance is enabled by default.

```bash
PUBLIC_BEARER_ENABLE=true
PUBLIC_BEARER_SK_PATH=/var/lib/freebird/keys/public_bearer_sk.der
PUBLIC_BEARER_METADATA_PATH=/var/lib/freebird/keys/public_bearer_metadata.json
PUBLIC_BEARER_VALIDITY=30d
PUBLIC_BEARER_MODULUS_BITS=2048
# Optional audience binding:
PUBLIC_BEARER_AUDIENCE=community.example
```

| Variable | Default | Description |
|----------|---------|-------------|
| `PUBLIC_BEARER_ENABLE` | `true` | Enables `/v1/public/issue` and public key metadata. |
| `PUBLIC_BEARER_SK_PATH` | `public_bearer_sk.der` | DER RSA private key for RFC 9474 blind signatures. Created if missing. |
| `PUBLIC_BEARER_METADATA_PATH` | `public_bearer_metadata.json` | Immutable V5 public key metadata. Created with the key. |
| `PUBLIC_BEARER_VALIDITY` | `30d` | Validity window for newly generated V5 metadata. |
| `PUBLIC_BEARER_AUDIENCE` | unset | Optional audience restriction for V5 verifiers. |
| `PUBLIC_BEARER_MODULUS_BITS` | `2048` | RSA modulus size. Accepted range is 2048 to 4096. |

Metadata is intentionally immutable for a key. To change `audience`, `spend_policy`, validity, or key parameters, rotate the V5 public bearer key and metadata together.

## Verifier

### Core

```bash
BIND_ADDR=0.0.0.0:8082
ISSUER_URL=https://issuer.example.com/.well-known/issuer
VERIFIER_ID=verifier:community:v4
VERIFIER_AUDIENCE=community.example
REFRESH_INTERVAL_MIN=10
REDIS_URL=redis://redis:6379
```

| Variable | Default | Description |
|----------|---------|-------------|
| `BIND_ADDR` | `0.0.0.0:8082` | Verifier listen address. |
| `ISSUER_URL` | `http://127.0.0.1:8081/.well-known/issuer` | Trusted issuer metadata URL. |
| `ISSUER_URLS` | unset | Comma-separated trusted issuer metadata URLs. |
| `VERIFIER_ID` | required | Stable verifier scope ID for V4. |
| `VERIFIER_AUDIENCE` | `VERIFIER_ID` | Audience for V4 scope and V5 audience checks. |
| `REFRESH_INTERVAL_MIN` | `10` | Issuer metadata refresh interval. |
| `REDIS_URL` | unset | Redis replay store. If unset, verifier uses in-memory replay storage. |

### V4 Private Verification

```bash
VERIFIER_SK_PATH=/run/secrets/issuer_sk.bin
# or:
VERIFIER_SK_B64=<base64url-raw-32-byte-key>
# or:
VERIFIER_KEYRING_B64='{"kid-a":"<base64url-key-a>","kid-b":"<base64url-key-b>"}'
```

| Variable | Description |
|----------|-------------|
| `VERIFIER_SK_PATH` | Raw 32-byte private verification key file. |
| `VERIFIER_SK_B64` | Base64url raw 32-byte private verification key. |
| `VERIFIER_KEYRING_B64` | JSON object mapping V4 `kid` values to base64url raw keys. |

V4 verification fails if the verifier trusts issuer metadata but has no matching private verification key.

### V5 Public Verification

No verifier secret is required for V5. The verifier fetches public bearer key metadata from the trusted issuer's `/.well-known/keys` endpoint.

The verifier accepts a V5 public key only when:

- `token_type = "public_bearer_pass"`;
- `rfc9474_variant = "RSABSSA-SHA384-PSS-Deterministic"`;
- `spend_policy = "single_use"`;
- `token_key_id = SHA-256(pubkey_spki)`;
- optional `audience` matches `VERIFIER_AUDIENCE`;
- the key is inside its validity window.

## Sybil Resistance

```bash
SYBIL_RESISTANCE=invitation
```

Supported modes:

| Mode | Purpose |
|------|---------|
| `none` | Local development only. |
| `invitation` | Invite-based community growth. |
| `pow` or `proof_of_work` | Permissionless computational cost. |
| `rate_limit` | Simple time-based throttling. |
| `progressive_trust` | Increasing quota with account age. |
| `proof_of_diversity` | Multi-signal diversity score. |
| `multi_party_vouching` | Peer vouching. |
| `webauthn` | Hardware-backed proof of humanity when built with WebAuthn support. |
| `combined` | Combine multiple mechanisms. |

### Invitation

```bash
SYBIL_INVITE_PER_USER=5
SYBIL_INVITE_COOLDOWN=1h
SYBIL_INVITE_EXPIRES=30d
SYBIL_INVITE_NEW_USER_WAIT=30d
SYBIL_INVITE_PERSISTENCE_PATH=/var/lib/freebird/invitations.json
SYBIL_INVITE_AUTOSAVE_INTERVAL=5m
SYBIL_INVITE_SIGNING_KEY_PATH=/var/lib/freebird/invitation_signing_key.bin
SYBIL_INVITE_BOOTSTRAP_USERS=admin:100
```

### Proof of Work and Rate Limit

```bash
SYBIL_POW_DIFFICULTY=20
SYBIL_RATE_LIMIT=1h
```

### Progressive Trust

```bash
SYBIL_PROGRESSIVE_TRUST_LEVELS=0:1:1d,30d:10:1h,90d:100:1m
SYBIL_PROGRESSIVE_TRUST_PERSISTENCE_PATH=/var/lib/freebird/progressive_trust.json
SYBIL_PROGRESSIVE_TRUST_AUTOSAVE=5m
SYBIL_PROGRESSIVE_TRUST_SECRET_PATH=/var/lib/freebird/progressive_trust_secret.bin
SYBIL_PROGRESSIVE_TRUST_SALT=<random-salt>
```

### Proof of Diversity

```bash
SYBIL_PROOF_OF_DIVERSITY_MIN_SCORE=40
SYBIL_PROOF_OF_DIVERSITY_PERSISTENCE_PATH=/var/lib/freebird/proof_of_diversity.json
SYBIL_PROOF_OF_DIVERSITY_AUTOSAVE=5m
SYBIL_PROOF_OF_DIVERSITY_SECRET_PATH=/var/lib/freebird/proof_of_diversity_secret.bin
SYBIL_PROOF_OF_DIVERSITY_SALT=<random-salt>
```

### Multi-Party Vouching

```bash
SYBIL_MULTI_PARTY_VOUCHING_REQUIRED=3
SYBIL_MULTI_PARTY_VOUCHING_COOLDOWN=1h
SYBIL_MULTI_PARTY_VOUCHING_EXPIRES=30d
SYBIL_MULTI_PARTY_VOUCHING_NEW_USER_WAIT=30d
SYBIL_MULTI_PARTY_VOUCHING_PERSISTENCE_PATH=/var/lib/freebird/multi_party_vouching.json
SYBIL_MULTI_PARTY_VOUCHING_AUTOSAVE=5m
SYBIL_MULTI_PARTY_VOUCHING_SECRET_PATH=/var/lib/freebird/multi_party_vouching_secret.bin
SYBIL_MULTI_PARTY_VOUCHING_SALT=<random-salt>
```

### Combined

```bash
SYBIL_RESISTANCE=combined
SYBIL_COMBINED_MECHANISMS=pow,rate_limit,invitation
SYBIL_COMBINED_MODE=threshold
SYBIL_COMBINED_THRESHOLD=2
```

`SYBIL_COMBINED_MODE` can be `or`, `and`, or `threshold`.

## Logging

```bash
RUST_LOG=info,freebird=debug
LOG_FORMAT=plain
```

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Standard Rust tracing filter. |
| `LOG_FORMAT` | `plain` | `plain` or `json`. |

## Example Development Config

Issuer:

```bash
ISSUER_ID=issuer:dev:v4
BIND_ADDR=127.0.0.1:8081
REQUIRE_TLS=false
SYBIL_RESISTANCE=none
ISSUER_SK_PATH=issuer_sk.bin
KEY_ROTATION_STATE_PATH=key_rotation_state.json
PUBLIC_BEARER_ENABLE=true
PUBLIC_BEARER_SK_PATH=public_bearer_sk.der
PUBLIC_BEARER_METADATA_PATH=public_bearer_metadata.json
```

Verifier:

```bash
BIND_ADDR=127.0.0.1:8082
ISSUER_URL=http://127.0.0.1:8081/.well-known/issuer
VERIFIER_ID=verifier:dev:v4
VERIFIER_AUDIENCE=dev
VERIFIER_SK_PATH=issuer_sk.bin
```

## Example Production Notes

- Use TLS and set `REQUIRE_TLS=true`.
- Use Redis for verifier replay storage.
- Store issuer and verifier secrets in a secret manager or mounted secret files.
- Keep issuer and verifier logs separate.
- Rotate V4 and V5 keys intentionally; V5 metadata changes require a new V5 key.
- Configure `PUBLIC_BEARER_AUDIENCE` when V5 tokens should be accepted only by a specific verifier audience.
