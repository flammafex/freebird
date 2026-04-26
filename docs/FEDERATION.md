# Issuer Trust

Freebird uses explicit issuer trust. A verifier accepts tokens only from issuer metadata URLs it is configured to trust.

This is intentionally minimal federation:

- no global issuer directory;
- no transitive trust graph;
- no token exchange between issuers;
- no redemption-time phone-home to the issuer;
- each verifier chooses its own issuer allowlist.

## Configuration

Configure trusted issuers with one URL or a comma-separated list:

```bash
ISSUER_URL=https://issuer.example.com/.well-known/issuer
ISSUER_URLS=https://issuer-a.example/.well-known/issuer,https://issuer-b.example/.well-known/issuer
```

The verifier fetches:

- `/.well-known/issuer` for issuer ID and active VOPRF metadata;
- `/.well-known/keys` for VOPRF key discovery and V5 public bearer key metadata.

## V4 Private Trust

V4 private verification requires explicit issuer trust plus private verification authority.

```bash
VERIFIER_SK_PATH=/run/secrets/issuer_sk.bin
# or:
VERIFIER_SK_B64=<base64url-raw-32-byte-key>
# or:
VERIFIER_KEYRING_B64='{"kid-a":"<base64url-key-a>","kid-b":"<base64url-key-b>"}'
```

The verifier recomputes the V4 authenticator locally. It does not ask the issuer whether a token is valid.

Use V4 when verifier-bound privacy matters more than easy public verification.

## V5 Public Trust

V5 public bearer verification requires explicit issuer trust plus valid public key metadata.

The issuer publishes public bearer keys in `/.well-known/keys`:

```json
{
  "public": [
    {
      "token_key_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "token_type": "public_bearer_pass",
      "rfc9474_variant": "RSABSSA-SHA384-PSS-Deterministic",
      "modulus_bits": 2048,
      "pubkey_spki_b64": "MIIB...",
      "issuer_id": "issuer:community:v4",
      "valid_from": 1760000000,
      "valid_until": 1762592000,
      "audience": "community.example",
      "spend_policy": "single_use"
    }
  ]
}
```

The verifier drops public keys unless:

- `token_type` is `public_bearer_pass`;
- `rfc9474_variant` is `RSABSSA-SHA384-PSS-Deterministic`;
- `spend_policy` is `single_use`;
- `token_key_id` is strict lowercase hex and equals `SHA-256(pubkey_spki)`;
- the SPKI parses as the declared RFC 9474 public key;
- the issuer ID matches the trusted issuer;
- the key is inside its validity window;
- optional `audience` matches the verifier audience.

Use V5 when public verification and simpler verifier deployment matter more than verifier-bound private verification.

## Multiple Issuers

A verifier can trust multiple issuers by configuring multiple URLs. Each issuer remains independent. A token is accepted only if its embedded issuer ID and key metadata match one configured issuer.

This lets self-hosted communities accept passes from partner communities without creating a global federation layer.
