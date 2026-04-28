# Troubleshooting

Common checks for Freebird issuer and verifier deployments.

---

## Quick Diagnostics

```bash
# Issuer metadata
curl http://localhost:8081/.well-known/issuer
curl http://localhost:8081/.well-known/keys

# Verifier metadata
curl http://localhost:8082/.well-known/verifier

# Redis, if configured
redis-cli ping
```

Verifier endpoints expect only `token_b64`:

```bash
curl -X POST http://localhost:8082/v1/check \
  -H "Content-Type: application/json" \
  -d '{"token_b64":"<base64url-token>"}'
```

## Startup Failures

These errors prevent the issuer or verifier from starting and appear in the first few log lines.

### ADMIN_API_KEY Not Set

**Error:** `ADMIN_API_KEY must be set (minimum 32 characters)`

**Cause:** The `ADMIN_API_KEY` environment variable is missing. Both the issuer and verifier require it to protect the admin API and dashboard.

**Resolution:**

```bash
# Generate a secure key (48 base64 chars = 36 bytes raw)
export ADMIN_API_KEY=$(openssl rand -base64 48)
```

Add the value to your `.env` file. See [CONFIGURATION.md](CONFIGURATION.md) for details.

### ADMIN_API_KEY Too Short

**Error:** `ADMIN_API_KEY must be at least 32 characters, got N`

**Cause:** `ADMIN_API_KEY` is set but shorter than 32 characters.

**Resolution:** Regenerate a longer key:

```bash
export ADMIN_API_KEY=$(openssl rand -base64 48)
```

### WebAuthn Proof Secret Missing

**Error:** `WEBAUTHN_PROOF_SECRET must be set when WebAuthn is enabled`

**Cause:** The issuer has WebAuthn Sybil resistance enabled but `WEBAUTHN_PROOF_SECRET` is not configured. The secret is required to sign WebAuthn proof tokens.

**Resolution:**

```bash
export WEBAUTHN_PROOF_SECRET=$(openssl rand -base64 48)
```

Add it to your `.env` and restart the issuer.

### Key Rotation Grace Period Too Short

**Error:** `grace period must be at least 3600 seconds (got N)`

**Cause:** A key rotation was requested with a grace period shorter than the minimum of 3600 seconds (1 hour). Deprecated keys must remain valid long enough for in-flight tokens to reach verifiers.

**Resolution:** Use a grace period of at least 3600 seconds:

```bash
# Via CLI
freebird-cli keys rotate --grace-period 3600

# Or via the admin API
 curl -X POST http://localhost:8081/admin/keys/rotate \
   -H "X-Admin-Key: $ADMIN_API_KEY" \
   -H "Content-Type: application/json" \
   -d '{"grace_period_sec":3600}'
```

### Verifier Issuer URL Not HTTPS

**Error:** `issuer metadata URL must use HTTPS: {url}`

**Cause:** The verifier is configured with an HTTP issuer URL. In hardened configurations the verifier refuses to fetch issuer metadata over plain HTTP.

**Resolution:** Change `ISSUER_URL` (or `ISSUER_URLS`) to use HTTPS:

```bash
export ISSUER_URL=https://issuer.example.com/.well-known/issuer
```

## Issuer Issues

### Address Already In Use

```bash
lsof -i :8081
export BIND_ADDR=127.0.0.1:9081
```

### Failed To Load V4 Issuer Key

Check the VOPRF key path:

```bash
ls -la "$ISSUER_SK_PATH"
chmod 600 "$ISSUER_SK_PATH"
```

If the local development key is corrupted, stop the issuer, move the file aside, and start again so a new key can be generated.

### Failed To Load V5 Public Bearer Key

Check the RSA blind-signature key and metadata:

```bash
ls -la "$PUBLIC_BEARER_SK_PATH" "$PUBLIC_BEARER_METADATA_PATH"
jq . "$PUBLIC_BEARER_METADATA_PATH"
```

The metadata must match the key. If you need to change V5 audience, validity, or key policy, rotate the V5 key and metadata together.

### Public Bearer Issuance Disabled

Check:

```bash
echo "$PUBLIC_BEARER_ENABLE"
```

`PUBLIC_BEARER_ENABLE=false` disables `/v1/public/issue`.

### Sybil Proof Required

The issuer has a Sybil mechanism enabled and the request did not include `sybil_proof`.

For local testing:

```bash
SYBIL_RESISTANCE=none
```

For real deployments, send the proof required by the configured mechanism.

## Verifier Issues

### Failed To Load Issuer Metadata

Check the trusted issuer URL:

```bash
echo "$ISSUER_URL"
curl -v "$ISSUER_URL"
```

The verifier also derives `/.well-known/keys` from the issuer metadata URL. Make sure both endpoints are reachable.

### V4 Tokens Always Fail

V4 requires matching private verification key material.

Check:

```bash
echo "$VERIFIER_SK_PATH"
echo "$VERIFIER_SK_B64"
echo "$VERIFIER_KEYRING_B64"
```

The key must correspond to the issuer VOPRF public key and the token `kid`. If the issuer rotated keys, update `VERIFIER_KEYRING_B64` or the mounted secret.

### V5 Tokens Always Fail

Check public key metadata:

```bash
curl http://localhost:8081/.well-known/keys | jq '.public'
```

The verifier drops V5 public keys unless:

- `token_type` is `public_bearer_pass`;
- `rfc9474_variant` is `RSABSSA-SHA384-PSS-Deterministic`;
- `spend_policy` is `single_use`;
- `token_key_id` matches `SHA-256(pubkey_spki)`;
- the key is inside its validity window;
- optional key `audience` matches `VERIFIER_AUDIENCE`.

### Token Already Used

Freebird tokens are single-use. A second `/v1/verify` for the same token should fail.

Use `/v1/check` when you need non-consuming validation.

### Replay Store Lost

If Redis data is lost, previously spent tokens may become spendable again.

Mitigations:

- restore Redis from backup when possible;
- rotate issuer keys if replay state loss is severe;
- prefer Redis persistence in production.

### Failed To Connect To Redis

```bash
redis-cli ping
echo "$REDIS_URL"
```

If Redis requires a password:

```bash
REDIS_URL=redis://:PASSWORD@redis.example.com:6379
```

## Network And TLS

### Connection Refused

```bash
systemctl status freebird-issuer
systemctl status freebird-verifier
netstat -tulpn | grep -E '8081|8082'
```

Make sure `BIND_ADDR` matches how the service is reached.

### TLS Errors

```bash
openssl s_client -connect issuer.example.com:443 -showcerts
curl -v https://issuer.example.com/.well-known/issuer
```

Use valid certificates in production.

## Performance

### Slow Issuance

Possible causes:

- expensive Sybil mechanism;
- CPU saturation;
- large batches;
- RSA key generation during first V5 startup.

Checks:

```bash
top -p "$(pgrep freebird-issuer)"
journalctl -u freebird-issuer -n 100
```

### Slow Verification

Possible causes:

- Redis latency;
- public RSA verification cost for V5;
- high replay-store contention.

Checks:

```bash
redis-cli --latency
top -p "$(pgrep freebird-verifier)"
```

## Logs

Enable more detail:

```bash
RUST_LOG=debug,freebird=trace
```

Do not log token bodies, blinded messages, blind signatures, or private keys.

## Common Configuration Mistakes

- `ISSUER_URL` points at the wrong issuer.
- `VERIFIER_ID` or `VERIFIER_AUDIENCE` changed after V4 tokens were issued.
- `VERIFIER_SK_PATH` points at the wrong V4 issuer key.
- V5 `PUBLIC_BEARER_METADATA_PATH` does not match `PUBLIC_BEARER_SK_PATH`.
- `PUBLIC_BEARER_AUDIENCE` is set to a different value than verifier `VERIFIER_AUDIENCE`.
- Redis is omitted in production, causing replay records to disappear on restart.
