# Admin CLI

The issuer package includes `freebird-cli`, a scriptable client for issuer
admin routes. It is an operator tool, not a replacement for the public issuance
or verifier APIs.

## Connection and authentication

Pass the issuer base URL and admin key explicitly:

```bash
cargo run -p freebird-issuer --bin freebird-cli -- \
  --url http://127.0.0.1:8081 \
  --key local-admin-key-must-be-at-least-32-chars \
  health
```

The same values can be supplied with `FREEBIRD_ISSUER_URL` and
`FREEBIRD_ADMIN_KEY`. Use a secret manager or protected environment in real
operations; do not commit keys or place them in shell history. The global
`--format` option supports `table`, `json`, and `compact` output.

## Commands

Run `freebird-cli --help` for the installed binary's exact help. The command
families currently include:

- `health`, `stats`, `config`, and `metrics`;
- `users list|get|ban|unban|bootstrap|register-owner`;
- `invites list|create|get|revoke|grant`;
- `vouching list|add|remove|submit|pending|clear-pending|mark-successful|mark-problematic`;
- `webauthn policy|stats|list|delete`;
- `keys list|rotate|cleanup`;
- `export users|invitations|audit`; and
- `audit`, with an optional `--limit`.

Examples:

```bash
cargo run -p freebird-issuer --bin freebird-cli -- \
  --url http://127.0.0.1:8081 --key "$FREEBIRD_ADMIN_KEY" \
  --format json config

cargo run -p freebird-issuer --bin freebird-cli -- \
  --url http://127.0.0.1:8081 --key "$FREEBIRD_ADMIN_KEY" \
  users list --limit 20 --offset 0
```

Commands mutate operator state or expose administrative data. Restrict the
admin network surface and follow [Admin Operations](../admin-operations.md) for
workflow semantics, audit implications, and route-level details.

## Configuration validation

The issuer package also provides `freebird-validate-config`. Run it against the
same environment and files that the issuer will use:

```bash
source .env
cargo run -p freebird-issuer --bin freebird-validate-config
```

It reports configuration, key, Sybil, optional WebAuthn, and optional HSM
checks. A successful validation is a preflight aid, not proof that a deployment
has a secure network boundary or a tested recovery plan.
