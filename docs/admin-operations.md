# Admin Operations

Freebird issuer admin routes are mounted under `/admin` for every Sybil mode.
They require `X-Admin-Key: <ADMIN_API_KEY>` or the admin session cookie created
by `POST /admin/login`.

Restrict `/admin` at the network layer for public deployments. The admin API is
an operational control plane, not a public user API.

## Invitation Workflows

Operators can manage invitation users and codes through HTTP:

| Action | Endpoint |
| --- | --- |
| List users | `GET /admin/users?limit=50&offset=0` |
| Inspect one user | `GET /admin/users/:user_id` |
| Add bootstrap user | `POST /admin/bootstrap/add` |
| Grant invite quota | `POST /admin/invites/grant` |
| Ban user or invite tree | `POST /admin/users/ban` |
| Unban user | `POST /admin/users/unban` |
| Create invitation codes | `POST /admin/invitations/create` |
| List invitation codes | `GET /admin/invitations` |
| Inspect invitation code | `GET /admin/invitations/:code` |
| Revoke pending invitation | `DELETE /admin/invitations/:code` |

Redeemed invitations are not deleted by the revocation endpoint. They remain in
state for accountability and invite graph inspection.

## Multi-Party Vouching

When `SYBIL_RESISTANCE=multi_party_vouching`, or a combined mode includes
`multi_party_vouching`, the admin API exposes voucher state:

| Action | Endpoint |
| --- | --- |
| List trusted vouchers | `GET /admin/vouching/vouchers` |
| Add trusted voucher public key | `POST /admin/vouching/vouchers` |
| Remove trusted voucher | `DELETE /admin/vouching/vouchers/:user_id` |
| Submit a vouch | `POST /admin/vouching/vouches` |
| List pending vouches | `GET /admin/vouching/pending` |
| Clear pending vouches for a user | `DELETE /admin/vouching/pending` |
| Mark vouched user successful | `POST /admin/vouching/mark-successful` |
| Mark vouched user problematic | `POST /admin/vouching/mark-problematic` |

Voucher public keys are P-256 SEC1 points encoded with base64url without
padding. Vouch signatures are P-256 ECDSA signatures over:

```text
vouch:<vouchee_id_hash>:<timestamp>
```

The server computes `vouchee_id_hash` with the configured multi-party vouching
salt and rejects vouches from unknown voucher keys.

## WebAuthn Workflows

WebAuthn operator routes are available even when the issuer binary was built
without the `human-gate-webauthn` feature. In that case they return disabled or
empty state rather than disappearing.

| Action | Endpoint |
| --- | --- |
| Show attestation and AAGUID policy | `GET /admin/webauthn/policy` |
| Show credential count | `GET /admin/webauthn/stats` |
| List credentials | `GET /admin/webauthn/credentials` |
| Delete credential | `DELETE /admin/webauthn/credentials/:cred_id` |

The WebAuthn AAGUID allowlist is configuration-managed through
`WEBAUTHN_ALLOWED_AAGUIDS`; operators can review the active allowlist through
`GET /admin/webauthn/policy`. Changing the allowlist requires changing
configuration and restarting the issuer.

## Audit Coverage

Admin flows write issuer audit entries for invite grants, user bans and unbans,
bootstrap user creation, owner registration, invitation creation, voucher
changes, vouch submission, pending vouch cleanup, and key rotation. Audit logs
are available through `GET /admin/audit` and `GET /admin/export/audit`.

