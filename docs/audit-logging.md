# Audit Logging

Freebird includes operational audit logging for issuer admin activity. Audit
logs help operators understand administrative changes, but they are not
tamper-evident security logs.

## Storage

The issuer initializes an audit log at startup with:

- path: `audit_log.json`
- maximum entries: `10000`
- autosave interval: `60` seconds

The audit log is stored as local JSON. The file should be on protected
persistent storage. Back it up if audit history matters for your deployment.

## Entry Fields

Each audit entry can contain:

- `timestamp`: Unix timestamp
- `level`: `info`, `warning`, `error`, or `success`
- `action`: event name
- `user_id`: optional user identifier
- `details`: optional free-form details
- `admin_id`: optional admin identifier

The current audit log can contain operational identifiers, invite data, user
IDs, and administrative details. Treat exported audit files as sensitive.

## Events

Issuer admin routes currently log events such as:

- invite grants
- user bans
- user unbans
- bootstrap user creation
- owner registration
- invitation creation
- voucher addition and removal
- vouch submission
- pending vouch cleanup
- key rotation

WebAuthn attestation handling can also log attestation details through tracing
when `WEBAUTHN_AUDIT_LOGGING` is enabled. When Redis is configured for WebAuthn,
registration audit metadata is stored under `webauthn:audit:*` with a longer
TTL for audit review.

## Admin Access

Audit logs are available through issuer admin endpoints, including list and
export routes. Admin routes require `ADMIN_API_KEY` or an admin session cookie,
but public deployments should also restrict admin route network access.

## Privacy Guidance

Operators should decide and document:

- how long audit logs are retained
- who can access audit exports
- whether audit files are encrypted at rest
- whether reverse-proxy logs duplicate IP or account metadata
- how incident reports are handled

Audit logs should not be used to correlate token issuance and redemption unless
that is an explicit property of the application using Freebird. The token layer
is designed for unlinkability, but surrounding logs can still create linkage.

## Current Limitations

- Audit JSON is not append-only or tamper-evident.
- Local file writes are process-local.
- Retention is count-based, not time-based.
- WebAuthn audit metadata and issuer audit entries are separate paths.
- A deployment-specific privacy policy is still required before public use.
