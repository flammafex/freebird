# API documentation

Freebird has separate V4 issuer, verifier, and operator surfaces.

## Pages

- [HTTP API](http-api.md): bounded public verification and discovery routes,
  plus the distinction between public and admin surfaces.
- [TypeScript SDK](typescript-sdk.md): supported client flows and safe token
  handling.
- [Admin CLI](cli.md): issuer operator commands.
- [Configuration](configuration.md): the main settings needed for local and
  production deployments.

For a runnable local setup, see the [quick start](../quick-start.md). For
issuer operations, invitations, WebAuthn, vouching, and audit workflows, use
[Admin Operations](../admin-operations.md).

## Scope and compatibility

These pages intentionally cover the bounded API surface rather than reproduce
every internal or version-specific payload. Clients should use discovery and
the SDK where available, validate response shapes, and treat unsupported token
unsupported token families as rejected.
