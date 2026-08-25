# API documentation

Freebird has separate issuer, verifier, and operator surfaces. The current
protocol compatibility set is V4 private-verification tokens and V7 native
bearer tokens. Retired V5 and V2 flows, and reserved V6, are not current APIs.

## Pages

- [HTTP API](http-api.md): bounded public verification and discovery routes,
  plus the distinction between public and admin surfaces.
- [TypeScript SDK](typescript-sdk.md): supported client flows and safe token
  handling.
- [Admin CLI](cli.md): issuer operator commands.
- [Configuration](configuration.md): the main settings needed for local and
  production deployments.

For a runnable local setup, see the [quick start](../quick-start.md). For
version-specific issuer operations, invitations, WebAuthn, vouching, and audit
workflows, use [Admin Operations](../admin-operations.md). The detailed V7
exchange contract is documented separately in [Public Bearer
Exchange](../public-bearer-exchange.md).

## Scope and compatibility

These pages intentionally cover the bounded API surface rather than reproduce
every internal or version-specific payload. Clients should use discovery and
the SDK where available, validate response shapes, and treat unsupported token
families as rejected. Do not infer an API from an old V2/V5 example.
