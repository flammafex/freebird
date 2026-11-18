# Freebird browser client

This experimental browser ESM package obtains and redeems Freebird Privacy
Pass type-2 tokens. It is **private and unpublished**: use it from a git
checkout. It requires a secure browser context with Web Crypto and Fetch.

The package ships unbundled source. Install the exact peer dependency
`@cloudflare/privacypass-ts@0.9.0` in the consuming project and configure your
bundler to resolve it to one copy. For example, the repository's
[browser demo](../../demo/web/README.md) points esbuild at its own
`node_modules` when importing the package from the checkout.

## API

```js
// Relative to the root of the checkout; adjust the path in your application.
import { fetchWithToken } from './packages/freebird-client/src/index.mjs';

const response = await fetchWithToken(
  new URL('/private-token/protected', location.origin),
  { issuer: 'https://issuer.example', admission: code },
);
```

- **`fetchWithToken(url, { issuer, admission, init, ...options })`** returns a
  `Response`. It first requests the absolute protected URL without a token.
  On `401` with a valid `PrivateToken` challenge, it obtains one token and
  retries the same request once with `Authorization: PrivateToken token="…"`.
  A second `401` throws; other Origin responses are returned as-is.
  `init` supports `method`, `headers`, `body` (string or `Uint8Array`), and
  `signal` (for the protected requests). It cannot set `Authorization` or
  `Freebird-Admission`. Only use it when the Origin rejects unauthenticated
  requests before making any changes: a request with a body can be sent twice.
- **`obtainToken(challengeHeader, { issuer, admission, ...options })`** takes
  the full `WWW-Authenticate` header and returns the serialized token as a
  padded base64url string. It checks the issuer name (including port) and
  advertised type-2 key against the configured Issuer's directory before
  sending a blind-RSA issuance request. The issuance URI must stay on the
  configured Issuer's origin.
- **`authorizationHeader(token)`** formats that token as an `Authorization`
  header value for a caller-managed redemption.
- **`admissionFromPow(issuer, payload, options?)`** posts an already-solved
  ALTCHA payload to `/freebird/pow/admission` and returns one 43-character
  admission code. It does not run the solver itself.

`issuer` is an HTTPS origin, including any non-default port, without a path,
query, fragment, or credentials. `admission` is either a code string or a
function returning a code or a promise for one. The function is called at most
once, after the directory and challenge have been validated. Pass a function
if obtaining a code requires a user interaction or a server call.

Requests omit cookies and other ambient credentials, reject redirects, bypass
caches, and suppress referrers. Optional settings are `timeout` (milliseconds
per request; defaults to 30,000), `fetch` (defaults to the platform `fetch`),
and `allowInsecureLoopback` (allows HTTP on `127.0.0.1` only, for tests).
The token APIs also accept `onStage(stage)` with the credential-free phase
names `challenged`, `admitted`, and `issued`.

## Errors

Check the exported `FreebirdError` for `stage` (`directory`, `challenge`,
`admission`, `issuance`, or `access`), `reason` (`http`, `protocol`, `network`,
`timeout`, or `aborted`), and `status` when available. In particular:

| Status | Meaning |
| --- | --- |
| `403` | PoW proof or admission refused; obtain a fresh one. |
| `422` | Issuer key mismatch; fetch a fresh challenge before trying again. |
| `429` | Busy. `retryAfter`, when present, is the suggested wait in seconds. |
| `401` at `access` | The Origin refused the token. No further retry is made. |

`retryAfter` may also be set on `503`. When accessing an endpoint cross-origin,
the endpoint must expose `Retry-After` for the client to read it. Invalid caller
configuration throws `TypeError`; errors from caller-provided admission and
stage callbacks propagate.

## Security and testing

- Keep the application key **server-side only**, for example in the
  [server package](../freebird-server/README.md). Give the browser only an
  admission code. One code authorizes one issuance; a token is also single-use.
  If issuance fails, do not assume the code is still usable.
- Never log keys, admission codes, or tokens. Keep codes and tokens out of
  URLs, analytics, and browser storage. Use secure, configured Issuer and
  protected origins; do not derive these URLs from untrusted input.
- Configure the Issuer's CORS policy to allow your page's origin and the
  `Content-Type` and `Freebird-Admission` request headers. If the protected
  resource is cross-origin, it must allow `Authorization` and expose
  `WWW-Authenticate`.
- The pinned peer's transitive `sjcl` dependency is affected by
  [GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m), an
  elliptic-curve point validation issue. This client uses only the peer's
  public-verification RSA path. The dependency finding remains unresolved.

Run `node --test` here (the repository uses Node 26). Pure and mock-fetch
tests do not require an install. The blind-RSA flow tests reuse the peer
installed by the browser demo's pinned dependency install; they skip with an
explanation if the peer is unavailable. No install in this package is needed.
