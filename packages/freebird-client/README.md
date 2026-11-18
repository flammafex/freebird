# The Freebird browser package obtains and redeems type-2 tokens

This experimental ESM package obtains and redeems Freebird Privacy Pass type-2
tokens in a secure browser context with Web Crypto and Fetch. Use the package
from a Git checkout because it is **private and unpublished**.

The package ships unbundled source. Install the exact peer dependency
`@cloudflare/privacypass-ts@0.9.0` in your project and configure your bundler
to resolve it to one copy. The repository's [demo build](../../demo/web/README.md)
uses esbuild with its own `node_modules` to resolve the dependency for imports
from the checkout.

## One call obtains a token and retries a challenged request

Import `fetchWithToken` to request a protected resource.

```js
// Relative to the root of the checkout; adjust the path in your application.
import { fetchWithToken } from './packages/freebird-client/src/index.mjs';

const response = await fetchWithToken(
  new URL('/private-token/protected', location.origin),
  { issuer: 'https://issuer.example', admission: code },
);
```

The package provides four functions for requesting resources, obtaining tokens,
formatting authorization headers, and requesting admission codes.

- Call **`fetchWithToken(url, { issuer, admission, init, ...options })`** to
  request an absolute protected URL and get a `Response`. The first request
  has no token. On `401` with a valid `PrivateToken` challenge, the function
  obtains one token and retries once with `Authorization: PrivateToken token="…"`.
  A second `401` throws. Other Origin responses are returned unchanged.
  `init` accepts `method`, `headers`, `body`, and `signal`. Pass a string or
  `Uint8Array` as `body`. The `signal` applies to the protected requests. The
  headers in `init` cannot include `Authorization` or `Freebird-Admission`.
  Use this function only if the Origin rejects unauthenticated requests
  before making changes, because a request with a body can be sent twice.
- Call **`obtainToken(challengeHeader, { issuer, admission, ...options })`**
  with the full `WWW-Authenticate` header to get a serialized token as a
  padded base64url string. Before sending the blind-RSA issuance request, the
  function checks the issuer name and the advertised type-2 key against the
  configured Issuer's directory. The issuer name check includes the port.
  The issuance URI must stay on the configured Issuer's origin.
- Call **`authorizationHeader(token)`** to format an `Authorization` header
  value when your code handles redemption.
- Call **`admissionFromPow(issuer, payload, options?)`** to exchange an ALTCHA
  solution for one 43-character admission code. The function posts the
  payload to `/freebird/pow/admission`. Solve the proof before calling it.

Pass the HTTPS origin as `issuer`, including any non-default port. Omit the
path, query, fragment, and credentials. Pass an admission code as a string
or a function that returns a code or a promise for one. Use a function if
obtaining a code requires user interaction or a server call. The function is
called at most once, after the directory and challenge have been validated.

Requests omit cookies and other ambient credentials, reject redirects, bypass
caches, and suppress referrers. Set `timeout` to change the per-request limit
from the default of 30,000 milliseconds. Set `fetch` to supply an
implementation other than the platform `fetch`. For tests, set
`allowInsecureLoopback` to allow HTTP on `127.0.0.1` only. The token APIs
accept `onStage(stage)` and pass it the credential-free names `challenged`,
`admitted`, and `issued`.

## Errors identify the failed stage and reason

Check the exported `FreebirdError` for `stage` and `reason`, and for `status`
when available. The `stage` can be `directory`, `challenge`, `admission`,
`issuance`, or `access`. The `reason` can be `http`, `protocol`, `network`,
`timeout`, or `aborted`. HTTP status codes distinguish the following cases.

| Status | Meaning |
| --- | --- |
| `403` | The proof of work or admission code was refused. Obtain a fresh one. |
| `422` | The Issuer key does not match. Fetch a fresh challenge before trying again. |
| `429` | The service is busy. If `retryAfter` is present, it gives the suggested wait in seconds. |
| `401` at `access` | The Origin refused the token. No further retry is made. |

The `retryAfter` property can also be set on `503`. A cross-origin endpoint
must expose `Retry-After` for the client to read it. Invalid caller
configuration throws `TypeError`. Errors from admission and stage callbacks
that you provide propagate to the caller.

## Configured origins control where credentials are sent

Keep the application key on the server and configure the browser to use
trusted origins.

- Keep the **application key on the server**, for example by using the
  [server package](../freebird-server/README.md). Give the browser only an
  admission code. One code authorizes one issuance, and each token can be
  redeemed once. If issuance fails, do not assume that the code is still usable.
- Keep **keys, admission codes, and tokens** out of logs. Keep admission codes
  and tokens out of URLs, analytics, and browser storage. Use secure, configured
  Issuer and protected origins. Do not derive them from untrusted input.
- Configure **CORS** on the Issuer to allow the page's origin and the
  `Content-Type` and `Freebird-Admission` request headers. If the protected
  resource is cross-origin, configure it to allow `Authorization` and expose
  `WWW-Authenticate`.

The pinned peer's transitive `sjcl` dependency is affected by
[GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m), which
concerns elliptic-curve point validation. The client uses only the peer's
public-verification RSA path, but the dependency finding remains unresolved.

## The blind-RSA tests run when the pinned peer is available

Run `node --test` in this directory. The repository uses Node 26. The pure
tests and tests with mocked `fetch` require no dependency install. The
blind-RSA flow tests reuse the peer from the demo's pinned dependency install.
They skip with an explanation if the peer is unavailable. You do not need to
install dependencies in this package.
