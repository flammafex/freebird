# Integrating an application

**Experimental, not a production service.** This guide shows how an
application puts Freebird in front of its own routes without implementing
Privacy Pass itself. It assumes the [single-host deployment](deployment.md) and
[admission for application servers](app-admission.md).

There are three pieces, and the application writes almost none of the
cryptography:

1. **nginx checks tokens** for the application's protected routes, using
   Freebird's Origin. The application only receives requests that carried a
   valid, unspent token.
2. **The application server requests admission codes** for the users its own
   policy approves, with `packages/freebird-server`.
3. **The browser obtains and spends tokens** with `packages/freebird-client`.

```text
browser ──► nginx ──auth_request──► Freebird Origin (checks + spends token)
   │          └──► your application (only if the token was accepted)
   │
   ├──► your application server ──► Freebird Issuer /freebird/app/admission
   │      (your policy decides)       (returns one admission code)
   └──► Freebird Issuer /private-token/issue (code + blinded request → token)
```

## 1. Protect routes with nginx

The nginx template ends with a commented **application protection example**
between `BEGIN app-protection example` and `END app-protection example`. Copy
those locations into the server block that serves your application and adapt
the upstream address. Each protected location:

- sends an internal `auth_request` subrequest to the Origin's
  `/private-token/protected` route, forwarding only `Authorization` and the
  nginx-chosen `Freebird-Scope`;
- lets the request through to your application only if the Origin answers 200,
  having verified and spent the token;
- returns the Origin's 401 and `WWW-Authenticate: PrivateToken …` challenge to
  the browser otherwise, without contacting your application;
- strips `Authorization` and `Freebird-Scope` before proxying to your
  application. The token is already spent and the application never needs it.

nginx's `auth_request` module must be present (`nginx -V 2>&1 | grep
auth_request`); Ubuntu's packaged nginx includes it.

### Binding tokens to one resource (scope)

By default a token works on any protected route of the Origin. To bind tokens
to one resource, such as a ballot, pool or thread, the internal auth location
sets `Freebird-Scope` to a value derived from the request. The template's
`/ballot/` example derives `ballot:<id>` from the query string. A token
obtained for `ballot:1` is refused at `ballot:2` and at unscoped routes, and the
browser receives a fresh challenge for the right scope.

- The scope is set **only by nginx**. A `Freebird-Scope` header sent by the
  client is never forwarded. The Origin trusts this header only because it
  listens on loopback behind nginx; never expose the Origin's port directly.
- Scopes are 1–128 visible ASCII characters. An empty value means unscoped. Two
  headers or an invalid value return 400.
- **Allowlist scope values in nginx** rather than copying arbitrary client
  input: every distinct scope creates challenge records for the hour. The
  template's example fails closed with 403 for identifiers outside its list.

Technically the scope is mixed into the challenge's redemption context, which
is derived from the Origin's secret, the hour and the scope. No new
cryptography is involved, and unscoped challenges are byte-for-byte unchanged.

## 2. Request admission codes from your server

Register the application once (`app-add`, see
[admission for application servers](app-admission.md)) and keep its key in the
server's secret store. When your own policy approves a user, request one code:

```js
import { requestAdmission } from '../path/to/freebird/packages/freebird-server/src/index.mjs';

const code = await requestAdmission({
  issuer: 'https://issuer.example.org',
  key: process.env.FREEBIRD_APP_KEY,
});
// Send `code` to that one user over your authenticated session. Never log it.
```

At the daily cap it throws an error with `status` 429 and `retryAfter` (seconds
until the next UTC midnight). A revoked or wrong key gives 401.

Each code buys exactly one token. Hand it to one user, and fetch it only when
that user is about to need a token: codes expire after 24 hours.

## 3. Obtain and spend a token in the browser

```js
import { fetchWithToken } from '../path/to/freebird/packages/freebird-client/src/index.mjs';

const response = await fetchWithToken('https://app.example.org/ballot/?ballot=1', {
  issuer: 'https://issuer.example.org',
  // Called at most once, only after the challenge and Issuer directory check out.
  admission: () => fetch('/my-app/admission-code').then(r => r.text()),
  init: { method: 'POST', body: vote },
});
```

`fetchWithToken` makes the request; on a 401 PrivateToken challenge it checks
that the challenge names the configured Issuer and one of its published keys,
then obtains the admission code, gets one token, and retries the request once
with it. If the Origin still refuses, it throws an error with stage `access`.
It never retries with the same code, and never logs codes or tokens.

The Issuer must allow your page's origin as its browser origin (the sixth
`serve-issuer` argument), and your page's Content Security Policy must allow
`connect-src` to the Issuer. The [browser demo](demo.md) uses the same package.

## Distribution and limits

The packages live in this repository and are **not published** while release
publishing is held for independent cryptographic review. Use them from a
checkout or vendor them at a fixed commit. The browser package needs
`@cloudflare/privacypass-ts` 0.9.0 as a peer dependency; that package carries
the `sjcl` ECC advisory
[GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m), and
Freebird uses only its RSA path.

Each token is spent by the request that carried it. If the response is lost,
the token is gone and the browser needs a new code. Tokens from one challenge
expire five minutes after the end of the hour in which they were issued.

## Tests

`python3 scripts/test-app-sidecar.py` runs real binaries behind nginx with TLS
and a stub application: unauthenticated requests are refused without reaching
the application, a token works once (GET and POST), a scoped token is refused at
another scope, and client-sent scope headers are ignored.
