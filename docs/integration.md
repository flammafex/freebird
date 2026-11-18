# Freebird checks tokens before requests reach the application.

Use nginx and the Freebird packages to protect application routes without
implementing Privacy Pass in the application. This experimental setup uses
the [single-host deployment](deployment.md) and
[app admission](app-admission.md). Do not use it in production.

nginx controls which requests reach the application, and the Freebird
packages handle admission and tokens:

1. Route protected requests through **nginx and the Freebird Origin** so that
   the application receives only requests that carry a valid, unspent token.
2. Use `packages/freebird-server` to **request admission codes** for users
   who meet the application's access rules.
3. Use `packages/freebird-client` in the browser to **obtain and spend a
   token** on a protected request.

```text
browser ──► nginx ──auth_request──► Freebird Origin (checks + spends token)
   │          └──► your application (only if the token was accepted)
   │
   ├──► your application server ──► Freebird Issuer /freebird/app/admission
   │      (your policy decides)       (returns one admission code)
   └──► Freebird Issuer /private-token/issue (code + blinded request → token)
```

## nginx checks tokens before proxying protected requests.

Copy the locations between `BEGIN app-protection example` and
`END app-protection example` in the nginx template into the server block
that serves your application. The example is commented out at the end of
the template. Set the upstream address to your application.

Verify that nginx includes the `auth_request` module so that it can call
the Origin before proxying a request. Ubuntu's packaged nginx includes
the module. Check with `nginx -V 2>&1 | grep auth_request`.

Each protected location handles access as follows:

- Send an **internal `auth_request` subrequest** to the Origin's
  `/private-token/protected` route to check the token. Forward only
  `Authorization` and the `Freebird-Scope` value that nginx sets.
- **Proxy the request to the application** only if the Origin verified and
  spent the token and returned 200.
- **Return the Origin's 401 challenge** with
  `WWW-Authenticate: PrivateToken …` so that the browser can obtain a token.
  nginx does not contact the application for that request.
- **Strip `Authorization` and `Freebird-Scope`** before proxying to the
  application. The Origin has spent the token, so the application does not
  need it.

### Set a scope to bind a token to one resource.

Set `Freebird-Scope` in the internal auth location to bind a token to a
resource such as a ballot, pool, or thread. Without scoping, a token works
on any protected route of the Origin. The template's `/ballot/` example
derives `ballot:<id>` from the query string. A token for `ballot:1` is
refused at `ballot:2` or at an unscoped route. The browser receives a fresh
challenge for the requested scope.

Apply these checks so that clients cannot set arbitrary scopes:

- **Set `Freebird-Scope` only in nginx** so that clients cannot set the value
  directly. Do not forward a client-supplied scope header. The Origin
  accepts this header because it listens on loopback behind nginx. Do not
  expose the Origin's port directly.
- Use **1–128 visible ASCII characters** for a scoped value and an empty
  value for an unscoped request. The Origin returns 400 for two scope
  headers or an invalid value.
- **Allow only listed scope values** in nginx because each distinct scope
  creates challenge records for the hour. Do not copy arbitrary client
  input. The template returns 403 for identifiers outside its list.

The Origin binds the scope by deriving the challenge's redemption context
from its secret, the hour, and the scope. It uses the same cryptography
and preserves the exact bytes of unscoped challenges.

## The application server requests an admission code for one user.

Register the application once with `app-add` for
[app admission](app-admission.md). Keep its key in the server's secret store.
Request one code when a user meets the application's access rules:

```js
import { requestAdmission } from '../path/to/freebird/packages/freebird-server/src/index.mjs';

const code = await requestAdmission({
  issuer: 'https://issuer.example.org',
  key: process.env.FREEBIRD_APP_KEY,
});
// Send `code` to that one user over your authenticated session. Never log it.
```

`requestAdmission` throws an error with `status` 429 at the daily cap.
The error's `retryAfter` is the number of seconds until the next UTC
midnight. A revoked or incorrect key results in 401.

Give each code to one user who is ready to request a token. A code can be
spent on exactly one token and expires after 24 hours.

## The browser retries a challenged request with one token.

Use `fetchWithToken` to obtain a token after verifying the Issuer in the
challenge, then retry the protected request:

```js
import { fetchWithToken } from '../path/to/freebird/packages/freebird-client/src/index.mjs';

const response = await fetchWithToken('https://app.example.org/ballot/?ballot=1', {
  issuer: 'https://issuer.example.org',
  // Called at most once, only after the challenge and Issuer directory check out.
  admission: () => fetch('/my-app/admission-code').then(r => r.text()),
  init: { method: 'POST', body: vote },
});
```

After receiving a 401 `PrivateToken` challenge, `fetchWithToken` checks
that the challenge names the configured Issuer and one of its published
keys. It then obtains one admission code, gets one token, and retries the
request once with that token. If the Origin refuses the retry,
`fetchWithToken` throws an error with stage `access`. It does not retry
with the same code or log codes or tokens.

Allow the page's origin in the sixth `serve-issuer` argument so that the
browser can contact the Issuer. Allow `connect-src` to the Issuer in the
page's Content Security Policy. The [browser demo](demo.md) uses the same
package.

## Use the packages from a source checkout.

Use the packages from this repository or vendor them at a fixed commit.
Release publishing requires independent cryptographic review, so the packages
are available only as source in the repository.

Install `@cloudflare/privacypass-ts` 0.9.0 as a peer dependency of the
browser package. Freebird uses only its RSA path. The dependency carries the
`sjcl` ECC advisory
[GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m).

## A protected request spends its token once.

A protected request spends its token even if the response is lost. If
the browser needs another token, it must obtain another admission code.
Tokens from a challenge expire five minutes after the end of the hour in
which they were issued.

## The integration test checks token use and scoping.

Run `python3 scripts/test-app-sidecar.py` to check the real Freebird binaries
behind nginx with TLS and a stub application. The test verifies that
unauthenticated requests never reach the application and that a token works
once for GET and for POST. It also verifies that the Origin refuses a token
at another scope and that nginx ignores client-supplied scope headers.
