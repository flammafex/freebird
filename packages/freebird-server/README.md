# The Freebird server package requests admission codes

This experimental Node.js ESM package requests Freebird admission codes for an
application and has no dependencies. It requires **Node.js 20 or later**. Use
it from a Git checkout because it is **private and unpublished**.

## One request exchanges an application key for an admission code

Call `requestAdmission` after checking that the user is eligible.

```js
// Relative to the root of the checkout; adjust the path in your application.
import { requestAdmission } from './packages/freebird-server/src/index.mjs';

// After verifying the user is eligible:
const code = await requestAdmission({
  issuer: 'https://issuer.example',
  key: process.env.FREEBIRD_APP_KEY,
});
// Hand only `code` to the eligible user, never the app key.
```

`requestAdmission({ issuer, key, fetch?, allowInsecureLoopback? })` sends a
single `POST /freebird/app/admission` with an empty body and
`Authorization: Bearer <key>`. It rejects redirects, times out after 10
seconds, and returns a validated 43-character base64url admission code.
It does not retry automatically.

The function takes a configured Issuer and key and accepts two optional
settings.

- Pass the **configured HTTPS origin** as `issuer` so that the key is sent
  only to the intended Issuer. Omit the path, credentials, query, and
  fragment. Do not accept this URL from the user.
- Pass the application's **`fba_…` secret** from the Issuer as `key` to
  authorize the request.
- Set **`fetch`** to use a different Fetch implementation. The default is
  Node's global `fetch`.
- Set **`allowInsecureLoopback`** to `true` to allow `http://127.0.0.1` for
  tests only. By default, the Issuer must use HTTPS.

## Errors distinguish rejected keys from busy Issuers

Check the exported `FreebirdError` for `status` and `reason`. On `401`, the
Issuer rejected the key. Check the key's configuration and whether it was
revoked. On `429`, the daily cap was reached or the Issuer is busy. On `429`
or `503`, `retryAfter`, when present, gives the suggested wait in seconds
from `Retry-After`.

A network error or timeout may have no `status`. Malformed success data
causes a protocol error. An invalid key format or invalid options cause a
`TypeError`. Keep the Issuer's raw errors and responses on the server.

## The key stays on the server when a code is sent to a user

Keep the **application key on the server** and check user eligibility there
before requesting admission. Send each code to exactly one eligible user
over HTTPS in a response that must not be cached.

Each code can be used once and is valid for up to 24 hours. Keep application
keys, admission codes, and tokens out of logs, URLs, and analytics.

The server package has no peer dependency and performs no cryptography. The
separate [browser client](../freebird-client/README.md) uses
`@cloudflare/privacypass-ts@0.9.0` as a peer. The client uses only the RSA path,
but the advisory for its transitive `sjcl` dependency remains unresolved:
[GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m).

## The tests run without a dependency install

Run `node --test` in this directory. The tests use Node's built-ins, a mocked
`fetch`, and a loopback listener.
