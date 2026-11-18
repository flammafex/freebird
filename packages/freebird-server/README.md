# Freebird server helper

This experimental, zero-dependency Node.js ESM package requests Freebird
admission codes on an application's behalf. It requires **Node.js 20 or
later** and is **private and unpublished**: use it from a git checkout.

## API

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

**`requestAdmission({ issuer, key, fetch?, allowInsecureLoopback? })`** makes one
empty-body `POST /freebird/app/admission` with `Authorization: Bearer <key>`.
It rejects redirects, uses a 10-second timeout, and returns the validated
43-character base64url admission code. It never retries automatically.

- `issuer`: the Issuer's HTTPS origin, with no path, credentials, query, or
  fragment. Use a configured origin, not a URL supplied by the user.
- `key`: the application's `fba_…` secret from the Issuer.
- `fetch`: optional fetch implementation; defaults to Node's global `fetch`.
- `allowInsecureLoopback`: explicit `true` allows `http://127.0.0.1` for tests
  only. HTTPS is required by default.

## Errors

Check this package's exported `FreebirdError` for `status` and `reason`.
`401` means the Issuer rejected the key; check its configuration or whether
it was revoked. `429` means the daily cap was reached or the Issuer is busy.
When present, `retryAfter` is the suggested wait in seconds from `Retry-After`
(also supported on `503`). A network or timeout error may have no `status`.
Malformed success data produces a protocol error; invalid options or key
format throw `TypeError`. Do not forward the Issuer's raw errors or responses
to the browser.

## Security and testing

- Keep the application key **server-side only**. Decide which users are
  eligible on the server before requesting an admission. Deliver a code to
  exactly one eligible user over HTTPS in a response that must not be cached.
- Each admission code is single-use and valid for up to 24 hours. Never log
  app keys, admission codes, or tokens. Keep them out of URLs and analytics.
- This helper has no peer dependency and performs no cryptography. The separate
  [browser client](../freebird-client/README.md) uses
  `@cloudflare/privacypass-ts@0.9.0` as a peer. Its transitive `sjcl` advisory
  [GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m)
  remains unresolved; only the RSA path is used by the browser client.

Run `node --test` in this directory. The tests use Node's built-ins, a mocked
fetch, and a loopback test listener; no dependency install is needed.
