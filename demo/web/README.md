# Freebird browser demo

The Origin serves this static page. JavaScript explicitly performs type-2
Privacy Pass; it does not depend on native Chrome/Firefox `PrivateToken` support.
Requires a modern browser, HTTPS/Web Crypto, and the configured Issuer's CORS
support. No CDN, analytics, remote fonts, cookies, or browser storage.

## Build and configure

Use Node **24+** and npm (`blindrsa-ts`, a pinned transitive dependency, requires
Node 24). All three direct devDependencies have exact versions; retain
`package-lock.json` in source control.

```sh
cd demo/web
npm ci --ignore-scripts
npm run build
node --test
npm audit
```

Set this tag in `public/index.html` **before building**, or edit the generated
`dist/index.html` when deploying:

```html
<meta name="freebird-issuer" content="https://issuer.example">
```

Use the actual Issuer HTTPS origin, including its port if non-default; no path,
credentials, query or fragment. The empty default deliberately disables the demo.
Deploy **only the contents of `dist/`**, including third-party license notices in
`dist/licenses/`, not source files or `node_modules/`.
Assets use relative URLs so the page can live at `/demo/` or another subpath.
The protected resource is always `/private-token/protected` on the page's Origin.

`dist/` and `node_modules/` are generated local artifacts (ignored by the
repository's root `.gitignore`); **do not commit them**.
The end-to-end browser test is `python3 scripts/test-browser-demo.py`.

## Flow and boundaries

1. **Solve and enter** fetches the Issuer directory and the Origin's 401
   `WWW-Authenticate` challenge, then runs ALTCHA locally in static Web Workers.
2. Before solving/issuing, the challenge must be type 2, name the directory URI's
   exact host (including port), and advertise a key present in the directory.
   The issuance URI must remain on the configured Issuer's HTTPS origin.
3. The widget's unchanged payload is posted as `{"payload":"…"}` to
   `/freebird/pow/admission`. The returned 43-character admission is held only
   in memory.
4. `publicVerif.Client(publicVerif.BlindRSAMode.PSS)` creates the 259-byte
   request. The admission is sent once as `Freebird-Admission` with
   `Content-Type: application/private-token-request`. A 256-byte response is
   deserialized and finalized; the 354-byte serialized token is padded base64url.
   `TokenChallenge.deserialize` and `TokenResponse.deserialize` receive
   standalone `Uint8Array.from(...)` copies to avoid upstream byte-offset bugs.
5. The token is redeemed at the protected resource with
   `Authorization: PrivateToken token="…"`. The response is never inserted as
   HTML. **Access granted (200)** is a status, not a navigation.
6. **Try replay** sends the spent token once more and expects **Replay refused
   (401)**. A replay returning 200 is explicitly reported as a protection failure.

Visible stages are solving → admitted → token obtained → access granted → replay
refused. Admission/proof rejection (403), key mismatch (422), busy (429), and
redemption refusal (401) have distinct messages. No automatic credential retries:
**Start again** obtains a fresh challenge/proof. Requests omit cookies, reject
redirects, bypass caches and have a 30-second timeout; PoW has the widget's
90-second timeout.

Only fixed statuses/errors are shown. Admission codes/tokens are never printed,
placed in the DOM, URLs, storage or console. One spent token stays in memory for
the replay demonstration, then is discarded (also on restart/pagehide). As with
any browser protocol, visitors can inspect their own requests in developer tools.
ALTCHA debug/HIS collection and server-side widget verification are disabled.

## Verified ALTCHA pairing

**Widget: `altcha` npm 3.6.0. Server: Rust `altcha` 1.1.0,
`altcha-lib-rs` commit `208ac08290b6f6ad35c093e9bf611eb574f40089`.**
The configured pairing is **PBKDF2/SHA-256, HMAC-SHA-256, Uint32**.
This is PoW **v2**; the older v1 challenge/solution format is not interchangeable.

Evidence inspected directly, not inferred from version numbers:

| Wire detail | Rust at the pinned commit | Shipped npm 3.6.0 source |
| --- | --- | --- |
| Challenge | `src/types.rs`: `Challenge { parameters, signature }`; camelCase `keyLength`, `keyPrefix`, `expiresAt` | `dist/types/index.d.ts`: matching `Challenge`/`ChallengeParameters`; `dist/external/altcha.js` accepts this JSON |
| Algorithm | `src/algorithms/mod.rs`: `PBKDF2/SHA-256`, `/SHA-384`, `/SHA-512` | `dist/workers/pbkdf2.js`: exactly these names; Web Crypto PBKDF2 with `cost` iterations and `keyLength * 8` bits |
| Counter | `src/types.rs`: default `CounterMode::Uint32`; `src/helpers.rs` `build_password`: decoded nonce followed by `counter.to_be_bytes()` | `dist/external/altcha.js` `verify`: v2 selects `"uint32"`; `dist/workers/pbkdf2.js` `PasswordBuffer`: `setUint32(nonce.length, n, false)` |
| Solution/payload | `src/types.rs`: `Payload { challenge, solution }`, `Solution { counter, derivedKey, time? }` | `dist/external/altcha.js` `verify`: `btoa(JSON.stringify({ challenge: { parameters, signature }, solution }))`; solution counter numeric, derived key hex, optional time in ms |
| Signature | `src/pow.rs`: HMAC of canonical parameters, signature is hex | Widget forwards parameters/signature unchanged; signing and verification remain server-side |

Upstream references:

- [Rust types](https://github.com/altcha-org/altcha-lib-rs/blob/208ac08290b6f6ad35c093e9bf611eb574f40089/src/types.rs)
- [Rust counter encoding](https://github.com/altcha-org/altcha-lib-rs/blob/208ac08290b6f6ad35c093e9bf611eb574f40089/src/helpers.rs)
- [Rust PoW](https://github.com/altcha-org/altcha-lib-rs/blob/208ac08290b6f6ad35c093e9bf611eb574f40089/src/pow.rs)
- [Widget changelog, tag v3.6.0](https://github.com/altcha-org/altcha/blob/v3.6.0/CHANGELOG.md):
  v3.3.0 specifically fixes iterative SHA truncation and arbitrary PBKDF2
  `keyLength` to match server ports. The chosen 3.6.0 includes these fixes.
- Reproduce the widget inspection from `node_modules/altcha/dist/` after `npm ci`;
  its tarball/integrity are pinned in the lockfile.

Compatibility limits: widget v3 calls the old `challengeurl` setting **`challenge`**;
the demo uses the new API with the exact `/freebird/pow/challenge` URL. The Rust
library also accepts empty prefixes, case-insensitive algorithm spellings, or
non-Latin-1 metadata that this widget's strict algorithm registry / nonempty-prefix
check / direct `btoa(JSON.stringify(...))` cannot handle. Use the configured
uppercase algorithm and normal nonempty hexadecimal prefix, with no such metadata.
There is no identified wire-format mismatch for the confirmed server defaults.
Only PBKDF2 and iterative SHA workers are shipped; SCRYPT/ARGON2ID are deliberately
unsupported here.

## nginx and CSP

Example on the **Origin HTTPS host**, after copying `dist/` contents to
`/srv/freebird-demo/`. Substitute the actual Issuer origin in both the meta tag
and CSP. Keep the existing Origin proxy/location for `/private-token/protected`;
do not put the static demo on the Issuer or another origin.

```nginx
location = /demo {
    return 308 /demo/;
}

location ^~ /demo/ {
    alias /srv/freebird-demo/;
    index index.html;

    add_header Content-Security-Policy "default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; img-src 'self'; connect-src 'self' https://issuer.example; worker-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Cache-Control "no-store" always;
}
```

Use nginx's normal `mime.types` so `.js` is served as JavaScript, `.css` as CSS.
If adding location-level headers overrides server-level security headers, repeat
the existing required headers in this location.

The build imports **`altcha/external`**, not its default CSS-injecting/inline-worker
bundle, and copies `altcha.css` and the two self-contained workers locally.
It statically rejects `eval`, `Function` constructors, WebAssembly, inline HTML
scripts/styles/handlers, and CSS asset URLs in the shipped files. No
`'unsafe-inline'`, `'unsafe-eval'`, `'wasm-unsafe-eval'`, `blob:` or `data:` CSP
allowance is required. The external widget contains optional floating-layout
CSSOM positioning code; this demo uses its standard layout, not floating mode.
This static check is not a browser CSP integration test.

Issuer deployment must allow the exact Origin via CORS for directory and PoW
GETs plus admission/issuance POSTs, including preflight for `Content-Type` and
`Freebird-Admission`. Credentials are not included. `WWW-Authenticate` is read
from a **same-origin** response; no cross-origin expose-header setting is needed
for that challenge. Do not configure access logs to capture admission or
Authorization header values.

## Validation and dependency advisory

Focused `node --test` tests cover canonical padded base64url (including unused pad
bits and offset views), unambiguous `WWW-Authenticate` parsing, HTTPS directory URI
boundaries, key rotation/membership and exact issuer host checks, plus fixed HTTP
status messages.

At implementation time: `npm ci --ignore-scripts`, `npm run build` (including CSP
static guards), and all **14** Node tests passed. `npm audit --json` exited **1**:
**3 high-severity affected packages**, 0 critical, all from
[GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m)
(`sjcl` 1.0.8 → `@cloudflare/blindrsa-ts` 0.4.5 →
`@cloudflare/privacypass-ts` 0.9.0), with no fix offered for the required pins.
The advisory concerns ECC point validation; this demo uses public-verification
RSA, but the dependency finding is not suppressed or represented as resolved.
These dependencies are build-time devDependencies **and their code ships in the
browser bundle**.

Live Issuer/Origin and Chrome/Firefox end-to-end/CSP checks were not run here.
Deployment smoke check: configure the meta/CSP/CORS, click **Solve and enter**,
observe each stage and 200 redemption, then **Try replay** and observe 401. Verify
the network panel has only Origin/Issuer requests and no CSP violations.

For visual polish, use **@designer** with `public/index.html` and
`public/demo.css`; preserve element IDs, live-region semantics and flow behavior.
