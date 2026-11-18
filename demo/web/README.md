# The Freebird browser demo redeems type-2 tokens

The Origin serves a static page that uses JavaScript for type-2 Privacy Pass.
The demo works independently of native `PrivateToken` support in Chrome and
Firefox. It requires a modern browser, HTTPS, Web Crypto, and CORS support from
the configured Issuer. It uses local assets and does not use a CDN, analytics,
remote fonts, cookies, or browser storage.

## A build and an Issuer URL prepare the demo for deployment

Use **Node 24 or later** and npm to build the demo because the pinned transitive
dependency `blindrsa-ts` requires Node 24. Keep `package-lock.json` in source
control. All three direct `devDependencies` have exact version pins.

```sh
cd demo/web
npm ci --ignore-scripts
npm run build
node --test
npm audit
```

Set the Issuer URL in `public/index.html` **before building** or edit the same
tag in the generated `dist/index.html` when deploying.

```html
<meta name="freebird-issuer" content="https://issuer.example">
```

Set the value to the Issuer's HTTPS origin, with its non-default port if it has
one. Omit the path, credentials, query, and fragment. An empty value disables
the demo.

Deploy **only the contents of `dist/`**, which include the third-party license
notices in `dist/licenses/`. Keep source files and `node_modules/` out of the
deployment. Relative asset URLs allow the page to run at `/demo/` or another
subpath. The protected resource is always `/private-token/protected` on the
page's Origin.

Keep the generated `dist/` and `node_modules/` out of source control. The root
`.gitignore` excludes both directories. Run `python3 scripts/test-browser-demo.py`
for the end-to-end browser test.

## A proof enables one token redemption

The demo solves a proof of work, obtains a token, and checks that the Origin
refuses to redeem the token twice.

1. Click **Solve and enter** to fetch the Issuer directory and the Origin's
   `401` response with a `WWW-Authenticate` challenge. Static Web Workers run
   ALTCHA locally.
2. Solving and issuance require a **type-2 challenge** that names the directory
   URI's exact host, including its port, and advertises a key in the directory.
   The issuance URI must remain on the configured Issuer's HTTPS origin.
3. Posting the **unchanged widget payload** as `{"payload":"…"}` to
   `/freebird/pow/admission` returns a 43-character admission code. The code is
   held only in memory.
4. `publicVerif.Client(publicVerif.BlindRSAMode.PSS)` creates the
   **259-byte issuance request**. It is sent with the admission code in
   `Freebird-Admission` and with `Content-Type: application/private-token-request`.
   The code is sent once. The browser deserializes and finalizes a 256-byte
   response, then encodes the 354-byte serialized token as padded base64url.
   `TokenChallenge.deserialize` and `TokenResponse.deserialize` receive
   standalone `Uint8Array.from(...)` copies to avoid upstream byte-offset bugs.
5. Sending `Authorization: PrivateToken token="…"` to the protected resource
   redeems the token. The page displays **Access granted (200)** as a status.
   It does not navigate or insert the response as HTML.
6. Click **Try replay** to send the spent token once more and check for
   **Replay refused (401)**. If the replay returns `200`, the demo reports a
   protection failure.

The page displays five stages in order: solving, admitted, token obtained,
access granted, and replay refused. Each failure has a distinct message:
admission or proof rejection (`403`), key mismatch (`422`), busy (`429`), and
redemption refusal (`401`). Click **Start again** to obtain a fresh challenge
and proof. The demo does not retry credentials automatically. Requests omit
cookies, reject redirects, bypass caches, and time out after 30 seconds. The
widget allows up to 90 seconds for proof of work.

The page displays only fixed status and error messages. It keeps admission
codes and tokens out of the DOM, URLs, browser storage, and the console. One
spent token stays in memory until replay, restart, or `pagehide`. Visitors
can inspect their own requests in browser developer tools. ALTCHA debug
mode, HIS collection, and server-side widget verification are disabled.

## The pinned ALTCHA libraries exchange v2 proofs

The `altcha` npm widget at version `3.6.0` and Rust `altcha` at version `1.1.0`
use the same proof format. The Rust pin is `altcha-lib-rs` commit
`208ac08290b6f6ad35c093e9bf611eb574f40089`. The pairing uses **PBKDF2/SHA-256**,
HMAC-SHA-256, and `Uint32`. The v1 challenge and solution format is incompatible
with v2.

The pinned Rust and npm sources agree on the wire details for the server
defaults.

| Wire detail | Rust at the pinned commit | Shipped npm 3.6.0 source |
| --- | --- | --- |
| Challenge | `src/types.rs` defines `Challenge { parameters, signature }` with the camelCase fields `keyLength`, `keyPrefix`, and `expiresAt`. | `dist/types/index.d.ts` defines matching `Challenge` and `ChallengeParameters` types. `dist/external/altcha.js` accepts this JSON. |
| Algorithm | `src/algorithms/mod.rs` defines `PBKDF2/SHA-256`, `PBKDF2/SHA-384`, and `PBKDF2/SHA-512`. | `dist/workers/pbkdf2.js` uses the same names. It runs Web Crypto PBKDF2 with `cost` iterations and `keyLength * 8` bits. |
| Counter | `src/types.rs` defaults to `CounterMode::Uint32`. In `src/helpers.rs`, `build_password` appends `counter.to_be_bytes()` to the decoded nonce. | In `dist/external/altcha.js`, `verify` selects `"uint32"` for v2. In `dist/workers/pbkdf2.js`, `PasswordBuffer` writes the counter with `setUint32(nonce.length, n, false)`. |
| Solution payload | `src/types.rs` defines `Payload { challenge, solution }` and `Solution { counter, derivedKey, time? }`. | In `dist/external/altcha.js`, `verify` encodes the payload with `btoa(JSON.stringify({ challenge: { parameters, signature }, solution }))`. The counter is numeric, the derived key is hex, and the optional time is in milliseconds. |
| Signature | `src/pow.rs` computes the HMAC of the canonical parameters and encodes the signature as hex. | The widget forwards the parameters and signature unchanged, so signing and verification remain server-side. |

The pinned source files and changelog document the format and compatibility
fixes.

- The [Rust types](https://github.com/altcha-org/altcha-lib-rs/blob/208ac08290b6f6ad35c093e9bf611eb574f40089/src/types.rs)
  define the **challenge and solution fields**.
- The [Rust counter encoding](https://github.com/altcha-org/altcha-lib-rs/blob/208ac08290b6f6ad35c093e9bf611eb574f40089/src/helpers.rs)
  shows how **the nonce and counter** form the password.
- The [Rust PoW implementation](https://github.com/altcha-org/altcha-lib-rs/blob/208ac08290b6f6ad35c093e9bf611eb574f40089/src/pow.rs)
  defines how **the server signs and verifies proofs**.
- The [widget changelog for v3.6.0](https://github.com/altcha-org/altcha/blob/v3.6.0/CHANGELOG.md)
  records the **v3.3.0 fixes** that align iterative SHA truncation and
  arbitrary PBKDF2 `keyLength` with server ports. Version 3.6.0 includes
  both fixes.
- Run `npm ci` to inspect **the shipped widget code** in `node_modules/altcha/dist/`.
  The lockfile pins the tarball and its integrity hash.

The demo sets the v3 widget's `challenge` option to the exact
`/freebird/pow/challenge` URL. This option corresponds to `challengeurl`
in the earlier API. Use the configured uppercase algorithm name and a
nonempty hexadecimal prefix, with metadata limited to Latin-1.

The Rust library accepts case-insensitive algorithm names and empty prefixes,
but the widget requires exact names and a nonempty prefix. The widget uses
`btoa(JSON.stringify(...))` directly, so it cannot handle non-Latin-1 metadata
that the Rust library accepts. The demo ships workers for PBKDF2 and iterative
SHA only. It does not support SCRYPT or ARGON2ID.

## nginx serves the demo on the Origin's HTTPS host

Copy the contents of `dist/` to `/srv/freebird-demo/` on the Origin's HTTPS
host so that the demo and protected resource share an origin. Keep the Origin
proxy location for `/private-token/protected`. Substitute the Issuer's HTTPS
origin in the meta tag and the example CSP.

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

Use nginx's standard `mime.types` so that nginx serves `.js` as JavaScript
and `.css` as CSS. If location-level headers override server-level security
headers, repeat the required headers in this location.

The build imports **`altcha/external`** and copies `altcha.css` and both
self-contained workers as local files. The default bundle injects CSS and uses
inline workers. The external widget includes optional CSSOM positioning code
for floating mode, but the demo uses the standard layout.

The build's static checks reject `eval`, `Function` constructors, and
WebAssembly in the shipped files. They also reject inline HTML scripts,
styles, and handlers, and CSS asset URLs. The page does not require
`'unsafe-inline'`, `'unsafe-eval'`, `'wasm-unsafe-eval'`, `blob:`, or `data:`
in its CSP. The static checks do not test CSP in a browser.

Configure Issuer CORS to allow the exact Origin for directory and proof of work
`GET` requests and admission and issuance `POST` requests. Allow preflight
requests for `Content-Type` and `Freebird-Admission`. The browser sends no
credentials and receives `WWW-Authenticate` from a **same-origin** response.
The challenge does not require a cross-origin header exposure setting.
Keep admission codes and `Authorization` header values out of access logs.

## Local checks passed and the dependency audit reported an advisory

The `node --test` suite covers canonical padded base64url, including unused
pad bits and offset views. It checks unambiguous `WWW-Authenticate` parsing,
HTTPS directory URI boundaries, key rotation, key membership, exact Issuer
host matching, and fixed HTTP status messages.

The install with `npm ci --ignore-scripts`, the build with `npm run build`,
and all **14** Node tests passed. The build included static CSP checks.
`npm audit --json` exited with code **1** and reported **3 high-severity
affected packages** and 0 critical findings. All three affected packages trace to
[GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m).
`@cloudflare/privacypass-ts` 0.9.0 depends on `@cloudflare/blindrsa-ts` 0.4.5,
which brings in `sjcl` 1.0.8.

The advisory affects ECC point validation. The demo uses public-verification
RSA, but the dependency finding remains unresolved and is reported by the
audit. The audit offered no fix for the required pins. These packages are
build-time `devDependencies`, and their code ships in the browser bundle.

## A browser smoke test checks redemption and replay refusal

The recorded results do not cover live Issuer and Origin checks or
end-to-end and CSP checks in Chrome or Firefox. Configure the meta tag, CSP,
and CORS to test the deployed demo. Click **Solve and enter** and check each
stage through `200` redemption. Click **Try replay** and check for `401`.
Verify that the network panel lists only Origin and Issuer requests and
that the browser reports no CSP violations.

Preserve element IDs, live-region semantics, and token flow when editing
`public/index.html` or `public/demo.css`.
