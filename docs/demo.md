# The browser demo exchanges a solved puzzle for an invitation.

Solve an [ALTCHA](https://altcha.org/) proof-of-work puzzle in the browser to
request one invitation. The Issuer exchanges the proof for the invitation,
and the page uses it to obtain and redeem one RFC 9578 type-2 token. This
experimental demo offers optional open admission on the
[single-host deployment](deployment.md). Do not use it in production.
Operators can also issue invitations with `provision` and `provision-live`.

Proof-of-work raises the cost of collecting tokens by requiring a puzzle
for each invitation. A client with enough computing power can solve many
puzzles. Use proof-of-work to raise the cost of repeated requests, not to
establish a person's identity or uniqueness.

## nginx serves the page and the Issuer verifies proofs.

The browser uses the page and these routes to obtain and spend a token:

| Page or route | Behavior |
|---|---|
| `demo/web/` | nginx serves the static page on the Origin host. The page runs the self-hosted ALTCHA widget 3.6.0 and `@cloudflare/privacypass-ts` 0.9.0 in the browser. |
| `GET /freebird/pow/challenge` | The Issuer returns a signed ALTCHA v2 challenge that is valid for 300 seconds. The challenge uses PBKDF2/SHA-256 and HMAC-SHA-256. |
| `POST /freebird/pow/admission` | The Issuer verifies `{"payload": …}`, records the challenge as spent, and provisions one invitation. It returns 403 for invalid, expired, or reused proofs and 429 when busy. |
| `/private-token/issue` | The page uses the standard issuance route and sends the invitation as `Freebird-Admission`. |
| `/private-token/protected` | The page uses the standard Origin redemption route, which returns 401 on replay. |

The Issuer commits the record of the spent challenge before it creates an
invitation. If creation fails, the proof remains spent. Each solved challenge
yields at most one invitation, and each invitation permits at most one
signing attempt.

The page runs Privacy Pass in JavaScript because browsers do not implement
it natively. The Issuer allows cross-origin requests from exactly one
configured browser origin.

The demo uses only the pinned TypeScript library's type-2 RSA path.
The library carries the `sjcl` ECC advisory
[GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m),
which can affect other uses of the library.

## Enable the puzzle routes and serve the demo page.

Set up proof-of-work on the Issuer and deploy the static page on the Origin:

1. **Initialize proof-of-work state** to create `pow-key` and `pow.sqlite`.
   Run the command once with the Issuer stopped or running. It fails if
   either file already exists:

    ```sh
    runuser -u freebird-issuer -- "$bin" init-issuer-pow "$issuer"
    ```

2. **Set the sixth `serve-issuer` argument** to the demo page's exact browser
   origin to enable the puzzle routes and CORS. Use `https://host[:port]`
   with no path. For the packaged unit, add a drop-in such as
   `/etc/systemd/system/freebird-issuer.service.d/60-pow.conf`:

    ```ini
    [Service]
    ExecStart=
    ExecStart=/usr/local/bin/freebird-privacy-pass-service serve-issuer /var/lib/freebird-issuer/state ${FREEBIRD_ISSUER_NAME} https://${FREEBIRD_ISSUER_NAME}/private-token/issue 127.0.0.1:8081 https://${FREEBIRD_ORIGIN_NAME}
    ```

    If you omit the sixth argument, the puzzle routes return 404 and the
    Issuer sends no CORS headers. With the argument set, startup fails if
    `pow-key` or `pow.sqlite` is missing or malformed. Startup does not
    create the files.

3. **Build and install the static page** so that nginx can serve it from
   the Origin's web root. Copy only the contents of `dist/`:

    ```sh
    cd demo/web
    npm ci --ignore-scripts && npm run build
    # Set <meta name="freebird-issuer" content="https://issuer.example.org"> in dist/index.html
    install -d -m 0755 /var/www/freebird-demo
    cp -R dist/. /var/www/freebird-demo/
    ```

4. **Allow the Issuer in the Origin's `Content-Security-Policy`** so that
   the page can contact it. Replace `https://issuer.example.org` with your
   Issuer origin in
   [`deploy/nginx/freebird.conf`](https://github.com/flammafex/freebird/blob/main/deploy/nginx/freebird.conf).
   The template limits `/freebird/pow/` to 10 requests per minute per
   client address with a burst of 5. It forwards the CORS headers that the
   Issuer checks. Run `nginx -t`, then reload nginx.

The page keeps the invitation and token in memory only. It uses no cookies
or browser storage and sends no requests to third parties.

## Recovery invalidates outstanding puzzles.

Back up `pow-key` and `pow.sqlite` with the Issuer state directory. During
[stopped recovery](recovery.md), `recover-issuer-admission` rotates `pow-key`
and clears the table of spent challenges. The Issuer then rejects exchanges
for challenges issued before the restore.

## Tests check proof exchange and token replay.

Run these tests to check the Issuer and browser flows:

- Run `python3 scripts/test-pow.py` to check **one invitation per solved
  challenge** against a real Issuer. The test requests and solves a challenge,
  checks that replay returns 403, and verifies CORS for the configured origin
  only.
- Run `python3 scripts/test-browser-demo.py` to check **issuance and
  redemption in Chrome** through nginx TLS with a real Issuer and Origin.
  The test runs headless, solves a puzzle, and checks for access 200 and
  replay 401. It verifies that there are no console errors, CSP violations,
  or requests outside the two hosts. It requires nginx, Chrome or Chromium,
  Node 26, and npm.
