# Browser demo and proof-of-work admission

**Experimental demo, not a production service.** Read the
[deployment guide](deployment.md) first. This page adds an optional, open way to
obtain one admission: a visitor solves an [ALTCHA](https://altcha.org/)
proof-of-work puzzle in the browser, the Issuer exchanges the solved puzzle for
one invitation, and the page uses that invitation to obtain and redeem one
RFC 9578 type-2 token. Operator invitations (`provision`, `provision-live`)
keep working unchanged.

Proof-of-work raises the cost of collecting many tokens. **It does not prove a
unique person**, and a well-resourced client can still solve many puzzles.
Treat it as rate limiting with a price, not identity.

## What runs where

| Piece | Role |
|---|---|
| `demo/web/` | Static page served by nginx on the **Origin** host. Runs the ALTCHA widget (3.6.0, self-hosted) and `@cloudflare/privacypass-ts` 0.9.0 in the browser. |
| `GET /freebird/pow/challenge` | Issuer: signed ALTCHA v2 challenge (PBKDF2/SHA-256, HMAC-SHA-256), valid 300 s. |
| `POST /freebird/pow/admission` | Issuer: verifies `{"payload": …}`, records the challenge as spent, then provisions **one** invitation. 403 for invalid, expired or reused proofs; 429 when busy. |
| `/private-token/issue` | Unchanged issuance; the page sends the invitation as `Freebird-Admission`. |
| `/private-token/protected` | Unchanged Origin redemption; replay returns 401. |

The Issuer commits the spent challenge **before** creating the invitation. If
creating the invitation fails, the proof is burned, not refunded. A solved
challenge yields at most one invitation, and an invitation still permits at
most one signing attempt.

Browsers do not speak Privacy Pass natively, so the page performs the protocol
in JavaScript. The Issuer allows cross-origin requests from exactly one
configured browser origin. The pinned TypeScript library carries the `sjcl`
ECC advisory
[GHSA-2w8x-224x-785m](https://github.com/advisories/GHSA-2w8x-224x-785m); the
demo uses only its type-2 RSA path. That does not make the advisory safe for
other uses of the library.

## Enable it

1. Initialize PoW state once, with the Issuer stopped or running (it creates
   `pow-key` and `pow.sqlite` and refuses if either exists):

    ```sh
    runuser -u freebird-issuer -- "$bin" init-issuer-pow "$issuer"
    ```

2. Start the Issuer with a sixth argument, the exact browser origin of the
   demo page (`https://host[:port]`, no path). With the shipped unit, add a
   drop-in such as `/etc/systemd/system/freebird-issuer.service.d/60-pow.conf`:

    ```ini
    [Service]
    ExecStart=
    ExecStart=/usr/local/bin/freebird-privacy-pass-service serve-issuer /var/lib/freebird-issuer/state ${FREEBIRD_ISSUER_NAME} https://${FREEBIRD_ISSUER_NAME}/private-token/issue 127.0.0.1:8081 https://${FREEBIRD_ORIGIN_NAME}
    ```

    Without the sixth argument the PoW routes return 404 and no CORS headers
    are sent. A missing or malformed `pow-key`/`pow.sqlite` refuses startup;
    nothing is created implicitly.

3. Build the page and copy only `dist/` to the Origin's web root:

    ```sh
    cd demo/web
    npm ci --ignore-scripts && npm run build
    # Set <meta name="freebird-issuer" content="https://issuer.example.org"> in dist/index.html
    install -d -m 0755 /var/www/freebird-demo
    cp -R dist/. /var/www/freebird-demo/
    ```

4. In [`deploy/nginx/freebird.conf`](https://github.com/flammafex/freebird/blob/main/deploy/nginx/freebird.conf),
   replace `https://issuer.example.org` in the Origin's
   `Content-Security-Policy` with your Issuer origin. The template already
   rate-limits `/freebird/pow/` (10 requests per minute per client address,
   burst 5) and forwards the CORS headers the Issuer checks. Run `nginx -t`,
   then reload.

The page sends no requests to third parties, uses no cookies or browser
storage, and keeps the invitation and token in memory only.

## Recovery

`pow-key` and `pow.sqlite` live in the Issuer state directory and are backed up
with it. `recover-issuer-admission` also rotates `pow-key` and clears the spent
table, so challenges issued before a restore can no longer be exchanged. See
[stopped backup and recovery](recovery.md).

## Tests

- `python3 scripts/test-pow.py` — real Issuer: challenge, solve, one
  admission, replay 403, CORS for the configured origin only.
- `python3 scripts/test-browser-demo.py` — headless Chrome through nginx TLS
  against real Issuer and Origin: PoW, issuance, access 200, replay 401, with
  no console errors, no CSP violations, and no requests outside the two hosts.
  Requires nginx, Chrome/Chromium, Node 26 and npm.
