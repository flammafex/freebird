# Application servers can request one-use admission codes.

Use app admission to let a trusted application server request one-use codes
from the Issuer. The application selects users based on its own policy,
such as membership, a subscription, a voter roll, or a social trust graph.
It gives each selected user one code. The user's client spends it to obtain
one token, which the application's server verifies using the Issuer's public
key as an Origin would.

This feature is experimental and is not for production use. It runs on the
[single-host deployment](deployment.md).

## Blinding prevents linking an admission code to a redeemed token.

Blinding prevents the application, the Issuer, or both together from linking
a distributed code to the token that is redeemed at the Origin. As in any
Privacy Pass deployment, IP addresses and timing can provide a separate way
to correlate activity.

The Issuer records which application requests codes and how many it requests
per day. Freebird does not store user accounts, social graphs, or end-user
identities. Each party has access to different parts of the exchange:

| Party | Information |
|---|---|
| Application server | The server can link each admission code that it distributes to the user who received it. |
| Issuer | The Issuer receives the application's identity and the time of each request for a code. It signs a blinded request and does not receive the resulting token. |
| Origin | The Origin receives a valid token once. The token does not identify the application or user that obtained it. |

## Create the store to enable app admission.

Run the following command once as the Issuer's service user to create
`app-clients.sqlite` in the Issuer state directory:

```sh
runuser -u freebird-issuer -- "$bin" init-issuer-app-admission "$issuer"
```

Initialization fails if the store already exists. When `serve-issuer`
starts with the store present, it serves `POST /freebird/app/admission`
regardless of the browser-origin argument. If the store is absent, app
admission stays off. A malformed or locked store blocks startup. Startup
does not create the store.

## Set quotas and control which keys can request codes.

Run these commands as the Issuer's service user to add an application, adjust
its cap, inspect usage, or revoke its key. The commands use the local
control socket while the Issuer serves. They open the store directly while
it is stopped:

```sh
# Prints the new key once. Store it like a password; the Issuer keeps only its hash.
(umask 077; runuser -u freebird-issuer -- "$bin" app-add "$issuer" my-app 500) \
  > /root/my-app.key
runuser -u freebird-issuer -- "$bin" app-cap "$issuer" my-app 1000
runuser -u freebird-issuer -- "$bin" app-list "$issuer"
runuser -u freebird-issuer -- "$bin" app-revoke "$issuer" my-app
```

Use these limits and command results to manage applications:

- Choose an **application name** of 1–64 characters using lowercase letters,
  digits, and `-` so that it can be registered. The store supports up to 256
  applications.
- Set a **daily cap** of 1 to 100,000 to limit how many codes an application
  can receive per UTC day.
- Use `app-list` to **check usage and status**. It prints
  `app <name> <cap> <issued-today> <active|revoked>` once per application,
  followed by `end`.
- Use `app-revoke` to **block a key immediately**. Run `app-add` with a
  revoked name to issue a replacement key and reactivate the application.
  The usage for that UTC day is preserved, so this does not reset the cap.
  Adding a name that is still active fails.
- **Revoke and re-add the application** if `app-add` succeeds but its output
  is lost. The key cannot be recovered.

## Send an authenticated POST to receive one code.

Send one POST from the application server with the key in `Authorization`
and no request body:

```http
POST /freebird/app/admission HTTP/1.1
Host: issuer.example.org
Authorization: Bearer fba_<43 characters>
```

The status indicates whether the Issuer returned a code:

| Status | Meaning |
|---|---|
| 200 | `{"admission":"<43 characters>"}` contains one code that expires in 24 hours and can be used once. |
| 401 | The key is missing, malformed, unknown, or revoked. |
| 429 | The daily cap was reached, the Issuer is busy, or the nginx rate limit was reached. For the daily cap, `Retry-After` gives the seconds until the next UTC midnight. A busy Issuer omits `Retry-After`. |
| 400 | The request contained a body. |
| 503 | A temporary failure prevented the request from completing. |

The Issuer counts the request toward the cap before it creates the code.
If creation fails, the request still counts. Give the code to exactly one
user and keep it out of logs. The user's client sends it in
`Freebird-Admission` with one token request, just as it would send an
operator invitation.

Keep the application key on the server. Browsers cannot call this endpoint
cross-site, even if you enable the [browser demo](demo.md). The nginx
template limits the route to POST, a body size of 1 KiB, and 60 requests
per minute per client address with a burst of 20. The
[integration flow](integration.md) uses this endpoint with protected nginx
routes and the browser and server packages.

## Recovery revokes every application key.

During [stopped recovery](recovery.md), `recover-issuer-admission` revokes
every application key so that a restored database cannot bring back a
revoked key. It also clears all usage. Run `app-add` after recovery to
give each application a replacement key.

## The admission test checks quotas and revocation.

Run `python3 scripts/test-app-admission.py` to check app admission against a
real Issuer. The test adds an application, requests codes up to the cap,
checks for 429, and lists usage. It confirms that issuance accepts a code
and that a revoked key returns 401.
