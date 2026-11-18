# Admission for application servers

**Experimental, not a production service.** Read the
[deployment guide](deployment.md) first.

App admission lets a trusted application server ask the Issuer for one-use
admission codes. The application decides which of its users deserve access
using its own rules: membership, a subscription, a voter roll, a social trust
graph, or anything else. It then hands each chosen user one code, which the
user's client spends to obtain a single token. The application's server
verifies that token with the Issuer's public key, as any Origin does.

Freebird keeps no user accounts or social graph and never learns who the end
users are. It knows only which application server asked for a code and how
many it has asked for today.

## What each party learns

| Party | Learns |
|---|---|
| Application server | Which of its users received which admission code. |
| Issuer | Which application requested each code, and when. It signs a blinded request and cannot see the token it produces. |
| Origin | A valid token, once. It cannot tell which application or user obtained it. |

The application can link a user to the code it handed out. Blinding still
prevents the application, the Issuer, or both together from linking that code
to the token later redeemed at the Origin. Network metadata such as IP
addresses and timing can still correlate activity, as with any Privacy Pass
deployment.

## Enable it

App admission is off unless its store exists. Create it once, as the Issuer's
service user:

```sh
runuser -u freebird-issuer -- "$bin" init-issuer-app-admission "$issuer"
```

This creates `app-clients.sqlite` in the Issuer state directory and refuses if
it already exists. On its next start, `serve-issuer` (with or without the
browser-origin argument) serves `POST /freebird/app/admission`. A malformed or
locked store refuses startup; nothing is created implicitly.

## Manage applications

Run these as the Issuer's service user. While the Issuer serves, they go
through its local control socket; while it is stopped, they open the store
directly.

```sh
# Prints the new key once. Store it like a password; the Issuer keeps only its hash.
(umask 077; runuser -u freebird-issuer -- "$bin" app-add "$issuer" my-app 500) \
  > /root/my-app.key
runuser -u freebird-issuer -- "$bin" app-cap "$issuer" my-app 1000
runuser -u freebird-issuer -- "$bin" app-list "$issuer"
runuser -u freebird-issuer -- "$bin" app-revoke "$issuer" my-app
```

- **Names** are 1–64 characters of lowercase letters, digits and `-`. Up to 256
  applications.
- **Daily cap** is the number of codes an application may receive per UTC day,
  from 1 to 100,000.
- `app-list` prints one line per application —
  `app <name> <cap> <issued-today> <active|revoked>` — followed by `end`.
- `app-revoke` takes effect immediately. Running `app-add` again with a revoked
  name issues a fresh key and reactivates it; today's usage is kept, so
  revoking and re-adding does not reset the cap. Adding a name that is still
  active is refused.
- If `app-add` succeeds but its output is lost, the key cannot be recovered.
  Revoke the name and add it again.

## Request a code

The application server sends one POST with no body:

```http
POST /freebird/app/admission HTTP/1.1
Host: issuer.example.org
Authorization: Bearer fba_<43 characters>
```

| Status | Meaning |
|---|---|
| 200 | `{"admission":"<43 characters>"}`. One code, valid for 24 hours and usable once. |
| 401 | Missing, malformed, unknown or revoked key. |
| 429 | Daily cap reached (`Retry-After` gives the seconds until the next UTC midnight), or the Issuer is busy (no `Retry-After`). nginx's own rate limit also returns 429. |
| 400 | The request had a body. |
| 503 | Temporary failure. |

The cap is counted before the code is created. If creating the code fails, that
unit of quota is spent anyway; nothing is refunded. Hand the code to exactly one
user and do not log it. The user's client sends it as the `Freebird-Admission`
header with one token request, exactly as with operator invitations.

This endpoint is for servers only. Browsers cannot call it cross-site even when
the [browser demo](demo.md) is enabled, and the application's key must never be
sent to a browser. The nginx template limits it to POST, 1 KiB bodies and 60
requests per minute per client address with a burst of 20.

## Recovery

`recover-issuer-admission` revokes **every** application and clears their
usage, because a restored database could bring back a key you had revoked. After
recovery, run `app-add` for each application again; each receives a new key.
See [stopped backup and recovery](recovery.md).

## Tests

`python3 scripts/test-app-admission.py` runs a real Issuer: it adds an
application, takes codes up to the cap, checks the 429, lists usage, confirms a
code is accepted for issuance, and checks that a revoked key gets 401.
