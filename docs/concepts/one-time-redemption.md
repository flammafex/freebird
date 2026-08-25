# One-Time Redemption

`POST /v1/verify` is the consuming verification operation. A valid token is
accepted only if the verifier can atomically record its replay identity. A
second use receives a replay rejection. `POST /v1/check` performs validation
without recording a spend, so checking does not make a token one-time-used.

## V4

The verifier derives a V4 nullifier from the parsed token and its configured
verifier scope, then stores a V4 spend key. V4 tokens do not carry an
issuer-enforced expiration timestamp, so the persistent replay record does not
use a token validity expiry.

## V7

The V7 replay identity is the issuer namespace plus the lowercase hexadecimal
body nullifier. It deliberately excludes the signature, whole artifact,
descriptor, graph, keyset, verifier, and audience. A second signature over the
same V7 body nullifier is therefore still a replay. V7 replay records expire at
the inclusive `valid_until` boundary.

The one-time property depends on the storage deployment, not only on token
cryptography. Use durable Redis for restart-safe or multi-instance operation;
memory is development-only. See [replay protection](replay-protection.md) and
[deployment modes](../architecture/deployment-modes.md).
