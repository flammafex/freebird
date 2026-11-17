# Privacy Pass hard fork: phase-one contract

**Status:** implementation contract; not a production-readiness claim. This
tree is not yet a deployable release.

## Standards and profile

The normative sources are [RFC 9576](https://www.rfc-editor.org/rfc/rfc9576)
(roles and privacy), [RFC 9577](https://www.rfc-editor.org/rfc/rfc9577)
(challenge and HTTP authentication), [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578)
(issuance and token type), and [RFC 9474](https://www.rfc-editor.org/rfc/rfc9474)
(blind RSA). This document specifies deployment policy where the RFCs leave a
choice; it does not redefine their wire formats.

- **Only token type `0x0002`:** RFC 9578 Section 6, publicly verifiable
  2048-bit blind RSA. Use `RSABSSA-SHA384-PSS-Deterministic` (identity message
  preparation, SHA-384, MGF1-SHA-384, 48-byte PSS salt). Do not confuse
  deterministic preparation with zero-salt PSS. No VOPRF or privately
  verifiable token support.
- **One token per request:** `TokenRequest = uint16(0x0002) ||
  uint8(truncated_token_key_id) || blinded_msg[256]` (259 bytes);
  `TokenResponse = blind_sig[256]`; `Token = uint16(0x0002) ||
  nonce[32] || challenge_digest[32] || token_key_id[32] ||
  authenticator[256]` (354 bytes). Exact lengths and complete consumption
  are mandatory; reject extra bytes.
- **Token input:** `0x0002 || nonce || SHA256(serialized TokenChallenge) ||
  SHA256(exact advertised RSA-PSS SPKI bytes)`; the client chooses a fresh 32-byte nonce
  and blinds this 98-byte input. The issuer sees neither nonce nor challenge.
  The key ID is SHA-256 of the RFC 9578 Section 6.5 SPKI, *not* a hash of
  PKCS#1 DER or an arbitrary string. The exact advertised SPKI must encode `id-RSASSA-PSS`
  with explicit SHA-384, MGF1-SHA-384, and salt length 48. The issuer
  identifies a request key by the last byte of that full key ID; keys
  concurrently eligible for issuance must have distinct suffixes. Do not
  silently re-encode a received SPKI to calculate a different identity.
- **Key roles:** the Issuer alone stores the private signing key. The Origin
  pins the trusted Issuer name and public SPKI; it never loads, mounts, or
  fetches a signing secret. Issuer, Attester, Client, and Origin are the RFC
  roles; Freebird may operate Attester and Issuer together. Public
  verification does not prevent a compromised Origin from authorizing its
  own requests, nor issuance/redemption timing correlation.

## HTTP surfaces

| Role | Surface | Contract |
| --- | --- | --- |
| Issuer | `GET /.well-known/private-token-issuer-directory` | RFC 9578 JSON directory, `application/private-token-issuer-directory`, with `issuer-request-uri` and `token-keys` containing type `2` and padded base64url canonical SPKI; bound cache lifetime to the key policy. |
| Issuer | `POST /private-token/issue` | Exactly one 259-byte RFC request, `Content-Type: application/private-token-request`; on success 256 bytes, `Content-Type: application/private-token-response`. Unsupported type, key suffix, or length returns 422. No JSON wrapper or batch. |
| Origin | `GET /private-token/protected` | Without a valid token, 401 with RFC 9577 `WWW-Authenticate: PrivateToken challenge="...", token-key="...", max-age=...`; with one accepted `Authorization: PrivateToken token="..."`, 200. This is a reference protected resource, not a generic token-check endpoint. |

HTTP base64url values include padding and are quoted whenever required by
HTTP auth-parameter syntax. Scheme and parameter names are case-insensitive;
unknown authorization parameters are ignored; duplicate mandatory parameters,
malformed encodings, and trailing binary bytes fail. Challenge parsing follows
RFC 9577 Section 2.1.1, including length-prefixed ASCII server names, exactly
0 or 32 context bytes, and no userinfo. The Origin's challenge has one
configured `origin_info` name equal to its own name, one pinned Issuer name,
and the selected type and public key. No client-specific challenge context.

The Issuer's **Freebird-only** `Freebird-Admission` header carries exactly
one unpadded base64url encoding of 32 CSPRNG bytes (43 ASCII characters).
Reject duplicate headers, whitespace, other encodings, or wrong lengths
with 400. It is separate from the standard binary request body, is not an
RFC parameter, and must not be logged. A local operator-only CLI provisions
one random invitation, prints it once to the operator, and durably stores
`SHA256(generation || invitation_bytes)` with an absolute 24-hour expiration;
no public endpoint can mint invitations. A missing, unknown, expired, or
consumed invitation receives the same 403 response, without a signature.
The reference client obtains the invitation from the operator. Malformed
RFC request bodies of 0–4096 bytes that are not exactly 259 bytes fail with
422 before admission consumption; unsupported media type fails with 415,
bodies over the separate 4096-byte transport cap fail with 413, exhausted signer
capacity with 429, and any storage/commit failure with 503. No alternate
issue, renewal, batch, or admin signer route may bypass admission.

## Issuance, redemption, and persistence

One invitation permits **one** signing attempt, not a batch. The Issuer must
validate a request and atomically consume the invitation in a crash-durable
transaction *before* signing. Concurrent contenders have exactly one winner. A lost
response or crash may burn an invitation; never refund an uncertain signature.
The issued blind response must not be cached alongside the invitation or
linked to a redeemed token. This is Freebird admission policy, not a
standardized Privacy Pass quota.

The Origin uses one shared 32-byte pseudorandom redemption context per UTC
hour, never a per-client value:
`HMAC-SHA256(origin_context_secret, "freebird-pp-context-v1" ||
u64_be(hour_index))`. The secret is generated once and persisted separately
from the Issuer key. The current hour is accepted through its end plus a
five-minute grace; the previous hour is accepted only until its end plus
that grace. It reconstructs the exact accepted `TokenChallenge` bytes and
compares their SHA-256 digests with the token's authenticated
`challenge_digest`. `max-age` advertises seconds left until the current
hour's acceptance deadline; it is **not token expiry**. Persist the greatest
observed Unix **second**, advancing it in the same durable transaction as
challenge issuance, redemption, and bounded replay pruning. If the wall
clock is earlier than that high-water mark, refuse both challenge issuance
and redemption until it catches up; at `now >= acceptance_deadline`, reject.
Once a challenge closes, no restart or clock step can re-open it. Fix these
values for the first implementation; changing them requires an explicit
persisted-state migration.

Before marking a token spent, the Origin validates the full token, type,
trusted public key ID, signature, Origin/Issuer/challenge binding, and
acceptance deadline. It atomically records a spend key from the authenticated
token's key ID, challenge digest, and nonce. Only one concurrent redemption
can succeed. Spent state survives restart. Each admitted request begins an
IMMEDIATE transaction, validates metadata and replay invariants **before**
deleting anything, refuses clock regression, and advances the durable high-water
mark. At `now >= acceptance_deadline + 120`, it prunes at most 256 challenges,
then at most 256 expired spends whose challenge row is absent. Challenges outside
the batch keep their spends; partial sweeps may legitimately leave spends without
challenges. Cutoffs are checked integer arithmetic, never SQLite deadline
addition. Pruning and redemption or new challenge persistence commit atomically
with high-water advancement; any failure rolls back and denies access. A 200 or
401 is returned only after commit. No TTL is safe without these enforced deadline
and rollback rules, including the no-snapshot-rollback requirement below.

Pruning is independent of offline key retirement: it neither retires a key nor
deletes its permanent record, and an empty superseded key still cannot retire
before `S+420`. Installation and retirement do not perform request pruning.
This is **not an absolute storage quota**: a frozen clock or high volume can
accumulate unexpired spends. Redeemable spends are never evicted to meet a cap.

The Origin admits at most two blocking jobs for all SQLite and RSA work. It
samples the clock after acquiring the connection mutex and beginning the
transaction, not while a job waits. Saturation returns 429 without a challenge or
state change; store, clock, or worker/join errors return 503. Cancelling an HTTP
future does not cancel its admitted blocking job or release its permit before
completion. A lost response may burn a token; never refund an uncertain spend.

**Supported topology is one Ubuntu 24.04 host with nginx TLS in front of
one loopback-only process per role, with no automatic failover.** See the
[deployment guide](../deployment.md). Each process takes an exclusive lifetime lock on its own local
transactional store; a second process fails startup. Transactions must be
crash-durable (for SQLite: WAL and `synchronous=FULL`) and recoverable after
restart. Reject or disable multi-replica deployment manifests before cutover.
Shared-store multi-replica/failover behavior is out of scope and cannot be
claimed.

Restoring an older snapshot of the Origin's high-water/replay store cannot be
detected by that same store. A restore is a mandatory maintenance operation:
keep the Origin closed, generate and persist a new context secret *outside
the restored snapshot*, discard all old accepted contexts, then reopen with
a fresh high-water mark; all old tokens become unusable. Likewise, on Issuer
admission-store restore, rotate the invitation generation outside the
restored snapshot and invalidate **every** invitation from the old generation
before reopening. These are documented operator steps; unannounced rollback
of both store and recovery marker cannot be made safe by local software.
Signing keys, context secrets, invitation generation, and one-use state have
separate, dedicated storage namespaces.

Key state is a schema-v2 SQLite manifest in each role's store: the Issuer keeps
`issuer-keys.sqlite` and the Origin keeps `origin.sqlite`. Each key row holds
the full key ID (SHA-256 of its canonical SPKI), the exact SPKI bytes, and an
activation time in whole UTC hours (Unix seconds divisible by 3600). Activation
and retirement are performed **offline** under the store's lifetime lock, and
stores refuse while a role serves. Both are implemented for one local instance
per role. There is no online rotation API.

Rotation order is **Origin first**. The Origin installs the new public key with
an activation hour `S`; it advertises that key only from `S` and accepts
redemptions for it only against challenges it recorded after `S`. The Issuer is
then scheduled at the same `S` using
`activate-issuer-key <issuer-state-dir> <key-id-hex> <S>`; the ID must name its
staged or scheduled candidate. The Issuer signs each request with exactly one
key, the greatest activation hour at or before the clock hour, and advertises
exactly one key. The Issuer latches the greatest hour it has seen in this
process, so a clock step back does not return it to an older key.
Directory responses are cached for at most 60 seconds, capped by the seconds
remaining until the next scheduled activation.

The Origin accepts only persistent `(full key ID, challenge digest, acceptance
deadline)` combinations. After its successor activates, a superseded Origin key
is in `verifying` state. It accepts only redemptions whose recorded challenge
deadline is still open, and the last such deadline is `S + 300` seconds. No
redemption is accepted for it afterwards. Its state stays `verifying` until
the operator retires it. Verification uses only the key named by the token, with
no trial verification across keys. An installed key with no challenge rows
cannot redeem. Because the challenge contains no key, digest matching alone
cannot authorize a key. Suffix collisions among privately held keys are
rejected.

Offline retirement is implemented: `retire-issuer-key <dir> <old-id>` is allowed
once `now >= S` (an active successor), and `retire-origin-key <dir> <old-id>` once
`now >= S+420` (the final `S+300` acceptance deadline plus a 120-second safety
margin). Issuer retirement atomically sets the old key's `pkcs8=NULL` and advances
high-water; Origin retirement atomically deletes its challenge/spent rows, sets
`retired=1`, and advances high-water. Public key records are retained permanently:
a retired ID can never be reinstalled. A second rotation requires retirement of
the superseded keys. The Issuer never signs with an old key after its successor's
activation, even before retirement.

Origin installation and rescheduling check streamed canonical SHA-256 replay
digests before and after all transaction mutations, including high-water changes.
Retirement uses the same check excluding only its target key. The fingerprints
include every replay column, canonical row ordering, domain/scope separation, and
row counts without materializing the replay store. Preservation relies on SHA-256
collision resistance, not literal equality of row snapshots. Unexpected SQLite
column types and digest mismatches fail closed; schema-object refusals remain.

Both stores use `secure_delete=ON`; Issuer retirement attempts a post-commit
`wal_checkpoint(TRUNCATE)`. Cleanup is best effort: a checkpoint failure does
not roll back retirement or turn its success into a reported failure. This is
not a destruction guarantee for journal copies, backups, snapshots, or process
memory, and no zeroization is claimed. There is no HSM, online rotation API,
multi-instance operation, or multi-key not-before directory. Release remains
blocked by independent crypto review, independent interop, and operational
backup/recovery tests.

## Verification and release gates

The authoritative code boundary will be `common/src/privacy_pass/` for
serialization and shared types, `crypto/` for a narrow RFC 9474 primitive
adapter, and `common/test-fixtures/privacy-pass/` for **verbatim** RFC 9577
Appendix A and RFC 9578 Appendix A.2 vectors with source URLs, hashes, and
the RFC's code-extraction license notice. Never derive expected values from
the code under test. Pin the selected primitive version and lockfile after
checking exact SPKI bytes, RFC vectors, and dependency advisories. The current
Git-pinned library fork, stable RSA backend, and review limits are recorded
in the repository's `SECURITY.md`.

Exit criteria for the end-to-end sketch:

1. The independent RFC vectors and negative parse/signature tests pass.
2. A Rust reference client receives a real HTTP challenge, requests exactly
   one blind signature with a one-use admission, finalizes, and redeems once.
   Replay, wrong Origin/challenge/key/type, trailing bytes, and store outage
   fail; signer concurrency is bounded.
3. Concurrent/restarted issuance cannot reuse an invitation; concurrent and
   restarted redemption cannot reuse a token. Test durable-commit failure,
   exclusive store ownership, crash recovery, same-hour clock rollback,
   `now == acceptance_deadline`, irreversible closure after restart and
   spent-record retirement, and the operator-controlled restored-store
   invalidation procedure. These establish acceptance policy, not an
   invented token expiration field.
4. The Origin has no private key path, environment fallback, or mounted
   signing secret. No alternative issuance or token-check route bypasses
   admission or redemption.
   Offline staged-key activation (Origin first, then Issuer schedule), status
   agreement between roles, refusals, truncated-suffix collisions, and old-key
   retirement are implemented and tested. The rotation drill covers Issuer
   retirement at `S`, Origin refusal at `S+419` and success at `S+420`,
   rejection of retired tokens/IDs, and a second full rotation.
5. SDK, CLI, CI, deployment files, and public docs describe and exercise only
   the new flow before any release is tagged. Intermediate commits are not
   deployable.

**Release blockers, even after a green sketch:** independent implementation
interop, security review of the selected RSA backend (including timing/fault
defenses), and an operator-tested backup/recovery procedure for the
single-host topology. Do not call this
production-ready merely because the happy path passes.

Out of scope: token type `0x0001`, batch issuance, draft
expiration or metadata extensions, browser-specific integration, public
cross-Origin tokens, generic `/check`, and HSM claims. A rollback goes to
maintenance mode or a compatible Privacy Pass build.
