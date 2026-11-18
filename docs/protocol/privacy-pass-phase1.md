# Freebird uses RFC 9578 type-2 tokens with one-use admission

Freebird uses the RFC wire formats and adds a one-use admission rule. The implementation is experimental and not ready for production deployment.

## Blind RSA supports public verification

[RFC 9578](https://www.rfc-editor.org/rfc/rfc9578) defines issuance and the token type. [RFC 9474](https://www.rfc-editor.org/rfc/rfc9474) defines blind RSA.
[RFC 9577](https://www.rfc-editor.org/rfc/rfc9577) defines challenges and HTTP authentication. [RFC 9576](https://www.rfc-editor.org/rfc/rfc9576) defines the roles and privacy properties.
Freebird sets deployment policy where the RFCs leave a choice and uses their wire formats unchanged.

The protocol uses the following rules for token encoding and key handling:

- **Token type `0x0002`** uses publicly verifiable 2048-bit blind RSA as specified in RFC 9578 Section 6.
  `RSABSSA-SHA384-PSS-Deterministic` uses identity message preparation, SHA-384, MGF1-SHA-384, and a 48-byte PSS salt.
  Deterministic message preparation does not mean zero-salt PSS. Freebird does not support VOPRF or privately verifiable tokens.
- **Each request can yield at most one token.** The 259-byte request is `TokenRequest = uint16(0x0002) || uint8(truncated_token_key_id) || blinded_msg[256]`.
  The response is `TokenResponse = blind_sig[256]`. The 354-byte token is `Token = uint16(0x0002) || nonce[32] || challenge_digest[32] || token_key_id[32] || authenticator[256]`.
  Require exact lengths and complete consumption. Reject trailing bytes.
- **The client blinds a 98-byte input** that includes a fresh 32-byte nonce: `0x0002 || nonce || SHA256(serialized TokenChallenge) || SHA256(exact advertised RSA-PSS SPKI bytes)`.
  The blinded request exposes neither the nonce nor the challenge to the Issuer. Hash the exact RFC 9578 Section 6.5 SPKI bytes with SHA-256 to get the key ID.
  Hashing PKCS#1 DER, arbitrary strings, or a re-encoded SPKI would not give the specified identity.
  The advertised SPKI must encode `id-RSASSA-PSS` with explicit SHA-384, MGF1-SHA-384, and salt length 48.
  The Issuer selects the request key by the last byte of its full key ID, so keys that are eligible for issuance at the same time must have distinct suffixes.
- **The Issuer alone stores the private signing key.** The Origin pins the trusted Issuer's name and public SPKI and does not load, mount, or fetch a signing secret.
  The RFCs define the Issuer, Attester, Client, and Origin roles. Freebird may operate the Attester and Issuer together.
  Public verification does not prevent a compromised Origin from authorizing its own requests or prevent correlation by issuance and redemption timing.

## HTTP routes separate discovery, issuance, and redemption

| Role | Surface | Contract |
| --- | --- | --- |
| Issuer | `GET /.well-known/private-token-issuer-directory` | This route serves an RFC 9578 JSON directory as `application/private-token-issuer-directory`. It includes `issuer-request-uri` and `token-keys` with type `2` and canonical SPKI in padded base64url. The cache lifetime follows the key policy. |
| Issuer | `POST /private-token/issue` | This route accepts one 259-byte RFC request with `Content-Type: application/private-token-request`. A successful response contains 256 bytes with `Content-Type: application/private-token-response`. An unsupported type, key suffix, or length returns 422. The route accepts neither a JSON wrapper nor a batch. |
| Origin | `GET /private-token/protected` | A request without a valid token receives 401 with RFC 9577 `WWW-Authenticate: PrivateToken challenge="...", token-key="...", max-age=...`. A request with one accepted `Authorization: PrivateToken token="..."` receives 200. The route is a reference protected resource, not a generic token-check endpoint. |

HTTP authentication uses padded base64url values and quotes them when the syntax requires it. Scheme and parameter names are case-insensitive.
The parser ignores unknown authorization parameters and rejects duplicate mandatory parameters, malformed encodings, and trailing binary bytes.
RFC 9577 Section 2.1.1 defines challenge parsing with length-prefixed ASCII server names, exactly 0 or 32 context bytes, and no userinfo.
The Origin puts its own name in `origin_info` and uses one pinned Issuer name and the selected token type. It advertises the selected public key with the challenge. The context is shared, not client-specific.

The Issuer accepts exactly one nonstandard `Freebird-Admission` header containing 32 CSPRNG bytes encoded as 43 unpadded base64url ASCII characters.
Duplicate headers, whitespace, other encodings, or wrong lengths return 400. This header is separate from the standard binary request body and is not an RFC parameter. Do not log it.

For operator-only admission, a local CLI provisions one random invitation and prints it once to the operator. It durably stores `SHA256(generation || invitation_bytes)` with an absolute 24-hour expiration.
No public endpoint mints invitations in this mode. The reference client obtains its invitation from the operator.
A missing, unknown, expired, or consumed invitation receives the same 403 response, and the Issuer does not sign the request.

Malformed RFC request bodies of 0–4096 bytes that are not exactly 259 bytes return 422 before the Issuer consumes the invitation.
An unsupported media type returns 415, and a body that exceeds the separate 4096-byte transport cap returns 413. Exhausted signer capacity returns 429, and storage or commit failures return 503.
All signing routes must enforce admission. Issuance, renewal, batch, or administrative routes must not bypass that requirement.

## The Issuer consumes admission before signing

One invitation permits one signing attempt, not a batch. The Issuer validates the request and atomically consumes the invitation in a crash-durable transaction before signing.
Only one of several concurrent contenders can consume an invitation. A lost response or crash can consume it, and the Issuer must not refund an uncertain signing attempt.
Do not cache the blind response with the invitation or link it to a redeemed token. This is Freebird policy, not a standardized Privacy Pass quota.

## The Origin commits each spend before granting access

The Origin derives one shared 32-byte pseudorandom redemption context per UTC hour as `HMAC-SHA256(origin_context_secret, "freebird-pp-context-v1" || u64_be(hour_index))`.
The Origin generates the secret once and persists it separately from the Issuer key. Challenges for the active hour remain acceptable until five minutes after that hour ends.
Challenges from the hour that just ended are accepted only during the grace period. The Origin reconstructs the exact accepted `TokenChallenge` bytes and compares their SHA-256 digests with the authenticated `challenge_digest`.
The `max-age` value gives the seconds until the deadline for the challenge of the active hour. It does not indicate token expiry.

The Origin persists the greatest observed Unix second in the same durable transaction as challenge issuance or redemption and bounded replay pruning.
If the wall clock falls below that high-water mark, the Origin refuses both challenge issuance and redemption until the clock catches up.
At `now >= acceptance_deadline`, the Origin rejects the challenge. A restart or clock step cannot reopen it after it closes. Changing the fixed deadline rules requires an explicit migration of persisted state.

The Origin checks the full token before marking it spent. It checks the type, trusted public key ID, signature, binding to the Origin, Issuer, and challenge, and acceptance deadline.
The Origin atomically records a spend key from the authenticated key ID, challenge digest, and nonce. Only one concurrent redemption can succeed, and restart does not clear the spent state.

Each admitted request begins an `IMMEDIATE` transaction that checks metadata and replay invariants before deleting any rows. The transaction refuses clock regression and advances the durable high-water mark.
At `now >= acceptance_deadline + 120`, the Origin prunes at most 256 challenges. It then prunes at most 256 expired spends whose challenge row is absent.
Spend rows for challenges outside the batch remain intact. A partial sweep may leave spends without challenges. The Origin calculates the cutoffs with checked integer arithmetic, not SQLite deadline addition.

Pruning, redemption or challenge persistence, and high-water advancement commit together. Any failure rolls back the transaction and denies access. The Origin returns 200 or 401 only after commit.
Pruning by a time limit is safe only with the enforced deadlines and rollback rules, including the restriction on rolling back snapshots.

Pruning neither retires a key nor deletes its permanent record. Even a superseded key without challenge and spend rows cannot retire before `S+420`. Offline installation and retirement do not prune request state.
A frozen clock or high request volume can accumulate unexpired spends because pruning does not impose an absolute storage quota. The Origin never evicts redeemable spends to meet a cap.

The Origin admits at most two blocking jobs for SQLite and RSA work. It samples the clock after it acquires the connection mutex and starts the transaction, not while the job waits.
Saturation returns 429 without a challenge or state change. Store, clock, worker, or join errors return 503.
Cancelling an HTTP future does not cancel its admitted blocking job or release the permit before completion. A lost response can spend a token. Do not refund an uncertain spend.

## Each role runs once and holds an exclusive store lock

The [deployment guide](../deployment.md) uses one Ubuntu 24.04 host with nginx terminating TLS in front of one loopback-only process per role. The setup does not provide automatic failover.
Each process takes an exclusive lifetime lock on its local transactional store, which prevents a second process from starting.
Transactions must withstand crashes and be recoverable after restart. SQLite uses WAL and `synchronous=FULL` for this purpose.
Reject or disable multi-replica deployment manifests before the services start. Freebird does not support multiple replicas or shared-store failover.

## Restoring state invalidates old tokens and invitations

Keep the Origin stopped during recovery because the store cannot detect its own rollback to an older snapshot.
Generate and persist a fresh context secret outside the restored snapshot and discard old accepted contexts before reopening the Origin.
All old tokens become unusable, and the restore retains the clock high-water mark.

When restoring the Issuer admission store, rotate the invitation generation outside the restored snapshot and invalidate every invitation from the old generation before reopening.
Local software cannot protect against an unannounced rollback of the store and the recovery marker together.
Signing keys, context secrets, invitation generation, and one-use state each have a dedicated storage namespace.

The [recovery runbook](../recovery.md) specifies the supported backup and restore steps and their limits.

## Both roles schedule rotation for the same UTC hour

Each role stores key state in a schema-v2 SQLite manifest. The Issuer uses `issuer-keys.sqlite`, and the Origin uses `origin.sqlite`.
Each key row stores its full key ID, which is the SHA-256 hash of its canonical SPKI, and the exact SPKI bytes.
The row also stores an activation time in whole UTC hours, expressed as Unix seconds divisible by 3600.
Activation and retirement support one local instance per role and require the lifetime lock while that role is offline. Freebird has no online rotation API.

Install the candidate public key at the Origin first with activation hour `S`. The Origin advertises it from `S` and accepts its tokens only for challenges that it records from `S`.
Then run `activate-issuer-key <issuer-state-dir> <key-id-hex> <S>` to schedule the Issuer for the same hour. The ID must name its staged or scheduled candidate.
The Issuer signs each request with exactly one key and advertises exactly one key. It selects the key with the greatest activation hour at or before the clock hour.
The Issuer retains the greatest clock hour for the life of the process, so a backward clock step does not restore an older key.
The directory cache lifetime is at most 60 seconds and cannot exceed the seconds until the next scheduled activation.
The Issuer rejects suffix collisions among the private keys that it holds.

The Origin accepts only stored tuples of full key ID, challenge digest, and acceptance deadline. It verifies only with the key that the token names.
The Origin rejects a token for a key without a stored challenge. A matching digest alone cannot authorize a key because the challenge does not contain the key.
Once a successor activates, the superseded Origin key enters `verifying` state until retirement.
The Origin accepts redemptions for that key only while its recorded challenge is within its deadline. The last deadline is `S + 300` seconds. The Origin rejects all redemptions for that key at and after that deadline.

## Retirement removes superseded material and keeps key IDs

Run `retire-issuer-key <dir> <old-id>` once `now >= S`, when the successor is active.
Run `retire-origin-key <dir> <old-id>` once `now >= S+420`, which is the final `S+300` acceptance deadline plus a 120-second safety margin.
The Issuer sets `pkcs8=NULL` for the superseded key and advances high-water in one transaction. The Origin deletes that key's challenges and spends, sets `retired=1`, and advances high-water in one transaction.
Both stores retain public key records permanently, so a retired ID cannot be reinstalled.
Retire the superseded keys before a second rotation. The Issuer stops signing with a key when its successor activates, even if retirement has not run.

Origin installation and rescheduling check streamed canonical SHA-256 digests of replay state before and after all changes within the transaction, including updates to the high-water mark.
The retirement check excludes only the target key. The digests cover every replay column in canonical row order, separate domains and scopes, and include row counts without loading the whole replay store into memory.
This check relies on SHA-256 collision resistance and does not compare literal snapshots row by row. Unexpected SQLite column types or digest mismatches abort the transaction. The checks on schema objects still apply.

Both key stores use `secure_delete=ON`. Issuer retirement attempts `wal_checkpoint(TRUNCATE)` after commit. A failed checkpoint neither rolls back retirement nor changes the reported success.
This best-effort cleanup does not guarantee destruction of journal copies, backups, snapshots, or process memory. Freebird does not guarantee zeroization.
Freebird also does not support HSMs, online rotation, multiple instances per role, or a multi-key directory with a not-before field.

## Tests verify the protocol, and independent review gates release

`common/src/privacy_pass/` contains serialization and shared types. `crypto/` contains the narrow adapter for the RFC 9474 primitive.
`common/test-fixtures/privacy-pass/` contains verbatim vectors from RFC 9577 Appendix A and RFC 9578 Appendix A.2 with source URLs, hashes, and the RFC's license notice for code extraction.
Derive expected values independently of the code under test. Verify exact SPKI bytes, RFC vectors, and dependency advisories before pinning the primitive version and lockfile.
The repository's `SECURITY.md` records the Git-pinned fork, stable RSA backend, and review limits.

The end-to-end implementation must meet these criteria:

1. **Independent RFC vectors** pass, and negative tests reject invalid encodings and signatures.
2. **The Rust reference client** receives a real HTTP challenge, requests exactly one blind signature with one-use admission, finalizes the token, and redeems it once.
   Tests verify rejection of replay, wrong Origin, challenge, key, or type, trailing bytes, and store outage. The signer limits concurrency.
3. **Durable one-use state** prevents invitation and token reuse under concurrency and after restart. Test commit failure, exclusive store ownership, crash recovery, and same-hour clock rollback.
   Test `now == acceptance_deadline`, irreversible closure after restart and retirement of spend records, and the operator-run procedure that invalidates restored credentials.
   These tests establish local acceptance policy, not a token expiration field.
4. **Public-key verification** requires an Origin with no path to a private key, environment fallback, or mounted signing secret. Every issuance and token-check route must enforce the applicable admission or redemption rule.
   Tests cover offline staged-key activation with the Origin first, agreement between the roles on key status, refused operations, collisions in truncated key IDs, and retirement of superseded keys.
   The rotation drill checks Issuer retirement at `S`, Origin refusal at `S+419` and success at `S+420`, rejection of retired tokens and IDs, and a second full rotation.
5. **Release materials and checks** must describe and exercise only the Privacy Pass flow. Verify the SDK, CLI, CI, deployment files, and public documentation before tagging any release. Do not deploy intermediate commits.

Independent security review of the selected RSA backend and protocol integration, including timing and fault defenses, is the sole release blocker. Passing the end-to-end checks does not establish production readiness.

This contract excludes token type `0x0001`, batch issuance, draft extensions for expiration or metadata, browser-specific integration, public cross-Origin tokens, generic `/check`, and HSM guarantees.
If a rollback is necessary, enter maintenance mode or use a compatible Privacy Pass build.
