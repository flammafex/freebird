# Implementation Plan: Freebird TypeScript SDK Enhancement (`@freebird/sdk`)

**Scope:** Make `@freebird/sdk` (at `sdk/js/`) a complete, installable client so consumers
(Scarcity, Clout, Rendezvous, Prestige) stop composing bespoke protocol code. This plan
incorporates all 10 oracle recommendations and corrects the false premises in
`dev/sdk-enhancement-specs.md` §1.1–1.7.

**Grounding:** All file paths and function names below were read from the actual source.
Key anchors:

- Client facade: `sdk/js/src/client.ts` (`FreebirdClient`)
- State: `sdk/js/src/client/state.ts` (`ClientState`, `createClientState`)
- Discovery: `sdk/js/src/client/discovery.ts` (`init`, `getKeyDiscoveryMetadata`,
  `refreshKeyDiscoveryMetadata`, `fetchKeyDiscoveryMetadata`)
- Issuance: `sdk/js/src/client/issuance.ts` (`issueToken`, `issuePublicBlindSignature`)
- Verification: `sdk/js/src/client/verification.ts` (`verifyToken` — currently collapses
  everything to `false`)
- Exchange: `sdk/js/src/client/exchange.ts` (`exchange`, `getExchangeStatus`,
  `exchangeRequestDigest`, `parseExchangeResponse`)
- Graph issuance: `sdk/js/src/client/graph_issuance.ts`, `graph_protocol.ts`,
  `graph_recovery.ts`
- Types: `sdk/js/src/types.ts` (`ClientConfig`, `FreebirdToken`, `SybilProof`,
  `KeyDiscoveryMetadata`, `GraphIssuanceRecoveryContext`, `ExchangeOutcome`)
- Contract gate: `sdk/js/tests/compile-time-surface.ts`
- Fixture-locked sybil test: `sdk/js/tests/sybil.test.ts` (locks
  `common/test-fixtures/sybil-proofs.json`)
- Service routes: `verifier/src/routes/public.rs` (`/v1/verify`, `/v1/check`,
  `/v1/verify/batch`), `issuer/src/routes/issue.rs` (`/v1/oprf/issue`, `/v1/oprf/renew`),
  `issuer/src/routes/batch_issue.rs` (`/v1/oprf/issue/batch`),
  `issuer/src/routes/public_issue.rs` (`/v1/public/issue`, `/v1/public/issue/batch`),
  `issuer/src/routes/metadata.rs` (`/.well-known/issuer`, `/.well-known/keys`),
  `common/src/api/{issuance,verification,sybil}.rs`

---

## Confirmed findings that shape the plan

1. **§1.3 is impossible as written.** `/.well-known/issuer` (`metadata.rs::well_known_handler`)
   publishes only `issuer_id`, `voprf`, `public`. `/.well-known/keys` (`keys_handler`)
   publishes `issuer_id`, epochs, `voprf`, `public`, `exchange`, `graph_issuance`. Neither
   publishes verifier endpoints; `/.well-known/verifier` lives on the verifier itself.
   → Verification methods **must require `verifierUrl`**; only the typed
   `VerifierNotConfiguredError` part is implementable.
2. **§1.2 "WebCrypto, no new deps" is wrong.** WebCrypto has no raw-RSA primitive; RFC 9474
   blinding needs bignum modexp. → Depend on `@cloudflare/blindrsa-ts`. `rsaVerify` via
   WebCrypto is fine.
3. **§1.6 "client-generate Sybil proofs" is half-impossible.** HMAC variants
   (`progressive_trust`, `proof_of_diversity`, `multi_party_vouching`, `invitation`) are
   keyed with server-side secrets. Only PoW, `rate_limit`, and `multi` composition are
   client-generable. PoW input is request-bound per endpoint (confirmed in
   `batch_issue.rs::batch_request_binding` and `public_issue.rs`/`issue.rs` bindings).
   Difficulty is **not** published in metadata (confirmed in `metadata.rs`). → SDK must
   construct the binding internally; no free-standing generator.

---

## Phase 0 — Packaging & publishability (Rec 10, §1.1)

**Pure SDK work.**

**Files:** `sdk/js/package.json`, new `sdk/js/README.md`.

**Changes:**
- Add `license: "MIT OR Apache-2.0"`, `repository`, `homepage`, `keywords` to `package.json`
  (matches repo convention `license = "MIT OR Apache-2.0"`).
- Add `prepublishOnly: "npm run build && npm run test"`.
- Add `README.md` documenting install, V4/V5/V2 flows, the low-level `crypto` escape hatch,
  and the new high-level methods added in later phases.
- **Decide version-lockstep policy:** the Rust workspace is lockstep `0.9.0`; the SDK is
  currently `0.1.0`. Recommend documenting that the JS SDK follows its own semver but records
  the wire-format/API compatibility against the Rust release in the README (do **not** force
  the JS SDK to match `0.9.0`). Record this decision in the README and a `CHANGELOG.md`.

**Tests:** `npm run lint` (tsc) + `npm test` still pass; `package-surface.test.ts` and
`package-consumers/` verify the published entry resolves.

---

## Phase 1 — Typed error hierarchy (Rec 4 prerequisite, §1.5)

**Pure SDK work.** This is a foundation phase; later phases (verification surface,
key-rotation retry) throw these errors.

**Files:** new `sdk/js/src/errors.ts`; export from `sdk/js/src/index.ts`; update
`sdk/js/src/client/verification.ts`, `issuance.ts`, `discovery.ts` to throw typed errors.

**Changes:**
- Add:
  ```ts
  class FreebirdError extends Error { code: FreebirdErrorCode }
  class DiscoveryError extends FreebirdError
  class VerificationError extends FreebirdError
  class VerifierNotConfiguredError extends FreebirdError
  class ExchangeError extends FreebirdError { outcome?: ExchangeOutcome }
  class GraphIssuanceError extends FreebirdError { outcome?: GraphIssuanceOutcome }
  class RateLimitedError extends FreebirdError { retryAfter: number }
  class VerifierUnavailableError extends FreebirdError
  class InvalidTokenError extends VerificationError
  class ReplayedTokenError extends VerificationError
  ```
- Export `FreebirdErrorCode` union.
- Convert existing `throw new Error(...)` in `verification.ts`, `issuance.ts`,
  `discovery.ts` to typed errors where they map to a failure mode. Keep generic messages (no
  client-facing detail leaks — see Security Conventions).

**Tests:** unit tests asserting each error class carries the right `code` and that
`instanceof` branching works. Update `compile-time-surface.ts` to pin the new exports.

---

## Phase 2 — Verification surface (Rec 1 + Rec 4)

**Pure SDK work** (no service changes needed — endpoints already exist in
`verifier/src/routes/public.rs`).

**Files:** `sdk/js/src/client/verification.ts`, `sdk/js/src/client.ts`, `sdk/js/src/types.ts`,
`sdk/js/src/index.ts`, `sdk/js/tests/compile-time-surface.ts`, new
`sdk/js/tests/verification.test.ts`.

**Changes:**
- **Fix §1.3:** `verifyToken`, `checkToken`, `verifyBatch` all require
  `state.config.verifierUrl`; if absent throw `VerifierNotConfiguredError` (typed, clear
  message). Remove the "resolve from discovery" idea entirely.
- **`checkToken(token): Promise<VerifyResp>`** → `POST {verifierUrl}/v1/check` (non-consuming
  validity check; confirmed in `public.rs::check`).
- **`verifyBatch(tokens): Promise<BatchVerifyResp>`** → `POST {verifierUrl}/v1/verify/batch`
  with `{ tokens: [{ token_b64 }] }`; surface per-token `VerifyResult` including
  `code: "replay_detected"` (confirmed in `public.rs::batch_verify` and
  `common/src/api/verification.rs`).
- **Rework `verifyToken`** to throw typed errors instead of returning `false` for everything:
  - `401`/`400` → `InvalidTokenError` or `ReplayedTokenError` (distinguish via the
    `replay_detected`/`verification_failed` semantics; `401` on `/v1/verify` means replay per
    `public.rs:149-152`).
  - `503` → `VerifierUnavailableError` (retryable).
  - `429` → `RateLimitedError` with `retryAfter` parsed from `Retry-After`.
  - Keep a `boolean`-returning convenience or add an `ok` field on the result so existing
    callers aren't broken — but the primary path throws typed errors.

**Tests (positive + negative/tamper):**
- Mock `fetch` returning each status; assert correct typed error thrown and `retryAfter`
  parsed on 429.
- `checkToken` does not consume (assert no spend semantics — it's a distinct endpoint).
- `verifyBatch` maps per-token `replay_detected` codes.
- `VerifierNotConfiguredError` thrown when `verifierUrl` unset.
- Update `compile-time-surface.ts` to pin `checkToken`, `verifyBatch`, and the new
  `verifyToken` signature.

---

## Phase 3 — V5 RSA blinding/unblinding (Rec 2, §1.2)

**Pure SDK work** (new dependency only).

**Files:** `sdk/js/package.json` (add `@cloudflare/blindrsa-ts`), new
`sdk/js/src/crypto/rsa.ts`, `sdk/js/src/index.ts` (extend `crypto` facade),
`sdk/js/src/client.ts` (add `issuePublicToken`, `verifyPublicBearerPassLocally`),
`sdk/js/src/client/issuance.ts`, `sdk/js/src/types.ts` (add `RsaBlindState`,
`PublicBearerPass`), `sdk/js/tests/compile-time-surface.ts`, new `sdk/js/tests/rsa.test.ts`.

**Changes:**
- Add `crypto.rsaBlind(publicKey, msg): { blinded, state }`, `crypto.rsaUnblind(state,
  blindSignature)`, `crypto.rsaVerify(publicKey, msg, signature)` — the latter via WebCrypto
  `RSA-PSS`/`SHA-384` (already used in `discovery.ts` for SPKI import). Blinding/unblinding
  delegate to `@cloudflare/blindrsa-ts` (constant-time, no hand-rolled bignum).
- Add high-level `issuePublicToken(msg, opts?): Promise<PublicBearerPass>` that does blind →
  `issuePublicBlindSignature` → unblind → `buildPublicBearerPass` in one call (reuses existing
  `voprf.buildPublicBearerPass`).
- Add `verifyPublicBearerPassLocally(pass, keyInfo): Promise<boolean>` using `rsaVerify` +
  `parsePublicBearerPass`. **Document clearly that local verification does NOT check spend
  status** — only `/v1/verify` does.

**Tests (positive + negative/tamper):**
- Round-trip: blind → sign (mock) → unblind → verify passes.
- Tamper: flip a byte in the signature/message → `rsaVerify` returns false.
- `issuePublicToken` end-to-end with mocked `/v1/public/issue`.
- Update `compile-time-surface.ts`.

---

## Phase 4 — Key rotation (Rec 5)

**Pure SDK work** (fixes a live bug; no service change).

**Files:** `sdk/js/src/client/discovery.ts`, `sdk/js/src/client/state.ts`,
`sdk/js/src/client.ts`, `sdk/js/src/client/issuance.ts`, `sdk/js/src/types.ts` (add cache
config to `ClientConfig`), `sdk/js/tests/compile-time-surface.ts`, new
`sdk/js/tests/key-rotation.test.ts`.

**Changes:**
- **Expose `refreshKeyDiscoveryMetadata()` on `FreebirdClient`** (the module function already
  exists at `discovery.ts:72`; it's just not surfaced on the facade).
- **Add epoch/TTL-based cache expiry:** `KeyDiscoveryMetadata` already carries `current_epoch`,
  `valid_epochs`, `epoch_duration_sec`. Cache `keyDiscoveryMetadata` with a TTL derived from
  `epoch_duration_sec` (e.g. refresh when the current epoch advances or after a configurable
  `keyCacheTtlMs` in `ClientConfig`). `getKeyDiscoveryMetadata` returns cached-if-fresh;
  `refreshKeyDiscoveryMetadata` forces a fetch.
- **Auto-refresh-and-retry on kid mismatch in issuance:** in `issueToken` (currently
  `issuance.ts:55` throws `'Issuer metadata changed during issuance'` on `kid` mismatch) and
  `issuePublicBlindSignature`, on `kid`/`token_key_id` mismatch: call
  `refreshKeyDiscoveryMetadata`, re-derive the input, and retry **once**. If it still
  mismatches, throw `DiscoveryError`.

**Tests:**
- Cache is fresh within TTL (no second fetch); stale after TTL (refetch).
- Simulate a rotation: first fetch returns kid A, issuance returns kid B → SDK refreshes and
  retries successfully with kid B.
- Negative: persistent mismatch after refresh → `DiscoveryError`.
- Update `compile-time-surface.ts`.

---

## Phase 5 — Batch issuance (Rec 6)

**Pure SDK work** (endpoints exist in `batch_issue.rs` and `public_issue.rs`).

**Files:** `sdk/js/src/client/issuance.ts`, `sdk/js/src/client.ts`, `sdk/js/src/types.ts` (add
`BatchIssueReq/Resp`, `TokenResult`, `PublicBatchIssueReq/Resp`), `sdk/js/src/index.ts`,
`sdk/js/tests/compile-time-surface.ts`, new `sdk/js/tests/batch.test.ts`.

**Changes:**
- **`issueTokens(msgs: Uint8Array[], opts?): Promise<FreebirdToken[]>`** → `POST
  {issuerUrl}/v1/oprf/issue/batch` with `{ blinded_elements: string[], sybil_proof }`;
  finalize each `TokenResult::Success` into a `FreebirdToken`; surface per-token
  `TokenResult::Error` codes.
- **`issuePublicTokens(msgs: Uint8Array[], opts?): Promise<PublicBearerPass[]>`** → `POST
  {issuerUrl}/v1/public/issue/batch` with `{ blinded_msgs, token_key_id, sybil_proof }`;
  unblind each returned `blind_signature`.
- Respect `MAX_BATCH_SIZE` (10_000) by chunking.

**Tests (positive + negative/tamper):**
- Round-trip batch with mocked responses; assert per-token finalization.
- Partial failure: some `TokenResult::Error` entries surfaced, not silently dropped.
- Chunking above 10k.
- Update `compile-time-surface.ts`.

---

## Phase 6 — Sybil PoW generation (Rec 3, §1.6)

**Mostly SDK work + one scoped service follow-up.**

**Files:** new `sdk/js/src/client/sybil.ts`, `sdk/js/src/client/issuance.ts`,
`sdk/js/src/client.ts`, `sdk/js/src/types.ts` (add `powDifficulty` to `ClientConfig`),
`sdk/js/tests/compile-time-surface.ts`, new `sdk/js/tests/sybil-pow.test.ts`. **Service
follow-up (separate PR):** `issuer/src/routes/metadata.rs` + `common/src/api/issuance.rs` to
publish sybil requirements in `/.well-known/issuer`.

**Changes:**
- **Only PoW, `rate_limit`, and `multi` composition are client-generable.** Do NOT expose a
  free-standing `generateSybilProof` that fabricates HMAC variants.
- **Integrate PoW generation inside `issueToken`, `issuePublicToken`, `issueTokens`,
  `issuePublicTokens`** so the SDK computes the exact per-endpoint request binding internally:
  - V4 single: `freebird:issue:v1:<issuer_id>:<blinded_element_b64>` (from `issue.rs`).
  - V5 single: `freebird:public-issue:v1:<issuer_id>:<blinded_msg_b64>` (from
    `public_issue.rs:56-59`).
  - Renew: `freebird:renew:v1:<issuer_id>:<blinded_element_b64>` (from `issue.rs:374-377`).
  - Batch: `batch_request_binding("issue-batch"|"public-issue-batch", issuer_id,
    blinded_elements)` (from `batch_issue.rs:76-94`).
- **`powDifficulty` as client config** (default off). Add an **async/yielding mining loop**
  (e.g. `await new Promise(r => setTimeout(r, 0))` every N iterations) so the event loop isn't
  blocked.
- **Service follow-up (scoped separately):** publish sybil requirements (whether PoW is
  required, difficulty, which mechanisms) in `/.well-known/issuer` so the SDK can auto-select.
  This is a **separate small PR** per the repo's "small focused PRs" rule and touches
  `metadata.rs` + `common/src/api/issuance.rs` + docs. Until it lands, the SDK uses
  `powDifficulty` client config.

**Tests:**
- PoW produces a valid `proof_of_work` with the exact per-endpoint binding string
  (fixture-locked against the Rust binding format).
- Negative: tampered binding (wrong issuer_id / blinded element) fails verification logic.
- Mining loop yields (assert no synchronous block via a timer-based test).
- Update `compile-time-surface.ts`.

---

## Phase 7 — Protocol utilities (Rec 7)

**Pure SDK work.**

**Files:** new `sdk/js/src/client/protocol.ts`, `sdk/js/src/client.ts`, `sdk/js/src/index.ts`,
`sdk/js/tests/compile-time-surface.ts`, new `sdk/js/tests/protocol.test.ts`.

**Changes:**
- **`generateOperationId(): string`** — canonical base64url for exactly 16 bytes (matches
  `validateExchangeOperationId` in `exchange.ts:37-50` and `isCanonicalBase64Url(…, 16)`).
- **`generateStatusCapability(): string`** — canonical base64url for exactly 32 bytes (matches
  `validateStatusCapability`/`validateGraphStatusCapability`).
- **`exchangePasses(sources, transition, opts?): Promise<ExchangeRequest>`** — assembles a
  valid `ExchangeRequest` from the active graph/transition (via `selectExchangeTransition`),
  filling `public_operation_id`, `graph_id`, `transition_id`, `source_keyset_id`,
  `target_keyset_id`, `sources`, and blinded `outputs`. This is the "no bespoke code"
  convenience that makes §1.7 achievable.

**Tests:**
- `generateOperationId`/`generateStatusCapability` produce canonical values that pass the
  existing validators.
- `exchangePasses` produces a request that passes `exchangeRequestDigest` and
  `validateExchangeRequestSelection` against a fixture graph/transition.
- Negative: mismatched source/target keyset rejected.
- Update `compile-time-surface.ts`.

---

## Phase 8 — Persistence & polling (Rec 8, §1.4)

**Pure SDK work.**

**Files:** new `sdk/js/src/client/token_store.ts`, new `sdk/js/src/client/poll.ts`,
`sdk/js/src/client.ts`, `sdk/js/src/types.ts` (add `tokenStore` to `ClientConfig`; widen
`TokenStore`), `sdk/js/src/index.ts`, `sdk/js/tests/compile-time-surface.ts`, new
`sdk/js/tests/token-store.test.ts`, new `sdk/js/tests/poll.test.ts`.

**Changes:**
- **Widen `TokenStore`** from the spec's single-slot interface to a multi-token store keyed by
  token id:
  ```ts
  interface TokenStore {
    save(token: FreebirdToken): Promise<void>;
    load(id?: string): Promise<FreebirdToken | null>;
    list(): Promise<FreebirdToken[]>;
    clear(): Promise<void>;
  }
  ```
- Provide `MemoryTokenStore` and `StorageTokenStore` (localStorage/IndexedDB in browser,
  filesystem in Node).
- **V5 `valid_until`-aware eviction:** `FreebirdToken`/`PublicBearerPass` should carry
  `valid_until` (from `PublicKeyInfo.valid_until`); evict expired tokens on `load`/`list`.
- **Documented serialization format for `GraphIssuanceRecoveryContext`** (JSON round-trip;
  `blindingState` is opaque/caller-owned per `types.ts:241-254`).
- **`pollExchangeStatus(request, statusCapability, { intervalMs?, timeoutMs?, signal? })`**
  and **`pollGraphIssuanceStatus(context, { … })`** wrapping `getExchangeStatus`/
  `getGraphIssuanceStatus` with retry/backoff until terminal outcome. **Honor server
  `retryAfter` as the floor** for the next poll (both helpers), matching the
  `ExchangePendingOutcome.retryAfter` already parsed in `exchange.ts:266-273`.

**Tests:**
- Multi-token save/load/list/clear; V5 expiry eviction (positive + expired negative).
- `GraphIssuanceRecoveryContext` JSON round-trip preserves all fields.
- Poll helpers terminate on committed/error; respect `retryAfter` floor; abort on `signal`.
- Update `compile-time-surface.ts`.

---

## Phase 9 — Explicit scoping statement (Rec 9)

**Pure SDK work (documentation + optional separate clients).**

**Files:** `sdk/js/README.md`, `sdk/js/src/index.ts` (optional), possibly new
`sdk/js/src/admin_client.ts` / `sdk/js/src/attester_client.ts` (optional).

**Changes:**
- Declare **out of scope** for the core client: admin operations, WebAuthn ceremony, attester
  interaction, and `/v1/oprf/renew` (admin-authenticated, `RegisteredUser`-only — confirmed in
  `issue.rs:276-291`). Point to `freebird-cli`, `admin-ui`, `docs/webauthn-browser-flow.md`.
- List `POST /v1/public/graph/replay-authority/probe` as **verifier-operator-only** (confirmed
  in `verifier/src/replay_authority.rs:31`).
- **Optional:** add a separate `AdminClient` (for `/v1/oprf/renew` with `X-Admin-Key`) and/or
  an attester client as opt-in submodules, clearly separated from the core client. This is
  optional and can be deferred.

**Tests:** README/type-surface only; if `AdminClient` is added, unit tests for the
`X-Admin-Key` header and constant-time key handling.

---

## Phase 10 — Contract gate + acceptance (Rec 10, §1.7)

**Pure SDK work.**

**Files:** `sdk/js/tests/compile-time-surface.ts`, `sdk/js/tests/package-surface.test.ts`,
`sdk/js/tests/package-consumers/`, `sdk/js/README.md`.

**Changes:**
- Extend `compile-time-surface.ts` to pin **every** new method added in Phases 1–8:
  `checkToken`, `verifyBatch`, `issuePublicToken`, `verifyPublicBearerPassLocally`,
  `refreshKeyDiscoveryMetadata`, `issueTokens`, `issuePublicTokens`, `generateOperationId`,
  `generateStatusCapability`, `exchangePasses`, `pollExchangeStatus`,
  `pollGraphIssuanceStatus`, plus the new error classes and `crypto.rsa*` exports.
- Update `package-surface.test.ts` and `package-consumers/` to confirm
  `npm install @freebird/sdk` + `import { FreebirdClient }` resolves types.
- **Acceptance (§1.7):** a consumer can complete V4 issue→verify, V5 issue→verify, and V2
  exchange→status with **zero bespoke protocol code** — demonstrated by a new example under
  `sdk/js/examples/` (or a consumer test) exercising `issueToken` → `verifyToken`,
  `issuePublicToken` → `verifyPublicBearerPassLocally` + `verifyToken`, and `exchangePasses` →
  `exchange` → `pollExchangeStatus`.

---

## Security conventions that apply (from AGENTS.md)

- **Constant-time compares:** any new secret comparison (e.g. `AdminClient` key check) must use
  `subtle`/`hmac`, never `==`. The SDK's existing `bytesEqual` in `wire.ts` is used for
  scope-digest checks — keep that pattern.
- **No client-facing error detail leaks:** typed errors carry a `code` and generic message;
  server error bodies (`errText`) must be logged/attached only where safe, never echoed
  verbatim to end users. Follow the existing pattern in `issuance.ts` which throws generic
  messages.
- **Zeroization:** `RsaBlindState` and `BlindState` hold secret blinding factors; document that
  `@cloudflare/blindrsa-ts` handles zeroization, and avoid persisting `blindingState` secrets
  to `TokenStore` (recovery context `blindingState` is caller-owned and opaque — do not
  serialize secrets into the store).
- **Generic error strings:** keep `FreebirdError.message` generic; put detail in `code`/server
  logs.

## AGENTS.md "ask before touching" constraints

- **Crypto primitives / token wire formats:** Phase 3 reuses existing
  `voprf.buildPublicBearerPass`/`parsePublicBearerPass` and delegates blinding to
  `@cloudflare/blindrsa-ts` — it does **not** modify `crypto/src/lib.rs` wire formats. Flag to
  a maintainer before any change to the V5 pass wire format.
- **Sybil semantics:** Phase 6 does not change combiner semantics; it only computes the
  existing per-endpoint request bindings. The service follow-up (publishing sybil
  requirements) must be reviewed for threat-model impact before merging.
- **Nullifier derivation:** not touched by any phase.

## Service changes requiring separate scoped PRs

1. **Publish sybil requirements in `/.well-known/issuer`** (Phase 6 follow-up):
   `issuer/src/routes/metadata.rs` + `common/src/api/issuance.rs` + docs. Needed to auto-select
   PoW difficulty; until then the SDK uses client config.
2. **Optional:** none of the verification/batch endpoints need service changes — they already
   exist.

---

## Verification strategy

- **Per-phase unit tests** (positive + negative/tamper) as listed above, using mocked `fetch`
  (pattern from `sybil.test.ts` / `client.test.ts`).
- **Contract gate:** `compile-time-surface.ts` updated in every phase that adds public API;
  `npm run lint` (`tsc --noEmit`) enforces it.
- **Fixture-locked tests:** `sybil.test.ts` locks `common/test-fixtures/sybil-proofs.json` — do
  not alter the fixture; new PoW tests add their own fixtures for the binding strings.
- **Integration tests:** add `sdk/js/tests/integration.test.ts` cases (or extend existing) that
  run against a live issuer+verifier (the local V4 round-trip from AGENTS.md) for
  `verifyToken`/`checkToken`/`verifyBatch` and key-rotation retry.
- **Full CI matrix (must pass before merge):**
  - `cargo fmt -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace` (Redis tests skip if unreachable)
  - `cargo audit`
  - `cd sdk/js && npm run lint && npm test`
  - `cargo check -p freebird-crypto --features pkcs11` (if crypto touched — not expected here)

---

## Recommended sequencing / priority

**Prerequisites for the "no bespoke code" acceptance bar (§1.7):**
1. **Phase 0** (packaging) — needed for installability.
2. **Phase 1** (typed errors) — foundation for everything else.
3. **Phase 2** (verification surface) — fixes the biggest consumer pain (verifyToken
   collapsing everything to `false`).
4. **Phase 3** (V5 RSA) — required for V5 issue→verify with zero bespoke code.
5. **Phase 4** (key rotation) — fixes a live bug; long-lived clients break without it.
6. **Phase 7** (protocol utilities incl. `exchangePasses`) — required for V2 exchange→status
   with zero bespoke code.
7. **Phase 8** (persistence/polling) — required for the "no bespoke retry/poll/storage" bar.

**High-value but not strictly on the acceptance critical path:**
8. **Phase 5** (batch issuance) — needed only for batch consumers.
9. **Phase 6** (Sybil PoW) — needed only where PoW is enforced; the service follow-up is a
   separate PR.
10. **Phase 9** (scoping) — documentation; do early alongside Phase 0 to set expectations.
11. **Phase 10** (contract gate + acceptance) — final gate; update incrementally with each
    phase, finalize last.

**Recommended order:** 0 → 1 → 2 → 3 → 4 → 7 → 8 → 5 → 6 → 9 → 10, with Phase 10's
contract-gate updates folded into each phase and finalized at the end. Phases 0–4, 7, 8 are
the minimum set to meet the §1.7 "zero bespoke code" bar for the three core flows (V4
issue→verify, V5 issue→verify, V2 exchange→status).
