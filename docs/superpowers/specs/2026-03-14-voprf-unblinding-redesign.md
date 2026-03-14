# VOPRF Unblinding Redesign

**Date:** 2026-03-14
**Status:** Draft
**Authors:** Human + Claude

## Problem

Freebird's VOPRF implementation omits the unblinding step from the protocol. In `Client::finalize()`, the evaluated element `B = A * sk` is hashed directly without removing the blinding factor `r`. The token sent to the verifier contains the original blinded element `A` and the DLEQ proof, making issuance and redemption trivially linkable.

This breaks three core security properties:

1. **Unlinkability**: The verifier sees `A`, the same value sent to the issuer. Colluding issuer and verifier can link tokens.
2. **Nullifier correctness**: Nullifiers derive from blinded `B` (which includes random `r`), so the same input blinded with different `r` values produces different nullifiers. This defeats replay protection — a user can double-spend by re-blinding the same input.
3. **Obliviousness**: The blinding serves no cryptographic purpose since blinded elements travel to the verifier unchanged.

The existing test suite passes because both `Client::finalize()` and `Verifier::verify()` hash blinded `B` directly, so their outputs match — but both values are wrong.

## Approach

Pure VOPRF per RFC 9381 with separated concerns:

- **DLEQ proof**: Used client-side only to verify issuer honesty during issuance. Discarded after verification. Never sent to verifier.
- **ECDSA signature**: Used verifier-side to authenticate token metadata. Issuer signs metadata fields. Verifier checks signature using issuer's public key.
- **PRF output**: Self-authenticating bearer credential. Only someone with the issuer's secret key can produce `H(input)^sk`. Serves as the nullifier source.

No backwards compatibility with V1/V2 token formats. Clean break.

## Protocol Flow

### Issuance (Client <-> Issuer)

```
CLIENT                              ISSUER
  |                                   |
  | 1. input = random(32)             |
  | 2. P = H2C(input)                 |
  | 3. r = random_scalar()            |
  | 4. A = P * r                      |
  |                                   |
  | 5. send A --------------------->  |
  |                                   | 6. B = A * sk
  |                                   | 7. proof = DLEQ(sk, G, pk, A, B)
  |                                   | 8. sig = ECDSA_sign(metadata_msg)
  |                                   |    (see "ECDSA Signed Message" below)
  |                                   |
  |  <--- (B, proof, sig, kid, exp,   |
  |        issuer_id) ------------    |
  |                                   |
  | 9.  verify DLEQ(G, pk, A, B, proof)
  | 10. r_inv = r^(-1)
  | 11. W = B * r_inv = H(input)^sk
  | 12. output = SHA256("VOPRF-P256-SHA256:Finalize"
  |              || ctx || encode_compressed(W))
  | 13. discard A, B, proof, r
  |                                   |
  | Client holds: (output, sig, kid, exp, issuer_id)
  | Client builds V3 redemption token from these fields.
```

### Redemption (Client <-> Verifier)

```
CLIENT                              VERIFIER
  |                                   |
  | send V3 redemption token -------->|
  |                                   |
  |                                   | 1. parse V3 token
  |                                   | 2. check exp > now (with clock skew tolerance)
  |                                   | 3. lookup issuer pubkey by (kid, issuer_id)
  |                                   | 4. verify ECDSA_sig over metadata_msg
  |                                   | 5. nullifier = base64url(SHA256(issuer_id || "|" || base64url(output)))
  |                                   | 6. check nullifier not in spent DB
  |                                   | 7. store nullifier with exp TTL
  |                                   |
  |  <------------- success ----------|
```

## Token Formats

### Issuance Evaluation (Issuer -> Client, ephemeral)

The VOPRF evaluation portion of the issuer's response:

```
[VERSION(1) | A(33) | B(33) | DLEQ_proof(64)] = 131 bytes
```

VERSION = `0x01` (unchanged). This is only the VOPRF evaluation blob. The full API response wraps it with additional fields (`sig`, `kid`, `exp`, `issuer_id`) as separate JSON fields — see `IssueResp` in the API Changes section.

Consumed by `Client::finalize()` to verify the DLEQ proof and unblind. Discarded after. Never sent to verifier.

### V3 Redemption Token (Client -> Verifier)

```
[VERSION(1) | output(32) | kid_len(1) | kid(N) | exp(8) | issuer_id_len(1) | issuer_id(M) | ECDSA_sig(64)]
```

- `VERSION`: `0x03`
- `output`: 32 bytes, unblinded PRF output (see PRF Output Derivation below)
- `kid_len` + `kid`: length-prefixed key ID (1-255 bytes)
- `exp`: 8 bytes, expiration as i64 big-endian seconds since Unix epoch (matches existing codebase convention; must be non-negative)
- `issuer_id_len` + `issuer_id`: length-prefixed issuer identifier (1-255 bytes)
- `ECDSA_sig`: 64 bytes over the metadata message (see ECDSA Signed Message below)

Maximum token size enforced at 512 bytes by verifiers.

**Parsing validation** (both Rust and JS parsers must enforce):

1. Total length >= 109 bytes (minimum: 1 + 32 + 1 + 1 + 8 + 1 + 1 + 64) and <= 512 bytes
2. `VERSION` == `0x03`
3. `kid_len` >= 1
4. `issuer_id_len` >= 1
5. After parsing `kid` and `issuer_id`, exactly 64 bytes must remain for `ECDSA_sig`
6. If any length check fails, reject with a decode error — do not attempt partial parsing

### Deleted Formats

- V1 (`0x01` MAC over blinded token): removed, all code paths deleted
- V2 (`0x02` ECDSA over blinded token): removed, all code paths deleted

Note: the issuance evaluation format retains `0x01` as its version byte. This is acceptable because the issuance evaluation is ephemeral and never interpreted by the verifier. There is no ambiguity — the verifier only accepts `0x03` redemption tokens.

### PRF Output Derivation

The PRF output is derived from the unblinded point `W`:

```
output = SHA256("VOPRF-P256-SHA256:Finalize" || ctx || encode_compressed(W))
```

Where:
- `"VOPRF-P256-SHA256:Finalize"` is the literal ASCII byte string (26 bytes)
- `ctx` is the VOPRF context bytes (e.g., `b"freebird:v1"`) — a client-side and issuer-side configuration parameter, not included in the redemption token
- `encode_compressed(W)` is the SEC1 compressed point encoding of `W` (33 bytes)
- `W = B * r^(-1) = H(input)^sk` — the unblinded VOPRF evaluation

The output is 32 bytes (SHA-256 digest).

### ECDSA Signed Message

```
ECDSA_sign(SHA256("freebird:token-metadata:v3" || kid_len || kid || exp || issuer_id_len || issuer_id))
```

Where:
- `"freebird:token-metadata:v3"` is the domain separation prefix (literal ASCII, 28 bytes)
- `kid_len` is a single byte encoding `len(kid)`
- `kid` is the raw key ID bytes
- `exp` is the 8-byte i64 big-endian encoding
- `issuer_id_len` is a single byte encoding `len(issuer_id)`
- `issuer_id` is the raw issuer identifier bytes

Length prefixes are included in the hash preimage to prevent field boundary ambiguity (e.g., `kid="ab", issuer_id="cd"` vs `kid="a", issuer_id="XXcd"`).

The PRF output is not included in the signed message because the issuer cannot compute it (it doesn't know `r` or `H(input)`). The output is self-authenticating via the discrete log assumption — see Trust Model below.

### Nullifier Derivation

```
nullifier = base64url(SHA256(issuer_id || "|" || base64url(output)))
```

This matches the existing `nullifier_key()` function signature and format. The only change is that `output` is now derived from the unblinded point `W` instead of the blinded point `B`.

## Trust Model for PRF Output

The verifier cannot independently recompute or verify the `output` field in the V3 redemption token. This is a fundamental property of the VOPRF design — the verifier does not know `input` or `sk`.

The verifier's trust in `output` rests on two properties:

1. **Unforgeability**: Producing a valid `output` requires computing `H(input)^sk`, which requires the issuer's secret key. An attacker without `sk` cannot forge outputs (discrete log assumption on P-256).
2. **ECDSA binding**: The ECDSA signature binds `(kid, exp, issuer_id)` to the issuer's identity. A valid signature proves the issuer authorized a token with this metadata.

The verifier trusts that the `output` field is a valid PRF evaluation because only the holder of the issuer's secret key could have caused the client to produce such a value. The DLEQ proof (verified client-side during issuance) ensures the client only accepts honestly-computed evaluations.

**Consequence**: If there is a bug in client-side unblinding, or if a malicious client sends a garbage `output`, the verifier will accept it as long as the ECDSA signature on the metadata is valid. The nullifier would be derived from the garbage output, meaning:
- A garbage output wastes a valid ECDSA signature (the attacker needs one from the issuer)
- The real token's output can still be redeemed separately (different nullifier)
- The attacker gains no additional capability beyond what the valid token already provides

This is the standard trust model for VOPRF-based bearer credentials (e.g., Privacy Pass).

## Component Changes

### crypto/src/voprf/core.rs

**Client::finalize()** — add unblinding:

```rust
// After DLEQ verification:
let r_inv = st.r.invert();
if bool::from(r_inv.is_none()) {
    return Err(Error::ZeroScalar); // unreachable: r guaranteed non-zero
}
let w = b * r_inv.unwrap();

// Check W is not identity point
if bool::from(w.to_affine().is_identity()) {
    return Err(Error::InvalidPoint);
}

let output = prf_output(&w, &self.ctx);
```

Return type changes from `(Vec<u8>, Vec<u8>)` (token_bytes, prf_output) to `[u8; 32]` — just the 32-byte unblinded PRF output. The blinded evaluation bytes are discarded.

**Verifier struct** — gutted. Removes all DLEQ verification and point decoding. Replaced with:

- `parse_redemption_token(token_bytes: &[u8]) -> Result<RedemptionToken, Error>` — deserialize V3 format
- `verify_redemption(token: &RedemptionToken, issuer_pubkey: &[u8]) -> Result<[u8; 32], Error>` — check ECDSA sig, return output for nullifier derivation

**Server::evaluate()** — unchanged. Still computes `B = A * sk` with DLEQ proof.

**prf_output_from_b()** — renamed to `prf_output()`. Parameter name changes from `b` to `w` to reflect it now takes the unblinded point. Hash preimage unchanged: `SHA256("VOPRF-P256-SHA256:Finalize" || ctx || encode_compressed(point))`.

### crypto/src/voprf/dleq.rs

Unchanged. DLEQ is still used client-side during `finalize()`.

### crypto/src/lib.rs

New struct:

```rust
pub struct RedemptionToken {
    pub output: [u8; 32],
    pub kid: String,
    pub exp: i64,
    pub issuer_id: String,
    pub sig: [u8; 64],
}
```

New functions:

- `build_redemption_token(token: &RedemptionToken) -> Vec<u8>` — serialize V3 wire format
- `parse_redemption_token(bytes: &[u8]) -> Result<RedemptionToken, Error>` — deserialize V3 format, validate version byte `0x03`

Updated functions:

```rust
// BEFORE:
pub fn compute_token_signature(
    issuer_sk: &[u8; 32],
    token_bytes: &[u8],    // REMOVED
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> Result<[u8; 64], Error>

// AFTER:
pub fn compute_token_signature(
    issuer_sk: &[u8; 32],
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> Result<[u8; 64], Error>
```

```rust
// BEFORE:
pub fn verify_token_signature(
    issuer_pubkey: &[u8],
    token_bytes: &[u8],    // REMOVED
    received_signature: &[u8; 64],
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> bool

// AFTER:
pub fn verify_token_signature(
    issuer_pubkey: &[u8],
    received_signature: &[u8; 64],
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> bool
```

Both functions internally compute:
```rust
SHA256("freebird:token-metadata:v3" || kid_len(1) || kid || exp(8, i64 BE) || issuer_id_len(1) || issuer_id)
```

Deleted functions:
- `verify_token_mac()` — V1 dead code
- `compute_token_mac()` — V1 dead code
- `derive_mac_key_v2()` — no longer needed (MAC format is dead)

`nullifier_key()` — signature unchanged (`fn nullifier_key(issuer_id: &str, token_output_b64: &str) -> String`). Now receives the base64url-encoded unblinded output instead of the blinded one.

### crypto/src/provider/*

```rust
// BEFORE:
async fn sign_token_metadata(
    &self,
    token_bytes: &[u8],    // REMOVED
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> Result<[u8; 64], CryptoError>

// AFTER:
async fn sign_token_metadata(
    &self,
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> Result<[u8; 64], CryptoError>
```

Updated in:
- `CryptoProvider` trait (`provider/mod.rs`)
- `SoftwareCryptoProvider` (`provider/software.rs`)
- `Pkcs11CryptoProvider` (`provider/pkcs11.rs`)

`derive_mac_key()` — removed from the trait (MAC format is dead).

### common/src/api.rs

**IssueResp** — updated:

```rust
pub struct IssueResp {
    /// Base64url-encoded VOPRF evaluation [VERSION|A|B|DLEQ_proof] (131 bytes)
    pub token: String,

    /// Base64url-encoded ECDSA signature over metadata (64 bytes)
    pub sig: String,

    /// Key identifier used for issuance
    pub kid: String,

    /// Expiration timestamp (Unix seconds, i64)
    pub exp: i64,

    /// Issuer identifier (needed by client to build redemption token)
    pub issuer_id: String,

    /// Optional Sybil resistance verification info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}
```

Changes from current:
- `proof` field removed (DLEQ proof is inside `token` bytes, not separate)
- `sig` field added (ECDSA signature, new)
- `issuer_id` field added (client needs it for redemption token)
- `epoch` field removed (was for MAC key derivation, MAC format is dead)

**TokenResult** (batch) — same changes: drop `proof` and `epoch`, add `sig` and `issuer_id`.

**VerifyReq** — simplified:

```rust
pub struct VerifyReq {
    /// Base64url-encoded V3 redemption token (self-contained)
    pub token_b64: String,
}
```

The V3 redemption token contains `output`, `kid`, `exp`, `issuer_id`, and `sig` internally. No separate fields needed. `epoch` is dropped (was for MAC key derivation). `issuer_id` is parsed from the token.

**TokenToVerify** (batch) — same simplification: just `token_b64`.

**VerifyResp** — unchanged.

### sdk/js/src/crypto/voprf.ts

**`finalize()` return type change:**

```typescript
// BEFORE:
finalize(state: BlindState, evaluationB64: string, issuerPubkeyB64: string): Uint8Array
// Returns: full 131-byte token (blinded, wrong)

// AFTER:
finalize(state: BlindState, evaluationB64: string, issuerPubkeyB64: string): Uint8Array
// Returns: 32-byte unblinded PRF output
```

Implementation adds:
```typescript
const rInv = modInverse(state.r, P256.CURVE.n);
const W = B.multiply(rInv);
const output = sha256("VOPRF-P256-SHA256:Finalize" || ctx || compressPoint(W));
return output; // 32 bytes
```

Blinded elements and DLEQ proof are discarded after verification.

**New functions:**

```typescript
// Build V3 redemption token from components
function buildRedemptionToken(
    output: Uint8Array,  // 32 bytes from finalize()
    kid: string,
    exp: bigint,         // i64
    issuerId: string,
    sig: Uint8Array      // 64 bytes from issuer response
): Uint8Array

// Parse V3 redemption token
function parseRedemptionToken(tokenBytes: Uint8Array): {
    output: Uint8Array,
    kid: string,
    exp: bigint,
    issuerId: string,
    sig: Uint8Array,
}
```

**Typical client usage:**

```typescript
// 1. Blind
const { blinded, state } = voprf.blind(input);

// 2. Send to issuer, receive response
const resp = await issuer.issue(blinded);

// 3. Finalize (verify DLEQ + unblind)
const output = voprf.finalize(state, resp.token, issuerPubkey);

// 4. Build redemption token
const redemptionToken = buildRedemptionToken(
    output, resp.kid, resp.exp, resp.issuer_id, resp.sig
);

// 5. Send to verifier
await verifier.verify(redemptionToken);
```

**`deriveTokenValue()`** — removed. Its purpose was to extract and hash `B` from the old token format. No longer needed since `finalize()` returns the PRF output directly.

### issuer/src/routes/issue.rs + batch_issue.rs

- `sign_token_metadata()` call drops `token_bytes` parameter: `provider.sign_token_metadata(kid, exp, issuer_id)`
- Response construction builds `IssueResp` with new fields (`sig`, `issuer_id`, no `proof`/`epoch`)
- MAC key derivation (`derive_mac_key_for_epoch`) calls removed

### issuer/src/voprf_core.rs + multi_key_voprf.rs

- `sign_token_metadata()` method signature drops `token_bytes: &[u8]` parameter
- `derive_mac_key_for_epoch()` — removed
- `EvaluationWithKid` may add `sig` field or be restructured

### verifier/src/

- Verification route accepts V3 redemption tokens only
- Calls `parse_redemption_token()` to extract fields
- Checks expiration from parsed `exp`
- Looks up issuer pubkey using parsed `(kid, issuer_id)` from federation config
- Calls `verify_token_signature()` with parsed fields (no `token_bytes`)
- Derives nullifier from `output` field via `nullifier_key(issuer_id, base64url(output))`
- All DLEQ verification, point decoding, and MAC verification logic removed

### Integration tests

Delete all existing roundtrip and e2e tests (they validate broken behavior). New tests:

- **Unblinding correctness**: For known `(input, sk)`, verify that `finalize()` produces `W = H(input)^sk` by independently computing the expected value server-side
- **ECDSA signature round-trip**: Sign metadata with `compute_token_signature()`, verify with `verify_token_signature()`, both using the new message format
- **Nullifier determinism**: Same `input` blinded with different `r` values produces identical `output` and identical nullifier after unblinding
- **V3 token round-trip**: `build_redemption_token()` then `parse_redemption_token()` recovers all fields
- **Tampered output rejection**: Modify `output` bytes in a V3 token — nullifier changes, so replay protection still works (but note: ECDSA sig does not cover output, so the signature still passes; the test verifies the nullifier is different)
- **Expired token rejection**: Token with `exp` in the past is rejected
- **Replay detection**: Same token redeemed twice — second attempt rejected via nullifier
- **Wrong issuer signature**: Token with valid format but signature from different key is rejected
- **Property test**: For any `(input, r1, r2, sk)`, blinding with `r1` vs `r2` produces identical `output` after unblinding

## Security Properties

### Restored

- **Unlinkability**: Verifier sees `(output, kid, exp, issuer_id, sig)`. None linkable to blinded element `A` seen by issuer. Different `r` values produce different `A` but identical `W = H(input)^sk` and identical `output`.
- **Nullifier correctness**: Nullifiers derive from deterministic `output`. Same `(input, sk)` pair always produces same nullifier regardless of blinding factor. Double-spend via re-blinding is eliminated.
- **Obliviousness**: Issuer sees only `A = H(input) * r`. Without `r`, it cannot recover `H(input)` or `input`.

### Preserved

- **Unforgeability**: Producing valid `output` requires computing `H(input)^sk`, which requires the secret key. Discrete log assumption on P-256.
- **Verifiability**: Client verifies DLEQ proof during issuance, ensuring issuer computed `B = A * sk` honestly.
- **Replay protection**: Deterministic nullifier from `output`, stored with expiration TTL.
- **Time-bound validity**: Expiration checked by verifier, encoded in signed metadata.

### Edge Cases

- **Scalar inversion**: `r` guaranteed non-zero by existing loop in `Client::blind()`. `Scalar::invert()` returns `CtOption`; safe to unwrap.
- **Identity point**: After unblinding, check `W != identity`. If identity, reject (indicates corrupted evaluation).
- **Timing**: Scalar inversion and ECDSA verification use constant-time RustCrypto arithmetic. No new timing channels.
- **Token size**: Variable-length `kid` and `issuer_id` bounded by `u8` length prefix (max 255 bytes each). Verifier enforces 512-byte max total.

### Known Limitations

**Output not covered by ECDSA signature**: The ECDSA signature covers `(kid_len || kid || exp || issuer_id_len || issuer_id)` but not `output`. A MITM who possesses a different valid `output` from the same issuer could swap it in. This requires the attacker to already hold a valid unredeemed token from the same issuer with identical `(kid, exp, issuer_id)`. In a batch issuance scenario, all tokens in a batch (which share the same metadata) are freely interchangeable — but this does not grant additional spending capability (N tokens remain N tokens, just shuffled). The attack is self-limiting.

**Context parameter (`ctx`) role change**: The VOPRF context string `ctx` (e.g., `b"freebird:v1"`) is used in PRF output derivation and DLEQ proof computation. Under the new design, `ctx` is purely a client-side and issuer-side parameter — it does not appear in the V3 redemption token and the verifier does not need it. Issuers and clients must agree on `ctx` out-of-band (typically via configuration).

## Migration

This is a clean break, not a migration.

**Deleted:**
- V1 token format (MAC over blinded token) — all code paths
- V2 token format (ECDSA over blinded token) — all code paths
- `Verifier::verify()` in `core.rs` (DLEQ-based verifier)
- `verify_token_mac()` and `compute_token_mac()` in `lib.rs`
- `derive_mac_key_v2()` in `lib.rs`
- `derive_mac_key()` from `CryptoProvider` trait
- `epoch` field from `IssueResp`, `TokenResult`, `VerifyReq`, `TokenToVerify`
- All token parsing expecting `[VERSION | A | B | Proof]` at the verifier
- All existing integration tests

**Kept:**
- `Client::blind()` — correct as-is
- `Server::evaluate()` — correct as-is
- `dleq.rs` — correct, used client-side
- `hash_to_curve()` — correct
- ECDSA signing/verification primitives — reused with new signed message format
- Nullifier derivation logic (`nullifier_key()`) — reused with correct (unblinded) input
- Provider abstraction — interface changes, architecture stays

**Deployment:** All existing V1/V2 tokens in the wild become invalid. Deployed systems must re-issue tokens after upgrading.
