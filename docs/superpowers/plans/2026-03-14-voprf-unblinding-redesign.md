# VOPRF Unblinding Redesign Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the missing VOPRF unblinding step, introduce V3 redemption tokens, and restore unlinkability across the entire Freebird stack.

**Architecture:** Bottom-up implementation starting from the crypto core (where unblinding happens), propagating through the wrapper layer, provider trait, API types, issuer, verifier, JS SDK, and integration tests. Each task produces a compiling, testable unit before moving on.

**Tech Stack:** Rust (p256, sha2, ecdsa crates), TypeScript (noble-curves), cargo test, TDD throughout.

**Spec:** `docs/superpowers/specs/2026-03-14-voprf-unblinding-redesign.md`

---

## Chunk 1: Crypto Core (VOPRF Unblinding + V3 Token Format)

### Task 1: Fix `Client::finalize()` to unblind

**Files:**
- Modify: `crypto/src/voprf/core.rs:96-105` (rename `prf_output_from_b` to `prf_output`)
- Modify: `crypto/src/voprf/core.rs:156-211` (add unblinding in `Client::finalize()`)
- Modify: `crypto/src/voprf/core.rs:301-424` (update tests)

- [ ] **Step 1: Rename `prf_output_from_b` to `prf_output` and change parameter name**

In `crypto/src/voprf/core.rs`, rename the function at lines 96-105:

```rust
fn prf_output(w: &ProjectivePoint, ctx: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"VOPRF-P256-SHA256:Finalize");
    h.update(ctx);
    h.update(encode_point(w));
    let out = h.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}
```

Update the call site in `Client::finalize()` (line 209) and `Verifier::verify()` (line 297) to use the new name. This is a rename-only change — no logic change yet.

- [ ] **Step 2: Run tests to verify rename is clean**

Run: `cargo test -p freebird-crypto -- voprf`
Expected: All existing tests still pass.

- [ ] **Step 3: Write the unblinding correctness test**

Add to the `tests` module in `crypto/src/voprf/core.rs`:

```rust
#[test]
fn test_unblinding_produces_correct_prf_output() {
    // Two clients blind the SAME input with DIFFERENT r values.
    // After unblinding, both must produce the SAME output.
    let ctx = b"UNBLIND-TEST";
    let sk_bytes = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    let server = Server::from_secret_key(sk_bytes, ctx).unwrap();
    let pk = server.public_key_sec1_compressed();
    let input = b"same input for both clients";

    // Client 1
    let mut client1 = Client::new(ctx);
    let (blinded1, state1) = client1.blind(input).unwrap();
    let token1 = server.evaluate(blinded1.as_slice()).unwrap();
    let output1 = client1.finalize(state1, &token1, &pk).unwrap();

    // Client 2 (different r, same input)
    let mut client2 = Client::new(ctx);
    let (blinded2, state2) = client2.blind(input).unwrap();
    let token2 = server.evaluate(blinded2.as_slice()).unwrap();
    let output2 = client2.finalize(state2, &token2, &pk).unwrap();

    // Blinded elements must differ (different r)
    assert_ne!(blinded1, blinded2);

    // Unblinded outputs must be identical
    assert_eq!(output1, output2);
}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cargo test -p freebird-crypto -- test_unblinding_produces_correct_prf_output`
Expected: FAIL — `output1 != output2` because `finalize()` currently hashes blinded `B` which includes random `r`.

- [ ] **Step 5: Implement unblinding in `Client::finalize()`**

Replace the body of `Client::finalize()` in `crypto/src/voprf/core.rs:156-211`. The new implementation:

```rust
pub fn finalize(
    self,
    st: BlindState,
    token_bytes: &[u8],
    issuer_pubkey_sec1_compressed: &[u8],
) -> Result<[u8; 32], Error> {
    if token_bytes.len() != TOKEN_LEN {
        return Err(Error::Decode);
    }

    // Check version byte
    if token_bytes[0] != TOKEN_VERSION_V1 {
        return Err(Error::UnsupportedVersion);
    }

    let offset = TOKEN_VERSION_LEN;
    let a = decode_point(&token_bytes[offset..offset + TOKEN_POINT_LEN])?;
    let b = decode_point(&token_bytes[offset + TOKEN_POINT_LEN..offset + TOKEN_POINT_LEN * 2])?;
    let proof_bytes: &[u8; 64] = token_bytes[offset + TOKEN_POINT_LEN * 2..]
        .try_into()
        .map_err(|_| Error::Decode)?;
    let proof = decode_proof(proof_bytes);
    let q = decode_point(issuer_pubkey_sec1_compressed)?;

    let ok = verify(
        &generator().to_affine(),
        &q.to_affine(),
        &a.to_affine(),
        &b.to_affine(),
        &proof,
        Some(&self.ctx),
    );
    if !ok {
        return Err(Error::InvalidProof);
    }

    // Unblind: W = B * r^(-1) = H(input)^sk
    let r_inv = st.r.invert();
    if bool::from(r_inv.is_none()) {
        return Err(Error::ZeroScalar);
    }
    let w = b * r_inv.unwrap();

    // Check W is not the identity point
    if bool::from(w.to_affine().is_identity()) {
        return Err(Error::InvalidPoint);
    }

    Ok(prf_output(&w, &self.ctx))
}
```

Key changes from old code:
- Return type: `Result<[u8; 32], Error>` instead of `Result<(Vec<u8>, Vec<u8>), Error>`
- Computes `r_inv = st.r.invert()` and `w = b * r_inv`
- Hashes unblinded `w` instead of blinded `b`
- Does NOT return the blinded token bytes (they are discarded)

- [ ] **Step 6: Update `test_voprf_rfc_test_vectors` for new return type**

The test at lines 310-350 currently does:
```rust
let (token, output) = client.finalize(state, &token_bytes, &pk).unwrap();
let verifier = Verifier::new(ctx);
let verified_output = verifier.verify(&token, &pk).unwrap();
assert_eq!(output, verified_output);
```

Update to:
```rust
let output = client.finalize(state, &token_bytes, &pk).unwrap();
// output is now a [u8; 32] — the unblinded PRF output
assert_eq!(output.len(), 32);
```

Remove the `Verifier` check from this test — the `Verifier` struct will be rewritten in a later task. For now, just verify `finalize()` returns a 32-byte output without error.

- [ ] **Step 7: Update `test_token_version_checking` for new return type**

The test at lines 385-404 currently matches `finalize()` returning a tuple. Update to match `Result<[u8; 32], Error>`.

- [ ] **Step 8: Update `test_dleq_proof_verification` for new return type**

The test at lines 407-423 currently checks `result.is_ok()` on a tuple. Update to verify the `[u8; 32]` return.

- [ ] **Step 8.5: Update the lib.rs wrapper `Client::finalize()` to compile**

The core `Client::finalize()` return type changed from `Result<(Vec<u8>, Vec<u8>), Error>` to `Result<[u8; 32], Error>`. The wrapper in `crypto/src/lib.rs:102-117` calls `self.inner.finalize()` and must be updated in the same commit to keep the crate compilable. Temporarily update it to:

```rust
pub fn finalize(
    self,
    st: BlindState,
    evaluation_b64: &str,
    issuer_pubkey_b64: &str,
) -> Result<String, Error> {
    let eval_bytes = Base64UrlUnpadded::decode_vec(evaluation_b64)
        .map_err(|_| Error::InvalidInput("bad base64 evaluation".into()))?;
    let pk_bytes = Base64UrlUnpadded::decode_vec(issuer_pubkey_b64)
        .map_err(|_| Error::InvalidInput("bad base64 pubkey".into()))?;

    let output = self.inner.finalize(st.inner, &eval_bytes, &pk_bytes)?;
    Ok(Base64UrlUnpadded::encode_string(&output))
}
```

Also temporarily update or comment out the wrapper `Verifier::verify()` (lines 139-159) if it references the old `prf_output_from_b` name or old `Verifier` behavior. At minimum it must compile. A full rewrite happens in Task 4.

Also update any lib.rs tests that call the wrapper `client.finalize()` expecting a tuple — they must match the new `Result<String, Error>` return.

**IMPORTANT:** This step is critical. Without it, `cargo test` fails between Task 1 and Task 4. The crate must always compile after each commit.

- [ ] **Step 9: Run all crypto tests (full crate, not just voprf module)**

Run: `cargo test -p freebird-crypto`
Expected: All tests pass, including the new `test_unblinding_produces_correct_prf_output`.

- [ ] **Step 10: Commit**

```bash
git add crypto/src/voprf/core.rs crypto/src/lib.rs
git commit -m "fix(crypto): implement VOPRF unblinding in Client::finalize()

Add r^(-1) scalar inversion to remove blinding factor from evaluated
element. finalize() now returns the 32-byte unblinded PRF output
instead of the blinded token bytes. Includes test proving two clients
with different blinding factors produce identical output for the
same input."
```

---

### Task 2: Add V3 redemption token format to crypto lib

**Files:**
- Modify: `crypto/src/lib.rs:63-67` (add Error variants)
- Modify: `crypto/src/lib.rs:169-170` (delete V1/V2 constants)
- Modify: `crypto/src/lib.rs:265-345` (update signature functions)
- Modify: `crypto/src/lib.rs:189-232` (delete MAC functions)
- Modify: `crypto/src/lib.rs:365-386` (delete `derive_mac_key_v2`)
- New code in `crypto/src/lib.rs` (add `RedemptionToken`, builders, parsers)

- [ ] **Step 1: Write test for `RedemptionToken` round-trip**

Add a new test in `crypto/src/lib.rs` test module:

```rust
#[test]
fn test_v3_redemption_token_roundtrip() {
    let token = RedemptionToken {
        output: [0xAA; 32],
        kid: "test-key-01".to_string(),
        exp: 1700000000i64,
        issuer_id: "issuer-abc".to_string(),
        sig: [0xBB; 64],
    };

    let bytes = build_redemption_token(&token).unwrap();

    // Check version byte
    assert_eq!(bytes[0], 0x03);

    // Round-trip
    let parsed = parse_redemption_token(&bytes).unwrap();
    assert_eq!(parsed.output, token.output);
    assert_eq!(parsed.kid, token.kid);
    assert_eq!(parsed.exp, token.exp);
    assert_eq!(parsed.issuer_id, token.issuer_id);
    assert_eq!(parsed.sig, token.sig);
}

#[test]
fn test_v3_redemption_token_rejects_bad_version() {
    let token = RedemptionToken {
        output: [0xAA; 32],
        kid: "k".to_string(),
        exp: 1i64,
        issuer_id: "i".to_string(),
        sig: [0xBB; 64],
    };
    let mut bytes = build_redemption_token(&token).unwrap();
    bytes[0] = 0x01; // wrong version
    assert!(parse_redemption_token(&bytes).is_err());
}

#[test]
fn test_v3_redemption_token_rejects_truncated() {
    let bytes = vec![0x03; 50]; // too short (min 109)
    assert!(parse_redemption_token(&bytes).is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p freebird-crypto -- test_v3_redemption_token`
Expected: FAIL — `RedemptionToken`, `build_redemption_token`, `parse_redemption_token` don't exist yet.

- [ ] **Step 3: Implement `RedemptionToken` struct and V3 constants**

Add to `crypto/src/lib.rs`, near the top (after existing structs):

```rust
const REDEMPTION_TOKEN_VERSION_V3: u8 = 0x03;
const REDEMPTION_TOKEN_MIN_LEN: usize = 1 + 32 + 1 + 1 + 8 + 1 + 1 + 64; // 109
const REDEMPTION_TOKEN_MAX_LEN: usize = 512;

pub struct RedemptionToken {
    pub output: [u8; 32],
    pub kid: String,
    pub exp: i64,
    pub issuer_id: String,
    pub sig: [u8; 64],
}
```

- [ ] **Step 4: Implement `build_redemption_token()`**

```rust
pub fn build_redemption_token(token: &RedemptionToken) -> Result<Vec<u8>, Error> {
    if token.kid.is_empty() || token.kid.len() > 255 {
        return Err(Error::InvalidInput("kid must be 1-255 bytes".into()));
    }
    if token.issuer_id.is_empty() || token.issuer_id.len() > 255 {
        return Err(Error::InvalidInput("issuer_id must be 1-255 bytes".into()));
    }

    let total_len = 1 + 32 + 1 + token.kid.len() + 8 + 1 + token.issuer_id.len() + 64;
    let mut buf = Vec::with_capacity(total_len);

    buf.push(REDEMPTION_TOKEN_VERSION_V3);
    buf.extend_from_slice(&token.output);
    buf.push(token.kid.len() as u8);
    buf.extend_from_slice(token.kid.as_bytes());
    buf.extend_from_slice(&token.exp.to_be_bytes());
    buf.push(token.issuer_id.len() as u8);
    buf.extend_from_slice(token.issuer_id.as_bytes());
    buf.extend_from_slice(&token.sig);

    Ok(buf)
}
```

- [ ] **Step 5: Implement `parse_redemption_token()`**

```rust
pub fn parse_redemption_token(bytes: &[u8]) -> Result<RedemptionToken, Error> {
    if bytes.len() < REDEMPTION_TOKEN_MIN_LEN {
        return Err(Error::InvalidInput("token too short".into()));
    }
    if bytes.len() > REDEMPTION_TOKEN_MAX_LEN {
        return Err(Error::InvalidInput("token too large".into()));
    }
    if bytes[0] != REDEMPTION_TOKEN_VERSION_V3 {
        return Err(Error::InvalidInput("unsupported token version".into()));
    }

    let mut pos = 1;

    // output (32 bytes)
    let output: [u8; 32] = bytes[pos..pos + 32]
        .try_into()
        .map_err(|_| Error::InvalidInput("bad output".into()))?;
    pos += 32;

    // kid (length-prefixed)
    let kid_len = bytes[pos] as usize;
    pos += 1;
    if kid_len == 0 || pos + kid_len > bytes.len() {
        return Err(Error::InvalidInput("bad kid_len".into()));
    }
    let kid = String::from_utf8(bytes[pos..pos + kid_len].to_vec())
        .map_err(|_| Error::InvalidInput("kid not utf8".into()))?;
    pos += kid_len;

    // exp (8 bytes, i64 big-endian)
    if pos + 8 > bytes.len() {
        return Err(Error::InvalidInput("truncated exp".into()));
    }
    let exp = i64::from_be_bytes(
        bytes[pos..pos + 8]
            .try_into()
            .map_err(|_| Error::InvalidInput("bad exp".into()))?,
    );
    pos += 8;

    // issuer_id (length-prefixed)
    if pos >= bytes.len() {
        return Err(Error::InvalidInput("truncated issuer_id_len".into()));
    }
    let issuer_id_len = bytes[pos] as usize;
    pos += 1;
    if issuer_id_len == 0 || pos + issuer_id_len > bytes.len() {
        return Err(Error::InvalidInput("bad issuer_id_len".into()));
    }
    let issuer_id = String::from_utf8(bytes[pos..pos + issuer_id_len].to_vec())
        .map_err(|_| Error::InvalidInput("issuer_id not utf8".into()))?;
    pos += issuer_id_len;

    // sig (exactly 64 bytes remaining)
    if bytes.len() - pos != 64 {
        return Err(Error::InvalidInput("bad sig length".into()));
    }
    let sig: [u8; 64] = bytes[pos..pos + 64]
        .try_into()
        .map_err(|_| Error::InvalidInput("bad sig".into()))?;

    Ok(RedemptionToken {
        output,
        kid,
        exp,
        issuer_id,
        sig,
    })
}
```

- [ ] **Step 6: Add `InvalidInput` variant to Error enum if not present**

Check `crypto/src/lib.rs:63-67` for the `Error` enum. Add:
```rust
InvalidInput(String),
```

- [ ] **Step 7: Run tests**

Run: `cargo test -p freebird-crypto -- test_v3_redemption_token`
Expected: All 3 tests pass.

- [ ] **Step 8: Commit**

```bash
git add crypto/src/lib.rs
git commit -m "feat(crypto): add V3 redemption token format

RedemptionToken struct with build/parse functions implementing the
V3 wire format: [VERSION|output|kid_len|kid|exp|issuer_id_len|
issuer_id|ECDSA_sig]. Includes round-trip, bad-version, and
truncation tests."
```

---

### Task 3: Update ECDSA signature functions for V3 metadata message

**Files:**
- Modify: `crypto/src/lib.rs:265-294` (`compute_token_signature`)
- Modify: `crypto/src/lib.rs:311-345` (`verify_token_signature`)
- Modify: `crypto/src/lib.rs` (tests using these functions)

- [ ] **Step 1: Write test for V3 metadata signature round-trip**

```rust
#[test]
fn test_v3_metadata_signature_roundtrip() {
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    let sk = SigningKey::random(&mut OsRng);
    let sk_bytes: [u8; 32] = sk.to_bytes().into();
    let pk_bytes = sk.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    let kid = "test-key-01";
    let exp = 1700000000i64;
    let issuer_id = "issuer-abc";

    let sig = compute_token_signature(&sk_bytes, kid, exp, issuer_id).unwrap();
    assert!(verify_token_signature(&pk_bytes, &sig, kid, exp, issuer_id));
}

#[test]
fn test_v3_metadata_signature_rejects_wrong_kid() {
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    let sk = SigningKey::random(&mut OsRng);
    let sk_bytes: [u8; 32] = sk.to_bytes().into();
    let pk_bytes = sk.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    let sig = compute_token_signature(&sk_bytes, "key-1", 100i64, "issuer").unwrap();
    // Wrong kid
    assert!(!verify_token_signature(&pk_bytes, &sig, "key-2", 100i64, "issuer"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p freebird-crypto -- test_v3_metadata_signature`
Expected: FAIL — current `compute_token_signature` requires `token_bytes` parameter.

- [ ] **Step 3: Update `compute_token_signature()`**

At `crypto/src/lib.rs:265-294`, change the function signature and message construction:

```rust
pub fn compute_token_signature(
    issuer_sk: &[u8; 32],
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> Result<[u8; 64], Error> {
    let signing_key = SigningKey::from_bytes(issuer_sk.into())
        .map_err(|_| Error::InvalidInput("bad signing key".into()))?;

    // Build domain-separated metadata message
    let msg = build_metadata_message(kid, exp, issuer_id);
    let digest = Sha256::digest(&msg);

    let (signature, _) = signing_key
        .sign_prehash_recoverable(&digest)
        .map_err(|_| Error::InvalidInput("signing failed".into()))?;

    Ok(signature.to_bytes().into())
}
```

- [ ] **Step 4: Update `verify_token_signature()`**

At `crypto/src/lib.rs:311-345`:

```rust
pub fn verify_token_signature(
    issuer_pubkey: &[u8],
    received_signature: &[u8; 64],
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> bool {
    let verifying_key = match VerifyingKey::from_sec1_bytes(issuer_pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let msg = build_metadata_message(kid, exp, issuer_id);
    let digest = Sha256::digest(&msg);

    let signature = match Signature::from_slice(received_signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    verifying_key.verify_prehash(&digest, &signature).is_ok()
}
```

- [ ] **Step 5: Add `build_metadata_message()` helper**

```rust
/// Build the canonical metadata message for V3 ECDSA signing.
/// Format: "freebird:token-metadata:v3" || kid_len(1) || kid || exp(8, i64 BE) || issuer_id_len(1) || issuer_id
fn build_metadata_message(kid: &str, exp: i64, issuer_id: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"freebird:token-metadata:v3");
    msg.push(kid.len() as u8);
    msg.extend_from_slice(kid.as_bytes());
    msg.extend_from_slice(&exp.to_be_bytes());
    msg.push(issuer_id.len() as u8);
    msg.extend_from_slice(issuer_id.as_bytes());
    msg
}
```

- [ ] **Step 6: Delete dead V1 MAC functions and V2 constants**

Delete from `crypto/src/lib.rs`:
- `TOKEN_FORMAT_V1_MAC` constant (line 169)
- `TOKEN_FORMAT_V2_SIGNATURE` constant (line 170)
- `compute_token_mac()` function (lines 189-205)
- `verify_token_mac()` function (lines 219-232)
- `derive_mac_key_v2()` function (lines 365-386)

- [ ] **Step 7: Update existing tests that reference deleted functions or old signatures**

Find and update/delete tests that call `compute_token_signature` with `token_bytes`, `verify_token_mac`, `compute_token_mac`, or `derive_mac_key_v2`. These tests validate broken V1/V2 behavior and should be removed.

- [ ] **Step 8: Run all crypto tests**

Run: `cargo test -p freebird-crypto`
Expected: All tests pass. Some old tests will have been removed. New V3 signature tests pass.

- [ ] **Step 9: Commit**

```bash
git add crypto/src/lib.rs
git commit -m "feat(crypto): update ECDSA signatures for V3 metadata message

Remove token_bytes parameter from compute_token_signature and
verify_token_signature. New signed message format uses domain
separation and length-prefixed fields. Delete dead V1 MAC functions
(compute_token_mac, verify_token_mac, derive_mac_key_v2) and V1/V2
format constants."
```

---

### Task 4: Test and polish crypto wrapper layer (`Client`, `Verifier` in lib.rs)

**Files:**
- Modify: `crypto/src/lib.rs:86-118` (wrapper `Client` impl — already updated in Task 1 Step 8.5, now add tests)
- Modify: `crypto/src/lib.rs:139-159` (wrapper `Verifier` impl — delete if not already done)

Note: The wrapper `Client::finalize()` was already updated in Task 1 Step 8.5 to keep the crate compilable. This task adds proper tests and cleans up the wrapper `Verifier`.

- [ ] **Step 1: Write test for wrapper Client::finalize() returning 32-byte output**

```rust
#[test]
fn test_wrapper_client_finalize_returns_unblinded_output() {
    let ctx = b"wrapper-test";
    let sk_bytes = [42u8; 32];
    let server = Server::from_secret_key(sk_bytes, ctx).unwrap();
    let pk_b64 = Base64UrlUnpadded::encode_string(&server.public_key_sec1_compressed());

    let mut client = Client::new(ctx);
    let (blinded_b64, state) = client.blind(b"test-input").unwrap();

    let blinded_raw = Base64UrlUnpadded::decode_vec(&blinded_b64).unwrap();
    let eval = server.evaluate_with_proof(&blinded_raw).unwrap();
    let eval_b64 = Base64UrlUnpadded::encode_string(&eval);

    let output_b64 = client.finalize(state, &eval_b64, &pk_b64).unwrap();
    let output_raw = Base64UrlUnpadded::decode_vec(&output_b64).unwrap();
    assert_eq!(output_raw.len(), 32);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p freebird-crypto -- test_wrapper_client_finalize_returns_unblinded_output`
Expected: FAIL — current wrapper `finalize()` returns `(String, String)`.

- [ ] **Step 3: Update wrapper `Client::finalize()`**

At `crypto/src/lib.rs:102-117`, update to match the new core return type:

```rust
pub fn finalize(
    self,
    st: BlindState,
    evaluation_b64: &str,
    issuer_pubkey_b64: &str,
) -> Result<String, Error> {
    let eval_bytes = Base64UrlUnpadded::decode_vec(evaluation_b64)
        .map_err(|_| Error::InvalidInput("bad base64 evaluation".into()))?;
    let pk_bytes = Base64UrlUnpadded::decode_vec(issuer_pubkey_b64)
        .map_err(|_| Error::InvalidInput("bad base64 pubkey".into()))?;

    let output = self.inner.finalize(st.inner, &eval_bytes, &pk_bytes)?;
    Ok(Base64UrlUnpadded::encode_string(&output))
}
```

Return type changes from `Result<(String, String), Error>` to `Result<String, Error>` — returns base64url-encoded 32-byte PRF output.

- [ ] **Step 4: Delete the wrapper `Verifier` impl**

Delete the entire `impl Verifier` block at `crypto/src/lib.rs:139-159`. The `Verifier` struct definition can stay but the old `verify()` method that does DLEQ verification on blinded elements is removed. V3 verification uses `parse_redemption_token()` + `verify_token_signature()` directly — no wrapper needed.

- [ ] **Step 5: Update/delete tests referencing old wrapper Verifier or old finalize return type**

Search for tests using `Verifier::new()` and `verifier.verify()` in `crypto/src/lib.rs` tests. Delete or update them.

- [ ] **Step 6: Run all crypto tests**

Run: `cargo test -p freebird-crypto`
Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
git add crypto/src/lib.rs
git commit -m "refactor(crypto): update wrapper Client::finalize() and remove old Verifier

Wrapper finalize() now returns base64url-encoded 32-byte unblinded
PRF output. Old Verifier::verify() (DLEQ-based, blinded tokens)
removed. V3 verification uses parse_redemption_token() +
verify_token_signature() directly."
```

---

### Task 5: Update CryptoProvider trait and implementations

**Files:**
- Modify: `crypto/src/provider/mod.rs:67` (delete `derive_mac_key`)
- Modify: `crypto/src/provider/mod.rs:93-99` (update `sign_token_metadata`)
- Modify: `crypto/src/provider/software.rs:86-106` (update implementations)
- Modify: `crypto/src/provider/pkcs11.rs:428-464` (update implementations)

- [ ] **Step 1: Update `CryptoProvider` trait**

In `crypto/src/provider/mod.rs`:

Remove `derive_mac_key()` method from the trait (line 67 area).

Update `sign_token_metadata()` (lines 93-99) — remove `token_bytes: &[u8]` parameter:

```rust
async fn sign_token_metadata(
    &self,
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> Result<[u8; 64], CryptoError>;
```

- [ ] **Step 2: Update `SoftwareCryptoProvider`**

In `crypto/src/provider/software.rs`:

Delete `derive_mac_key()` implementation (lines 86-94).

Update `sign_token_metadata()` (lines 96-106) — remove `token_bytes` parameter, call updated `compute_token_signature()`:

```rust
async fn sign_token_metadata(
    &self,
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> Result<[u8; 64], CryptoError> {
    crate::compute_token_signature(&self.sk_bytes, kid, exp, issuer_id)
        .map_err(|e| CryptoError::SigningError(format!("{:?}", e)))
}
```

- [ ] **Step 3: Update `Pkcs11CryptoProvider`**

In `crypto/src/provider/pkcs11.rs`:

Delete `derive_mac_key()` implementation (lines 428-437).

Update `sign_token_metadata()` (lines 439-464) — remove `token_bytes` parameter, update the message construction to use `build_metadata_message()`:

```rust
async fn sign_token_metadata(
    &self,
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> Result<[u8; 64], CryptoError> {
    // Build V3 metadata message and sign via HSM
    let msg = crate::build_metadata_message(kid, exp, issuer_id);
    // ... HSM signing logic using msg ...
}
```

Note: Make `build_metadata_message` `pub(crate)` so the PKCS#11 provider can use it.

- [ ] **Step 4: Update provider tests**

Update tests in `crypto/src/provider/software.rs` that call `sign_token_metadata` with `token_bytes`. Remove the `token_bytes` argument from test calls.

- [ ] **Step 5: Run all crypto tests**

Run: `cargo test -p freebird-crypto`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add crypto/src/provider/
git commit -m "refactor(crypto): update CryptoProvider trait for V3 metadata signing

Remove derive_mac_key() from trait (MAC format deleted). Remove
token_bytes parameter from sign_token_metadata() — V3 signs only
(kid, exp, issuer_id) with domain separation."
```

## Chunk 2: API Types, Issuer, and Verifier

### Task 6: Update API types in common/src/api.rs

**Files:**
- Modify: `common/src/api.rs:24-44` (`IssueResp`)
- Modify: `common/src/api.rs:80-93` (`TokenResult`)
- Modify: `common/src/api.rs:100-111` (`VerifyReq`)
- Modify: `common/src/api.rs:129-145` (`BatchVerifyReq`, `TokenToVerify`)

- [ ] **Step 1: Update `IssueResp`**

Replace `IssueResp` at lines 24-44:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct IssueResp {
    /// Base64url-encoded VOPRF evaluation [VERSION|A|B|DLEQ_proof] (131 bytes)
    pub token: String,

    /// Base64url-encoded ECDSA signature over metadata (64 bytes)
    pub sig: String,

    /// Key identifier used for issuance
    pub kid: String,

    /// Expiration timestamp (Unix seconds)
    pub exp: i64,

    /// Issuer identifier
    pub issuer_id: String,

    /// Optional Sybil resistance verification info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}
```

Changes: removed `proof` and `epoch`, added `sig` and `issuer_id`.

- [ ] **Step 2: Update `TokenResult` (batch)**

Replace the `Success` variant in `TokenResult` at lines 82-88:

```rust
Success {
    token: String,
    sig: String,
    kid: String,
    exp: i64,
    issuer_id: String,
},
```

- [ ] **Step 3: Simplify `VerifyReq`**

Replace `VerifyReq` at lines 100-111:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyReq {
    /// Base64url-encoded V3 redemption token (self-contained)
    pub token_b64: String,
}
```

- [ ] **Step 4: Simplify `BatchVerifyReq` and `TokenToVerify`**

Replace `BatchVerifyReq` at lines 129-132:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchVerifyReq {
    pub tokens: Vec<TokenToVerify>,
}
```

Replace `TokenToVerify` at lines 135-145:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenToVerify {
    /// Base64url-encoded V3 redemption token (self-contained)
    pub token_b64: String,
}
```

- [ ] **Step 5: Check compilation**

Run: `cargo check --workspace`
Expected: Compilation errors in issuer and verifier code that reference removed fields (`proof`, `epoch`, `issuer_id` on `VerifyReq`). This is expected — we fix those in the next tasks.

- [ ] **Step 6: Commit**

```bash
git add common/src/api.rs
git commit -m "refactor(api): update types for V3 redemption tokens

IssueResp: remove proof/epoch, add sig/issuer_id.
VerifyReq: simplify to just token_b64 (V3 token is self-contained).
BatchVerifyReq/TokenToVerify: remove issuer_id/epoch/exp fields."
```

---

### Task 7: Update issuer routes

**Files:**
- Modify: `issuer/src/voprf_core.rs:68-86` (delete `derive_mac_key_for_epoch`, update `sign_token_metadata`)
- Modify: `issuer/src/multi_key_voprf.rs:231-248` (same changes)
- Modify: `issuer/src/routes/issue.rs:242-275` (update signature call and response construction)
- Modify: `issuer/src/routes/batch_issue.rs` (same changes if file exists)

- [ ] **Step 1: Update `VoprfCore::sign_token_metadata()`**

In `issuer/src/voprf_core.rs`, delete `derive_mac_key_for_epoch()` (lines 68-75).

Update `sign_token_metadata()` (lines 76-86) — remove `token_bytes` parameter:

```rust
pub async fn sign_token_metadata(
    &self,
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> Result<[u8; 64], IssuanceError> {
    self.provider
        .sign_token_metadata(kid, exp, issuer_id)
        .await
        .map_err(|e| IssuanceError::SigningError(format!("{:?}", e)))
}
```

- [ ] **Step 2: Update `MultiKeyVoprfCore::sign_token_metadata()`**

In `issuer/src/multi_key_voprf.rs`, delete `derive_mac_key_for_epoch()` (lines 231-235).

Update `sign_token_metadata()` (lines 237-248) — remove `token_bytes` parameter.

- [ ] **Step 3: Update issue route response construction**

In `issuer/src/routes/issue.rs`, find where `IssueResp` is constructed (around lines 268-275). Update to:

```rust
IssueResp {
    token: eval_b64,
    sig: Base64UrlUnpadded::encode_string(&sig_bytes),
    kid: kid.clone(),
    exp,
    issuer_id: issuer_id.clone(),
    sybil_info,
}
```

Find the `sign_token_metadata` call (around line 242) and remove the `token_bytes` argument. Remove any `derive_mac_key_for_epoch` calls.

Remove the code that appends the signature to the token bytes (around line 254) — the signature is now a separate response field.

- [ ] **Step 4: Update batch_issue route if it exists**

Apply the same pattern: remove `token_bytes` from `sign_token_metadata` calls, update `TokenResult::Success` construction, remove MAC key derivation.

- [ ] **Step 5: Check issuer compilation**

Run: `cargo check -p freebird-issuer`
Expected: Compiles without errors.

- [ ] **Step 6: Commit**

```bash
git add issuer/
git commit -m "refactor(issuer): update routes for V3 metadata signing

Remove token_bytes from sign_token_metadata calls. Remove MAC key
derivation. IssueResp now returns sig and issuer_id as separate
fields instead of appending signature to token bytes."
```

---

### Task 8: Update verifier

**Files:**
- Modify: `verifier/src/main.rs:296-470` (`verify` function)
- Modify: `verifier/src/main.rs:506-665` (`check` function, if applicable)
- Modify: `verifier/src/main.rs:668-865` (`batch_verify` function)

- [ ] **Step 1: Rewrite the `verify()` function**

The verifier now:
1. Decodes base64url `token_b64` from `VerifyReq`
2. Calls `parse_redemption_token()` to extract V3 fields
3. Checks `exp > now` (with clock skew tolerance)
4. Looks up issuer pubkey using `(kid, issuer_id)` from federation config
5. Calls `verify_token_signature(pubkey, &token.sig, &token.kid, token.exp, &token.issuer_id)`
6. Derives nullifier via `nullifier_key(&token.issuer_id, &base64url(token.output))`
7. Checks/stores nullifier in spend DB

Remove all references to:
- DLEQ proof verification
- `Verifier::new()` / `verifier.verify()`
- MAC verification / `verify_token_mac()`
- `epoch` parameter
- Decoding blinded elements / points

This is the most invasive change. Read the entire `verify()`, `check()`, and `batch_verify()` functions before editing.

- [ ] **Step 2: Update `batch_verify()` function**

Same pattern as single verify: parse V3 token, check ECDSA sig, derive nullifier.

`BatchVerifyReq` no longer has `issuer_id` at the top level — each `TokenToVerify` contains a self-contained V3 token with its own `issuer_id`.

- [ ] **Step 3: Update `check()` function if it exists**

Same changes as `verify()`.

- [ ] **Step 4: Check verifier compilation**

Run: `cargo check -p freebird-verifier`
Expected: Compiles. Warnings about unused imports are fine — clean up in the next step.

- [ ] **Step 5: Clean up unused imports**

Remove imports for DLEQ, MAC, old token parsing that are no longer used.

- [ ] **Step 6: Commit**

```bash
git add verifier/
git commit -m "refactor(verifier): rewrite for V3 redemption tokens

Parse self-contained V3 tokens, verify ECDSA signature over
metadata, derive nullifier from unblinded PRF output. Remove all
DLEQ proof verification, MAC verification, and blinded element
decoding."
```

## Chunk 3: JS SDK and Integration Tests

### Task 9: Update JS SDK VOPRF client

**Files:**
- Modify: `sdk/js/src/crypto/voprf.ts:49-107` (`finalize()`)
- Modify: `sdk/js/src/crypto/voprf.ts:113-129` (delete `deriveTokenValue()`)
- Add new functions: `buildRedemptionToken()`, `parseRedemptionToken()`

- [ ] **Step 1: Update `finalize()` to unblind and return 32-byte output**

In `sdk/js/src/crypto/voprf.ts`, update `finalize()` (lines 49-107).

After DLEQ proof verification, add unblinding:

```typescript
// Unblind: W = B * r^(-1)
const rInv = modInverse(state.r, P256.CURVE.n);
const W = B.multiply(rInv);

// Derive PRF output from unblinded point
const wBytes = W.toRawBytes(true); // SEC1 compressed, 33 bytes
const finalizeInput = new Uint8Array([
    ...new TextEncoder().encode("VOPRF-P256-SHA256:Finalize"),
    ...ctx,
    ...wBytes,
]);
const output = sha256(finalizeInput); // 32 bytes

return output;
```

The function return type changes from `Uint8Array` (131-byte blinded token) to `Uint8Array` (32-byte PRF output).

Add `modInverse` helper if not already present (use `noble-curves` `invert` function or compute manually via Fermat's little theorem).

- [ ] **Step 2: Delete `deriveTokenValue()`**

Remove the `deriveTokenValue()` function (lines 113-129). It extracted and hashed blinded `B` — no longer needed since `finalize()` returns the PRF output directly.

- [ ] **Step 3: Add `buildRedemptionToken()`**

```typescript
const REDEMPTION_TOKEN_VERSION_V3 = 0x03;

export function buildRedemptionToken(
    output: Uint8Array,  // 32 bytes
    kid: string,
    exp: bigint,
    issuerId: string,
    sig: Uint8Array      // 64 bytes
): Uint8Array {
    const kidBytes = new TextEncoder().encode(kid);
    const issuerIdBytes = new TextEncoder().encode(issuerId);

    if (kidBytes.length === 0 || kidBytes.length > 255) {
        throw new Error("kid must be 1-255 bytes");
    }
    if (issuerIdBytes.length === 0 || issuerIdBytes.length > 255) {
        throw new Error("issuer_id must be 1-255 bytes");
    }

    const buf = new Uint8Array(
        1 + 32 + 1 + kidBytes.length + 8 + 1 + issuerIdBytes.length + 64
    );
    let pos = 0;

    buf[pos++] = REDEMPTION_TOKEN_VERSION_V3;
    buf.set(output, pos); pos += 32;
    buf[pos++] = kidBytes.length;
    buf.set(kidBytes, pos); pos += kidBytes.length;
    // exp as i64 big-endian
    const expView = new DataView(buf.buffer, buf.byteOffset + pos, 8);
    expView.setBigInt64(0, exp);
    pos += 8;
    buf[pos++] = issuerIdBytes.length;
    buf.set(issuerIdBytes, pos); pos += issuerIdBytes.length;
    buf.set(sig, pos);

    return buf;
}
```

- [ ] **Step 4: Add `parseRedemptionToken()`**

```typescript
export function parseRedemptionToken(bytes: Uint8Array): {
    output: Uint8Array;
    kid: string;
    exp: bigint;
    issuerId: string;
    sig: Uint8Array;
} {
    if (bytes.length < 109 || bytes.length > 512) {
        throw new Error("invalid token length");
    }
    if (bytes[0] !== REDEMPTION_TOKEN_VERSION_V3) {
        throw new Error("unsupported token version");
    }

    let pos = 1;
    const output = bytes.slice(pos, pos + 32); pos += 32;

    const kidLen = bytes[pos++];
    if (kidLen === 0 || pos + kidLen > bytes.length) {
        throw new Error("invalid kid_len");
    }
    const kid = new TextDecoder().decode(bytes.slice(pos, pos + kidLen));
    pos += kidLen;

    const expView = new DataView(bytes.buffer, bytes.byteOffset + pos, 8);
    const exp = expView.getBigInt64(0);
    pos += 8;

    const issuerIdLen = bytes[pos++];
    if (issuerIdLen === 0 || pos + issuerIdLen > bytes.length) {
        throw new Error("invalid issuer_id_len");
    }
    const issuerId = new TextDecoder().decode(bytes.slice(pos, pos + issuerIdLen));
    pos += issuerIdLen;

    if (bytes.length - pos !== 64) {
        throw new Error("invalid sig length");
    }
    const sig = bytes.slice(pos, pos + 64);

    return { output, kid, exp, issuerId, sig };
}
```

- [ ] **Step 5: Update any SDK-level imports/exports**

Check `sdk/js/src/crypto/index.ts` or similar barrel exports. Export the new functions, remove `deriveTokenValue` export.

- [ ] **Step 6: Run JS tests if available**

Run: `cd sdk/js && npm test` (or whatever the test command is)
Expected: Pass, or if no tests exist, at least `npm run build` / `tsc` compiles.

- [ ] **Step 7: Commit**

```bash
git add sdk/js/
git commit -m "feat(sdk/js): implement VOPRF unblinding and V3 redemption tokens

finalize() now unblinds using r^(-1) and returns 32-byte PRF output.
Add buildRedemptionToken/parseRedemptionToken for V3 wire format.
Remove deriveTokenValue (no longer needed)."
```

---

### Task 10: Rewrite integration tests

**Files:**
- Modify/rewrite: `integration_tests/tests/smoke_voprf_roundtrip.rs`
- Modify/rewrite: `integration_tests/tests/e2e_issuance_verification.rs`
- Update remaining test files to compile with new API types

- [ ] **Step 1: Rewrite `smoke_voprf_roundtrip.rs`**

This is the fundamental correctness test. New version:

```rust
//! Smoke test: VOPRF blind -> evaluate -> unblind -> build V3 token -> verify signature

use freebird_crypto::{
    Client, Server, RedemptionToken,
    build_redemption_token, parse_redemption_token,
    compute_token_signature, verify_token_signature,
    nullifier_key,
};
use base64ct::{Base64UrlUnpadded, Encoding};

#[test]
fn test_full_voprf_roundtrip_v3() {
    let ctx = b"roundtrip-test";
    let sk_bytes = [42u8; 32];
    let kid = "test-key-01";
    let exp = 1700000000i64;
    let issuer_id = "test-issuer";

    // Setup
    let server = Server::from_secret_key(sk_bytes, ctx).unwrap();
    let pk = server.public_key_sec1_compressed();

    // Client blinds
    let mut client = Client::new(ctx);
    let input = b"anonymous-credential-input";
    let (blinded_b64, state) = client.blind(input).unwrap();

    // Server evaluates
    let blinded_raw = Base64UrlUnpadded::decode_vec(&blinded_b64).unwrap();
    let eval = server.evaluate_with_proof(&blinded_raw).unwrap();

    // Client finalizes (unblinds)
    let eval_b64 = Base64UrlUnpadded::encode_string(&eval);
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let output_b64 = client.finalize(state, &eval_b64, &pk_b64).unwrap();

    // Issuer signs metadata
    let sig = compute_token_signature(&sk_bytes, kid, exp, issuer_id).unwrap();

    // Client builds V3 redemption token
    let output_raw = Base64UrlUnpadded::decode_vec(&output_b64).unwrap();
    let redemption = RedemptionToken {
        output: output_raw.try_into().unwrap(),
        kid: kid.to_string(),
        exp,
        issuer_id: issuer_id.to_string(),
        sig,
    };
    let token_bytes = build_redemption_token(&redemption).unwrap();

    // Verifier parses V3 token
    let parsed = parse_redemption_token(&token_bytes).unwrap();
    assert_eq!(parsed.kid, kid);
    assert_eq!(parsed.exp, exp);
    assert_eq!(parsed.issuer_id, issuer_id);

    // Verifier checks ECDSA signature
    assert!(verify_token_signature(
        &pk, &parsed.sig, &parsed.kid, parsed.exp, &parsed.issuer_id
    ));

    // Nullifier is deterministic
    let nullifier = nullifier_key(
        &parsed.issuer_id,
        &Base64UrlUnpadded::encode_string(&parsed.output),
    );
    assert!(!nullifier.is_empty());
}

#[test]
fn test_nullifier_determinism_across_blinding_factors() {
    let ctx = b"nullifier-test";
    let sk_bytes = [42u8; 32];
    let server = Server::from_secret_key(sk_bytes, ctx).unwrap();
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let input = b"same-input";

    // Two independent blind-evaluate-unblind cycles with same input
    let output1 = {
        let mut c = Client::new(ctx);
        let (b, st) = c.blind(input).unwrap();
        let raw = Base64UrlUnpadded::decode_vec(&b).unwrap();
        let eval = server.evaluate_with_proof(&raw).unwrap();
        c.finalize(st, &Base64UrlUnpadded::encode_string(&eval), &pk_b64).unwrap()
    };

    let output2 = {
        let mut c = Client::new(ctx);
        let (b, st) = c.blind(input).unwrap();
        let raw = Base64UrlUnpadded::decode_vec(&b).unwrap();
        let eval = server.evaluate_with_proof(&raw).unwrap();
        c.finalize(st, &Base64UrlUnpadded::encode_string(&eval), &pk_b64).unwrap()
    };

    // Outputs must be identical (different r, same input)
    assert_eq!(output1, output2);

    // Nullifiers must be identical
    let n1 = nullifier_key("issuer", &output1);
    let n2 = nullifier_key("issuer", &output2);
    assert_eq!(n1, n2);
}
```

- [ ] **Step 2: Rewrite `e2e_issuance_verification.rs`**

Focus on the full flow with signature verification and replay detection. Test:
- Valid V3 token accepted
- Expired token rejected
- Wrong issuer signature rejected
- Replay (same nullifier) rejected

- [ ] **Step 3: Update remaining integration test files to compile**

The other 11 test files reference `IssueResp`, `VerifyReq`, `TokenResult`, etc. with old fields. At minimum, update them to compile. For tests that are fundamentally about V1/V2 behavior (e.g., `signature_based_tokens.rs`, `token_contract_matrix.rs`), either delete them or rewrite for V3.

Priority: get the workspace compiling. Tests that exercise features orthogonal to the token format (key rotation, Sybil modes, federation metadata) may just need field name updates.

- [ ] **Step 4: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add integration_tests/
git commit -m "test: rewrite integration tests for V3 redemption tokens

New smoke test verifies full blind-evaluate-unblind-sign-verify flow.
Nullifier determinism test proves different blinding factors produce
identical outputs. Updated remaining tests for new API types."
```

---

### Task 11: Final compilation check and cleanup

**Files:**
- All workspace crates

- [ ] **Step 1: Full workspace build**

Run: `cargo build --workspace`
Expected: Clean build, no errors.

- [ ] **Step 2: Full workspace test**

Run: `cargo test --workspace`
Expected: All tests pass.

- [ ] **Step 3: Check for dead code warnings**

Run: `cargo build --workspace 2>&1 | grep "warning: unused"`
Address any warnings related to removed V1/V2 code (unused imports, dead constants, etc.).

- [ ] **Step 4: Run clippy**

Run: `cargo clippy --workspace`
Fix any new clippy warnings introduced by the changes.

- [ ] **Step 5: Commit cleanup**

```bash
git add -A
git commit -m "chore: clean up dead code and warnings after V3 migration"
```

- [ ] **Step 6: Verify JS SDK builds**

Run: `cd sdk/js && npm run build` (or `tsc`)
Expected: Clean build.

- [ ] **Step 7: Final commit if JS cleanup needed**

```bash
git add sdk/js/
git commit -m "chore(sdk/js): clean up after V3 migration"
```
