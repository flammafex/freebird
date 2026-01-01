// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: Key Rotation During Verification
//
// This test validates that tokens issued with an old key can still be verified
// after key rotation, as long as they are within the grace period.
//
// Scenarios tested:
// 1. Token issued with key A, key rotates to B, token still verifiable
// 2. Token issued with key A, key rotates to B then C, token from A still works (within retention)
// 3. Token issued with key A, after grace period expires, token no longer valid
// 4. New tokens after rotation use the new key

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use freebird_crypto::{Client, Server, Verifier, nullifier_key, compute_token_signature, verify_token_signature};
use freebird_verifier::store::{InMemoryStore, SpendStore};

const CONTEXT: &[u8] = b"freebird:v1";
const ISSUER_ID: &str = "issuer:test:rotation";
const EXP_SEC: u64 = 3600;

/// Represents an issuer key (active or deprecated)
struct IssuerKey {
    sk: [u8; 32],
    server: Server,
    pk: Vec<u8>,
    kid: String,
}

impl IssuerKey {
    fn new(sk: [u8; 32]) -> Self {
        let server = Server::from_secret_key(sk, CONTEXT).expect("server from sk");
        let pk = server.public_key_sec1_compressed().to_vec();
        let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
        let kid = format!("kid:{}", &pk_b64[..8]);

        Self { sk, server, pk, kid }
    }
}

/// Simplified multi-key verifier for testing
struct MultiKeyVerifier {
    keys: HashMap<String, IssuerKey>,
    active_kid: String,
    crypto: Verifier,
    store: Arc<dyn SpendStore>,
}

impl MultiKeyVerifier {
    fn new(active_key: IssuerKey) -> Self {
        let active_kid = active_key.kid.clone();
        let mut keys = HashMap::new();
        keys.insert(active_key.kid.clone(), active_key);

        Self {
            keys,
            active_kid,
            crypto: Verifier::new(CONTEXT),
            store: Arc::new(InMemoryStore::default()),
        }
    }

    /// Add a deprecated key that can still verify tokens
    fn add_deprecated_key(&mut self, key: IssuerKey) {
        self.keys.insert(key.kid.clone(), key);
    }

    /// Rotate to a new active key
    fn rotate_to(&mut self, new_key: IssuerKey) {
        self.active_kid = new_key.kid.clone();
        self.keys.insert(new_key.kid.clone(), new_key);
    }

    /// Remove a key (simulating grace period expiration)
    fn remove_key(&mut self, kid: &str) -> bool {
        if kid == self.active_kid {
            return false; // Can't remove active key
        }
        self.keys.remove(kid).is_some()
    }

    /// Verify a token with the specified key ID
    async fn verify_token(&self, token_b64: &str, kid: &str, exp: i64) -> Result<bool> {
        let key = self.keys.get(kid)
            .ok_or_else(|| anyhow::anyhow!("unknown key ID: {}", kid))?;

        // Decode token (195 bytes = 131 VOPRF + 64 sig)
        let token_with_sig = Base64UrlUnpadded::decode_vec(token_b64)?;
        if token_with_sig.len() != 195 {
            return Err(anyhow::anyhow!("invalid token length"));
        }

        // Split token and signature
        let (token_data, sig_bytes) = token_with_sig.split_at(131);
        let signature: [u8; 64] = sig_bytes.try_into()?;

        // Verify signature
        if !verify_token_signature(&key.pk, token_data, &signature, kid, exp, ISSUER_ID) {
            return Ok(false);
        }

        // Verify VOPRF and check replay
        let token_data_b64 = Base64UrlUnpadded::encode_string(token_data);
        let output_b64 = self.crypto.verify(&token_data_b64, &key.pk)
            .map_err(|e| anyhow::anyhow!("VOPRF verify failed: {:?}", e))?;

        let null_key = nullifier_key(ISSUER_ID, &output_b64);
        let spend_key = format!("freebird:spent:{}:{}", ISSUER_ID, null_key);

        let is_fresh = self.store.mark_spent(&spend_key, Duration::from_secs(EXP_SEC)).await?;
        Ok(is_fresh)
    }
}

/// Issue a token with the given key
fn issue_token(key: &IssuerKey, user_input: &[u8; 32]) -> (String, String, i64) {
    let mut client = Client::new(CONTEXT);
    let (blinded_b64, _) = client.blind(user_input).expect("blind");
    let eval_b64 = key.server.evaluate_with_proof(&blinded_b64).expect("evaluate");
    let eval_bytes = Base64UrlUnpadded::decode_vec(&eval_b64).expect("decode");

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64 + EXP_SEC as i64;

    let signature = compute_token_signature(&key.sk, &eval_bytes, &key.kid, exp, ISSUER_ID)
        .expect("signature");

    let mut final_token = eval_bytes;
    final_token.extend_from_slice(&signature);
    let token_b64 = Base64UrlUnpadded::encode_string(&final_token);

    (token_b64, key.kid.clone(), exp)
}

#[tokio::test]
async fn test_verify_token_after_single_rotation() -> Result<()> {
    println!("🔄 Testing verification after single key rotation");

    // Setup: Create two keys
    let key_a = IssuerKey::new([0x11u8; 32]);
    let key_b = IssuerKey::new([0x22u8; 32]);

    let kid_a = key_a.kid.clone();
    let kid_b = key_b.kid.clone();

    // Start with key A as active
    let mut verifier = MultiKeyVerifier::new(key_a);

    // Issue token with key A (before rotation)
    let (token_a, kid_token_a, exp_a) = issue_token(
        verifier.keys.get(&kid_a).unwrap(),
        &[0xAAu8; 32],
    );
    println!("✅ Issued token with key A: {}", kid_token_a);

    // Rotate to key B (key A becomes deprecated)
    let key_a_deprecated = IssuerKey::new([0x11u8; 32]); // Same key, just moved
    verifier.rotate_to(key_b);
    verifier.add_deprecated_key(key_a_deprecated);
    println!("🔄 Rotated to key B, key A deprecated");

    // Issue token with key B (after rotation)
    let (token_b, kid_token_b, exp_b) = issue_token(
        verifier.keys.get(&kid_b).unwrap(),
        &[0xBBu8; 32],
    );
    println!("✅ Issued token with key B: {}", kid_token_b);

    // Verify both tokens should succeed
    let result_a = verifier.verify_token(&token_a, &kid_token_a, exp_a).await?;
    assert!(result_a, "Token from key A should still verify after rotation");
    println!("✅ Token A verified successfully (deprecated key)");

    let result_b = verifier.verify_token(&token_b, &kid_token_b, exp_b).await?;
    assert!(result_b, "Token from key B should verify");
    println!("✅ Token B verified successfully (active key)");

    println!("🎉 Single rotation test passed");
    Ok(())
}

#[tokio::test]
async fn test_verify_token_after_multiple_rotations() -> Result<()> {
    println!("🔄 Testing verification after multiple key rotations");

    // Setup: Create three keys
    let key_a = IssuerKey::new([0x11u8; 32]);
    let key_b = IssuerKey::new([0x22u8; 32]);
    let key_c = IssuerKey::new([0x33u8; 32]);

    let kid_a = key_a.kid.clone();
    let kid_b = key_b.kid.clone();
    let kid_c = key_c.kid.clone();

    // Start with key A
    let mut verifier = MultiKeyVerifier::new(key_a);

    // Issue token with key A
    let (token_a, _, exp_a) = issue_token(
        verifier.keys.get(&kid_a).unwrap(),
        &[0x11u8; 32],
    );

    // Rotate A -> B
    let key_a_deprecated = IssuerKey::new([0x11u8; 32]);
    verifier.rotate_to(key_b);
    verifier.add_deprecated_key(key_a_deprecated);

    // Issue token with key B
    let (token_b, _, exp_b) = issue_token(
        verifier.keys.get(&kid_b).unwrap(),
        &[0x22u8; 32],
    );

    // Rotate B -> C
    let key_b_deprecated = IssuerKey::new([0x22u8; 32]);
    verifier.rotate_to(key_c);
    verifier.add_deprecated_key(key_b_deprecated);

    // Issue token with key C
    let (token_c, _, exp_c) = issue_token(
        verifier.keys.get(&kid_c).unwrap(),
        &[0x33u8; 32],
    );

    println!("📊 Keys status: A (deprecated), B (deprecated), C (active)");
    println!("📊 Total keys in verifier: {}", verifier.keys.len());

    // All three tokens should still verify
    assert!(verifier.verify_token(&token_a, &kid_a, exp_a).await?,
            "Token A should verify (2 rotations ago)");
    println!("✅ Token A verified");

    assert!(verifier.verify_token(&token_b, &kid_b, exp_b).await?,
            "Token B should verify (1 rotation ago)");
    println!("✅ Token B verified");

    assert!(verifier.verify_token(&token_c, &kid_c, exp_c).await?,
            "Token C should verify (current key)");
    println!("✅ Token C verified");

    println!("🎉 Multiple rotation test passed");
    Ok(())
}

#[tokio::test]
async fn test_verify_fails_after_key_removal() -> Result<()> {
    println!("🗑️ Testing verification fails after key removal (grace period expired)");

    // Setup with two keys
    let key_a = IssuerKey::new([0x11u8; 32]);
    let key_b = IssuerKey::new([0x22u8; 32]);

    let kid_a = key_a.kid.clone();
    let kid_b = key_b.kid.clone();

    let mut verifier = MultiKeyVerifier::new(key_a);

    // Issue token with key A
    let (_token_a, _, _exp_a) = issue_token(
        verifier.keys.get(&kid_a).unwrap(),
        &[0xAAu8; 32],
    );

    // Rotate to key B, keep A as deprecated
    let key_a_deprecated = IssuerKey::new([0x11u8; 32]);
    verifier.rotate_to(key_b);
    verifier.add_deprecated_key(key_a_deprecated);

    // Verify token A works while key A is still present
    // Note: We need a fresh token since the first one would be marked as spent
    let (token_a2, _, exp_a2) = {
        let key_a_for_issue = IssuerKey::new([0x11u8; 32]);
        issue_token(&key_a_for_issue, &[0xBBu8; 32])
    };

    assert!(verifier.verify_token(&token_a2, &kid_a, exp_a2).await?,
            "Token should verify while key A is present");
    println!("✅ Token verified while key A present");

    // Simulate grace period expiration: remove key A
    let removed = verifier.remove_key(&kid_a);
    assert!(removed, "Key A should be removable");
    println!("🗑️ Key A removed (grace period expired)");

    // New token from removed key should fail verification
    let (token_a3, _, exp_a3) = {
        let key_a_for_issue = IssuerKey::new([0x11u8; 32]);
        issue_token(&key_a_for_issue, &[0xCCu8; 32])
    };

    let result = verifier.verify_token(&token_a3, &kid_a, exp_a3).await;
    assert!(result.is_err(), "Token should fail after key removal");
    println!("✅ Token correctly rejected after key removal");

    // Token from key B should still work
    let (token_b, _, exp_b) = issue_token(
        verifier.keys.get(&kid_b).unwrap(),
        &[0xDDu8; 32],
    );
    assert!(verifier.verify_token(&token_b, &kid_b, exp_b).await?,
            "Active key should still work");
    println!("✅ Active key B still works");

    println!("🎉 Key removal test passed");
    Ok(())
}

#[tokio::test]
async fn test_cross_key_verification_fails() -> Result<()> {
    println!("❌ Testing that tokens from one key don't verify with another");

    let key_a = IssuerKey::new([0x11u8; 32]);
    let key_b = IssuerKey::new([0x22u8; 32]);

    let _kid_a = key_a.kid.clone();
    let kid_b = key_b.kid.clone();

    // Issue token with key A
    let (token_a, _, exp_a) = issue_token(&key_a, &[0xAAu8; 32]);

    // Try to verify with key B (wrong key)
    let mut verifier = MultiKeyVerifier::new(key_b);

    // Attempting to verify with wrong kid should fail
    let result = verifier.verify_token(&token_a, &kid_b, exp_a).await;

    // The signature check will fail because the token was signed with key A
    // but we're trying to verify with key B's public key
    assert!(
        result.is_err() || result.unwrap() == false,
        "Token from key A should not verify with key B"
    );
    println!("✅ Cross-key verification correctly rejected");

    println!("🎉 Cross-key test passed");
    Ok(())
}

#[tokio::test]
async fn test_epoch_based_rotation_validity() -> Result<()> {
    println!("📅 Testing epoch-based key rotation validity");

    /// Calculate epoch from timestamp
    fn epoch_from_ts(ts: u64, epoch_duration: u64) -> u32 {
        (ts / epoch_duration) as u32
    }

    /// Check if epoch is valid (within retention window)
    fn is_epoch_valid(epoch: u32, current_epoch: u32, retention: u32) -> bool {
        let min_valid = current_epoch.saturating_sub(retention);
        epoch >= min_valid && epoch <= current_epoch
    }

    let epoch_duration = 86400u64; // 1 day
    let retention = 2u32; // Accept 2 previous epochs

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let current_epoch = epoch_from_ts(now, epoch_duration);
    println!("📊 Current epoch: {}", current_epoch);

    // Test valid epochs
    assert!(is_epoch_valid(current_epoch, current_epoch, retention),
            "Current epoch should be valid");
    assert!(is_epoch_valid(current_epoch - 1, current_epoch, retention),
            "Previous epoch should be valid");
    assert!(is_epoch_valid(current_epoch - 2, current_epoch, retention),
            "Two epochs ago should be valid");

    // Test invalid epochs
    assert!(!is_epoch_valid(current_epoch - 3, current_epoch, retention),
            "Three epochs ago should be invalid");
    assert!(!is_epoch_valid(current_epoch + 1, current_epoch, retention),
            "Future epoch should be invalid");

    println!("✅ Valid epochs: [{}, {}, {}]",
             current_epoch - 2, current_epoch - 1, current_epoch);
    println!("❌ Invalid epochs: {} and earlier, {} and later",
             current_epoch - 3, current_epoch + 1);

    println!("🎉 Epoch validity test passed");
    Ok(())
}
