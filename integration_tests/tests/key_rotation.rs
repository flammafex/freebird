// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: Key Rotation During Verification (V3)
//
// This test validates that tokens issued with an old key can still be verified
// after key rotation, as long as they are within the grace period.
//
// In V3, the verifier receives the PRF output inside the redemption token and
// verifies the ECDSA metadata signature.

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use freebird_crypto::{
    compute_token_signature, nullifier_key, verify_token_signature, Client, Server,
};
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

        Self {
            sk,
            server,
            pk,
            kid,
        }
    }
}

/// V3 token: carries PRF output + metadata + ECDSA signature
#[derive(Clone)]
struct IssuedToken {
    output_b64: String,
    kid: String,
    exp: i64,
    signature: [u8; 64],
}

/// Simplified multi-key verifier for testing
struct MultiKeyVerifier {
    keys: HashMap<String, IssuerKey>,
    active_kid: String,
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
            store: Arc::new(InMemoryStore::default()),
        }
    }

    fn add_deprecated_key(&mut self, key: IssuerKey) {
        self.keys.insert(key.kid.clone(), key);
    }

    fn rotate_to(&mut self, new_key: IssuerKey) {
        self.active_kid = new_key.kid.clone();
        self.keys.insert(new_key.kid.clone(), new_key);
    }

    fn remove_key(&mut self, kid: &str) -> bool {
        if kid == self.active_kid {
            return false;
        }
        self.keys.remove(kid).is_some()
    }

    async fn verify_token(&self, token: &IssuedToken) -> Result<bool> {
        let key = self
            .keys
            .get(&token.kid)
            .ok_or_else(|| anyhow::anyhow!("unknown key ID: {}", token.kid))?;

        // V3: verify ECDSA signature over metadata
        if !verify_token_signature(&key.pk, &token.signature, &token.kid, token.exp, ISSUER_ID) {
            return Ok(false);
        }

        // Derive nullifier from PRF output (received in V3 redemption token)
        let null_key = nullifier_key(ISSUER_ID, &token.output_b64);
        let spend_key = format!("freebird:spent:{}:{}", ISSUER_ID, null_key);

        let is_fresh = self
            .store
            .mark_spent(&spend_key, Duration::from_secs(EXP_SEC))
            .await?;
        Ok(is_fresh)
    }
}

/// Issue a token with the given key. Returns an IssuedToken with PRF output.
fn issue_token(key: &IssuerKey, user_input: &[u8; 32]) -> IssuedToken {
    let pk_b64 = Base64UrlUnpadded::encode_string(&key.pk);

    let mut client = Client::new(CONTEXT);
    let (blinded_b64, state) = client.blind(user_input).expect("blind");
    let eval_b64 = key
        .server
        .evaluate_with_proof(&blinded_b64)
        .expect("evaluate");

    // Client unblinds to get PRF output
    let output_b64 = client.finalize(state, &eval_b64, &pk_b64).expect("finalize");

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + EXP_SEC as i64;

    // V3: sign metadata only
    let signature =
        compute_token_signature(&key.sk, &key.kid, exp, ISSUER_ID).expect("signature");

    IssuedToken {
        output_b64,
        kid: key.kid.clone(),
        exp,
        signature,
    }
}

#[tokio::test]
async fn test_verify_token_after_single_rotation() -> Result<()> {
    println!("Testing verification after single key rotation");

    let key_a = IssuerKey::new([0x11u8; 32]);
    let key_b = IssuerKey::new([0x22u8; 32]);

    let kid_a = key_a.kid.clone();
    let kid_b = key_b.kid.clone();

    let mut verifier = MultiKeyVerifier::new(key_a);

    // Issue token with key A (before rotation)
    let token_a = issue_token(verifier.keys.get(&kid_a).unwrap(), &[0xAAu8; 32]);
    println!("Issued token with key A: {}", token_a.kid);

    // Rotate to key B (key A becomes deprecated)
    let key_a_deprecated = IssuerKey::new([0x11u8; 32]);
    verifier.rotate_to(key_b);
    verifier.add_deprecated_key(key_a_deprecated);
    println!("Rotated to key B, key A deprecated");

    // Issue token with key B (after rotation)
    let token_b = issue_token(verifier.keys.get(&kid_b).unwrap(), &[0xBBu8; 32]);
    println!("Issued token with key B: {}", token_b.kid);

    // Verify both tokens should succeed
    let result_a = verifier.verify_token(&token_a).await?;
    assert!(
        result_a,
        "Token from key A should still verify after rotation"
    );
    println!("Token A verified successfully (deprecated key)");

    let result_b = verifier.verify_token(&token_b).await?;
    assert!(result_b, "Token from key B should verify");
    println!("Token B verified successfully (active key)");

    println!("Single rotation test passed");
    Ok(())
}

#[tokio::test]
async fn test_verify_token_after_multiple_rotations() -> Result<()> {
    println!("Testing verification after multiple key rotations");

    let key_a = IssuerKey::new([0x11u8; 32]);
    let key_b = IssuerKey::new([0x22u8; 32]);
    let key_c = IssuerKey::new([0x33u8; 32]);

    let kid_a = key_a.kid.clone();
    let kid_b = key_b.kid.clone();
    let kid_c = key_c.kid.clone();

    let mut verifier = MultiKeyVerifier::new(key_a);

    let token_a = issue_token(verifier.keys.get(&kid_a).unwrap(), &[0x11u8; 32]);

    let key_a_deprecated = IssuerKey::new([0x11u8; 32]);
    verifier.rotate_to(key_b);
    verifier.add_deprecated_key(key_a_deprecated);

    let token_b = issue_token(verifier.keys.get(&kid_b).unwrap(), &[0x22u8; 32]);

    let key_b_deprecated = IssuerKey::new([0x22u8; 32]);
    verifier.rotate_to(key_c);
    verifier.add_deprecated_key(key_b_deprecated);

    let token_c = issue_token(verifier.keys.get(&kid_c).unwrap(), &[0x33u8; 32]);

    println!("Keys status: A (deprecated), B (deprecated), C (active)");
    println!("Total keys in verifier: {}", verifier.keys.len());

    assert!(
        verifier.verify_token(&token_a).await?,
        "Token A should verify (2 rotations ago)"
    );
    println!("Token A verified");

    assert!(
        verifier.verify_token(&token_b).await?,
        "Token B should verify (1 rotation ago)"
    );
    println!("Token B verified");

    assert!(
        verifier.verify_token(&token_c).await?,
        "Token C should verify (current key)"
    );
    println!("Token C verified");

    println!("Multiple rotation test passed");
    Ok(())
}

#[tokio::test]
async fn test_verify_fails_after_key_removal() -> Result<()> {
    println!("Testing verification fails after key removal (grace period expired)");

    let key_a = IssuerKey::new([0x11u8; 32]);
    let key_b = IssuerKey::new([0x22u8; 32]);

    let kid_a = key_a.kid.clone();
    let kid_b = key_b.kid.clone();

    let mut verifier = MultiKeyVerifier::new(key_a);

    let _token_a = issue_token(verifier.keys.get(&kid_a).unwrap(), &[0xAAu8; 32]);

    let key_a_deprecated = IssuerKey::new([0x11u8; 32]);
    verifier.rotate_to(key_b);
    verifier.add_deprecated_key(key_a_deprecated);

    // Verify token A works while key A is still present
    let token_a2 = {
        let key_a_for_issue = IssuerKey::new([0x11u8; 32]);
        issue_token(&key_a_for_issue, &[0xBBu8; 32])
    };

    assert!(
        verifier.verify_token(&token_a2).await?,
        "Token should verify while key A is present"
    );
    println!("Token verified while key A present");

    // Simulate grace period expiration: remove key A
    let removed = verifier.remove_key(&kid_a);
    assert!(removed, "Key A should be removable");
    println!("Key A removed (grace period expired)");

    // New token from removed key should fail verification
    let token_a3 = {
        let key_a_for_issue = IssuerKey::new([0x11u8; 32]);
        issue_token(&key_a_for_issue, &[0xCCu8; 32])
    };

    let result = verifier.verify_token(&token_a3).await;
    assert!(result.is_err(), "Token should fail after key removal");
    println!("Token correctly rejected after key removal");

    // Token from key B should still work
    let token_b = issue_token(verifier.keys.get(&kid_b).unwrap(), &[0xDDu8; 32]);
    assert!(
        verifier.verify_token(&token_b).await?,
        "Active key should still work"
    );
    println!("Active key B still works");

    println!("Key removal test passed");
    Ok(())
}

#[tokio::test]
async fn test_cross_key_verification_fails() -> Result<()> {
    println!("Testing that tokens from one key don't verify with another");

    let key_a = IssuerKey::new([0x11u8; 32]);
    let key_b = IssuerKey::new([0x22u8; 32]);

    // Issue token with key A
    let token_a = issue_token(&key_a, &[0xAAu8; 32]);

    // Try to verify with key B (wrong key) -- note the token carries key A's kid,
    // so the verifier will look up key A's kid in its map and fail (key not found).
    let verifier = MultiKeyVerifier::new(key_b);

    let result = verifier.verify_token(&token_a).await;

    // Token was issued with key A but verifier only has key B
    assert!(
        result.is_err() || result.unwrap() == false,
        "Token from key A should not verify with key B"
    );
    println!("Cross-key verification correctly rejected");

    println!("Cross-key test passed");
    Ok(())
}

#[tokio::test]
async fn test_epoch_based_rotation_validity() -> Result<()> {
    println!("Testing epoch-based key rotation validity");

    fn epoch_from_ts(ts: u64, epoch_duration: u64) -> u32 {
        (ts / epoch_duration) as u32
    }

    fn is_epoch_valid(epoch: u32, current_epoch: u32, retention: u32) -> bool {
        let min_valid = current_epoch.saturating_sub(retention);
        epoch >= min_valid && epoch <= current_epoch
    }

    let epoch_duration = 86400u64;
    let retention = 2u32;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let current_epoch = epoch_from_ts(now, epoch_duration);
    println!("Current epoch: {}", current_epoch);

    assert!(is_epoch_valid(current_epoch, current_epoch, retention));
    assert!(is_epoch_valid(current_epoch - 1, current_epoch, retention));
    assert!(is_epoch_valid(current_epoch - 2, current_epoch, retention));
    assert!(!is_epoch_valid(current_epoch - 3, current_epoch, retention));
    assert!(!is_epoch_valid(current_epoch + 1, current_epoch, retention));

    println!("Epoch validity test passed");
    Ok(())
}

#[tokio::test]
async fn test_new_tokens_always_use_current_active_key() -> Result<()> {
    println!("Testing new issuance always uses current active key");

    let key_a = IssuerKey::new([0x11u8; 32]);
    let key_b = IssuerKey::new([0x22u8; 32]);
    let key_c = IssuerKey::new([0x33u8; 32]);
    let kid_a = key_a.kid.clone();
    let kid_b = key_b.kid.clone();
    let kid_c = key_c.kid.clone();

    let mut verifier = MultiKeyVerifier::new(key_a);

    let token_a = issue_token(
        verifier.keys.get(&verifier.active_kid).unwrap(),
        &[0xA1; 32],
    );
    assert_eq!(token_a.kid, kid_a);
    assert!(verifier.verify_token(&token_a).await?);

    verifier.rotate_to(key_b);
    let token_b = issue_token(
        verifier.keys.get(&verifier.active_kid).unwrap(),
        &[0xB2; 32],
    );
    assert_eq!(token_b.kid, kid_b);
    assert!(verifier.verify_token(&token_b).await?);

    verifier.rotate_to(key_c);
    let token_c = issue_token(
        verifier.keys.get(&verifier.active_kid).unwrap(),
        &[0xC3; 32],
    );
    assert_eq!(token_c.kid, kid_c);
    assert!(verifier.verify_token(&token_c).await?);

    println!("Active key issuance invariant holds across rotations");
    Ok(())
}

#[tokio::test]
async fn test_cannot_remove_active_key() -> Result<()> {
    println!("Testing active key cannot be removed");

    let key_a = IssuerKey::new([0x11u8; 32]);
    let kid_a = key_a.kid.clone();
    let mut verifier = MultiKeyVerifier::new(key_a);

    let removed = verifier.remove_key(&kid_a);
    assert!(!removed, "active key removal should be blocked");

    let token = issue_token(
        verifier.keys.get(&verifier.active_kid).unwrap(),
        &[0x5A; 32],
    );
    assert_eq!(token.kid, kid_a);
    assert!(verifier.verify_token(&token).await?);

    println!("Active key protection invariant holds");
    Ok(())
}
