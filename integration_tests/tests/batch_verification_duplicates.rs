// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: Batch Verification with Duplicate Tokens
//
// This test validates that the batch verification endpoint correctly:
// 1. Accepts unique tokens in a batch
// 2. Rejects duplicate tokens within the same batch (replay detection)
// 3. Maintains correct success/failure counts
// 4. Handles mixed batches of valid and duplicate tokens

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use std::sync::Arc;
use std::time::Duration;

use freebird_crypto::{Client, Server, Verifier, nullifier_key, compute_token_signature, verify_token_signature};
use freebird_verifier::store::{InMemoryStore, SpendStore};

const CONTEXT: &[u8] = b"freebird:v1";
const ISSUER_ID: &str = "issuer:test:batch";
const EXP_SEC: u64 = 3600;

/// Token with metadata needed for verification
#[derive(Clone)]
struct TestToken {
    token_b64: String,
    kid: String,
    exp: i64,
    epoch: u32,
}

/// Result of verifying a single token
#[derive(Debug, PartialEq)]
enum VerifyResult {
    Success,
    Replay,
    InvalidSignature,
    InvalidToken,
}

/// Batch verification result
struct BatchResult {
    results: Vec<VerifyResult>,
    successful: usize,
    failed: usize,
}

/// Simple batch verifier for testing
struct BatchVerifier {
    issuer_pk: Vec<u8>,
    issuer_kid: String,
    crypto: Verifier,
    store: Arc<dyn SpendStore>,
    epoch_duration: u64,
    epoch_retention: u32,
}

impl BatchVerifier {
    fn new(issuer_pk: Vec<u8>, issuer_kid: String) -> Self {
        Self {
            issuer_pk,
            issuer_kid,
            crypto: Verifier::new(CONTEXT),
            store: Arc::new(InMemoryStore::default()),
            epoch_duration: 86400,
            epoch_retention: 2,
        }
    }

    fn current_epoch(&self) -> u32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (now / self.epoch_duration) as u32
    }

    fn is_epoch_valid(&self, epoch: u32) -> bool {
        let current = self.current_epoch();
        let min_valid = current.saturating_sub(self.epoch_retention);
        epoch >= min_valid && epoch <= current
    }

    /// Verify a single token and check replay
    async fn verify_one(&self, token: &TestToken) -> VerifyResult {
        // 1. Check epoch
        if !self.is_epoch_valid(token.epoch) {
            return VerifyResult::InvalidToken;
        }

        // 2. Decode token (195 bytes)
        let token_with_sig = match Base64UrlUnpadded::decode_vec(&token.token_b64) {
            Ok(t) if t.len() == 195 => t,
            _ => return VerifyResult::InvalidToken,
        };

        // 3. Split and verify signature
        let (token_data, sig_bytes) = token_with_sig.split_at(131);
        let signature: [u8; 64] = match sig_bytes.try_into() {
            Ok(s) => s,
            Err(_) => return VerifyResult::InvalidToken,
        };

        if !verify_token_signature(
            &self.issuer_pk,
            token_data,
            &signature,
            &token.kid,
            token.exp,
            ISSUER_ID,
        ) {
            return VerifyResult::InvalidSignature;
        }

        // 4. Verify VOPRF
        let token_data_b64 = Base64UrlUnpadded::encode_string(token_data);
        let output_b64 = match self.crypto.verify(&token_data_b64, &self.issuer_pk) {
            Ok(o) => o,
            Err(_) => return VerifyResult::InvalidToken,
        };

        // 5. Check replay
        let null_key = nullifier_key(ISSUER_ID, &output_b64);
        let spend_key = format!("freebird:spent:{}:{}", ISSUER_ID, null_key);

        match self.store.mark_spent(&spend_key, Duration::from_secs(EXP_SEC)).await {
            Ok(true) => VerifyResult::Success,
            Ok(false) => VerifyResult::Replay,
            Err(_) => VerifyResult::InvalidToken,
        }
    }

    /// Verify a batch of tokens
    async fn verify_batch(&self, tokens: &[TestToken]) -> BatchResult {
        let mut results = Vec::with_capacity(tokens.len());

        // Process sequentially to ensure consistent replay detection order
        for token in tokens {
            results.push(self.verify_one(token).await);
        }

        let successful = results.iter().filter(|r| **r == VerifyResult::Success).count();
        let failed = results.len() - successful;

        BatchResult {
            results,
            successful,
            failed,
        }
    }
}

/// Issue a unique token
fn issue_token(server: &Server, sk: &[u8; 32], kid: &str, user_input: &[u8; 32]) -> TestToken {
    let mut client = Client::new(CONTEXT);
    let (blinded_b64, _) = client.blind(user_input).expect("blind");
    let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluate");
    let eval_bytes = Base64UrlUnpadded::decode_vec(&eval_b64).expect("decode");

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64 + EXP_SEC as i64;

    let epoch = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() / 86400) as u32;

    let signature = compute_token_signature(sk, &eval_bytes, kid, exp, ISSUER_ID).expect("signature");

    let mut final_token = eval_bytes;
    final_token.extend_from_slice(&signature);
    let token_b64 = Base64UrlUnpadded::encode_string(&final_token);

    TestToken {
        token_b64,
        kid: kid.to_string(),
        exp,
        epoch,
    }
}

#[tokio::test]
async fn test_batch_all_unique_tokens() -> Result<()> {
    println!("🔢 Testing batch verification with all unique tokens");

    // Setup issuer
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT).expect("server");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let kid = format!("kid:{}", &pk_b64[..8]);

    let verifier = BatchVerifier::new(pk.to_vec(), kid.clone());

    // Issue 5 unique tokens
    let tokens: Vec<TestToken> = (0..5u8)
        .map(|i| {
            let input = [i * 0x11; 32];
            issue_token(&server, &sk, &kid, &input)
        })
        .collect();

    println!("📝 Issued {} unique tokens", tokens.len());

    // Verify batch
    let result = verifier.verify_batch(&tokens).await;

    assert_eq!(result.successful, 5, "All 5 unique tokens should succeed");
    assert_eq!(result.failed, 0, "No tokens should fail");

    for (i, r) in result.results.iter().enumerate() {
        assert_eq!(*r, VerifyResult::Success, "Token {} should succeed", i);
    }

    println!("✅ All {} unique tokens verified successfully", tokens.len());
    Ok(())
}

#[tokio::test]
async fn test_batch_with_duplicates() -> Result<()> {
    println!("🔄 Testing batch verification with duplicate tokens");

    // Setup issuer
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT).expect("server");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let kid = format!("kid:{}", &pk_b64[..8]);

    let verifier = BatchVerifier::new(pk.to_vec(), kid.clone());

    // Issue one token
    let token = issue_token(&server, &sk, &kid, &[0xAAu8; 32]);

    // Create batch with the same token repeated 5 times
    let tokens: Vec<TestToken> = vec![token.clone(); 5];

    println!("📝 Created batch with 5 copies of the same token");

    // Verify batch
    let result = verifier.verify_batch(&tokens).await;

    // Only the first one should succeed
    assert_eq!(result.successful, 1, "Only first token should succeed");
    assert_eq!(result.failed, 4, "4 duplicates should fail");

    assert_eq!(result.results[0], VerifyResult::Success, "First should succeed");
    for i in 1..5 {
        assert_eq!(result.results[i], VerifyResult::Replay, "Token {} should be replay", i);
    }

    println!("✅ Duplicate detection working: 1 success, 4 replays");
    Ok(())
}

#[tokio::test]
async fn test_batch_mixed_unique_and_duplicates() -> Result<()> {
    println!("🎲 Testing batch with mixed unique and duplicate tokens");

    // Setup issuer
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT).expect("server");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let kid = format!("kid:{}", &pk_b64[..8]);

    let verifier = BatchVerifier::new(pk.to_vec(), kid.clone());

    // Create tokens: [A, B, A, C, B, D, A]
    // Expected: A=success, B=success, A=replay, C=success, B=replay, D=success, A=replay
    let token_a = issue_token(&server, &sk, &kid, &[0xAAu8; 32]);
    let token_b = issue_token(&server, &sk, &kid, &[0xBBu8; 32]);
    let token_c = issue_token(&server, &sk, &kid, &[0xCCu8; 32]);
    let token_d = issue_token(&server, &sk, &kid, &[0xDDu8; 32]);

    let tokens = vec![
        token_a.clone(), // 0: A - success
        token_b.clone(), // 1: B - success
        token_a.clone(), // 2: A - replay
        token_c.clone(), // 3: C - success
        token_b.clone(), // 4: B - replay
        token_d.clone(), // 5: D - success
        token_a.clone(), // 6: A - replay
    ];

    println!("📝 Batch order: [A, B, A, C, B, D, A]");
    println!("📝 Expected:    [✓, ✓, R, ✓, R, ✓, R]");

    // Verify batch
    let result = verifier.verify_batch(&tokens).await;

    // 4 unique tokens should succeed
    assert_eq!(result.successful, 4, "4 unique tokens should succeed");
    assert_eq!(result.failed, 3, "3 duplicates should fail");

    // Check specific positions
    assert_eq!(result.results[0], VerifyResult::Success, "A@0 should succeed");
    assert_eq!(result.results[1], VerifyResult::Success, "B@1 should succeed");
    assert_eq!(result.results[2], VerifyResult::Replay, "A@2 should be replay");
    assert_eq!(result.results[3], VerifyResult::Success, "C@3 should succeed");
    assert_eq!(result.results[4], VerifyResult::Replay, "B@4 should be replay");
    assert_eq!(result.results[5], VerifyResult::Success, "D@5 should succeed");
    assert_eq!(result.results[6], VerifyResult::Replay, "A@6 should be replay");

    println!("✅ Mixed batch handled correctly: 4 successes, 3 replays");
    Ok(())
}

#[tokio::test]
async fn test_batch_previously_used_tokens() -> Result<()> {
    println!("⏮️ Testing batch with tokens already used in previous verification");

    // Setup issuer
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT).expect("server");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let kid = format!("kid:{}", &pk_b64[..8]);

    let verifier = BatchVerifier::new(pk.to_vec(), kid.clone());

    // Issue tokens
    let token_a = issue_token(&server, &sk, &kid, &[0xAAu8; 32]);
    let token_b = issue_token(&server, &sk, &kid, &[0xBBu8; 32]);
    let token_c = issue_token(&server, &sk, &kid, &[0xCCu8; 32]);

    // First batch: use token A and B
    let batch1 = vec![token_a.clone(), token_b.clone()];
    let result1 = verifier.verify_batch(&batch1).await;
    assert_eq!(result1.successful, 2, "First batch should succeed");
    println!("✅ Batch 1: A, B verified");

    // Second batch: try to use A again along with new token C
    let batch2 = vec![token_a.clone(), token_c.clone()];
    let result2 = verifier.verify_batch(&batch2).await;

    assert_eq!(result2.successful, 1, "Only C should succeed");
    assert_eq!(result2.failed, 1, "A should fail (previously used)");
    assert_eq!(result2.results[0], VerifyResult::Replay, "A should be replay");
    assert_eq!(result2.results[1], VerifyResult::Success, "C should succeed");

    println!("✅ Batch 2: A rejected (replay), C accepted");
    println!("✅ Cross-batch replay detection working");
    Ok(())
}

#[tokio::test]
async fn test_batch_size_limits() -> Result<()> {
    println!("📏 Testing batch with various sizes");

    // Setup issuer
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT).expect("server");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let kid = format!("kid:{}", &pk_b64[..8]);

    let verifier = BatchVerifier::new(pk.to_vec(), kid.clone());

    // Test empty batch
    let empty: Vec<TestToken> = vec![];
    let result = verifier.verify_batch(&empty).await;
    assert_eq!(result.successful, 0);
    assert_eq!(result.failed, 0);
    println!("✅ Empty batch handled");

    // Test single token batch
    let single = vec![issue_token(&server, &sk, &kid, &[0x01u8; 32])];
    let result = verifier.verify_batch(&single).await;
    assert_eq!(result.successful, 1);
    println!("✅ Single token batch handled");

    // Test larger batch (100 tokens)
    let large: Vec<TestToken> = (0..100u8)
        .map(|i| {
            let input = [i; 32];
            issue_token(&server, &sk, &kid, &input)
        })
        .collect();

    let result = verifier.verify_batch(&large).await;
    assert_eq!(result.successful, 100, "All 100 unique tokens should succeed");
    println!("✅ Large batch (100 tokens) handled");

    Ok(())
}

#[tokio::test]
async fn test_batch_throughput_metrics() -> Result<()> {
    println!("⏱️ Testing batch verification throughput");

    // Setup issuer
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT).expect("server");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let kid = format!("kid:{}", &pk_b64[..8]);

    let verifier = BatchVerifier::new(pk.to_vec(), kid.clone());

    // Create 50 unique tokens
    let tokens: Vec<TestToken> = (0..50u8)
        .map(|i| {
            let input = [i; 32];
            issue_token(&server, &sk, &kid, &input)
        })
        .collect();

    let start = std::time::Instant::now();
    let result = verifier.verify_batch(&tokens).await;
    let elapsed = start.elapsed();

    let throughput = result.successful as f64 / elapsed.as_secs_f64();

    println!("📊 Batch size: {}", tokens.len());
    println!("📊 Successful: {}", result.successful);
    println!("📊 Time: {:?}", elapsed);
    println!("📊 Throughput: {:.0} tokens/sec", throughput);

    assert_eq!(result.successful, 50, "All tokens should succeed");
    assert!(elapsed.as_millis() < 5000, "Batch should complete in <5s");

    println!("✅ Throughput test passed");
    Ok(())
}
