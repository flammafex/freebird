// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: Batch Verification with Duplicate Tokens (V3)
//
// This test validates that the batch verification endpoint correctly:
// 1. Accepts unique tokens in a batch
// 2. Rejects duplicate tokens within the same batch (replay detection)
// 3. Maintains correct success/failure counts
// 4. Handles mixed batches of valid and duplicate tokens
//
// In V3, the verifier receives the PRF output inside the redemption token.
// Nullifiers are derived from the PRF output, not from Verifier::verify().

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use std::sync::Arc;
use std::time::Duration;

use freebird_crypto::{
    compute_token_signature, nullifier_key, verify_token_signature, Client, Server,
};
use freebird_verifier::store::{InMemoryStore, SpendStore};

const CONTEXT: &[u8] = b"freebird:v1";
const ISSUER_ID: &str = "issuer:test:batch";
const EXP_SEC: u64 = 3600;

/// Token with metadata needed for verification (V3 style)
#[derive(Clone)]
struct TestToken {
    /// The client's unblinded PRF output (what would be in the V3 redemption token)
    output_b64: String,
    kid: String,
    exp: i64,
    signature: [u8; 64],
}

/// Result of verifying a single token
#[derive(Debug, PartialEq)]
enum VerifyResult {
    Success,
    Replay,
    InvalidSignature,
}

/// Batch verification result
struct BatchResult {
    results: Vec<VerifyResult>,
    successful: usize,
    failed: usize,
}

/// Simple batch verifier for testing (V3 style)
struct BatchVerifier {
    issuer_pk: Vec<u8>,
    store: Arc<dyn SpendStore>,
}

impl BatchVerifier {
    fn new(issuer_pk: Vec<u8>) -> Self {
        Self {
            issuer_pk,
            store: Arc::new(InMemoryStore::default()),
        }
    }

    /// Verify a single token and check replay
    async fn verify_one(&self, token: &TestToken) -> VerifyResult {
        // 1. Verify ECDSA signature over metadata
        if !verify_token_signature(
            &self.issuer_pk,
            &token.signature,
            &token.kid,
            token.exp,
            ISSUER_ID,
        ) {
            return VerifyResult::InvalidSignature;
        }

        // 2. Derive nullifier from PRF output (received in V3 redemption token)
        let null_key = nullifier_key(ISSUER_ID, &token.output_b64);
        let spend_key = format!("freebird:spent:{}:{}", ISSUER_ID, null_key);

        match self
            .store
            .mark_spent(&spend_key, Duration::from_secs(EXP_SEC))
            .await
        {
            Ok(true) => VerifyResult::Success,
            Ok(false) => VerifyResult::Replay,
            Err(_) => VerifyResult::InvalidSignature,
        }
    }

    /// Verify a batch of tokens
    async fn verify_batch(&self, tokens: &[TestToken]) -> BatchResult {
        let mut results = Vec::with_capacity(tokens.len());

        // Process sequentially to ensure consistent replay detection order
        for token in tokens {
            results.push(self.verify_one(token).await);
        }

        let successful = results
            .iter()
            .filter(|r| **r == VerifyResult::Success)
            .count();
        let failed = results.len() - successful;

        BatchResult {
            results,
            successful,
            failed,
        }
    }
}

/// Issue a unique token (V3 style: includes client's unblinded PRF output)
fn issue_token(server: &Server, sk: &[u8; 32], kid: &str, user_input: &[u8; 32]) -> TestToken {
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);

    let mut client = Client::new(CONTEXT);
    let (blinded_b64, state) = client.blind(user_input).expect("blind");
    let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluate");

    // Client unblinds to get PRF output
    let output_b64 = client.finalize(state, &eval_b64, &pk_b64).expect("finalize");

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + EXP_SEC as i64;

    // V3: sign metadata only
    let signature =
        compute_token_signature(sk, kid, exp, ISSUER_ID).expect("signature");

    TestToken {
        output_b64,
        kid: kid.to_string(),
        exp,
        signature,
    }
}

#[tokio::test]
async fn test_batch_all_unique_tokens() -> Result<()> {
    println!("Testing batch verification with all unique tokens");

    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT).expect("server");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let kid = format!("kid:{}", &pk_b64[..8]);

    let verifier = BatchVerifier::new(pk.to_vec());

    let tokens: Vec<TestToken> = (0..5u8)
        .map(|i| {
            let input = [i * 0x11; 32];
            issue_token(&server, &sk, &kid, &input)
        })
        .collect();

    println!("Issued {} unique tokens", tokens.len());

    let result = verifier.verify_batch(&tokens).await;

    assert_eq!(result.successful, 5, "All 5 unique tokens should succeed");
    assert_eq!(result.failed, 0, "No tokens should fail");

    for (i, r) in result.results.iter().enumerate() {
        assert_eq!(*r, VerifyResult::Success, "Token {} should succeed", i);
    }

    println!("All {} unique tokens verified successfully", tokens.len());
    Ok(())
}

#[tokio::test]
async fn test_batch_with_duplicates() -> Result<()> {
    println!("Testing batch verification with duplicate tokens");

    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT).expect("server");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let kid = format!("kid:{}", &pk_b64[..8]);

    let verifier = BatchVerifier::new(pk.to_vec());

    let token = issue_token(&server, &sk, &kid, &[0xAAu8; 32]);
    let tokens: Vec<TestToken> = vec![token.clone(); 5];

    println!("Created batch with 5 copies of the same token");

    let result = verifier.verify_batch(&tokens).await;

    assert_eq!(result.successful, 1, "Only first token should succeed");
    assert_eq!(result.failed, 4, "4 duplicates should fail");

    assert_eq!(
        result.results[0],
        VerifyResult::Success,
        "First should succeed"
    );
    for i in 1..5 {
        assert_eq!(
            result.results[i],
            VerifyResult::Replay,
            "Token {} should be replay",
            i
        );
    }

    println!("Duplicate detection working: 1 success, 4 replays");
    Ok(())
}

#[tokio::test]
async fn test_batch_mixed_unique_and_duplicates() -> Result<()> {
    println!("Testing batch with mixed unique and duplicate tokens");

    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT).expect("server");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let kid = format!("kid:{}", &pk_b64[..8]);

    let verifier = BatchVerifier::new(pk.to_vec());

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

    println!("Batch order: [A, B, A, C, B, D, A]");
    println!("Expected:    [S, S, R, S, R, S, R]");

    let result = verifier.verify_batch(&tokens).await;

    assert_eq!(result.successful, 4, "4 unique tokens should succeed");
    assert_eq!(result.failed, 3, "3 duplicates should fail");

    assert_eq!(result.results[0], VerifyResult::Success, "A@0 should succeed");
    assert_eq!(result.results[1], VerifyResult::Success, "B@1 should succeed");
    assert_eq!(result.results[2], VerifyResult::Replay, "A@2 should be replay");
    assert_eq!(result.results[3], VerifyResult::Success, "C@3 should succeed");
    assert_eq!(result.results[4], VerifyResult::Replay, "B@4 should be replay");
    assert_eq!(result.results[5], VerifyResult::Success, "D@5 should succeed");
    assert_eq!(result.results[6], VerifyResult::Replay, "A@6 should be replay");

    println!("Mixed batch handled correctly: 4 successes, 3 replays");
    Ok(())
}

#[tokio::test]
async fn test_batch_previously_used_tokens() -> Result<()> {
    println!("Testing batch with tokens already used in previous verification");

    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT).expect("server");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let kid = format!("kid:{}", &pk_b64[..8]);

    let verifier = BatchVerifier::new(pk.to_vec());

    let token_a = issue_token(&server, &sk, &kid, &[0xAAu8; 32]);
    let token_b = issue_token(&server, &sk, &kid, &[0xBBu8; 32]);
    let token_c = issue_token(&server, &sk, &kid, &[0xCCu8; 32]);

    // First batch: use token A and B
    let batch1 = vec![token_a.clone(), token_b.clone()];
    let result1 = verifier.verify_batch(&batch1).await;
    assert_eq!(result1.successful, 2, "First batch should succeed");
    println!("Batch 1: A, B verified");

    // Second batch: try to use A again along with new token C
    let batch2 = vec![token_a.clone(), token_c.clone()];
    let result2 = verifier.verify_batch(&batch2).await;

    assert_eq!(result2.successful, 1, "Only C should succeed");
    assert_eq!(result2.failed, 1, "A should fail (previously used)");
    assert_eq!(result2.results[0], VerifyResult::Replay, "A should be replay");
    assert_eq!(result2.results[1], VerifyResult::Success, "C should succeed");

    println!("Batch 2: A rejected (replay), C accepted");
    println!("Cross-batch replay detection working");
    Ok(())
}

#[tokio::test]
async fn test_batch_size_limits() -> Result<()> {
    println!("Testing batch with various sizes");

    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT).expect("server");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let kid = format!("kid:{}", &pk_b64[..8]);

    let verifier = BatchVerifier::new(pk.to_vec());

    // Test empty batch
    let empty: Vec<TestToken> = vec![];
    let result = verifier.verify_batch(&empty).await;
    assert_eq!(result.successful, 0);
    assert_eq!(result.failed, 0);
    println!("Empty batch handled");

    // Test single token batch (use 0xFF to avoid collision with large batch)
    let single = vec![issue_token(&server, &sk, &kid, &[0xFFu8; 32])];
    let result = verifier.verify_batch(&single).await;
    assert_eq!(result.successful, 1);
    println!("Single token batch handled");

    // Test larger batch (100 tokens with inputs [0..100])
    let large: Vec<TestToken> = (0..100u8)
        .map(|i| {
            let input = [i; 32];
            issue_token(&server, &sk, &kid, &input)
        })
        .collect();

    let result = verifier.verify_batch(&large).await;
    assert_eq!(
        result.successful, 100,
        "All 100 unique tokens should succeed"
    );
    println!("Large batch (100 tokens) handled");

    Ok(())
}

#[tokio::test]
async fn test_batch_throughput_metrics() -> Result<()> {
    println!("Testing batch verification throughput");

    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT).expect("server");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);
    let kid = format!("kid:{}", &pk_b64[..8]);

    let verifier = BatchVerifier::new(pk.to_vec());

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

    println!("Batch size: {}", tokens.len());
    println!("Successful: {}", result.successful);
    println!("Time: {:?}", elapsed);
    println!("Throughput: {:.0} tokens/sec", throughput);

    assert_eq!(result.successful, 50, "All tokens should succeed");
    assert!(elapsed.as_millis() < 5000, "Batch should complete in <5s");

    println!("Throughput test passed");
    Ok(())
}
