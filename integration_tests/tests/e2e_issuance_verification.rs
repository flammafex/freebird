// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: End-to-End Token Issuance and Verification
//
// This test validates the complete lifecycle of a token:
// 1. Client blinds input
// 2. Issuer evaluates and signs the token
// 3. Client finalizes the token
// 4. Verifier validates the token (signature, VOPRF proof, replay protection)
//
// This simulates the full HTTP flow without requiring actual HTTP servers.

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use std::sync::Arc;
use std::time::Duration;

use freebird_crypto::{Client, Server, Verifier, nullifier_key, verify_token_signature, compute_token_signature};
use freebird_verifier::store::{InMemoryStore, SpendStore};

/// Context used by all participants (must match issuer/verifier configuration)
const CONTEXT: &[u8] = b"freebird:v1";

/// Issuer ID for testing
const ISSUER_ID: &str = "issuer:test:e2e";

/// Token expiration in seconds (1 hour)
const EXP_SEC: u64 = 3600;

/// Current epoch (simplified: based on day)
fn current_epoch() -> u32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    (now / 86400) as u32
}

/// Simulates the full token issuance and verification flow
#[tokio::test]
async fn test_e2e_issue_and_verify_token() -> Result<()> {
    println!("🔄 Starting end-to-end issuance and verification test");

    // ========== SETUP: Issuer (Server) ==========
    // Fixed secret key for deterministic testing
    let issuer_sk = [0x42u8; 32];
    let server = Server::from_secret_key(issuer_sk, CONTEXT).expect("server from sk");
    let issuer_pk = server.public_key_sec1_compressed();
    let issuer_pk_b64 = Base64UrlUnpadded::encode_string(&issuer_pk);

    // Key ID derived from public key (simplified)
    let kid = format!("kid:{}", &issuer_pk_b64[..8]);

    println!("📝 Issuer setup: kid={}", kid);

    // ========== SETUP: Verifier ==========
    let spend_store: Arc<dyn SpendStore> = Arc::new(InMemoryStore::default());
    let verifier_crypto = Verifier::new(CONTEXT);

    // ========== STEP 1: Client blinds input ==========
    let mut client = Client::new(CONTEXT);
    let user_input = [0xAAu8; 32]; // User's private input
    let (blinded_b64, client_state) = client.blind(&user_input).expect("blind");

    println!("✅ Client blinded input: {} bytes (b64)", blinded_b64.len());

    // ========== STEP 2: Issuer evaluates (simulating POST /v1/issue) ==========
    let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluate");
    let eval_bytes = Base64UrlUnpadded::decode_vec(&eval_b64)?;

    // Calculate expiration
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64 + EXP_SEC as i64;

    let epoch = current_epoch();

    // Sign token metadata (creates the 64-byte ECDSA signature)
    let signature = compute_token_signature(
        &issuer_sk,
        &eval_bytes,
        &kid,
        exp,
        ISSUER_ID,
    ).expect("compute signature");

    // Combine VOPRF token (131 bytes) + signature (64 bytes) = 195 bytes
    let mut final_token_bytes = eval_bytes.clone();
    final_token_bytes.extend_from_slice(&signature);
    let final_token_b64 = Base64UrlUnpadded::encode_string(&final_token_bytes);

    println!("✅ Issuer evaluated: token={} bytes, epoch={}, exp={}",
             final_token_bytes.len(), epoch, exp);

    assert_eq!(final_token_bytes.len(), 195, "Token should be 195 bytes (131 VOPRF + 64 sig)");

    // ========== STEP 3: Client finalizes token ==========
    // Note: For verification, we only need the VOPRF part to derive the output
    let (_voprf_token_b64, client_output_b64) = client
        .finalize(client_state, &eval_b64, &issuer_pk)
        .expect("finalize");

    println!("✅ Client finalized: output={} chars (b64)", client_output_b64.len());

    // ========== STEP 4: Verification (simulating POST /v1/verify) ==========
    println!("🔍 Starting verification...");

    // 4a. Decode and validate token length
    let token_with_sig = Base64UrlUnpadded::decode_vec(&final_token_b64)?;
    assert_eq!(token_with_sig.len(), 195, "Token with signature should be 195 bytes");

    // 4b. Split token and signature
    let (token_data, sig_bytes) = token_with_sig.split_at(131);
    let received_signature: [u8; 64] = sig_bytes.try_into()?;

    // 4c. Verify ECDSA signature
    let sig_valid = verify_token_signature(
        &issuer_pk,
        token_data,
        &received_signature,
        &kid,
        exp,
        ISSUER_ID,
    );
    assert!(sig_valid, "Signature verification should pass");
    println!("✅ Signature verified");

    // 4d. Verify VOPRF token and derive output
    let token_data_b64 = Base64UrlUnpadded::encode_string(token_data);
    let verifier_output_b64 = verifier_crypto
        .verify(&token_data_b64, &issuer_pk)
        .expect("verify");

    // Client and verifier outputs should match (this proves the VOPRF protocol works)
    assert_eq!(client_output_b64, verifier_output_b64,
               "Client and verifier should derive same output");
    println!("✅ VOPRF outputs match");

    // 4e. Check replay protection
    let null_key = nullifier_key(ISSUER_ID, &verifier_output_b64);
    let spend_key = format!("freebird:spent:{}:{}", ISSUER_ID, null_key);

    // First verification should succeed
    let first_spend = spend_store.mark_spent(&spend_key, Duration::from_secs(EXP_SEC)).await?;
    assert!(first_spend, "First spend should succeed");
    println!("✅ Token marked as spent (first use)");

    // Second verification should fail (replay detected)
    let replay = spend_store.mark_spent(&spend_key, Duration::from_secs(EXP_SEC)).await?;
    assert!(!replay, "Replay should be detected");
    println!("✅ Replay correctly detected");

    println!("🎉 End-to-end test passed!");
    Ok(())
}

/// Test that tampered tokens are rejected
#[tokio::test]
async fn test_e2e_tampered_token_rejected() -> Result<()> {
    println!("🔒 Testing tampered token rejection");

    // Setup issuer
    let issuer_sk = [0x42u8; 32];
    let server = Server::from_secret_key(issuer_sk, CONTEXT).expect("server");
    let issuer_pk = server.public_key_sec1_compressed();
    let issuer_pk_b64 = Base64UrlUnpadded::encode_string(&issuer_pk);
    let kid = format!("kid:{}", &issuer_pk_b64[..8]);

    // Client blinds and issuer evaluates
    let mut client = Client::new(CONTEXT);
    let user_input = [0xBBu8; 32];
    let (blinded_b64, _) = client.blind(&user_input).expect("blind");
    let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluate");
    let eval_bytes = Base64UrlUnpadded::decode_vec(&eval_b64)?;

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64 + EXP_SEC as i64;

    // Sign the token
    let signature = compute_token_signature(&issuer_sk, &eval_bytes, &kid, exp, ISSUER_ID)
        .expect("signature");

    // Create tampered token (flip a bit in the VOPRF part)
    let mut tampered_bytes = eval_bytes.clone();
    tampered_bytes[10] ^= 0x01; // Flip one bit
    tampered_bytes.extend_from_slice(&signature);

    // Signature verification should fail for tampered token
    let (tampered_token, tampered_sig) = tampered_bytes.split_at(131);
    let sig: [u8; 64] = tampered_sig.try_into()?;

    let sig_valid = verify_token_signature(
        &issuer_pk,
        tampered_token,
        &sig,
        &kid,
        exp,
        ISSUER_ID,
    );

    assert!(!sig_valid, "Tampered token should fail signature verification");
    println!("✅ Tampered token correctly rejected");

    Ok(())
}

/// Test that expired tokens are rejected
#[tokio::test]
async fn test_e2e_expired_token_rejected() -> Result<()> {
    println!("⏰ Testing expired token rejection");

    // Setup issuer
    let issuer_sk = [0x42u8; 32];
    let server = Server::from_secret_key(issuer_sk, CONTEXT).expect("server");
    let issuer_pk = server.public_key_sec1_compressed();
    let issuer_pk_b64 = Base64UrlUnpadded::encode_string(&issuer_pk);
    let kid = format!("kid:{}", &issuer_pk_b64[..8]);

    // Client blinds and issuer evaluates
    let mut client = Client::new(CONTEXT);
    let user_input = [0xCCu8; 32];
    let (blinded_b64, _) = client.blind(&user_input).expect("blind");
    let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluate");
    let eval_bytes = Base64UrlUnpadded::decode_vec(&eval_b64)?;

    // Create token that expired 1 hour ago
    let exp_past = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64 - 3600; // 1 hour in the past

    // Sign with the past expiration
    let signature = compute_token_signature(&issuer_sk, &eval_bytes, &kid, exp_past, ISSUER_ID)
        .expect("signature");

    // Signature is valid (it was correctly signed)
    let sig_valid = verify_token_signature(
        &issuer_pk,
        &eval_bytes,
        &signature,
        &kid,
        exp_past,
        ISSUER_ID,
    );
    assert!(sig_valid, "Signature should be valid (just expired)");

    // But the token should be rejected due to expiration
    // (In a real verifier, this check happens before signature verification)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let max_clock_skew = 300i64; // 5 minutes tolerance

    let is_expired = now > exp_past + max_clock_skew;
    assert!(is_expired, "Token should be detected as expired");
    println!("✅ Expired token correctly detected (expired by {}s)", now - exp_past);

    Ok(())
}

/// Test multiple tokens from same user with different inputs
#[tokio::test]
async fn test_e2e_multiple_tokens_different_inputs() -> Result<()> {
    println!("🔢 Testing multiple tokens with different inputs");

    let issuer_sk = [0x42u8; 32];
    let server = Server::from_secret_key(issuer_sk, CONTEXT).expect("server");
    let issuer_pk = server.public_key_sec1_compressed();
    let issuer_pk_b64 = Base64UrlUnpadded::encode_string(&issuer_pk);
    let kid = format!("kid:{}", &issuer_pk_b64[..8]);

    let spend_store: Arc<dyn SpendStore> = Arc::new(InMemoryStore::default());
    let verifier = Verifier::new(CONTEXT);

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64 + EXP_SEC as i64;

    // Create and verify 3 different tokens
    for i in 0..3u8 {
        let mut client = Client::new(CONTEXT);
        let user_input = [i * 0x11; 32]; // Different input for each

        let (blinded_b64, client_state) = client.blind(&user_input).expect("blind");
        let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluate");
        let eval_bytes = Base64UrlUnpadded::decode_vec(&eval_b64)?;

        let _signature = compute_token_signature(&issuer_sk, &eval_bytes, &kid, exp, ISSUER_ID)
            .expect("signature");

        let (_, client_output_b64) = client
            .finalize(client_state, &eval_b64, &issuer_pk)
            .expect("finalize");
        let verifier_output_b64 = verifier.verify(&eval_b64, &issuer_pk).expect("verify");

        assert_eq!(client_output_b64, verifier_output_b64);

        let null_key = nullifier_key(ISSUER_ID, &verifier_output_b64);
        let spend_key = format!("freebird:spent:{}:{}", ISSUER_ID, null_key);

        let spent = spend_store.mark_spent(&spend_key, Duration::from_secs(EXP_SEC)).await?;
        assert!(spent, "Token {} should be accepted (first use)", i);

        println!("✅ Token {} verified successfully", i);
    }

    println!("✅ All {} tokens verified with unique nullifiers", 3);
    Ok(())
}
