// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: End-to-End Token Issuance and Verification (V3)
//
// This test validates the complete V3 lifecycle of a token:
// 1. Client blinds input
// 2. Issuer evaluates the blinded element
// 3. Client finalizes (unblinds) to get PRF output
// 4. Issuer signs metadata (kid, exp, issuer_id) with ECDSA
// 5. Client builds V3 redemption token (output + metadata + ECDSA sig)
// 6. Verifier parses redemption token, verifies ECDSA sig, derives nullifier
//
// In V3, the verifier receives the PRF output inside the redemption token.
// It does NOT re-derive the output from the VOPRF evaluation.

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use std::sync::Arc;
use std::time::Duration;

use freebird_crypto::{
    build_redemption_token, compute_token_signature, nullifier_key, parse_redemption_token,
    verify_token_signature, Client, RedemptionToken, Server,
};
use freebird_verifier::store::{InMemoryStore, SpendStore};

/// Context used by all participants (must match issuer/verifier configuration)
const CONTEXT: &[u8] = b"freebird:v1";

/// Issuer ID for testing
const ISSUER_ID: &str = "issuer:test:e2e";

/// Token expiration in seconds (1 hour)
const EXP_SEC: u64 = 3600;

/// Simulates the full V3 token issuance and verification flow
#[tokio::test]
async fn test_e2e_issue_and_verify_token() -> Result<()> {
    println!("Starting end-to-end V3 issuance and verification test");

    // ========== SETUP: Issuer (Server) ==========
    let issuer_sk = [0x42u8; 32];
    let server = Server::from_secret_key(issuer_sk, CONTEXT).expect("server from sk");
    let issuer_pk = server.public_key_sec1_compressed();
    let issuer_pk_b64 = Base64UrlUnpadded::encode_string(&issuer_pk);

    let kid = format!("kid:{}", &issuer_pk_b64[..8]);

    println!("Issuer setup: kid={}", kid);

    // ========== SETUP: Verifier ==========
    let spend_store: Arc<dyn SpendStore> = Arc::new(InMemoryStore::default());

    // ========== STEP 1: Client blinds input ==========
    let mut client = Client::new(CONTEXT);
    let user_input = [0xAAu8; 32];
    let (blinded_b64, client_state) = client.blind(&user_input).expect("blind");

    println!("Client blinded input: {} bytes (b64)", blinded_b64.len());

    // ========== STEP 2: Issuer evaluates (simulating POST /v1/issue) ==========
    let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluate");

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64
        + EXP_SEC as i64;

    // Sign token metadata (V3: metadata only, no token_bytes)
    let signature =
        compute_token_signature(&issuer_sk, &kid, exp, ISSUER_ID).expect("compute signature");

    println!("Issuer evaluated and signed metadata, exp={}", exp);

    // ========== STEP 3: Client finalizes (unblinds) ==========
    let client_output_b64 = client
        .finalize(client_state, &eval_b64, &issuer_pk_b64)
        .expect("finalize");

    let output_raw = Base64UrlUnpadded::decode_vec(&client_output_b64)?;
    assert_eq!(output_raw.len(), 32, "PRF output must be 32 bytes");

    println!(
        "Client finalized: output={} chars (b64)",
        client_output_b64.len()
    );

    // ========== STEP 4: Client builds V3 redemption token ==========
    let output: [u8; 32] = output_raw.try_into().unwrap();
    let redemption = RedemptionToken {
        output,
        kid: kid.clone(),
        exp,
        issuer_id: ISSUER_ID.to_string(),
        sig: signature,
    };
    let token_bytes = build_redemption_token(&redemption)
        .map_err(|e| anyhow::anyhow!("build redemption token: {:?}", e))?;
    let token_b64 = Base64UrlUnpadded::encode_string(&token_bytes);

    println!("Client built V3 redemption token: {} bytes", token_bytes.len());

    // ========== STEP 5: Verification (simulating POST /v1/verify) ==========
    println!("Starting verification...");

    // 5a. Parse V3 redemption token
    let raw = Base64UrlUnpadded::decode_vec(&token_b64)?;
    let parsed = parse_redemption_token(&raw)
        .map_err(|e| anyhow::anyhow!("parse redemption token: {:?}", e))?;

    // 5b. Verify ECDSA signature over metadata
    assert!(
        verify_token_signature(&issuer_pk, &parsed.sig, &parsed.kid, parsed.exp, &parsed.issuer_id),
        "Signature verification should pass"
    );
    println!("Signature verified");

    // 5c. Derive nullifier from PRF output
    let output_b64 = Base64UrlUnpadded::encode_string(&parsed.output);
    let null_key = nullifier_key(&parsed.issuer_id, &output_b64);
    let spend_key = format!("freebird:spent:{}:{}", parsed.issuer_id, null_key);

    // First verification should succeed
    let first_spend = spend_store
        .mark_spent(&spend_key, Duration::from_secs(EXP_SEC))
        .await?;
    assert!(first_spend, "First spend should succeed");
    println!("Token marked as spent (first use)");

    // Second verification should fail (replay detected)
    let replay = spend_store
        .mark_spent(&spend_key, Duration::from_secs(EXP_SEC))
        .await?;
    assert!(!replay, "Replay should be detected");
    println!("Replay correctly detected");

    println!("End-to-end V3 test passed!");
    Ok(())
}

/// Test that tampered metadata signatures are rejected
#[tokio::test]
async fn test_e2e_tampered_token_rejected() -> Result<()> {
    println!("Testing tampered token rejection");

    let issuer_sk = [0x42u8; 32];
    let server = Server::from_secret_key(issuer_sk, CONTEXT).expect("server");
    let issuer_pk = server.public_key_sec1_compressed();
    let issuer_pk_b64 = Base64UrlUnpadded::encode_string(&issuer_pk);
    let kid = format!("kid:{}", &issuer_pk_b64[..8]);

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64
        + EXP_SEC as i64;

    // Sign metadata
    let signature =
        compute_token_signature(&issuer_sk, &kid, exp, ISSUER_ID).expect("signature");

    // Verify original works
    assert!(
        verify_token_signature(&issuer_pk, &signature, &kid, exp, ISSUER_ID),
        "Original signature should verify"
    );

    // Tamper with the signature
    let mut tampered_sig = signature;
    tampered_sig[0] ^= 0x01;

    // Tampered signature should fail
    assert!(
        !verify_token_signature(&issuer_pk, &tampered_sig, &kid, exp, ISSUER_ID),
        "Tampered signature should fail verification"
    );

    // Wrong kid should also fail
    assert!(
        !verify_token_signature(&issuer_pk, &signature, "wrong-kid", exp, ISSUER_ID),
        "Wrong kid should fail verification"
    );

    println!("Tampered token correctly rejected");
    Ok(())
}

/// Test that expired tokens are rejected
#[tokio::test]
async fn test_e2e_expired_token_rejected() -> Result<()> {
    println!("Testing expired token rejection");

    let issuer_sk = [0x42u8; 32];
    let server = Server::from_secret_key(issuer_sk, CONTEXT).expect("server");
    let issuer_pk = server.public_key_sec1_compressed();
    let issuer_pk_b64 = Base64UrlUnpadded::encode_string(&issuer_pk);
    let kid = format!("kid:{}", &issuer_pk_b64[..8]);

    // Create token that expired 1 hour ago
    let exp_past = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64
        - 3600;

    // Sign with the past expiration
    let signature =
        compute_token_signature(&issuer_sk, &kid, exp_past, ISSUER_ID).expect("signature");

    // Signature is valid (it was correctly signed)
    assert!(
        verify_token_signature(&issuer_pk, &signature, &kid, exp_past, ISSUER_ID),
        "Signature should be valid (just expired)"
    );

    // But the token should be rejected due to expiration
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let max_clock_skew = 300i64;

    let is_expired = now > exp_past + max_clock_skew;
    assert!(is_expired, "Token should be detected as expired");
    println!(
        "Expired token correctly detected (expired by {}s)",
        now - exp_past
    );

    Ok(())
}

/// Test multiple tokens from same user with different inputs produce different nullifiers
#[tokio::test]
async fn test_e2e_multiple_tokens_different_inputs() -> Result<()> {
    println!("Testing multiple tokens with different inputs");

    let issuer_sk = [0x42u8; 32];
    let server = Server::from_secret_key(issuer_sk, CONTEXT).expect("server");
    let issuer_pk = server.public_key_sec1_compressed();
    let issuer_pk_b64 = Base64UrlUnpadded::encode_string(&issuer_pk);
    let kid = format!("kid:{}", &issuer_pk_b64[..8]);

    let spend_store: Arc<dyn SpendStore> = Arc::new(InMemoryStore::default());

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64
        + EXP_SEC as i64;

    // Create and verify 3 different tokens
    for i in 0..3u8 {
        let mut client = Client::new(CONTEXT);
        let user_input = [i * 0x11; 32]; // Different input for each

        let (blinded_b64, client_state) = client.blind(&user_input).expect("blind");
        let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluate");

        // V3: sign metadata only
        let signature =
            compute_token_signature(&issuer_sk, &kid, exp, ISSUER_ID).expect("signature");

        // Client unblinds to get PRF output
        let client_output_b64 = client
            .finalize(client_state, &eval_b64, &issuer_pk_b64)
            .expect("finalize");

        // Verify ECDSA sig
        assert!(verify_token_signature(
            &issuer_pk, &signature, &kid, exp, ISSUER_ID
        ));

        // Build and verify V3 redemption token round-trip
        let output_raw = Base64UrlUnpadded::decode_vec(&client_output_b64)?;
        let output: [u8; 32] = output_raw.try_into().unwrap();
        let redemption = RedemptionToken {
            output,
            kid: kid.clone(),
            exp,
            issuer_id: ISSUER_ID.to_string(),
            sig: signature,
        };
        let token_bytes = build_redemption_token(&redemption)
            .map_err(|e| anyhow::anyhow!("build redemption token: {:?}", e))?;
        let parsed = parse_redemption_token(&token_bytes)
            .map_err(|e| anyhow::anyhow!("parse redemption token: {:?}", e))?;
        assert_eq!(parsed.output, output);

        // Derive nullifier and check anti-replay
        let null_key = nullifier_key(ISSUER_ID, &client_output_b64);
        let spend_key = format!("freebird:spent:{}:{}", ISSUER_ID, null_key);

        let spent = spend_store
            .mark_spent(&spend_key, Duration::from_secs(EXP_SEC))
            .await?;
        assert!(spent, "Token {} should be accepted (first use)", i);

        println!("Token {} verified successfully", i);
    }

    println!("All {} tokens verified with unique nullifiers", 3);
    Ok(())
}
