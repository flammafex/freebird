// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Integration test for signature-based token authentication (Layer 1 Federation)
//!
//! This test demonstrates that:
//! 1. Issuer can generate signature-based tokens (V2, 195 bytes)
//! 2. Verifier can authenticate tokens using ONLY the issuer's public key
//! 3. No shared secret is required between issuer and verifier
//! 4. This enables multi-issuer federation

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto::{Client, Server, Verifier};

#[test]
fn test_signature_based_token_generation() {
    // Setup: Issuer generates keypair
    let ctx = b"freebird:v1";
    let issuer_sk = [0x42u8; 32]; // Issuer's secret key
    let server = Server::from_secret_key(issuer_sk, ctx).expect("server from sk");
    let issuer_pubkey = server.public_key_sec1_compressed();

    // Step 1: Client blinds input
    let mut client = Client::new(ctx);
    let input = [0x11u8; 32];
    let (blinded_b64, state) = client.blind(&input).expect("blind");

    // Step 2: Issuer evaluates to get VOPRF token (131 bytes)
    let voprf_token_b64 = server
        .evaluate_with_proof(&blinded_b64)
        .expect("server evaluate");

    // Step 3: Client finalizes
    let (token_b64, _out_b64) = client
        .finalize(state, &voprf_token_b64, &issuer_pubkey)
        .expect("finalize");

    // Step 4: Decode VOPRF token (this is what issuer works with)
    let voprf_token = Base64UrlUnpadded::decode_vec(&token_b64).expect("decode token");
    assert_eq!(voprf_token.len(), 131, "VOPRF token should be 131 bytes");

    // Step 5: Issuer signs token metadata (simulating signature-based mode)
    let kid = "test-key-001";
    let exp = 1234567890i64;
    let issuer_id = "issuer:freebird:v1";

    let signature = crypto::compute_token_signature(
        &issuer_sk,
        &voprf_token,
        kid,
        exp,
        issuer_id,
    )
    .expect("compute signature");

    assert_eq!(signature.len(), 64, "ECDSA signature should be 64 bytes");

    // Step 6: Construct signature-based token (V2 format)
    let mut signature_token = voprf_token.clone();
    signature_token.extend_from_slice(&signature);
    assert_eq!(
        signature_token.len(),
        195,
        "Signature-based token should be 195 bytes (131 VOPRF + 64 signature)"
    );

    // Step 7: Verifier authenticates using ONLY the public key (no secret key!)
    let signature_valid = crypto::verify_token_signature(
        &issuer_pubkey,
        &voprf_token,
        &signature,
        kid,
        exp,
        issuer_id,
    );

    assert!(
        signature_valid,
        "Signature verification should succeed with public key only"
    );

    println!("✅ Signature-based token test passed!");
    println!("   VOPRF token: {} bytes", voprf_token.len());
    println!("   Signature: {} bytes", signature.len());
    println!("   Total token (V2): {} bytes", signature_token.len());
}

#[test]
fn test_mac_vs_signature_token_sizes() {
    // Demonstrate the difference between MAC-based (V1) and signature-based (V2) tokens
    let ctx = b"freebird:v1";
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, ctx).expect("server");
    let pubkey = server.public_key_sec1_compressed();

    // Generate VOPRF token
    let mut client = Client::new(ctx);
    let input = [0xAAu8; 32];
    let (blinded_b64, state) = client.blind(&input).expect("blind");
    let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluate");
    let (token_b64, _) = client.finalize(state, &eval_b64, &pubkey).expect("finalize");
    let voprf_token = Base64UrlUnpadded::decode_vec(&token_b64).expect("decode");

    let kid = "key-001";
    let exp = 9999999999i64;
    let issuer_id = "issuer:test";

    // V1: MAC-based token (163 bytes)
    let mac = crypto::compute_token_mac(&sk, &voprf_token, kid, exp, issuer_id);
    let mut mac_token = voprf_token.clone();
    mac_token.extend_from_slice(&mac);
    assert_eq!(mac_token.len(), 163, "MAC token (V1) = 131 + 32 = 163 bytes");

    // V2: Signature-based token (195 bytes)
    let signature = crypto::compute_token_signature(&sk, &voprf_token, kid, exp, issuer_id)
        .expect("signature");
    let mut sig_token = voprf_token.clone();
    sig_token.extend_from_slice(&signature);
    assert_eq!(
        sig_token.len(),
        195,
        "Signature token (V2) = 131 + 64 = 195 bytes"
    );

    println!("✅ Token format comparison:");
    println!("   V1 (MAC):       {} bytes", mac_token.len());
    println!("   V2 (Signature): {} bytes", sig_token.len());
    println!("   Overhead:       {} bytes (worth it for federation!)",
             sig_token.len() - mac_token.len());
}

#[test]
fn test_signature_determinism() {
    // RFC 6979 deterministic ECDSA should produce same signature for same inputs
    let ctx = b"freebird:v1";
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, ctx).expect("server");
    let pubkey = server.public_key_sec1_compressed();

    let mut client = Client::new(ctx);
    let input = [0xBBu8; 32];
    let (blinded_b64, state) = client.blind(&input).expect("blind");
    let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluate");
    let (token_b64, _) = client.finalize(state, &eval_b64, &pubkey).expect("finalize");
    let token = Base64UrlUnpadded::decode_vec(&token_b64).expect("decode");

    let kid = "key-001";
    let exp = 1234567890i64;
    let issuer_id = "issuer:test";

    // Sign twice with same inputs
    let sig1 = crypto::compute_token_signature(&sk, &token, kid, exp, issuer_id).expect("sig1");
    let sig2 = crypto::compute_token_signature(&sk, &token, kid, exp, issuer_id).expect("sig2");

    assert_eq!(sig1, sig2, "Signatures should be deterministic (RFC 6979)");

    // Both should verify
    assert!(crypto::verify_token_signature(&pubkey, &token, &sig1, kid, exp, issuer_id));
    assert!(crypto::verify_token_signature(&pubkey, &token, &sig2, kid, exp, issuer_id));

    println!("✅ Signature determinism test passed!");
}

#[test]
fn test_signature_tampering_detection() {
    // Verify that tampering with token data invalidates the signature
    let ctx = b"freebird:v1";
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, ctx).expect("server");
    let pubkey = server.public_key_sec1_compressed();

    let mut client = Client::new(ctx);
    let input = [0xCCu8; 32];
    let (blinded_b64, state) = client.blind(&input).expect("blind");
    let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluate");
    let (token_b64, _) = client.finalize(state, &eval_b64, &pubkey).expect("finalize");
    let mut token = Base64UrlUnpadded::decode_vec(&token_b64).expect("decode");

    let kid = "key-001";
    let exp = 1234567890i64;
    let issuer_id = "issuer:test";

    // Sign original token
    let signature = crypto::compute_token_signature(&sk, &token, kid, exp, issuer_id).expect("sig");

    // Verify original works
    assert!(crypto::verify_token_signature(&pubkey, &token, &signature, kid, exp, issuer_id));

    // Tamper with token
    token[0] ^= 0x01;

    // Verification should fail
    assert!(
        !crypto::verify_token_signature(&pubkey, &token, &signature, kid, exp, issuer_id),
        "Tampered token should fail verification"
    );

    println!("✅ Tampering detection test passed!");
}

#[test]
fn test_federation_scenario() {
    // Simulate multi-issuer federation scenario
    // Issuer A and Issuer B both issue tokens
    // Verifier can verify both without knowing their secret keys

    let ctx = b"freebird:v1";

    // Issuer A
    let sk_a = [0x11u8; 32];
    let server_a = Server::from_secret_key(sk_a, ctx).expect("server A");
    let pubkey_a = server_a.public_key_sec1_compressed();

    // Issuer B
    let sk_b = [0x22u8; 32];
    let server_b = Server::from_secret_key(sk_b, ctx).expect("server B");
    let pubkey_b = server_b.public_key_sec1_compressed();

    // Client gets token from Issuer A
    let mut client_a = Client::new(ctx);
    let input_a = [0xAAu8; 32];
    let (blinded_a, state_a) = client_a.blind(&input_a).expect("blind A");
    let eval_a = server_a.evaluate_with_proof(&blinded_a).expect("eval A");
    let (token_a_b64, _) = client_a.finalize(state_a, &eval_a, &pubkey_a).expect("finalize A");
    let token_a = Base64UrlUnpadded::decode_vec(&token_a_b64).expect("decode A");

    // Client gets token from Issuer B
    let mut client_b = Client::new(ctx);
    let input_b = [0xBBu8; 32];
    let (blinded_b, state_b) = client_b.blind(&input_b).expect("blind B");
    let eval_b = server_b.evaluate_with_proof(&blinded_b).expect("eval B");
    let (token_b_b64, _) = client_b.finalize(state_b, &eval_b, &pubkey_b).expect("finalize B");
    let token_b = Base64UrlUnpadded::decode_vec(&token_b_b64).expect("decode B");

    // Both issuers sign their tokens
    let kid_a = "issuer-a-key-001";
    let kid_b = "issuer-b-key-001";
    let exp = 9999999999i64;
    let issuer_id_a = "issuer:a:v1";
    let issuer_id_b = "issuer:b:v1";

    let sig_a = crypto::compute_token_signature(&sk_a, &token_a, kid_a, exp, issuer_id_a)
        .expect("sig A");
    let sig_b = crypto::compute_token_signature(&sk_b, &token_b, kid_b, exp, issuer_id_b)
        .expect("sig B");

    // Verifier has ONLY public keys (federation mode!)
    // No secret keys required!

    // Verify token from Issuer A
    let valid_a = crypto::verify_token_signature(&pubkey_a, &token_a, &sig_a, kid_a, exp, issuer_id_a);
    assert!(valid_a, "Token from Issuer A should verify with public key only");

    // Verify token from Issuer B
    let valid_b = crypto::verify_token_signature(&pubkey_b, &token_b, &sig_b, kid_b, exp, issuer_id_b);
    assert!(valid_b, "Token from Issuer B should verify with public key only");

    // Cross-verification should fail (wrong issuer's public key)
    let invalid_cross = crypto::verify_token_signature(&pubkey_a, &token_b, &sig_b, kid_b, exp, issuer_id_b);
    assert!(!invalid_cross, "Token from B should not verify with A's key");

    println!("✅ Federation scenario test passed!");
    println!("   Verifier successfully authenticated tokens from 2 issuers");
    println!("   using ONLY public keys (no shared secrets!)");
}
