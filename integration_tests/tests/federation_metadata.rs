// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Test federation metadata serialization and endpoint structure

use freebird_common::federation::FederationMetadata;

#[test]
fn test_federation_metadata_serialization() {
    // Test that FederationMetadata can be created and serialized
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let metadata = FederationMetadata {
        issuer_id: "issuer:test:v1".to_string(),
        vouches: Vec::new(),
        revocations: Vec::new(),
        updated_at: now,
        cache_ttl_secs: Some(3600),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&metadata).expect("serialize");
    assert!(json.contains("issuer:test:v1"));
    assert!(json.contains("\"vouches\":[]"));
    // Note: revocations is skipped when empty due to skip_serializing_if

    // Deserialize back
    let decoded: FederationMetadata = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.issuer_id, "issuer:test:v1");
    assert_eq!(decoded.vouches.len(), 0);
    assert_eq!(decoded.revocations.len(), 0);
    assert_eq!(decoded.cache_ttl_secs, Some(3600));

    println!("✅ Federation metadata serialization test passed");
}

#[test]
fn test_federation_metadata_with_vouches() {
    // Test FederationMetadata with actual vouches
    use freebird_common::federation::Vouch;
    use freebird_crypto::Server;

    let ctx = b"freebird:v1";
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, ctx).expect("server");
    let pk = server.public_key_sec1_compressed();

    // Create a vouch
    let mut vouch = Vouch {
        voucher_issuer_id: "issuer:a:v1".to_string(),
        vouched_issuer_id: "issuer:b:v1".to_string(),
        vouched_pubkey: pk.to_vec(),
        expires_at: 9999999999,
        created_at: 1234567890,
        trust_level: Some(80),
        signature: [0u8; 64],
    };

    // Sign the vouch
    let signature = vouch.sign(&sk).expect("sign vouch");
    vouch.signature = signature;

    // Verify it works
    assert!(vouch.verify(&pk), "Vouch should verify");

    // Create metadata with the vouch
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let metadata = FederationMetadata {
        issuer_id: "issuer:a:v1".to_string(),
        vouches: vec![vouch.clone()],
        revocations: Vec::new(),
        updated_at: now,
        cache_ttl_secs: Some(3600),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&metadata).expect("serialize");

    // Deserialize back
    let decoded: FederationMetadata = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.vouches.len(), 1);
    assert_eq!(decoded.vouches[0].voucher_issuer_id, "issuer:a:v1");
    assert_eq!(decoded.vouches[0].vouched_issuer_id, "issuer:b:v1");
    assert_eq!(decoded.vouches[0].trust_level, Some(80));

    // Verify the deserialized vouch signature still validates
    assert!(decoded.vouches[0].verify(&pk), "Deserialized vouch should verify");

    println!("✅ Federation metadata with vouches test passed");
}
