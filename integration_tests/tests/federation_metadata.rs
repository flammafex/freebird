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
    assert!(
        decoded.vouches[0].verify(&pk),
        "Deserialized vouch should verify"
    );

    println!("✅ Federation metadata with vouches test passed");
}

#[test]
fn test_vouch_trust_level_tampering_is_rejected() {
    use freebird_common::federation::Vouch;
    use freebird_crypto::Server;

    let ctx = b"freebird:v1";
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, ctx).expect("server");
    let pk = server.public_key_sec1_compressed();

    let mut vouch = Vouch {
        voucher_issuer_id: "issuer:a:v1".to_string(),
        vouched_issuer_id: "issuer:b:v1".to_string(),
        vouched_pubkey: pk.to_vec(),
        expires_at: 9999999999,
        created_at: 1234567890,
        trust_level: Some(10),
        signature: [0u8; 64],
    };
    vouch.signature = vouch.sign(&sk).expect("sign vouch");
    assert!(vouch.verify(&pk), "original vouch should verify");

    // Tamper trust-level after signing (privilege escalation attempt).
    vouch.trust_level = Some(100);
    assert!(
        !vouch.verify(&pk),
        "tampered trust_level must invalidate signature"
    );
}

#[test]
fn test_revocation_signature_validation_and_enforcement() {
    use freebird_common::federation::Revocation;
    use freebird_crypto::Server;

    fn is_revoked_enforced(
        target_issuer: &str,
        revocations: &[Revocation],
        revoker_pubkey: &[u8],
    ) -> bool {
        revocations
            .iter()
            .any(|r| r.revoked_issuer_id == target_issuer && r.verify(revoker_pubkey))
    }

    let ctx = b"freebird:v1";
    let revoker_sk = [0x11u8; 32];
    let bad_actor_sk = [0x22u8; 32];
    let revoker_server = Server::from_secret_key(revoker_sk, ctx).expect("revoker server");
    let bad_actor_server = Server::from_secret_key(bad_actor_sk, ctx).expect("bad actor server");
    let revoker_pk = revoker_server.public_key_sec1_compressed();
    let bad_actor_pk = bad_actor_server.public_key_sec1_compressed();

    let mut valid_revocation = Revocation {
        revoker_issuer_id: "issuer:root:v1".to_string(),
        revoked_issuer_id: "issuer:bad:v1".to_string(),
        revoked_at: 1234567890,
        reason: Some("compromised".to_string()),
        signature: [0u8; 64],
    };
    valid_revocation.signature = valid_revocation.sign(&revoker_sk).expect("sign revocation");
    assert!(valid_revocation.verify(&revoker_pk));

    // Valid signature should enforce revocation.
    assert!(is_revoked_enforced(
        "issuer:bad:v1",
        &[valid_revocation.clone()],
        &revoker_pk
    ));

    // Tampered revocation should not be enforced.
    let mut tampered = valid_revocation.clone();
    tampered.revoked_issuer_id = "issuer:other:v1".to_string();
    assert!(!tampered.verify(&revoker_pk));

    // Forged signature from unrelated key should not be enforced.
    let mut forged = Revocation {
        revoker_issuer_id: "issuer:root:v1".to_string(),
        revoked_issuer_id: "issuer:bad:v1".to_string(),
        revoked_at: 1234567890,
        reason: None,
        signature: [0u8; 64],
    };
    forged.signature = forged.sign(&bad_actor_sk).expect("forged sign");
    assert!(!forged.verify(&revoker_pk));
    assert!(forged.verify(&bad_actor_pk));
    assert!(!is_revoked_enforced(
        "issuer:bad:v1",
        &[forged],
        &revoker_pk
    ));
}

#[test]
fn test_vouch_created_expired_timestamp_sanity() {
    use freebird_common::federation::Vouch;

    let now = 1_700_000_000i64;
    let skew = 300i64;

    let invalid_order = Vouch {
        voucher_issuer_id: "issuer:a:v1".to_string(),
        vouched_issuer_id: "issuer:b:v1".to_string(),
        vouched_pubkey: vec![1, 2, 3],
        created_at: now + 10,
        expires_at: now - 10,
        trust_level: Some(50),
        signature: [0u8; 64],
    };
    assert!(
        !invalid_order.is_valid_at(now, skew),
        "created_at after expires_at must be invalid"
    );

    let future_created = Vouch {
        voucher_issuer_id: "issuer:a:v1".to_string(),
        vouched_issuer_id: "issuer:b:v1".to_string(),
        vouched_pubkey: vec![1, 2, 3],
        created_at: now + skew + 1,
        expires_at: now + 3600,
        trust_level: Some(50),
        signature: [0u8; 64],
    };
    assert!(
        !future_created.is_valid_at(now, skew),
        "created_at too far in future must be invalid"
    );

    let expired_beyond_skew = Vouch {
        voucher_issuer_id: "issuer:a:v1".to_string(),
        vouched_issuer_id: "issuer:b:v1".to_string(),
        vouched_pubkey: vec![1, 2, 3],
        created_at: now - 7200,
        expires_at: now - skew - 1,
        trust_level: Some(50),
        signature: [0u8; 64],
    };
    assert!(
        !expired_beyond_skew.is_valid_at(now, skew),
        "expired beyond skew tolerance must be invalid"
    );
}
