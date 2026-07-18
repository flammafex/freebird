// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Pure validation and frozen engine serialization contracts.

use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::exchange_api::{ExchangeOutput, ExchangeSource, EXCHANGE_PROFILE_V1};
use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};
use sha2::Digest;

fn slot(descriptor: char, keyset: char, name: &str) -> ExchangeSlot {
    ExchangeSlot {
        descriptor_id: descriptor.to_string().repeat(64),
        keyset_id: keyset.to_string().repeat(64),
        slot_id: name.into(),
        quantity: 1,
    }
}

fn structural_request() -> ExchangeRequest {
    ExchangeRequest {
        profile: EXCHANGE_PROFILE_V1.into(),
        rule_id: "c".repeat(64),
        sources: vec![ExchangeSource {
            slot: slot('a', '1', "in"),
            artifact: Base64UrlUnpadded::encode_string(b"artifact-one"),
        }],
        outputs: vec![ExchangeOutput {
            slot: slot('b', '2', "out"),
            blinded_value: Base64UrlUnpadded::encode_string(b"blind"),
        }],
    }
}

#[test]
fn exchange_pure_artifact_request_binding() {
    let operation = [9; 16];
    let first = structural_request();
    let mut changed = first.clone();
    changed.sources[0].artifact = Base64UrlUnpadded::encode_string(b"artifact-two");
    assert_ne!(
        first.canonical_hash(&operation).unwrap(),
        changed.canonical_hash(&operation).unwrap()
    );
    let mut reordered = first.clone();
    reordered.outputs.push(ExchangeOutput {
        slot: slot('d', '2', "second"),
        blinded_value: Base64UrlUnpadded::encode_string(b"blind-2"),
    });
    reordered.outputs.swap(0, 1);
    assert_ne!(
        first.canonical_hash(&operation).unwrap(),
        reordered.canonical_hash(&operation).unwrap()
    );
}

#[test]
fn exchange_pure_invalid_source_and_output_precede_reservation() {
    let source_provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
    let target_provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let target_path = dir.path().join("target.der");
    std::fs::write(&target_path, target_provider.to_der().unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let descriptor = |role: &str, class: &str, id: char, provider: &SoftwareBlindRsaProvider| {
        profiles::ExchangeDescriptor {
            id: id.to_string().repeat(64),
            profile_id: EXCHANGE_PROFILE_V1.into(),
            role: role.into(),
            class: class.into(),
            issuer_id: "issuer:test".into(),
            kid: hex::encode(provider.token_key_id()),
            audience: None,
            spki_b64: Base64UrlUnpadded::encode_string(provider.public_key_spki()),
            suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
            max_quantity: 1,
            valid_from: 0,
            valid_until: i64::MAX,
        }
    };
    let source = descriptor("source", "source", 'a', &source_provider);
    let target = descriptor("target", "target", 'b', &target_provider);
    let profile = profiles::ExchangeProfile {
        profile_id: EXCHANGE_PROFILE_V1.into(),
        sources: profiles::ExchangeSourceAllowlist {
            descriptors: vec![source.clone()],
        },
        target_keyset: profiles::ExchangeKeyset {
            id: "2".repeat(64),
            targets: vec![profiles::ExchangeTargetKey {
                descriptor: target.clone(),
                private_key_path: target_path.display().to_string(),
            }],
        },
        rules: vec![profiles::ExchangeRule {
            id: "c".repeat(64),
            sources: vec![profiles::ExchangeRuleSlot {
                descriptor_id: source.id.clone(),
                slot_id: "in".into(),
                class: "source".into(),
                quantity: 1,
            }],
            outputs: vec![profiles::ExchangeRuleSlot {
                descriptor_id: target.id.clone(),
                slot_id: "out".into(),
                class: "target".into(),
                quantity: 1,
            }],
        }],
    };
    let signers = source_v5::PinnedTargetSigners::load(&profile, &[]).unwrap();
    let request = structural_request();
    let artifact =
        freebird_common::exchange_api::decode_base64url(&request.sources[0].artifact, MAX_ARTIFACT)
            .unwrap();
    assert!(source_v5::validate_source_v5(&profile, &source.id, &artifact, "issuer:test").is_err());
    let mut invalid_output = request.outputs.clone();
    invalid_output[0].blinded_value =
        Base64UrlUnpadded::encode_string(&vec![0; usize::from(target_provider.modulus_bits()) / 8]);
    assert!(signers
        .validate_outputs(&profile.target_keyset.id, &invalid_output)
        .is_err());
    // These APIs are pure and have no ExchangeStore argument: neither failure can reserve.
}

#[test]
fn exchange_fixed_result_receipt_response_vectors() {
    let mut result = ExchangeResult {
        operation_id: Base64UrlUnpadded::encode_string(&[7; 16]),
        profile: EXCHANGE_PROFILE_V1.into(),
        target_keyset_id: "2".repeat(64),
        outputs: vec![ExchangeResultOutput {
            slot: ExchangeSlot {
                descriptor_id: "b".repeat(64),
                keyset_id: "2".repeat(64),
                slot_id: "0".into(),
                quantity: 1,
            },
            blinded_value: Base64UrlUnpadded::encode_string(b"blind"),
            blind_signature: Base64UrlUnpadded::encode_string(&[1; 32]),
        }],
        result_digest: String::new(),
    };
    let digest = result.result_digest().unwrap();
    assert_eq!(
        hex::encode(digest),
        "8d5f7a19a611d1546e511ae80b4f6d86b4118952cfe54b87aeb79dd3b99174a1"
    );
    result.result_digest = Base64UrlUnpadded::encode_string(&digest);
    let receipt = ExchangeReceipt {
        operation_id: result.operation_id.clone(),
        profile: EXCHANGE_PROFILE_V1.into(),
        target_keyset_id: "2".repeat(64),
        result_digest: result.result_digest.clone(),
        created_at: 10,
        expires_at: 20,
        receipt_key_id: "4".repeat(64),
        signature: Base64UrlUnpadded::encode_string(&[5; 64]),
    };
    assert_eq!(
        hex::encode(receipt.signing_digest().unwrap()),
        "5fceb51349a31a03e74174e717342ef47b4f439eeae285b1d482a9e88d4c5d05"
    );
    let result_bytes = serde_json::to_vec(&result).unwrap();
    let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
    let response = serde_json::to_vec(&ExchangeResponse {
        result: &result,
        receipt: &receipt,
    })
    .unwrap();
    assert_eq!(
        hex::encode(sha2::Sha256::digest(&result_bytes)),
        "eafb7d491f53d4ca3ddba09353faca9162419ee72316223ef29a0d95df968c52"
    );
    assert_eq!(
        hex::encode(sha2::Sha256::digest(&receipt_bytes)),
        "809ca166cc007e731399edb80d171c54a8e8b53f824f0c9196030715d0f5e959"
    );
    assert_eq!(
        hex::encode(sha2::Sha256::digest(&response)),
        "330ed51af6c30bab6b8593b84a9ef9002cc2c01a2e721d5e90bf60b9e62564cc"
    );
}
