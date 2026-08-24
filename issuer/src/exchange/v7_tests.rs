// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::{redis_harness::RedisHarness, v7::*, v7_store::V7ExchangeStore};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{
    native_exchange_v3_ordered_root, native_exchange_v3_output_leaf,
    native_exchange_v3_source_leaf, ExchangeReceiptKeyInfo, NativeExchangeV3Descriptor,
    NativeExchangeV3Discovery, NativeExchangeV3Keyset, NativeExchangeV3Output,
    NativeExchangeV3Profile, NativeExchangeV3Request, NativeExchangeV3Slot, NativeExchangeV3Source,
    NativeExchangeV3Transition, NATIVE_EXCHANGE_V3_PROFILE_ID, NATIVE_EXCHANGE_V3_QUANTITY,
    NATIVE_EXCHANGE_V3_RECEIPT_LIFETIME_SECS, NATIVE_EXCHANGE_V3_SUITE, NATIVE_EXCHANGE_V3_VERSION,
};
use freebird_crypto::{
    blind_v7, finalize_v7, PublicBearerV7Body, V7BlindState, V7MessageRandomizer,
    V7PublicKeyBinding, V7TokenKeyId,
};
use std::{path::Path, sync::Arc, time::SystemTime};
use tempfile::{tempdir, TempDir};

use crate::{
    config::NativeBearerV7Config,
    exchange::receipt::*,
    v7_signers::{V7Signer, V7SignerIdentity, V7SignerInventory, V7SignerSpec},
};

struct Fixture {
    _redis: RedisHarness,
    _directory: TempDir,
    engine: V7ExchangeEngine,
    request: NativeExchangeV3Request,
    output_binding: V7PublicKeyBinding,
    output_state: V7BlindState,
    output_randomizer: V7MessageRandomizer,
    output_body: PublicBearerV7Body,
    replay_artifact: Vec<u8>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn id(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn config(root: &Path, byte: u8, descriptor: &str) -> NativeBearerV7Config {
    NativeBearerV7Config {
        sk_path: root.join(format!("{byte}.der")),
        metadata_path: root.join(format!("{byte}.json")),
        registry_path: root.join("registry.json"),
        profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
        descriptor_id: descriptor.into(),
        token_key_id: id(byte),
        asset_id: "USD".into(),
        amount_minor: 1,
        validity_secs: NATIVE_EXCHANGE_V3_RECEIPT_LIFETIME_SECS + 86_400,
    }
}

fn descriptor(signer: &V7Signer) -> NativeExchangeV3Descriptor {
    let metadata = signer.metadata();
    NativeExchangeV3Descriptor {
        descriptor_id: metadata.descriptor_id.clone(),
        profile_id: metadata.profile_id.clone(),
        issuer_id: metadata.issuer_id.clone(),
        token_key_id: metadata.token_key_id.clone(),
        asset_id: metadata.asset_id.clone(),
        amount_minor: metadata.amount_minor.to_string(),
        suite: metadata.suite.clone(),
        modulus_bits: metadata.modulus_bits,
        exponent: metadata.exponent,
        pubkey_spki_b64: metadata.pubkey_spki_b64.clone(),
        spki_fingerprint: metadata.spki_fingerprint.clone(),
        valid_from: metadata.valid_from as u64,
        valid_until: metadata.valid_until as u64,
    }
}

async fn signed_token(
    signer: &V7Signer,
    binding: &V7PublicKeyBinding,
    nonce: [u8; 32],
    owner: [u8; 32],
) -> (Vec<u8>, PublicBearerV7Body) {
    let nullifier =
        PublicBearerV7Body::derive_nullifier(binding.issuer_id(), &nonce, &owner).unwrap();
    let body =
        PublicBearerV7Body::new_with_binding("USD", 1, binding, nonce, nullifier, owner).unwrap();
    let (blind, randomizer, state) = blind_v7(binding, &body).unwrap();
    let blind_signature = signer.sign(&blind).await.unwrap();
    let signature = finalize_v7(binding, state, &blind_signature).unwrap();
    (
        freebird_crypto::NativeBearerV7Token::new(body.clone(), randomizer, signature)
            .serialize()
            .unwrap(),
        body,
    )
}

async fn fixture() -> Option<Fixture> {
    let redis = RedisHarness::start().ok()?;
    let directory = tempdir().unwrap();
    let output_descriptor = id(0xaa);
    let source_descriptor = id(0xbb);
    let inventory = Arc::new(
        V7SignerInventory::load_or_generate(
            V7SignerSpec::from_native_config(
                &config(directory.path(), 0x22, &output_descriptor),
                "issuer:test",
            )
            .unwrap(),
            vec![V7SignerSpec::from_native_config(
                &config(directory.path(), 0x11, &source_descriptor),
                "issuer:test",
            )
            .unwrap()],
            &directory.path().join("registry.json"),
        )
        .unwrap(),
    );
    let output_identity = V7SignerIdentity::new(
        "issuer:test",
        NATIVE_EXCHANGE_V3_PROFILE_ID,
        output_descriptor.clone(),
        V7TokenKeyId::new([0x22; 32]),
    )
    .unwrap();
    let source_identity = V7SignerIdentity::new(
        "issuer:test",
        NATIVE_EXCHANGE_V3_PROFILE_ID,
        source_descriptor.clone(),
        V7TokenKeyId::new([0x11; 32]),
    )
    .unwrap();
    let output_signer = inventory.lookup(&output_identity).unwrap();
    let source_signer = inventory.lookup(&source_identity).unwrap();
    let output_binding = output_signer.binding().clone();
    let source_binding = source_signer.binding().clone();
    let (source_artifact, _) = signed_token(source_signer, &source_binding, [7; 32], [8; 32]).await;
    let (replay_artifact, _) = signed_token(source_signer, &source_binding, [7; 32], [8; 32]).await;
    let output_body = {
        let nonce = [9; 32];
        let owner = [10; 32];
        let nullifier =
            PublicBearerV7Body::derive_nullifier(output_binding.issuer_id(), &nonce, &owner)
                .unwrap();
        PublicBearerV7Body::new_with_binding("USD", 1, &output_binding, nonce, nullifier, owner)
            .unwrap()
    };
    let (output_blind, output_randomizer, output_state) =
        blind_v7(&output_binding, &output_body).unwrap();
    let source = descriptor(source_signer);
    let output = descriptor(output_signer);
    let source_keyset = id(0xcc);
    let target_keyset = id(0xdd);
    let transition_id = id(0xee);
    let graph_id = id(0xff);
    let profile = NativeExchangeV3Profile {
        version: NATIVE_EXCHANGE_V3_VERSION,
        profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
        graph_id: graph_id.clone(),
        suite: NATIVE_EXCHANGE_V3_SUITE.into(),
        modulus_bits: 3072,
        exponent: 65_537,
    };
    let discovery = NativeExchangeV3Discovery {
        version: NATIVE_EXCHANGE_V3_VERSION,
        profile,
        active_descriptors: vec![source, output],
        retained_descriptors: vec![],
        active_keysets: vec![
            NativeExchangeV3Keyset {
                keyset_id: source_keyset.clone(),
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                descriptor_ids: vec![source_descriptor.clone()],
            },
            NativeExchangeV3Keyset {
                keyset_id: target_keyset.clone(),
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                descriptor_ids: vec![output_descriptor.clone()],
            },
        ],
        retained_keysets: vec![],
        transitions: vec![NativeExchangeV3Transition {
            transition_id: transition_id.clone(),
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            source_keyset_id: source_keyset.clone(),
            target_keyset_id: target_keyset.clone(),
            source_slots: vec![NativeExchangeV3Slot {
                descriptor_id: source_descriptor.clone(),
                keyset_id: source_keyset.clone(),
                slot_id: "source".into(),
                quantity: NATIVE_EXCHANGE_V3_QUANTITY,
            }],
            output_slots: vec![NativeExchangeV3Slot {
                descriptor_id: output_descriptor.clone(),
                keyset_id: target_keyset.clone(),
                slot_id: "output".into(),
                quantity: NATIVE_EXCHANGE_V3_QUANTITY,
            }],
        }],
    };
    let source_digest = hex::encode(
        freebird_crypto::parse_native_bearer_v7_token(&source_artifact)
            .unwrap()
            .artifact_digest()
            .unwrap(),
    );
    let mut request = NativeExchangeV3Request {
        version: NATIVE_EXCHANGE_V3_VERSION,
        profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
        issuer_or_federation_id: "federation:test".into(),
        public_operation_id: Base64UrlUnpadded::encode_string(&[1; 16]),
        graph_id: graph_id.clone(),
        transition_id,
        source_keyset_id: source_keyset.clone(),
        target_keyset_id: target_keyset.clone(),
        asset_id: "USD".into(),
        source_count: 1,
        output_count: 1,
        source_total_minor: "1".into(),
        output_total_minor: "1".into(),
        source_root: "01".repeat(32),
        request_output_root: "02".repeat(32),
        sources: vec![NativeExchangeV3Source {
            artifact: Base64UrlUnpadded::encode_string(&source_artifact),
            source_artifact_digest: source_digest,
            descriptor_id: source_descriptor,
            keyset_id: source_keyset,
            slot_id: "source".into(),
        }],
        outputs: vec![NativeExchangeV3Output {
            output_id: Base64UrlUnpadded::encode_string(&[3; 16]),
            descriptor_id: output_descriptor,
            keyset_id: target_keyset,
            slot_id: "output".into(),
            asset_id: "USD".into(),
            amount_minor: "1".into(),
            blinded_message: Base64UrlUnpadded::encode_string(output_blind.as_bytes()),
            handoff_commitment: "03".repeat(32),
            request_output_commitment: "04".repeat(32),
            request_output_proof: Base64UrlUnpadded::encode_string(&[5; 192]),
        }],
    };
    let source = &request.sources[0];
    let source_leaf = native_exchange_v3_source_leaf(
        0,
        &Base64UrlUnpadded::decode_vec(&source.artifact).unwrap(),
        &hex::decode(&source.source_artifact_digest)
            .unwrap()
            .try_into()
            .unwrap(),
        &hex::decode(&source.descriptor_id)
            .unwrap()
            .try_into()
            .unwrap(),
        &hex::decode(&source.keyset_id).unwrap().try_into().unwrap(),
        &source.slot_id,
    )
    .unwrap();
    request.source_root = hex::encode(native_exchange_v3_ordered_root(&[source_leaf]).unwrap());
    let output = &request.outputs[0];
    let output_leaf = native_exchange_v3_output_leaf(
        false,
        0,
        &Base64UrlUnpadded::decode_vec(&output.output_id)
            .unwrap()
            .try_into()
            .unwrap(),
        &hex::decode(&output.request_output_commitment)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    request.request_output_root =
        hex::encode(native_exchange_v3_ordered_root(&[output_leaf]).unwrap());
    request.validate().unwrap();
    let receipt = load_or_generate_receipt_key(&directory.path().join("receipt.key")).unwrap();
    let lifetime_end = now() + NATIVE_EXCHANGE_V3_RECEIPT_LIFETIME_SECS + 86_400;
    let receipt_config = ReceiptKeyConfig {
        metadata: ExchangeReceiptKeyInfo {
            key_id: receipt.key_id(),
            algorithm: "Ed25519".into(),
            purpose: "exchange_receipt_v7".into(),
            public_key_b64: Base64UrlUnpadded::encode_string(receipt.verifying_key().as_bytes()),
            valid_from: now().saturating_sub(1),
            valid_until: lifetime_end,
        },
        private_key_path: directory.path().join("receipt.key"),
    };
    let receipt_ring = ReceiptKeyRing::load_v7(receipt_config, &[]).unwrap();
    let engine = V7ExchangeEngine::new(
        discovery,
        V7ExchangeStore::new(&redis.url).unwrap(),
        inventory,
        receipt_ring,
        "federation:test".into(),
        graph_id,
    )
    .await
    .unwrap();
    Some(Fixture {
        _redis: redis,
        _directory: directory,
        engine,
        request,
        output_binding,
        output_state,
        output_randomizer,
        output_body,
        replay_artifact,
    })
}

#[tokio::test]
async fn v7_exchange_success_is_idempotent_and_verifies_output() {
    let Some(fixture) = fixture().await else {
        return;
    };
    let first = fixture
        .engine
        .process_or_recover(&fixture.request, &[6; 32])
        .await
        .unwrap();
    let second = fixture
        .engine
        .process_or_recover(&fixture.request, &[6; 32])
        .await
        .unwrap();
    let V7ProcessDecision::Committed(first) = first else {
        panic!("V7 exchange did not commit")
    };
    let V7ProcessDecision::Committed(second) = second else {
        panic!("V7 exchange was not idempotent")
    };
    assert_eq!(first, second);
    let body: serde_json::Value = serde_json::from_slice(&first).unwrap();
    let result: freebird_common::api::NativeExchangeV3Result =
        serde_json::from_value(body["result"].clone()).unwrap();
    let signature = Base64UrlUnpadded::decode_vec(&result.outputs[0].blind_signature).unwrap();
    let blind_signature = freebird_crypto::V7BlindSignature::from_bytes(&signature).unwrap();
    let finalized = finalize_v7(
        &fixture.output_binding,
        fixture.output_state,
        &blind_signature,
    )
    .unwrap();
    let token = freebird_crypto::NativeBearerV7Token::new(
        fixture.output_body,
        fixture.output_randomizer,
        finalized,
    );
    token
        .verify(
            &fixture.output_binding,
            &freebird_crypto::V7BodyPolicy::new("USD", 1).unwrap(),
        )
        .unwrap();
}

#[tokio::test]
async fn v7_exchange_rejects_legacy_trailing_and_raw_boundary_inputs_without_state() {
    let Some(fixture) = fixture().await else {
        return;
    };
    for (index, version) in [(2u8, 5u8), (3, 6)] {
        let mut request = fixture.request.clone();
        request.public_operation_id = Base64UrlUnpadded::encode_string(&[index; 16]);
        let mut artifact = Base64UrlUnpadded::decode_vec(&request.sources[0].artifact).unwrap();
        artifact[0] = version;
        request.sources[0].artifact = Base64UrlUnpadded::encode_string(&artifact);
        assert!(matches!(
            fixture
                .engine
                .process_or_recover(&request, &[7; 32])
                .await
                .unwrap(),
            V7ProcessDecision::Rejected
        ));
    }
    let mut trailing = fixture.request.clone();
    trailing.public_operation_id = Base64UrlUnpadded::encode_string(&[8; 16]);
    let mut artifact = Base64UrlUnpadded::decode_vec(&trailing.sources[0].artifact).unwrap();
    artifact.push(0);
    trailing.sources[0].artifact = Base64UrlUnpadded::encode_string(&artifact);
    assert!(matches!(
        fixture
            .engine
            .process_or_recover(&trailing, &[7; 32])
            .await
            .unwrap(),
        V7ProcessDecision::Rejected
    ));
    let mut short_blind = fixture.request.clone();
    short_blind.public_operation_id = Base64UrlUnpadded::encode_string(&[9; 16]);
    short_blind.outputs[0].blinded_message = Base64UrlUnpadded::encode_string(&[0; 383]);
    assert!(matches!(
        fixture
            .engine
            .process_or_recover(&short_blind, &[7; 32])
            .await
            .unwrap(),
        V7ProcessDecision::Rejected
    ));
    let mut long_blind = fixture.request.clone();
    long_blind.public_operation_id = Base64UrlUnpadded::encode_string(&[11; 16]);
    long_blind.outputs[0].blinded_message = Base64UrlUnpadded::encode_string(&[0; 385]);
    assert!(matches!(
        fixture
            .engine
            .process_or_recover(&long_blind, &[7; 32])
            .await
            .unwrap(),
        V7ProcessDecision::Rejected
    ));
    let mut zero_blind = fixture.request.clone();
    zero_blind.public_operation_id = Base64UrlUnpadded::encode_string(&[17; 16]);
    zero_blind.outputs[0].blinded_message = Base64UrlUnpadded::encode_string(&[0; 384]);
    assert!(matches!(
        fixture
            .engine
            .process_or_recover(&zero_blind, &[7; 32])
            .await
            .unwrap(),
        V7ProcessDecision::Rejected
    ));
    let mut out_of_range_blind = fixture.request.clone();
    out_of_range_blind.public_operation_id = Base64UrlUnpadded::encode_string(&[18; 16]);
    out_of_range_blind.outputs[0].blinded_message = Base64UrlUnpadded::encode_string(&[0xff; 384]);
    assert!(matches!(
        fixture
            .engine
            .process_or_recover(&out_of_range_blind, &[7; 32])
            .await
            .unwrap(),
        V7ProcessDecision::Rejected
    ));
    let mut policy_tamper = fixture.request.clone();
    policy_tamper.public_operation_id = Base64UrlUnpadded::encode_string(&[12; 16]);
    policy_tamper.outputs[0].asset_id = "EUR".into();
    assert!(matches!(
        fixture
            .engine
            .process_or_recover(&policy_tamper, &[7; 32])
            .await
            .unwrap(),
        V7ProcessDecision::Rejected
    ));
    let mut identity_tamper = fixture.request.clone();
    identity_tamper.public_operation_id = Base64UrlUnpadded::encode_string(&[13; 16]);
    identity_tamper.sources[0].descriptor_id = id(0xaa);
    assert!(matches!(
        fixture
            .engine
            .process_or_recover(&identity_tamper, &[7; 32])
            .await
            .unwrap(),
        V7ProcessDecision::Rejected
    ));
    let mut source_root_tamper = fixture.request.clone();
    source_root_tamper.public_operation_id = Base64UrlUnpadded::encode_string(&[14; 16]);
    source_root_tamper.source_root = "00".repeat(32);
    assert!(matches!(
        fixture
            .engine
            .process_or_recover(&source_root_tamper, &[7; 32])
            .await
            .unwrap(),
        V7ProcessDecision::Rejected
    ));
    let mut output_root_tamper = fixture.request.clone();
    output_root_tamper.public_operation_id = Base64UrlUnpadded::encode_string(&[15; 16]);
    output_root_tamper.request_output_root = "00".repeat(32);
    assert!(matches!(
        fixture
            .engine
            .process_or_recover(&output_root_tamper, &[7; 32])
            .await
            .unwrap(),
        V7ProcessDecision::Rejected
    ));
    let mut graph_tamper = fixture.request.clone();
    graph_tamper.public_operation_id = Base64UrlUnpadded::encode_string(&[16; 16]);
    graph_tamper.graph_id = id(0x12);
    assert!(matches!(
        fixture
            .engine
            .process_or_recover(&graph_tamper, &[7; 32])
            .await
            .unwrap(),
        V7ProcessDecision::Rejected
    ));
}

#[tokio::test]
async fn v7_exchange_same_body_nullifier_rejects_distinct_signature_replay() {
    let Some(fixture) = fixture().await else {
        return;
    };
    assert!(matches!(
        fixture
            .engine
            .process_or_recover(&fixture.request, &[8; 32])
            .await
            .unwrap(),
        V7ProcessDecision::Committed(_)
    ));
    let mut replay = fixture.request.clone();
    replay.public_operation_id = Base64UrlUnpadded::encode_string(&[10; 16]);
    replay.sources[0].artifact = Base64UrlUnpadded::encode_string(&fixture.replay_artifact);
    replay.sources[0].source_artifact_digest = hex::encode(
        freebird_crypto::parse_native_bearer_v7_token(&fixture.replay_artifact)
            .unwrap()
            .artifact_digest()
            .unwrap(),
    );
    assert!(matches!(
        fixture
            .engine
            .process_or_recover(&replay, &[8; 32])
            .await
            .unwrap(),
        V7ProcessDecision::Rejected
    ));
}
