// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::{receipt::*, v7::V7ExchangeEngine, v7_store::V7ExchangeStore};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{
    native_exchange_v3_ordered_root, native_exchange_v3_output_leaf,
    native_exchange_v3_output_proof, native_exchange_v3_source_leaf,
    native_exchange_v3_verify_output_proof, NativeExchangeV3Descriptor, NativeExchangeV3Discovery,
    NativeExchangeV3Keyset, NativeExchangeV3Output, NativeExchangeV3Profile,
    NativeExchangeV3Request, NativeExchangeV3Slot, NativeExchangeV3Source,
    NativeExchangeV3Transition, NATIVE_EXCHANGE_V3_PROFILE_ID, NATIVE_EXCHANGE_V3_SUITE,
    NATIVE_EXCHANGE_V3_VERSION,
};
use rand::{rngs::OsRng, RngCore};
use sha2::Digest;
use std::{path::Path, sync::Arc};
use tempfile::{tempdir, TempDir};

use crate::{
    config::NativeBearerV7Config,
    v7_signers::{V7Signer, V7SignerInventory, V7SignerSpec},
};

fn lp(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut input = domain.to_vec();
    input.extend_from_slice(bytes);
    hex::encode(sha2::Sha256::digest(input))
}

fn keyset_id(descriptor_id: &str) -> String {
    let mut bytes = Vec::new();
    lp(&mut bytes, descriptor_id.as_bytes());
    digest(b"freebird native exchange keyset v3\0", &bytes)
}

fn transition_id(
    source_keyset_id: &str,
    target_keyset_id: &str,
    sources: &[NativeExchangeV3Slot],
    outputs: &[NativeExchangeV3Slot],
) -> String {
    let mut bytes = Vec::new();
    lp(&mut bytes, source_keyset_id.as_bytes());
    lp(&mut bytes, target_keyset_id.as_bytes());
    for slots in [sources, outputs] {
        bytes.extend_from_slice(&(slots.len() as u32).to_be_bytes());
        for slot in slots {
            lp(&mut bytes, slot.descriptor_id.as_bytes());
            lp(&mut bytes, slot.keyset_id.as_bytes());
            lp(&mut bytes, slot.slot_id.as_bytes());
            bytes.extend_from_slice(&slot.quantity.to_be_bytes());
        }
    }
    digest(b"freebird native exchange transition v3\0", &bytes)
}

fn graph_id(keysets: &[&str], transitions: &[&str]) -> String {
    let mut bytes = Vec::new();
    lp(&mut bytes, NATIVE_EXCHANGE_V3_PROFILE_ID.as_bytes());
    for keyset in keysets {
        lp(&mut bytes, keyset.as_bytes());
    }
    for transition in transitions {
        lp(&mut bytes, transition.as_bytes());
    }
    digest(b"freebird native exchange graph v3\0", &bytes)
}

fn signer_config(root: &Path, byte: u8) -> NativeBearerV7Config {
    NativeBearerV7Config {
        sk_path: root.join(format!("exchange-{byte}.der")),
        metadata_path: root.join(format!("exchange-{byte}.json")),
        registry_path: root.join("exchange-registry.json"),
        profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
        descriptor_id: String::new(),
        token_key_id: format!("{byte:02x}").repeat(32),
        asset_id: "USD".into(),
        amount_minor: 1,
        validity_secs: 86_400,
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

struct Fixture {
    _directory: TempDir,
    inventory: Arc<V7SignerInventory>,
    discovery: NativeExchangeV3Discovery,
    receipt_keys: ReceiptKeyRing,
}

fn fixture() -> Fixture {
    let directory = tempdir().unwrap();
    let active =
        V7SignerSpec::from_native_config(&signer_config(directory.path(), 0x11), "issuer:test")
            .unwrap();
    let retained =
        V7SignerSpec::from_native_config(&signer_config(directory.path(), 0x22), "issuer:test")
            .unwrap();
    let registry_path = directory.path().join("exchange-registry.json");
    V7SignerInventory::load_or_generate(retained.clone(), Vec::new(), &registry_path).unwrap();
    let inventory = Arc::new(
        V7SignerInventory::load_or_generate(active, vec![retained], &registry_path).unwrap(),
    );
    let source_signer = inventory.active();
    let output_signer = inventory
        .registry()
        .entries()
        .iter()
        .find(|entry| entry.descriptor_id != source_signer.metadata().descriptor_id)
        .map(|entry| {
            let identity = crate::v7_signers::V7SignerIdentity::new(
                entry.issuer_id.clone(),
                entry.profile_id.clone(),
                entry.descriptor_id.clone(),
                freebird_crypto::V7TokenKeyId::new(entry.token_key_id_bytes().unwrap()),
            )
            .unwrap();
            inventory.lookup(&identity).unwrap()
        })
        .unwrap();
    let source = descriptor(source_signer);
    let output = descriptor(output_signer);
    let source_keyset_id = keyset_id(&source.descriptor_id);
    let target_keyset_id = keyset_id(&output.descriptor_id);
    let source_slots = (0..2)
        .map(|index| NativeExchangeV3Slot {
            descriptor_id: source.descriptor_id.clone(),
            keyset_id: source_keyset_id.clone(),
            slot_id: format!("source-{index}"),
            quantity: 1,
        })
        .collect::<Vec<_>>();
    let output_slots = (0..2)
        .map(|index| NativeExchangeV3Slot {
            descriptor_id: output.descriptor_id.clone(),
            keyset_id: target_keyset_id.clone(),
            slot_id: format!("output-{index}"),
            quantity: 1,
        })
        .collect::<Vec<_>>();
    let transition_id = transition_id(
        &source_keyset_id,
        &target_keyset_id,
        &source_slots,
        &output_slots,
    );
    let graph_id = graph_id(&[&source_keyset_id, &target_keyset_id], &[&transition_id]);
    let discovery = NativeExchangeV3Discovery {
        version: NATIVE_EXCHANGE_V3_VERSION,
        profile: NativeExchangeV3Profile {
            version: NATIVE_EXCHANGE_V3_VERSION,
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            graph_id,
            suite: NATIVE_EXCHANGE_V3_SUITE.into(),
            modulus_bits: 3_072,
            exponent: 65_537,
        },
        active_descriptors: vec![source, output],
        retained_descriptors: Vec::new(),
        active_keysets: vec![
            NativeExchangeV3Keyset {
                keyset_id: source_keyset_id.clone(),
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                descriptor_ids: vec![source_signer.metadata().descriptor_id.clone()],
            },
            NativeExchangeV3Keyset {
                keyset_id: target_keyset_id.clone(),
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                descriptor_ids: vec![output_signer.metadata().descriptor_id.clone()],
            },
        ],
        retained_keysets: Vec::new(),
        transitions: vec![NativeExchangeV3Transition {
            transition_id,
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            source_keyset_id,
            target_keyset_id,
            source_slots,
            output_slots,
        }],
    };
    discovery.validate().unwrap();

    let receipt_path = directory.path().join("receipt.key");
    let receipt_key = load_or_generate_receipt_key(&receipt_path).unwrap();
    let receipt_metadata = ReceiptKeyMetadata {
        key_id: receipt_key.key_id(),
        algorithm: "Ed25519".into(),
        purpose: "exchange_receipt_v7".into(),
        public_key_b64: Base64UrlUnpadded::encode_string(receipt_key.verifying_key().as_bytes()),
        valid_from: 1,
        valid_until: freebird_common::api::EXCHANGE_MAX_VALID_UNTIL as u64,
    };
    let receipt_keys = ReceiptKeyRing::load_v7(
        ReceiptKeyConfig {
            metadata: receipt_metadata,
            private_key_path: receipt_path,
        },
        &[],
    )
    .unwrap();
    Fixture {
        _directory: directory,
        inventory,
        discovery,
        receipt_keys,
    }
}

#[tokio::test]
async fn canonical_exchange_bootstrap_builds_enabled_engine_without_redis() {
    let fixture = fixture();
    let graph_id = fixture.discovery.profile.graph_id.clone();
    let engine = V7ExchangeEngine::new(
        fixture.discovery,
        V7ExchangeStore::new("redis://127.0.0.1:6379").unwrap(),
        fixture.inventory,
        fixture.receipt_keys,
        "federation:test".into(),
        graph_id,
    )
    .await;
    assert!(engine.is_ok());
}

#[tokio::test]
async fn exchange_engine_rejects_tampered_descriptor_before_store_use() {
    let mut fixture = fixture();
    fixture.discovery.active_descriptors[0].amount_minor = "2".into();
    let graph_id = fixture.discovery.profile.graph_id.clone();
    let result = V7ExchangeEngine::new(
        fixture.discovery,
        V7ExchangeStore::new("redis://127.0.0.1:6379").unwrap(),
        fixture.inventory,
        fixture.receipt_keys,
        "federation:test".into(),
        graph_id,
    )
    .await;
    assert!(result.is_err());
}

#[derive(serde::Deserialize)]
struct ExchangeResponse {
    result: freebird_common::api::NativeExchangeV3Result,
    receipt: freebird_common::api::NativeExchangeV3Receipt,
}

struct OutputFinalizeState {
    body: freebird_crypto::PublicBearerV7Body,
    randomizer: freebird_crypto::V7MessageRandomizer,
    state: freebird_crypto::V7BlindState,
}

async fn valid_request(
    fixture: &Fixture,
    operation: [u8; 16],
    seed: u8,
) -> (
    NativeExchangeV3Request,
    Vec<OutputFinalizeState>,
    Vec<String>,
) {
    let source_signer = fixture.inventory.active();
    let output_identity = fixture
        .inventory
        .registry()
        .entries()
        .iter()
        .find(|entry| entry.descriptor_id != source_signer.metadata().descriptor_id)
        .map(|entry| {
            crate::v7_signers::V7SignerIdentity::new(
                entry.issuer_id.clone(),
                entry.profile_id.clone(),
                entry.descriptor_id.clone(),
                freebird_crypto::V7TokenKeyId::new(entry.token_key_id_bytes().unwrap()),
            )
            .unwrap()
        })
        .unwrap();
    let output_signer = fixture.inventory.lookup(&output_identity).unwrap();
    let source_descriptor = descriptor(source_signer);
    let output_descriptor = descriptor(output_signer);
    let source_keyset_id = keyset_id(&source_descriptor.descriptor_id);
    let target_keyset_id = keyset_id(&output_descriptor.descriptor_id);
    let source_slots = (0..2)
        .map(|index| NativeExchangeV3Slot {
            descriptor_id: source_descriptor.descriptor_id.clone(),
            keyset_id: source_keyset_id.clone(),
            slot_id: format!("source-{index}"),
            quantity: 1,
        })
        .collect::<Vec<_>>();
    let output_slots = (0..2)
        .map(|index| NativeExchangeV3Slot {
            descriptor_id: output_descriptor.descriptor_id.clone(),
            keyset_id: target_keyset_id.clone(),
            slot_id: format!("output-{index}"),
            quantity: 1,
        })
        .collect::<Vec<_>>();
    let mut sources = Vec::new();
    let mut spent_keys = Vec::new();
    let mut source_leaves = Vec::new();
    for (index, slot) in source_slots.iter().enumerate() {
        let nonce = [seed.wrapping_add(index as u8); 32];
        let owner = [seed.wrapping_add(20 + index as u8); 32];
        let body = freebird_crypto::PublicBearerV7Body::new_derived(
            "USD",
            1,
            source_signer.identity().issuer_id(),
            *source_signer.identity().token_key_id(),
            nonce,
            owner,
        )
        .unwrap();
        let (blind, randomizer, state) =
            freebird_crypto::blind_v7(source_signer.binding(), &body).unwrap();
        let blind_signature = fixture
            .inventory
            .sign(source_signer.identity(), &blind)
            .await
            .unwrap();
        let signature =
            freebird_crypto::finalize_v7(source_signer.binding(), state, &blind_signature).unwrap();
        let token = freebird_crypto::NativeBearerV7Token::new(body, randomizer, signature);
        token
            .verify(source_signer.binding(), source_signer.policy())
            .unwrap();
        let artifact = token.serialize().unwrap();
        let token_digest = token.artifact_digest().unwrap();
        let descriptor_id: [u8; 32] = hex::decode(&slot.descriptor_id)
            .unwrap()
            .try_into()
            .unwrap();
        let keyset_id_bytes: [u8; 32] = hex::decode(&slot.keyset_id).unwrap().try_into().unwrap();
        source_leaves.push(
            native_exchange_v3_source_leaf(
                index as u32,
                &artifact,
                &token_digest,
                &descriptor_id,
                &keyset_id_bytes,
                &slot.slot_id,
            )
            .unwrap(),
        );
        spent_keys.push(V7ExchangeStore::spent_key(
            "federation:test",
            token.body().nullifier(),
        ));
        sources.push(NativeExchangeV3Source {
            artifact: Base64UrlUnpadded::encode_string(&artifact),
            source_artifact_digest: hex::encode(token_digest),
            descriptor_id: slot.descriptor_id.clone(),
            keyset_id: slot.keyset_id.clone(),
            slot_id: slot.slot_id.clone(),
        });
    }

    let mut outputs = Vec::new();
    let mut finalizers = Vec::new();
    for (index, slot) in output_slots.iter().enumerate() {
        let nonce = [seed.wrapping_add(40 + index as u8); 32];
        let owner = [seed.wrapping_add(60 + index as u8); 32];
        let body = freebird_crypto::PublicBearerV7Body::new_derived(
            "USD",
            1,
            output_identity.issuer_id(),
            *output_identity.token_key_id(),
            nonce,
            owner,
        )
        .unwrap();
        let (blind, randomizer, state) =
            freebird_crypto::blind_v7(output_signer.binding(), &body).unwrap();
        let output_id = [seed.wrapping_add(80 + index as u8); 16];
        let commitment = [seed.wrapping_add(100 + index as u8); 32];
        outputs.push(NativeExchangeV3Output {
            output_id: Base64UrlUnpadded::encode_string(&output_id),
            descriptor_id: slot.descriptor_id.clone(),
            keyset_id: slot.keyset_id.clone(),
            slot_id: slot.slot_id.clone(),
            asset_id: "USD".into(),
            amount_minor: "1".into(),
            blinded_message: Base64UrlUnpadded::encode_string(blind.as_bytes()),
            handoff_commitment: hex::encode([seed.wrapping_add(120 + index as u8); 32]),
            request_output_commitment: hex::encode(commitment),
            request_output_proof: String::new(),
        });
        finalizers.push(OutputFinalizeState {
            body,
            randomizer,
            state,
        });
    }
    let request_leaves = outputs
        .iter()
        .enumerate()
        .map(|(index, output)| {
            native_exchange_v3_output_leaf(
                false,
                index as u32,
                &Base64UrlUnpadded::decode_vec(&output.output_id)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                &hex::decode(&output.request_output_commitment)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    for (index, output) in outputs.iter_mut().enumerate() {
        output.request_output_proof =
            native_exchange_v3_output_proof(&request_leaves, index).unwrap();
    }
    let request = NativeExchangeV3Request {
        version: NATIVE_EXCHANGE_V3_VERSION,
        profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
        issuer_or_federation_id: "federation:test".into(),
        public_operation_id: Base64UrlUnpadded::encode_string(&operation),
        graph_id: fixture.discovery.profile.graph_id.clone(),
        transition_id: fixture.discovery.transitions[0].transition_id.clone(),
        source_keyset_id,
        target_keyset_id,
        asset_id: "USD".into(),
        source_count: 2,
        output_count: 2,
        source_total_minor: "2".into(),
        output_total_minor: "2".into(),
        source_root: hex::encode(native_exchange_v3_ordered_root(&source_leaves).unwrap()),
        request_output_root: hex::encode(native_exchange_v3_ordered_root(&request_leaves).unwrap()),
        sources,
        outputs,
    };
    request.validate().unwrap();
    (request, finalizers, spent_keys)
}

fn redis_url() -> Option<String> {
    std::env::var("FREEBIRD_REDIS_LIVE_URL").ok()
}

#[tokio::test]
async fn redis_v7_engine_commits_and_recovers_current_result_ready_without_resigning() {
    let Some(redis_url) = redis_url() else {
        eprintln!("skipping Redis-backed V7 release gate: FREEBIRD_REDIS_LIVE_URL is unset");
        return;
    };
    assert!(
        redis_url.starts_with("redis://127.0.0.1:"),
        "release gate requires an isolated loopback Redis URL"
    );
    let port = redis_url
        .trim_start_matches("redis://127.0.0.1:")
        .split(['/', '?'])
        .next()
        .unwrap()
        .parse::<u16>()
        .unwrap();
    assert_ne!(
        port, 6379,
        "never run the release test against shared Redis"
    );

    let fixture = fixture();
    let graph_id = fixture.discovery.profile.graph_id.clone();
    let store = V7ExchangeStore::new(&redis_url).unwrap();
    store.readiness_check().await.unwrap();
    let engine = V7ExchangeEngine::new(
        fixture.discovery.clone(),
        store.clone(),
        fixture.inventory.clone(),
        fixture.receipt_keys.clone(),
        "federation:test".into(),
        graph_id,
    )
    .await
    .unwrap();

    let mut operation = [0u8; 16];
    OsRng.fill_bytes(&mut operation);
    let mut capability = [0u8; 32];
    OsRng.fill_bytes(&mut capability);
    let (request, finalizers, _) = valid_request(&fixture, operation, 5).await;
    let response_bytes = match engine
        .process_or_recover(&request, &capability)
        .await
        .unwrap()
    {
        super::v7::V7ProcessDecision::Committed(bytes) => bytes,
        other => panic!("expected committed V7 exchange, got {other:?}"),
    };
    let response: ExchangeResponse = serde_json::from_slice(&response_bytes).unwrap();
    response.result.validate().unwrap();
    assert_eq!(response.result.outputs.len(), 2);
    assert_eq!(response.result.output_count, 2);
    let request_digest = request.request_digest().unwrap();
    assert_eq!(response.result.request_digest, hex::encode(request_digest));
    let mut finalizers = finalizers;
    for (index, (source, result_output)) in request
        .outputs
        .iter()
        .zip(&response.result.outputs)
        .enumerate()
    {
        assert_eq!(source.output_id, result_output.output_id);
        assert_eq!(source.blinded_message, result_output.blinded_message);
        let id: [u8; 16] = Base64UrlUnpadded::decode_vec(&result_output.output_id)
            .unwrap()
            .try_into()
            .unwrap();
        let request_commitment: [u8; 32] = hex::decode(&result_output.request_output_commitment)
            .unwrap()
            .try_into()
            .unwrap();
        let result_commitment: [u8; 32] = hex::decode(&result_output.result_output_commitment)
            .unwrap()
            .try_into()
            .unwrap();
        let request_root: [u8; 32] = hex::decode(&response.result.request_output_root)
            .unwrap()
            .try_into()
            .unwrap();
        let result_root: [u8; 32] = hex::decode(&response.result.result_output_root)
            .unwrap()
            .try_into()
            .unwrap();
        native_exchange_v3_verify_output_proof(
            false,
            index as u32,
            &id,
            &request_commitment,
            &result_output.request_output_proof,
            &request_root,
        )
        .unwrap();
        native_exchange_v3_verify_output_proof(
            true,
            index as u32,
            &id,
            &result_commitment,
            &result_output.result_output_proof,
            &result_root,
        )
        .unwrap();
        let blind_signature =
            Base64UrlUnpadded::decode_vec(&result_output.blind_signature).unwrap();
        let blind_signature =
            freebird_crypto::V7BlindSignature::from_bytes(&blind_signature).unwrap();
        let output_signer = fixture
            .inventory
            .registry()
            .entries()
            .iter()
            .find(|entry| entry.descriptor_id == result_output.descriptor_id)
            .unwrap();
        let identity = crate::v7_signers::V7SignerIdentity::new(
            output_signer.issuer_id.clone(),
            output_signer.profile_id.clone(),
            output_signer.descriptor_id.clone(),
            freebird_crypto::V7TokenKeyId::new(output_signer.token_key_id_bytes().unwrap()),
        )
        .unwrap();
        let signer = fixture.inventory.lookup(&identity).unwrap();
        let finalizer = finalizers.remove(0);
        let signature =
            freebird_crypto::finalize_v7(signer.binding(), finalizer.state, &blind_signature)
                .unwrap();
        let artifact = freebird_crypto::NativeBearerV7Token::new(
            finalizer.body,
            finalizer.randomizer,
            signature,
        );
        artifact.verify(signer.binding(), signer.policy()).unwrap();
    }
    response.receipt.validate().unwrap();
    assert_eq!(response.receipt.request_digest, hex::encode(request_digest));
    assert_eq!(
        response.receipt.result_digest,
        response.result.result_digest
    );
    assert_eq!(
        response.receipt.receipt_key_id,
        fixture.receipt_keys.active_id()
    );
    let receipt_key = fixture
        .receipt_keys
        .resolve(&response.receipt.receipt_key_id)
        .unwrap();
    ReceiptKey::verify_receipt_v7(
        &response.receipt,
        &receipt_key.verifying_key(),
        &Base64UrlUnpadded::decode_vec(&response.receipt.signature).unwrap(),
    )
    .unwrap();
    let operation_id: [u8; 16] = Base64UrlUnpadded::decode_vec(&request.public_operation_id)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        engine
            .process_or_recover(&request, &capability)
            .await
            .unwrap(),
        super::v7::V7ProcessDecision::Committed(response_bytes.clone())
    );
    assert_eq!(
        engine.status(&operation_id, &capability).await.unwrap(),
        super::v7::V7StatusDecision::Committed(response_bytes.clone())
    );
    let wrong_capability = [0xA5; 32];
    assert_eq!(
        engine
            .status(&operation_id, &wrong_capability)
            .await
            .unwrap(),
        super::v7::V7StatusDecision::Unauthorized
    );

    // Exercise current-format ResultReady recovery using a second operation
    // and fresh source nullifiers. Only the isolated test Redis key's lease is
    // advanced to an expired timestamp; production lease behavior is untouched.
    let mut recovery_operation = [0u8; 16];
    OsRng.fill_bytes(&mut recovery_operation);
    let mut recovery_capability = [0u8; 32];
    OsRng.fill_bytes(&mut recovery_capability);
    let (recovery_request, recovery_finalizers, spent_keys) =
        valid_request(&fixture, recovery_operation, 77).await;
    let request_bytes = serde_json::to_vec(&recovery_request).unwrap();
    let request_digest = recovery_request.request_digest().unwrap();
    let reserve = store
        .reserve(
            &recovery_operation,
            &request_bytes,
            &request_digest,
            &recovery_capability,
            &spent_keys,
            fixture.receipt_keys.active_id(),
        )
        .await
        .unwrap();
    let reservation = match reserve {
        super::v7_store::V7ReserveOutcome::Created(reservation) => reservation,
        other => panic!("expected new ResultReady reservation, got {other:?}"),
    };
    let mut signed_outputs = Vec::new();
    for output in &recovery_request.outputs {
        let identity = crate::v7_signers::V7SignerIdentity::new(
            "issuer:test",
            NATIVE_EXCHANGE_V3_PROFILE_ID,
            output.descriptor_id.clone(),
            freebird_crypto::V7TokenKeyId::new(
                hex::decode(
                    &fixture
                        .discovery
                        .active_descriptors
                        .iter()
                        .find(|d| d.descriptor_id == output.descriptor_id)
                        .unwrap()
                        .token_key_id,
                )
                .unwrap()
                .try_into()
                .unwrap(),
            ),
        )
        .unwrap();
        let blind = freebird_crypto::V7BlindMessage::from_bytes(
            &Base64UrlUnpadded::decode_vec(&output.blinded_message).unwrap(),
        )
        .unwrap();
        let signature = fixture.inventory.sign(&identity, &blind).await.unwrap();
        signed_outputs.push((
            output,
            Base64UrlUnpadded::encode_string(signature.as_bytes()),
        ));
    }
    let mut persisted_result = super::v7::build_result(&recovery_request, signed_outputs).unwrap();
    let persisted_digest = persisted_result.result_digest().unwrap();
    persisted_result.result_digest = hex::encode(persisted_digest);
    persisted_result.validate().unwrap();
    let persisted_result_bytes = serde_json::to_vec(&persisted_result).unwrap();
    assert_eq!(
        store
            .result_ready(
                &recovery_operation,
                &reservation.fence,
                &persisted_result_bytes,
                &persisted_digest,
            )
            .await
            .unwrap(),
        super::v7_store::V7TransitionOutcome::Applied
    );
    let op_key = V7ExchangeStore::operation_key(&recovery_operation);
    let client = redis::Client::open(redis_url.as_str()).unwrap();
    let mut connection = client.get_async_connection().await.unwrap();
    redis::cmd("HSET")
        .arg(op_key)
        .arg("lease_until")
        .arg(1u64)
        .query_async::<_, ()>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let attempts_before_recovery = fixture
        .inventory
        .lookup(
            &crate::v7_signers::V7SignerIdentity::new(
                "issuer:test",
                NATIVE_EXCHANGE_V3_PROFILE_ID,
                fixture.discovery.active_descriptors[1]
                    .descriptor_id
                    .clone(),
                freebird_crypto::V7TokenKeyId::new(
                    hex::decode(&fixture.discovery.active_descriptors[1].token_key_id)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
            )
            .unwrap(),
        )
        .unwrap()
        .sign_attempts();
    let recovered_bytes = match engine
        .process_or_recover(&recovery_request, &recovery_capability)
        .await
        .unwrap()
    {
        super::v7::V7ProcessDecision::Committed(bytes) => bytes,
        other => panic!("expected recovered ResultReady commit, got {other:?}"),
    };
    assert_eq!(
        fixture
            .inventory
            .lookup(
                &crate::v7_signers::V7SignerIdentity::new(
                    "issuer:test",
                    NATIVE_EXCHANGE_V3_PROFILE_ID,
                    fixture.discovery.active_descriptors[1]
                        .descriptor_id
                        .clone(),
                    freebird_crypto::V7TokenKeyId::new(
                        hex::decode(&fixture.discovery.active_descriptors[1].token_key_id)
                            .unwrap()
                            .try_into()
                            .unwrap(),
                    ),
                )
                .unwrap()
            )
            .unwrap()
            .sign_attempts(),
        attempts_before_recovery,
        "ResultReady recovery must not re-sign outputs"
    );
    let recovered: ExchangeResponse = serde_json::from_slice(&recovered_bytes).unwrap();
    assert_eq!(recovered.result, persisted_result);
    assert_eq!(
        engine
            .status(&recovery_operation, &recovery_capability)
            .await
            .unwrap(),
        super::v7::V7StatusDecision::Committed(recovered_bytes)
    );

    let mut corrupt_result = persisted_result;
    corrupt_result.outputs[0].result_output_proof =
        corrupt_result.outputs[0].request_output_proof.clone();
    let error = corrupt_result.result_digest().unwrap_err();
    assert!(error.to_string().contains("proof"), "{error}");
    let _ = recovery_finalizers;
}
