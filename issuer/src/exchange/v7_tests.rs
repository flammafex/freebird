// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::{receipt::*, v7::V7ExchangeEngine, v7_store::V7ExchangeStore};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{
    NativeExchangeV3Descriptor, NativeExchangeV3Discovery, NativeExchangeV3Keyset,
    NativeExchangeV3Profile, NativeExchangeV3Slot, NativeExchangeV3Transition,
    NATIVE_EXCHANGE_V3_PROFILE_ID, NATIVE_EXCHANGE_V3_SUITE, NATIVE_EXCHANGE_V3_VERSION,
};
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
    source: &NativeExchangeV3Slot,
    output: &NativeExchangeV3Slot,
) -> String {
    let mut bytes = Vec::new();
    lp(&mut bytes, source_keyset_id.as_bytes());
    lp(&mut bytes, target_keyset_id.as_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    for slot in [source, output] {
        lp(&mut bytes, slot.descriptor_id.as_bytes());
        lp(&mut bytes, slot.keyset_id.as_bytes());
        lp(&mut bytes, slot.slot_id.as_bytes());
        bytes.extend_from_slice(&slot.quantity.to_be_bytes());
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
    let signers = inventory
        .registry()
        .entries()
        .iter()
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
        .collect::<Vec<_>>();
    let source = descriptor(signers[0]);
    let output = descriptor(signers[1]);
    let source_keyset_id = keyset_id(&source.descriptor_id);
    let target_keyset_id = keyset_id(&output.descriptor_id);
    let source_slot = NativeExchangeV3Slot {
        descriptor_id: source.descriptor_id.clone(),
        keyset_id: source_keyset_id.clone(),
        slot_id: "source".into(),
        quantity: 1,
    };
    let output_slot = NativeExchangeV3Slot {
        descriptor_id: output.descriptor_id.clone(),
        keyset_id: target_keyset_id.clone(),
        slot_id: "output".into(),
        quantity: 1,
    };
    let transition_id = transition_id(
        &source_keyset_id,
        &target_keyset_id,
        &source_slot,
        &output_slot,
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
                descriptor_ids: vec![signers[0].metadata().descriptor_id.clone()],
            },
            NativeExchangeV3Keyset {
                keyset_id: target_keyset_id.clone(),
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                descriptor_ids: vec![signers[1].metadata().descriptor_id.clone()],
            },
        ],
        retained_keysets: Vec::new(),
        transitions: vec![NativeExchangeV3Transition {
            transition_id,
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            source_keyset_id,
            target_keyset_id,
            source_slots: vec![source_slot],
            output_slots: vec![output_slot],
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
