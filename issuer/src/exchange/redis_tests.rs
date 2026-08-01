// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Redis atomicity, fencing, recovery, and AOF acceptance matrix.

use super::{
    load_or_generate_receipt_key,
    profiles::{
        ExchangeAdmissionStateV2, ExchangeDescriptorV2, ExchangeKeyV2, ExchangeKeysetV2,
        ExchangeProfileV2, ExchangeTransitionSlotV2, ExchangeTransitionV2,
    },
    redis_harness::RedisHarness,
    store::{
        ExchangeStore, OutputWork, State, TransitionOutcome, V2ReservationInput, V2ReserveOutcome,
        V2SourceSpend,
    },
};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::exchange_api::{
    ExchangeOutput, ExchangeReceiptV2, ExchangeRequestV2, ExchangeResultOutput, ExchangeResultV2,
    ExchangeSlot, ExchangeSource, EXCHANGE_PROFILE_V2, EXCHANGE_VERSION_V2,
};
use freebird_crypto::{
    build_public_bearer_message_from_parts, build_public_bearer_pass,
    provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider},
    PublicBearerPass,
};
use rand::RngCore;
use sha2::{Digest, Sha384};
use std::sync::Arc;

fn harness() -> Option<RedisHarness> {
    if !RedisHarness::binary_available() {
        return None;
    }
    Some(RedisHarness::start().expect("redis-server exists but isolated durable fixture failed"))
}

fn output(id: &str) -> OutputWork {
    OutputWork {
        descriptor_id: id.into(),
        keyset_id: "k".repeat(64),
        slot_id: "out".into(),
        quantity: 1,
        blinded_value: vec![1, 2, 3],
    }
}

async fn issue_source_artifact(
    provider: &SoftwareBlindRsaProvider,
    issuer_id: &str,
    nonce: [u8; 32],
) -> String {
    let token_key_id = *provider.token_key_id();
    let message = build_public_bearer_message_from_parts(&nonce, &token_key_id, issuer_id).unwrap();
    let message_hash = Sha384::digest(message);
    let mut salt = [0u8; 48];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut pss_hash = Sha384::new();
    pss_hash.update([0u8; 8]);
    pss_hash.update(message_hash);
    pss_hash.update(salt);
    let pss_hash = pss_hash.finalize();
    let em_len = usize::from(provider.modulus_bits()).div_ceil(8);
    let db_len = em_len - 48 - 1;
    let mut db = vec![0u8; db_len];
    let separator = db_len - salt.len() - 1;
    db[separator] = 1;
    db[separator + 1..].copy_from_slice(&salt);
    let mut mask = vec![0u8; db_len];
    let mut offset = 0;
    for counter in 0u32.. {
        if offset == mask.len() {
            break;
        }
        let mut hash = Sha384::new();
        hash.update(pss_hash);
        hash.update(counter.to_be_bytes());
        let block = hash.finalize();
        let take = (mask.len() - offset).min(block.len());
        mask[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
    }
    for (byte, mask) in db.iter_mut().zip(mask) {
        *byte ^= mask;
    }
    db[0] &= 0x7f;
    let mut encoded = db;
    encoded.extend_from_slice(&pss_hash);
    encoded.push(0xbc);
    let signature = provider.blind_sign(&encoded).await.unwrap();
    let token = PublicBearerPass {
        nonce,
        token_key_id,
        issuer_id: issuer_id.into(),
        signature,
    };
    let artifact = build_public_bearer_pass(&token).unwrap();
    freebird_crypto::verify_public_bearer_signature(provider.public_key_spki(), &token).unwrap();
    Base64UrlUnpadded::encode_string(&artifact)
}

struct V2EngineFixture {
    _dir: tempfile::TempDir,
    graph: ExchangeProfileV2,
    request_ab: ExchangeRequestV2,
    request_ba: ExchangeRequestV2,
    receipt_path: std::path::PathBuf,
}

fn v2_receipt_ring(
    active_path: &std::path::Path,
    retained_paths: &[std::path::PathBuf],
) -> super::ReceiptKeyRing {
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    let config = |path: &std::path::Path, purpose: &str| {
        let key = load_or_generate_receipt_key(path).unwrap();
        super::ReceiptKeyConfig {
            metadata: freebird_common::api::ExchangeReceiptKeyInfo {
                key_id: key.key_id(),
                algorithm: "Ed25519".into(),
                purpose: purpose.into(),
                public_key_b64: Base64UrlUnpadded::encode_string(key.verifying_key().as_bytes()),
                valid_from: now - 60,
                valid_until: now + 3600,
            },
            private_key_path: path.to_path_buf(),
        }
    };
    let active = config(active_path, "exchange_receipt_active");
    let retained = retained_paths
        .iter()
        .map(|path| config(path, "exchange_receipt_retained"))
        .collect::<Vec<_>>();
    super::ReceiptKeyRing::load_v2(active, &retained).unwrap()
}

async fn v2_engine_fixture(issuer_id: &str) -> V2EngineFixture {
    let dir = tempfile::tempdir().unwrap();
    let provider_a = SoftwareBlindRsaProvider::generate(2048).unwrap();
    let provider_b = SoftwareBlindRsaProvider::generate(2048).unwrap();
    let path_a = dir.path().join("a.der");
    let path_b = dir.path().join("b.der");
    for (path, provider) in [(&path_a, &provider_a), (&path_b, &provider_b)] {
        std::fs::write(path, provider.to_der().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let descriptor = |provider: &SoftwareBlindRsaProvider| {
        let mut descriptor = ExchangeDescriptorV2 {
            id: String::new(),
            profile_id: EXCHANGE_PROFILE_V2.into(),
            issuer_id: issuer_id.into(),
            kid: hex::encode(provider.token_key_id()),
            audience: Some("exchange".into()),
            spki_b64: Base64UrlUnpadded::encode_string(provider.public_key_spki()),
            suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
            valid_from: now - 60,
            valid_until: now + 3600,
        };
        descriptor.id = descriptor.canonical_id().unwrap();
        descriptor
    };
    let keyset = |descriptor: ExchangeDescriptorV2, path: &std::path::Path| {
        let mut keyset = ExchangeKeysetV2 {
            id: String::new(),
            keys: vec![ExchangeKeyV2 {
                descriptor,
                private_key_path: Some(path.display().to_string()),
            }],
        };
        keyset.id = keyset.canonical_id();
        keyset
    };
    let keyset_a = keyset(descriptor(&provider_a), &path_a);
    let keyset_b = keyset(descriptor(&provider_b), &path_b);
    let transition = |source: &ExchangeKeysetV2, target: &ExchangeKeysetV2, budget: &str| {
        let mut transition = ExchangeTransitionV2 {
            id: String::new(),
            source_keyset_id: source.id.clone(),
            target_keyset_id: target.id.clone(),
            sources: vec![ExchangeTransitionSlotV2 {
                descriptor_id: source.keys[0].descriptor.id.clone(),
                slot_id: "in".into(),
                class: "bearer".into(),
                quantity: 1,
            }],
            outputs: vec![ExchangeTransitionSlotV2 {
                descriptor_id: target.keys[0].descriptor.id.clone(),
                slot_id: "out".into(),
                class: "bearer".into(),
                quantity: 1,
            }],
            budget_id: budget.into(),
            budget_limit: 100,
            admission_state: ExchangeAdmissionStateV2::AcceptingNew,
        };
        transition.id = transition.canonical_id();
        transition
    };
    let transition_ab = transition(&keyset_a, &keyset_b, "budget-a-b");
    let transition_ba = transition(&keyset_b, &keyset_a, "budget-b-a");
    let mut graph = ExchangeProfileV2 {
        profile_id: EXCHANGE_PROFILE_V2.into(),
        graph_id: String::new(),
        keysets: vec![keyset_a.clone(), keyset_b.clone()],
        transitions: vec![transition_ab.clone(), transition_ba.clone()],
    };
    graph.graph_id = graph.canonical_graph_id();
    let request = |operation: [u8; 16],
                   source: &ExchangeKeysetV2,
                   target: &ExchangeKeysetV2,
                   transition: &ExchangeTransitionV2,
                   artifact: String,
                   provider: &SoftwareBlindRsaProvider| {
        let mut representative = vec![0u8; usize::from(provider.modulus_bits()) / 8];
        *representative.last_mut().unwrap() = 1;
        ExchangeRequestV2 {
            version: EXCHANGE_VERSION_V2,
            public_operation_id: Base64UrlUnpadded::encode_string(&operation),
            graph_id: graph.graph_id.clone(),
            transition_id: transition.id.clone(),
            source_keyset_id: source.id.clone(),
            target_keyset_id: target.id.clone(),
            sources: vec![ExchangeSource {
                slot: ExchangeSlot {
                    descriptor_id: source.keys[0].descriptor.id.clone(),
                    keyset_id: source.id.clone(),
                    slot_id: "in".into(),
                    quantity: 1,
                },
                artifact,
            }],
            outputs: vec![ExchangeOutput {
                slot: ExchangeSlot {
                    descriptor_id: target.keys[0].descriptor.id.clone(),
                    keyset_id: target.id.clone(),
                    slot_id: "out".into(),
                    quantity: 1,
                },
                blinded_value: Base64UrlUnpadded::encode_string(&representative),
            }],
        }
    };
    let artifact_a = issue_source_artifact(&provider_a, issuer_id, [0xa1; 32]).await;
    let artifact_b = issue_source_artifact(&provider_b, issuer_id, [0xb1; 32]).await;
    let request_ab = request(
        [0xa1; 16],
        &keyset_a,
        &keyset_b,
        &transition_ab,
        artifact_a,
        &provider_b,
    );
    let request_ba = request(
        [0xb1; 16],
        &keyset_b,
        &keyset_a,
        &transition_ba,
        artifact_b,
        &provider_a,
    );
    V2EngineFixture {
        receipt_path: dir.path().join("receipt.key"),
        _dir: dir,
        graph,
        request_ab,
        request_ba,
    }
}

fn created_v2(outcome: V2ReserveOutcome) -> Vec<u8> {
    match outcome {
        V2ReserveOutcome::Created(reservation) => reservation.fence,
        other => panic!("expected V2 creation, got {other:?}"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn reserve_v2(
    store: &ExchangeStore,
    id: &[u8; 16],
    hash: &[u8; 32],
    capability: &[u8; 32],
    source_key: &str,
    budget_id: &str,
    policy_digest: &[u8; 32],
    budget_limit: u64,
    quantity: u32,
) -> V2ReserveOutcome {
    let now = store.redis_time().await.unwrap() as i64;
    let sources = [V2SourceSpend {
        spend_key: source_key.into(),
        valid_from: now - 1,
        valid_until: now + 120,
    }];
    let outputs = [OutputWork {
        quantity,
        ..output("v2-target")
    }];
    let signer_refs = [ExchangeStore::signer_ref_key_v2("v2-signer")];
    reserve_v2_with(
        store,
        id,
        hash,
        capability,
        &sources,
        &outputs,
        &signer_refs,
        budget_id,
        policy_digest,
        budget_limit,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn reserve_v2_with(
    store: &ExchangeStore,
    id: &[u8; 16],
    hash: &[u8; 32],
    capability: &[u8; 32],
    sources: &[V2SourceSpend],
    outputs: &[OutputWork],
    signer_refs: &[String],
    budget_id: &str,
    policy_digest: &[u8; 32],
    budget_limit: u64,
) -> V2ReserveOutcome {
    store
        .reserve_v2(V2ReservationInput {
            operation_id: id,
            public_operation_id: &Base64UrlUnpadded::encode_string(id),
            status_capability: capability,
            request_hash: hash,
            graph_id: "graph-v2",
            transition_id: "transition-v2",
            source_keyset_id: "source-keyset-v2",
            target_keyset_id: "target-keyset-v2",
            sources,
            outputs,
            signer_ref_keys: signer_refs,
            receipt_key_id: "receipt-v2",
            receipt_ref_key: &ExchangeStore::receipt_ref_key_v2("receipt-v2"),
            budget_id,
            budget_policy_digest: policy_digest,
            budget_limit,
            receipt_lifetime_secs: 300,
            receipt_valid_from: 1,
            receipt_valid_until: freebird_common::api::EXCHANGE_MAX_VALID_UNTIL as u64,
        })
        .await
        .unwrap()
}

fn fixed_v2_wire_vector() -> (ExchangeRequestV2, ExchangeResultV2, ExchangeReceiptV2) {
    let encoded = |bytes: &[u8]| Base64UrlUnpadded::encode_string(bytes);
    let request = ExchangeRequestV2 {
        version: EXCHANGE_VERSION_V2,
        public_operation_id: encoded(&[7; 16]),
        graph_id: "3".repeat(64),
        transition_id: "4".repeat(64),
        source_keyset_id: "1".repeat(64),
        target_keyset_id: "2".repeat(64),
        sources: vec![ExchangeSource {
            slot: ExchangeSlot {
                descriptor_id: "a".repeat(64),
                keyset_id: "1".repeat(64),
                slot_id: "source-0".into(),
                quantity: 1,
            },
            artifact: encoded(b"source artifact"),
        }],
        outputs: vec![ExchangeOutput {
            slot: ExchangeSlot {
                descriptor_id: "b".repeat(64),
                keyset_id: "2".repeat(64),
                slot_id: "output-0".into(),
                quantity: 2,
            },
            blinded_value: encoded(b"blinded output"),
        }],
    };
    let mut result = ExchangeResultV2 {
        version: request.version,
        public_operation_id: request.public_operation_id.clone(),
        graph_id: request.graph_id.clone(),
        transition_id: request.transition_id.clone(),
        source_keyset_id: request.source_keyset_id.clone(),
        target_keyset_id: request.target_keyset_id.clone(),
        outputs: vec![freebird_common::exchange_api::ExchangeResultOutput {
            slot: request.outputs[0].slot.clone(),
            blinded_value: request.outputs[0].blinded_value.clone(),
            blind_signature: encoded(b"blind signature"),
        }],
        result_digest: String::new(),
    };
    result.result_digest = encoded(&result.result_digest().unwrap());
    let receipt = ExchangeReceiptV2 {
        version: result.version,
        public_operation_id: result.public_operation_id.clone(),
        graph_id: result.graph_id.clone(),
        transition_id: result.transition_id.clone(),
        source_keyset_id: result.source_keyset_id.clone(),
        target_keyset_id: result.target_keyset_id.clone(),
        result_digest: result.result_digest.clone(),
        created_at: 1_700_000_000,
        expires_at: 1_700_003_600,
        receipt_key_id: "5".repeat(64),
        signature: encoded(&[9; 64]),
    };
    (request, result, receipt)
}

#[test]
fn exchange_v2_canonical_wire_bytes_and_digest_vectors_are_frozen() {
    let (request, result, receipt) = fixed_v2_wire_vector();
    let expected_request = concat!(
        "02000000100707070707070707070707070707070700000040333333333333333333333333333333333333333333333333333333333333333333333333333333",
        "33333333333333333333333333333333333333333333333333000000403434343434343434343434343434343434343434343434343434343434343434343434",
        "34343434343434343434343434343434343434343434343434343434340000004031313131313131313131313131313131313131313131313131313131313131",
        "31313131313131313131313131313131313131313131313131313131313131313100000040323232323232323232323232323232323232323232323232323232",
        "32323232323232323232323232323232323232323232323232323232323232323232323232000000010000004061616161616161616161616161616161616161",
        "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616100000040313131313131313131313131313131",
        "3131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313100000008736f757263652d30000000",
        "010000000f736f757263652061727469666163740000000100000040626262626262626262626262626262626262626262626262626262626262626262626262",
        "62626262626262626262626262626262626262626262626262626262000000403232323232323232323232323232323232323232323232323232323232323232",
        "3232323232323232323232323232323232323232323232323232323232323232000000086f75747075742d30000000020000000e626c696e646564206f757470",
        "7574",
    );
    let expected_result = concat!(
        "02000000100707070707070707070707070707070700000040333333333333333333333333333333333333333333333333333333333333333333333333333333",
        "33333333333333333333333333333333333333333333333333000000403434343434343434343434343434343434343434343434343434343434343434343434",
        "34343434343434343434343434343434343434343434343434343434340000004031313131313131313131313131313131313131313131313131313131313131",
        "31313131313131313131313131313131313131313131313131313131313131313100000040323232323232323232323232323232323232323232323232323232",
        "32323232323232323232323232323232323232323232323232323232323232323232323232000000010000004062626262626262626262626262626262626262",
        "62626262626262626262626262626262626262626262626262626262626262626262626262626262626262626200000040323232323232323232323232323232",
        "32323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232000000086f75747075742d30000000",
        "020000000e626c696e646564206f75747075740000000f626c696e64207369676e617475726500000020da7314e61fde88e19256f3f4c54d056f9856a4974ee0",
        "faf26dd23195f2ad1215",
    );
    let expected_receipt_payload = concat!(
        "02000000100707070707070707070707070707070700000040333333333333333333333333333333333333333333333333333333333333333333333333333333",
        "33333333333333333333333333333333333333333333333333000000403434343434343434343434343434343434343434343434343434343434343434343434",
        "34343434343434343434343434343434343434343434343434343434340000004031313131313131313131313131313131313131313131313131313131313131",
        "31313131313131313131313131313131313131313131313131313131313131313100000040323232323232323232323232323232323232323232323232323232",
        "3232323232323232323232323232323232323232323232323232323232323232323232323200000020da7314e61fde88e19256f3f4c54d056f9856a4974ee0fa",
        "f26dd23195f2ad1215000000006553f100000000006553ff10000000403535353535353535353535353535353535353535353535353535353535353535353535",
        "3535353535353535353535353535353535353535353535353535353535",
    );
    assert_eq!(
        hex::encode(request.canonical_bytes().unwrap()),
        expected_request
    );
    assert_eq!(
        hex::encode(request.request_digest().unwrap()),
        "201624b62529476aa387900fb8ed97dfc59115b0b8ce6fa7837438758576d70a"
    );
    assert_eq!(
        hex::encode(result.canonical_bytes().unwrap()),
        expected_result
    );
    assert_eq!(
        hex::encode(result.result_digest().unwrap()),
        "da7314e61fde88e19256f3f4c54d056f9856a4974ee0faf26dd23195f2ad1215"
    );
    assert_eq!(
        hex::encode(receipt.canonical_payload().unwrap()),
        expected_receipt_payload
    );
    assert_eq!(
        hex::encode(receipt.receipt_digest().unwrap()),
        "620e2fdb0e255e5bc6a70bdfdf22a7d0381b6facae0d25d0f6e751a8ec040f9a"
    );
    assert!(receipt.validate_result(&result).is_ok());
}

#[tokio::test]
async fn exchange_v2_receipt_interval_comes_from_atomic_redis_time() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let before = store.redis_time().await.unwrap();
    created_v2(
        reserve_v2(
            &store,
            &[0xd1; 16],
            &[0xd1; 32],
            &[0xd2; 32],
            "spend:v2:redis-time",
            "budget-v2-redis-time",
            &[0xd3; 32],
            10,
            1,
        )
        .await,
    );
    let after = store.redis_time().await.unwrap();
    let record = store.get_v2(&[0xd1; 16]).await.unwrap().unwrap();
    assert!((before..=after).contains(&record.created_at));
    assert_eq!(record.receipt_expires_at, record.created_at + 300);

    let now = store.redis_time().await.unwrap() as i64;
    let sources = [V2SourceSpend {
        spend_key: "spend:v2:invalid-receipt-window".into(),
        valid_from: now - 1,
        valid_until: now + 60,
    }];
    let outputs = [output("invalid-receipt-window")];
    let refs = [ExchangeStore::signer_ref_key_v2("invalid-window")];
    let outcome = store
        .reserve_v2(V2ReservationInput {
            operation_id: &[0xd4; 16],
            public_operation_id: &Base64UrlUnpadded::encode_string(&[0xd4; 16]),
            status_capability: &[0xd5; 32],
            request_hash: &[0xd4; 32],
            graph_id: "graph",
            transition_id: "transition",
            source_keyset_id: "source",
            target_keyset_id: "target",
            sources: &sources,
            outputs: &outputs,
            signer_ref_keys: &refs,
            receipt_key_id: "receipt",
            receipt_ref_key: &ExchangeStore::receipt_ref_key_v2("receipt-invalid"),
            budget_id: "budget-invalid-window",
            budget_policy_digest: &[0xd6; 32],
            budget_limit: 10,
            receipt_lifetime_secs: 300,
            receipt_valid_from: u64::try_from(now + 10).unwrap(),
            receipt_valid_until: u64::try_from(now + 1000).unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(outcome, V2ReserveOutcome::InvalidEntries);
    assert!(store.get_v2(&[0xd4; 16]).await.unwrap().is_none());
    let spend: Option<Vec<u8>> = store
        .raw_command("GET", &[b"spend:v2:invalid-receipt-window"])
        .await
        .unwrap();
    assert!(spend.is_none());
}

#[tokio::test]
async fn exchange_v2_exact_lua_max_uses_absolute_inclusive_expiry() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let now = store.redis_time().await.unwrap() as i64;
    let max = freebird_common::api::EXCHANGE_MAX_VALID_UNTIL;
    let sources = [V2SourceSpend {
        spend_key: "spend:v2:max-inclusive".into(),
        valid_from: now - 1,
        valid_until: max,
    }];
    let outputs = [output("max-inclusive")];
    let refs = [ExchangeStore::signer_ref_key_v2("max-inclusive")];
    let outcome = store
        .reserve_v2(V2ReservationInput {
            operation_id: &[0xd7; 16],
            public_operation_id: &Base64UrlUnpadded::encode_string(&[0xd7; 16]),
            status_capability: &[0xd8; 32],
            request_hash: &[0xd7; 32],
            graph_id: "graph",
            transition_id: "transition",
            source_keyset_id: "source",
            target_keyset_id: "target",
            sources: &sources,
            outputs: &outputs,
            signer_ref_keys: &refs,
            receipt_key_id: "receipt",
            receipt_ref_key: &ExchangeStore::receipt_ref_key_v2("receipt-max"),
            budget_id: "budget-max-inclusive",
            budget_policy_digest: &[0xd9; 32],
            budget_limit: freebird_common::api::EXCHANGE_MAX_BUDGET_LIMIT,
            receipt_lifetime_secs: 300,
            receipt_valid_from: 1,
            receipt_valid_until: max as u64,
        })
        .await
        .unwrap();
    created_v2(outcome);
    let expires_at: i64 = store
        .raw_command("EXPIRETIME", &[b"spend:v2:max-inclusive"])
        .await
        .unwrap();
    assert_eq!(
        expires_at,
        max + 1,
        "inclusive validity must expire at valid_until + 1"
    );
}

#[tokio::test]
async fn exchange_v2_operation_record_has_no_ttl_in_any_durable_state() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let operation = [0xd0; 16];
    let fence = created_v2(
        reserve_v2(
            &store,
            &operation,
            &[0xd1; 32],
            &[0xd2; 32],
            "spend:v2:op-no-ttl",
            "budget-v2:op-no-ttl",
            &[0xd3; 32],
            10,
            1,
        )
        .await,
    );
    let ttl: i64 = store
        .raw_command("TTL", &[ExchangeStore::op_v2(&operation).as_bytes()])
        .await
        .unwrap();
    assert_eq!(ttl, -1);
    assert_eq!(
        store
            .result_ready_v2(&operation, &fence, b"no-ttl-result", &[0xd4; 32])
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    let ttl: i64 = store
        .raw_command("TTL", &[ExchangeStore::op_v2(&operation).as_bytes()])
        .await
        .unwrap();
    assert_eq!(ttl, -1);
    assert_eq!(
        store
            .commit_v2(&operation, &fence, b"no-ttl-receipt", b"no-ttl-response")
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    let ttl: i64 = store
        .raw_command("TTL", &[ExchangeStore::op_v2(&operation).as_bytes()])
        .await
        .unwrap();
    assert_eq!(ttl, -1);
}

#[tokio::test]
async fn exchange_v2_duplicate_and_overlapping_sources_have_zero_mutation() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let now = store.redis_time().await.unwrap() as i64;
    let duplicate_source = V2SourceSpend {
        spend_key: "spend:v2:duplicate".into(),
        valid_from: now - 1,
        valid_until: now + 120,
    };
    let duplicate_sources = [duplicate_source.clone(), duplicate_source];
    let duplicate_outputs = [output("v2-duplicate")];
    let duplicate_refs = [ExchangeStore::signer_ref_key_v2("duplicate")];
    let duplicate_outcome = store
        .reserve_v2(V2ReservationInput {
            operation_id: &[0xe0; 16],
            public_operation_id: &Base64UrlUnpadded::encode_string(&[0xe0; 16]),
            status_capability: &[0xe1; 32],
            request_hash: &[0xe0; 32],
            graph_id: "graph-v2",
            transition_id: "transition-v2",
            source_keyset_id: "source-keyset-v2",
            target_keyset_id: "target-keyset-v2",
            sources: &duplicate_sources,
            outputs: &duplicate_outputs,
            signer_ref_keys: &duplicate_refs,
            receipt_key_id: "receipt-v2",
            receipt_ref_key: &ExchangeStore::receipt_ref_key_v2("receipt-v2"),
            budget_id: "budget-v2-duplicate",
            budget_policy_digest: &[0xe2; 32],
            budget_limit: 10,
            receipt_lifetime_secs: 300,
            receipt_valid_from: 1,
            receipt_valid_until: freebird_common::api::EXCHANGE_MAX_VALID_UNTIL as u64,
        })
        .await;
    assert!(duplicate_outcome.is_err());
    assert!(store.get_v2(&[0xe0; 16]).await.unwrap().is_none());
    for key in [
        "spend:v2:duplicate".to_owned(),
        ExchangeStore::signer_ref_key_v2("duplicate"),
        ExchangeStore::budget_key_v2("budget-v2-duplicate"),
    ] {
        let values: Vec<Vec<u8>> = store
            .raw_command("HGETALL", &[key.as_bytes()])
            .await
            .unwrap_or_default();
        let value: Option<Vec<u8>> = store.raw_command("GET", &[key.as_bytes()]).await.unwrap();
        assert!(
            values.is_empty() && value.is_none(),
            "duplicate wrote {key}"
        );
    }

    let shared = V2SourceSpend {
        spend_key: "spend:v2:overlap".into(),
        valid_from: now - 1,
        valid_until: now + 120,
    };
    let first_sources = [shared.clone()];
    let first_outputs = [output("v2-overlap-first")];
    let first_refs = [ExchangeStore::signer_ref_key_v2("overlap-first")];
    created_v2(
        reserve_v2_with(
            &store,
            &[0xe3; 16],
            &[0xe3; 32],
            &[0xe4; 32],
            &first_sources,
            &first_outputs,
            &first_refs,
            "budget-v2-overlap",
            &[0xe5; 32],
            10,
        )
        .await,
    );
    let fresh = V2SourceSpend {
        spend_key: "spend:v2:overlap-fresh".into(),
        valid_from: now - 1,
        valid_until: now + 120,
    };
    let overlapping_sources = [shared, fresh];
    let overlapping_outputs = [output("v2-overlap-second")];
    let overlapping_refs = [ExchangeStore::signer_ref_key_v2("overlap-second")];
    assert_eq!(
        reserve_v2_with(
            &store,
            &[0xe6; 16],
            &[0xe6; 32],
            &[0xe7; 32],
            &overlapping_sources,
            &overlapping_outputs,
            &overlapping_refs,
            "budget-v2-overlap",
            &[0xe5; 32],
            10,
        )
        .await,
        V2ReserveOutcome::Spent
    );
    assert!(store.get_v2(&[0xe6; 16]).await.unwrap().is_none());
    let fresh_spend: Option<Vec<u8>> = store
        .raw_command("GET", &[b"spend:v2:overlap-fresh"])
        .await
        .unwrap();
    let second_ref: Option<Vec<u8>> = store
        .raw_command(
            "GET",
            &[ExchangeStore::signer_ref_key_v2("overlap-second").as_bytes()],
        )
        .await
        .unwrap();
    let charged: i64 = store
        .raw_command(
            "HGET",
            &[
                ExchangeStore::budget_key_v2("budget-v2-overlap").as_bytes(),
                b"charged",
            ],
        )
        .await
        .unwrap();
    let receipt_count: i64 = store
        .raw_command(
            "GET",
            &[ExchangeStore::receipt_ref_key_v2("receipt-v2").as_bytes()],
        )
        .await
        .unwrap();
    assert!(fresh_spend.is_none() && second_ref.is_none());
    assert_eq!(charged, 1, "overlap rejection must not overcharge");
    assert_eq!(
        receipt_count, 1,
        "overlap rejection must not increment receipts"
    );
}

#[tokio::test]
async fn exchange_v2_independent_budgets_policy_conflicts_exhaustion_and_no_overcharge() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let now = store.redis_time().await.unwrap() as i64;
    let source = |name: &str| V2SourceSpend {
        spend_key: format!("spend:v2:budget:{name}"),
        valid_from: now - 1,
        valid_until: now + 120,
    };
    let output = |name: &str, quantity| OutputWork {
        quantity,
        ..output(name)
    };
    let policy_a = [0xa1; 32];
    let policy_b = [0xb1; 32];
    let source_a = [source("a")];
    let output_a = [output("budget-a", 2)];
    let refs_a = [ExchangeStore::signer_ref_key_v2("budget-a")];
    created_v2(
        reserve_v2_with(
            &store,
            &[0xf0; 16],
            &[0xf0; 32],
            &[0xf1; 32],
            &source_a,
            &output_a,
            &refs_a,
            "budget-v2-a",
            &policy_a,
            3,
        )
        .await,
    );
    let source_b = [source("b")];
    let output_b = [output("budget-b", 2)];
    let refs_b = [ExchangeStore::signer_ref_key_v2("budget-b")];
    created_v2(
        reserve_v2_with(
            &store,
            &[0xf2; 16],
            &[0xf2; 32],
            &[0xf3; 32],
            &source_b,
            &output_b,
            &refs_b,
            "budget-v2-b",
            &policy_b,
            3,
        )
        .await,
    );
    let charged_a: i64 = store
        .raw_command(
            "HGET",
            &[
                ExchangeStore::budget_key_v2("budget-v2-a").as_bytes(),
                b"charged",
            ],
        )
        .await
        .unwrap();
    let charged_b: i64 = store
        .raw_command(
            "HGET",
            &[
                ExchangeStore::budget_key_v2("budget-v2-b").as_bytes(),
                b"charged",
            ],
        )
        .await
        .unwrap();
    assert_eq!((charged_a, charged_b), (2, 2));

    let conflict_source = [source("policy-conflict")];
    let conflict_output = [output("policy-conflict", 1)];
    let conflict_ref = [ExchangeStore::signer_ref_key_v2("policy-conflict")];
    assert_eq!(
        reserve_v2_with(
            &store,
            &[0xf4; 16],
            &[0xf4; 32],
            &[0xf5; 32],
            &conflict_source,
            &conflict_output,
            &conflict_ref,
            "budget-v2-a",
            &[0xa2; 32],
            3,
        )
        .await,
        V2ReserveOutcome::BudgetPolicyConflict
    );
    assert!(store.get_v2(&[0xf4; 16]).await.unwrap().is_none());
    let conflict_spend: Option<Vec<u8>> = store
        .raw_command("GET", &[b"spend:v2:budget:policy-conflict"])
        .await
        .unwrap();
    assert!(conflict_spend.is_none());

    let exhausted_source = [source("exhausted")];
    let exhausted_output = [output("exhausted", 2)];
    let exhausted_ref = [ExchangeStore::signer_ref_key_v2("exhausted")];
    assert_eq!(
        reserve_v2_with(
            &store,
            &[0xf6; 16],
            &[0xf6; 32],
            &[0xf7; 32],
            &exhausted_source,
            &exhausted_output,
            &exhausted_ref,
            "budget-v2-a",
            &policy_a,
            3,
        )
        .await,
        V2ReserveOutcome::BudgetExhausted
    );
    assert!(store.get_v2(&[0xf6; 16]).await.unwrap().is_none());
    let exhausted_spend: Option<Vec<u8>> = store
        .raw_command("GET", &[b"spend:v2:budget:exhausted"])
        .await
        .unwrap();
    let exhausted_ref_value: Option<Vec<u8>> = store
        .raw_command(
            "GET",
            &[ExchangeStore::signer_ref_key_v2("exhausted").as_bytes()],
        )
        .await
        .unwrap();
    let charged_after: i64 = store
        .raw_command(
            "HGET",
            &[
                ExchangeStore::budget_key_v2("budget-v2-a").as_bytes(),
                b"charged",
            ],
        )
        .await
        .unwrap();
    assert!(exhausted_spend.is_none() && exhausted_ref_value.is_none());
    assert_eq!(charged_after, 2, "rejected work must not overcharge");
}

#[tokio::test]
async fn exchange_v2_reserve_exact_retry_hash_and_capability_outcomes() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let operation = [0xf8; 16];
    let request_hash = [0xf9; 32];
    let capability = [0xfa; 32];
    created_v2(
        reserve_v2(
            &store,
            &operation,
            &request_hash,
            &capability,
            "spend:v2:retry-original",
            "budget-v2:retry-original",
            &[0xfb; 32],
            10,
            1,
        )
        .await,
    );
    let retry = reserve_v2(
        &store,
        &operation,
        &request_hash,
        &capability,
        "spend:v2:retry-ignored",
        "budget-v2:retry-ignored",
        &[0xfc; 32],
        10,
        1,
    )
    .await;
    let existing = match retry {
        V2ReserveOutcome::Existing(record) => record,
        other => panic!("exact V2 retry was not Existing: {other:?}"),
    };
    assert_eq!(existing.request_hash, request_hash);
    assert_eq!(existing.state, State::Reserved);
    assert_eq!(existing.outputs[0].quantity, 1);

    assert_eq!(
        reserve_v2(
            &store,
            &operation,
            &[0xfd; 32],
            &capability,
            "spend:v2:retry-changed-hash",
            "budget-v2:retry-changed-hash",
            &[0xfe; 32],
            10,
            1,
        )
        .await,
        V2ReserveOutcome::Conflict
    );
    assert_eq!(
        reserve_v2(
            &store,
            &operation,
            &request_hash,
            &[0xff; 32],
            "spend:v2:retry-changed-capability",
            "budget-v2:retry-changed-capability",
            &[0x01; 32],
            10,
            1,
        )
        .await,
        V2ReserveOutcome::CapabilityMismatch
    );
    assert!(store
        .raw_command::<Option<Vec<u8>>>("GET", &[b"spend:v2:retry-ignored"])
        .await
        .unwrap()
        .is_none());
    assert!(store
        .raw_command::<Option<Vec<u8>>>("GET", &[b"spend:v2:retry-changed-hash"])
        .await
        .unwrap()
        .is_none());
    assert!(store
        .raw_command::<Option<Vec<u8>>>("GET", &[b"spend:v2:retry-changed-capability"])
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn exchange_v2_registry_is_additive_and_detects_removal_or_conflict() {
    use super::store::{KeyRegistryEntry, KeyRegistryOutcome};

    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let first = KeyRegistryEntry {
        key_id: "1".repeat(64),
        canonical_metadata: b"first".to_vec(),
    };
    let second = KeyRegistryEntry {
        key_id: "2".repeat(64),
        canonical_metadata: b"second".to_vec(),
    };
    assert_eq!(
        store
            .initialize_key_registry_v2(std::slice::from_ref(&first))
            .await
            .unwrap(),
        KeyRegistryOutcome::Initialized
    );
    assert_eq!(
        store
            .initialize_key_registry_v2(&[first.clone(), second.clone()])
            .await
            .unwrap(),
        KeyRegistryOutcome::Initialized
    );
    assert_eq!(
        store
            .initialize_key_registry_v2(std::slice::from_ref(&second))
            .await
            .unwrap(),
        KeyRegistryOutcome::Missing
    );
    let mut conflict = first.clone();
    conflict.canonical_metadata = b"changed".to_vec();
    assert_eq!(
        store
            .initialize_key_registry_v2(&[conflict, second])
            .await
            .unwrap(),
        KeyRegistryOutcome::Conflict
    );
}

#[tokio::test]
async fn exchange_v2_accepting_requires_prior_durable_disabled_publication() {
    let Some(mut h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let transition = "a".repeat(64);
    assert!(store
        .validate_publication_admission_v2(std::slice::from_ref(&transition))
        .await
        .is_err());
    let marker_key = format!("freebird:exchange:v2:publication:disabled:{transition}");
    let marker_exists: i64 = store
        .raw_command("EXISTS", &[marker_key.as_bytes()])
        .await
        .unwrap();
    assert_eq!(
        marker_exists, 0,
        "failed startup validation must not leave an acknowledgement"
    );
    store
        .acknowledge_disabled_publication_v2(std::slice::from_ref(&transition))
        .await
        .unwrap();
    h.restart().unwrap();
    let restarted = ExchangeStore::new(&h.url).unwrap();
    let mut last_loading_error = None;
    for _ in 0..250 {
        match restarted
            .validate_publication_admission_v2(std::slice::from_ref(&transition))
            .await
        {
            Ok(()) => return,
            Err(error) if error.to_string().contains("loading the dataset") => {
                last_loading_error = Some(error);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Err(error) => panic!("durable publication acknowledgement was not restored: {error:#}"),
        }
    }
    panic!(
        "Redis did not finish loading durable publication acknowledgement: {:#}",
        last_loading_error.unwrap()
    );
}

async fn force_lease_v2(store: &ExchangeStore, id: &[u8; 16], lease: u64) {
    let key = ExchangeStore::op_v2(id);
    let lease = lease.to_string();
    let _: i64 = store
        .raw_command("HSET", &[key.as_bytes(), b"lease_until", lease.as_bytes()])
        .await
        .unwrap();
}

async fn seed_v2_pending(
    engine: &super::ExchangeEngine,
    store: &ExchangeStore,
    request: &ExchangeRequestV2,
    capability: &[u8; 32],
) -> Vec<u8> {
    let operation =
        freebird_common::exchange_api::parse_operation_id(&request.public_operation_id).unwrap();
    let fresh = engine.validate_fresh_v2(request).unwrap();
    let receipt_key_id = engine.receipt_keys.active_id().to_owned();
    let (receipt_valid_from, receipt_valid_until) = engine.receipt_keys.active_validity().unwrap();
    let receipt_ref = ExchangeStore::receipt_ref_key_v2(&receipt_key_id);
    let outcome = store
        .reserve_v2(V2ReservationInput {
            operation_id: &operation,
            public_operation_id: &request.public_operation_id,
            status_capability: capability,
            request_hash: &request.request_digest().unwrap(),
            graph_id: &request.graph_id,
            transition_id: &request.transition_id,
            source_keyset_id: &request.source_keyset_id,
            target_keyset_id: &request.target_keyset_id,
            sources: &fresh.sources,
            outputs: &fresh.outputs,
            signer_ref_keys: &fresh.signer_refs,
            receipt_key_id: &receipt_key_id,
            receipt_ref_key: &receipt_ref,
            budget_id: &fresh.budget_id,
            budget_policy_digest: &fresh.budget_policy_digest,
            budget_limit: fresh.budget_limit,
            receipt_lifetime_secs: engine.receipt_lifetime_secs,
            receipt_valid_from,
            receipt_valid_until,
        })
        .await
        .unwrap();
    created_v2(outcome)
}

fn canonical_result_v2(request: &ExchangeRequestV2) -> (Vec<u8>, [u8; 32]) {
    let mut result = ExchangeResultV2 {
        version: EXCHANGE_VERSION_V2,
        public_operation_id: request.public_operation_id.clone(),
        graph_id: request.graph_id.clone(),
        transition_id: request.transition_id.clone(),
        source_keyset_id: request.source_keyset_id.clone(),
        target_keyset_id: request.target_keyset_id.clone(),
        outputs: request
            .outputs
            .iter()
            .map(|output| ExchangeResultOutput {
                slot: output.slot.clone(),
                blinded_value: output.blinded_value.clone(),
                blind_signature: Base64UrlUnpadded::encode_string(&[1; 256]),
            })
            .collect(),
        result_digest: String::new(),
    };
    let digest = result.result_digest().unwrap();
    result.result_digest = Base64UrlUnpadded::encode_string(&digest);
    (serde_json::to_vec(&result).unwrap(), digest)
}

async fn exchange_test_panic() -> axum::http::StatusCode {
    panic!("sensitive test panic")
}

#[tokio::test]
async fn exchange_v2_engine_bidirectional_exact_status_and_secret_non_persistence() {
    let Some(h) = harness() else { return };
    let issuer_id = "issuer:v2:bidirectional";
    let fixture = v2_engine_fixture(issuer_id).await;
    let store = ExchangeStore::new(&h.url).unwrap();
    let engine = super::ExchangeEngine::new_v2(
        fixture.graph.clone(),
        vec![],
        store.clone(),
        issuer_id.into(),
        v2_receipt_ring(&fixture.receipt_path, &[]),
        300,
    )
    .await
    .unwrap();
    let capability_ab = [0x31; 32];
    let capability_ba = [0x32; 32];
    let response_ab = match engine
        .process_or_recover_v2(&fixture.request_ab, &capability_ab)
        .await
        .unwrap()
    {
        super::ProcessDecision::Committed(response) => response,
        decision => panic!("A to B did not commit: {decision:?}"),
    };
    assert!(matches!(
        engine
            .process_or_recover_v2(&fixture.request_ba, &capability_ba)
            .await
            .unwrap(),
        super::ProcessDecision::Committed(_)
    ));
    assert_eq!(
        engine
            .process_or_recover_v2(&fixture.request_ab, &capability_ab)
            .await
            .unwrap(),
        super::ProcessDecision::Committed(response_ab.clone())
    );
    let operation_ab =
        freebird_common::exchange_api::parse_operation_id(&fixture.request_ab.public_operation_id)
            .unwrap();
    assert_eq!(
        engine
            .status_v2(&operation_ab, &capability_ab)
            .await
            .unwrap(),
        super::StatusDecision::Committed(response_ab.clone())
    );
    assert_eq!(
        engine.status_v2(&operation_ab, &[0x99; 32]).await.unwrap(),
        super::StatusDecision::Unauthorized
    );
    assert_eq!(
        engine
            .process_or_recover_v2(&fixture.request_ab, &[0x99; 32])
            .await
            .unwrap(),
        super::ProcessDecision::Conflict
    );
    let mut unauthorized_edge = fixture.request_ab.clone();
    unauthorized_edge.public_operation_id = Base64UrlUnpadded::encode_string(&[0xcc; 16]);
    unauthorized_edge.transition_id = "f".repeat(64);
    assert_eq!(
        engine
            .process_or_recover_v2(&unauthorized_edge, &[0x33; 32])
            .await
            .unwrap(),
        super::ProcessDecision::Rejected
    );

    let response: serde_json::Value = serde_json::from_slice(&response_ab).unwrap();
    assert!(response.get("status_capability").is_none());
    assert!(response["result"].get("status_capability").is_none());
    assert!(response["receipt"].get("status_capability").is_none());
    for (request, capability) in [
        (&fixture.request_ab, &capability_ab),
        (&fixture.request_ba, &capability_ba),
    ] {
        let operation =
            freebird_common::exchange_api::parse_operation_id(&request.public_operation_id)
                .unwrap();
        let values: Vec<Vec<u8>> = store
            .raw_command("HVALS", &[ExchangeStore::op_v2(&operation).as_bytes()])
            .await
            .unwrap();
        let fields: Vec<Vec<u8>> = store
            .raw_command("HKEYS", &[ExchangeStore::op_v2(&operation).as_bytes()])
            .await
            .unwrap();
        let raw_source = Base64UrlUnpadded::decode_vec(&request.sources[0].artifact).unwrap();
        let encoded_capability = Base64UrlUnpadded::encode_string(capability);
        assert!(!fields.iter().any(|field| {
            field == b"status_capability" || field == b"source_artifact" || field == b"artifact"
        }));
        assert!(!values.iter().any(|value| {
            value
                .windows(raw_source.len())
                .any(|window| window == raw_source)
                || value
                    .windows(capability.len())
                    .any(|window| window == capability.as_slice())
                || value
                    .windows(encoded_capability.len())
                    .any(|window| window == encoded_capability.as_bytes())
        }));
    }
}

#[tokio::test]
async fn exchange_v2_source_expiry_uses_global_key_longest_validity() {
    let Some(h) = harness() else { return };
    let issuer_id = "issuer:v2:global-expiry";
    let fixture = v2_engine_fixture(issuer_id).await;
    let source = &fixture.graph.keysets[0].keys[0].descriptor;
    let longest = source.valid_until + 600;
    let mut validity = fixture
        .graph
        .keysets
        .iter()
        .flat_map(|keyset| &keyset.keys)
        .map(|key| (key.descriptor.kid.clone(), key.descriptor.valid_until))
        .collect::<std::collections::BTreeMap<_, _>>();
    validity.insert(source.kid.clone(), longest);
    let engine = super::ExchangeEngine::new_v2_with_source_validity(
        fixture.graph.clone(),
        vec![],
        ExchangeStore::new(&h.url).unwrap(),
        issuer_id.into(),
        v2_receipt_ring(&fixture.receipt_path, &[]),
        300,
        validity,
    )
    .await
    .unwrap();
    let work = engine.validate_fresh_v2(&fixture.request_ab).unwrap();
    assert_eq!(work.sources[0].valid_until, longest);
}

#[tokio::test]
async fn exchange_v2_recovery_only_finishes_pending_and_disabled_rejects() {
    let Some(h) = harness() else { return };
    let issuer_id = "issuer:v2:recovery";
    let fixture = v2_engine_fixture(issuer_id).await;
    let store = ExchangeStore::new(&h.url).unwrap();
    let accepting = super::ExchangeEngine::new_v2(
        fixture.graph.clone(),
        vec![],
        store.clone(),
        issuer_id.into(),
        v2_receipt_ring(&fixture.receipt_path, &[]),
        300,
    )
    .await
    .unwrap();
    let capability_ab = [0x41; 32];
    seed_v2_pending(&accepting, &store, &fixture.request_ab, &capability_ab).await;
    let capability_ba = [0x42; 32];
    seed_v2_pending(&accepting, &store, &fixture.request_ba, &capability_ba).await;
    let operation_ab =
        freebird_common::exchange_api::parse_operation_id(&fixture.request_ab.public_operation_id)
            .unwrap();
    assert_eq!(
        accepting
            .status_v2(&operation_ab, &capability_ab)
            .await
            .unwrap(),
        super::StatusDecision::Pending
    );
    assert_eq!(
        accepting
            .process_or_recover_v2(&fixture.request_ab, &capability_ab)
            .await
            .unwrap(),
        super::ProcessDecision::Retryable
    );
    force_lease_v2(&store, &operation_ab, 0).await;
    let operation_ba =
        freebird_common::exchange_api::parse_operation_id(&fixture.request_ba.public_operation_id)
            .unwrap();
    force_lease_v2(&store, &operation_ba, 0).await;
    let mut recovery_graph = fixture.graph.clone();
    recovery_graph.transitions[0].admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
    let recovery = super::ExchangeEngine::new_v2(
        recovery_graph,
        vec![],
        store.clone(),
        issuer_id.into(),
        v2_receipt_ring(&fixture.receipt_path, &[]),
        300,
    )
    .await
    .unwrap();
    assert!(matches!(
        recovery
            .process_or_recover_v2(&fixture.request_ab, &capability_ab)
            .await
            .unwrap(),
        super::ProcessDecision::Committed(_)
    ));

    let mut disabled_graph = fixture.graph.clone();
    disabled_graph.transitions[1].admission_state = ExchangeAdmissionStateV2::Disabled;
    let disabled = super::ExchangeEngine::new_v2(
        disabled_graph,
        vec![],
        store,
        issuer_id.into(),
        v2_receipt_ring(&fixture.receipt_path, &[]),
        300,
    )
    .await
    .unwrap();
    assert_eq!(
        disabled
            .process_or_recover_v2(&fixture.request_ba, &capability_ba)
            .await
            .unwrap(),
        super::ProcessDecision::Rejected
    );
    let mut fresh_disabled = fixture.request_ba.clone();
    fresh_disabled.public_operation_id = Base64UrlUnpadded::encode_string(&[0xb2; 16]);
    assert_eq!(
        disabled
            .process_or_recover_v2(&fresh_disabled, &[0x43; 32])
            .await
            .unwrap(),
        super::ProcessDecision::Rejected
    );
}

#[tokio::test]
async fn exchange_v2_private_signers_may_retire_only_after_disabled_work_is_drained() {
    let Some(h) = harness() else { return };
    let issuer_id = "issuer:v2:retirement";
    let fixture = v2_engine_fixture(issuer_id).await;
    let store = ExchangeStore::new(&h.url).unwrap();
    let accepting = super::ExchangeEngine::new_v2(
        fixture.graph.clone(),
        vec![],
        store.clone(),
        issuer_id.into(),
        v2_receipt_ring(&fixture.receipt_path, &[]),
        300,
    )
    .await
    .unwrap();
    let capability = [0xe1; 32];
    seed_v2_pending(&accepting, &store, &fixture.request_ab, &capability).await;

    let mut retired = fixture.graph.clone();
    for transition in &mut retired.transitions {
        transition.admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
    }
    for key in retired
        .keysets
        .iter_mut()
        .flat_map(|keyset| &mut keyset.keys)
    {
        key.private_key_path = None;
    }
    assert!(super::ExchangeEngine::new_v2(
        retired.clone(),
        vec![],
        store.clone(),
        issuer_id.into(),
        v2_receipt_ring(&fixture.receipt_path, &[]),
        300,
    )
    .await
    .is_err());

    let operation =
        freebird_common::exchange_api::parse_operation_id(&fixture.request_ab.public_operation_id)
            .unwrap();
    force_lease_v2(&store, &operation, 0).await;
    assert!(matches!(
        accepting
            .process_or_recover_v2(&fixture.request_ab, &capability)
            .await
            .unwrap(),
        super::ProcessDecision::Committed(_)
    ));
    for transition in &mut retired.transitions {
        transition.admission_state = ExchangeAdmissionStateV2::Disabled;
    }
    super::ExchangeEngine::new_v2(
        retired,
        vec![],
        store,
        issuer_id.into(),
        v2_receipt_ring(&fixture.receipt_path, &[]),
        300,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn exchange_v2_recovery_rejects_tampered_persisted_result_binding() {
    let Some(h) = harness() else { return };
    let issuer_id = "issuer:v2:tamper";
    let fixture = v2_engine_fixture(issuer_id).await;
    let store = ExchangeStore::new(&h.url).unwrap();
    let engine = super::ExchangeEngine::new_v2(
        fixture.graph.clone(),
        vec![],
        store.clone(),
        issuer_id.into(),
        v2_receipt_ring(&fixture.receipt_path, &[]),
        300,
    )
    .await
    .unwrap();
    let capability = [0x51; 32];
    let fence = seed_v2_pending(&engine, &store, &fixture.request_ab, &capability).await;
    let operation =
        freebird_common::exchange_api::parse_operation_id(&fixture.request_ab.public_operation_id)
            .unwrap();
    let mut result = ExchangeResultV2 {
        version: EXCHANGE_VERSION_V2,
        public_operation_id: fixture.request_ab.public_operation_id.clone(),
        graph_id: "f".repeat(64),
        transition_id: fixture.request_ab.transition_id.clone(),
        source_keyset_id: fixture.request_ab.source_keyset_id.clone(),
        target_keyset_id: fixture.request_ab.target_keyset_id.clone(),
        outputs: vec![ExchangeResultOutput {
            slot: fixture.request_ab.outputs[0].slot.clone(),
            blinded_value: fixture.request_ab.outputs[0].blinded_value.clone(),
            blind_signature: Base64UrlUnpadded::encode_string(&[1; 256]),
        }],
        result_digest: String::new(),
    };
    let digest = result.result_digest().unwrap();
    result.result_digest = Base64UrlUnpadded::encode_string(&digest);
    store
        .result_ready_v2(
            &operation,
            &fence,
            &serde_json::to_vec(&result).unwrap(),
            &digest,
        )
        .await
        .unwrap();
    force_lease_v2(&store, &operation, 0).await;
    assert!(engine
        .process_or_recover_v2(&fixture.request_ab, &capability)
        .await
        .is_err());
}

#[tokio::test]
async fn exchange_v2_http_pending_retry_conflict_status_and_exact_replay() {
    let Some(h) = harness() else { return };
    let issuer_id = "issuer:v2:http";
    let fixture = v2_engine_fixture(issuer_id).await;
    let store = ExchangeStore::new(&h.url).unwrap();
    let engine = super::ExchangeEngine::new_v2(
        fixture.graph.clone(),
        vec![],
        store.clone(),
        issuer_id.into(),
        v2_receipt_ring(&fixture.receipt_path, &[]),
        300,
    )
    .await
    .unwrap();
    let pending_capability = [0x61; 32];
    seed_v2_pending(&engine, &store, &fixture.request_ba, &pending_capability).await;
    let engine = Arc::new(engine);
    let voprf = Arc::new(
        crate::multi_key_voprf::MultiKeyVoprfCore::new(
            [7; 32],
            "public".into(),
            "kid".into(),
            freebird_crypto::VOPRF_CONTEXT_V4,
        )
        .unwrap(),
    );
    let state = Arc::new(crate::AppStateWithSybil {
        issuer_id: issuer_id.into(),
        kid: "kid".into(),
        pubkey_b64: "public".into(),
        require_tls: false,
        behind_proxy: false,
        sybil_checker: None,
        invitation_system: None,
        public_issuer: None,
        exchange_engine: Some(engine),
        exchange_metadata: None,
        graph_issuance_engine: None,
        graph_issuance_metadata: None,
        epoch_duration_sec: 86_400,
        epoch_retention: 2,
        admin_api_key: None,
    });
    let app = crate::startup::apply_public_layers(
        crate::startup::exchange_router(3 * 1024 * 1024, 30).with_state((state, voprf)),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    let client = reqwest::Client::new();
    let exchange_url = format!("http://{address}/v2/public/exchange");
    let status_url = format!(
        "http://{address}/v2/public/exchange/status?public_operation_id={}",
        fixture.request_ab.public_operation_id
    );
    let header = "exchange-status-capability";
    let pending = client
        .post(&exchange_url)
        .header(
            header,
            Base64UrlUnpadded::encode_string(&pending_capability),
        )
        .json(&fixture.request_ba)
        .send()
        .await
        .unwrap();
    assert_eq!(pending.status(), reqwest::StatusCode::ACCEPTED);
    assert_eq!(pending.headers()["retry-after"], "1");

    let capability = [0x62; 32];
    let encoded_capability = Base64UrlUnpadded::encode_string(&capability);
    let request_body = serde_json::to_vec(&fixture.request_ab).unwrap();
    let committed = client
        .post(&exchange_url)
        .header(header, &encoded_capability)
        .header("content-type", "application/json")
        .body(request_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(committed.status(), reqwest::StatusCode::OK);
    let exact = committed.bytes().await.unwrap();
    let replay = client
        .post(&exchange_url)
        .header(header, &encoded_capability)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), reqwest::StatusCode::OK);
    assert_eq!(replay.bytes().await.unwrap(), exact);
    let status = client
        .get(&status_url)
        .header(header, &encoded_capability)
        .send()
        .await
        .unwrap();
    assert_eq!(status.status(), reqwest::StatusCode::OK);
    assert_eq!(status.bytes().await.unwrap(), exact);
    let unauthorized = client
        .get(&status_url)
        .header(header, Base64UrlUnpadded::encode_string(&[0x63; 32]))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), reqwest::StatusCode::FORBIDDEN);
    let conflict = client
        .post(&exchange_url)
        .header(header, Base64UrlUnpadded::encode_string(&[0x63; 32]))
        .json(&fixture.request_ab)
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), reqwest::StatusCode::CONFLICT);
    server.abort();
}

#[tokio::test]
async fn exchange_http_post_status_conflict_duplicate_and_no_store() {
    let Some(h) = harness() else { return };
    let fixture = v2_engine_fixture("issuer:http:e2e").await;
    let store = ExchangeStore::new(&h.url).unwrap();
    let receipt_keys = v2_receipt_ring(&fixture.receipt_path, &[]);
    let receipt_metadata = receipt_keys.discovery_metadata();
    let exchange_metadata =
        crate::startup::exchange_discovery_v2(&fixture.graph, &[], &receipt_metadata).unwrap();
    let engine = super::ExchangeEngine::new_v2(
        fixture.graph.clone(),
        vec![],
        store.clone(),
        "issuer:http:e2e".into(),
        receipt_keys,
        300,
    )
    .await
    .unwrap();
    let pending_capability = [0x56; 32];
    seed_v2_pending(&engine, &store, &fixture.request_ba, &pending_capability).await;
    let engine = Arc::new(engine);
    let voprf = Arc::new(
        crate::multi_key_voprf::MultiKeyVoprfCore::new(
            [7; 32],
            "public".into(),
            "kid".into(),
            freebird_crypto::VOPRF_CONTEXT_V4,
        )
        .unwrap(),
    );
    let state = Arc::new(crate::AppStateWithSybil {
        issuer_id: "issuer:http:e2e".into(),
        kid: "kid".into(),
        pubkey_b64: "public".into(),
        require_tls: false,
        behind_proxy: false,
        sybil_checker: None,
        invitation_system: None,
        public_issuer: None,
        exchange_engine: Some(engine),
        exchange_metadata: Some(exchange_metadata),
        graph_issuance_engine: None,
        graph_issuance_metadata: None,
        epoch_duration_sec: 86_400,
        epoch_retention: 2,
        admin_api_key: None,
    });
    let app = axum::Router::new()
        .route(
            "/exchange-test-panic",
            axum::routing::get(exchange_test_panic),
        )
        .route(
            "/.well-known/issuer",
            axum::routing::get(crate::routes::metadata::well_known_handler),
        )
        .route(
            "/.well-known/keys",
            axum::routing::get(crate::routes::metadata::keys_handler),
        )
        .merge(crate::startup::exchange_router(3 * 1024 * 1024, 30))
        .with_state((state, voprf));
    let app = crate::startup::apply_public_layers(app).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    let client = reqwest::Client::new();
    let exchange_url = format!("http://{address}/v2/public/exchange");
    let status_url = format!(
        "http://{address}/v2/public/exchange/status?public_operation_id={}",
        fixture.request_ab.public_operation_id
    );
    let operation = Base64UrlUnpadded::encode_string(&[0x53; 32]);
    let request_body = serde_json::to_vec(&fixture.request_ab).unwrap();
    let legacy_path = client
        .post(format!("http://{address}/v1/public/exchange"))
        .header("exchange-status-capability", &operation)
        .body(request_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(legacy_path.status(), reqwest::StatusCode::NOT_FOUND);
    let pending = client
        .post(&exchange_url)
        .header(
            "exchange-status-capability",
            Base64UrlUnpadded::encode_string(&pending_capability),
        )
        .json(&fixture.request_ba)
        .send()
        .await
        .unwrap();
    assert_eq!(pending.status(), reqwest::StatusCode::ACCEPTED);
    assert_eq!(pending.headers()["retry-after"], "1");
    assert_eq!(pending.headers()["cache-control"], "no-store");
    let response = client
        .post(&exchange_url)
        .header("content-type", "application/json")
        .header("exchange-status-capability", &operation)
        .body(request_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let committed = response.bytes().await.unwrap();
    let response = client
        .get(&status_url)
        .header("exchange-status-capability", &operation)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.bytes().await.unwrap(), committed);
    let retry_one = client
        .post(&exchange_url)
        .header("exchange-status-capability", &operation)
        .json(&fixture.request_ab)
        .send();
    let retry_two = client
        .post(&exchange_url)
        .header("exchange-status-capability", &operation)
        .json(&fixture.request_ab)
        .send();
    let (retry_one, retry_two) = tokio::join!(retry_one, retry_two);
    for retry in [retry_one.unwrap(), retry_two.unwrap()] {
        assert_eq!(retry.status(), reqwest::StatusCode::OK);
        assert_eq!(retry.bytes().await.unwrap(), committed);
    }
    let mut changed = fixture.request_ab.clone();
    changed.sources[0].artifact = fixture.request_ba.sources[0].artifact.clone();
    let response = client
        .post(&exchange_url)
        .header("content-type", "application/json")
        .header("exchange-status-capability", &operation)
        .body(serde_json::to_vec(&changed).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    let mut duplicate_headers = reqwest::header::HeaderMap::new();
    duplicate_headers.append("exchange-status-capability", operation.parse().unwrap());
    duplicate_headers.append("exchange-status-capability", operation.parse().unwrap());
    let response = client
        .post(&exchange_url)
        .header("content-type", "application/json")
        .headers(duplicate_headers)
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let oversized = client
        .post(&exchange_url)
        .header(
            "exchange-status-capability",
            Base64UrlUnpadded::encode_string(&[0x57; 32]),
        )
        .header("content-type", "application/json")
        .body(vec![b'x'; 3 * 1024 * 1024 + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(oversized.headers()["cache-control"], "no-store");
    let unknown = client
        .get(format!(
            "http://{address}/v2/public/exchange/status?public_operation_id={}",
            Base64UrlUnpadded::encode_string(&[0x7f; 16])
        ))
        .header(
            "exchange-status-capability",
            Base64UrlUnpadded::encode_string(&[0x7f; 32]),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(unknown.headers()["cache-control"], "no-store");
    let discovery = client
        .get(format!("http://{address}/.well-known/keys"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(discovery["public"], serde_json::json!([]));
    assert_eq!(
        discovery["exchange"]["active_receipt_key"]["purpose"],
        "exchange_receipt_active"
    );
    let public_key = discovery["exchange"]["active_receipt_key"]["public_key_b64"]
        .as_str()
        .unwrap();
    assert_eq!(Base64UrlUnpadded::decode_vec(public_key).unwrap().len(), 32);
    let panic_response = client
        .get(format!("http://{address}/exchange-test-panic"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        panic_response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(panic_response.headers()["cache-control"], "no-store");
    assert_eq!(
        panic_response.json::<serde_json::Value>().await.unwrap()["error"],
        "internal_error"
    );
    server.abort();
}

#[tokio::test]
async fn exchange_redis_durability_configuration_is_enforced() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    store.validate_durable_standalone().await.unwrap();
    let _: String = store
        .raw_command("CONFIG", &[b"SET", b"appendfsync", b"everysec"])
        .await
        .unwrap();
    assert!(store.validate_durable_standalone().await.is_err());
}

#[test]
fn exchange_redis_readiness_rejects_replica_and_bad_aof_health() {
    let server = "redis_mode:standalone\r\n";
    let healthy = "aof_enabled:1\r\naof_last_write_status:ok\r\n";
    assert!(super::store::validate_redis_info(server, "role:master\r\n", healthy).is_ok());
    assert!(super::store::validate_redis_info(server, "role:slave\r\n", healthy).is_err());
    assert!(super::store::validate_redis_info(
        server,
        "role:master\r\n",
        "aof_enabled:1\r\naof_last_write_status:err\r\n"
    )
    .is_err());
    assert!(
        super::store::validate_redis_info(server, "role:master\r\n", "aof_enabled:1\r\n").is_err()
    );
    assert!(super::store::validate_redis_info(
        "redis_mode:cluster\r\n",
        "role:master\r\n",
        healthy
    )
    .is_err());
}
