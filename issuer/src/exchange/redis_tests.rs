// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Redis atomicity, fencing, recovery, and AOF acceptance matrix.

use super::{
    load_or_generate_receipt_key,
    profiles::{
        ExchangeDescriptor, ExchangeKeyset, ExchangeProfile, ExchangeRule, ExchangeRuleSlot,
        ExchangeSourceAllowlist, ExchangeTargetKey,
    },
    redis_harness::RedisHarness,
    store::{
        capacity_key, receipt_ref_key, target_ref_key, CapacityEntry, ClaimOutcome, ExchangeStore,
        OutputWork, ReservationInput, ReserveOutcome, SourceWork, State, TransitionOutcome,
    },
};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::exchange_api::{
    keyset_id, rule_id, ExchangeOutput, ExchangeRequest, ExchangeResult, ExchangeResultOutput,
    ExchangeSlot, ExchangeSource, EXCHANGE_PROFILE_V1,
};
use freebird_common::spend_key::v5_spend_key;
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

struct E2eFixture {
    _dir: tempfile::TempDir,
    profile: ExchangeProfile,
    request: ExchangeRequest,
    alternate_artifact: String,
    receipt_path: std::path::PathBuf,
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

async fn e2e_fixture(issuer_id: &str, output_count: usize) -> E2eFixture {
    let dir = tempfile::tempdir().unwrap();
    let source_provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
    let target_provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
    let target_path = dir.path().join("target.der");
    std::fs::write(&target_path, target_provider.to_der().unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let descriptor =
        |role: &str, class: &str, provider: &SoftwareBlindRsaProvider| -> ExchangeDescriptor {
            let mut descriptor = ExchangeDescriptor {
                id: String::new(),
                profile_id: EXCHANGE_PROFILE_V1.into(),
                role: role.into(),
                class: class.into(),
                issuer_id: issuer_id.into(),
                kid: hex::encode(provider.token_key_id()),
                audience: None,
                spki_b64: Base64UrlUnpadded::encode_string(provider.public_key_spki()),
                suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
                max_quantity: u32::try_from(output_count.max(1)).unwrap(),
                valid_from: now - 60,
                valid_until: now + 3600,
            };
            descriptor.id = descriptor.canonical_id().unwrap();
            descriptor
        };
    let source = descriptor("source", "source", &source_provider);
    let target = descriptor("target", "target", &target_provider);
    let target_keyset_id = keyset_id(std::slice::from_ref(&target.id));
    let source_rule = ExchangeRuleSlot {
        descriptor_id: source.id.clone(),
        slot_id: "in".into(),
        class: "source".into(),
        quantity: 1,
    };
    let output_rules = (0..output_count)
        .map(|index| ExchangeRuleSlot {
            descriptor_id: target.id.clone(),
            slot_id: format!("out-{index}"),
            class: "target".into(),
            quantity: 1,
        })
        .collect::<Vec<_>>();
    let mut canonical_rule = Vec::new();
    for rule_slot in std::iter::once(&source_rule).chain(&output_rules) {
        for value in [
            rule_slot.descriptor_id.as_bytes(),
            rule_slot.slot_id.as_bytes(),
            rule_slot.class.as_bytes(),
        ] {
            canonical_rule.extend_from_slice(&(value.len() as u32).to_be_bytes());
            canonical_rule.extend_from_slice(value);
        }
        canonical_rule.extend_from_slice(&rule_slot.quantity.to_be_bytes());
    }
    let rule = ExchangeRule {
        id: rule_id(&canonical_rule),
        sources: vec![source_rule],
        outputs: output_rules,
    };
    let mut representative = vec![0u8; usize::from(target_provider.modulus_bits()) / 8];
    *representative.last_mut().unwrap() = 1;
    let artifact = issue_source_artifact(&source_provider, issuer_id, [0x41; 32]).await;
    let alternate_artifact = issue_source_artifact(&source_provider, issuer_id, [0x42; 32]).await;
    let request = ExchangeRequest {
        profile: EXCHANGE_PROFILE_V1.into(),
        rule_id: rule.id.clone(),
        sources: vec![ExchangeSource {
            slot: ExchangeSlot {
                descriptor_id: source.id.clone(),
                keyset_id: source.kid.clone(),
                slot_id: "in".into(),
                quantity: 1,
            },
            artifact,
        }],
        outputs: (0..output_count)
            .map(|index| ExchangeOutput {
                slot: ExchangeSlot {
                    descriptor_id: target.id.clone(),
                    keyset_id: target_keyset_id.clone(),
                    slot_id: format!("out-{index}"),
                    quantity: 1,
                },
                blinded_value: Base64UrlUnpadded::encode_string(&representative),
            })
            .collect(),
    };
    let profile = ExchangeProfile {
        profile_id: EXCHANGE_PROFILE_V1.into(),
        sources: ExchangeSourceAllowlist {
            descriptors: vec![source],
        },
        target_keyset: ExchangeKeyset {
            id: target_keyset_id,
            targets: vec![ExchangeTargetKey {
                descriptor: target,
                private_key_path: target_path.display().to_string(),
            }],
        },
        rules: vec![rule],
    };
    profile.validate(None).unwrap();
    let receipt_path = dir.path().join("receipt.key");
    E2eFixture {
        _dir: dir,
        profile,
        request,
        alternate_artifact,
        receipt_path,
    }
}

async fn reserve(
    store: &ExchangeStore,
    id: &[u8; 16],
    hash: &[u8; 32],
    source_key: &str,
    target_id: &str,
    capacities: &[CapacityEntry],
) -> ReserveOutcome {
    let now = store.redis_time().await.unwrap() as i64;
    let sources = vec![SourceWork {
        descriptor_id: "source-descriptor".into(),
        spend_key: source_key.into(),
        valid_from: now - 2,
        valid_until: now + 120,
    }];
    let outputs = vec![output(target_id)];
    let target_refs = vec![target_ref_key(target_id, now - 2, now + 120)];
    let receipt_ref = receipt_ref_key("receipt-key");
    store
        .reserve(ReservationInput {
            operation_id: id,
            request_hash: hash,
            profile_id: "profile",
            rule_id: "rule",
            target_keyset_id: &"k".repeat(64),
            receipt_key_id: "receipt-key",
            sources: &sources,
            outputs: &outputs,
            target_refs: &target_refs,
            receipt_ref_key: &receipt_ref,
            capacities,
            receipt_lifetime_secs: 300,
        })
        .await
        .unwrap()
}

fn created(outcome: ReserveOutcome) -> Vec<u8> {
    match outcome {
        ReserveOutcome::Created(reservation) => reservation.fence,
        other => panic!("expected created, got {other:?}"),
    }
}

async fn force_lease(store: &ExchangeStore, id: &[u8; 16], lease: u64) {
    let key = ExchangeStore::op(id);
    let lease = lease.to_string();
    let _: i64 = store
        .raw_command("HSET", &[key.as_bytes(), b"lease_until", lease.as_bytes()])
        .await
        .unwrap();
}

async fn exchange_test_panic() -> axum::http::StatusCode {
    panic!("sensitive test panic")
}

#[tokio::test]
async fn exchange_engine_fresh_valid_request_commits_and_spends_embedded_artifact() {
    let Some(h) = harness() else { return };
    let fixture = e2e_fixture("issuer:e2e:fresh", 1).await;
    let store = ExchangeStore::new(&h.url).unwrap();
    let embedded = freebird_common::exchange_api::decode_base64url(
        &fixture.request.sources[0].artifact,
        freebird_common::exchange_api::MAX_ARTIFACT,
    )
    .unwrap();
    let embedded_spend = super::source_v5::validate_source_v5(
        &fixture.profile,
        &fixture.request.sources[0].slot.descriptor_id,
        &embedded,
        "issuer:e2e:fresh",
    )
    .unwrap()
    .spend_key;
    let alternate = freebird_common::exchange_api::decode_base64url(
        &fixture.alternate_artifact,
        freebird_common::exchange_api::MAX_ARTIFACT,
    )
    .unwrap();
    let alternate_spend = super::source_v5::validate_source_v5(
        &fixture.profile,
        &fixture.request.sources[0].slot.descriptor_id,
        &alternate,
        "issuer:e2e:fresh",
    )
    .unwrap()
    .spend_key;
    let engine = super::ExchangeEngine::new(
        fixture.profile.clone(),
        vec![],
        store.clone(),
        "issuer:e2e:fresh".into(),
        super::ReceiptKeyRing::load(&fixture.receipt_path, &[]).unwrap(),
        300,
    )
    .await
    .unwrap();
    let operation = [0x51; 16];
    let response = match engine
        .process_or_recover(&operation, &fixture.request)
        .await
        .unwrap()
    {
        super::ProcessDecision::Committed(response) => response,
        decision => panic!("fresh exchange did not commit: {decision:?}"),
    };
    let record = store.get(&operation).await.unwrap().unwrap();
    assert_eq!(record.state, State::Committed);
    assert_eq!(record.response.as_deref(), Some(response.as_slice()));
    assert_eq!(record.sources[0].spend_key, embedded_spend);
    let embedded_value: Option<Vec<u8>> = store
        .raw_command("GET", &[embedded_spend.as_bytes()])
        .await
        .unwrap();
    let alternate_value: Option<Vec<u8>> = store
        .raw_command("GET", &[alternate_spend.as_bytes()])
        .await
        .unwrap();
    assert!(embedded_value.is_some());
    assert!(alternate_value.is_none());
    let mut changed = fixture.request.clone();
    changed.sources[0].artifact = fixture.alternate_artifact;
    assert_eq!(
        engine
            .process_or_recover(&operation, &changed)
            .await
            .unwrap(),
        super::ProcessDecision::Conflict
    );
    let exact = engine
        .process_or_recover(&operation, &fixture.request)
        .await
        .unwrap();
    assert_eq!(exact, super::ProcessDecision::Committed(response));
}

#[tokio::test]
async fn exchange_engine_malformed_later_output_leaves_no_reservation_or_spend() {
    let Some(h) = harness() else { return };
    let mut fixture = e2e_fixture("issuer:e2e:malformed-output", 2).await;
    fixture.request.outputs[1].blinded_value = Base64UrlUnpadded::encode_string(&vec![0; 256]);
    let source = freebird_common::exchange_api::decode_base64url(
        &fixture.request.sources[0].artifact,
        freebird_common::exchange_api::MAX_ARTIFACT,
    )
    .unwrap();
    let spend_key = super::source_v5::validate_source_v5(
        &fixture.profile,
        &fixture.request.sources[0].slot.descriptor_id,
        &source,
        "issuer:e2e:malformed-output",
    )
    .unwrap()
    .spend_key;
    let store = ExchangeStore::new(&h.url).unwrap();
    let engine = super::ExchangeEngine::new(
        fixture.profile.clone(),
        vec![],
        store.clone(),
        "issuer:e2e:malformed-output".into(),
        super::ReceiptKeyRing::load(&fixture.receipt_path, &[]).unwrap(),
        300,
    )
    .await
    .unwrap();
    let operation = [0x52; 16];
    assert_eq!(
        engine
            .process_or_recover(&operation, &fixture.request)
            .await
            .unwrap(),
        super::ProcessDecision::Rejected
    );
    assert!(store.get(&operation).await.unwrap().is_none());
    let spend: Option<Vec<u8>> = store
        .raw_command("GET", &[spend_key.as_bytes()])
        .await
        .unwrap();
    assert!(spend.is_none());
}

#[tokio::test]
async fn exchange_engine_multi_input_multi_output_rule_commits_atomically() {
    let Some(h) = harness() else { return };
    let mut fixture = e2e_fixture("issuer:e2e:multi", 2).await;
    let mut second_source = fixture.request.sources[0].clone();
    second_source.slot.slot_id = "in-1".into();
    second_source.artifact = fixture.alternate_artifact.clone();
    fixture.request.sources.push(second_source);
    let mut second_rule = fixture.profile.rules[0].sources[0].clone();
    second_rule.slot_id = "in-1".into();
    fixture.profile.rules[0].sources.push(second_rule);
    let mut canonical = Vec::new();
    for slot in fixture.profile.rules[0]
        .sources
        .iter()
        .chain(&fixture.profile.rules[0].outputs)
    {
        for value in [
            slot.descriptor_id.as_bytes(),
            slot.slot_id.as_bytes(),
            slot.class.as_bytes(),
        ] {
            canonical.extend_from_slice(&(value.len() as u32).to_be_bytes());
            canonical.extend_from_slice(value);
        }
        canonical.extend_from_slice(&slot.quantity.to_be_bytes());
    }
    fixture.profile.rules[0].id = rule_id(&canonical);
    fixture.request.rule_id = fixture.profile.rules[0].id.clone();
    fixture.profile.validate(None).unwrap();
    let store = ExchangeStore::new(&h.url).unwrap();
    let engine = super::ExchangeEngine::new(
        fixture.profile,
        vec![],
        store.clone(),
        "issuer:e2e:multi".into(),
        super::ReceiptKeyRing::load(&fixture.receipt_path, &[]).unwrap(),
        300,
    )
    .await
    .unwrap();
    let operation = [0x54; 16];
    assert!(matches!(
        engine
            .process_or_recover(&operation, &fixture.request)
            .await
            .unwrap(),
        super::ProcessDecision::Committed(_)
    ));
    let record = store.get(&operation).await.unwrap().unwrap();
    assert_eq!(record.sources.len(), 2);
    assert_eq!(record.outputs.len(), 2);
    assert_ne!(record.sources[0].spend_key, record.sources[1].spend_key);
    for source in record.sources {
        let spent: Option<Vec<u8>> = store
            .raw_command("GET", &[source.spend_key.as_bytes()])
            .await
            .unwrap();
        assert!(spent.is_some());
    }
}

#[tokio::test]
async fn exchange_http_post_status_conflict_duplicate_and_no_store() {
    let Some(h) = harness() else { return };
    let mut fixture = e2e_fixture("issuer:http:e2e", 1).await;
    let store = ExchangeStore::new(&h.url).unwrap();
    let receipt_keys = super::ReceiptKeyRing::load(&fixture.receipt_path, &[]).unwrap();
    let receipt_key_id = receipt_keys.active_id().to_owned();
    let original_artifact = fixture.request.sources[0].artifact.clone();
    fixture.request.sources[0].artifact = fixture.alternate_artifact.clone();
    let pending_request = fixture.request.clone();
    let pending_operation = [0x56; 16];
    seed_fixture_work(
        &store,
        &pending_operation,
        &fixture,
        "issuer:http:e2e",
        &receipt_key_id,
    )
    .await;
    fixture.request.sources[0].artifact = original_artifact;
    let exchange_metadata = crate::startup::exchange_discovery(
        &fixture.profile,
        &[],
        receipt_keys.discovery_metadata(),
    );
    let engine = Arc::new(
        super::ExchangeEngine::new(
            fixture.profile.clone(),
            vec![],
            store.clone(),
            "issuer:http:e2e".into(),
            receipt_keys,
            300,
        )
        .await
        .unwrap(),
    );
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
    let exchange_url = format!("http://{address}/v1/public/exchange");
    let status_url = format!("http://{address}/v1/public/exchange/status");
    let operation = Base64UrlUnpadded::encode_string(&[0x53; 16]);
    let request_body = serde_json::to_vec(&fixture.request).unwrap();
    let pending = client
        .post(&exchange_url)
        .header(
            "idempotency-key",
            Base64UrlUnpadded::encode_string(&pending_operation),
        )
        .json(&pending_request)
        .send()
        .await
        .unwrap();
    assert_eq!(pending.status(), reqwest::StatusCode::ACCEPTED);
    assert_eq!(pending.headers()["retry-after"], "1");
    assert_eq!(pending.headers()["cache-control"], "no-store");
    let response = client
        .post(&exchange_url)
        .header("content-type", "application/json")
        .header("idempotency-key", &operation)
        .body(request_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let committed = response.bytes().await.unwrap();
    let response = client
        .get(&status_url)
        .header("idempotency-key", &operation)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.bytes().await.unwrap(), committed);
    let retry_one = client
        .post(&exchange_url)
        .header("idempotency-key", &operation)
        .json(&fixture.request)
        .send();
    let retry_two = client
        .post(&exchange_url)
        .header("idempotency-key", &operation)
        .json(&fixture.request)
        .send();
    let (retry_one, retry_two) = tokio::join!(retry_one, retry_two);
    for retry in [retry_one.unwrap(), retry_two.unwrap()] {
        assert_eq!(retry.status(), reqwest::StatusCode::OK);
        assert_eq!(retry.bytes().await.unwrap(), committed);
    }
    let mut changed = fixture.request.clone();
    changed.sources[0].artifact = fixture.alternate_artifact;
    let response = client
        .post(&exchange_url)
        .header("content-type", "application/json")
        .header("idempotency-key", &operation)
        .body(serde_json::to_vec(&changed).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    let mut duplicate_headers = reqwest::header::HeaderMap::new();
    duplicate_headers.append("idempotency-key", operation.parse().unwrap());
    duplicate_headers.append("idempotency-key", operation.parse().unwrap());
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
            "idempotency-key",
            Base64UrlUnpadded::encode_string(&[0x57; 16]),
        )
        .header("content-type", "application/json")
        .body(vec![b'x'; 3 * 1024 * 1024 + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(oversized.headers()["cache-control"], "no-store");
    let unknown = client
        .get(&status_url)
        .header(
            "idempotency-key",
            Base64UrlUnpadded::encode_string(&[0x7f; 16]),
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
        discovery["exchange"]["receipt_keys"][0]["purpose"],
        "exchange_receipt_active"
    );
    let public_key = discovery["exchange"]["receipt_keys"][0]["public_key_b64"]
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

async fn seed_engine_work(
    store: &ExchangeStore,
    id: &[u8; 16],
    request: &ExchangeRequest,
    descriptor: &ExchangeDescriptor,
    representative: &[u8],
    receipt_key_id: &str,
    now: i64,
) -> Vec<u8> {
    let sources = vec![SourceWork {
        descriptor_id: "a".repeat(64),
        spend_key: format!("spend:engine:{}", hex::encode(id)),
        valid_from: now - 1,
        valid_until: now + 120,
    }];
    let outputs = vec![OutputWork {
        descriptor_id: descriptor.id.clone(),
        keyset_id: request.outputs[0].slot.keyset_id.clone(),
        slot_id: "out".into(),
        quantity: 1,
        blinded_value: representative.to_vec(),
    }];
    let refs = vec![target_ref_key(&descriptor.id, now - 1, now + 120)];
    let rr = receipt_ref_key(receipt_key_id);
    let hash = request.canonical_hash(id).unwrap();
    let outcome = store
        .reserve(ReservationInput {
            operation_id: id,
            request_hash: &hash,
            profile_id: EXCHANGE_PROFILE_V1,
            rule_id: &request.rule_id,
            target_keyset_id: &request.outputs[0].slot.keyset_id,
            receipt_key_id,
            sources: &sources,
            outputs: &outputs,
            target_refs: &refs,
            receipt_ref_key: &rr,
            capacities: &[],
            receipt_lifetime_secs: 300,
        })
        .await
        .unwrap();
    created(outcome)
}

async fn seed_fixture_work(
    store: &ExchangeStore,
    id: &[u8; 16],
    fixture: &E2eFixture,
    issuer_id: &str,
    receipt_key_id: &str,
) -> Vec<u8> {
    let source_bytes = freebird_common::exchange_api::decode_base64url(
        &fixture.request.sources[0].artifact,
        freebird_common::exchange_api::MAX_ARTIFACT,
    )
    .unwrap();
    let validated = super::source_v5::validate_source_v5(
        &fixture.profile,
        &fixture.request.sources[0].slot.descriptor_id,
        &source_bytes,
        issuer_id,
    )
    .unwrap();
    let source_descriptor = &fixture.profile.sources.descriptors[0];
    let sources = vec![SourceWork {
        descriptor_id: source_descriptor.id.clone(),
        spend_key: validated.spend_key,
        valid_from: source_descriptor.valid_from,
        valid_until: source_descriptor.valid_until,
    }];
    let outputs = fixture
        .request
        .outputs
        .iter()
        .map(|output| OutputWork {
            descriptor_id: output.slot.descriptor_id.clone(),
            keyset_id: output.slot.keyset_id.clone(),
            slot_id: output.slot.slot_id.clone(),
            quantity: output.slot.quantity,
            blinded_value: freebird_common::exchange_api::decode_base64url(
                &output.blinded_value,
                freebird_common::exchange_api::MAX_ARTIFACT,
            )
            .unwrap(),
        })
        .collect::<Vec<_>>();
    let target = &fixture.profile.target_keyset.targets[0].descriptor;
    let refs = vec![target_ref_key(
        &target.id,
        target.valid_from,
        target.valid_until,
    )];
    let receipt_ref = receipt_ref_key(receipt_key_id);
    let hash = fixture.request.canonical_hash(id).unwrap();
    created(
        store
            .reserve(ReservationInput {
                operation_id: id,
                request_hash: &hash,
                profile_id: &fixture.request.profile,
                rule_id: &fixture.request.rule_id,
                target_keyset_id: &fixture.profile.target_keyset.id,
                receipt_key_id,
                sources: &sources,
                outputs: &outputs,
                target_refs: &refs,
                receipt_ref_key: &receipt_ref,
                capacities: &[],
                receipt_lifetime_secs: 300,
            })
            .await
            .unwrap(),
    )
}

fn seeded_result(id: &[u8; 16], fixture: &E2eFixture) -> (Vec<u8>, [u8; 32]) {
    let mut result = ExchangeResult {
        operation_id: Base64UrlUnpadded::encode_string(id),
        profile: fixture.request.profile.clone(),
        target_keyset_id: fixture.profile.target_keyset.id.clone(),
        outputs: fixture
            .request
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

#[tokio::test]
async fn exchange_redis_reserve_creates_expected_typed_state() {
    let Some(_h) = harness() else { return };
    let store = ExchangeStore::new(&_h.url).unwrap();
    let id = [1; 16];
    let hash = [2; 32];
    created(reserve(&store, &id, &hash, "spend:a", "target-a", &[]).await);
    let record = store.get(&id).await.unwrap().unwrap();
    assert_eq!(record.request_hash, hash);
    assert_eq!(record.state, State::Reserved);
    assert_eq!(record.sources[0].spend_key, "spend:a");
    assert_eq!(record.outputs[0], output("target-a"));
    assert!(record.result.is_none());
    assert_eq!(record.receipt_key_id, "receipt-key");
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

#[tokio::test]
async fn exchange_redis_exact_retry_no_double_increment_and_change_conflict() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let id = [3; 16];
    let hash = [4; 32];
    let target = "target-retry";
    created(reserve(&store, &id, &hash, "spend:retry", target, &[]).await);
    let record = store.get(&id).await.unwrap().unwrap();
    assert!(matches!(
        reserve(&store, &id, &hash, "ignored", target, &[]).await,
        ReserveOutcome::Existing(_)
    ));
    assert!(matches!(
        reserve(&store, &id, &[5; 32], "ignored", target, &[]).await,
        ReserveOutcome::Conflict
    ));
    // Retry cannot create its alternate source key or increment its counters.
    let alternate: Option<Vec<u8>> = store.raw_command("GET", &[b"ignored"]).await.unwrap();
    assert!(alternate.is_none());
    let target_count: i64 = store
        .raw_command("GET", &[record.target_refs[0].key.as_bytes()])
        .await
        .unwrap();
    assert_eq!(target_count, 1);
    let receipt_count: i64 = store
        .raw_command("GET", &[record.receipt_ref.as_bytes()])
        .await
        .unwrap();
    assert_eq!(receipt_count, 1);
}

#[tokio::test]
async fn exchange_redis_concurrent_same_operation_is_single_reservation() {
    let Some(h) = harness() else { return };
    let a = ExchangeStore::new(&h.url).unwrap();
    let b = a.clone();
    let id = [6; 16];
    let hash = [7; 32];
    let (x, y) = tokio::join!(
        reserve(&a, &id, &hash, "spend:race", "target-race", &[]),
        reserve(&b, &id, &hash, "spend:race", "target-race", &[])
    );
    assert!(matches!(
        (&x, &y),
        (ReserveOutcome::Created(_), ReserveOutcome::Existing(_))
            | (ReserveOutcome::Existing(_), ReserveOutcome::Created(_))
    ));
}

#[tokio::test]
async fn exchange_redis_overlapping_and_duplicate_sources_are_atomic() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    created(
        reserve(
            &store,
            &[8; 16],
            &[8; 32],
            "spend:shared",
            "target-one",
            &[],
        )
        .await,
    );
    assert!(matches!(
        reserve(
            &store,
            &[9; 16],
            &[9; 32],
            "spend:shared",
            "target-two",
            &[]
        )
        .await,
        ReserveOutcome::Spent
    ));
    let now = store.redis_time().await.unwrap() as i64;
    let source = SourceWork {
        descriptor_id: "s".into(),
        spend_key: "spend:dup".into(),
        valid_from: now - 1,
        valid_until: now + 30,
    };
    let sources = vec![source.clone(), source];
    let outputs = vec![output("dup")];
    let refs = vec![target_ref_key("dup", now - 1, now + 30)];
    let rr = receipt_ref_key("r");
    let duplicate = store
        .reserve(ReservationInput {
            operation_id: &[10; 16],
            request_hash: &[10; 32],
            profile_id: "p",
            rule_id: "r",
            target_keyset_id: "k",
            receipt_key_id: "r",
            sources: &sources,
            outputs: &outputs,
            target_refs: &refs,
            receipt_ref_key: &rr,
            capacities: &[],
            receipt_lifetime_secs: 10,
        })
        .await;
    assert!(duplicate.is_err());
    assert!(store.get(&[10; 16]).await.unwrap().is_none());
}

#[tokio::test]
async fn exchange_redis_verifier_spend_exclusion_both_directions() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let verifier_key = v5_spend_key("verifier-first");
    let _: String = store
        .raw_command("SET", &[verifier_key.as_bytes(), b"1", b"EX", b"120"])
        .await
        .unwrap();
    assert!(matches!(
        reserve(&store, &[11; 16], &[11; 32], &verifier_key, "t11", &[]).await,
        ReserveOutcome::Spent
    ));
    let exchange_key = v5_spend_key("exchange-first");
    created(reserve(&store, &[12; 16], &[12; 32], &exchange_key, "t12", &[]).await);
    let result: Option<String> = store
        .raw_command(
            "SET",
            &[exchange_key.as_bytes(), b"verifier", b"NX", b"EX", b"120"],
        )
        .await
        .unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn exchange_redis_window_and_spend_ttl_endpoint() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let now = store.redis_time().await.unwrap() as i64;
    let sources = vec![SourceWork {
        descriptor_id: "s".into(),
        spend_key: "spend:endpoint".into(),
        valid_from: now,
        valid_until: now + 3,
    }];
    let outputs = vec![output("endpoint")];
    let refs = vec![target_ref_key("endpoint", now, now + 3)];
    let rr = receipt_ref_key("r");
    let outcome = store
        .reserve(ReservationInput {
            operation_id: &[13; 16],
            request_hash: &[13; 32],
            profile_id: "p",
            rule_id: "r",
            target_keyset_id: "k",
            receipt_key_id: "r",
            sources: &sources,
            outputs: &outputs,
            target_refs: &refs,
            receipt_ref_key: &rr,
            capacities: &[],
            receipt_lifetime_secs: 10,
        })
        .await
        .unwrap();
    created(outcome);
    let ttl: i64 = store
        .raw_command("TTL", &[b"spend:endpoint"])
        .await
        .unwrap();
    assert!((2..=4).contains(&ttl), "ttl={ttl}");
    let future = vec![SourceWork {
        valid_from: now + 100,
        ..sources[0].clone()
    }];
    let rejected = store
        .reserve(ReservationInput {
            operation_id: &[14; 16],
            request_hash: &[14; 32],
            profile_id: "p",
            rule_id: "r",
            target_keyset_id: "k",
            receipt_key_id: "r",
            sources: &future,
            outputs: &outputs,
            target_refs: &refs,
            receipt_ref_key: &rr,
            capacities: &[],
            receipt_lifetime_secs: 10,
        })
        .await
        .unwrap();
    assert_eq!(rejected, ReserveOutcome::SourceWindow);
}

#[tokio::test]
async fn exchange_redis_independent_quotas_duplicate_and_exhaustion() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let a = CapacityEntry {
        key: capacity_key("qa"),
        amount: 2,
        limit: 3,
    };
    let b = CapacityEntry {
        key: capacity_key("qb"),
        amount: 1,
        limit: 1,
    };
    created(
        reserve(
            &store,
            &[15; 16],
            &[15; 32],
            "spend:q1",
            "qt1",
            &[a.clone(), b.clone()],
        )
        .await,
    );
    assert!(matches!(
        reserve(
            &store,
            &[16; 16],
            &[16; 32],
            "spend:q2",
            "qt2",
            &[CapacityEntry {
                amount: 2,
                ..a.clone()
            }]
        )
        .await,
        ReserveOutcome::Capacity
    ));
    let duplicate = vec![a.clone(), a];
    let now = store.redis_time().await.unwrap() as i64;
    let sources = vec![SourceWork {
        descriptor_id: "s".into(),
        spend_key: "spend:qdup".into(),
        valid_from: now - 1,
        valid_until: now + 30,
    }];
    let outputs = vec![output("qdup")];
    let refs = vec![target_ref_key("qdup", now - 1, now + 30)];
    let rr = receipt_ref_key("r");
    assert!(store
        .reserve(ReservationInput {
            operation_id: &[17; 16],
            request_hash: &[17; 32],
            profile_id: "p",
            rule_id: "r",
            target_keyset_id: "k",
            receipt_key_id: "r",
            sources: &sources,
            outputs: &outputs,
            target_refs: &refs,
            receipt_ref_key: &rr,
            capacities: &duplicate,
            receipt_lifetime_secs: 10
        })
        .await
        .is_err());
    let qb: i64 = store
        .raw_command("GET", &[capacity_key("qb").as_bytes()])
        .await
        .unwrap();
    assert_eq!(qb, 1);
}

#[tokio::test]
async fn exchange_redis_refs_two_to_one_to_zero() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let target = "refs";
    let f1 = created(reserve(&store, &[18; 16], &[18; 32], "spend:r1", target, &[]).await);
    let f2 = created(reserve(&store, &[19; 16], &[19; 32], "spend:r2", target, &[]).await);
    let r1 = store.get(&[18; 16]).await.unwrap().unwrap();
    let key = &r1.target_refs[0].key;
    let count: i64 = store.raw_command("GET", &[key.as_bytes()]).await.unwrap();
    assert_eq!(count, 2);
    assert_eq!(
        store
            .result_ready(&[18; 16], &f1, b"result-one", &[1; 32])
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    let count: i64 = store.raw_command("GET", &[key.as_bytes()]).await.unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        store
            .result_ready(&[19; 16], &f2, b"result-two", &[2; 32])
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    let count: i64 = store.raw_command("GET", &[key.as_bytes()]).await.unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn exchange_redis_live_and_expired_claims() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let id = [20; 16];
    created(reserve(&store, &id, &[20; 32], "spend:claim", "claim", &[]).await);
    assert_eq!(store.claim(&id).await.unwrap(), ClaimOutcome::Live);
    force_lease(&store, &id, 0).await;
    assert!(matches!(
        store.claim(&id).await.unwrap(),
        ClaimOutcome::Claimed(_)
    ));
}

#[tokio::test]
async fn exchange_redis_stale_fence_repeated_conflict_and_underflow() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let id = [21; 16];
    let fence = created(
        reserve(
            &store,
            &id,
            &[21; 32],
            "spend:transition",
            "transition",
            &[],
        )
        .await,
    );
    assert_eq!(
        store
            .result_ready(&id, b"stale", b"result", &[1; 32])
            .await
            .unwrap(),
        TransitionOutcome::StaleFence
    );
    assert_eq!(
        store
            .result_ready(&id, &fence, b"result", &[1; 32])
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    assert_eq!(
        store
            .result_ready(&id, &fence, b"result", &[1; 32])
            .await
            .unwrap(),
        TransitionOutcome::Repeated
    );
    assert_eq!(
        store
            .result_ready(&id, &fence, b"other", &[2; 32])
            .await
            .unwrap(),
        TransitionOutcome::Conflict
    );
    assert_eq!(
        store
            .commit(&id, b"stale", b"receipt", b"response")
            .await
            .unwrap(),
        TransitionOutcome::StaleFence
    );
    assert_eq!(
        store
            .commit(&id, &fence, b"receipt", b"response")
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    assert_eq!(
        store
            .commit(&id, &fence, b"receipt", b"response")
            .await
            .unwrap(),
        TransitionOutcome::Repeated
    );
    assert_eq!(
        store
            .commit(&id, &fence, b"other", b"response")
            .await
            .unwrap(),
        TransitionOutcome::Conflict
    );
    let id2 = [22; 16];
    let fence2 =
        created(reserve(&store, &id2, &[22; 32], "spend:underflow", "underflow", &[]).await);
    let record = store.get(&id2).await.unwrap().unwrap();
    let _: i64 = store
        .raw_command("SET", &[record.target_refs[0].key.as_bytes(), b"0"])
        .await
        .unwrap();
    assert_eq!(
        store
            .result_ready(&id2, &fence2, b"r", &[3; 32])
            .await
            .unwrap(),
        TransitionOutcome::Underflow
    );

    let id3 = [31; 16];
    let fence3 = created(
        reserve(
            &store,
            &id3,
            &[31; 32],
            "spend:receipt-underflow",
            "receipt-underflow",
            &[],
        )
        .await,
    );
    assert_eq!(
        store
            .result_ready(&id3, &fence3, b"receipt-result", &[4; 32])
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    let record3 = store.get(&id3).await.unwrap().unwrap();
    let _: i64 = store
        .raw_command("SET", &[record3.receipt_ref.as_bytes(), b"0"])
        .await
        .unwrap();
    assert_eq!(
        store
            .commit(&id3, &fence3, b"receipt", b"response")
            .await
            .unwrap(),
        TransitionOutcome::Underflow
    );
}

#[tokio::test]
async fn exchange_redis_recovery_new_client_reserved_and_result_ready() {
    let Some(h) = harness() else { return };
    let first = ExchangeStore::new(&h.url).unwrap();
    let reserved = [23; 16];
    created(reserve(&first, &reserved, &[23; 32], "spend:new1", "new1", &[]).await);
    force_lease(&first, &reserved, 0).await;
    let second = ExchangeStore::new(&h.url).unwrap();
    assert!(matches!(
        second.claim(&reserved).await.unwrap(),
        ClaimOutcome::Claimed(_)
    ));
    let ready = [24; 16];
    let fence = created(reserve(&first, &ready, &[24; 32], "spend:new2", "new2", &[]).await);
    assert_eq!(
        first
            .result_ready(&ready, &fence, b"result", &[4; 32])
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    force_lease(&first, &ready, 0).await;
    assert!(matches!(
        second.claim(&ready).await.unwrap(),
        ClaimOutcome::Claimed(_)
    ));
}

#[tokio::test]
async fn exchange_engine_recovers_reserved_result_ready_and_exact_committed_bytes() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
    let target_path = dir.path().join("target.der");
    std::fs::write(&target_path, provider.to_der().unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let descriptor = ExchangeDescriptor {
        id: "b".repeat(64),
        profile_id: EXCHANGE_PROFILE_V1.into(),
        role: "target".into(),
        class: "target".into(),
        issuer_id: "issuer:recovery".into(),
        kid: hex::encode(provider.token_key_id()),
        audience: None,
        spki_b64: Base64UrlUnpadded::encode_string(provider.public_key_spki()),
        suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
        max_quantity: 10,
        valid_from: 0,
        valid_until: i64::MAX,
    };
    let source_descriptor = ExchangeDescriptor {
        role: "source".into(),
        class: "source".into(),
        id: "a".repeat(64),
        ..descriptor.clone()
    };
    let profile = ExchangeProfile {
        profile_id: EXCHANGE_PROFILE_V1.into(),
        sources: ExchangeSourceAllowlist {
            descriptors: vec![source_descriptor],
        },
        target_keyset: ExchangeKeyset {
            id: "2".repeat(64),
            targets: vec![ExchangeTargetKey {
                descriptor: descriptor.clone(),
                private_key_path: target_path.display().to_string(),
            }],
        },
        rules: Vec::<ExchangeRule>::new(),
    };
    let mut representative = vec![0; usize::from(provider.modulus_bits()) / 8];
    *representative.last_mut().unwrap() = 1;
    let request = ExchangeRequest {
        profile: EXCHANGE_PROFILE_V1.into(),
        rule_id: "c".repeat(64),
        sources: vec![ExchangeSource {
            slot: ExchangeSlot {
                descriptor_id: "a".repeat(64),
                keyset_id: "1".repeat(64),
                slot_id: "in".into(),
                quantity: 1,
            },
            artifact: Base64UrlUnpadded::encode_string(b"not-persisted"),
        }],
        outputs: vec![ExchangeOutput {
            slot: ExchangeSlot {
                descriptor_id: descriptor.id.clone(),
                keyset_id: profile.target_keyset.id.clone(),
                slot_id: "out".into(),
                quantity: 1,
            },
            blinded_value: Base64UrlUnpadded::encode_string(&representative),
        }],
    };
    let receipt_path = dir.path().join("receipt.key");
    let receipt_key_id = load_or_generate_receipt_key(&receipt_path)
        .unwrap()
        .key_id();
    let now = store.redis_time().await.unwrap() as i64;
    let reserved = [29; 16];
    seed_engine_work(
        &store,
        &reserved,
        &request,
        &descriptor,
        &representative,
        &receipt_key_id,
        now,
    )
    .await;
    force_lease(&store, &reserved, 0).await;
    let engine = super::ExchangeEngine::new(
        profile.clone(),
        vec![],
        ExchangeStore::new(&h.url).unwrap(),
        "issuer:recovery".into(),
        super::ReceiptKeyRing::load(&receipt_path, &[]).unwrap(),
        300,
    )
    .await
    .unwrap();
    let response = match engine
        .process_or_recover(&reserved, &request)
        .await
        .unwrap()
    {
        super::ProcessDecision::Committed(bytes) => bytes,
        other => panic!("reserved recovery: {other:?}"),
    };
    assert_eq!(
        engine
            .process_or_recover(&reserved, &request)
            .await
            .unwrap(),
        super::ProcessDecision::Committed(response.clone())
    );

    let ready = [30; 16];
    let ready_fence = seed_engine_work(
        &store,
        &ready,
        &request,
        &descriptor,
        &representative,
        &receipt_key_id,
        now,
    )
    .await;
    let mut result = ExchangeResult {
        operation_id: Base64UrlUnpadded::encode_string(&ready),
        profile: EXCHANGE_PROFILE_V1.into(),
        target_keyset_id: profile.target_keyset.id.clone(),
        outputs: vec![ExchangeResultOutput {
            slot: request.outputs[0].slot.clone(),
            blinded_value: request.outputs[0].blinded_value.clone(),
            blind_signature: Base64UrlUnpadded::encode_string(&[1; 256]),
        }],
        result_digest: String::new(),
    };
    let digest = result.result_digest().unwrap();
    result.result_digest = Base64UrlUnpadded::encode_string(&digest);
    let result_bytes = serde_json::to_vec(&result).unwrap();
    assert_eq!(
        store
            .result_ready(&ready, &ready_fence, &result_bytes, &digest)
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    force_lease(&store, &ready, 0).await;
    let new_engine = super::ExchangeEngine::new(
        profile,
        vec![],
        ExchangeStore::new(&h.url).unwrap(),
        "issuer:recovery".into(),
        super::ReceiptKeyRing::load(&receipt_path, &[]).unwrap(),
        300,
    )
    .await
    .unwrap();
    assert!(matches!(
        new_engine
            .process_or_recover(&ready, &request)
            .await
            .unwrap(),
        super::ProcessDecision::Committed(_)
    ));
}

#[tokio::test]
async fn exchange_redis_committed_exact_response_no_raw_source_and_no_ttl() {
    let Some(h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let id = [25; 16];
    let marker = b"RAW-SOURCE-MUST-NOT-PERSIST";
    let fence = created(reserve(&store, &id, &[25; 32], "spend:no-raw", "no-raw", &[]).await);
    store
        .result_ready(&id, &fence, b"canonical-result", &[5; 32])
        .await
        .unwrap();
    let response = b"exact\0binary-response";
    store
        .commit(&id, &fence, b"signed-receipt", response)
        .await
        .unwrap();
    let record = store.get(&id).await.unwrap().unwrap();
    assert_eq!(record.response.as_deref(), Some(response.as_slice()));
    let ttl: i64 = store
        .raw_command("TTL", &[ExchangeStore::op(&id).as_bytes()])
        .await
        .unwrap();
    assert_eq!(ttl, -1);
    let raw: Vec<Vec<u8>> = store
        .raw_command("HVALS", &[ExchangeStore::op(&id).as_bytes()])
        .await
        .unwrap();
    assert!(!raw
        .iter()
        .any(|value| value.windows(marker.len()).any(|window| window == marker)));
}

#[tokio::test]
async fn exchange_engine_rotation_and_aof_restart_recover_reserved_and_result_ready() {
    let Some(mut harness) = harness() else { return };
    let issuer_id = "issuer:e2e:rotation";
    let old = e2e_fixture(issuer_id, 1).await;
    let current = e2e_fixture(issuer_id, 1).await;
    let old_receipt_id = load_or_generate_receipt_key(&old.receipt_path)
        .unwrap()
        .key_id();
    let retained_ring = super::ReceiptKeyRing::load(
        &current.receipt_path,
        std::slice::from_ref(&old.receipt_path),
    )
    .unwrap();
    let discovery = crate::startup::exchange_discovery(
        &current.profile,
        std::slice::from_ref(&old.profile),
        retained_ring.discovery_metadata(),
    );
    assert_eq!(discovery.receipt_keys.len(), 2);
    assert!(discovery
        .receipt_keys
        .iter()
        .any(|key| key.key_id == old_receipt_id && key.purpose == "exchange_receipt_retained"));
    let store = ExchangeStore::new(&harness.url).unwrap();
    let current_only_engine = super::ExchangeEngine::new(
        current.profile.clone(),
        vec![],
        store.clone(),
        issuer_id.into(),
        super::ReceiptKeyRing::load(&current.receipt_path, &[]).unwrap(),
        300,
    )
    .await
    .unwrap();
    let reserved = [0x61; 16];
    seed_fixture_work(&store, &reserved, &old, issuer_id, &old_receipt_id).await;
    force_lease(&store, &reserved, 0).await;
    assert_eq!(
        current_only_engine
            .process_or_recover(&reserved, &old.request)
            .await
            .unwrap(),
        super::ProcessDecision::Retryable
    );
    let unavailable_record = store.get(&reserved).await.unwrap().unwrap();
    let unavailable_spend: Option<Vec<u8>> = store
        .raw_command("GET", &[unavailable_record.sources[0].spend_key.as_bytes()])
        .await
        .unwrap();
    assert!(unavailable_spend.is_some());
    let result_ready = [0x62; 16];
    let result_fence =
        seed_fixture_work(&store, &result_ready, &old, issuer_id, &old_receipt_id).await;
    let (result_bytes, digest) = seeded_result(&result_ready, &old);
    assert_eq!(
        store
            .result_ready(&result_ready, &result_fence, &result_bytes, &digest)
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    force_lease(&store, &result_ready, 0).await;
    let reserved_before = store.get(&reserved).await.unwrap().unwrap();
    let ready_before = store.get(&result_ready).await.unwrap().unwrap();
    drop(store);
    harness.restart().expect("durable Redis restart");

    let missing = super::ExchangeEngine::new(
        current.profile.clone(),
        vec![],
        ExchangeStore::new(&harness.url).unwrap(),
        issuer_id.into(),
        super::ReceiptKeyRing::load(&current.receipt_path, &[]).unwrap(),
        300,
    )
    .await;
    assert!(
        missing.is_err(),
        "pending signer readiness must fail closed"
    );

    let engine = super::ExchangeEngine::new(
        current.profile.clone(),
        vec![old.profile.clone()],
        ExchangeStore::new(&harness.url).unwrap(),
        issuer_id.into(),
        super::ReceiptKeyRing::load(
            &current.receipt_path,
            std::slice::from_ref(&old.receipt_path),
        )
        .unwrap(),
        300,
    )
    .await
    .unwrap();
    let reserved_response = match engine
        .process_or_recover(&reserved, &old.request)
        .await
        .unwrap()
    {
        super::ProcessDecision::Committed(response) => response,
        decision => panic!("reserved rotation recovery failed: {decision:?}"),
    };
    let ready_response = match engine
        .process_or_recover(&result_ready, &old.request)
        .await
        .unwrap()
    {
        super::ProcessDecision::Committed(response) => response,
        decision => panic!("result-ready rotation recovery failed: {decision:?}"),
    };
    assert_eq!(
        engine
            .process_or_recover(&reserved, &old.request)
            .await
            .unwrap(),
        super::ProcessDecision::Committed(reserved_response.clone())
    );
    assert_eq!(
        engine
            .process_or_recover(&result_ready, &old.request)
            .await
            .unwrap(),
        super::ProcessDecision::Committed(ready_response.clone())
    );
    let recovered_store = ExchangeStore::new(&harness.url).unwrap();
    for (id, original, response) in [
        (reserved, reserved_before, reserved_response),
        (result_ready, ready_before, ready_response),
    ] {
        let record = recovered_store.get(&id).await.unwrap().unwrap();
        assert_eq!(record.state, State::Committed);
        assert_eq!(record.response, Some(response));
        let spend: Option<Vec<u8>> = recovered_store
            .raw_command("GET", &[original.sources[0].spend_key.as_bytes()])
            .await
            .unwrap();
        assert!(
            spend.is_some(),
            "source spend must survive restart/recovery"
        );
        for target in original.target_refs {
            let count: i64 = recovered_store
                .raw_command("GET", &[target.key.as_bytes()])
                .await
                .unwrap();
            assert_eq!(count, 0);
        }
        let receipt_count: i64 = recovered_store
            .raw_command("GET", &[original.receipt_ref.as_bytes()])
            .await
            .unwrap();
        assert_eq!(receipt_count, 0);
    }
}

#[tokio::test]
async fn exchange_redis_aof_restart_reserved_result_ready_committed() {
    let Some(mut h) = harness() else { return };
    let store = ExchangeStore::new(&h.url).unwrap();
    let reserved = [26; 16];
    created(reserve(&store, &reserved, &[26; 32], "spend:aof1", "aof1", &[]).await);
    let ready = [27; 16];
    let ready_fence = created(reserve(&store, &ready, &[27; 32], "spend:aof2", "aof2", &[]).await);
    store
        .result_ready(&ready, &ready_fence, b"durable-result", &[7; 32])
        .await
        .unwrap();
    let committed = [28; 16];
    let committed_fence =
        created(reserve(&store, &committed, &[28; 32], "spend:aof3", "aof3", &[]).await);
    store
        .result_ready(&committed, &committed_fence, b"result", &[8; 32])
        .await
        .unwrap();
    store
        .commit(
            &committed,
            &committed_fence,
            b"receipt",
            b"durable-response",
        )
        .await
        .unwrap();
    drop(store);
    h.restart().expect("AOF Redis restart");
    let recovered = ExchangeStore::new(&h.url).unwrap();
    assert_eq!(
        recovered.get(&reserved).await.unwrap().unwrap().state,
        State::Reserved
    );
    assert_eq!(
        recovered
            .get(&ready)
            .await
            .unwrap()
            .unwrap()
            .result
            .as_deref(),
        Some(b"durable-result".as_slice())
    );
    let record = recovered.get(&committed).await.unwrap().unwrap();
    assert_eq!(record.state, State::Committed);
    assert_eq!(
        record.response.as_deref(),
        Some(b"durable-response".as_slice())
    );
}
