// SPDX-License-Identifier: Apache-2.0 OR MIT

use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{
    validate_graph_issuance_discovery_v2_update, BatchIssueReq, BatchIssueResp, BatchVerifyReq,
    BatchVerifyResp, ExchangeAdmissionStateV2, ExchangeDescriptorDiscoveryV2,
    ExchangeDescriptorInfoV2, ExchangeDiscoveryV2, ExchangeGraphDiscoveryV2, ExchangeGraphInfoV2,
    ExchangeKeysetDiscoveryV2, ExchangeKeysetInfoV2, ExchangeReceiptKeyInfo,
    ExchangeTransitionDiscoveryV2, ExchangeTransitionInfoV2, ExchangeTransitionSlotDiscoveryV2,
    ExchangeTransitionSlotInfoV2, GraphIssuanceDiscovery, GraphIssuanceDiscoveryV2,
    GraphIssuancePolicyDiscovery, GraphIssuancePolicyDiscoveryV2,
    GraphIssuanceReplayAuthorityDiscoveryV1, IssueReq, IssueResp, KeyDiscoveryResp,
    PublicBatchIssueReq, PublicBatchIssueResp, PublicIssueReq, PublicIssueResp, PublicKeyInfo,
    ReplayAuthorityDiscoveryV1, SybilInfo, SybilProof, TokenResult, TokenToVerify,
    VerifierMetadataResp, VerifyReq, VerifyResp, VerifyResult, VoprfKeyInfo, VouchProof,
    EXCHANGE_LUA_MAX_EXACT_INTEGER, EXCHANGE_MAX_BUDGET_LIMIT, EXCHANGE_MAX_VALID_UNTIL,
};
use freebird_common::exchange_api::EXCHANGE_PROFILE_V2;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

fn with_unknown<T: serde::Serialize>(value: &T) -> Value {
    let mut value = serde_json::to_value(value).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unknown_contract_field".into(), Value::Bool(true));
    value
}

fn assert_unknown<T: DeserializeOwned>(value: Value, accepted: bool) {
    assert_eq!(serde_json::from_value::<T>(value).is_ok(), accepted);
}

fn receipt_key(purpose: &str) -> ExchangeReceiptKeyInfo {
    let public = [7u8; 32];
    ExchangeReceiptKeyInfo {
        key_id: hex::encode(Sha256::digest(public)),
        algorithm: "Ed25519".into(),
        purpose: purpose.into(),
        public_key_b64: Base64UrlUnpadded::encode_string(&public),
        valid_from: 1,
        valid_until: 2,
    }
}

fn vector_descriptor() -> ExchangeDescriptorDiscoveryV2 {
    ExchangeDescriptorDiscoveryV2 {
        descriptor_id: "52e59d1afa1cc0572649cb021793dfd900d2ac522ee7e2d05c7a47e1d4a7e9a3".into(),
        profile_id: EXCHANGE_PROFILE_V2.into(),
        issuer_id: "issuer:test".into(),
        token_key_id: "kid:test".into(),
        audience: Some("audience".into()),
        pubkey_spki_b64: "AQID".into(),
        suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
        valid_from: 10,
        valid_until: 20,
    }
}

fn vector_keyset() -> ExchangeKeysetDiscoveryV2 {
    ExchangeKeysetDiscoveryV2 {
        keyset_id: "17091a292fc8619e4a9f56576fa7f2d01cfd05c9c42f502c8492d1ad11cd8fec".into(),
        descriptor_ids: vec![vector_descriptor().descriptor_id],
    }
}

fn vector_transition() -> ExchangeTransitionDiscoveryV2 {
    ExchangeTransitionDiscoveryV2 {
        transition_id: "b26ab754febf25d5a7bfd54d72c6d0c1b2ee5f53a178b2afca2e8b4c943d2e61".into(),
        source_keyset_id: vector_keyset().keyset_id,
        target_keyset_id: "2".repeat(64),
        source_slots: vec![ExchangeTransitionSlotDiscoveryV2 {
            descriptor_id: vector_descriptor().descriptor_id,
            slot_id: "input".into(),
            class: "bearer".into(),
            quantity: 1,
        }],
        output_slots: vec![ExchangeTransitionSlotDiscoveryV2 {
            descriptor_id: "c".repeat(64),
            slot_id: "output".into(),
            class: "bearer".into(),
            quantity: 2,
        }],
        budget_id: "budget:test".into(),
        budget_limit: 100,
        admission_state: ExchangeAdmissionStateV2::AcceptingNew,
    }
}

fn vector_graph() -> ExchangeGraphDiscoveryV2 {
    ExchangeGraphDiscoveryV2 {
        profile_id: EXCHANGE_PROFILE_V2.into(),
        graph_id: "3b2e375fb6edf94e14f3e779a0e0db6a4db5d27111cb7b19a4eac6f96e355fb0".into(),
        descriptors: vec![vector_descriptor()],
        keysets: vec![
            vector_keyset(),
            ExchangeKeysetDiscoveryV2 {
                keyset_id: "2".repeat(64),
                descriptor_ids: vec!["c".repeat(64)],
            },
        ],
        transitions: vec![vector_transition()],
    }
}

fn graph_issuance_discovery() -> GraphIssuanceDiscoveryV2 {
    GraphIssuanceDiscoveryV2 {
        version: 2,
        policies: vec![],
        replay_authority: GraphIssuanceReplayAuthorityDiscoveryV1 {
            authority_id: "authority".into(),
            v4_scope_digest_tombstones: vec![],
        },
    }
}

fn exchange_discovery() -> ExchangeDiscoveryV2 {
    ExchangeDiscoveryV2 {
        active_graph: ExchangeGraphDiscoveryV2 {
            profile_id: "v2".into(),
            graph_id: "graph".into(),
            descriptors: vec![],
            keysets: vec![],
            transitions: vec![],
        },
        retained_graphs: vec![],
        active_receipt_key: ExchangeReceiptKeyInfo {
            key_id: "receipt".into(),
            algorithm: "Ed25519".into(),
            purpose: "exchange_receipt_active".into(),
            public_key_b64: "public".into(),
            valid_from: 1,
            valid_until: 2,
        },
        retained_receipt_keys: vec![],
    }
}

#[test]
fn api_json_aliases_tags_defaults_and_skips_are_frozen() {
    let request: IssueReq = serde_json::from_value(json!({"blinded": "blind"})).unwrap();
    assert_eq!(request.blinded_element_b64, "blind");
    assert_eq!(
        serde_json::to_value(request).unwrap(),
        json!({"blinded_element_b64":"blind","ctx_b64":null,"sybil_proof":null})
    );

    let batch: BatchIssueReq = serde_json::from_value(json!({"blinded_elements":[]})).unwrap();
    assert_eq!(batch.ctx_b64, None);
    assert!(batch.sybil_proof.is_none());
    let verify: VerifyResp = serde_json::from_value(json!({"ok":true})).unwrap();
    assert_eq!(verify.verified_at, 0);
    let public: PublicIssueReq =
        serde_json::from_value(json!({"blinded_msg_b64":"blind"})).unwrap();
    assert_eq!(public.token_key_id, None);
    assert!(public.sybil_proof.is_none());
    let public_batch: PublicBatchIssueReq =
        serde_json::from_value(json!({"blinded_msgs":[]})).unwrap();
    assert_eq!(public_batch.token_key_id, None);
    assert!(public_batch.sybil_proof.is_none());

    assert_eq!(
        serde_json::to_value(TokenResult::Success {
            token: "token".into(),
            kid: "kid".into(),
            issuer_id: "issuer".into(),
        })
        .unwrap(),
        json!({"status":"success","token":"token","kid":"kid","issuer_id":"issuer"})
    );
    assert_eq!(
        serde_json::to_value(VerifyResult::Error {
            message: "message".into(),
            code: "code".into(),
        })
        .unwrap(),
        json!({"status":"error","message":"message","code":"code"})
    );

    assert!(!serde_json::to_value(IssueResp {
        token: "token".into(),
        kid: "kid".into(),
        issuer_id: "issuer".into(),
        sybil_info: None,
    })
    .unwrap()
    .as_object()
    .unwrap()
    .contains_key("sybil_info"));
    assert!(!serde_json::to_value(PublicIssueResp {
        blind_signature_b64: "signature".into(),
        token_key_id: "kid".into(),
        issuer_id: "issuer".into(),
        sybil_info: None,
    })
    .unwrap()
    .as_object()
    .unwrap()
    .contains_key("sybil_info"));
    assert!(!serde_json::to_value(PublicBatchIssueResp {
        blind_signatures: vec![],
        token_key_id: "kid".into(),
        issuer_id: "issuer".into(),
        successful: 0,
        failed: 0,
        processing_time_ms: 0,
        throughput: 0.0,
        sybil_info: None,
    })
    .unwrap()
    .as_object()
    .unwrap()
    .contains_key("sybil_info"));
    assert!(!serde_json::to_value(BatchIssueResp {
        results: vec![],
        successful: 0,
        failed: 0,
        processing_time_ms: 0,
        throughput: 0.0,
        sybil_info: None,
    })
    .unwrap()
    .as_object()
    .unwrap()
    .contains_key("sybil_info"));
    assert!(!serde_json::to_value(VerifyResp {
        ok: true,
        error: None,
        verified_at: 0,
    })
    .unwrap()
    .as_object()
    .unwrap()
    .contains_key("error"));
    assert!(!serde_json::to_value(VerifierMetadataResp {
        verifier_id: "verifier".into(),
        audience: "audience".into(),
        scope_digest_b64: "scope".into(),
        accepted_token_versions: None,
    })
    .unwrap()
    .as_object()
    .unwrap()
    .contains_key("accepted_token_versions"));
    assert!(!serde_json::to_value(PublicKeyInfo {
        token_key_id: "kid".into(),
        token_type: "type".into(),
        rfc9474_variant: "variant".into(),
        modulus_bits: 2048,
        pubkey_spki_b64: "spki".into(),
        issuer_id: "issuer".into(),
        valid_from: 1,
        valid_until: 2,
        audience: None,
        spend_policy: "single_use".into(),
        max_uses: None,
    })
    .unwrap()
    .as_object()
    .unwrap()
    .contains_key("audience"));
    assert!(!serde_json::to_value(ExchangeDescriptorDiscoveryV2 {
        audience: None,
        ..vector_descriptor()
    })
    .unwrap()
    .as_object()
    .unwrap()
    .contains_key("audience"));
    assert!(!serde_json::to_value(GraphIssuancePolicyDiscoveryV2 {
        issuance_policy_id: "policy".into(),
        graph_id: "graph".into(),
        keyset_id: "keyset".into(),
        descriptor_id: "descriptor".into(),
        budget_id: "budget".into(),
        budget_limit: 1,
        quantity: 1,
        admission_state: ExchangeAdmissionStateV2::Disabled,
        authorization_scheme: "hmac_sha256".into(),
        authorization_scope_digest_b64: None,
    })
    .unwrap()
    .as_object()
    .unwrap()
    .contains_key("authorization_scope_digest_b64"));

    let authority: GraphIssuanceReplayAuthorityDiscoveryV1 =
        serde_json::from_value(json!({"authority_id":"authority"})).unwrap();
    assert!(authority.v4_scope_digest_tombstones.is_empty());
    let exchange: ExchangeDiscoveryV2 = serde_json::from_value(json!({
        "active_graph": serde_json::to_value(&exchange_discovery().active_graph).unwrap(),
        "active_receipt_key": serde_json::to_value(receipt_key("exchange_receipt_active")).unwrap()
    }))
    .unwrap();
    assert!(exchange.retained_graphs.is_empty());
    assert!(exchange.retained_receipt_keys.is_empty());
}

#[test]
fn api_json_unknown_field_policy_is_frozen() {
    assert_unknown::<IssueReq>(json!({"blinded_element_b64":"x","extra":true}), true);
    assert_unknown::<IssueResp>(
        json!({"token":"x","kid":"k","issuer_id":"i","extra":true}),
        true,
    );
    assert_unknown::<SybilInfo>(
        json!({"required":true,"passed":true,"cost":1,"extra":true}),
        true,
    );
    assert_unknown::<BatchIssueReq>(json!({"blinded_elements":[],"extra":true}), true);
    assert_unknown::<BatchIssueResp>(
        json!({"results":[],"successful":0,"failed":0,"processing_time_ms":0,"throughput":0.0,"extra":true}),
        true,
    );
    assert_unknown::<TokenResult>(
        json!({"status":"success","token":"x","kid":"k","issuer_id":"i","extra":true}),
        true,
    );
    assert_unknown::<PublicIssueResp>(
        json!({"blind_signature_b64":"x","token_key_id":"k","issuer_id":"i","extra":true}),
        true,
    );
    assert_unknown::<PublicBatchIssueResp>(
        json!({"blind_signatures":[],"token_key_id":"k","issuer_id":"i","successful":0,"failed":0,"processing_time_ms":0,"throughput":0.0,"extra":true}),
        true,
    );
    assert_unknown::<VerifyReq>(json!({"token_b64":"x","extra":true}), true);
    assert_unknown::<VerifyResp>(json!({"ok":true,"extra":true}), true);
    assert_unknown::<VerifierMetadataResp>(
        json!({"verifier_id":"v","audience":"a","scope_digest_b64":"s","extra":true}),
        true,
    );
    assert_unknown::<BatchVerifyReq>(json!({"tokens":[],"extra":true}), true);
    assert_unknown::<TokenToVerify>(json!({"token_b64":"x","extra":true}), true);
    assert_unknown::<BatchVerifyResp>(
        json!({"results":[],"successful":0,"failed":0,"processing_time_ms":0,"throughput":0.0,"extra":true}),
        true,
    );
    assert_unknown::<VerifyResult>(
        json!({"status":"success","verified_at":0,"extra":true}),
        true,
    );
    assert_unknown::<VouchProof>(
        json!({"voucher_id":"v","vouchee_id":"u","timestamp":1,"signature":"s","voucher_pubkey_b64":"p","extra":true}),
        true,
    );
    assert_unknown::<SybilProof>(json!({"type":"none","extra":true}), true);
    assert_unknown::<KeyDiscoveryResp>(
        json!({"issuer_id":"i","current_epoch":1,"valid_epochs":[],"epoch_duration_sec":1,"voprf":{"suite":"s","kid":"k","pubkey":"p"},"extra":true}),
        true,
    );
    assert_unknown::<VoprfKeyInfo>(
        json!({"suite":"s","kid":"k","pubkey":"p","extra":true}),
        true,
    );
    assert_unknown::<PublicKeyInfo>(
        with_unknown(&PublicKeyInfo {
            token_key_id: "kid".into(),
            token_type: "type".into(),
            rfc9474_variant: "variant".into(),
            modulus_bits: 2048,
            pubkey_spki_b64: "spki".into(),
            issuer_id: "issuer".into(),
            valid_from: 1,
            valid_until: 2,
            audience: None,
            spend_policy: "single_use".into(),
            max_uses: None,
        }),
        true,
    );

    assert_unknown::<PublicIssueReq>(json!({"blinded_msg_b64":"x","extra":true}), false);
    assert_unknown::<PublicBatchIssueReq>(json!({"blinded_msgs":[],"extra":true}), false);
    assert_unknown::<GraphIssuanceReplayAuthorityDiscoveryV1>(
        with_unknown(&GraphIssuanceReplayAuthorityDiscoveryV1 {
            authority_id: "authority".into(),
            v4_scope_digest_tombstones: vec![],
        }),
        false,
    );
    assert_unknown::<GraphIssuanceDiscoveryV2>(with_unknown(&graph_issuance_discovery()), false);
    assert_unknown::<GraphIssuancePolicyDiscoveryV2>(
        with_unknown(&GraphIssuancePolicyDiscoveryV2 {
            issuance_policy_id: "policy".into(),
            graph_id: "graph".into(),
            keyset_id: "keyset".into(),
            descriptor_id: "descriptor".into(),
            budget_id: "budget".into(),
            budget_limit: 1,
            quantity: 1,
            admission_state: ExchangeAdmissionStateV2::Disabled,
            authorization_scheme: "hmac_sha256".into(),
            authorization_scope_digest_b64: None,
        }),
        false,
    );
    assert_unknown::<ExchangeReceiptKeyInfo>(
        with_unknown(&receipt_key("exchange_receipt_active")),
        false,
    );
    assert_unknown::<ExchangeDiscoveryV2>(with_unknown(&exchange_discovery()), false);
    assert_unknown::<ExchangeGraphDiscoveryV2>(with_unknown(&vector_graph()), false);
    assert_unknown::<ExchangeDescriptorDiscoveryV2>(with_unknown(&vector_descriptor()), false);
    assert_unknown::<ExchangeKeysetDiscoveryV2>(with_unknown(&vector_keyset()), false);
    assert_unknown::<ExchangeTransitionSlotDiscoveryV2>(
        with_unknown(&vector_transition().source_slots[0]),
        false,
    );
    assert_unknown::<ExchangeTransitionDiscoveryV2>(with_unknown(&vector_transition()), false);
}

#[test]
fn key_discovery_json_order_and_omission_are_frozen() {
    let base = KeyDiscoveryResp {
        issuer_id: "issuer:test".into(),
        current_epoch: 7,
        valid_epochs: vec![6, 7],
        epoch_duration_sec: 86_400,
        voprf: VoprfKeyInfo {
            suite: "suite".into(),
            kid: "kid".into(),
            pubkey: "pubkey".into(),
        },
        public: vec![],
        exchange: None,
        graph_issuance: None,
    };
    assert_eq!(
        serde_json::to_string(&base).unwrap(),
        r#"{"issuer_id":"issuer:test","current_epoch":7,"valid_epochs":[6,7],"epoch_duration_sec":86400,"voprf":{"suite":"suite","kid":"kid","pubkey":"pubkey"},"public":[]}"#
    );

    let full = KeyDiscoveryResp {
        exchange: Some(exchange_discovery()),
        graph_issuance: Some(graph_issuance_discovery()),
        ..base
    };
    assert_eq!(
        serde_json::to_string(&full).unwrap(),
        r#"{"issuer_id":"issuer:test","current_epoch":7,"valid_epochs":[6,7],"epoch_duration_sec":86400,"voprf":{"suite":"suite","kid":"kid","pubkey":"pubkey"},"public":[],"exchange":{"active_graph":{"profile_id":"v2","graph_id":"graph","descriptors":[],"keysets":[],"transitions":[]},"retained_graphs":[],"active_receipt_key":{"key_id":"receipt","algorithm":"Ed25519","purpose":"exchange_receipt_active","public_key_b64":"public","valid_from":1,"valid_until":2},"retained_receipt_keys":[]},"graph_issuance":{"version":2,"policies":[],"replay_authority":{"authority_id":"authority","v4_scope_digest_tombstones":[]}}}"#
    );
}

#[test]
fn fully_populated_key_discovery_json_vector_is_frozen() {
    const VECTOR: &str = r#"{"issuer_id":"issuer:vector","current_epoch":42,"valid_epochs":[40,41,42],"epoch_duration_sec":86400,"voprf":{"suite":"VOPRF-P256-SHA256","kid":"voprf-kid","pubkey":"voprf-pubkey"},"public":[{"token_key_id":"public-kid","token_type":"public_bearer","rfc9474_variant":"RSABSSA-SHA384-PSS-Deterministic","modulus_bits":2048,"pubkey_spki_b64":"public-spki","issuer_id":"issuer:vector","valid_from":100,"valid_until":200,"audience":"public-audience","spend_policy":"single_use"}],"exchange":{"active_graph":{"profile_id":"freebird/public-bearer-exchange/v2","graph_id":"graph-vector","descriptors":[{"descriptor_id":"descriptor-source","profile_id":"freebird/public-bearer-exchange/v2","issuer_id":"issuer:vector","token_key_id":"exchange-source-kid","audience":"exchange-audience","pubkey_spki_b64":"exchange-source-spki","suite":"RSABSSA-SHA384-PSS-Deterministic","valid_from":100,"valid_until":200},{"descriptor_id":"descriptor-target","profile_id":"freebird/public-bearer-exchange/v2","issuer_id":"issuer:vector","token_key_id":"exchange-target-kid","audience":"exchange-audience","pubkey_spki_b64":"exchange-target-spki","suite":"RSABSSA-SHA384-PSS-Deterministic","valid_from":100,"valid_until":200}],"keysets":[{"keyset_id":"keyset-source","descriptor_ids":["descriptor-source"]},{"keyset_id":"keyset-target","descriptor_ids":["descriptor-target"]}],"transitions":[{"transition_id":"transition-accepting","source_keyset_id":"keyset-source","target_keyset_id":"keyset-target","source_slots":[{"descriptor_id":"descriptor-source","slot_id":"input","class":"bearer","quantity":1}],"output_slots":[{"descriptor_id":"descriptor-target","slot_id":"output","class":"bearer","quantity":1}],"budget_id":"budget-accepting","budget_limit":10,"admission_state":"accepting_new"},{"transition_id":"transition-recovery","source_keyset_id":"keyset-source","target_keyset_id":"keyset-target","source_slots":[{"descriptor_id":"descriptor-source","slot_id":"input","class":"bearer","quantity":1}],"output_slots":[{"descriptor_id":"descriptor-target","slot_id":"output","class":"bearer","quantity":1}],"budget_id":"budget-recovery","budget_limit":11,"admission_state":"recovery_only"},{"transition_id":"transition-disabled","source_keyset_id":"keyset-source","target_keyset_id":"keyset-target","source_slots":[{"descriptor_id":"descriptor-source","slot_id":"input","class":"bearer","quantity":1}],"output_slots":[{"descriptor_id":"descriptor-target","slot_id":"output","class":"bearer","quantity":1}],"budget_id":"budget-disabled","budget_limit":12,"admission_state":"disabled"}]},"retained_graphs":[],"active_receipt_key":{"key_id":"receipt-active","algorithm":"Ed25519","purpose":"exchange_receipt_active","public_key_b64":"receipt-active-public","valid_from":100,"valid_until":200},"retained_receipt_keys":[{"key_id":"receipt-retained","algorithm":"Ed25519","purpose":"exchange_receipt_retained","public_key_b64":"receipt-retained-public","valid_from":50,"valid_until":150}]},"graph_issuance":{"version":2,"policies":[{"issuance_policy_id":"issuance-policy","graph_id":"graph-vector","keyset_id":"keyset-target","descriptor_id":"descriptor-target","budget_id":"issuance-budget","budget_limit":9,"quantity":1,"admission_state":"recovery_only","authorization_scheme":"hmac_sha256","authorization_scope_digest_b64":"scope-vector"}],"replay_authority":{"authority_id":"authority-vector","v4_scope_digest_tombstones":["scope-tombstone"]}}}"#;

    let discovery: KeyDiscoveryResp = serde_json::from_str(VECTOR).unwrap();
    assert_eq!(serde_json::to_string(&discovery).unwrap(), VECTOR);
    assert_eq!(discovery.public.len(), 1);
    assert_eq!(discovery.public[0].max_uses, None);
    assert!(!VECTOR.contains("\"max_uses\""));

    let vector_with_max_uses = VECTOR.replacen(
        "\"spend_policy\":\"single_use\"",
        "\"spend_policy\":\"single_use\",\"max_uses\":3",
        1,
    );
    let discovery_with_max_uses: KeyDiscoveryResp =
        serde_json::from_str(&vector_with_max_uses).unwrap();
    assert_eq!(discovery_with_max_uses.public[0].max_uses, Some(3));
    assert_eq!(
        serde_json::to_string(&discovery_with_max_uses).unwrap(),
        vector_with_max_uses
    );
    let states: Vec<_> = discovery
        .exchange
        .as_ref()
        .unwrap()
        .active_graph
        .transitions
        .iter()
        .map(|transition| transition.admission_state)
        .collect();
    assert_eq!(
        states,
        vec![
            ExchangeAdmissionStateV2::AcceptingNew,
            ExchangeAdmissionStateV2::RecoveryOnly,
            ExchangeAdmissionStateV2::Disabled,
        ]
    );
}

#[test]
fn sybil_fixture_is_found_from_manifest_root_and_round_trips() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-fixtures/sybil-proofs.json");
    assert!(path.is_file(), "missing fixture at {}", path.display());
    let manifest_fixture = fs::read_to_string(path).unwrap();
    assert_eq!(
        manifest_fixture,
        include_str!("../test-fixtures/sybil-proofs.json")
    );
    let value: Value = serde_json::from_str(&manifest_fixture).unwrap();
    for variant in value["variants"].as_array().unwrap() {
        let proof: SybilProof = serde_json::from_value(variant.clone()).unwrap();
        assert_eq!(serde_json::to_value(proof).unwrap(), *variant);
    }
}

#[test]
fn downstream_style_root_facade_imports_and_type_aliases_compile() {
    let _: Option<ReplayAuthorityDiscoveryV1> = None;
    let _: Option<GraphIssuanceDiscovery> = None;
    let _: Option<GraphIssuancePolicyDiscovery> = None;
    let _: Option<ExchangeDescriptorInfoV2> = None;
    let _: Option<ExchangeGraphInfoV2> = None;
    let _: Option<ExchangeKeysetInfoV2> = None;
    let _: Option<ExchangeTransitionInfoV2> = None;
    let _: Option<ExchangeTransitionSlotInfoV2> = None;
    type DiscoveryUpdate = fn(
        &ExchangeDiscoveryV2,
        Option<&GraphIssuanceDiscoveryV2>,
        Option<&GraphIssuanceDiscoveryV2>,
    ) -> Result<(), String>;
    let _update: DiscoveryUpdate = validate_graph_issuance_discovery_v2_update;
    assert_eq!(EXCHANGE_LUA_MAX_EXACT_INTEGER, (1u64 << 53) - 1);
    assert_eq!(
        EXCHANGE_MAX_VALID_UNTIL,
        EXCHANGE_LUA_MAX_EXACT_INTEGER as i64
    );
    assert_eq!(EXCHANGE_MAX_BUDGET_LIMIT, EXCHANGE_LUA_MAX_EXACT_INTEGER);
}

#[test]
fn v2_canonical_bytes_and_ids_are_frozen() {
    let descriptor = vector_descriptor();
    assert_eq!(
        hex::encode(descriptor.canonical_descriptor_bytes().unwrap()),
        "0000002266726565626972642f7075626c69632d6265617265722d65786368616e67652f76320000000b6973737565723a74657374000000086b69643a7465737400000020525341425353412d5348413338342d5053532d44657465726d696e6973746963010000000861756469656e636500000003010203000000000000000a0000000000000014"
    );
    assert_eq!(
        descriptor.canonical_descriptor_id().unwrap(),
        "52e59d1afa1cc0572649cb021793dfd900d2ac522ee7e2d05c7a47e1d4a7e9a3"
    );

    let keyset = vector_keyset();
    assert_eq!(
        hex::encode({
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&(keyset.descriptor_ids[0].len() as u32).to_be_bytes());
            bytes.extend_from_slice(keyset.descriptor_ids[0].as_bytes());
            bytes
        }),
        "0000004035326535396431616661316363303537323634396362303231373933646664393030643261633532326565376532643035633761343765316434613765396133"
    );
    assert_eq!(
        keyset.canonical_keyset_id(),
        "17091a292fc8619e4a9f56576fa7f2d01cfd05c9c42f502c8492d1ad11cd8fec"
    );

    let transition = vector_transition();
    assert_eq!(
        hex::encode(transition.stable_contract_bytes()),
        "0000004031373039316132393266633836313965346139663536353736666137663264303163666430356339633432663530326338343932643161643131636438666563000000403232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323200000001000000403532653539643161666131636330353732363439636230323137393364666439303064326163353232656537653264303563376134376531643461376539613300000005696e7075740000000662656172657200000001000000010000004063636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363000000066f757470757400000006626561726572000000020000000b6275646765743a746573740000000000000064"
    );
    assert_eq!(
        transition.canonical_transition_id(),
        "b26ab754febf25d5a7bfd54d72c6d0c1b2ee5f53a178b2afca2e8b4c943d2e61"
    );
    assert_eq!(transition.budget_id, "budget:test");
    assert_eq!(
        transition.budget_contract_bytes(),
        transition.stable_contract_bytes()
    );

    let graph = vector_graph();
    assert_eq!(
        hex::encode(graph.canonical_graph_bytes()),
        "0000002266726565626972642f7075626c69632d6265617265722d65786368616e67652f7632000000403137303931613239326663383631396534613966353635373666613766326430316366643035633963343266353032633834393264316164313163643866656300000040323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232320000004062323661623735346665626632356435613762666435346437326336643063316232656535663533613137386232616663613265386234633934336432653631"
    );
    assert_eq!(
        graph.canonical_graph_id(),
        "3b2e375fb6edf94e14f3e779a0e0db6a4db5d27111cb7b19a4eac6f96e355fb0"
    );
    assert_eq!(
        receipt_key("exchange_receipt_active")
            .canonical_key_id()
            .unwrap(),
        "4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0"
    );
    let receipt_public =
        Base64UrlUnpadded::decode_vec(&receipt_key("exchange_receipt_active").public_key_b64)
            .unwrap();
    assert_eq!(
        hex::encode(receipt_public),
        "0707070707070707070707070707070707070707070707070707070707070707"
    );
}

#[test]
fn v2_admission_state_is_excluded_from_identity() {
    let transition = vector_transition();
    let mut recovery = transition.clone();
    recovery.admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
    let mut disabled = transition.clone();
    disabled.admission_state = ExchangeAdmissionStateV2::Disabled;
    assert_eq!(
        transition.canonical_transition_id(),
        recovery.canonical_transition_id()
    );
    assert_eq!(
        transition.canonical_transition_id(),
        disabled.canonical_transition_id()
    );
    assert_eq!(
        transition.budget_contract_bytes(),
        recovery.budget_contract_bytes()
    );

    let graph = vector_graph();
    let mut lifecycle = graph.clone();
    lifecycle.transitions[0].admission_state = ExchangeAdmissionStateV2::Disabled;
    assert_eq!(graph.canonical_graph_id(), lifecycle.canonical_graph_id());
}

#[test]
fn unsorted_multi_element_ordering_changes_v2_canonical_outputs() {
    let mut descriptor_a = vector_descriptor();
    descriptor_a.descriptor_id = "z".repeat(64);
    let mut descriptor_b = vector_descriptor();
    descriptor_b.descriptor_id = "a".repeat(64);
    let descriptors = [descriptor_a, descriptor_b];
    assert_eq!(descriptors.len(), 2);
    assert!(descriptors[0].descriptor_id > descriptors[1].descriptor_id);
    let mut descriptor_membership = ExchangeKeysetDiscoveryV2 {
        keyset_id: String::new(),
        descriptor_ids: descriptors
            .iter()
            .map(|descriptor| descriptor.descriptor_id.clone())
            .collect(),
    };
    descriptor_membership.keyset_id = descriptor_membership.canonical_keyset_id();
    let descriptor_bytes = descriptor_membership.descriptor_ids.clone();
    descriptor_membership.descriptor_ids.swap(0, 1);
    assert_ne!(
        descriptor_bytes, descriptor_membership.descriptor_ids,
        "the deliberately unsorted descriptor membership must be order-bearing"
    );
    assert_ne!(
        descriptor_membership.keyset_id,
        descriptor_membership.canonical_keyset_id()
    );

    let mut graph = vector_graph();
    let second_keyset = ExchangeKeysetDiscoveryV2 {
        keyset_id: "0".repeat(64),
        descriptor_ids: vec!["d".repeat(64)],
    };
    graph.keysets.push(second_keyset);
    let mut second_transition = vector_transition();
    second_transition.transition_id = "a-transition".into();
    second_transition.budget_id = "budget:second".into();
    graph.transitions.push(second_transition);
    let graph_bytes = graph.canonical_graph_bytes();
    let graph_id = graph.canonical_graph_id();
    graph.keysets.swap(0, 1);
    assert_ne!(graph_bytes, graph.canonical_graph_bytes());
    assert_ne!(graph_id, graph.canonical_graph_id());
    graph.keysets.swap(0, 1);
    graph.transitions.swap(0, 1);
    assert_ne!(graph_bytes, graph.canonical_graph_bytes());
    assert_ne!(graph_id, graph.canonical_graph_id());

    let mut transition = vector_transition();
    transition
        .source_slots
        .push(ExchangeTransitionSlotDiscoveryV2 {
            descriptor_id: "0".repeat(64),
            slot_id: "input-second".into(),
            class: "bearer".into(),
            quantity: 1,
        });
    transition
        .output_slots
        .push(ExchangeTransitionSlotDiscoveryV2 {
            descriptor_id: "a".repeat(64),
            slot_id: "output-second".into(),
            class: "bearer".into(),
            quantity: 1,
        });
    let transition_bytes = transition.stable_contract_bytes();
    let transition_id = transition.canonical_transition_id();
    transition.source_slots.swap(0, 1);
    assert_ne!(transition_bytes, transition.stable_contract_bytes());
    assert_ne!(transition_id, transition.canonical_transition_id());
    transition.source_slots.swap(0, 1);
    transition.output_slots.swap(0, 1);
    assert_ne!(transition_bytes, transition.stable_contract_bytes());
    assert_ne!(transition_id, transition.canonical_transition_id());
}

#[test]
fn validation_error_and_first_error_precedence_vectors_are_frozen() {
    let invalid_bounds = ExchangeDiscoveryV2 {
        active_graph: ExchangeGraphDiscoveryV2 {
            profile_id: "wrong".into(),
            graph_id: String::new(),
            descriptors: vec![],
            keysets: vec![],
            transitions: vec![],
        },
        retained_graphs: vec![],
        active_receipt_key: receipt_key("wrong-purpose"),
        retained_receipt_keys: vec![],
    };
    assert_eq!(
        freebird_common::api::validate_exchange_discovery_v2("issuer:test", &invalid_bounds)
            .unwrap_err(),
        "invalid V2 exchange graph bounds"
    );

    let mut invalid_descriptor = vector_graph();
    invalid_descriptor.descriptors[0].descriptor_id = "bad".into();
    assert_eq!(
        freebird_common::api::validate_exchange_discovery_v2(
            "issuer:test",
            &ExchangeDiscoveryV2 {
                active_graph: invalid_descriptor,
                retained_graphs: vec![],
                active_receipt_key: receipt_key("exchange_receipt_active"),
                retained_receipt_keys: vec![],
            },
        )
        .unwrap_err(),
        "invalid descriptor id"
    );

    let invalid_issuance = GraphIssuanceDiscoveryV2 {
        version: 1,
        policies: vec![GraphIssuancePolicyDiscoveryV2 {
            issuance_policy_id: "policy".into(),
            graph_id: "graph".into(),
            keyset_id: "keyset".into(),
            descriptor_id: "descriptor".into(),
            budget_id: "budget".into(),
            budget_limit: 0,
            quantity: 0,
            admission_state: ExchangeAdmissionStateV2::AcceptingNew,
            authorization_scheme: "unknown".into(),
            authorization_scope_digest_b64: Some("scope".into()),
        }],
        replay_authority: GraphIssuanceReplayAuthorityDiscoveryV1 {
            authority_id: "bad".into(),
            v4_scope_digest_tombstones: vec![],
        },
    };
    assert_eq!(
        freebird_common::api::validate_graph_issuance_discovery_v2(
            &exchange_discovery(),
            &invalid_issuance,
        )
        .unwrap_err(),
        "invalid graph issuance discovery bounds"
    );
    assert_eq!(
        receipt_key("exchange_receipt_active")
            .canonical_key_id()
            .unwrap(),
        "4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0"
    );
    let bad_receipt = ExchangeReceiptKeyInfo {
        public_key_b64: "not-base64".into(),
        ..receipt_key("exchange_receipt_active")
    };
    assert_eq!(
        bad_receipt.canonical_key_id().unwrap_err(),
        "invalid base64url"
    );
}
