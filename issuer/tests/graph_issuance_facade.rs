// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Compile-only characterization of the graph issuance public facade.

use freebird_common::{
    api::GraphIssuanceDiscoveryV2,
    graph_issuance_api::{GraphIssuanceRequestV2, ReplayAuthorityProbeV1},
};
use freebird_issuer::{
    config::{GraphIssuanceAuthorizationConfig, GraphIssuanceV4VerificationKey},
    exchange::profiles::ExchangeProfileV2,
    graph_issuance::{
        validate_configured_authorizer, validate_runtime_graph_issuance_signers,
        AuthorizationClaim, DevelopmentMockAuthorizer, DisabledGraphIssuanceAuthorizer,
        GraphIssuanceAdmissionState, GraphIssuanceAuthorizer, GraphIssuanceEngine,
        GraphIssuancePolicy, GraphIssuancePolicyDocument, GraphIssuanceStore,
        GraphIssuanceV4LocalPolicy, GraphIssuanceV4TrustedIssuer, HmacGraphIssuanceAuthorizer,
        ProcessDecision, StatusDecision, V4LocalGraphIssuanceAuthorizer, POLICY_DOCUMENT_VERSION,
        REPLAY_AUTHORITY_ID_KEY,
    },
};
use std::sync::Arc;

type EngineConstructor = fn(
    &ExchangeProfileV2,
    &[ExchangeProfileV2],
    GraphIssuancePolicyDocument,
    &str,
    Arc<dyn GraphIssuanceAuthorizer>,
) -> anyhow::Result<GraphIssuanceEngine>;

type EnabledEngineConstructor = fn(
    &ExchangeProfileV2,
    &[ExchangeProfileV2],
    GraphIssuancePolicyDocument,
    &str,
    Arc<dyn GraphIssuanceAuthorizer>,
    bool,
) -> anyhow::Result<GraphIssuanceEngine>;

#[test]
fn graph_issuance_facade_exports_and_signatures_remain_stable() {
    let v4_local = GraphIssuanceV4LocalPolicy {
        verifier_id: "verifier".into(),
        audience: "audience".into(),
        trusted_issuers: vec![GraphIssuanceV4TrustedIssuer {
            issuer_id: "issuer".into(),
            key_ids: vec!["kid".into()],
        }],
    };
    let policy = GraphIssuancePolicy {
        issuance_policy_id: "policy".into(),
        graph_id: "1".repeat(64),
        keyset_id: "2".repeat(64),
        descriptor_id: "3".repeat(64),
        budget_id: "budget".into(),
        budget_limit: 1,
        quantity: 1,
        admission_state: GraphIssuanceAdmissionState::RecoveryOnly,
        authorization_scheme: "v4_local".into(),
        v4_local: Some(v4_local),
    };
    let document = GraphIssuancePolicyDocument {
        version: POLICY_DOCUMENT_VERSION.into(),
        policies: vec![policy.clone()],
    };
    let _: AuthorizationClaim = AuthorizationClaim {
        nullifier_digest: [0; 32],
        global_spend_key: None,
    };
    let _: fn(
        &std::path::Path,
        &ExchangeProfileV2,
        &[ExchangeProfileV2],
    ) -> anyhow::Result<GraphIssuancePolicyDocument> = GraphIssuancePolicyDocument::load;
    let _: fn(
        &GraphIssuancePolicyDocument,
        &ExchangeProfileV2,
        &[ExchangeProfileV2],
    ) -> anyhow::Result<()> = GraphIssuancePolicyDocument::validate;
    let _: fn(&GraphIssuancePolicyDocument, &str, &[String]) -> GraphIssuanceDiscoveryV2 =
        GraphIssuancePolicyDocument::discovery;

    let _: fn(&str) -> anyhow::Result<GraphIssuanceStore> = GraphIssuanceStore::new;
    let _: fn(&[u8; 32]) -> String = GraphIssuanceStore::probe_key;
    let _: fn(&[u8; 32]) -> String = GraphIssuanceStore::ack_key;
    let _: fn(Vec<u8>) -> anyhow::Result<HmacGraphIssuanceAuthorizer> =
        HmacGraphIssuanceAuthorizer::new;
    let _: fn(
        Vec<GraphIssuanceV4VerificationKey>,
    ) -> anyhow::Result<V4LocalGraphIssuanceAuthorizer> = V4LocalGraphIssuanceAuthorizer::new;
    let _: EngineConstructor = GraphIssuanceEngine::new;
    let _: EnabledEngineConstructor = GraphIssuanceEngine::new_with_enabled;
    let _: fn(
        &GraphIssuanceAuthorizationConfig,
        &GraphIssuancePolicyDocument,
    ) -> anyhow::Result<()> = validate_configured_authorizer;
    let _: fn(
        &ExchangeProfileV2,
        &[ExchangeProfileV2],
        &GraphIssuancePolicyDocument,
    ) -> anyhow::Result<()> = validate_runtime_graph_issuance_signers;

    fn trait_method_shape<T: GraphIssuanceAuthorizer>(
        authorizer: &T,
        policy: &GraphIssuancePolicy,
        request: &GraphIssuanceRequestV2,
    ) -> anyhow::Result<AuthorizationClaim> {
        authorizer.authorize(
            policy,
            &request.authorization_binding_digest()?,
            &request.authorization,
        )
    }

    let _ = trait_method_shape::<DevelopmentMockAuthorizer>;
    let _ = trait_method_shape::<DisabledGraphIssuanceAuthorizer>;
    fn authorizer_validation_shape<T: GraphIssuanceAuthorizer>(
        authorizer: &T,
        policy: &GraphIssuancePolicy,
    ) -> anyhow::Result<()> {
        authorizer.validate_policy_configuration(policy)
    }
    let _ = authorizer_validation_shape::<DevelopmentMockAuthorizer>;

    fn store_method_shapes(
        store: &GraphIssuanceStore,
        probe: &ReplayAuthorityProbeV1,
        scopes: &[[u8; 32]],
    ) {
        std::mem::drop(store.redis_time());
        std::mem::drop(store.initialize_replay_authority(scopes));
        std::mem::drop(store.read_replay_authority_state());
        std::mem::drop(store.replay_authority_probe(probe, "issuer"));
    }
    let store = GraphIssuanceStore::new("redis://facade-shape").unwrap();
    let probe = ReplayAuthorityProbeV1 {
        version: 1,
        authority_id: "A".repeat(43),
        probe_id: "B".repeat(43),
    };
    store_method_shapes(&store, &probe, &[[0; 32]]);

    fn engine_method_shapes(
        engine: &mut GraphIssuanceEngine,
        request: &GraphIssuanceRequestV2,
        operation: &[u8; 16],
        capability: &[u8; 32],
        probe: &ReplayAuthorityProbeV1,
    ) {
        let _ = engine.issuance_enabled();
        std::mem::drop(engine.initialize());
        std::mem::drop(engine.discovery_from_durable());
        std::mem::drop(engine.replay_authority_probe(probe, "issuer"));
        std::mem::drop(engine.readiness_check());
        std::mem::drop(engine.process(request, capability));
        std::mem::drop(engine.status(operation, capability));
    }
    let _ = engine_method_shapes;
    let _ = (
        GraphIssuanceAdmissionState::AcceptingNew,
        GraphIssuanceAdmissionState::RecoveryOnly,
        GraphIssuanceAdmissionState::Disabled,
        ProcessDecision::Conflict,
        StatusDecision::Unauthorized,
        GraphIssuanceV4LocalPolicy {
            verifier_id: String::new(),
            audience: String::new(),
            trusted_issuers: Vec::<GraphIssuanceV4TrustedIssuer>::new(),
        },
        POLICY_DOCUMENT_VERSION,
        REPLAY_AUTHORITY_ID_KEY,
        policy,
        document,
    );
}

#[test]
fn graph_issuance_children_are_not_public_facade_modules() {
    let source = include_str!("../src/graph_issuance.rs");
    for child in ["policy", "authorizer", "store", "engine"] {
        assert!(
            !source.lines().any(|line| {
                let line = line.trim();
                line == format!("pub mod {child};")
                    || line == format!("pub mod {child} {{")
                    || line == format!("pub(crate) mod {child};")
                    || line == format!("pub(crate) mod {child} {{")
            }),
            "graph issuance child {child} must remain private to the facade"
        );
    }
}
