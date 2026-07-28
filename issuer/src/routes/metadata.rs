// issuer/src/routes/metadata.rs
use crate::multi_key_voprf::MultiKeyVoprfCore;
use crate::AppStateWithSybil;
use axum::{extract::State, http::StatusCode, Json};
use freebird_common::api::{KeyDiscoveryResp, PublicKeyInfo, VoprfKeyInfo};
use serde::Serialize;
use std::sync::Arc;

// Define the response structures (moved from old main.rs)
#[derive(Serialize)]
pub struct WellKnown {
    issuer_id: String,
    voprf: VoprfInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    public: Option<PublicModeInfo>,
}

#[derive(Serialize)]
struct VoprfInfo {
    suite: String,
    kid: String,
    pubkey: String,
}

#[derive(Serialize)]
struct PublicModeInfo {
    token_type: String,
    token_key_id: String,
    rfc9474_variant: String,
    modulus_bits: u16,
    spend_policy: String,
}

// Define the type alias for the state we injected in startup.rs
// It must match exactly: (Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>)
type SharedState = (Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>);

// The handler function itself (moved from old main.rs)
pub async fn well_known_handler(State((state, voprf)): State<SharedState>) -> Json<WellKnown> {
    let active_kid = voprf.active_kid().await;
    let active_pubkey = voprf.active_pubkey_b64().await;

    Json(WellKnown {
        issuer_id: state.issuer_id.clone(),
        voprf: VoprfInfo {
            suite: "OPRF(P-256, SHA-256)-verifiable".into(),
            kid: active_kid,
            pubkey: active_pubkey,
        },
        public: state
            .public_issuer
            .as_ref()
            .map(|issuer| public_mode_info(issuer.metadata())),
    })
}

/// Key discovery endpoint for epoch-based key rotation
///
/// Returns current epoch information and valid epoch range for clients
/// to derive and validate MAC keys independently.
///
/// This enables clients to:
/// - Verify token metadata binding without trusting the issuer
/// - Detect if issuer tries to modify token metadata (kid, exp, issuer_id)
/// - Validate epoch is within acceptable range during verification
pub async fn keys_handler(
    State((state, voprf)): State<SharedState>,
) -> Result<Json<KeyDiscoveryResp>, StatusCode> {
    let active_kid = voprf.active_kid().await;
    let active_pubkey = voprf.active_pubkey_b64().await;
    let graph_issuance = match state.graph_issuance_engine.as_ref() {
        Some(engine) => Some(
            engine
                .discovery_from_durable()
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        ),
        None => None,
    };

    Ok(Json(KeyDiscoveryResp {
        issuer_id: state.issuer_id.clone(),
        current_epoch: state.current_epoch(),
        valid_epochs: state.valid_epochs(),
        epoch_duration_sec: state.epoch_duration_sec,
        voprf: VoprfKeyInfo {
            suite: "OPRF(P-256, SHA-256)-verifiable".into(),
            kid: active_kid,
            pubkey: active_pubkey,
        },
        public: state
            .public_issuer
            .as_ref()
            .map(|issuer| vec![issuer.metadata().clone()])
            .unwrap_or_default(),
        exchange: state.exchange_metadata.clone(),
        graph_issuance,
    }))
}

fn public_mode_info(metadata: &PublicKeyInfo) -> PublicModeInfo {
    PublicModeInfo {
        token_type: metadata.token_type.clone(),
        token_key_id: metadata.token_key_id.clone(),
        rfc9474_variant: metadata.rfc9474_variant.clone(),
        modulus_bits: metadata.modulus_bits,
        spend_policy: metadata.spend_policy.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freebird_common::api::{
        ExchangeDiscoveryV2, ExchangeGraphDiscoveryV2, ExchangeReceiptKeyInfo,
    };

    #[tokio::test]
    async fn key_discovery_publishes_only_the_configured_v2_exchange_container() {
        let exchange = ExchangeDiscoveryV2 {
            active_graph: ExchangeGraphDiscoveryV2 {
                profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V2.into(),
                graph_id: "a".repeat(64),
                descriptors: vec![],
                keysets: vec![],
                transitions: vec![],
            },
            retained_graphs: vec![],
            active_receipt_key: ExchangeReceiptKeyInfo {
                key_id: "b".repeat(64),
                algorithm: "Ed25519".into(),
                purpose: "exchange_receipt_active".into(),
                public_key_b64: "AQ".into(),
                valid_from: 1,
                valid_until: 2,
            },
            retained_receipt_keys: vec![],
        };
        let state = Arc::new(crate::AppStateWithSybil {
            issuer_id: "issuer:test".into(),
            kid: "kid".into(),
            pubkey_b64: "pubkey".into(),
            require_tls: false,
            behind_proxy: false,
            sybil_checker: None,
            invitation_system: None,
            public_issuer: None,
            exchange_engine: None,
            exchange_metadata: Some(exchange.clone()),
            graph_issuance_engine: None,
            graph_issuance_metadata: None,
            epoch_duration_sec: 86_400,
            epoch_retention: 2,
            admin_api_key: None,
        });
        let voprf = Arc::new(
            MultiKeyVoprfCore::new([7; 32], "pubkey".into(), "kid".into(), b"test").unwrap(),
        );

        let response = keys_handler(State((state, voprf))).await.unwrap().0;
        assert_eq!(response.exchange, Some(exchange));
        assert!(response
            .exchange
            .as_ref()
            .is_some_and(|exchange| exchange.active_graph.profile_id.ends_with("/v2")));
    }
}
