// issuer/src/routes/metadata.rs
use crate::multi_key_voprf::MultiKeyVoprfCore;
use crate::AppStateWithSybil;
use axum::{extract::State, http::StatusCode, Json};
use freebird_common::api::{V4ReplayAuthorityDiscovery, V7KeyDiscoveryResp, V7VoprfKeyInfo};
use serde::Serialize;
use std::sync::Arc;

// Define the response structures (moved from old main.rs)
#[derive(Serialize)]
pub struct WellKnown {
    issuer_id: String,
    voprf: VoprfInfo,
    native_bearer_v7: freebird_common::api::NativeBearerV7KeyInfo,
    native_bearer_v7_retained: Vec<freebird_common::api::NativeBearerV7KeyInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sybil: Option<crate::routes::admin::SybilConfigSummary>,
}

#[derive(Serialize)]
struct VoprfInfo {
    suite: String,
    kid: String,
    pubkey: String,
}

// Define the type alias for the state we injected in startup.rs
// It must match exactly: (Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>)
type SharedState = (Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>);

/// Stable authority-only metadata path consumed by V4 replay health checks.
pub const REPLAY_AUTHORITY_DISCOVERY_ROUTE: &str = "/.well-known/replay-authority";

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
        native_bearer_v7: state.native_bearer_v7.metadata().clone(),
        native_bearer_v7_retained: state.native_bearer_v7_retained.clone(),
        sybil: state.sybil_summary.clone(),
    })
}

/// Key discovery endpoint for epoch-based key rotation.
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
) -> Result<Json<V7KeyDiscoveryResp>, StatusCode> {
    Ok(Json(v7_discovery(&state, &voprf).await?))
}

/// Return the durable V4 replay-authority container separately from the strict
/// V7 issuer-key discovery document.  The verifier's authority health client
/// consumes this legacy-shaped contract; V7 trust refresh must never consume
/// it or see descriptors from retired protocol families.
pub async fn replay_authority_handler(
    State((state, _)): State<SharedState>,
) -> Result<Json<V4ReplayAuthorityDiscovery>, StatusCode> {
    let authority = state
        .replay_authority
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    authority
        .discovery(state.issuer_id.clone())
        .await
        .map(Json)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

async fn v7_discovery(
    state: &AppStateWithSybil,
    voprf: &MultiKeyVoprfCore,
) -> Result<V7KeyDiscoveryResp, StatusCode> {
    Ok(V7KeyDiscoveryResp {
        issuer_id: state.issuer_id.clone(),
        current_epoch: state.current_epoch(),
        valid_epochs: state.valid_epochs(),
        epoch_duration_sec: state.epoch_duration_sec,
        voprf: V7VoprfKeyInfo {
            suite: "VOPRF-P256-SHA256".into(),
            kid: voprf.active_kid().await,
            pubkey: voprf.active_pubkey_b64().await,
        },
        native_bearer_v7: state.native_bearer_v7.metadata().clone(),
        native_bearer_v7_retained: state.native_bearer_v7_retained.clone(),
        native_exchange_v7: state.native_exchange_v7_discovery.clone(),
        native_graph_issuance_v7: state.native_graph_issuance_v7_discovery.clone(),
    })
}
