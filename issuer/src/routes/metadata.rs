// issuer/src/routes/metadata.rs
use crate::multi_key_voprf::MultiKeyVoprfCore;
use crate::AppStateWithSybil;
use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use std::sync::Arc;

// Define the response structures (moved from old main.rs)
#[derive(Serialize)]
pub struct WellKnown {
    issuer_id: String,
    voprf: VoprfInfo,
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
) -> Result<Json<V4KeyDiscovery>, StatusCode> {
    Ok(Json(key_discovery(&state, &voprf).await?))
}

async fn key_discovery(
    state: &AppStateWithSybil,
    voprf: &MultiKeyVoprfCore,
) -> Result<V4KeyDiscovery, StatusCode> {
    Ok(V4KeyDiscovery {
        issuer_id: state.issuer_id.clone(),
        current_epoch: state.current_epoch(),
        valid_epochs: state.valid_epochs(),
        epoch_duration_sec: state.epoch_duration_sec,
        voprf: VoprfInfo {
            suite: "VOPRF-P256-SHA256".into(),
            kid: voprf.active_kid().await,
            pubkey: voprf.active_pubkey_b64().await,
        },
    })
}

#[derive(Serialize)]
pub struct V4KeyDiscovery {
    issuer_id: String,
    current_epoch: u32,
    valid_epochs: Vec<u32>,
    epoch_duration_sec: u64,
    voprf: VoprfInfo,
}
