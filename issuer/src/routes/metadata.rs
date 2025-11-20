// issuer/src/routes/metadata.rs
use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;
use crate::multi_key_voprf::MultiKeyVoprfCore;
use crate::AppStateWithSybil;

// Define the response structures (moved from old main.rs)
#[derive(Serialize)]
pub struct WellKnown {
    issuer_id: String,
    voprf: VoprfInfo,
}

#[derive(Serialize)]
struct VoprfInfo {
    suite: String,
    kid: String,
    pubkey: String,
    exp_sec: u64,
}

// Define the type alias for the state we injected in startup.rs
// It must match exactly: (Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>)
type SharedState = (
    Arc<AppStateWithSybil>,
    Arc<MultiKeyVoprfCore>,
);

// The handler function itself (moved from old main.rs)
pub async fn well_known_handler(
    State((state, voprf)): State<SharedState>
) -> Json<WellKnown> {
    let active_kid = voprf.active_kid().await;
    let active_pubkey = voprf.active_pubkey_b64().await;

    Json(WellKnown {
        issuer_id: state.issuer_id.clone(),
        voprf: VoprfInfo {
            suite: "OPRF(P-256, SHA-256)-verifiable".into(),
            kid: active_kid,
            pubkey: active_pubkey,
            exp_sec: state.exp_sec,
        },
    })
}