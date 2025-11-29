// issuer/src/routes/metadata.rs
use axum::{extract::State, Json};
use freebird_common::api::{KeyDiscoveryResp, VoprfKeyInfo};
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
    State((state, voprf)): State<SharedState>
) -> Json<KeyDiscoveryResp> {
    let active_kid = voprf.active_kid().await;
    let active_pubkey = voprf.active_pubkey_b64().await;

    Json(KeyDiscoveryResp {
        issuer_id: state.issuer_id.clone(),
        current_epoch: state.current_epoch(),
        valid_epochs: state.valid_epochs(),
        epoch_duration_sec: state.epoch_duration_sec,
        voprf: VoprfKeyInfo {
            suite: "OPRF(P-256, SHA-256)-verifiable".into(),
            kid: active_kid,
            pubkey: active_pubkey,
            exp_sec: state.exp_sec,
        },
    })
}

/// Federation metadata endpoint (Layer 2 Federation)
///
/// Returns information about which issuers this issuer trusts (vouches)
/// and which it has revoked. This enables ActivityPub-style federation
/// where verifiers can traverse trust graphs to make authorization decisions.
pub async fn federation_handler(
    State((state, _voprf)): State<SharedState>
) -> Json<freebird_common::federation::FederationMetadata> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Load vouches and revocations from storage
    let vouches = state.federation_store.get_vouches().await;
    let revocations = state.federation_store.get_revocations().await;

    Json(freebird_common::federation::FederationMetadata {
        issuer_id: state.issuer_id.clone(),
        vouches,
        revocations,
        updated_at: now,
        cache_ttl_secs: Some(3600), // 1 hour cache
    })
}