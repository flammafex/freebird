// issuer/src/routes/metadata.rs
use crate::multi_key_voprf::MultiKeyVoprfCore;
use crate::AppStateWithSybil;
use axum::{extract::State, Json};
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
pub async fn keys_handler(State((state, voprf)): State<SharedState>) -> Json<KeyDiscoveryResp> {
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
        },
        public: state
            .public_issuer
            .as_ref()
            .map(|issuer| vec![issuer.metadata().clone()])
            .unwrap_or_default(),
    })
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
