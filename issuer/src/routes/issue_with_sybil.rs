// issuer/src/routes/issue_with_sybil.rs
//! Token issuance with Sybil resistance

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::{debug, error, info, warn};

use crate::voprf_core::VoprfCore;
use crate::AppStateWithSybil;

// Sybil resistance
use crate::sybil_resistance::{SybilProof, SybilResistance};

/// Issue request with optional Sybil resistance proof
#[derive(Deserialize, Debug)]
pub struct IssueReqWithSybil {
    /// Blinded element for VOPRF
    #[serde(alias = "blinded")]
    pub blinded_element_b64: String,

    /// Optional context
    #[serde(default)]
    pub ctx_b64: Option<String>,

    /// Sybil resistance proof (optional for backward compatibility)
    #[serde(default)]
    pub sybil_proof: Option<SybilProof>,
}

#[derive(Serialize)]
pub struct IssueRespWithSybil {
    pub token: String,
    pub proof: String,
    pub kid: String,
    pub exp: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}

#[derive(Serialize)]
pub struct SybilInfo {
    pub required: bool,
    pub passed: bool,
    pub cost: u64,
}

/// Handler with Sybil resistance
pub async fn handle_with_sybil(
    State(state): State<Arc<AppStateWithSybil>>,
    voprf: Arc<VoprfCore>,
    Json(req): Json<IssueReqWithSybil>,
) -> Result<Json<IssueRespWithSybil>, (StatusCode, String)> {
    info!(
        "🔥 /v1/oprf/issue (with sybil) entered; kid={}, has_proof={}",
        state.kid,
        req.sybil_proof.is_some()
    );

    // --- SYBIL CHECK ---
    let sybil_info = if let Some(ref checker) = state.sybil_checker {
        debug!("sybil resistance enabled, verifying proof");

        let proof = req.sybil_proof.as_ref().ok_or_else(|| {
            warn!("sybil proof required but not provided");
            (StatusCode::BAD_REQUEST, "sybil_proof required".into())
        })?;

        match checker.verify(proof) {
            Ok(()) => {
                info!("✅ sybil resistance check passed");
                Some(SybilInfo {
                    required: true,
                    passed: true,
                    cost: checker.cost(),
                })
            }
            Err(e) => {
                warn!("❌ sybil resistance check failed: {}", e);
                return Err((
                    StatusCode::FORBIDDEN,
                    format!("sybil resistance check failed: {}", e),
                ));
            }
        }
    } else {
        debug!("no sybil resistance configured, skipping check");
        None
    };

    // --- STANDARD VOPRF FLOW ---
    let blinded_bytes = Base64UrlUnpadded::decode_vec(&req.blinded_element_b64).map_err(|e| {
        error!("invalid base64 for blinded_element_b64: {e:?}");
        (StatusCode::BAD_REQUEST, "invalid base64".into())
    })?;

    if blinded_bytes.len() != 33 {
        error!("blinded_element length = {}, expected 33", blinded_bytes.len());
        return Err((
            StatusCode::BAD_REQUEST,
            "blinded_element must be 33 bytes".into(),
        ));
    }

    if let Some(ctx_b64) = &req.ctx_b64 {
        Base64UrlUnpadded::decode_vec(ctx_b64).map_err(|e| {
            error!("ctx_b64 decode failed: {e:?}");
            (StatusCode::BAD_REQUEST, "invalid ctx_b64".into())
        })?;
    }

    debug!("calling voprf.evaluate_b64()");
    let evaluated_b64 = voprf.evaluate_b64(&req.blinded_element_b64).map_err(|e| {
        error!("evaluate_b64 failed: {e:?}");
        (StatusCode::BAD_REQUEST, "invalid blinded_element".into())
    })?;

    let exp = OffsetDateTime::now_utc().unix_timestamp() + state.exp_sec as i64;

    Ok(Json(IssueRespWithSybil {
        token: evaluated_b64,
        proof: String::new(),
        kid: state.kid.clone(),
        exp,
        sybil_info,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sybil_resistance::{proof_of_work::ProofOfWork, NoSybilResistance};

    #[test]
    fn test_structure_no_sybil() {
        let state = AppStateWithSybil {
            issuer_id: "test".into(),
            kid: "test-key".into(),
            exp_sec: 3600,
            pubkey_b64: "test-pubkey".into(),
            sybil_checker: None,
        };

        assert!(state.sybil_checker.is_none());
    }

    #[test]
    fn test_structure_with_pow() {
        let state = AppStateWithSybil {
            issuer_id: "test".into(),
            kid: "test-key".into(),
            exp_sec: 3600,
            pubkey_b64: "test-pubkey".into(),
            sybil_checker: Some(Arc::new(ProofOfWork::new(16))),
        };

        assert!(state.sybil_checker.is_some());
    }

    #[test]
    fn test_structure_with_no_sybil_explicit() {
        let state = AppStateWithSybil {
            issuer_id: "test".into(),
            kid: "test-key".into(),
            exp_sec: 3600,
            pubkey_b64: "test-pubkey".into(),
            sybil_checker: Some(Arc::new(NoSybilResistance)),
        };

        assert!(state.sybil_checker.is_some());
    }
}
