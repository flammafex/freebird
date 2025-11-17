// issuer/src/routes/issue.rs
//! Unified token issuance with optional Sybil resistance
//!
//! This module handles both protected and unprotected token issuance:
//! - If Sybil resistance is configured AND a proof is provided, it's verified
//! - If neither is present, tokens are issued freely (backward compatible)
//! - Mismatch cases are handled appropriately

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::{debug, error, info, warn};

use crate::voprf_core::VoprfCore;
use crate::AppStateWithSybil;
use crate::sybil_resistance::SybilProof;

/// Universal issue request supporting both protected and unprotected modes
#[derive(Deserialize, Debug)]
pub struct IssueReq {
    /// Blinded element for VOPRF
    #[serde(alias = "blinded")]
    pub blinded_element_b64: String,

    /// Optional context (currently unused but reserved)
    #[serde(default)]
    pub ctx_b64: Option<String>,

    /// Optional Sybil resistance proof
    /// - If provided with configured Sybil resistance: verified
    /// - If provided without configured Sybil resistance: ignored with warning
    /// - If not provided but Sybil resistance required: rejected
    #[serde(default)]
    pub sybil_proof: Option<SybilProof>,
}

/// Issue response with optional Sybil information
#[derive(Serialize)]
pub struct IssueResp {
    /// Base64url-encoded evaluation token
    pub token: String,
    
    /// DLEQ proof (currently empty, reserved for future use)
    pub proof: String,
    
    /// Key identifier
    pub kid: String,
    
    /// Expiration timestamp (Unix seconds)
    pub exp: i64,

    /// Optional Sybil resistance information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}

/// Information about Sybil resistance verification
#[derive(Serialize, Debug)]
pub struct SybilInfo {
    /// Was Sybil resistance required?
    pub required: bool,
    
    /// Did the proof pass verification?
    pub passed: bool,
    
    /// Computational cost (for PoW) or time cost (for rate limiting)
    pub cost: u64,
}

/// Unified handler supporting both protected and unprotected issuance
///
/// # Behavior Matrix
///
/// | Sybil Config | Proof Provided | Result |
/// |--------------|----------------|--------|
/// | None         | None           | ✅ Issue (backward compatible) |
/// | None         | Some           | ⚠️ Issue + warn (proof ignored) |
/// | Some         | None           | ❌ Reject (proof required) |
/// | Some         | Some (valid)   | ✅ Issue (after verification) |
/// | Some         | Some (invalid) | ❌ Reject (failed verification) |
pub async fn handle(
    State(state): State<Arc<AppStateWithSybil>>,
    voprf: Arc<VoprfCore>,
    Json(req): Json<IssueReq>,
) -> Result<Json<IssueResp>, (StatusCode, String)> {
    info!(
        "📥 /v1/oprf/issue entered; kid={}, has_proof={}, sybil_configured={}",
        state.kid,
        req.sybil_proof.is_some(),
        state.sybil_checker.is_some()
    );

    // --- SYBIL RESISTANCE CHECK ---
    let sybil_info = match (&state.sybil_checker, &req.sybil_proof) {
        // Case 1: Sybil configured + proof provided → VERIFY
        (Some(checker), Some(proof)) => {
            debug!("verifying Sybil proof");
            
            match checker.verify(proof) {
                Ok(()) => {
                    info!("✅ Sybil resistance check passed");
                    Some(SybilInfo {
                        required: true,
                        passed: true,
                        cost: checker.cost(),
                    })
                }
                Err(e) => {
                    warn!("❌ Sybil resistance check failed: {}", e);
                    return Err((
                        StatusCode::FORBIDDEN,
                        "Sybil resistance verification failed".to_string(),
                    ));
                }
            }
        }

        // Case 2: Sybil configured + NO proof → REJECT
        (Some(_checker), None) => {
            warn!("❌ Sybil proof required but not provided");
            return Err((
                StatusCode::BAD_REQUEST,
                "Sybil resistance proof required".to_string(),
            ));
        }

        // Case 3: Sybil NOT configured + proof provided → WARN and proceed
        (None, Some(_proof)) => {
            warn!("⚠️ Sybil proof provided but Sybil resistance not configured (proof ignored)");
            None
        }

        // Case 4: Sybil NOT configured + NO proof → OK (backward compatible)
        (None, None) => {
            debug!("no Sybil resistance (backward compatible mode)");
            None
        }
    };

    // --- VOPRF EVALUATION (common for all cases) ---
    
    // Decode and validate blinded element
    let blinded_bytes = Base64UrlUnpadded::decode_vec(&req.blinded_element_b64).map_err(|e| {
        error!("invalid base64 for blinded_element_b64: {e:?}");
        (StatusCode::BAD_REQUEST, "invalid base64 encoding".into())
    })?;

    if blinded_bytes.len() != 33 {
        error!(
            "blinded_element wrong length: got {} bytes, expected 33",
            blinded_bytes.len()
        );
        return Err((
            StatusCode::BAD_REQUEST,
            "blinded_element must be 33 bytes (SEC1 compressed point)".into(),
        ));
    }

    // Optional context validation (decode-only, not currently used)
    if let Some(ctx_b64) = &req.ctx_b64 {
        Base64UrlUnpadded::decode_vec(ctx_b64).map_err(|e| {
            error!("ctx_b64 decode failed: {e:?}");
            (StatusCode::BAD_REQUEST, "invalid ctx_b64 encoding".into())
        })?;
    }

    // Perform VOPRF evaluation
    debug!("calling voprf.evaluate_b64()");
    let evaluated_b64 = voprf.evaluate_b64(&req.blinded_element_b64).map_err(|e| {
        error!("evaluate_b64 failed: {e:?}");
        (StatusCode::BAD_REQUEST, "VOPRF evaluation failed".into())
    })?;

    // Calculate expiration
    let exp = OffsetDateTime::now_utc().unix_timestamp() + state.exp_sec as i64;
    
    debug!(
        "✅ token issued: kid={}, exp={}, sybil_verified={}",
        state.kid,
        exp,
        sybil_info.is_some()
    );

    Ok(Json(IssueResp {
        token: evaluated_b64,
        proof: String::new(), // Reserved for future DLEQ proof inclusion
        kid: state.kid.clone(),
        exp,
        sybil_info,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sybil_resistance::{NoSybilResistance, ProofOfWork, SybilResistance};
    use std::sync::Arc;

    fn mock_state(sybil_checker: Option<Arc<dyn SybilResistance>>) -> AppStateWithSybil {
        AppStateWithSybil {
            issuer_id: "test-issuer".into(),
            kid: "test-key-001".into(),
            exp_sec: 3600,
            pubkey_b64: "test-pubkey".into(),
            require_tls: false,
            behind_proxy: false,
            sybil_checker,
        }
    }

    #[test]
    fn test_state_no_sybil() {
        let state = mock_state(None);
        assert!(state.sybil_checker.is_none());
    }

    #[test]
    fn test_state_with_pow() {
        let state = mock_state(Some(Arc::new(ProofOfWork::new(16))));
        assert!(state.sybil_checker.is_some());
    }

    #[test]
    fn test_state_with_no_sybil_explicit() {
        let state = mock_state(Some(Arc::new(NoSybilResistance)));
        assert!(state.sybil_checker.is_some());
    }

    // Note: Full integration tests with actual VOPRF evaluation
    // are in the integration_tests crate
}