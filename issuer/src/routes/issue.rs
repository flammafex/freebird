// issuer/src/routes/issue.rs
//! Unified token issuance with optional Sybil resistance
//!
//! This module handles both protected and unprotected token issuance:
//! - If Sybil resistance is configured AND a proof is provided, it's verified
//! - If neither is present, tokens are issued freely (backward compatible)
//! - Mismatch cases are handled appropriately

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use tracing::{debug, error, info, instrument, warn};

use crate::multi_key_voprf::MultiKeyVoprfCore;
use crate::sybil_resistance::{ClientData, SybilRequestContext}; // Keep ClientData local to issuer/sybil if not in common
use crate::AppStateWithSybil;
use freebird_common::api::{IssueReq, IssueResp, SybilInfo, SybilProof};
use freebird_common::tls_enforcement::ValidatedClientIp;

// / Extract client information from HTTP request
// /
// / This attempts to get the real client IP address, accounting for proxies.
// / In the future, this can be extended to include browser fingerprinting.
// /
// / # Arguments
// /
// / * `connect_info` - Direct socket connection info
// / * `behind_proxy` - Whether the server is behind a reverse proxy
// / * `headers` - HTTP headers (for X-Forwarded-For, User-Agent, etc.)
// /
// / # Returns
// /
// / ClientData with available client information for entropy
pub fn extract_client_data(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    _behind_proxy: bool,
    headers: &HeaderMap,
    validated_ip: Option<Extension<ValidatedClientIp>>,
) -> ClientData {
    // Extract IP address
    let _ = (connect_info, _behind_proxy);
    let ip_addr = validated_ip.map(|Extension(ip)| ip.0.to_string());

    // Extract User-Agent as fingerprint
    // In production, you might want to hash this or combine multiple headers
    let fingerprint = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|ua| {
            // Hash the User-Agent to avoid storing it directly
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"freebird:ua:");
            hasher.update(ua.as_bytes());
            let hash = hasher.finalize();
            base64ct::Base64UrlUnpadded::encode_string(&hash[..16])
        });

    match (ip_addr, fingerprint) {
        (Some(ip), Some(fp)) => ClientData::from_ip_and_fingerprint(ip, fp),
        (Some(ip), None) => ClientData::from_ip(ip),
        (None, Some(fp)) => ClientData {
            ip_addr: None,
            fingerprint: Some(fp),
            extra: None,
        },
        (None, None) => {
            warn!("⚠️ Could not extract any client data for invitee ID generation");
            ClientData::default()
        }
    }
}

// / Unified handler supporting both protected and unprotected issuance
// /
// / # Behavior Matrix
// /
// / | Sybil Config | Proof Provided | Result |
// / |--------------|----------------|--------|
// / | None         | None           | ✅ Issue (backward compatible) |
// / | None         | Some           | ⚠️ Issue + warn (proof ignored) |
// / | Some         | None           | ❌ Reject (proof required) |
// / | Some         | Some (valid)   | ✅ Issue (after verification) |
// / | Some         | Some (invalid) | ❌ Reject (failed verification) |
// /
// / # Client Data Extraction
// /
// / When invitation-based Sybil resistance is used, this handler attempts to
// / extract client-specific information (IP address, User-Agent hash) to include
// / as additional entropy in invitee ID generation. This makes IDs more unique
// / and resistant to pre-computation attacks.
#[instrument(
    name = "issue_token",
    skip(state, voprf, connect_info, headers),
    fields(
        kid = tracing::field::Empty,
        sybil_configured = tracing::field::Empty,
        has_proof = req.sybil_proof.is_some(),
    )
)]
pub async fn handle(
    // Change: Extract tuple from State
    State((state, voprf)): State<(Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>)>,
    // Remove: voprf: Arc<MultiKeyVoprfCore> (it's now in State)
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
    headers: HeaderMap,
    Json(req): Json<IssueReq>,
) -> Result<Json<IssueResp>, (StatusCode, String)> {
    tracing::Span::current()
        .record("kid", state.kid.as_str())
        .record("sybil_configured", state.sybil_checker.is_some());

    info!(
        "📥 /v1/oprf/issue entered; kid={}, has_proof={}, sybil_configured={}",
        state.kid,
        req.sybil_proof.is_some(),
        state.sybil_checker.is_some()
    );

    // Extract client data for invitation-based Sybil resistance
    // This is only used if invitation system is configured
    let client_data = extract_client_data(connect_info, state.behind_proxy, &headers, validated_ip);
    debug!(
        "extracted client_data: has_ip={}, has_fp={}",
        client_data.ip_addr.is_some(),
        client_data.fingerprint.is_some()
    );

    // --- SYBIL RESISTANCE CHECK ---
    let sybil_info = match (&state.sybil_checker, &req.sybil_proof) {
        // Case 1: Sybil configured + proof provided → VERIFY
        (Some(checker), Some(proof)) => {
            debug!("verifying Sybil proof");

            // Note: For invitation proofs, the client_data will be used
            // internally by the invitation system for invitee ID generation.
            // Request context keeps public issuance checks tied to server-observed
            // request data where each Sybil mechanism supports it.
            let sybil_ctx = SybilRequestContext {
                client_data: Some(client_data.clone()),
                request_binding: Some(format!(
                    "freebird:issue:v1:{}:{}",
                    state.issuer_id, req.blinded_element_b64
                )),
                allow_registered_user: false,
            };
            match checker.verify_with_context(proof, &sybil_ctx) {
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

    // Perform VOPRF evaluation with multi-key support
    debug!("calling voprf.evaluate_b64()");
    let eval_result = voprf
        .evaluate_b64(&req.blinded_element_b64)
        .await // Add .await - it's async now
        .map_err(|e| {
            error!("evaluate_b64 failed: {e:?}");
            (StatusCode::BAD_REQUEST, "VOPRF evaluation failed".into())
        })?;

    // Extract token and kid from result
    let token_b64 = eval_result.token;
    let kid_used = eval_result.kid;

    debug!(
        "✅ token issued: kid={}, issuer_id={}, sybil_verified={}",
        kid_used,
        state.issuer_id,
        sybil_info.is_some(),
    );

    Ok(Json(IssueResp {
        token: token_b64,
        kid: kid_used,
        issuer_id: state.issuer_id.clone(),
        sybil_info,
    }))
}

/// Constant-time API key verification using HMAC-then-compare.
///
/// Both values are HMAC'd with a fixed key to produce equal-length digests,
/// eliminating the timing side-channel from length comparison. Mirrors the
/// helper in `routes/admin.rs` but kept local so this module does not depend
/// on private admin internals.
fn constant_time_key_verify(expected: &str, provided: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use subtle::ConstantTimeEq;

    type HmacSha256 = Hmac<Sha256>;
    let key = b"freebird-renew-key-compare";

    let mut mac_expected = HmacSha256::new_from_slice(key).unwrap();
    mac_expected.update(expected.as_bytes());
    let h_expected = mac_expected.finalize().into_bytes();

    let mut mac_provided = HmacSha256::new_from_slice(key).unwrap();
    mac_provided.update(provided.as_bytes());
    let h_provided = mac_provided.finalize().into_bytes();

    bool::from(h_expected.ct_eq(&h_provided))
}

/// Admin-authenticated token renewal endpoint.
///
/// `POST /v1/oprf/renew` is the privileged counterpart to `/v1/oprf/issue`.
/// It requires an `X-Admin-Key` header matching the server's configured
/// `admin_api_key` and ONLY accepts `RegisteredUser` sybil proofs (setting
/// `allow_registered_user: true` in the `SybilRequestContext`). This lets
/// already-registered users renew their Day Passes without a fresh invitation
/// code, while invitations still have to go through the public issue route.
///
/// Behavior matrix (differs from `handle`):
/// - No `X-Admin-Key` header / `admin_api_key` unset → 401/503
/// - Wrong admin key → 401
/// - No sybil proof → 400 (renewal is specifically for registered users)
/// - `Invitation` proof → 400 (use the public issue route)
/// - `RegisteredUser` proof (valid) → ✅ issue
/// - `RegisteredUser` proof (invalid) → 403
#[instrument(
    name = "renew_token",
    skip(state, voprf, connect_info, headers),
    fields(
        kid = tracing::field::Empty,
        sybil_configured = tracing::field::Empty,
        has_proof = req.sybil_proof.is_some(),
    )
)]
pub async fn renew(
    State((state, voprf)): State<(Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>)>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
    headers: HeaderMap,
    Json(req): Json<IssueReq>,
) -> Result<Json<IssueResp>, (StatusCode, String)> {
    tracing::Span::current()
        .record("kid", state.kid.as_str())
        .record("sybil_configured", state.sybil_checker.is_some());

    info!(
        "📥 /v1/oprf/renew entered; kid={}, has_proof={}, sybil_configured={}",
        state.kid,
        req.sybil_proof.is_some(),
        state.sybil_checker.is_some()
    );

    // --- ADMIN AUTHENTICATION ---
    let expected_key = match &state.admin_api_key {
        Some(k) => k,
        None => {
            warn!("❌ renewal requested but admin_api_key is not configured");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "renewal endpoint not configured".to_string(),
            ));
        }
    };

    let provided_key = match headers.get("x-admin-key").and_then(|h| h.to_str().ok()) {
        Some(k) => k,
        None => {
            warn!("❌ renewal request missing X-Admin-Key header");
            return Err((StatusCode::UNAUTHORIZED, "admin key required".to_string()));
        }
    };

    if !constant_time_key_verify(expected_key, provided_key) {
        warn!("❌ renewal request rejected: invalid admin key");
        return Err((StatusCode::UNAUTHORIZED, "invalid admin key".to_string()));
    }

    // --- SYBIL RESISTANCE CHECK ---
    // The renewal endpoint ONLY accepts RegisteredUser proofs. Invitations must
    // go through the public /v1/oprf/issue route.
    let sybil_info = match (&state.sybil_checker, &req.sybil_proof) {
        (Some(checker), Some(proof)) => {
            // Reject anything that isn't a RegisteredUser proof.
            match proof {
                SybilProof::RegisteredUser { .. } => {}
                SybilProof::Invitation { .. } => {
                    warn!("❌ Invitation proof sent to renewal endpoint");
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "invitation proofs must use the public issue route".to_string(),
                    ));
                }
                _ => {
                    warn!("❌ non-RegisteredUser proof sent to renewal endpoint");
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "renewal endpoint only accepts RegisteredUser proofs".to_string(),
                    ));
                }
            }

            debug!("verifying RegisteredUser sybil proof for renewal");

            let client_data =
                extract_client_data(connect_info, state.behind_proxy, &headers, validated_ip);
            let sybil_ctx = SybilRequestContext {
                client_data: Some(client_data.clone()),
                request_binding: Some(format!(
                    "freebird:renew:v1:{}:{}",
                    state.issuer_id, req.blinded_element_b64
                )),
                allow_registered_user: true,
            };
            match checker.verify_with_context(proof, &sybil_ctx) {
                Ok(()) => {
                    info!("✅ Sybil resistance check passed (renewal)");
                    Some(SybilInfo {
                        required: true,
                        passed: true,
                        cost: checker.cost(),
                    })
                }
                Err(e) => {
                    warn!("❌ Sybil resistance check failed (renewal): {}", e);
                    return Err((
                        StatusCode::FORBIDDEN,
                        "Sybil resistance verification failed".to_string(),
                    ));
                }
            }
        }

        // No proof → renewal is specifically for registered users, so reject.
        (Some(_checker), None) => {
            warn!("❌ renewal requires a RegisteredUser proof but none was provided");
            return Err((
                StatusCode::BAD_REQUEST,
                "RegisteredUser proof required for renewal".to_string(),
            ));
        }

        // Sybil resistance not configured — there is nothing to "renew" against.
        // Reject so the endpoint can't be used to bypass issuance controls.
        (None, _) => {
            warn!("❌ renewal requested but Sybil resistance is not configured");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "renewal requires Sybil resistance to be configured".to_string(),
            ));
        }
    };

    // --- VOPRF EVALUATION (same as `handle`) ---
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

    if let Some(ctx_b64) = &req.ctx_b64 {
        Base64UrlUnpadded::decode_vec(ctx_b64).map_err(|e| {
            error!("ctx_b64 decode failed: {e:?}");
            (StatusCode::BAD_REQUEST, "invalid ctx_b64 encoding".into())
        })?;
    }

    debug!("calling voprf.evaluate_b64() (renewal)");
    let eval_result = voprf
        .evaluate_b64(&req.blinded_element_b64)
        .await
        .map_err(|e| {
            error!("evaluate_b64 failed: {e:?}");
            (StatusCode::BAD_REQUEST, "VOPRF evaluation failed".into())
        })?;

    let token_b64 = eval_result.token;
    let kid_used = eval_result.kid;

    debug!(
        "✅ token renewed: kid={}, issuer_id={}, sybil_verified={}",
        kid_used,
        state.issuer_id,
        sybil_info.is_some(),
    );

    Ok(Json(IssueResp {
        token: token_b64,
        kid: kid_used,
        issuer_id: state.issuer_id.clone(),
        sybil_info,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sybil_resistance::{NoSybilResistance, ProofOfWork, SybilResistance};
    use std::sync::Arc;

    async fn mock_state(sybil_checker: Option<Arc<dyn SybilResistance>>) -> AppStateWithSybil {
        AppStateWithSybil {
            issuer_id: "test-issuer".into(),
            kid: "test-key-001".into(),
            pubkey_b64: "test-pubkey".into(),
            require_tls: false,
            behind_proxy: false,
            sybil_checker,
            invitation_system: None,
            public_issuer: None,
            exchange_engine: None,
            exchange_metadata: None,
            epoch_duration_sec: 86400,
            epoch_retention: 2,
            admin_api_key: None,
        }
    }

    #[tokio::test]
    async fn test_state_no_sybil() {
        let state = mock_state(None).await;
        assert!(state.sybil_checker.is_none());
    }

    #[tokio::test]
    async fn test_state_with_pow() {
        let state = mock_state(Some(Arc::new(ProofOfWork::new(16)))).await;
        assert!(state.sybil_checker.is_some());
    }

    #[tokio::test]
    async fn test_state_with_no_sybil_explicit() {
        let state = mock_state(Some(Arc::new(NoSybilResistance))).await;
        assert!(state.sybil_checker.is_some());
    }

    #[test]
    fn test_extract_client_data_direct() {
        use std::str::FromStr;

        let addr = SocketAddr::from_str("192.168.1.100:1234").unwrap();
        let connect_info = Some(ConnectInfo(addr));
        let headers = HeaderMap::new();

        let client_data = extract_client_data(
            connect_info,
            false,
            &headers,
            Some(Extension(ValidatedClientIp(
                "192.168.1.100".parse().unwrap(),
            ))),
        );

        assert!(client_data.ip_addr.is_some());
        assert_eq!(client_data.ip_addr.unwrap(), "192.168.1.100");
    }

    #[test]
    fn test_extract_client_data_behind_proxy() {
        use std::str::FromStr;

        let addr = SocketAddr::from_str("10.0.0.1:1234").unwrap(); // Local proxy IP
        let connect_info = Some(ConnectInfo(addr));

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.42".parse().unwrap());

        let client_data = extract_client_data(
            connect_info,
            true,
            &headers,
            Some(Extension(ValidatedClientIp(
                "203.0.113.42".parse().unwrap(),
            ))),
        );

        assert!(client_data.ip_addr.is_some());
        assert_eq!(client_data.ip_addr.unwrap(), "203.0.113.42");
    }

    #[test]
    fn test_extract_client_data_with_user_agent() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "Mozilla/5.0 (Test Browser)".parse().unwrap());

        let client_data = extract_client_data(
            None,
            false,
            &headers,
            Some(Extension(ValidatedClientIp(
                "192.168.1.100".parse().unwrap(),
            ))),
        );

        assert!(client_data.fingerprint.is_some());
        // Fingerprint should be a hash, not the raw UA
        assert!(!client_data
            .fingerprint
            .as_ref()
            .unwrap()
            .contains("Mozilla"));
    }

    // Note: Full integration tests with actual VOPRF evaluation
    // are in the integration_tests crate
}
