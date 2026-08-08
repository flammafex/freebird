// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Public verifier routes and their public-only middleware.

use axum::{
    extract::{rejection::JsonRejection, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{
    BatchVerifyReq, BatchVerifyResp, TokenToVerify, VerifierMetadataResp, VerifyReq, VerifyResp,
    VerifyResult,
};
use freebird_common::rate_limit::PublicRateLimitLayer;
use freebird_common::spend_key::{v4_spend_key, v5_spend_key};
use rayon::prelude::*;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info, instrument, warn};

use crate::readiness::{self, TokenFamily};
use crate::state::{
    compute_throughput, ensure_token_family_enabled, ensure_v4_replay_authority_ready,
    record_spend, AppState,
};
use crate::verify::{decode_token_version, verify_v4_token, verify_v5_public_token};

pub(crate) fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(readiness_handler))
        .route("/.well-known/verifier", get(verifier_metadata))
        .route("/v1/verify", post(verify_with_logging))
        .route("/v1/verify/batch", post(batch_verify))
        .route("/v1/check", post(check_with_logging))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([axum::http::header::CONTENT_TYPE])
                .max_age(Duration::from_secs(86400)),
        )
        .layer(PublicRateLimitLayer::default())
        .with_state(state)
}

// ---------- Verification metadata handler ----------
async fn verifier_metadata(State(st): State<Arc<AppState>>) -> Json<VerifierMetadataResp> {
    Json(VerifierMetadataResp {
        verifier_id: st.verifier_id.clone(),
        audience: st.audience.clone(),
        scope_digest_b64: Base64UrlUnpadded::encode_string(&st.scope_digest),
        accepted_token_versions: Some(
            st.accepted_token_families
                .iter()
                .map(|family| match family {
                    TokenFamily::V4 => "v4".to_string(),
                    TokenFamily::V5 => "v5".to_string(),
                })
                .collect(),
        ),
    })
}

// Wrapper to catch and log JSON deserialization errors
async fn verify_with_logging(
    state: State<Arc<AppState>>,
    result: Result<Json<VerifyReq>, JsonRejection>,
) -> Result<Response, (StatusCode, String)> {
    info!("/v1/verify request received");

    match result {
        Ok(Json(req)) => verify(state, Json(req)).await,
        Err(rejection) => {
            error!("JSON deserialization failed: {}", rejection);
            Err((
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON: {}", rejection),
            ))
        }
    }
}

// ---------- Verification handler ----------
#[instrument(name = "verify_token", skip_all)]
async fn verify(
    State(st): State<Arc<AppState>>,
    Json(req): Json<VerifyReq>,
) -> Result<Response, (StatusCode, String)> {
    let version = decode_token_version(&req.token_b64)?;
    ensure_token_family_enabled(version, &st.accepted_token_families)?;
    if version == freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 {
        ensure_v4_replay_authority_ready(&st).await?;
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let (spend_key, valid_until) = match version {
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 => {
            info!("Starting V4 token verification");
            let issuers = st.issuers.read().await;
            let (parsed, _issuer) = verify_v4_token(&req.token_b64, &issuers, &st.scope_digest)?;
            drop(issuers);
            let null_key =
                freebird_crypto::nullifier_key_v4(&parsed, &st.verifier_id, &st.audience).map_err(
                    |e| {
                        error!(error = ?e, "failed to derive V4 nullifier");
                        (StatusCode::BAD_REQUEST, "verification failed".to_string())
                    },
                )?;
            (v4_spend_key(&null_key), None)
        }
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V5 => {
            info!("Starting V5 public bearer verification");
            let issuers = st.issuers.read().await;
            let (parsed, key) = verify_v5_public_token(&req.token_b64, &issuers, &st.audience)?;
            drop(issuers);
            let null_key = freebird_crypto::nullifier_key_v5(&parsed).map_err(|e| {
                error!(error = ?e, "failed to derive V5 nullifier");
                (StatusCode::BAD_REQUEST, "verification failed".to_string())
            })?;
            (v5_spend_key(&null_key), Some(key.valid_until))
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "unsupported token version".to_string(),
            ))
        }
    };

    debug!("Checking replay for token");
    let spent = record_spend(st.store.as_ref(), &spend_key, valid_until)
        .await
        .map_err(|e| {
            error!("store error while recording token spend: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error".into())
        })?;

    if !spent {
        warn!("replay detected (token already used)");
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(VerifyResp {
                ok: false,
                error: Some("replay_detected".to_string()),
                verified_at: 0,
            }),
        )
            .into_response());
    }

    info!("Token verified successfully");

    Ok(Json(VerifyResp {
        ok: true,
        error: None,
        verified_at: now,
    })
    .into_response())
}

// ---------- Check handler (verify without consuming) ----------
// Wrapper to catch and log JSON deserialization errors
async fn check_with_logging(
    state: State<Arc<AppState>>,
    result: Result<Json<VerifyReq>, JsonRejection>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    info!("/v1/check request received");

    match result {
        Ok(Json(req)) => check(state, Json(req)).await,
        Err(rejection) => {
            error!("JSON deserialization failed: {}", rejection);
            Err((
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON: {}", rejection),
            ))
        }
    }
}

/// Check token validity WITHOUT consuming/recording the nullifier.
///
/// This endpoint validates the token's V4 format and private authenticator but
/// does NOT mark it as spent. Use this for:
/// - Verifying a user holds a valid Day Pass
/// - Checking token validity before a multi-step operation
/// - Rate-limiting based on token possession without consumption
///
/// The token can still be used with /v1/verify after being checked here.
#[instrument(name = "check_token", skip_all)]
async fn check(
    State(st): State<Arc<AppState>>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (StatusCode, String)> {
    let version = decode_token_version(&req.token_b64)?;
    ensure_token_family_enabled(version, &st.accepted_token_families)?;
    let issuers = st.issuers.read().await;
    match version {
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 => {
            info!("Starting V4 token check (no consumption)");
            verify_v4_token(&req.token_b64, &issuers, &st.scope_digest)?;
        }
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V5 => {
            info!("Starting V5 public bearer check (no consumption)");
            verify_v5_public_token(&req.token_b64, &issuers, &st.audience)?;
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "unsupported token version".to_string(),
            ))
        }
    }
    drop(issuers);

    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    // NOTE: We intentionally skip mark_spent() here - this is the key difference from /v1/verify
    // The token remains valid for future use with /v1/verify

    info!("Token check passed (not consumed)");

    Ok(Json(VerifyResp {
        ok: true,
        error: None,
        verified_at: now,
    }))
}

/// Maximum batch size for batch verification
const MAX_BATCH_SIZE: usize = 10_000;

/// Minimum batch size for parallel processing
const MIN_PARALLEL_BATCH_SIZE: usize = 10;

// ---------- Batch Verification Handler (V4) ----------
#[instrument(name = "batch_verify", skip_all, fields(batch_size = req.tokens.len()))]
async fn batch_verify(
    State(st): State<Arc<AppState>>,
    Json(req): Json<BatchVerifyReq>,
) -> Result<Json<BatchVerifyResp>, (StatusCode, String)> {
    let start = Instant::now();
    let batch_size = req.tokens.len();

    info!("/v1/verify/batch: size={}", batch_size);

    // --- VALIDATION ---
    if batch_size == 0 {
        return Err((StatusCode::BAD_REQUEST, "batch cannot be empty".to_string()));
    }

    if batch_size > MAX_BATCH_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "batch size {} exceeds maximum {}",
                batch_size, MAX_BATCH_SIZE
            ),
        ));
    }

    // Reject disabled families before taking issuer snapshots or doing crypto.
    let mut contains_v4 = false;
    for token in &req.tokens {
        let version = decode_token_version(&token.token_b64)?;
        ensure_token_family_enabled(version, &st.accepted_token_families)?;
        contains_v4 |= version == freebird_crypto::REDEMPTION_TOKEN_VERSION_V4;
    }
    if contains_v4 {
        // Gate the entire batch before taking any spend-store mutation path.
        ensure_v4_replay_authority_ready(&st).await?;
    }

    // Snapshot issuers map for parallel processing
    let issuers = st.issuers.read().await;
    let issuers_snapshot: HashMap<String, crate::routes::admin::IssuerInfo> = issuers.clone();
    drop(issuers);

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let runtime_handle = tokio::runtime::Handle::current();

    // Helper function to verify a single token
    let verify_one = |token_req: &TokenToVerify| -> VerifyResult {
        let version = match decode_token_version(&token_req.token_b64) {
            Ok(version) => version,
            Err((_status, msg)) => {
                return VerifyResult::Error {
                    message: msg,
                    code: "verification_failed".to_string(),
                }
            }
        };

        let (spend_key, valid_until) = match version {
            freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 => {
                let parsed = match verify_v4_token(
                    &token_req.token_b64,
                    &issuers_snapshot,
                    &st.scope_digest,
                ) {
                    Ok((parsed, _issuer)) => parsed,
                    Err((_status, msg)) => {
                        return VerifyResult::Error {
                            message: msg,
                            code: "verification_failed".to_string(),
                        };
                    }
                };
                let null_key =
                    match freebird_crypto::nullifier_key_v4(&parsed, &st.verifier_id, &st.audience)
                    {
                        Ok(key) => key,
                        Err(_) => {
                            return VerifyResult::Error {
                                message: "verification failed".to_string(),
                                code: "verification_failed".to_string(),
                            };
                        }
                    };
                (v4_spend_key(&null_key), None)
            }
            freebird_crypto::REDEMPTION_TOKEN_VERSION_V5 => {
                let (parsed, key) = match verify_v5_public_token(
                    &token_req.token_b64,
                    &issuers_snapshot,
                    &st.audience,
                ) {
                    Ok(result) => result,
                    Err((_status, msg)) => {
                        return VerifyResult::Error {
                            message: msg,
                            code: "verification_failed".to_string(),
                        };
                    }
                };
                let null_key = match freebird_crypto::nullifier_key_v5(&parsed) {
                    Ok(key) => key,
                    Err(_) => {
                        return VerifyResult::Error {
                            message: "verification failed".to_string(),
                            code: "verification_failed".to_string(),
                        };
                    }
                };
                (v5_spend_key(&null_key), Some(key.valid_until))
            }
            _ => {
                return VerifyResult::Error {
                    message: "unsupported token version".to_string(),
                    code: "verification_failed".to_string(),
                }
            }
        };

        let spent = runtime_handle
            .block_on(async { record_spend(st.store.as_ref(), &spend_key, valid_until).await });

        match spent {
            Ok(true) => VerifyResult::Success { verified_at: now },
            Ok(false) => VerifyResult::Error {
                message: "token already used".to_string(),
                code: "replay_detected".to_string(),
            },
            Err(_) => VerifyResult::Error {
                message: "store error".to_string(),
                code: "store_error".to_string(),
            },
        }
    };

    // Process tokens in parallel or sequentially based on batch size
    let results: Vec<VerifyResult> = if batch_size < MIN_PARALLEL_BATCH_SIZE {
        debug!(
            "using sequential processing for small batch (n={})",
            batch_size
        );
        req.tokens.iter().map(verify_one).collect()
    } else {
        debug!("using parallel processing for batch (n={})", batch_size);
        req.tokens.par_iter().map(verify_one).collect()
    };

    // --- AGGREGATE RESULTS ---
    let successful = results
        .iter()
        .filter(|r| matches!(r, VerifyResult::Success { .. }))
        .count();
    let failed = batch_size - successful;

    let total_time_ms = start.elapsed().as_millis() as u64;
    let throughput = compute_throughput(successful, total_time_ms);

    info!(
        "Batch verify metrics: total={}ms, success={}/{}, throughput={:.0} tok/s",
        total_time_ms, successful, batch_size, throughput
    );

    Ok(Json(BatchVerifyResp {
        results,
        successful,
        failed,
        processing_time_ms: total_time_ms,
        throughput,
    }))
}

// ---------- Health check handlers ----------
async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Process liveness only. Dependencies intentionally do not affect this endpoint.
async fn readiness_handler(State(st): State<Arc<AppState>>) -> impl axum::response::IntoResponse {
    let issuers = st.issuers.read().await.clone();
    let metadata = st.metadata.read().await.clone();
    let report = readiness::evaluate(
        &st.store_health,
        &issuers,
        &metadata,
        &st.issuer_urls,
        &st.accepted_token_families,
        st.refresh_interval,
        Some(&st.replay_authority),
    )
    .await;
    if report.ready() {
        (StatusCode::OK, Json(serde_json::json!({"status": "ready"})))
    } else {
        // Never expose dependency, issuer, or key details on the public endpoint.
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "not_ready"})),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{check, router, verify};
    use crate::readiness::{MetadataStatus, StoreHealth, TokenFamily};
    use crate::replay_authority::{ReplayAuthorityConfig, ReplayAuthorityHealth};
    use crate::routes::admin::IssuerInfo;
    use crate::state::AppState;
    use crate::store::{InMemoryStore, SpendStore};
    use axum::{body::to_bytes, body::Body, http::Request, http::StatusCode, Json};
    use base64ct::{Base64UrlUnpadded, Encoding};
    use freebird_common::api::VerifyReq;
    use freebird_crypto::{
        build_private_token_input, build_redemption_token, build_scope_digest, Client,
        RedemptionToken, Server, VOPRF_CONTEXT_V4,
    };
    use serde_json::{json, Value};
    use std::{
        collections::HashMap,
        sync::Arc,
        time::{Duration, Instant},
    };
    use tokio::sync::RwLock;

    const ISSUER_ID: &str = "issuer:test:verify-contract";
    const ISSUER_KID: &str = "kid:test:verify-contract";
    const VERIFIER_ID: &str = "verifier:test:verify-contract";
    const AUDIENCE: &str = "verify-contract";
    use tower::ServiceExt;

    fn cold_start_state() -> Arc<AppState> {
        let store: Arc<dyn SpendStore> = Arc::new(InMemoryStore::default());
        Arc::new(AppState {
            issuers: Arc::new(RwLock::new(HashMap::new())),
            store: store.clone(),
            verifier_id: "verifier:test".into(),
            audience: "test".into(),
            scope_digest: [0; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
            epoch_duration_sec: 86_400,
            epoch_retention: 2,
            issuer_urls: vec!["http://issuer.test/.well-known/issuer".into()],
            metadata: Arc::new(RwLock::new(HashMap::<String, MetadataStatus>::new())),
            accepted_token_families: vec![TokenFamily::V4],
            refresh_interval: Duration::from_secs(600),
            store_health: StoreHealth::new(store.clone()),
            replay_authority: Arc::new(
                ReplayAuthorityHealth::new(
                    store,
                    ReplayAuthorityConfig {
                        graph_issuer_urls: vec![],
                        probe_interval: Duration::from_secs(30),
                        max_staleness: Duration::from_secs(60),
                    },
                    [0; 32],
                )
                .unwrap(),
            ),
            store_is_memory: true,
        })
    }

    fn issue_v4_token(sk: [u8; 32], nonce: [u8; 32]) -> RedemptionToken {
        let server = Server::from_secret_key(sk, VOPRF_CONTEXT_V4).unwrap();
        let scope_digest = build_scope_digest(VERIFIER_ID, AUDIENCE).unwrap();
        let input =
            build_private_token_input(ISSUER_ID, ISSUER_KID, &nonce, &scope_digest).unwrap();
        let mut client = Client::new(VOPRF_CONTEXT_V4);
        let (blinded, blind_state) = client.blind(&input).unwrap();
        let evaluation = server.evaluate_with_proof(&blinded).unwrap();
        let authenticator = client
            .finalize(
                blind_state,
                &evaluation,
                &Base64UrlUnpadded::encode_string(&server.public_key_sec1_compressed()),
            )
            .unwrap();
        RedemptionToken {
            nonce,
            scope_digest,
            kid: ISSUER_KID.to_string(),
            issuer_id: ISSUER_ID.to_string(),
            authenticator: Base64UrlUnpadded::decode_vec(&authenticator)
                .unwrap()
                .try_into()
                .unwrap(),
        }
    }

    fn token_b64(token: &RedemptionToken) -> String {
        Base64UrlUnpadded::encode_string(&build_redemption_token(token).unwrap())
    }

    fn verification_state(sk: [u8; 32]) -> Arc<AppState> {
        let store: Arc<dyn SpendStore> = Arc::new(InMemoryStore::default());
        let authority = Arc::new(
            ReplayAuthorityHealth::new(
                store.clone(),
                ReplayAuthorityConfig {
                    graph_issuer_urls: vec![],
                    probe_interval: Duration::from_secs(30),
                    max_staleness: Duration::from_secs(60),
                },
                [0; 32],
            )
            .unwrap(),
        );
        let server = Server::from_secret_key(sk, VOPRF_CONTEXT_V4).unwrap();
        let scope_digest = build_scope_digest(VERIFIER_ID, AUDIENCE).unwrap();
        let issuer = IssuerInfo {
            pubkey_bytes: server.public_key_sec1_compressed().to_vec(),
            kid: ISSUER_KID.to_string(),
            ctx: VOPRF_CONTEXT_V4.to_vec(),
            verification_key: Some(sk),
            deprecated_verification_keys: HashMap::new(),
            public_keys: HashMap::new(),
            last_refreshed: Some(Instant::now()),
        };
        Arc::new(AppState {
            issuers: Arc::new(RwLock::new(HashMap::from([(
                ISSUER_ID.to_string(),
                issuer,
            )]))),
            store: store.clone(),
            verifier_id: VERIFIER_ID.to_string(),
            audience: AUDIENCE.to_string(),
            scope_digest,
            epoch_duration_sec: 86_400,
            epoch_retention: 2,
            issuer_urls: vec![],
            metadata: Arc::new(RwLock::new(HashMap::new())),
            accepted_token_families: vec![TokenFamily::V4],
            refresh_interval: Duration::from_secs(600),
            store_health: StoreHealth::new(store.clone()),
            replay_authority: authority,
            store_is_memory: true,
        })
    }

    #[tokio::test]
    async fn cold_start_keeps_health_live_and_readiness_unavailable() {
        let response = router(cold_start_state())
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let response = router(cold_start_state())
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn public_router_preserves_cors_layer_and_public_paths() {
        let response = router(cold_start_state())
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/health")
                    .header("origin", "https://client.example")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
    }

    #[tokio::test]
    async fn replay_response_is_structured_and_check_never_reports_replay() {
        let sk = [0x41u8; 32];
        let state = verification_state(sk);
        let token = token_b64(&issue_v4_token(sk, [0x01u8; 32]));
        let request = || {
            Json(VerifyReq {
                token_b64: token.clone(),
            })
        };

        verify(axum::extract::State(state.clone()), request())
            .await
            .unwrap();
        let replay = verify(axum::extract::State(state.clone()), request())
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        let replay_body = to_bytes(replay.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&replay_body).unwrap(),
            json!({
                "ok": false,
                "error": "replay_detected",
                "verified_at": 0
            })
        );

        let checked = check(axum::extract::State(state), request()).await.unwrap();
        assert!(checked.0.error.is_none());
        assert!(checked.0.ok);
        assert_ne!(checked.0.error.as_deref(), Some("replay_detected"));
    }

    #[tokio::test]
    async fn invalid_authentication_remains_generic_and_is_not_replay() {
        let sk = [0x42u8; 32];
        let state = verification_state(sk);
        let mut token = issue_v4_token(sk, [0x02u8; 32]);
        token.authenticator[0] ^= 1;
        let result = verify(
            axum::extract::State(state),
            Json(VerifyReq {
                token_b64: token_b64(&token),
            }),
        )
        .await;

        let Err((status, message)) = result else {
            panic!("invalid authentication unexpectedly succeeded");
        };
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(message, "verification failed");
        assert_ne!(message, "replay_detected");
    }
}
