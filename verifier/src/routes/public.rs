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
use freebird_common::spend_key::v4_spend_key;
use futures::{stream, StreamExt};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info, instrument, warn};

use crate::readiness;
use crate::state::{compute_throughput, record_spend, AppState};
use crate::store::SpendOutcome;
use crate::verify::{decode_token_version, verify_v4_token};

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
        accepted_token_versions: Some(vec!["v4".to_string()]),
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
    if version != freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 {
        return Err((
            StatusCode::BAD_REQUEST,
            "unsupported token version".to_string(),
        ));
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let spend_key = match version {
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
            v4_spend_key(&null_key)
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "unsupported token version".to_string(),
            ))
        }
    };

    debug!("Checking replay for token");
    let spent = record_spend(st.store.as_ref(), &spend_key)
        .await
        .map_err(|e| {
            error!("store error while recording token spend: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error".into())
        })?;

    match spent {
        SpendOutcome::Fresh => {}
        SpendOutcome::Replay => {
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
/// This endpoint validates a V4 token but does NOT mark it as
/// spent. Use this for:
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
    let issuers = st.issuers.read().await;
    match version {
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 => {
            info!("Starting V4 token check (no consumption)");
            verify_v4_token(&req.token_b64, &issuers, &st.scope_digest)?;
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

struct PreparedSpend {
    spend_key: String,
}

fn prepare_spend(
    token_b64: &str,
    issuers_snapshot: &HashMap<String, crate::routes::admin::IssuerInfo>,
    verifier_id: &str,
    audience: &str,
    scope_digest: &[u8; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
) -> Result<PreparedSpend, VerifyResult> {
    let version = match decode_token_version(token_b64) {
        Ok(version) => version,
        Err((_status, msg)) => {
            return Err(VerifyResult::Error {
                message: msg,
                code: "verification_failed".to_string(),
            })
        }
    };

    let spend_key = match version {
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 => {
            let parsed = match verify_v4_token(token_b64, issuers_snapshot, scope_digest) {
                Ok((parsed, _issuer)) => parsed,
                Err((_status, msg)) => {
                    return Err(VerifyResult::Error {
                        message: msg,
                        code: "verification_failed".to_string(),
                    });
                }
            };
            let null_key = match freebird_crypto::nullifier_key_v4(&parsed, verifier_id, audience) {
                Ok(key) => key,
                Err(_) => {
                    return Err(VerifyResult::Error {
                        message: "verification failed".to_string(),
                        code: "verification_failed".to_string(),
                    });
                }
            };
            v4_spend_key(&null_key)
        }
        _ => {
            return Err(VerifyResult::Error {
                message: "unsupported token version".to_string(),
                code: "verification_failed".to_string(),
            });
        }
    };

    Ok(PreparedSpend { spend_key })
}

fn spend_result(result: anyhow::Result<SpendOutcome>, now: i64) -> VerifyResult {
    match result {
        Ok(SpendOutcome::Fresh) => VerifyResult::Success { verified_at: now },
        Ok(SpendOutcome::Replay) => VerifyResult::Error {
            message: "token already used".to_string(),
            code: "replay_detected".to_string(),
        },
        Err(_) => VerifyResult::Error {
            message: "store error".to_string(),
            code: "store_error".to_string(),
        },
    }
}

async fn verify_one_async(
    token_req: &TokenToVerify,
    issuers_snapshot: &HashMap<String, crate::routes::admin::IssuerInfo>,
    st: &AppState,
    now: i64,
) -> VerifyResult {
    let prepared = match prepare_spend(
        &token_req.token_b64,
        issuers_snapshot,
        &st.verifier_id,
        &st.audience,
        &st.scope_digest,
    ) {
        Ok(prepared) => prepared,
        Err(result) => return result,
    };

    spend_result(
        record_spend(st.store.as_ref(), &prepared.spend_key).await,
        now,
    )
}

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
    for token in &req.tokens {
        let version = decode_token_version(&token.token_b64)?;
        if version != freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 {
            return Err((
                StatusCode::BAD_REQUEST,
                "unsupported token version".to_string(),
            ));
        }
    }
    // Snapshot issuers map for parallel processing
    let issuers = st.issuers.read().await;
    let issuers_snapshot = Arc::new(issuers.clone());
    drop(issuers);

    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    // Keep small batches sequential; larger batches use ordered bounded async
    // futures so store mutations never run on a Rayon worker.
    let results: Vec<VerifyResult> = if batch_size < MIN_PARALLEL_BATCH_SIZE {
        debug!(
            "using sequential processing for small batch (n={})",
            batch_size
        );
        let mut results = Vec::with_capacity(batch_size);
        for token_req in &req.tokens {
            results.push(verify_one_async(token_req, issuers_snapshot.as_ref(), &st, now).await);
        }
        results
    } else {
        debug!(
            "using bounded async processing for batch (n={})",
            batch_size
        );
        let verifier_id = st.verifier_id.clone();
        let audience = st.audience.clone();
        let scope_digest = st.scope_digest;
        let store = st.store.clone();
        stream::iter(req.tokens.into_iter().map(|token_req| {
            let token_b64 = token_req.token_b64;
            let issuers_snapshot = issuers_snapshot.clone();
            let verifier_id = verifier_id.clone();
            let audience = audience.clone();
            let store = store.clone();
            async move {
                let prepared = tokio::task::spawn_blocking(move || {
                    prepare_spend(
                        &token_b64,
                        issuers_snapshot.as_ref(),
                        &verifier_id,
                        &audience,
                        &scope_digest,
                    )
                })
                .await;

                match prepared {
                    Ok(Ok(prepared)) => {
                        spend_result(record_spend(store.as_ref(), &prepared.spend_key).await, now)
                    }
                    Ok(Err(result)) => result,
                    Err(_) => VerifyResult::Error {
                        message: "verification failed".to_string(),
                        code: "verification_failed".to_string(),
                    },
                }
            }
        }))
        .buffered(32)
        .collect()
        .await
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
        st.refresh_interval,
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
    use crate::readiness::{MetadataStatus, StoreHealth};
    use crate::routes::admin::IssuerInfo;
    use crate::state::AppState;
    use crate::store::{InMemoryStore, SpendStore};
    use axum::{
        body::to_bytes,
        body::Body,
        http::{Request, StatusCode},
        Json,
    };
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
            refresh_interval: Duration::from_secs(600),
            store_health: StoreHealth::new(store.clone()),
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
        let server = Server::from_secret_key(sk, VOPRF_CONTEXT_V4).unwrap();
        let scope_digest = build_scope_digest(VERIFIER_ID, AUDIENCE).unwrap();
        let issuer = IssuerInfo {
            pubkey_bytes: server.public_key_sec1_compressed().to_vec(),
            kid: ISSUER_KID.to_string(),
            ctx: VOPRF_CONTEXT_V4.to_vec(),
            verification_key: Some(sk),
            deprecated_verification_keys: HashMap::new(),
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
            refresh_interval: Duration::from_secs(600),
            store_health: StoreHealth::new(store.clone()),
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

    fn json_request(uri: &str, value: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .unwrap()
    }

    fn v4_batch_request(tokens: &[String]) -> Request<Body> {
        json_request(
            "/v1/verify/batch",
            json!({
                "tokens": tokens
                    .iter()
                    .map(|token| json!({"token_b64": token}))
                    .collect::<Vec<_>>()
            }),
        )
    }

    #[tokio::test]
    async fn successful_v4_two_token_batch_is_replayed_as_two_rejections() {
        let sk = [0x43u8; 32];
        let state = verification_state(sk);
        let tokens = [
            token_b64(&issue_v4_token(sk, [0x10u8; 32])),
            token_b64(&issue_v4_token(sk, [0x11u8; 32])),
        ];
        let app = router(state);

        let response = app
            .clone()
            .oneshot(v4_batch_request(&tokens))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["successful"], 2);
        assert_eq!(body["failed"], 0);
        assert!(body["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|result| result["status"] == "success"));

        let replay = app.oneshot(v4_batch_request(&tokens)).await.unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(replay.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["successful"], 0);
        assert_eq!(body["failed"], 2);
        assert!(body["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|result| result["status"] == "error" && result["code"] == "replay_detected"));
    }

    #[tokio::test]
    async fn v4_batch_threshold_sizes_complete_without_runtime_panics() {
        for (batch_size, seed) in [(1, 0x50u8), (9, 0x60), (10, 0x70)] {
            let sk = [seed; 32];
            let state = verification_state(sk);
            let tokens: Vec<_> = (0..batch_size)
                .map(|index| token_b64(&issue_v4_token(sk, [index as u8; 32])))
                .collect();

            let response = router(state)
                .oneshot(v4_batch_request(&tokens))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "batch size {batch_size}");
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(body["successful"], batch_size, "batch size {batch_size}");
            assert_eq!(body["failed"], 0, "batch size {batch_size}");
        }
    }
}
