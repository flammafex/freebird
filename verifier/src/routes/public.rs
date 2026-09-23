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

use crate::readiness::{self, TokenFamily};
use crate::state::{
    compute_throughput, ensure_token_family_enabled, ensure_v4_replay_authority_ready,
    record_spend, v7_spend_key_for_body, v7_trust_registry, AppState,
};
use crate::store::SpendOutcome;
use crate::verify::{decode_token_version, verify_v4_token, verify_v7_public_token};

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
                    TokenFamily::V7 => "v7".to_string(),
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
        freebird_crypto::public_bearer_v7::V7_ENVELOPE_VERSION => {
            info!("Starting V7 public bearer verification");
            let trust = v7_trust_registry();
            let (parsed, entry) = verify_v7_public_token(&req.token_b64, &trust)?;
            (
                v7_spend_key_for_body(parsed.body()),
                Some(entry.valid_until),
            )
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
        SpendOutcome::Expired => {
            return Err((StatusCode::UNAUTHORIZED, "verification failed".into()));
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
/// This endpoint validates an accepted V4 or V7 token but does NOT mark it as
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
    ensure_token_family_enabled(version, &st.accepted_token_families)?;
    let issuers = st.issuers.read().await;
    match version {
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 => {
            info!("Starting V4 token check (no consumption)");
            verify_v4_token(&req.token_b64, &issuers, &st.scope_digest)?;
        }
        freebird_crypto::public_bearer_v7::V7_ENVELOPE_VERSION => {
            info!("Starting V7 public bearer check (no consumption)");
            let trust = v7_trust_registry();
            verify_v7_public_token(&req.token_b64, &trust)?;
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
    valid_until: Option<i64>,
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

    let (spend_key, valid_until) = match version {
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
            (v4_spend_key(&null_key), None)
        }
        freebird_crypto::public_bearer_v7::V7_ENVELOPE_VERSION => {
            let trust = v7_trust_registry();
            let (parsed, entry) = match verify_v7_public_token(token_b64, &trust) {
                Ok(result) => result,
                Err((_status, msg)) => {
                    return Err(VerifyResult::Error {
                        message: msg,
                        code: "verification_failed".to_string(),
                    });
                }
            };
            (
                v7_spend_key_for_body(parsed.body()),
                Some(entry.valid_until),
            )
        }
        _ => {
            return Err(VerifyResult::Error {
                message: "unsupported token version".to_string(),
                code: "verification_failed".to_string(),
            });
        }
    };

    Ok(PreparedSpend {
        spend_key,
        valid_until,
    })
}

fn spend_result(result: anyhow::Result<SpendOutcome>, now: i64) -> VerifyResult {
    match result {
        Ok(SpendOutcome::Fresh) => VerifyResult::Success { verified_at: now },
        Ok(SpendOutcome::Replay) => VerifyResult::Error {
            message: "token already used".to_string(),
            code: "replay_detected".to_string(),
        },
        Ok(SpendOutcome::Expired) => VerifyResult::Error {
            message: "verification failed".to_string(),
            code: "verification_failed".to_string(),
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
        record_spend(st.store.as_ref(), &prepared.spend_key, prepared.valid_until).await,
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
                    Ok(Ok(prepared)) => spend_result(
                        record_spend(store.as_ref(), &prepared.spend_key, prepared.valid_until)
                            .await,
                        now,
                    ),
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
    let v7_trust = v7_trust_registry();
    let report = readiness::evaluate(
        &st.store_health,
        &issuers,
        &v7_trust,
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
    use crate::state::{
        commit_v7_trust, AppState, V7DescriptorIdentity, V7IssuerTrustEntry, V7IssuerTrustSnapshot,
    };
    use crate::store::{InMemoryStore, SpendOutcome, SpendStore};
    use axum::{
        body::to_bytes,
        body::Body,
        http::{Request, StatusCode},
        Json,
    };
    use base64ct::{Base64UrlUnpadded, Encoding};
    use freebird_common::api::VerifyReq;
    use freebird_crypto::{
        blind_v7, build_private_token_input, build_redemption_token, build_scope_digest,
        finalize_v7, provider::software::SoftwareV7BlindRsaProvider, Client, NativeBearerV7Token,
        PublicBearerV7Body, RedemptionToken, Server, V7BodyPolicy, V7KeyIdentity, V7TokenKeyId,
        VOPRF_CONTEXT_V4,
    };
    use serde_json::{json, Value};
    use std::{
        collections::{HashMap, HashSet},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        thread::ThreadId,
        time::{Duration, Instant},
    };
    use tokio::sync::RwLock;
    static V7_ROUTE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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

    #[derive(Default)]
    struct ExpiredSpendStore;

    #[async_trait::async_trait]
    impl SpendStore for ExpiredSpendStore {
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn mark_spent(&self, _key: &str, _ttl: Option<Duration>) -> anyhow::Result<bool> {
            Ok(true)
        }

        async fn mark_spent_through(
            &self,
            _key: &str,
            _valid_until: i64,
        ) -> anyhow::Result<SpendOutcome> {
            Ok(SpendOutcome::Expired)
        }
    }

    struct SlowSpendStore {
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SpendStore for SlowSpendStore {
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn mark_spent(&self, _key: &str, _ttl: Option<Duration>) -> anyhow::Result<bool> {
            Ok(true)
        }

        async fn mark_spent_through(
            &self,
            _key: &str,
            _valid_until: i64,
        ) -> anyhow::Result<SpendOutcome> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(SpendOutcome::Fresh)
        }
    }

    #[derive(Default)]
    struct ThreadRecordingSpendStore {
        spent: Mutex<HashSet<String>>,
        mutation_threads: Mutex<Vec<ThreadId>>,
    }

    #[async_trait::async_trait]
    impl SpendStore for ThreadRecordingSpendStore {
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn mark_spent(&self, _key: &str, _ttl: Option<Duration>) -> anyhow::Result<bool> {
            Ok(true)
        }

        async fn mark_spent_through(
            &self,
            key: &str,
            _valid_until: i64,
        ) -> anyhow::Result<SpendOutcome> {
            self.mutation_threads
                .lock()
                .unwrap()
                .push(std::thread::current().id());
            tokio::task::yield_now().await;
            if self.spent.lock().unwrap().insert(key.to_owned()) {
                Ok(SpendOutcome::Fresh)
            } else {
                Ok(SpendOutcome::Replay)
            }
        }
    }

    async fn v7_route_fixture(label: &str, validity_offset: i64) -> (Arc<AppState>, String) {
        let store: Arc<dyn SpendStore> = Arc::new(InMemoryStore::default());
        v7_route_fixture_with_store(label, validity_offset, store).await
    }

    async fn v7_route_fixture_with_store(
        label: &str,
        validity_offset: i64,
        store: Arc<dyn SpendStore>,
    ) -> (Arc<AppState>, String) {
        let v7_issuer = format!(
            "issuer:test:route-v7-{}",
            V7_ROUTE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let key_id = V7TokenKeyId::new([0x71; 32]);
        let provider =
            SoftwareV7BlindRsaProvider::generate(V7KeyIdentity::new(&v7_issuer, key_id).unwrap())
                .unwrap();
        let body =
            PublicBearerV7Body::new_derived("USD", 7, &v7_issuer, key_id, [0x72; 32], [0x73; 32])
                .unwrap();
        let (blind_message, randomizer, state) = blind_v7(provider.binding(), &body).unwrap();
        let blind_signature = provider
            .blind_sign(provider.binding().identity(), &blind_message)
            .await
            .unwrap();
        let signature = finalize_v7(provider.binding(), state, &blind_signature).unwrap();
        let token = NativeBearerV7Token::new(body, randomizer, signature);

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut snapshot = V7IssuerTrustSnapshot::default();
        snapshot.by_token_key_id.insert(
            key_id,
            V7IssuerTrustEntry {
                binding: provider.binding().clone(),
                policy: V7BodyPolicy::new("USD", 7).unwrap(),
                identity: V7DescriptorIdentity {
                    profile_id: format!("route-profile:{label}"),
                    descriptor_id: format!("route-descriptor:{label}"),
                },
                valid_from: now - 60,
                valid_until: now + validity_offset,
            },
        );
        commit_v7_trust(&v7_issuer, snapshot).unwrap();

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
        let app = Arc::new(AppState {
            issuers: Arc::new(RwLock::new(HashMap::new())),
            store: store.clone(),
            verifier_id: "verifier:test:v7".into(),
            audience: "audience:test:v7".into(),
            scope_digest: [0; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
            epoch_duration_sec: 86_400,
            epoch_retention: 2,
            issuer_urls: vec![],
            metadata: Arc::new(RwLock::new(HashMap::new())),
            accepted_token_families: vec![TokenFamily::V7],
            refresh_interval: Duration::from_secs(600),
            store_health: StoreHealth::new(store),
            replay_authority: authority,
            store_is_memory: true,
        });
        (
            app,
            Base64UrlUnpadded::encode_string(&token.serialize().unwrap()),
        )
    }

    fn json_request(uri: &str, value: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .unwrap()
    }

    fn v7_batch_request(tokens: &[String]) -> Request<Body> {
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

    #[tokio::test]
    async fn v7_direct_exchange_and_graph_routes_check_verify_then_replay_through_valid_until_plus_one(
    ) {
        for label in ["direct", "exchange", "graph"] {
            // The trust entry expires one second after issuance. The verify
            // route must retain the replay marker through valid_until + 1.
            let (state, token) = v7_route_fixture(label, 1).await;
            let app = router(state);
            assert_eq!(
                app.clone()
                    .oneshot(json_request("/v1/check", json!({"token_b64": token})))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK,
                "{label} check"
            );
            assert_eq!(
                app.clone()
                    .oneshot(json_request("/v1/verify", json!({"token_b64": token})))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK,
                "{label} verify"
            );
            assert_eq!(
                app.oneshot(json_request("/v1/verify", json!({"token_b64": token})))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED,
                "{label} replay"
            );
        }
    }

    #[tokio::test]
    async fn retired_reserved_and_unknown_versions_reject_on_all_public_routes() {
        for version in [0x05_u8, 0x06, 0x99] {
            let label = format!("rejected-{version:02x}");
            let (state, token) = v7_route_fixture(&label, 60).await;
            let app = router(state);
            let encoded = Base64UrlUnpadded::encode_string(&[version, 0]);
            let check_response = app
                .clone()
                .oneshot(json_request("/v1/check", json!({"token_b64": encoded})))
                .await
                .unwrap();
            assert_eq!(
                check_response.status(),
                StatusCode::BAD_REQUEST,
                "{version:#x} check"
            );

            let verify_response = app
                .clone()
                .oneshot(json_request("/v1/verify", json!({"token_b64": encoded})))
                .await
                .unwrap();
            assert_eq!(
                verify_response.status(),
                StatusCode::BAD_REQUEST,
                "{version:#x} verify"
            );

            let mixed = json!({"tokens": [
                {"token_b64": token},
                {"token_b64": encoded}
            ]});
            let batch_response = app
                .clone()
                .oneshot(json_request("/v1/verify/batch", mixed))
                .await
                .unwrap();
            assert_eq!(
                batch_response.status(),
                StatusCode::BAD_REQUEST,
                "{version:#x} mixed batch"
            );

            // The rejected requests must not have consumed the valid token or
            // altered the V7 trust registry.
            assert_eq!(
                app.oneshot(json_request("/v1/verify", json!({"token_b64": token})))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK,
                "{version:#x} mutation check"
            );
        }
    }

    #[tokio::test]
    async fn successful_v7_batch_is_replayed_as_ten_rejections() {
        let (state, first) = v7_route_fixture("batch-00", 60).await;
        let mut tokens = vec![first];
        for index in 1..10 {
            let (_, token) = v7_route_fixture(&format!("batch-{index:02}"), 60).await;
            tokens.push(token);
        }
        let app = router(state);
        let response = app
            .clone()
            .oneshot(v7_batch_request(&tokens))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["successful"], 10);
        assert_eq!(body["failed"], 0);

        let replay = app.oneshot(v7_batch_request(&tokens)).await.unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(replay.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["successful"], 0);
        assert_eq!(body["failed"], 10);
        assert!(body["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|result| { result["status"] == "error" && result["code"] == "replay_detected" }));
    }

    #[tokio::test]
    async fn large_mixed_v7_batch_preserves_input_order_and_outcomes() {
        let (state, first) = v7_route_fixture("ordered-first", 60).await;
        let (_, second) = v7_route_fixture("ordered-second", 60).await;
        let invalid = Base64UrlUnpadded::encode_string(&[
            freebird_crypto::public_bearer_v7::V7_ENVELOPE_VERSION,
            0,
        ]);
        let tokens = vec![
            first.clone(),
            invalid.clone(),
            first.clone(),
            second.clone(),
            invalid.clone(),
            second.clone(),
            first.clone(),
            second.clone(),
            invalid,
            first.clone(),
            second,
            first,
        ];

        let response = router(state)
            .oneshot(v7_batch_request(&tokens))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["successful"], 2);
        assert_eq!(body["failed"], 10);

        let results = body["results"].as_array().unwrap();
        for index in [1, 4, 8] {
            assert_eq!(results[index]["status"], "error");
            assert_eq!(results[index]["code"], "verification_failed");
        }
        for group in [&[0usize, 2, 6, 9, 11][..], &[3usize, 5, 7, 10][..]] {
            let fresh = group
                .iter()
                .filter(|&&index| results[index]["status"] == "success")
                .count();
            assert_eq!(fresh, 1);
            for &index in group {
                if results[index]["status"] != "success" {
                    assert_eq!(results[index]["code"], "replay_detected");
                }
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn large_v7_batch_does_not_require_blocking_runtime_driving() {
        let runtime_thread = std::thread::current().id();
        let tracking = Arc::new(ThreadRecordingSpendStore::default());
        let store: Arc<dyn SpendStore> = tracking.clone();
        let (state, token) = v7_route_fixture_with_store("constrained-runtime", 60, store).await;
        let response = router(state)
            .oneshot(v7_batch_request(&vec![token; 10]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["successful"], 1);
        assert_eq!(body["failed"], 9);
        let results = body["results"].as_array().unwrap();
        assert_eq!(
            results
                .iter()
                .filter(|result| result["status"] == "success")
                .count(),
            1
        );
        assert!(results.iter().all(|result| {
            result["status"] == "success" || result["code"] == "replay_detected"
        }));
        assert_eq!(tracking.mutation_threads.lock().unwrap().len(), 10);
        assert!(tracking
            .mutation_threads
            .lock()
            .unwrap()
            .iter()
            .all(|thread| *thread == runtime_thread));
    }

    #[tokio::test]
    async fn large_v7_batch_bounds_replay_mutation_concurrency() {
        let tracking = Arc::new(SlowSpendStore {
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        });
        let store: Arc<dyn SpendStore> = tracking.clone();
        let (state, token) = v7_route_fixture_with_store("bounded-mutation", 60, store).await;
        let response = router(state)
            .oneshot(v7_batch_request(&vec![token; 64]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["successful"], 64);
        assert_eq!(body["failed"], 0);
        assert!(tracking.max_active.load(Ordering::SeqCst) <= 32);
        assert!(tracking.max_active.load(Ordering::SeqCst) > 1);
    }

    #[tokio::test]
    async fn expired_v7_token_is_rejected_by_public_verify_route() {
        let (state, token) = v7_route_fixture("expired", -1).await;
        let response = router(state)
            .oneshot(json_request("/v1/verify", json!({"token_b64": token})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn storage_expiry_is_generic_on_single_verify_route() {
        let store: Arc<dyn SpendStore> = Arc::new(ExpiredSpendStore);
        let (state, token) = v7_route_fixture_with_store("storage-expired-single", 60, store).await;

        let Err((status, message)) = verify(
            axum::extract::State(state),
            Json(VerifyReq { token_b64: token }),
        )
        .await
        else {
            panic!("storage expiry unexpectedly succeeded");
        };

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(message, "verification failed");
        assert!(!message.contains("expired"));
    }

    #[tokio::test]
    async fn storage_expiry_is_generic_in_batch_verify_results() {
        let store: Arc<dyn SpendStore> = Arc::new(ExpiredSpendStore);
        let (state, token) = v7_route_fixture_with_store("storage-expired-batch", 60, store).await;

        let response = router(state)
            .oneshot(v7_batch_request(&[token]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["successful"], 0);
        assert_eq!(body["failed"], 1);
        assert_eq!(body["results"][0]["status"], "error");
        assert_eq!(body["results"][0]["code"], "verification_failed");
        assert_eq!(body["results"][0]["message"], "verification failed");
        assert_ne!(body["results"][0]["message"], "expired");
    }
}
