use crate::routes::batch_issue::{batch_request_binding, MAX_BATCH_SIZE};
use crate::routes::issue::extract_client_data;
use crate::sybil_resistance::SybilRequestContext;
use crate::AppStateWithSybil;
use axum::{
    extract::Extension,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{
    ErrorResp, PublicBatchIssueReq, PublicBatchIssueResp, PublicIssueReq, PublicIssueResp,
    SybilInfo, SybilProof,
};
use freebird_common::tls_enforcement::ValidatedClientIp;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, instrument, warn};

#[instrument(
    name = "issue_public_bearer_pass",
    skip(state, connect_info, headers),
    fields(has_proof = req.sybil_proof.is_some())
)]
pub async fn handle(
    State(state): State<(
        Arc<AppStateWithSybil>,
        Arc<crate::multi_key_voprf::MultiKeyVoprfCore>,
    )>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
    headers: HeaderMap,
    Json(req): Json<PublicIssueReq>,
) -> Result<Response, (StatusCode, String)> {
    info!(
        "/v1/public/issue entered; has_proof={}, sybil_configured={}",
        req.sybil_proof.is_some(),
        state.0.sybil_checker.is_some()
    );
    let state = state.0;
    let public_issuer = state.public_issuer.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "public bearer issuance is disabled".to_string(),
        )
    })?;

    if let Err(error) = validate_requested_key(&public_issuer, req.token_key_id.as_deref()) {
        return match error {
            RequestedKeyError::Invalid => {
                Err((StatusCode::BAD_REQUEST, "invalid token_key_id".to_string()))
            }
            RequestedKeyError::NotActive => Ok(token_key_not_active_response()),
        };
    }

    let client_data = extract_client_data(connect_info, state.behind_proxy, &headers, validated_ip);
    let sybil_info = verify_sybil(
        &state,
        req.sybil_proof.as_ref(),
        SybilRequestContext {
            client_data: Some(client_data),
            request_binding: Some(format!(
                "freebird:public-issue:v1:{}:{}",
                state.issuer_id, req.blinded_msg_b64
            )),
            allow_registered_user: false,
        },
    )?;
    let blinded_msg = decode_blinded_msg(&req.blinded_msg_b64, public_issuer.modulus_bytes())?;

    let blind_signature = public_issuer.blind_sign(&blinded_msg).await.map_err(|e| {
        error!(error = ?e, "V5 public bearer blind signing failed");
        (StatusCode::BAD_REQUEST, "blind signing failed".to_string())
    })?;

    Ok(Json(PublicIssueResp {
        blind_signature_b64: Base64UrlUnpadded::encode_string(&blind_signature),
        token_key_id: public_issuer.token_key_id_hex().to_string(),
        issuer_id: state.issuer_id.clone(),
        sybil_info,
    })
    .into_response())
}

#[instrument(
    name = "issue_public_bearer_pass_batch",
    skip(state, connect_info, headers),
    fields(batch_size = req.blinded_msgs.len(), has_proof = req.sybil_proof.is_some())
)]
pub async fn handle_batch(
    State(state): State<(
        Arc<AppStateWithSybil>,
        Arc<crate::multi_key_voprf::MultiKeyVoprfCore>,
    )>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
    headers: HeaderMap,
    Json(req): Json<PublicBatchIssueReq>,
) -> Result<Response, (StatusCode, String)> {
    let start = Instant::now();
    let batch_size = req.blinded_msgs.len();
    info!(
        "/v1/public/issue/batch entered; batch_size={}, has_proof={}, sybil_configured={}",
        batch_size,
        req.sybil_proof.is_some(),
        state.0.sybil_checker.is_some()
    );

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

    let state = state.0;
    let public_issuer = state.public_issuer.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "public bearer issuance is disabled".to_string(),
        )
    })?;

    if let Err(error) = validate_requested_key(&public_issuer, req.token_key_id.as_deref()) {
        return match error {
            RequestedKeyError::Invalid => {
                Err((StatusCode::BAD_REQUEST, "invalid token_key_id".to_string()))
            }
            RequestedKeyError::NotActive => Ok(token_key_not_active_response()),
        };
    }

    let client_data = extract_client_data(connect_info, state.behind_proxy, &headers, validated_ip);
    let sybil_info = verify_sybil(
        &state,
        req.sybil_proof.as_ref(),
        SybilRequestContext {
            client_data: Some(client_data),
            request_binding: Some(batch_request_binding(
                "public-issue-batch",
                &state.issuer_id,
                &req.blinded_msgs,
            )),
            allow_registered_user: false,
        },
    )?;
    let mut blind_signatures = Vec::with_capacity(batch_size);
    for blinded_msg_b64 in &req.blinded_msgs {
        let blinded_msg = decode_blinded_msg(blinded_msg_b64, public_issuer.modulus_bytes())?;
        let blind_signature = public_issuer.blind_sign(&blinded_msg).await.map_err(|e| {
            error!(error = ?e, "V5 public bearer batch blind signing failed");
            (StatusCode::BAD_REQUEST, "blind signing failed".to_string())
        })?;
        blind_signatures.push(Base64UrlUnpadded::encode_string(&blind_signature));
    }

    let total_time_ms = start.elapsed().as_millis() as u64;
    let throughput = if total_time_ms == 0 {
        0.0
    } else {
        (batch_size as f64 / total_time_ms as f64) * 1000.0
    };

    Ok(Json(PublicBatchIssueResp {
        blind_signatures,
        token_key_id: public_issuer.token_key_id_hex().to_string(),
        issuer_id: state.issuer_id.clone(),
        successful: batch_size,
        failed: 0,
        processing_time_ms: total_time_ms,
        throughput,
        sybil_info,
    })
    .into_response())
}

fn verify_sybil(
    state: &AppStateWithSybil,
    proof: Option<&SybilProof>,
    ctx: SybilRequestContext,
) -> Result<Option<SybilInfo>, (StatusCode, String)> {
    match (&state.sybil_checker, proof) {
        (Some(checker), Some(proof)) => {
            debug!("verifying Sybil proof for V5 public issuance");
            checker.verify_with_context(proof, &ctx).map_err(|e| {
                warn!("Sybil resistance check failed: {}", e);
                (
                    StatusCode::FORBIDDEN,
                    "Sybil resistance verification failed".to_string(),
                )
            })?;
            Ok(Some(SybilInfo {
                required: true,
                passed: true,
                cost: checker.cost(),
            }))
        }
        (Some(_), None) => Err((
            StatusCode::BAD_REQUEST,
            "Sybil resistance proof required".to_string(),
        )),
        (None, Some(_)) => {
            warn!("Sybil proof provided but Sybil resistance is not configured");
            Ok(None)
        }
        (None, None) => Ok(None),
    }
}

enum RequestedKeyError {
    Invalid,
    NotActive,
}

fn token_key_not_active_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResp {
            error: "token_key_not_active".to_string(),
        }),
    )
        .into_response()
}

fn validate_requested_key(
    public_issuer: &crate::public_tokens::PublicTokenIssuer,
    requested: Option<&str>,
) -> Result<(), RequestedKeyError> {
    let Some(requested) = requested else {
        return Ok(());
    };
    let decoded = freebird_crypto::decode_token_key_id_hex(requested)
        .map_err(|_| RequestedKeyError::Invalid)?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let metadata = public_issuer.metadata();
    if decoded != *public_issuer.token_key_id()
        || now < metadata.valid_from
        || now > metadata.valid_until
    {
        return Err(RequestedKeyError::NotActive);
    }
    Ok(())
}

fn decode_blinded_msg(
    blinded_msg_b64: &str,
    expected_len: usize,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let blinded_msg = Base64UrlUnpadded::decode_vec(blinded_msg_b64).map_err(|e| {
        error!("invalid base64 for blinded_msg_b64: {e:?}");
        (StatusCode::BAD_REQUEST, "invalid base64 encoding".into())
    })?;

    if blinded_msg.len() != expected_len {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "blinded_msg must be {} bytes for the active public bearer key",
                expected_len
            ),
        ));
    }

    Ok(blinded_msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PublicKeyConfig;
    use crate::multi_key_voprf::MultiKeyVoprfCore;
    use crate::sybil_resistance::{SybilRequestContext, SybilResistance};
    use crate::AppStateWithSybil;
    use axum::{body::to_bytes, extract::State};
    use freebird_crypto::{Server, VOPRF_CONTEXT_V4};
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tempfile::{tempdir, TempDir};

    struct CountingChecker {
        calls: Arc<AtomicUsize>,
    }

    impl SybilResistance for CountingChecker {
        fn verify(&self, _proof: &SybilProof) -> anyhow::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn verify_with_context(
            &self,
            _proof: &SybilProof,
            _ctx: &SybilRequestContext,
        ) -> anyhow::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn supports(&self, _proof: &SybilProof) -> bool {
            true
        }

        fn cost(&self) -> u64 {
            1
        }
    }

    fn test_state() -> (
        Arc<AppStateWithSybil>,
        Arc<MultiKeyVoprfCore>,
        Arc<AtomicUsize>,
        TempDir,
    ) {
        let issuer_id = "issuer:test:public-issue-contract";
        let sk = [0x51u8; 32];
        let server = Server::from_secret_key(sk, VOPRF_CONTEXT_V4).unwrap();
        let pubkey_b64 = Base64UrlUnpadded::encode_string(&server.public_key_sec1_compressed());
        let voprf = Arc::new(
            MultiKeyVoprfCore::new(
                sk,
                pubkey_b64.clone(),
                "kid:test:public-issue-contract".to_string(),
                VOPRF_CONTEXT_V4,
            )
            .unwrap(),
        );
        let temp = tempdir().unwrap();
        let public_issuer = Arc::new(
            crate::public_tokens::PublicTokenIssuer::load_or_generate(
                &PublicKeyConfig {
                    enabled: true,
                    sk_path: temp.path().join("public.der"),
                    metadata_path: temp.path().join("public-metadata.json"),
                    validity_secs: 3600,
                    audience: None,
                    modulus_bits: 2048,
                },
                issuer_id,
            )
            .unwrap()
            .unwrap(),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let checker: Arc<dyn SybilResistance> = Arc::new(CountingChecker {
            calls: calls.clone(),
        });
        let state = Arc::new(AppStateWithSybil {
            issuer_id: issuer_id.to_string(),
            kid: "kid:test:public-issue-contract".to_string(),
            pubkey_b64,
            require_tls: false,
            behind_proxy: false,
            sybil_checker: Some(checker),
            invitation_system: None,
            public_issuer: Some(public_issuer),
            exchange_engine: None,
            exchange_metadata: None,
            graph_issuance_engine: None,
            graph_issuance_metadata: None,
            epoch_duration_sec: 86_400,
            epoch_retention: 2,
            admin_api_key: None,
            sybil_summary: None,
        });
        (state, voprf, calls, temp)
    }

    async fn assert_stale_key_response(response: Response) {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error": "token_key_not_active"})
        );
    }

    #[tokio::test]
    async fn stale_single_key_is_rejected_before_sybil_proof_processing() {
        let (state, voprf, calls, _temp) = test_state();
        let response = handle(
            State((state, voprf)),
            None,
            None,
            HeaderMap::new(),
            Json(PublicIssueReq {
                blinded_msg_b64: "not-decoded-after-key-check".to_string(),
                token_key_id: Some("00".repeat(32)),
                sybil_proof: Some(SybilProof::None),
            }),
        )
        .await
        .unwrap();

        assert_stale_key_response(response).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stale_batch_key_is_rejected_before_sybil_proof_processing() {
        let (state, voprf, calls, _temp) = test_state();
        let response = handle_batch(
            State((state, voprf)),
            None,
            None,
            HeaderMap::new(),
            Json(PublicBatchIssueReq {
                blinded_msgs: vec!["not-decoded-after-key-check".to_string()],
                token_key_id: Some("00".repeat(32)),
                sybil_proof: Some(SybilProof::None),
            }),
        )
        .await
        .unwrap();

        assert_stale_key_response(response).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
