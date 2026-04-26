use crate::routes::batch_issue::MAX_BATCH_SIZE;
use crate::routes::issue::extract_client_data;
use crate::AppStateWithSybil;
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{
    PublicBatchIssueReq, PublicBatchIssueResp, PublicIssueReq, PublicIssueResp, SybilInfo,
    SybilProof,
};
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
    headers: HeaderMap,
    Json(req): Json<PublicIssueReq>,
) -> Result<Json<PublicIssueResp>, (StatusCode, String)> {
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

    let _client_data = extract_client_data(connect_info, state.behind_proxy, &headers);
    let sybil_info = verify_sybil(&state, req.sybil_proof.as_ref())?;
    validate_requested_key(&public_issuer, req.token_key_id.as_deref())?;
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
    }))
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
    headers: HeaderMap,
    Json(req): Json<PublicBatchIssueReq>,
) -> Result<Json<PublicBatchIssueResp>, (StatusCode, String)> {
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

    let _client_data = extract_client_data(connect_info, state.behind_proxy, &headers);
    let sybil_info = verify_sybil(&state, req.sybil_proof.as_ref())?;
    validate_requested_key(&public_issuer, req.token_key_id.as_deref())?;

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
    }))
}

fn verify_sybil(
    state: &AppStateWithSybil,
    proof: Option<&SybilProof>,
) -> Result<Option<SybilInfo>, (StatusCode, String)> {
    match (&state.sybil_checker, proof) {
        (Some(checker), Some(proof)) => {
            debug!("verifying Sybil proof for V5 public issuance");
            checker.verify(proof).map_err(|e| {
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

fn validate_requested_key(
    public_issuer: &crate::public_tokens::PublicTokenIssuer,
    requested: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    let Some(requested) = requested else {
        return Ok(());
    };
    let decoded = freebird_crypto::decode_token_key_id_hex(requested)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid token_key_id".to_string()))?;
    if decoded != *public_issuer.token_key_id() {
        return Err((
            StatusCode::BAD_REQUEST,
            "requested token_key_id is not active".to_string(),
        ));
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
