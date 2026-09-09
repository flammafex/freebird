// SPDX-License-Identifier: Apache-2.0 OR MIT

//! V7-only direct native bearer issuance routes.

use crate::routes::batch_issue::MAX_BATCH_SIZE;
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
    NativeBearerV7BatchIssueReq, NativeBearerV7BatchIssueResp, NativeBearerV7IssueReq,
    NativeBearerV7IssueResp, SybilInfo, SybilProof,
};
use freebird_common::tls_enforcement::ValidatedClientIp;
use freebird_crypto::{V7BlindMessage, V7KeyIdentity, V7TokenKeyId};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, instrument, warn};

#[cfg(test)]
#[path = "v7_preflight_tests.rs"]
mod v7_preflight_tests;

type StateTuple = (
    Arc<AppStateWithSybil>,
    Arc<crate::multi_key_voprf::MultiKeyVoprfCore>,
);

const SINGLE_BINDING_DOMAIN: &str = "freebird:native-bearer-v7:issue:v1";
const BATCH_BINDING_DOMAIN: &str = "freebird:native-bearer-v7:issue-batch:v1";

#[instrument(
    name = "issue_native_bearer_v7",
    skip(state, _voprf, headers, connect_info, validated_ip, req)
)]
pub async fn handle(
    State((state, _voprf)): State<StateTuple>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
    headers: HeaderMap,
    Json(req): Json<NativeBearerV7IssueReq>,
) -> Result<Response, (StatusCode, String)> {
    req.validate().map_err(|_| invalid_message())?;
    let issuer = state.native_bearer_v7.clone();
    let identity = resolve_identity(&issuer, &req.token_key_id)?;
    let message = decode_message(&req.blinded_msg_b64)?;
    issuer
        .preflight_at(
            &identity,
            &message,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(preflight_error)?;
    let client_data = extract_client_data(connect_info, state.behind_proxy, &headers, validated_ip);
    let sybil_info = verify_sybil(
        &state,
        req.sybil_proof.as_ref(),
        SybilRequestContext {
            client_data: Some(client_data),
            request_binding: Some(single_request_binding(
                &state.issuer_id,
                &req.token_key_id,
                &req.blinded_msg_b64,
            )),
            allow_registered_user: false,
        },
    )?;
    let signature = issuer.sign(&identity, &message).await.map_err(|error| {
        error!(error = ?error, "V7 native bearer blind signing failed");
        signing_error(&error)
    })?;

    Ok(Json(NativeBearerV7IssueResp {
        blind_signature_b64: Base64UrlUnpadded::encode_string(signature.as_bytes()),
        token_key_id: req.token_key_id,
        issuer_id: state.issuer_id.clone(),
        sybil_info,
    })
    .into_response())
}

#[instrument(
    name = "issue_native_bearer_v7_batch",
    skip(state, _voprf, headers, connect_info, validated_ip, req)
)]
pub async fn handle_batch(
    State((state, _voprf)): State<StateTuple>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
    headers: HeaderMap,
    Json(req): Json<NativeBearerV7BatchIssueReq>,
) -> Result<Response, (StatusCode, String)> {
    req.validate().map_err(|_| invalid_message())?;
    let batch_size = req.blinded_msgs_b64.len();
    if batch_size > MAX_BATCH_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("batch size {batch_size} exceeds maximum {MAX_BATCH_SIZE}"),
        ));
    }
    let issuer = state.native_bearer_v7.clone();
    let identity = resolve_identity(&issuer, &req.token_key_id)?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let messages = req
        .blinded_msgs_b64
        .iter()
        .map(|value| {
            let message = decode_message(value)?;
            issuer
                .preflight_at(&identity, &message, now)
                .map_err(preflight_error)?;
            Ok(message)
        })
        .collect::<Result<Vec<_>, (StatusCode, String)>>()?;
    let client_data = extract_client_data(connect_info, state.behind_proxy, &headers, validated_ip);
    let sybil_info = verify_sybil(
        &state,
        req.sybil_proof.as_ref(),
        SybilRequestContext {
            client_data: Some(client_data),
            request_binding: Some(batch_request_binding(
                &state.issuer_id,
                &req.token_key_id,
                &req.blinded_msgs_b64,
            )),
            allow_registered_user: false,
        },
    )?;

    let start = Instant::now();
    let mut signatures = Vec::with_capacity(batch_size);
    for message in &messages {
        let signature = issuer.sign(&identity, message).await.map_err(|error| {
            error!(error = ?error, "V7 native bearer batch blind signing failed");
            signing_error(&error)
        })?;
        signatures.push(Base64UrlUnpadded::encode_string(signature.as_bytes()));
    }
    let processing_time_ms = start.elapsed().as_millis() as u64;
    let throughput = if processing_time_ms == 0 {
        0.0
    } else {
        (batch_size as f64 / processing_time_ms as f64) * 1000.0
    };

    Ok(Json(NativeBearerV7BatchIssueResp {
        blind_signatures_b64: signatures,
        token_key_id: req.token_key_id,
        issuer_id: state.issuer_id.clone(),
        successful: batch_size,
        failed: 0,
        processing_time_ms,
        throughput,
        sybil_info,
    })
    .into_response())
}

fn resolve_identity(
    issuer: &crate::native_bearer_v7::NativeBearerV7Issuer,
    requested: &str,
) -> Result<V7KeyIdentity, (StatusCode, String)> {
    let requested_bytes = hex::decode(requested).map_err(|_| invalid_key_id())?;
    let requested = V7TokenKeyId::from_bytes(&requested_bytes).map_err(|_| invalid_key_id())?;
    if requested != *issuer.binding().token_key_id() {
        return Err((StatusCode::BAD_REQUEST, "token_key_not_active".into()));
    }
    Ok(issuer.identity().clone())
}

fn invalid_key_id() -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, "invalid token_key_id".into())
}

fn single_request_binding(issuer_id: &str, token_key_id: &str, blinded_message: &str) -> String {
    format!("{SINGLE_BINDING_DOMAIN}:{issuer_id}:{token_key_id}:{blinded_message}")
}

fn decode_message(value: &str) -> Result<V7BlindMessage, (StatusCode, String)> {
    let bytes = Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid blinded message".into()))?;
    V7BlindMessage::from_bytes(&bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid blinded message".into()))
}

fn invalid_message() -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, "invalid blinded message".into())
}

fn preflight_error(error: crate::v7_signers::V7PreflightError) -> (StatusCode, String) {
    match error {
        crate::v7_signers::V7PreflightError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "V7 signer temporarily unavailable".into(),
        ),
        crate::v7_signers::V7PreflightError::InvalidRepresentative => invalid_message(),
    }
}

fn signing_error(error: &anyhow::Error) -> (StatusCode, String) {
    if let Some(error) = error.downcast_ref::<crate::v7_signers::V7PreflightError>() {
        preflight_error(*error)
    } else {
        (StatusCode::BAD_REQUEST, "blind signing failed".into())
    }
}

fn verify_sybil(
    state: &AppStateWithSybil,
    proof: Option<&SybilProof>,
    ctx: SybilRequestContext,
) -> Result<Option<SybilInfo>, (StatusCode, String)> {
    match (&state.sybil_checker, proof) {
        (Some(checker), Some(proof)) => {
            checker.verify_with_context(proof, &ctx).map_err(|error| {
                warn!(error = ?error, "V7 Sybil resistance check failed");
                crate::routes::issue::sybil_verification_error(&error)
            })?;
            Ok(Some(SybilInfo {
                required: true,
                passed: true,
                cost: checker.cost(),
            }))
        }
        (Some(_), None) => Err((
            StatusCode::BAD_REQUEST,
            "Sybil resistance proof required".into(),
        )),
        (None, Some(_)) => Ok(None),
        (None, None) => Ok(None),
    }
}

fn batch_request_binding(
    issuer_id: &str,
    token_key_id: &str,
    blinded_elements: &[String],
) -> String {
    use base64ct::Base64UrlUnpadded;
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for element in blinded_elements {
        hasher.update((element.len() as u64).to_le_bytes());
        hasher.update(element.as_bytes());
    }
    let digest = hasher.finalize();
    format!(
        "{BATCH_BINDING_DOMAIN}:{issuer_id}:{token_key_id}:{}:{}",
        blinded_elements.len(),
        Base64UrlUnpadded::encode_string(&digest[..16])
    )
}
