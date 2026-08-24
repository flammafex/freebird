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

type StateTuple = (
    Arc<AppStateWithSybil>,
    Arc<crate::multi_key_voprf::MultiKeyVoprfCore>,
);

const SINGLE_BINDING_DOMAIN: &str = "freebird:native-bearer-v7:issue:v1";
const BATCH_BINDING_DOMAIN: &str = "freebird:native-bearer-v7:issue-batch:v1";

#[instrument(
    name = "issue_native_bearer_v7",
    skip(state, _voprf, headers, connect_info)
)]
pub async fn handle(
    State((state, _voprf)): State<StateTuple>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
    headers: HeaderMap,
    Json(req): Json<NativeBearerV7IssueReq>,
) -> Result<Response, (StatusCode, String)> {
    req.validate()
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let issuer = state.native_bearer_v7.clone();
    let identity = resolve_identity(&issuer, &req.token_key_id)?;
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
    let message = decode_message(&req.blinded_msg_b64)?;
    let signature = issuer.sign(&identity, &message).await.map_err(|error| {
        error!(error = ?error, "V7 native bearer blind signing failed");
        (StatusCode::BAD_REQUEST, "blind signing failed".to_string())
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
    skip(state, _voprf, headers, connect_info)
)]
pub async fn handle_batch(
    State((state, _voprf)): State<StateTuple>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    validated_ip: Option<Extension<ValidatedClientIp>>,
    headers: HeaderMap,
    Json(req): Json<NativeBearerV7BatchIssueReq>,
) -> Result<Response, (StatusCode, String)> {
    req.validate()
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let batch_size = req.blinded_msgs_b64.len();
    if batch_size > MAX_BATCH_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("batch size {batch_size} exceeds maximum {MAX_BATCH_SIZE}"),
        ));
    }
    let issuer = state.native_bearer_v7.clone();
    let identity = resolve_identity(&issuer, &req.token_key_id)?;
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
    for blinded_msg in &req.blinded_msgs_b64 {
        let message = decode_message(blinded_msg)?;
        let signature = issuer.sign(&identity, &message).await.map_err(|error| {
            error!(error = ?error, "V7 native bearer batch blind signing failed");
            (StatusCode::BAD_REQUEST, "blind signing failed".to_string())
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

fn verify_sybil(
    state: &AppStateWithSybil,
    proof: Option<&SybilProof>,
    ctx: SybilRequestContext,
) -> Result<Option<SybilInfo>, (StatusCode, String)> {
    match (&state.sybil_checker, proof) {
        (Some(checker), Some(proof)) => {
            checker.verify_with_context(proof, &ctx).map_err(|error| {
                warn!(error = ?error, "V7 Sybil resistance check failed");
                (
                    StatusCode::FORBIDDEN,
                    "Sybil resistance verification failed".into(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use base64ct::Encoding;
    use freebird_common::api::NativeBearerV7IssueReq;
    use std::sync::Arc;

    fn state() -> State<StateTuple> {
        State((
            Arc::new(crate::AppStateWithSybil {
                issuer_id: "test-issuer".into(),
                kid: "kid".into(),
                pubkey_b64: "pubkey".into(),
                require_tls: false,
                behind_proxy: false,
                sybil_checker: None,
                invitation_system: None,
                native_bearer_v7: crate::main_state::test_native_bearer_v7(),
                native_bearer_v7_retained: vec![],
                public_issuer: None,
                exchange_engine: None,
                exchange_metadata: None,
                graph_issuance_engine: None,
                graph_issuance_metadata: None,
                native_exchange_v7: None,
                native_exchange_v7_discovery: None,
                native_graph_issuance_v7: None,
                native_graph_issuance_v7_discovery: None,
                epoch_duration_sec: 86_400,
                epoch_retention: 2,
                admin_api_key: None,
                sybil_summary: None,
            }),
            Arc::new(
                crate::multi_key_voprf::MultiKeyVoprfCore::new(
                    [7; 32],
                    "pubkey".into(),
                    "kid".into(),
                    b"test",
                )
                .unwrap(),
            ),
        ))
    }

    fn request(blinded_msg_b64: String) -> NativeBearerV7IssueReq {
        NativeBearerV7IssueReq {
            token_key_id: "01".repeat(32),
            blinded_msg_b64,
            sybil_proof: None,
        }
    }

    #[tokio::test]
    async fn handler_issues_a_valid_v7_raw384_message() {
        let blinded = Base64UrlUnpadded::encode_string(&[1; 384]);
        let response = handle(
            state(),
            None,
            None,
            HeaderMap::new(),
            Json(request(blinded)),
        )
        .await
        .expect("valid V7 request should issue");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handler_rejects_a_wrong_active_key() {
        let mut req = request(Base64UrlUnpadded::encode_string(&[1; 384]));
        req.token_key_id = "02".repeat(32);
        let error = handle(state(), None, None, HeaderMap::new(), Json(req))
            .await
            .expect_err("wrong V7 key must be rejected");
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert_eq!(error.1, "token_key_not_active");
    }

    #[tokio::test]
    async fn handler_rejects_malformed_raw384_message() {
        let error = handle(
            state(),
            None,
            None,
            HeaderMap::new(),
            Json(request("AQ".into())),
        )
        .await
        .expect_err("malformed raw384 must be rejected");
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(error.1.contains("blinded_msg_b64"));
    }

    #[test]
    fn binding_domains_are_composed_once_and_include_the_v7_key() {
        let single = single_request_binding("issuer:test", &"11".repeat(32), "blinded");
        assert_eq!(
            single,
            "freebird:native-bearer-v7:issue:v1:issuer:test:".to_string()
                + &"11".repeat(32)
                + ":blinded"
        );

        let batch = batch_request_binding(
            "issuer:test",
            &"11".repeat(32),
            &["first".into(), "second".into()],
        );
        assert_eq!(
            batch,
            format!(
                "freebird:native-bearer-v7:issue-batch:v1:issuer:test:{}:2:L_ip8B2idsSfAVu-OKO1Dg",
                "11".repeat(32)
            )
        );
    }

    #[test]
    fn rotated_v7_key_ids_cannot_reuse_a_batch_binding() {
        let messages = vec!["same-blinded-message".into()];
        assert_ne!(
            batch_request_binding("issuer:test", &"11".repeat(32), &messages),
            batch_request_binding("issuer:test", &"22".repeat(32), &messages),
        );
    }
}
