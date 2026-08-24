// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::AppStateWithSybil;
use axum::{
    body::Body,
    extract::{rejection::JsonRejection, rejection::QueryRejection, Query, State},
    http::{header, StatusCode},
    response::Response,
    Json,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::NativeGraphIssuanceV7Request;
use freebird_common::replay_authority_api::{
    ReplayAuthorityProbeV1, ReplayAuthorityProofV1, REPLAY_AUTHORITY_VERSION_V1,
};
use serde::Deserialize;
use std::sync::Arc;

type SharedState = (
    Arc<AppStateWithSybil>,
    Arc<crate::multi_key_voprf::MultiKeyVoprfCore>,
);

/// Handle the native V7 graph-issuance contract.
///
/// This handler deliberately has a V7 engine state of its own and is not
/// registered in the legacy router yet.  Keeping the state type explicit
/// prevents the V7 lane from accidentally selecting a historical graph
/// provider or Redis namespace.
pub async fn post_v7(
    State((state, _)): State<SharedState>,
    request: Result<Json<NativeGraphIssuanceV7Request>, JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(value) => value,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "v7_graph_request_too_large")
        }
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_v7_graph_request"),
    };
    let Some(engine) = state.native_graph_issuance_v7.as_ref() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "v7_graph_unavailable");
    };
    match engine.process(&request).await {
        Ok(crate::graph_issuance::V7ProcessDecision::Committed(bytes)) => {
            exact(StatusCode::OK, bytes)
        }
        Ok(crate::graph_issuance::V7ProcessDecision::Conflict) => {
            error(StatusCode::CONFLICT, "v7_graph_operation_conflict")
        }
        Ok(crate::graph_issuance::V7ProcessDecision::Rejected) => {
            error(StatusCode::BAD_REQUEST, "invalid_v7_graph_request")
        }
        Ok(crate::graph_issuance::V7ProcessDecision::Unavailable) => {
            error(StatusCode::SERVICE_UNAVAILABLE, "v7_graph_unavailable")
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "v7_graph_unavailable"),
    }
}

/// Return the durable status of a V7 graph issuance operation.
pub async fn status_v7(
    State((state, _)): State<SharedState>,
    query: Result<Query<StatusQuery>, QueryRejection>,
) -> Response {
    let operation_id = match query.ok().and_then(|Query(query)| {
        freebird_common::v7_wire::parse_operation_id(&query.public_operation_id).ok()
    }) {
        Some(value) => value,
        None => return error(StatusCode::BAD_REQUEST, "invalid_public_operation_id"),
    };
    let Some(engine) = state.native_graph_issuance_v7.as_ref() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "v7_graph_unavailable");
    };
    match engine.status(&operation_id).await {
        Ok(crate::graph_issuance::V7StatusDecision::Committed(bytes)) => {
            exact(StatusCode::OK, bytes)
        }
        Ok(crate::graph_issuance::V7StatusDecision::Unknown) => {
            error(StatusCode::NOT_FOUND, "unknown_operation")
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "v7_graph_unavailable"),
    }
}

/// Probe the dedicated V4 replay authority. Challenge consumption and
/// acknowledgement creation are atomic inside the authority module.
pub async fn replay_authority_probe(
    State((state, _)): State<SharedState>,
    request: Result<Json<ReplayAuthorityProbeV1>, JsonRejection>,
) -> Response {
    let Json(probe) = match request {
        Ok(value) => value,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_replay_authority_probe"),
    };
    if probe.validate().is_err() {
        return error(StatusCode::BAD_REQUEST, "invalid_replay_authority_probe");
    }
    let Some(authority) = state.replay_authority.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "replay_authority_unavailable",
        );
    };
    match authority.probe(&probe, &state.issuer_id).await {
        Ok(Some(proof)) => {
            let authority_id = match probe.authority_id() {
                Ok(value) => Base64UrlUnpadded::encode_string(&value),
                Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_replay_authority_probe"),
            };
            let probe_id = match probe.probe_id() {
                Ok(value) => Base64UrlUnpadded::encode_string(&value),
                Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_replay_authority_probe"),
            };
            exact_json(
                StatusCode::OK,
                &ReplayAuthorityProofV1 {
                    version: REPLAY_AUTHORITY_VERSION_V1,
                    authority_id,
                    probe_id,
                    proof: Base64UrlUnpadded::encode_string(&proof),
                },
            )
        }
        Ok(None) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "replay_authority_unavailable",
        ),
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "replay_authority_unavailable",
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusQuery {
    public_operation_id: String,
}

fn exact(status: StatusCode, body: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .expect("static graph issuance response")
}

fn exact_json<T: serde::Serialize>(status: StatusCode, body: &T) -> Response {
    exact(
        status,
        serde_json::to_vec(body).expect("static graph issuance response"),
    )
}

fn error(status: StatusCode, code: &'static str) -> Response {
    exact(
        status,
        serde_json::to_vec(&serde_json::json!({"error": code}))
            .expect("static graph issuance error JSON"),
    )
}
