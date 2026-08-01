// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    graph_issuance::{ProcessDecision, StatusDecision},
    AppStateWithSybil,
};
use axum::{
    body::Body,
    extract::{rejection::JsonRejection, rejection::QueryRejection, Query, State},
    http::{header, HeaderMap, HeaderName, StatusCode},
    response::Response,
    Json,
};
use base64ct::Encoding;
use freebird_common::graph_issuance_api::{
    GraphIssuanceRequestV2, ReplayAuthorityProbeV1, ReplayAuthorityProofV1,
};
use serde::Deserialize;
use std::sync::Arc;

pub const STATUS_CAPABILITY: HeaderName =
    HeaderName::from_static("graph-issuance-status-capability");

type SharedState = (
    Arc<AppStateWithSybil>,
    Arc<crate::multi_key_voprf::MultiKeyVoprfCore>,
);

pub async fn post(
    State((state, _)): State<SharedState>,
    headers: HeaderMap,
    request: Result<Json<GraphIssuanceRequestV2>, JsonRejection>,
) -> Response {
    let capability = match status_capability(&headers) {
        Ok(value) => value,
        Err(()) => return error(StatusCode::BAD_REQUEST, "invalid_status_capability"),
    };
    let Json(request) = match request {
        Ok(value) => value,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "graph_issuance_request_too_large",
            )
        }
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_graph_issuance_request"),
    };
    let Some(engine) = state.graph_issuance_engine.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "graph_issuance_unavailable",
        );
    };
    match engine.process(&request, &capability).await {
        Ok(ProcessDecision::Committed(bytes)) => exact(StatusCode::OK, bytes),
        Ok(ProcessDecision::Conflict) => error(StatusCode::CONFLICT, "operation_conflict"),
        Ok(ProcessDecision::Rejected) => error(StatusCode::BAD_REQUEST, "invalid_graph_issuance"),
        Ok(ProcessDecision::Unavailable) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "graph_issuance_unavailable",
        ),
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "graph_issuance_unavailable",
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusQuery {
    public_operation_id: String,
}

#[cfg(test)]
pub(crate) fn status_query_for_test(public_operation_id: String) -> StatusQuery {
    StatusQuery {
        public_operation_id,
    }
}

pub async fn status(
    State((state, _)): State<SharedState>,
    headers: HeaderMap,
    query: Result<Query<StatusQuery>, QueryRejection>,
) -> Response {
    let capability = match status_capability(&headers) {
        Ok(value) => value,
        Err(()) => return error(StatusCode::BAD_REQUEST, "invalid_status_capability"),
    };
    let operation_id = match query.ok().and_then(|Query(query)| {
        freebird_common::graph_issuance_api::parse_operation_id(&query.public_operation_id).ok()
    }) {
        Some(value) => value,
        None => return error(StatusCode::BAD_REQUEST, "invalid_public_operation_id"),
    };
    let Some(engine) = state.graph_issuance_engine.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "graph_issuance_unavailable",
        );
    };
    match engine.status(&operation_id, &capability).await {
        Ok(StatusDecision::Committed(bytes)) => exact(StatusCode::OK, bytes),
        Ok(StatusDecision::Unknown) => error(StatusCode::NOT_FOUND, "unknown_operation"),
        Ok(StatusDecision::Unauthorized) => error(StatusCode::FORBIDDEN, "status_unauthorized"),
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "graph_issuance_unavailable",
        ),
    }
}

/// Probe the permanent V4 replay authority. The engine performs GETDEL on the
/// request-bound challenge before computing the proof and writes the matching
/// acknowledgement through the same Redis client. No probe material is
/// included in logs or error responses.
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
    let Some(engine) = state.graph_issuance_engine.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "graph_issuance_unavailable",
        );
    };
    match engine
        .replay_authority_probe(&probe, &state.issuer_id)
        .await
    {
        Ok(Some(proof)) => {
            let authority_id = match probe.authority_id() {
                Ok(value) => base64ct::Base64UrlUnpadded::encode_string(&value),
                Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_replay_authority_probe"),
            };
            let probe_id = match probe.probe_id() {
                Ok(value) => base64ct::Base64UrlUnpadded::encode_string(&value),
                Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_replay_authority_probe"),
            };
            exact_json(
                StatusCode::OK,
                &ReplayAuthorityProofV1 {
                    version: freebird_common::graph_issuance_api::REPLAY_AUTHORITY_VERSION_V1,
                    authority_id,
                    probe_id,
                    proof: base64ct::Base64UrlUnpadded::encode_string(&proof),
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

fn status_capability(headers: &HeaderMap) -> Result<[u8; 32], ()> {
    let mut values = headers.get_all(&STATUS_CAPABILITY).iter();
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    freebird_common::graph_issuance_api::decode_digest(value).map_err(|_| ())
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};

    #[test]
    fn capability_is_exactly_one_canonical_32_byte_header() {
        let encoded = Base64UrlUnpadded::encode_string(&[7; 32]);
        let mut headers = HeaderMap::new();
        headers.insert(&STATUS_CAPABILITY, encoded.parse().unwrap());
        assert_eq!(status_capability(&headers).unwrap(), [7; 32]);
        headers.append(&STATUS_CAPABILITY, encoded.parse().unwrap());
        assert!(status_capability(&headers).is_err());
    }
}
