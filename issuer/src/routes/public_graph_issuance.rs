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
use freebird_common::graph_issuance_api::GraphIssuanceRequestV1;
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
    request: Result<Json<GraphIssuanceRequestV1>, JsonRejection>,
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
        let bytes =
            freebird_common::exchange_api::decode_base64url(&query.public_operation_id, 16).ok()?;
        bytes.try_into().ok()
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

fn status_capability(headers: &HeaderMap) -> Result<[u8; 32], ()> {
    let mut values = headers.get_all(&STATUS_CAPABILITY).iter();
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    freebird_common::exchange_api::decode_base64url(value, 32)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())
}

fn exact(status: StatusCode, body: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .expect("static graph issuance response")
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
