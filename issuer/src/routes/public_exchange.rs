// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    exchange::{ProcessDecision, StatusDecision},
    AppStateWithSybil,
};
use axum::{
    body::Body,
    extract::{rejection::JsonRejection, rejection::QueryRejection, Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
    Json,
};
use freebird_common::exchange_api::{parse_operation_id, ExchangeRequestV2};
use serde::Deserialize;
use std::sync::Arc;

pub const STATUS_CAPABILITY: HeaderName = HeaderName::from_static("exchange-status-capability");
/// Compatibility symbol for the startup lane's CORS allow-list. Its wire value
/// is the V2 status capability and is not an operation identifier.
pub const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("exchange-status-capability");

type SharedState = (
    Arc<AppStateWithSybil>,
    Arc<crate::multi_key_voprf::MultiKeyVoprfCore>,
);

pub async fn post_exchange(
    State((state, _)): State<SharedState>,
    headers: HeaderMap,
    request: Result<Json<ExchangeRequestV2>, JsonRejection>,
) -> Response {
    let status_capability = match status_capability(&headers) {
        Ok(capability) => capability,
        Err(()) => return error(StatusCode::BAD_REQUEST, "invalid_status_capability"),
    };
    let Some(engine) = state.exchange_engine.as_ref() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "exchange_unavailable");
    };
    let Json(request) = match request {
        Ok(request) => request,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "exchange_request_too_large")
        }
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_exchange_request"),
    };
    match engine
        .process_or_recover_v2(&request, &status_capability)
        .await
    {
        Ok(ProcessDecision::Committed(bytes)) => exact(StatusCode::OK, bytes),
        Ok(ProcessDecision::Retryable) => retryable(),
        Ok(ProcessDecision::Conflict) => error(StatusCode::CONFLICT, "operation_conflict"),
        Ok(ProcessDecision::Rejected) => error(StatusCode::BAD_REQUEST, "invalid_exchange"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "exchange_unavailable"),
    }
}

pub async fn get_exchange_status(
    State((state, _)): State<SharedState>,
    headers: HeaderMap,
    query: Result<Query<ExchangeStatusQuery>, QueryRejection>,
) -> Response {
    let status_capability = match status_capability(&headers) {
        Ok(capability) => capability,
        Err(()) => return error(StatusCode::BAD_REQUEST, "invalid_status_capability"),
    };
    let operation_id = match query
        .ok()
        .and_then(|Query(query)| parse_operation_id(&query.public_operation_id).ok())
    {
        Some(operation_id) => operation_id,
        None => return error(StatusCode::BAD_REQUEST, "invalid_public_operation_id"),
    };
    let Some(engine) = state.exchange_engine.as_ref() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "exchange_unavailable");
    };
    match engine.status_v2(&operation_id, &status_capability).await {
        Ok(StatusDecision::Committed(bytes)) => exact(StatusCode::OK, bytes),
        Ok(StatusDecision::Pending) => retryable(),
        Ok(StatusDecision::Unknown) => error(StatusCode::NOT_FOUND, "unknown_operation"),
        Ok(StatusDecision::Unauthorized) => error(StatusCode::FORBIDDEN, "status_unauthorized"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "exchange_unavailable"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeStatusQuery {
    public_operation_id: String,
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

fn retryable() -> Response {
    let mut response = error(StatusCode::ACCEPTED, "exchange_retryable");
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn exact(status: StatusCode, bytes: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(bytes))
        .expect("static exchange response")
}

fn error(status: StatusCode, code: &'static str) -> Response {
    let body = serde_json::to_vec(&serde_json::json!({"error": code}))
        .expect("static exchange error JSON");
    exact(status, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};

    #[test]
    fn status_header_is_exactly_one_canonical_32_byte_capability() {
        let encoded = Base64UrlUnpadded::encode_string(&[7; 32]);
        let mut headers = HeaderMap::new();
        headers.insert(&STATUS_CAPABILITY, encoded.parse().unwrap());
        assert_eq!(status_capability(&headers).unwrap(), [7; 32]);
        headers.append(&STATUS_CAPABILITY, encoded.parse().unwrap());
        assert!(status_capability(&headers).is_err());
        headers.clear();
        headers.insert(&STATUS_CAPABILITY, "padded==".parse().unwrap());
        assert!(status_capability(&headers).is_err());
        headers.clear();
        headers.insert(
            &STATUS_CAPABILITY,
            Base64UrlUnpadded::encode_string(&[7; 16]).parse().unwrap(),
        );
        assert!(status_capability(&headers).is_err());
    }
}
