// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    exchange::{ProcessDecision, StatusDecision},
    AppStateWithSybil,
};
use axum::{
    body::Body,
    extract::{rejection::JsonRejection, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
    Json,
};
use freebird_common::exchange_api::{parse_operation_id_header, ExchangeRequest};
use std::sync::Arc;

pub const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");

type SharedState = (
    Arc<AppStateWithSybil>,
    Arc<crate::multi_key_voprf::MultiKeyVoprfCore>,
);

pub async fn post_exchange(
    State((state, _)): State<SharedState>,
    headers: HeaderMap,
    request: Result<Json<ExchangeRequest>, JsonRejection>,
) -> Response {
    let operation_id = match operation_id(&headers) {
        Ok(operation_id) => operation_id,
        Err(()) => return error(StatusCode::BAD_REQUEST, "invalid_idempotency_key"),
    };
    let Some(engine) = state.exchange_engine.as_ref() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "exchange_unavailable");
    };
    let Json(request) = match request {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_exchange_request"),
    };
    match engine.process_or_recover(&operation_id, &request).await {
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
) -> Response {
    let operation_id = match operation_id(&headers) {
        Ok(operation_id) => operation_id,
        Err(()) => return error(StatusCode::BAD_REQUEST, "invalid_idempotency_key"),
    };
    let Some(engine) = state.exchange_engine.as_ref() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "exchange_unavailable");
    };
    match engine.status(&operation_id).await {
        Ok(StatusDecision::Committed(bytes)) => exact(StatusCode::OK, bytes),
        Ok(StatusDecision::Pending) => retryable(),
        Ok(StatusDecision::Unknown) => error(StatusCode::NOT_FOUND, "unknown_operation"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "exchange_unavailable"),
    }
}

fn operation_id(headers: &HeaderMap) -> Result<[u8; 16], ()> {
    let mut values = headers.get_all(&IDEMPOTENCY_KEY).iter();
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    parse_operation_id_header(value).map_err(|_| ())
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
    fn idempotency_header_is_exactly_one_canonical_capability() {
        let encoded = Base64UrlUnpadded::encode_string(&[7; 16]);
        let mut headers = HeaderMap::new();
        headers.insert(&IDEMPOTENCY_KEY, encoded.parse().unwrap());
        assert_eq!(operation_id(&headers).unwrap(), [7; 16]);
        headers.append(&IDEMPOTENCY_KEY, encoded.parse().unwrap());
        assert!(operation_id(&headers).is_err());
        headers.clear();
        headers.insert(&IDEMPOTENCY_KEY, "padded==".parse().unwrap());
        assert!(operation_id(&headers).is_err());
    }
}
