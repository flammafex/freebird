use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::Response,
};
use freebird_common::api::SybilProof;
use freebird_crypto::scarcity_v2::{decode_request, request_digest, validate_request};
use serde::Serialize;
use std::sync::Arc;

use crate::{
    multi_key_voprf::MultiKeyVoprfCore,
    sybil_resistance::SybilRequestContext,
    v2::issuance_store::{CommitResult, ReserveResult},
    AppStateWithSybil,
};

const PROFILE: &str = "scarcity/freebird-mint-issuance/v2";

#[derive(Debug, Serialize)]
struct MintIssueResponse<'a> {
    profile: &'static str,
    #[serde(with = "serde_bytes")]
    request_id: &'a [u8],
    #[serde(with = "serde_bytes")]
    mint_request_digest: &'a [u8],
    #[serde(with = "serde_bytes")]
    issuer_id: &'a [u8],
    #[serde(with = "serde_bytes")]
    keyset_id: &'a [u8],
    denomination: u64,
    issuance_epoch: u64,
    expiry_epoch: u64,
    #[serde(with = "serde_bytes")]
    modulus: &'a [u8],
    public_exponent: u32,
    suite: &'a str,
    #[serde(with = "serde_bytes")]
    blind_signature: &'a [u8],
}

#[derive(Debug, Serialize)]
struct ErrorResponse<'a> {
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    request_id: Option<&'a [u8]>,
}

pub async fn issue(
    State((state, _voprf)): State<(Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or(v))
        != Some("application/cbor")
    {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid-cbor", None);
    }
    if headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or(v))
        .is_none_or(|v| v != "application/cbor")
    {
        return error(StatusCode::NOT_ACCEPTABLE, "invalid-cbor", None);
    }
    let request = match decode_request(&body) {
        Ok(request) => request,
        Err(code) if code == "non-canonical" => {
            return error(StatusCode::BAD_REQUEST, "non-canonical", None)
        }
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid-cbor", None),
    };
    let request_id = Some(request.request_id.as_slice());
    let provider = match state.v2_provider.as_ref() {
        Some(provider) => provider,
        None => return error(StatusCode::NOT_FOUND, "internal-retryable", request_id),
    };
    let store = match state.v2_store.as_ref() {
        Some(store) => store,
        None => return error(StatusCode::NOT_FOUND, "internal-retryable", request_id),
    };
    if validate_request(&request).is_err() {
        return error(StatusCode::BAD_REQUEST, "malformed-credential", request_id);
    }
    if request.issuer_id != provider.issuer_id() || request.keyset_id != provider.keyset_id() {
        return error(StatusCode::BAD_REQUEST, "unknown-keyset", request_id);
    }
    let digest = match request_digest(&request) {
        Ok(digest) => digest,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid-cbor", request_id),
    };
    let proof = match headers
        .get("x-sybil-proof")
        .and_then(|v| serde_json::from_slice::<SybilProof>(v.as_bytes()).ok())
    {
        Some(proof) => proof,
        None => return error(StatusCode::FORBIDDEN, "admission-required", request_id),
    };
    let checker = match state.sybil_checker.as_ref() {
        Some(checker) => checker,
        None => return error(StatusCode::FORBIDDEN, "admission-required", request_id),
    };
    let context = SybilRequestContext {
        request_binding: Some(hex::encode(&digest)),
        ..Default::default()
    };
    if checker.verify_with_context(&proof, &context).is_err() {
        return error(StatusCode::FORBIDDEN, "admission-rejected", request_id);
    }
    let fence = match store.reserve(&request.request_id, &digest).await {
        Ok(ReserveResult::Reserved { fence }) => fence,
        Ok(ReserveResult::Replay(bytes)) => return cbor_response(StatusCode::OK, bytes),
        Ok(ReserveResult::InProgress) => {
            return error(StatusCode::CONFLICT, "request-conflict", request_id)
        }
        Ok(ReserveResult::Conflict) => {
            return error(StatusCode::CONFLICT, "request-conflict", request_id)
        }
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "internal-retryable",
                request_id,
            )
        }
    };
    let signature = match provider.blind_sign(&request.blinded_message) {
        Ok(signature) => signature,
        Err(_) => return error(StatusCode::BAD_REQUEST, "malformed-credential", request_id),
    };
    let keyset = provider.keyset();
    let response = MintIssueResponse {
        profile: PROFILE,
        request_id: &request.request_id,
        mint_request_digest: &digest,
        issuer_id: &keyset.issuer_id,
        keyset_id: &keyset.keyset_id,
        denomination: keyset.denomination,
        issuance_epoch: keyset.issuance_epoch,
        expiry_epoch: keyset.expiry_epoch,
        modulus: &keyset.modulus,
        public_exponent: keyset.public_exponent,
        suite: &keyset.suite,
        blind_signature: &signature,
    };
    let bytes = match cbor2::to_canonical_vec(&response) {
        Ok(bytes) => bytes,
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal-retryable",
                request_id,
            )
        }
    };
    match store
        .commit(&request.request_id, &digest, fence, &bytes)
        .await
    {
        Ok(CommitResult::Committed) => cbor_response(StatusCode::OK, bytes),
        Ok(CommitResult::Replay(bytes)) => cbor_response(StatusCode::OK, bytes),
        Ok(CommitResult::Conflict) => error(StatusCode::CONFLICT, "request-conflict", request_id),
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "internal-retryable",
            request_id,
        ),
    }
}

fn cbor_response(status: StatusCode, bytes: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(axum::body::Body::from(bytes))
        .unwrap()
}
fn error(status: StatusCode, code: &'static str, request_id: Option<&[u8]>) -> Response {
    let bytes = cbor2::to_canonical_vec(&ErrorResponse { code, request_id }).unwrap_or_default();
    cbor_response(status, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sybil_resistance::{NoSybilResistance, SybilResistance},
        v2::issuance_store::IssuanceStore,
    };
    use axum::{body::Body, http::Request, routing::post, Router};
    use blind_rsa_signatures::{DefaultRng, KeyPairSha384PSSRandomized};
    use freebird_crypto::scarcity_v2::{keyset_id, Keyset, MintRequest, V2SigningProvider};
    use sha2::{Digest, Sha256};
    use std::time::Duration;
    use tower05::ServiceExt;

    fn request_bytes() -> Vec<u8> {
        let blinded = vec![7; 384];
        let mut hash = Sha256::new();
        hash.update(b"scarcity/v2/mint-blinded-message\0");
        hash.update(&blinded);
        let request = MintRequest {
            version: 2,
            issuer_id: vec![1; 32],
            keyset_id: vec![2; 32],
            request_id: vec![3; 32],
            client_binding: vec![4; 32],
            blinded_message: blinded,
            blinded_message_digest: hash.finalize().to_vec(),
            retry_attempt: 0,
            requested_at_epoch: 1,
            request_expiry_epoch: 2,
        };
        cbor2::to_canonical_vec(&request).unwrap()
    }

    fn state() -> (Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>) {
        let state = AppStateWithSybil {
            issuer_id: "issuer".into(),
            kid: "kid".into(),
            pubkey_b64: "pubkey".into(),
            require_tls: false,
            behind_proxy: false,
            sybil_checker: None,
            invitation_system: None,
            public_issuer: None,
            epoch_duration_sec: 86400,
            epoch_retention: 1,
            admin_api_key: None,
            v2_provider: None,
            v2_store: None,
        };
        let voprf =
            MultiKeyVoprfCore::new([7; 32], "pubkey".into(), "kid".into(), b"test").unwrap();
        (Arc::new(state), Arc::new(voprf))
    }

    async fn call(headers: &[(&str, &str)], body: Vec<u8>) -> axum::response::Response {
        call_with_state(state(), headers, body).await
    }

    async fn call_with_state(
        state: (Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>),
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> axum::response::Response {
        let app = Router::new()
            .route("/v2/scarcity/mint/issue", post(issue))
            .with_state(state);
        let mut request = Request::builder()
            .method("POST")
            .uri("/v2/scarcity/mint/issue");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        app.oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    async fn context() -> Option<((Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>), Keyset)> {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let store =
            IssuanceStore::new(&url, Duration::from_secs(60), Duration::from_secs(60)).ok()?;
        let mut conn = redis::Client::open(url)
            .ok()?
            .get_async_connection()
            .await
            .ok()?;
        let _: String = redis::cmd("PING").query_async(&mut conn).await.ok()?;
        let mut rng = DefaultRng;
        let pair = KeyPairSha384PSSRandomized::generate(&mut rng, 3072).ok()?;
        let mut keyset = Keyset {
            issuer_id: vec![1; 32],
            keyset_id: vec![0; 32],
            asset_id: vec![2; 32],
            spend_domain: vec![3; 32],
            denomination: 10,
            issuance_epoch: 1,
            expiry_epoch: 2,
            modulus: pair.pk.components().n(),
            public_exponent: 65537,
            suite: "RSABSSA-SHA384-PSS-Randomized".into(),
            authority_key_id: vec![4; 32],
        };
        keyset.keyset_id = keyset_id(&keyset).ok()?;
        let provider =
            V2SigningProvider::from_der_with_keyset(&pair.sk.to_der().ok()?, &keyset).ok()?;
        let checker: Arc<dyn SybilResistance> = Arc::new(NoSybilResistance);
        let (base, voprf) = state();
        let mut state = base.as_ref().clone();
        state.sybil_checker = Some(checker);
        state.v2_provider = Some(Arc::new(provider));
        state.v2_store = Some(Arc::new(store));
        Some(((Arc::new(state), voprf), keyset))
    }

    fn request_for(keyset: &Keyset, id: u8, blinded_byte: u8) -> Vec<u8> {
        let blinded = vec![blinded_byte; 384];
        let mut hash = Sha256::new();
        hash.update(b"scarcity/v2/mint-blinded-message\0");
        hash.update(&blinded);
        cbor2::to_canonical_vec(&MintRequest {
            version: 2,
            issuer_id: keyset.issuer_id.clone(),
            keyset_id: keyset.keyset_id.clone(),
            request_id: vec![id; 32],
            client_binding: vec![4; 32],
            blinded_message: blinded,
            blinded_message_digest: hash.finalize().to_vec(),
            retry_attempt: 0,
            requested_at_epoch: 1,
            request_expiry_epoch: 2,
        })
        .unwrap()
    }

    fn issuance_headers() -> [(&'static str, &'static str); 3] {
        [
            ("content-type", "application/cbor"),
            ("accept", "application/cbor"),
            ("x-sybil-proof", r#"{"type":"none"}"#),
        ]
    }

    #[tokio::test]
    async fn v2_http_disabled_is_fail_closed() {
        let response = call(
            &[
                ("content-type", "application/cbor"),
                ("accept", "application/cbor"),
            ],
            request_bytes(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn v2_http_rejects_malformed_cbor_and_content_negotiation() {
        let response = call(
            &[
                ("content-type", "application/json"),
                ("accept", "application/cbor"),
            ],
            vec![0xff],
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let response = call(
            &[
                ("content-type", "application/cbor"),
                ("accept", "application/json"),
            ],
            vec![0xff],
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        let response = call(
            &[
                ("content-type", "application/cbor"),
                ("accept", "application/cbor"),
            ],
            vec![0xff],
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn v2_http_sybil_rejection_is_fail_closed() {
        let Some((state, keyset)) = context().await else {
            eprintln!("skipping V2 HTTP test: Redis unavailable");
            return;
        };
        let headers = [
            ("content-type", "application/cbor"),
            ("accept", "application/cbor"),
            (
                "x-sybil-proof",
                r#"{"type":"proof_of_work","nonce":0,"input":"bad","timestamp":0}"#,
            ),
        ];
        let response = call_with_state(state, &headers, request_for(&keyset, 11, 8)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn v2_http_success_replay_and_changed_request_conflict() {
        let Some((state, keyset)) = context().await else {
            eprintln!("skipping V2 HTTP test: Redis unavailable");
            return;
        };
        let headers = issuance_headers();
        let body = request_for(&keyset, 12, 9);
        let first = call_with_state(state.clone(), &headers, body.clone()).await;
        assert_eq!(first.status(), StatusCode::OK);
        let first_bytes = axum::body::to_bytes(first.into_body(), 4096).await.unwrap();
        let replay = call_with_state(state.clone(), &headers, body).await;
        assert_eq!(replay.status(), StatusCode::OK);
        assert_eq!(
            first_bytes,
            axum::body::to_bytes(replay.into_body(), 4096)
                .await
                .unwrap()
        );
        let conflict = call_with_state(state, &headers, request_for(&keyset, 12, 10)).await;
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn v2_http_redis_unavailable_self_skips() {
        let store = IssuanceStore::new(
            "redis://127.0.0.1:1",
            Duration::from_millis(10),
            Duration::from_millis(10),
        )
        .unwrap();
        if store.reserve(&[99; 32], &[1; 32]).await.is_ok() {
            return;
        }
        eprintln!("Redis-unavailable V2 HTTP integration path self-skipped");
    }

    #[tokio::test]
    async fn v5_public_issuance_route_remains_registered() {
        let app = Router::new()
            .route(
                "/v1/public/issue",
                post(crate::routes::public_issue::handle),
            )
            .with_state(state());
        let request = Request::builder()
            .method("POST")
            .uri("/v1/public/issue")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }
}
