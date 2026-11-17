//! Active-key-only experimental RFC 9578 issuer.
use crate::admission::AdmissionStore;
use crate::key_store::KeyStore;
use anyhow::{bail, Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64ct::{Base64Url, Base64UrlUnpadded, Encoding};
use freebird_common::privacy_pass::TokenRequest;
use freebird_crypto::privacy_pass::SecretKey;
use std::{
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

const REQUEST_MEDIA: &str = "application/private-token-request";
const SIGNER_CAPACITY: usize = 2;

pub struct Issuer {
    _key_store: KeyStore,
    key: SecretKey,
    admission: Arc<AdmissionStore>,
    spki: Vec<u8>,
    key_id: [u8; 32],
    request_url: String,
    signers: Arc<Semaphore>,
}

impl Issuer {
    /// Explicit initialization only; callers must use a dedicated Privacy Pass path.
    pub fn initialize_key(key_path: impl AsRef<Path>) -> Result<()> {
        KeyStore::initialize(key_path)
    }

    pub fn open(
        key_path: impl AsRef<Path>,
        admission: Arc<AdmissionStore>,
        issuer_name: impl Into<String>,
        request_url: impl Into<String>,
    ) -> Result<Self> {
        let issuer_name = issuer_name.into();
        let request_url = request_url.into();
        if issuer_name.is_empty()
            || !issuer_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_:[]".contains(&b))
        {
            bail!("invalid issuer name");
        }
        let uri: axum::http::Uri = request_url.parse().context("invalid issuer request URI")?;
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri.authority().map(|a| a.as_str()) != Some(issuer_name.as_str())
            || uri.path() != "/private-token/issue"
            || uri.query().is_some()
        {
            bail!("issuer request URI must identify this issuer's issuance endpoint");
        }
        let key_store = KeyStore::open(key_path)?;
        let key = key_store.active_key()?;
        let public = key.public_key()?;
        Ok(Self {
            _key_store: key_store,
            spki: public.to_spki().to_vec(),
            key_id: public.key_id(),
            key,
            admission,
            request_url,
            signers: Arc::new(Semaphore::new(SIGNER_CAPACITY)),
        })
    }
}

pub fn router(issuer: Arc<Issuer>) -> Router {
    Router::new()
        .route(
            "/.well-known/private-token-issuer-directory",
            get(directory),
        )
        .route("/private-token/issue", post(issue))
        .with_state(issuer)
}

async fn directory(State(issuer): State<Arc<Issuer>>) -> Response {
    let directory = serde_json::json!({
        "issuer-request-uri": issuer.request_url,
        "token-keys": [{"token-type": 2, "token-key": Base64Url::encode_string(&issuer.spki)}]
    });
    (
        [
            (
                header::CONTENT_TYPE,
                "application/private-token-issuer-directory",
            ),
            (header::CACHE_CONTROL, "public, max-age=60"),
        ],
        directory.to_string(),
    )
        .into_response()
}

async fn issue(State(issuer): State<Arc<Issuer>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    // Apply the transport limit even for unsupported media.
    let bytes = match to_bytes(body, 4096).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let mut media = parts.headers.get_all(header::CONTENT_TYPE).iter();
    if media
        .next()
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case(REQUEST_MEDIA))
        != Some(true)
        || media.next().is_some()
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let token_request = match TokenRequest::from_bytes(&bytes) {
        Ok(request) if request.truncated_token_key_id == issuer.key_id[31] => request,
        _ => return StatusCode::UNPROCESSABLE_ENTITY.into_response(),
    };
    let mut values = parts.headers.get_all("freebird-admission").iter();
    let code = match values.next() {
        None => return StatusCode::FORBIDDEN.into_response(),
        Some(value) => match value.to_str() {
            Ok(code) => code.to_owned(),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        },
    };
    let decoded = Base64UrlUnpadded::decode_vec(&code);
    if values.next().is_some()
        || code.len() != 43
        || !matches!(decoded, Ok(ref bytes) if bytes.len() == 32 && Base64UrlUnpadded::encode_string(bytes) == code)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let permit = match issuer.signers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
    };
    // The permit stays inside the blocking job, including if the HTTP future
    // is cancelled. The store commits before the sole signing call.
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        match issuer.admission.consume(&code, now) {
            Ok(true) => {}
            Ok(false) => return Err(StatusCode::FORBIDDEN),
            Err(_) => return Err(StatusCode::SERVICE_UNAVAILABLE),
        }
        issuer
            .key
            .blind_sign(&token_request.blinded_msg)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    })
    .await;
    match result {
        Ok(Ok(signature)) => (
            [
                (header::CONTENT_TYPE, "application/private-token-response"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            Body::from(signature.to_vec()),
        )
            .into_response(),
        Ok(Err(status)) => status.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freebird_common::privacy_pass::{token_input, token_key_id};
    use freebird_crypto::privacy_pass::PublicKey;
    use std::fs;

    fn fixture() -> (tempfile::TempDir, Arc<Issuer>) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("admission.sqlite");
        let generation = dir.path().join("generation");
        AdmissionStore::initialize(&db, &generation).unwrap();
        let admission = Arc::new(AdmissionStore::open(&db, &generation).unwrap());
        let key = dir.path().join("pp-signing.sqlite");
        assert!(Issuer::open(
            &key,
            admission.clone(),
            "issuer.test",
            "https://issuer.test/private-token/issue"
        )
        .is_err());
        Issuer::initialize_key(&key).unwrap();
        assert!(Issuer::initialize_key(&key).is_err());
        let issuer = Arc::new(
            Issuer::open(
                &key,
                admission.clone(),
                "issuer.test",
                "https://issuer.test/private-token/issue",
            )
            .unwrap(),
        );
        let corrupt = dir.path().join("corrupt");
        fs::write(&corrupt, b"not a key").unwrap();
        assert!(Issuer::open(
            &corrupt,
            admission,
            "issuer.test",
            "https://issuer.test/private-token/issue"
        )
        .is_err());
        (dir, issuer)
    }

    fn request(body: Vec<u8>, code: &str) -> Request {
        Request::builder()
            .method("POST")
            .uri("/private-token/issue")
            .header(header::CONTENT_TYPE, REQUEST_MEDIA)
            .header("freebird-admission", code)
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn staged_key_is_not_advertised_or_issued_and_preserves_invitation() {
        let (_dir, issuer) = fixture();
        let staged_id = issuer._key_store.stage().expect("stage a key");
        let staged_spki = issuer._key_store.staged_spki().unwrap().unwrap();
        let staged = PublicKey::from_spki(&staged_spki).unwrap();
        let input = token_input(&[7; 32], &[8; 32], &staged_id);
        let (blinded_msg, _) = staged.blind(&input).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let code = issuer.admission.provision(now).unwrap();
        let staged_request = TokenRequest {
            truncated_token_key_id: staged_id[31],
            blinded_msg,
        };
        assert_eq!(
            issue(
                State(issuer.clone()),
                request(staged_request.to_bytes().to_vec(), &code)
            )
            .await
            .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let response = directory(State(issuer.clone())).await;
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document["token-keys"].as_array().unwrap().len(), 1);
        assert_eq!(
            document["token-keys"][0]["token-key"],
            Base64Url::encode_string(&issuer.spki)
        );
        let active = PublicKey::from_spki(&issuer.spki).unwrap();
        let input = token_input(&[7; 32], &[8; 32], &issuer.key_id);
        let (blinded_msg, state) = active.blind(&input).unwrap();
        let active_request = TokenRequest {
            truncated_token_key_id: issuer.key_id[31],
            blinded_msg,
        };
        let response = issue(
            State(issuer.clone()),
            request(active_request.to_bytes().to_vec(), &code),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let signature: [u8; 256] = to_bytes(response.into_body(), 256)
            .await
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let signature = active.finalize(state, &signature).unwrap();
        active.verify(&input, &signature).unwrap();
    }

    #[tokio::test]
    async fn directory_and_one_use_issuance() {
        let (_dir, issuer) = fixture();
        let response = directory(State(issuer.clone())).await;
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/private-token-issuer-directory"
        );
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            document["issuer-request-uri"],
            "https://issuer.test/private-token/issue"
        );
        assert_eq!(document["token-keys"][0]["token-type"], 2);
        let encoded = document["token-keys"][0]["token-key"].as_str().unwrap();
        let spki = Base64Url::decode_vec(encoded).unwrap();
        assert_eq!(Base64Url::encode_string(&spki), encoded);
        assert_eq!(token_key_id(&spki), issuer.key_id);
        let public = PublicKey::from_spki(&spki).unwrap();
        let input = token_input(&[7; 32], &[8; 32], &issuer.key_id);
        let (blinded_msg, state) = public.blind(&input).unwrap();
        let wire = TokenRequest {
            truncated_token_key_id: issuer.key_id[31],
            blinded_msg,
        }
        .to_bytes();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let code = issuer.admission.provision(now).unwrap();
        for length in [0, 258, 260, 4096] {
            assert_eq!(
                issue(State(issuer.clone()), request(vec![0; length], &code))
                    .await
                    .status(),
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        let mut wrong_key = wire;
        wrong_key[2] ^= 1;
        assert_eq!(
            issue(State(issuer.clone()), request(wrong_key.to_vec(), &code))
                .await
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            issue(State(issuer.clone()), request(vec![0; 4097], &code))
                .await
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            issue(State(issuer.clone()), request(wire.to_vec(), "malformed"))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        let mut duplicate = request(wire.to_vec(), &code);
        duplicate
            .headers_mut()
            .append("freebird-admission", code.parse().unwrap());
        assert_eq!(
            issue(State(issuer.clone()), duplicate).await.status(),
            StatusCode::BAD_REQUEST
        );
        let mut unsupported = request(wire.to_vec(), &code);
        unsupported
            .headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        assert_eq!(
            issue(State(issuer.clone()), unsupported).await.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        let permit = issuer
            .signers
            .clone()
            .acquire_many_owned(SIGNER_CAPACITY as u32)
            .await
            .unwrap();
        assert_eq!(
            issue(State(issuer.clone()), request(wire.to_vec(), &code))
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        drop(permit);
        let response = issue(State(issuer.clone()), request(wire.to_vec(), &code)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/private-token-response"
        );
        let signature: [u8; 256] = to_bytes(response.into_body(), 256)
            .await
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let signature = public.finalize(state, &signature).unwrap();
        public.verify(&input, &signature).unwrap();
        assert_eq!(
            issue(State(issuer), request(wire.to_vec(), &code))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
}
