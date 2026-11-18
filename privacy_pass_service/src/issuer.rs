//! The experimental RFC 9578 issuer signs with the key whose activation hour is the latest that
//! does not exceed the highest observed hour. The keys loaded at startup stay in memory until restart.
use crate::admission::AdmissionStore;
use crate::app_admission::AppAdmission;
use crate::key_store::{select_active, KeyStore, SigningKey};
use crate::pow::{BrowserOrigin, Pow};
use anyhow::{bail, ensure, Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, request::Parts, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64ct::{Base64Url, Base64UrlUnpadded, Encoding};
use freebird_common::privacy_pass::TokenRequest;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

const REQUEST_MEDIA: &str = "application/private-token-request";
const SIGNER_CAPACITY: usize = 2;
const SECONDS_PER_HOUR: u64 = 3600;

pub struct Issuer {
    /// Keeps the key store locked while the issuer serves so that offline maintenance cannot change it.
    _key_store: KeyStore,
    /// Stores activated and scheduled private keys in order of activation hour.
    keys: Arc<Vec<SigningKey>>,
    /// Records the highest observed hour so that a clock rollback cannot select an older key.
    latch: AtomicU64,
    admission: Arc<AdmissionStore>,
    request_url: String,
    signers: Arc<Semaphore>,
}

impl Issuer {
    /// Initializes a key store at a dedicated path for Privacy Pass.
    pub fn initialize_key(key_path: impl AsRef<Path>) -> Result<()> {
        KeyStore::initialize(key_path)
    }

    pub fn open(
        key_path: impl AsRef<Path>,
        admission: Arc<AdmissionStore>,
        issuer_name: impl Into<String>,
        request_url: impl Into<String>,
        now: u64,
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
        let keys = key_store.signing_keys(now)?;
        let hour = now / SECONDS_PER_HOUR;
        let hours: Vec<u64> = keys.iter().map(|k| k.activation_hour).collect();
        ensure!(
            select_active(&hours, hour).is_some(),
            "no active issuer key at this time"
        );
        Ok(Self {
            _key_store: key_store,
            keys: Arc::new(keys),
            latch: AtomicU64::new(hour),
            admission,
            request_url,
            signers: Arc::new(Semaphore::new(SIGNER_CAPACITY)),
        })
    }

    /// Updates the highest observed hour with `now` if it is later, then returns the index of the selected key.
    fn selected(&self, now: u64) -> Option<usize> {
        let hour = now / SECONDS_PER_HOUR;
        let previous = self.latch.fetch_max(hour, Ordering::SeqCst);
        let effective = previous.max(hour);
        let hours: Vec<u64> = self.keys.iter().map(|k| k.activation_hour).collect();
        select_active(&hours, effective)
    }

    /// Returns a directory body that advertises only the key selected at `now`.
    pub fn directory_at(&self, now: u64) -> Result<String> {
        let index = self.selected(now).context("no active issuer key")?;
        Ok(self.directory_for(index))
    }

    fn directory_for(&self, index: usize) -> String {
        let key = &self.keys[index];
        serde_json::json!({
            "issuer-request-uri": self.request_url,
            "token-keys": [{
                "token-type": 2,
                "token-key": Base64Url::encode_string(key.public.to_spki())
            }]
        })
        .to_string()
    }

    /// Use the same key selection for the body and cache lifetime so that the cached directory
    /// expires by the next scheduled activation.
    fn directory_response_at(&self, now: u64) -> Response {
        let Some(index) = self.selected(now) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let max_age = self.keys.get(index + 1).map_or(60, |next| {
            (next.activation_hour * SECONDS_PER_HOUR)
                .saturating_sub(now)
                .min(60)
        });
        (
            [
                (
                    header::CONTENT_TYPE,
                    "application/private-token-issuer-directory".to_owned(),
                ),
                (header::CACHE_CONTROL, format!("public, max-age={max_age}")),
            ],
            self.directory_for(index),
        )
            .into_response()
    }

    /// Uses `now` to select a single signing key and checks that the request targets it before consuming admission.
    pub async fn issue_at(&self, parts: &Parts, bytes: &[u8], now: u64) -> Response {
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
        let token_request = match TokenRequest::from_bytes(bytes) {
            Ok(request) => request,
            Err(_) => return StatusCode::UNPROCESSABLE_ENTITY.into_response(),
        };
        let Some(index) = self.selected(now) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        if token_request.truncated_token_key_id != self.keys[index].public.key_id()[31] {
            return StatusCode::UNPROCESSABLE_ENTITY.into_response();
        }
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
        let permit = match self.signers.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
        };
        let keys = self.keys.clone();
        let admission = self.admission.clone();
        // Move the permit into the blocking job so that cancelling the request cannot free it
        // before the job ends. Commit the invitation's removal before making the single signing call.
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let now = i64::try_from(now).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            match admission.consume(&code, now) {
                Ok(true) => {}
                Ok(false) => return Err(StatusCode::FORBIDDEN),
                Err(_) => return Err(StatusCode::SERVICE_UNAVAILABLE),
            }
            keys[index]
                .secret
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

/// Adds the PoW routes and enables browser CORS while keeping the same issuance and admission checks.
pub fn router_with_pow(issuer: Arc<Issuer>, pow: Arc<Pow>, origin: BrowserOrigin) -> Router {
    router(issuer)
        .merge(crate::pow::router(pow))
        .route_layer(middleware::from_fn_with_state(origin, browser_cors))
}

/// Merge the application route after attaching browser CORS so that the server-to-server
/// endpoint does not receive CORS headers. Passing `None` leaves the path unrouted, so it returns HTTP 404.
pub fn with_app_admission(router: Router, app: Option<Arc<AppAdmission>>) -> Router {
    match app {
        Some(app) => router.merge(crate::app_admission::router(app)),
        None => router,
    }
}

async fn browser_cors(
    State(origin): State<BrowserOrigin>,
    request: Request,
    next: Next,
) -> Response {
    let mut origins = request.headers().get_all(header::ORIGIN).iter();
    let allowed = origins.next() == Some(origin.header()) && origins.next().is_none();
    let preflight = request.method() == Method::OPTIONS;
    let mut response = if preflight {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
    if allowed {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.header().clone());
        if preflight {
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, POST"),
            );
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("Content-Type, Freebird-Admission"),
            );
            headers.insert(
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from_static("600"),
            );
        }
    }
    response
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

async fn directory(State(issuer): State<Arc<Issuer>>) -> Response {
    let Some(now) = unix_now() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    issuer.directory_response_at(now)
}

async fn issue(State(issuer): State<Arc<Issuer>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    // Limit the request body before checking the media type so that unsupported types are bounded too.
    let bytes = match to_bytes(body, 4096).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let Some(now) = unix_now() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    issuer.issue_at(&parts, &bytes, now).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_store::KeyStore;
    use freebird_common::privacy_pass::{token_input, token_key_id};
    use freebird_crypto::privacy_pass::{BlindState, PublicKey};
    use std::fs;

    const T0: u64 = 1_000;
    const H: u64 = 10;
    const S: u64 = H * SECONDS_PER_HOUR;
    const ISSUER_URL: &str = "https://issuer.test/private-token/issue";

    fn admission(dir: &Path) -> Arc<AdmissionStore> {
        let db = dir.join("admission.sqlite");
        let generation = dir.join("generation");
        AdmissionStore::initialize(&db, &generation).unwrap();
        Arc::new(AdmissionStore::open(&db, &generation).unwrap())
    }

    fn open_at(key: &Path, admission: Arc<AdmissionStore>, now: u64) -> Result<Issuer> {
        Issuer::open(key, admission, "issuer.test", ISSUER_URL, now)
    }

    /// Creates the initial key K0 and stages K1 at `T0` for activation at `S`.
    /// Closes the store and returns the IDs of K0 and K1 in that order.
    fn two_key_store(key: &Path) -> ([u8; 32], [u8; 32]) {
        Issuer::initialize_key(key).unwrap();
        let store = KeyStore::open(key).unwrap();
        let k1 = store.stage(T0).unwrap();
        assert_eq!(store.schedule_activation(S, T0).unwrap(), k1);
        let k0 = store
            .manifest(T0)
            .unwrap()
            .keys
            .iter()
            .find(|k| k.activation_hour == Some(0))
            .unwrap()
            .key_id;
        (k0, k1)
    }

    fn fixture() -> (tempfile::TempDir, Arc<Issuer>) {
        let dir = tempfile::tempdir().unwrap();
        let adm = admission(dir.path());
        let key = dir.path().join("pp-signing.sqlite");
        Issuer::initialize_key(&key).unwrap();
        let issuer = Arc::new(open_at(&key, adm, T0).unwrap());
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

    fn unix_seconds_i64() -> i64 {
        i64::try_from(unix_now().unwrap()).unwrap()
    }

    struct Blinded {
        wire: Vec<u8>,
        state: BlindState,
        input: [u8; 98],
    }

    fn blinded(public: &PublicKey, key_id: &[u8; 32]) -> Blinded {
        let input = token_input(&[7; 32], &[8; 32], key_id);
        let (blinded_msg, state) = public.blind(&input).unwrap();
        let wire = TokenRequest {
            truncated_token_key_id: key_id[31],
            blinded_msg,
        }
        .to_bytes()
        .to_vec();
        Blinded { wire, state, input }
    }

    async fn issue_at_with(issuer: &Issuer, body: Vec<u8>, code: &str, now: u64) -> Response {
        let (parts, body) = request(body, code).into_parts();
        let bytes = to_bytes(body, 4096).await.unwrap();
        issuer.issue_at(&parts, &bytes, now).await
    }

    async fn assert_signed(response: Response, public: &PublicKey, request: Blinded) {
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
        let signature = public.finalize(request.state, &signature).unwrap();
        public.verify(&request.input, &signature).unwrap();
    }

    /// Checks that every directory entry has token type 2 and returns the decoded public keys.
    fn advertised(body: &str) -> Vec<Vec<u8>> {
        let document: serde_json::Value = serde_json::from_str(body).unwrap();
        document["token-keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                assert_eq!(entry["token-type"], 2);
                Base64Url::decode_vec(entry["token-key"].as_str().unwrap()).unwrap()
            })
            .collect()
    }

    #[test]
    fn open_refuses_missing_corrupt_and_below_high_water() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir().unwrap();
        let adm = admission(dir.path());
        let key = dir.path().join("pp-signing.sqlite");
        assert!(open_at(&key, adm.clone(), T0).is_err());
        Issuer::initialize_key(&key).unwrap();
        assert!(Issuer::initialize_key(&key).is_err());
        let corrupt = dir.path().join("corrupt");
        fs::write(&corrupt, b"not a key").unwrap();
        assert!(open_at(&corrupt, adm.clone(), T0).is_err());
        KeyStore::open(&key).unwrap().stage(T0).unwrap();
        let behind = open_at(&key, adm.clone(), T0 - 1)
            .err()
            .expect("open below the high-water mark must refuse");
        assert!(behind.to_string().contains("high-water"), "{behind:#}");
        assert!(open_at(&key, adm, T0).is_ok());
    }

    #[test]
    fn open_refuses_when_no_key_is_active() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir().unwrap();
        let adm = admission(dir.path());
        let key = dir.path().join("pp-signing.sqlite");
        Issuer::initialize_key(&key).unwrap();
        // Set activation to hour 5 so that the store is valid but has no active key before then.
        rusqlite::Connection::open(&key)
            .unwrap()
            .execute(
                "UPDATE keys SET activation_hour=5 WHERE activation_hour=0",
                [],
            )
            .unwrap();
        assert!(open_at(&key, adm.clone(), 0).is_err());
        assert!(open_at(&key, adm, 5 * SECONDS_PER_HOUR).is_ok());
    }

    #[tokio::test]
    async fn no_selected_key_yields_503_without_consuming_invitation() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let dir = tempfile::tempdir().unwrap();
        let adm = admission(dir.path());
        let key = dir.path().join("pp-signing.sqlite");
        Issuer::initialize_key(&key).unwrap();
        rusqlite::Connection::open(&key)
            .unwrap()
            .execute(
                "UPDATE keys SET activation_hour=5 WHERE activation_hour=0",
                [],
            )
            .unwrap();
        let store = KeyStore::open(&key).unwrap();
        let wire = {
            let keys = store.signing_keys(5 * SECONDS_PER_HOUR).unwrap();
            blinded(&keys[0].public, &keys[0].public.key_id()).wire
        };
        // Build the issuer directly with an empty key set to exercise failed selection.
        // `Issuer::open` rejects an empty key set before any request can arrive.
        let empty = Issuer {
            _key_store: store,
            keys: Arc::new(Vec::new()),
            latch: AtomicU64::new(0),
            admission: adm.clone(),
            request_url: ISSUER_URL.to_owned(),
            signers: Arc::new(Semaphore::new(SIGNER_CAPACITY)),
        };
        assert!(empty.directory_at(0).is_err());
        let code = adm.provision(0).unwrap();
        assert_eq!(
            issue_at_with(&empty, wire, &code, 0).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(adm.consume(&code, 0).unwrap(), "503 must not consume");
    }

    #[tokio::test]
    async fn directory_and_requests_follow_the_scheduled_hour() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let dir = tempfile::tempdir().unwrap();
        let adm = admission(dir.path());
        let key = dir.path().join("pp-signing.sqlite");
        let (k0, k1) = two_key_store(&key);

        let early = open_at(&key, adm.clone(), T0).unwrap();
        assert_eq!(early.keys.len(), 2);
        let k0_spki = early.keys[0].public.to_spki().to_vec();
        let k1_spki = early.keys[1].public.to_spki().to_vec();
        assert_eq!(advertised(&early.directory_at(T0).unwrap()), vec![k0_spki]);
        let code = adm.provision(T0 as i64).unwrap();
        // A request for the wrong key returns HTTP 422 and leaves the invitation usable.
        let wrong = blinded(&early.keys[1].public, &k1);
        assert_eq!(
            issue_at_with(&early, wrong.wire, &code, T0).await.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let right = blinded(&early.keys[0].public, &k0);
        let response = issue_at_with(&early, right.wire.clone(), &code, T0).await;
        assert_signed(response, &early.keys[0].public, right).await;
        drop(early);

        let late = open_at(&key, adm.clone(), S).unwrap();
        assert_eq!(
            advertised(&late.directory_at(S).unwrap()),
            vec![k1_spki.clone()]
        );
        assert_eq!(
            advertised(&late.directory_at(S + 3599).unwrap()),
            vec![k1_spki]
        );
        let code = adm.provision(S as i64).unwrap();
        let stale = blinded(&late.keys[0].public, &k0);
        assert_eq!(
            issue_at_with(&late, stale.wire, &code, S).await.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let fresh = blinded(&late.keys[1].public, &k1);
        let response = issue_at_with(&late, fresh.wire.clone(), &code, S).await;
        assert_signed(response, &late.keys[1].public, fresh).await;
    }

    #[tokio::test]
    async fn directory_cache_expires_at_next_activation() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let dir = tempfile::tempdir().unwrap();
        let adm = admission(dir.path());
        let key = dir.path().join("pp-signing.sqlite");
        let (old, new) = two_key_store(&key);
        let issuer = open_at(&key, adm, T0).unwrap();
        for (now, max_age, id) in [
            (S - 61, 60, old),
            (S - 60, 60, old),
            (S - 59, 59, old),
            (S - 1, 1, old),
            (S, 60, new),
            (S + 1, 60, new),
        ] {
            let response = issuer.directory_response_at(now);
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                format!("public, max-age={max_age}")
            );
            let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
            let body = std::str::from_utf8(&bytes).unwrap();
            let keys = advertised(body);
            assert_eq!(keys.len(), 1);
            assert_eq!(PublicKey::from_spki(&keys[0]).unwrap().key_id(), id);
        }
    }

    #[tokio::test]
    async fn clock_step_back_never_returns_to_an_older_key() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let dir = tempfile::tempdir().unwrap();
        let adm = admission(dir.path());
        let key = dir.path().join("pp-signing.sqlite");
        let (k0, k1) = two_key_store(&key);
        let issuer = open_at(&key, adm.clone(), T0).unwrap();
        let k1_spki = issuer.keys[1].public.to_spki().to_vec();
        // Advancing to K1's activation hour keeps K1 selected even if the clock goes back.
        assert_eq!(
            advertised(&issuer.directory_at(S).unwrap()),
            vec![k1_spki.clone()]
        );
        assert_eq!(
            advertised(&issuer.directory_at(S - 1).unwrap()),
            vec![k1_spki.clone()]
        );
        let code = adm.provision((S - 1) as i64).unwrap();
        let stale = blinded(&issuer.keys[0].public, &k0);
        assert_eq!(
            issue_at_with(&issuer, stale.wire, &code, S - 1)
                .await
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let fresh = blinded(&issuer.keys[1].public, &k1);
        let response = issue_at_with(&issuer, fresh.wire.clone(), &code, S - 1).await;
        assert_signed(response, &issuer.keys[1].public, fresh).await;
        assert_eq!(advertised(&issuer.directory_at(T0).unwrap()), vec![k1_spki]);
    }

    #[tokio::test]
    async fn staged_key_is_not_advertised_or_issued_and_preserves_invitation() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (_dir, issuer) = fixture();
        let staged_id = issuer._key_store.stage(T0).expect("stage a key");
        let staged_spki = issuer._key_store.spki(staged_id).unwrap();
        let staged = PublicKey::from_spki(&staged_spki).unwrap();
        let code = issuer.admission.provision(unix_seconds_i64()).unwrap();
        let staged_request = blinded(&staged, &staged_id);
        assert_eq!(
            issue(State(issuer.clone()), request(staged_request.wire, &code))
                .await
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let response = directory(State(issuer.clone())).await;
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(
            advertised(&body),
            vec![issuer.keys[0].public.to_spki().to_vec()]
        );
        let active_id = issuer.keys[0].public.key_id();
        let active_request = blinded(&issuer.keys[0].public, &active_id);
        let response = issue(
            State(issuer.clone()),
            request(active_request.wire.clone(), &code),
        )
        .await;
        assert_signed(response, &issuer.keys[0].public, active_request).await;
    }

    #[tokio::test]
    async fn directory_and_one_use_issuance() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (_dir, issuer) = fixture();
        let response = directory(State(issuer.clone())).await;
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/private-token-issuer-directory"
        );
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=60"
        );
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            document["issuer-request-uri"],
            "https://issuer.test/private-token/issue"
        );
        assert_eq!(document["token-keys"].as_array().unwrap().len(), 1);
        assert_eq!(document["token-keys"][0]["token-type"], 2);
        let encoded = document["token-keys"][0]["token-key"].as_str().unwrap();
        let spki = Base64Url::decode_vec(encoded).unwrap();
        assert_eq!(Base64Url::encode_string(&spki), encoded);
        let key_id = issuer.keys[0].public.key_id();
        assert_eq!(token_key_id(&spki), key_id);
        let public = PublicKey::from_spki(&spki).unwrap();
        let input = token_input(&[7; 32], &[8; 32], &key_id);
        let (blinded_msg, state) = public.blind(&input).unwrap();
        let wire = TokenRequest {
            truncated_token_key_id: key_id[31],
            blinded_msg,
        }
        .to_bytes();
        let code = issuer.admission.provision(unix_seconds_i64()).unwrap();
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
