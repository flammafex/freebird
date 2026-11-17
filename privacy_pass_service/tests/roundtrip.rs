//! Reference client: only HTTP wire data and the advertised public key cross roles.
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    response::Response,
    Router,
};
use base64ct::{Base64Url, Base64UrlUnpadded, Encoding};
use freebird_common::privacy_pass::{
    build_authorization_header, token_input, token_key_id, Token, TokenChallenge, TokenRequest,
    TokenResponse,
};
use freebird_crypto::privacy_pass::PublicKey;
use freebird_privacy_pass_service::{
    admission::AdmissionStore,
    issuer::{self, Issuer},
    key_store::KeyStore,
    origin::{self, Origin},
};
use std::{
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::Service;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Genesis SPKI and key ID, read through the key store before any role opens it.
fn genesis(key_path: &Path) -> (Vec<u8>, [u8; 32]) {
    let manifest = KeyStore::open(key_path)
        .unwrap()
        .manifest(unix_now())
        .unwrap();
    let genesis = manifest
        .keys
        .iter()
        .find(|key| key.activation_hour == Some(0))
        .unwrap();
    (genesis.spki.clone(), genesis.key_id)
}

// tower 0.4's optional `util` feature is not enabled in this package.
// Router is always ready; this is the same single-request dispatch as oneshot.
async fn oneshot(mut router: Router, request: Request<Body>) -> Response {
    router.call(request).await.unwrap()
}

async fn get(router: &Router, path: &str, authorization: Option<&str>) -> Response {
    let mut request = Request::builder().uri(path);
    if let Some(value) = authorization {
        request = request.header(header::AUTHORIZATION, value);
    }
    oneshot(router.clone(), request.body(Body::empty()).unwrap()).await
}

async fn issue(router: &Router, body: &[u8], admission: &str) -> Response {
    oneshot(
        router.clone(),
        Request::builder()
            .method("POST")
            .uri("/private-token/issue")
            .header(header::CONTENT_TYPE, "application/private-token-request")
            .header("Freebird-Admission", admission)
            .body(Body::from(body.to_vec()))
            .unwrap(),
    )
    .await
}

async fn empty(response: Response, status: StatusCode) {
    assert_eq!(response.status(), status);
    assert!(response.headers().get(header::CONTENT_TYPE).is_none());
    assert!(to_bytes(response.into_body(), 4096)
        .await
        .unwrap()
        .is_empty());
}

// Deliberately limited to the three parameters emitted by this reference Origin;
// this is not a general-purpose RFC authentication parser.
fn challenge(response: &Response) -> (TokenChallenge, Vec<u8>) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let field = response.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap();
    let fields: Vec<_> = field
        .strip_prefix("PrivateToken ")
        .unwrap()
        .split(", ")
        .collect();
    assert_eq!(fields.len(), 3);
    let decode = |field: &str, prefix: &str| {
        let encoded = field
            .strip_prefix(prefix)
            .unwrap()
            .strip_suffix('"')
            .unwrap();
        let bytes = Base64Url::decode_vec(encoded).unwrap();
        assert_eq!(Base64Url::encode_string(&bytes), encoded);
        bytes
    };
    let bytes = decode(fields[0], "challenge=\"");
    let parsed = TokenChallenge::parse(&bytes).unwrap();
    assert_eq!(parsed.serialize(), bytes); // Preserve the issued challenge exactly.
    let max_age: u64 = fields[2].strip_prefix("max-age=").unwrap().parse().unwrap();
    assert!((1..=3900).contains(&max_age));
    (parsed, decode(fields[1], "token-key=\""))
}

#[tokio::test]
async fn http_reference_client_and_durable_single_use() {
    let files = tempfile::tempdir().unwrap();
    let admission_path = files.path().join("admission.sqlite");
    let generation = files.path().join("admission-generation");
    let signing_key = files.path().join("issuer-keys.sqlite");
    let replay_path = files.path().join("origin.sqlite");
    let context = files.path().join("origin-context");
    AdmissionStore::initialize(&admission_path, &generation).unwrap();
    Issuer::initialize_key(&signing_key).unwrap();
    let (genesis_spki, genesis_id) = genesis(&signing_key);
    Origin::initialize(&replay_path, &context, &genesis_spki, genesis_id).unwrap();
    let admission = Arc::new(AdmissionStore::open(&admission_path, &generation).unwrap());
    let issuer_state = Arc::new(
        Issuer::open(
            &signing_key,
            admission.clone(),
            "issuer.test",
            "https://issuer.test/private-token/issue",
            unix_now(),
        )
        .unwrap(),
    );
    let issuer_router = issuer::router(issuer_state.clone());
    let directory = get(
        &issuer_router,
        "/.well-known/private-token-issuer-directory",
        None,
    )
    .await;
    assert_eq!(directory.status(), StatusCode::OK);
    assert_eq!(
        directory.headers()[header::CONTENT_TYPE],
        "application/private-token-issuer-directory"
    );
    let document: serde_json::Value =
        serde_json::from_slice(&to_bytes(directory.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(
        document["issuer-request-uri"],
        "https://issuer.test/private-token/issue"
    );
    assert_eq!(document["token-keys"].as_array().unwrap().len(), 1);
    assert_eq!(document["token-keys"][0]["token-type"], 2);
    let encoded = document["token-keys"][0]["token-key"].as_str().unwrap();
    let spki = Base64Url::decode_vec(encoded).unwrap();
    assert_eq!(Base64Url::encode_string(&spki), encoded);
    let public = PublicKey::from_spki(&spki).unwrap();
    // Origin receives only the public directory bytes, never a signing-key path.
    let origin_state =
        Arc::new(Origin::open(&replay_path, &context, "issuer.test", "origin.test").unwrap());
    let origin_router = origin::router(origin_state.clone());
    let response = get(&origin_router, "/private-token/protected", None).await;
    let (issued_challenge, advertised_key) = challenge(&response);
    empty(response, StatusCode::UNAUTHORIZED).await;
    assert_eq!(advertised_key, spki);
    assert_eq!(issued_challenge.issuer_name(), "issuer.test");
    assert_eq!(issued_challenge.origin_info(), "origin.test");
    let nonce = rand::random::<[u8; 32]>();
    let key_id = token_key_id(&spki);
    let input = token_input(&nonce, &issued_challenge.digest(), &key_id);
    let (blinded_msg, blind_state) = public.blind(&input).unwrap();
    let wire = TokenRequest {
        truncated_token_key_id: key_id[31],
        blinded_msg,
    }
    .to_bytes();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let invitation = admission.provision(now).unwrap();
    let unknown = Base64UrlUnpadded::encode_string(&[0; 32]);
    empty(
        issue(&issuer_router, &wire, &unknown).await,
        StatusCode::FORBIDDEN,
    )
    .await;
    for (length, status) in [
        (4096, StatusCode::UNPROCESSABLE_ENTITY),
        (4097, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        empty(
            issue(&issuer_router, &vec![0; length], &invitation).await,
            status,
        )
        .await;
    }
    for index in [0, 2] {
        let mut invalid = wire;
        invalid[index] ^= 1;
        empty(
            issue(&issuer_router, &invalid, &invitation).await,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }
    let mut trailing = wire.to_vec();
    trailing.push(0);
    empty(
        issue(&issuer_router, &trailing, &invitation).await,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await;
    let signed = issue(&issuer_router, &wire, &invitation).await;
    assert_eq!(signed.status(), StatusCode::OK);
    assert_eq!(
        signed.headers()[header::CONTENT_TYPE],
        "application/private-token-response"
    );
    assert_eq!(signed.headers()[header::CACHE_CONTROL], "no-store");
    let signed =
        TokenResponse::from_bytes(&to_bytes(signed.into_body(), 256).await.unwrap()).unwrap();
    let authenticator = public.finalize(blind_state, &signed.blind_sig).unwrap();
    public.verify(&input, &authenticator).unwrap();
    let token = Token {
        nonce,
        challenge_digest: issued_challenge.digest(),
        token_key_id: key_id,
        authenticator,
    };
    for index in [0, 34, 66] {
        let mut invalid = token.to_bytes().to_vec();
        invalid[index] ^= 1;
        let authorization = format!(
            "PrivateToken token=\"{}\"",
            Base64Url::encode_string(&invalid)
        );
        empty(
            get(
                &origin_router,
                "/private-token/protected",
                Some(&authorization),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        )
        .await;
    }
    let mut trailing = token.to_bytes().to_vec();
    trailing.push(0);
    let authorization = format!(
        "PrivateToken token=\"{}\"",
        Base64Url::encode_string(&trailing)
    );
    empty(
        get(
            &origin_router,
            "/private-token/protected",
            Some(&authorization),
        )
        .await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    // A distinct Origin has its own issued contexts, even with the same public key.
    let other_db = files.path().join("other.sqlite");
    let other_context = files.path().join("other-context");
    Origin::initialize(&other_db, &other_context, &spki, public.key_id()).unwrap();
    let other = origin::router(Arc::new(
        Origin::open(&other_db, &other_context, "issuer.test", "other.test").unwrap(),
    ));
    let authorization = build_authorization_header(&token);
    empty(
        get(&other, "/private-token/protected", Some(&authorization)).await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    // Concurrent HTTP redemption has exactly one winner.
    let (first, second) = tokio::join!(
        get(
            &origin_router,
            "/private-token/protected",
            Some(&authorization)
        ),
        get(
            &origin_router,
            "/private-token/protected",
            Some(&authorization)
        )
    );
    let (accepted, rejected) = if first.status() == StatusCode::OK {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(
        accepted.headers()[header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        &to_bytes(accepted.into_body(), 4096).await.unwrap()[..],
        b"protected resource\n"
    );
    empty(rejected, StatusCode::UNAUTHORIZED).await;
    for path in [
        "/issue",
        "/verify",
        "/v1/issue",
        "/v1/verify",
        "/renew",
        "/admin/issue",
    ] {
        empty(get(&issuer_router, path, None).await, StatusCode::NOT_FOUND).await;
        empty(get(&origin_router, path, None).await, StatusCode::NOT_FOUND).await;
    }
    drop(origin_router);
    drop(origin_state);
    drop(issuer_router);
    drop(issuer_state);
    drop(admission);
    let admission = Arc::new(AdmissionStore::open(&admission_path, &generation).unwrap());
    let issuer_router = issuer::router(Arc::new(
        Issuer::open(
            &signing_key,
            admission,
            "issuer.test",
            "https://issuer.test/private-token/issue",
            unix_now(),
        )
        .unwrap(),
    ));
    let origin_router = origin::router(Arc::new(
        Origin::open(&replay_path, &context, "issuer.test", "origin.test").unwrap(),
    ));
    empty(
        issue(&issuer_router, &wire, &invitation).await,
        StatusCode::FORBIDDEN,
    )
    .await;
    empty(
        get(
            &origin_router,
            "/private-token/protected",
            Some(&authorization),
        )
        .await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
}
