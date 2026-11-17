//! Loopback HTTP reference client, including durable single-use enforcement.
use base64ct::{Base64Url, Encoding};
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
use reqwest::{header, Client, StatusCode};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, task::JoinHandle};

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

// Abort on unwinding too, so a failed assertion cannot leave a listener running.
struct Server(JoinHandle<()>);

impl Server {
    fn start(listener: TcpListener, router: axum::Router) -> Self {
        Self(tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        }))
    }

    async fn stop(self) {
        self.0.abort();
        // Await cancellation before reopening either store.
        // Borrow the handle because this type implements Drop.
        let mut server = self;
        let result = (&mut server.0).await;
        assert!(result.unwrap_err().is_cancelled());
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn issue(client: &Client, url: &str, wire: &[u8], invitation: &str) -> reqwest::Response {
    client
        .post(url)
        .header(header::CONTENT_TYPE, "application/private-token-request")
        .header("Freebird-Admission", invitation)
        .body(wire.to_vec())
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn loopback_http_roundtrip_and_durable_single_use() {
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
    let now = unix_now() as i64;
    let invitation = admission.provision(now).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer_name = listener.local_addr().unwrap().to_string();
    let issuer_base = format!("http://{issuer_name}");
    let issue_url = format!("{issuer_base}/private-token/issue");
    let server = Server::start(
        listener,
        issuer::router(Arc::new(
            Issuer::open(
                &signing_key,
                admission.clone(),
                &issuer_name,
                &issue_url,
                unix_now(),
            )
            .unwrap(),
        )),
    );
    drop(admission);
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    let directory = client
        .get(format!(
            "{issuer_base}/.well-known/private-token-issuer-directory"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(directory.status(), StatusCode::OK);
    assert_eq!(
        directory.headers()[header::CONTENT_TYPE],
        "application/private-token-issuer-directory"
    );
    let document: serde_json::Value =
        serde_json::from_slice(&directory.bytes().await.unwrap()).unwrap();
    assert_eq!(document["issuer-request-uri"], issue_url);
    assert_eq!(document["token-keys"][0]["token-type"], 2);
    let encoded = document["token-keys"][0]["token-key"].as_str().unwrap();
    let spki = Base64Url::decode_vec(encoded).unwrap();
    assert_eq!(Base64Url::encode_string(&spki), encoded);
    let public = PublicKey::from_spki(&spki).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let protected_url = format!(
        "http://{}/private-token/protected",
        listener.local_addr().unwrap()
    );
    let origin_server = Server::start(
        listener,
        origin::router(Arc::new(
            Origin::open(&replay_path, &context, &issuer_name, "origin.test").unwrap(),
        )),
    );
    let response = client.get(&protected_url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let field = response.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap();
    // This parser intentionally handles only this Origin's three RFC parameters.
    let fields: Vec<_> = field
        .strip_prefix("PrivateToken ")
        .unwrap()
        .split(", ")
        .collect();
    assert_eq!(fields.len(), 3);
    let decode = |value: &str, prefix: &str| {
        let encoded = value
            .strip_prefix(prefix)
            .unwrap()
            .strip_suffix('"')
            .unwrap();
        let bytes = Base64Url::decode_vec(encoded).unwrap();
        assert_eq!(Base64Url::encode_string(&bytes), encoded);
        bytes
    };
    let challenge_bytes = decode(fields[0], "challenge=\"");
    let challenge = TokenChallenge::parse(&challenge_bytes).unwrap();
    assert_eq!(challenge.serialize(), challenge_bytes);
    assert_eq!(decode(fields[1], "token-key=\""), spki);
    assert_eq!(challenge.issuer_name(), issuer_name);
    assert_eq!(challenge.origin_info(), "origin.test");
    let age: u64 = fields[2].strip_prefix("max-age=").unwrap().parse().unwrap();
    assert!((1..=3900).contains(&age));
    drop(response);

    let nonce = rand::random::<[u8; 32]>();
    let key_id = token_key_id(&spki);
    let input = token_input(&nonce, &challenge.digest(), &key_id);
    let (blinded_msg, blind_state) = public.blind(&input).unwrap();
    let wire = TokenRequest {
        truncated_token_key_id: key_id[31],
        blinded_msg,
    }
    .to_bytes();
    let mut wrong_type = wire;
    wrong_type[0] ^= 1;
    assert_eq!(
        issue(&client, &issue_url, &wrong_type, &invitation)
            .await
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut trailing = wire.to_vec();
    trailing.push(0);
    assert_eq!(
        issue(&client, &issue_url, &trailing, &invitation)
            .await
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let signed = issue(&client, &issue_url, &wire, &invitation).await;
    assert_eq!(signed.status(), StatusCode::OK);
    assert_eq!(
        signed.headers()[header::CONTENT_TYPE],
        "application/private-token-response"
    );
    assert_eq!(signed.headers()[header::CACHE_CONTROL], "no-store");
    let signed = TokenResponse::from_bytes(&signed.bytes().await.unwrap()).unwrap();
    let authenticator = public.finalize(blind_state, &signed.blind_sig).unwrap();
    public.verify(&input, &authenticator).unwrap();
    let authorization = build_authorization_header(&Token {
        nonce,
        challenge_digest: challenge.digest(),
        token_key_id: key_id,
        authenticator,
    });
    let accepted = client
        .get(&protected_url)
        .header(header::AUTHORIZATION, &authorization)
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(
        accepted.bytes().await.unwrap().as_ref(),
        b"protected resource\n"
    );
    assert_eq!(
        client
            .get(&protected_url)
            .header(header::AUTHORIZATION, &authorization)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        issue(&client, &issue_url, &wire, &invitation)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    origin_server.stop().await;
    server.stop().await;

    let admission = Arc::new(AdmissionStore::open(&admission_path, &generation).unwrap());
    let listener = TcpListener::bind(&issuer_name).await.unwrap();
    let server = Server::start(
        listener,
        issuer::router(Arc::new(
            Issuer::open(
                &signing_key,
                admission,
                &issuer_name,
                &issue_url,
                unix_now(),
            )
            .unwrap(),
        )),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reopened_protected_url = format!(
        "http://{}/private-token/protected",
        listener.local_addr().unwrap()
    );
    let origin_server = Server::start(
        listener,
        origin::router(Arc::new(
            Origin::open(&replay_path, &context, &issuer_name, "origin.test").unwrap(),
        )),
    );
    assert_eq!(
        issue(&client, &issue_url, &wire, &invitation)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .get(&reopened_protected_url)
            .header(header::AUTHORIZATION, &authorization)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    origin_server.stop().await;
    server.stop().await;
    drop(client);
    files.close().unwrap();
}
