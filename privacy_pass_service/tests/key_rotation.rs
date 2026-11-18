//! These tests pass explicit times to `Issuer::directory_at`, `Issuer::issue_at`, and
//! `Origin::request_at` to exercise offline rotation and retirement with blind RSA.
//! The CLI tests use a far-future activation and a past retirement deadline so that the real
//! clock cannot cross either boundary during the tests. The loopback client verifies the full HTTP flow.
use axum::{
    body::to_bytes,
    http::{header, Request, StatusCode},
};
use base64ct::{Base64Url, Encoding};
use freebird_common::privacy_pass::{
    token_input, Token, TokenChallenge, TokenRequest, TokenResponse,
};
use freebird_crypto::privacy_pass::{BlindState, PublicKey, SecretKey};
use freebird_privacy_pass_service::{
    admission::AdmissionStore,
    issuer::Issuer,
    key_store::{KeyState, KeyStore},
    origin::{Origin, OriginKeyState},
};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// Coordinate store tests and CLI launches within this test binary so that a child cannot
// temporarily inherit a file lock while another test is reopening the store.
static SPAWN_LOCK: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

const BIN: &str = env!("CARGO_BIN_EXE_freebird-privacy-pass-service");
const TIMEOUT: Duration = Duration::from_secs(60);
const ISSUER: &str = "issuer.test";
const ORIGIN: &str = "origin.test";
const ISSUE_URL: &str = "https://issuer.test/private-token/issue";
const H0: u64 = 500_000;
const T0: u64 = H0 * 3600 + 17;
const S: u64 = (H0 + 10) * 3600;
const ZERO_ID: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const KEY_V1: &str = "key schema v1 unsupported; no migration — initialize fresh state";
const ORIGIN_V1: &str = "origin schema v1 unsupported; no migration — initialize fresh state";
const V1_ORIGIN_DDL: &str = "CREATE TABLE metadata (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        version INTEGER NOT NULL CHECK(version=1),
        secret_hash BLOB NOT NULL,
        high_water INTEGER NOT NULL CHECK(high_water>=0),
        binding BLOB);
     INSERT INTO metadata VALUES(1,1,zeroblob(32),0,NULL);
     CREATE TABLE challenges (
        key_id BLOB NOT NULL, digest BLOB NOT NULL, deadline INTEGER NOT NULL,
        PRIMARY KEY(key_id,digest));
     CREATE TABLE spent (
        key_id BLOB NOT NULL, digest BLOB NOT NULL, nonce BLOB NOT NULL,
        deadline INTEGER NOT NULL,
        PRIMARY KEY(key_id,digest,nonce));";

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Picks an hour about ten years ahead so that the activation time stays in the future during the test.
fn far_future() -> u64 {
    (unix_now() / 3600 + 24 * 365 * 10) * 3600
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Loads the initial public key and its ID before either service opens its store.
fn genesis(keys: &Path, now: u64) -> (Vec<u8>, [u8; 32]) {
    let manifest = KeyStore::open(keys).unwrap().manifest(now).unwrap();
    let key = manifest
        .keys
        .iter()
        .find(|key| key.activation_hour == Some(0))
        .unwrap();
    (key.spki.clone(), key.key_id)
}

// Keep the blinded request and client state together so that the test can finalize the issuer's reply.

struct Blinded {
    wire: Vec<u8>,
    input: [u8; 98],
    state: BlindState,
    nonce: [u8; 32],
    key_id: [u8; 32],
    digest: [u8; 32],
}

fn blind(public: &PublicKey, digest: [u8; 32]) -> Blinded {
    let nonce = rand::random::<[u8; 32]>();
    let key_id = public.key_id();
    let input = token_input(&nonce, &digest, &key_id);
    let (blinded_msg, state) = public.blind(&input).unwrap();
    let wire = TokenRequest {
        truncated_token_key_id: key_id[31],
        blinded_msg,
    }
    .to_bytes()
    .to_vec();
    Blinded {
        wire,
        input,
        state,
        nonce,
        key_id,
        digest,
    }
}

fn finish(public: &PublicKey, blinded: Blinded, blind_sig: &[u8; 256]) -> Token {
    let authenticator = public.finalize(blinded.state, blind_sig).unwrap();
    public.verify(&blinded.input, &authenticator).unwrap();
    Token {
        nonce: blinded.nonce,
        challenge_digest: blinded.digest,
        token_key_id: blinded.key_id,
        authenticator,
    }
}

async fn send(issuer: &Issuer, invitation: &str, wire: &[u8], now: u64) -> (StatusCode, Vec<u8>) {
    let (parts, _) = Request::builder()
        .method("POST")
        .uri("/private-token/issue")
        .header(header::CONTENT_TYPE, "application/private-token-request")
        .header("Freebird-Admission", invitation)
        .body(())
        .unwrap()
        .into_parts();
    let response = issuer.issue_at(&parts, wire, now).await;
    let status = response.status();
    let body = to_bytes(response.into_body(), 256).await.unwrap().to_vec();
    (status, body)
}

async fn issue(
    issuer: &Issuer,
    invitation: &str,
    public: &PublicKey,
    digest: [u8; 32],
    now: u64,
) -> Token {
    let blinded = blind(public, digest);
    let (status, body) = send(issuer, invitation, &blinded.wire, now).await;
    assert_eq!(status, StatusCode::OK);
    let response = TokenResponse::from_bytes(&body).unwrap();
    finish(public, blinded, &response.blind_sig)
}

fn invite(admission: &AdmissionStore, now: u64) -> String {
    admission.provision(now as i64).unwrap()
}

/// Checks that the directory at `now` advertises exactly one type 2 key and returns it.
fn advertised(issuer: &Issuer, now: u64) -> PublicKey {
    let document: serde_json::Value =
        serde_json::from_str(&issuer.directory_at(now).unwrap()).unwrap();
    let keys = document["token-keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["token-type"], 2);
    let spki = Base64Url::decode_vec(keys[0]["token-key"].as_str().unwrap()).unwrap();
    PublicKey::from_spki(&spki).unwrap()
}

/// Sends an unauthenticated request at `now` and returns the challenge, public key bytes, and `max-age`.
fn challenge(origin: &Origin, now: u64) -> (TokenChallenge, Vec<u8>, u64) {
    let header = origin
        .request_at(None, now)
        .unwrap()
        .expect("unauthenticated request is challenged");
    let fields: Vec<&str> = header
        .strip_prefix("PrivateToken ")
        .unwrap()
        .split(", ")
        .collect();
    assert_eq!(fields.len(), 3);
    let quoted = |field: &str, name: &str| {
        let encoded = field.strip_prefix(name).unwrap().strip_suffix('"').unwrap();
        Base64Url::decode_vec(encoded).unwrap()
    };
    let challenge = TokenChallenge::parse(&quoted(fields[0], "challenge=\"")).unwrap();
    let key = quoted(fields[1], "token-key=\"");
    let max_age = fields[2].strip_prefix("max-age=").unwrap().parse().unwrap();
    (challenge, key, max_age)
}

/// Returns `true` if redemption at `now` succeeds and the origin does not send another challenge.
fn redeem(origin: &Origin, token: &Token, now: u64) -> bool {
    origin.request_at(Some(token), now).unwrap().is_none()
}

#[tokio::test]
async fn in_process_rotation_drill_with_injected_clock() {
    let _spawn_guard = SPAWN_LOCK.read().await;
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("issuer-keys.sqlite");
    let admission_path = dir.path().join("admission.sqlite");
    let generation = dir.path().join("generation");
    let origin_db = dir.path().join("origin.sqlite");
    let context = dir.path().join("context");
    AdmissionStore::initialize(&admission_path, &generation).unwrap();
    Issuer::initialize_key(&keys).unwrap();
    let (genesis_spki, genesis_id) = genesis(&keys, T0);
    Origin::initialize(&origin_db, &context, &genesis_spki, genesis_id).unwrap();

    // Stage at `T0` and install the public key on the origin before scheduling it on the issuer
    // so that the origin can verify tokens as soon as issuance switches keys.
    let store = KeyStore::open(&keys).unwrap();
    let next_id = store.stage(T0).unwrap();
    let next_spki = store.spki(next_id).unwrap();
    drop(store);
    Origin::install_key(&origin_db, &next_spki, next_id, S, T0).unwrap();
    let store = KeyStore::open(&keys).unwrap();
    assert_eq!(store.schedule_activation(S, T0).unwrap(), next_id);
    // Sign with the scheduled private key in the test to check that redemption still requires
    // a challenge issued for that key.
    let next_secret = store
        .signing_keys(T0)
        .unwrap()
        .into_iter()
        .find(|key| key.activation_hour == H0 + 10)
        .unwrap()
        .secret;
    drop(store);

    let admission = Arc::new(AdmissionStore::open(&admission_path, &generation).unwrap());
    let issuer = Issuer::open(&keys, admission.clone(), ISSUER, ISSUE_URL, T0).unwrap();
    let origin = Origin::open(&origin_db, &context, ISSUER, ORIGIN).unwrap();
    let genesis_public = PublicKey::from_spki(&genesis_spki).unwrap();
    let next_public = PublicKey::from_spki(&next_spki).unwrap();

    // Before `S`, the directory advertises only the initial key because the successor is not active.
    assert_eq!(advertised(&issuer, T0).key_id(), genesis_id);

    // At `S - 3`, the origin rejects a token signed by the installed key K1 because it has
    // no challenge row for K1, even though K0 issued a challenge for that digest.
    let before = S - 3;
    let (pre, pre_key, pre_age) = challenge(&origin, before);
    assert_eq!(pre_key, genesis_spki);
    assert_eq!(pre_age, S + 300 - before);
    let d9 = pre.digest();
    let forged = {
        let blinded = blind(&next_public, d9);
        let msg = TokenRequest::from_bytes(&blinded.wire).unwrap().blinded_msg;
        let signature = next_secret.blind_sign(&msg).unwrap();
        finish(&next_public, blinded, &signature)
    };
    assert!(!redeem(&origin, &forged, before));

    // At `S - 2`, a request with K1's truncated ID returns HTTP 422 because the issuer selects K0.
    // The same invitation still works for a request that targets K0.
    let at = S - 2;
    assert_eq!(advertised(&issuer, at).key_id(), genesis_id);
    let token_a = issue(&issuer, &invite(&admission, at), &genesis_public, d9, at).await;
    let invitation_b = invite(&admission, at);
    let wrong_key = blind(&next_public, d9).wire;
    assert_eq!(
        send(&issuer, &invitation_b, &wrong_key, at).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let token_b = issue(&issuer, &invitation_b, &genesis_public, d9, at).await;
    let token_c = issue(&issuer, &invite(&admission, at), &genesis_public, d9, at).await;
    let token_d = issue(&issuer, &invite(&admission, at), &genesis_public, d9, at).await;

    // At `S - 1`, the hour is still `H0 + 9`, so the challenge has the same digest.
    // The deadline at `S + 300` gives a `max-age` of 301 seconds.
    let (late, late_key, late_age) = challenge(&origin, S - 1);
    assert_eq!(late.digest(), d9);
    assert_eq!(late_key, genesis_spki);
    assert_eq!(late_age, 301);

    // Offline retirement fails before `S` and succeeds at `S`, when the successor takes over issuance.
    // The origin can still verify signatures from before retirement because it uses the public key.
    drop(issuer);
    let store = KeyStore::open(&keys).unwrap();
    assert!(store.retire(genesis_id, S - 1).is_err());
    store.retire(genesis_id, S).unwrap();
    let manifest = store.manifest(S).unwrap();
    assert_eq!(manifest.keys[0].state, KeyState::Retired);
    assert!(!manifest.keys[0].has_private);
    assert_eq!(store.signing_keys(S).unwrap().len(), 1);
    drop(store);
    let issuer = Issuer::open(&keys, admission.clone(), ISSUER, ISSUE_URL, S).unwrap();

    // At `S + 1`, both services advertise K1, and the issuer rejects requests that target K0.
    let at = S + 1;
    assert_eq!(advertised(&issuer, at).key_id(), next_id);
    let (post, post_key, post_age) = challenge(&origin, at);
    assert_eq!(post_key, next_spki);
    assert_eq!(post_age, 3600 + 300 - 1);
    let d10 = post.digest();
    assert_ne!(d10, d9);
    let invitation_e = invite(&admission, at);
    let genesis_request = blind(&genesis_public, d10).wire;
    assert_eq!(
        send(&issuer, &invitation_e, &genesis_request, at).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let token_e = issue(&issuer, &invitation_e, &next_public, d10, at).await;
    // The issuer signs with K1, but the origin rejects that token because the digest was challenged under K0.
    let token_g = issue(&issuer, &invite(&admission, at), &next_public, d9, at).await;

    // At `S + 2`, a K1 token for its own challenge redeems once, while the K1 token for K0's challenge fails.
    assert!(redeem(&origin, &token_e, S + 2));
    assert!(!redeem(&origin, &token_e, S + 2), "replay must fail");
    assert!(!redeem(&origin, &token_g, S + 2));

    // At `S + 10`, changing only the key ID from K0 to K1 makes redemption fail.
    // The token with its original ID still redeems.
    let swapped = Token {
        nonce: token_d.nonce,
        challenge_digest: token_d.challenge_digest,
        token_key_id: next_id,
        authenticator: token_d.authenticator,
    };
    assert!(!redeem(&origin, &swapped, S + 10));
    assert!(redeem(&origin, &token_d, S + 11));

    // At `S + 100`, a token issued before activation redeems once because it is still within the grace period.
    assert!(redeem(&origin, &token_a, S + 100));
    assert!(!redeem(&origin, &token_a, S + 100));

    // Redemption succeeds at `S + 299` but fails at `S + 300` because the deadline is exclusive.
    assert!(redeem(&origin, &token_c, S + 299));
    assert!(!redeem(&origin, &token_b, S + 300));

    // Offline retirement on the origin requires the 300-second grace period and a 120-second safety margin to pass.
    // Retirement removes both the challenge and spent rows for the retired key in one transaction.
    drop(origin);
    drop(issuer);
    assert!(Origin::retire_key(&origin_db, genesis_id, S + 419).is_err());
    Origin::retire_key(&origin_db, genesis_id, S + 420).unwrap();
    let status = Origin::status(&origin_db, S + 420).unwrap();
    assert_eq!(status.high_water, S + 420);
    assert_eq!(status.keys[0].state, OriginKeyState::Retired);
    assert_eq!(status.keys[1].state, OriginKeyState::Advertising);
    assert!(Origin::install_key(&origin_db, &genesis_spki, genesis_id, S + 7200, S + 420).is_err());
    let origin = Origin::open(&origin_db, &context, ISSUER, ORIGIN).unwrap();
    // A token for the retired key returns a challenge, which the HTTP handler sends with HTTP 401.
    assert!(origin
        .request_at(Some(&token_b), S + 420)
        .unwrap()
        .is_some());
    drop(origin);

    // Retired rows remain to prevent reuse of their IDs, but they leave room to stage the next candidate.
    let at = S + 421;
    let s2 = S + 7200;
    let store = KeyStore::open(&keys).unwrap();
    let third_id = store.stage(at).unwrap();
    let third_spki = store.spki(third_id).unwrap();
    drop(store);
    Origin::install_key(&origin_db, &third_spki, third_id, s2, at).unwrap();
    let store = KeyStore::open(&keys).unwrap();
    assert_eq!(store.schedule_activation(s2, at).unwrap(), third_id);
    drop(store);
    let issuer = Issuer::open(&keys, admission.clone(), ISSUER, ISSUE_URL, at).unwrap();
    let origin = Origin::open(&origin_db, &context, ISSUER, ORIGIN).unwrap();
    assert_eq!(advertised(&issuer, s2 - 1).key_id(), next_id);
    let (pre, key, age) = challenge(&origin, s2 - 1);
    assert_eq!(key, next_spki);
    assert_eq!(age, 301);
    let carried = issue(
        &issuer,
        &invite(&admission, s2 - 1),
        &next_public,
        pre.digest(),
        s2 - 1,
    )
    .await;

    assert_eq!(advertised(&issuer, s2).key_id(), third_id);
    let (post, key, _) = challenge(&origin, s2);
    assert_eq!(key, third_spki);
    let third_public = PublicKey::from_spki(&third_spki).unwrap();
    let fresh = issue(
        &issuer,
        &invite(&admission, s2),
        &third_public,
        post.digest(),
        s2,
    )
    .await;
    assert!(redeem(&origin, &carried, s2));
    assert!(!redeem(&origin, &carried, s2));
    assert!(redeem(&origin, &fresh, s2));
    assert!(!redeem(&origin, &fresh, s2));
    drop(issuer);
    drop(origin);
    KeyStore::open(&keys).unwrap().retire(next_id, s2).unwrap();
    Origin::retire_key(&origin_db, next_id, s2 + 420).unwrap();
    let issuer = Issuer::open(&keys, admission.clone(), ISSUER, ISSUE_URL, s2 + 420).unwrap();
    assert_eq!(advertised(&issuer, s2 + 420).key_id(), third_id);
    assert_eq!(
        Origin::status(&origin_db, s2 + 420)
            .unwrap()
            .keys
            .iter()
            .filter(|key| key.state == OriginKeyState::Retired)
            .count(),
        2
    );
    assert!(Origin::install_key(&origin_db, &next_spki, next_id, s2 + 7200, s2 + 420).is_err());
    let origin = Origin::open(&origin_db, &context, ISSUER, ORIGIN).unwrap();
    assert!(!redeem(&origin, &carried, s2 + 420));
    let (post, _, _) = challenge(&origin, s2 + 420);
    let after_retirement = issue(
        &issuer,
        &invite(&admission, s2 + 420),
        &third_public,
        post.digest(),
        s2 + 420,
    )
    .await;
    assert!(redeem(&origin, &after_retirement, s2 + 420));
}

// Wrap each CLI subprocess so that drop stops it and waits for it to exit, even if an assertion fails.

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run(args: &[&str]) -> Output {
    let mut child = Process(
        Command::new(BIN)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn CLI"),
    );
    let deadline = Instant::now() + TIMEOUT;
    while child.0.try_wait().expect("poll CLI").is_none() {
        assert!(Instant::now() < deadline, "{args:?} timed out");
        thread::sleep(Duration::from_millis(25));
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    Output {
        status: child.0.wait().unwrap(),
        stdout,
        stderr,
    }
}

fn run_ok(args: &[&str]) -> Output {
    let output = run(args);
    assert!(output.status.success(), "{args:?} failed: {output:?}");
    output
}

fn run_refused(args: &[&str]) -> Output {
    let output = run(args);
    assert!(!output.status.success(), "{args:?} unexpectedly succeeded");
    output
}

fn run_refused_with(args: &[&str], message: &str) {
    let output = run_refused(args);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(message),
        "{args:?}: expected {message:?} in {stderr}"
    );
}

fn spawn_server(args: &[&str]) -> Process {
    Process(
        Command::new(BIN)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn server"),
    )
}

fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("loopback test environment")
        .local_addr()
        .unwrap()
}

/// Sends a plain HTTP/1.1 `GET` and returns its response, or returns `None` if the attempt fails.
fn respond(address: SocketAddr, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(200)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut text = String::new();
    stream.take(65536).read_to_string(&mut text).ok()?;
    Some(text)
}

fn wait_ready(server: &mut Process, address: SocketAddr, path: &str, ready: impl Fn(&str) -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "server exited before readiness (possible port race)"
        );
        if respond(address, path).is_some_and(|text| ready(&text)) {
            return;
        }
        assert!(Instant::now() < deadline, "readiness timed out");
        thread::sleep(Duration::from_millis(25));
    }
}

/// Decodes the `token-keys` from a directory response into public key bytes.
fn directory_keys(text: &str) -> Vec<Vec<u8>> {
    let body = text.split_once("\r\n\r\n").unwrap().1;
    let document: serde_json::Value = serde_json::from_str(body).unwrap();
    document["token-keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| Base64Url::decode_vec(key["token-key"].as_str().unwrap()).unwrap())
        .collect()
}

/// Decodes the `token-key` parameter from the origin's challenge into public key bytes.
fn challenge_token_key(text: &str) -> Vec<u8> {
    let marker = "token-key=\"";
    let start = text.find(marker).unwrap() + marker.len();
    let end = start + text[start..].find('"').unwrap();
    Base64Url::decode_vec(&text[start..end]).unwrap()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    state: String,
    id: String,
    activation: String,
    issuance_end: String,
    acceptance_deadline: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Status {
    high_water: u64,
    rows: Vec<Row>,
}

/// Checks that status starts with `now` and `high-water`, then parses each key's five fields.
/// Each row has the state, ID, activation time, end of issuance, and acceptance deadline.
fn parse_status(output: &Output) -> Status {
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout.clone()).unwrap();
    let mut lines = text.lines();
    let now = lines.next().unwrap().strip_prefix("now ").unwrap();
    now.parse::<u64>().expect("now is decimal seconds");
    let high = lines.next().unwrap().strip_prefix("high-water ").unwrap();
    let high_water = high.parse::<u64>().unwrap();
    let rows = lines
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            assert_eq!(fields.len(), 5, "row: {line}");
            assert!(matches!(
                fields[0],
                "staged"
                    | "scheduled"
                    | "active"
                    | "retired-for-issuance"
                    | "retired"
                    | "installed"
                    | "advertising"
                    | "verifying"
            ));
            assert_eq!(fields[1].len(), 64);
            assert!(fields[1]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
            for time in &fields[2..] {
                assert!(
                    *time == "-" || (!time.is_empty() && time.bytes().all(|b| b.is_ascii_digit())),
                    "time field: {time}"
                );
            }
            Row {
                state: fields[0].to_owned(),
                id: fields[1].to_owned(),
                activation: fields[2].to_owned(),
                issuance_end: fields[3].to_owned(),
                acceptance_deadline: fields[4].to_owned(),
            }
        })
        .collect();
    Status { high_water, rows }
}

fn issuer_status(dir: &Path) -> Status {
    parse_status(&run_ok(&["issuer-key-status", p(dir)]))
}

fn origin_status(dir: &Path) -> Status {
    parse_status(&run_ok(&["origin-key-status", p(dir)]))
}

fn row(state: &str, id: &str, activation: &str, issuance_end: &str, acceptance: &str) -> Row {
    Row {
        state: state.to_owned(),
        id: id.to_owned(),
        activation: activation.to_owned(),
        issuance_end: issuance_end.to_owned(),
        acceptance_deadline: acceptance.to_owned(),
    }
}

/// Sorts the ID and activation pairs so that the two roles can be compared regardless of row order.
fn id_and_activation(status: &Status) -> Vec<(String, String)> {
    let mut pairs: Vec<_> = status
        .rows
        .iter()
        .map(|row| (row.id.clone(), row.activation.clone()))
        .collect();
    pairs.sort();
    pairs
}

fn example_binary() -> PathBuf {
    // Locate the example relative to the service binary that Cargo provides so that this works
    // even when Cargo uses a separate build directory.
    let example = Path::new(BIN)
        .parent()
        .unwrap()
        .join("examples")
        .join("loopback_client");
    assert!(
        example.exists(),
        "build examples first (cargo test --all-targets): {}",
        example.display()
    );
    example
}

// Run both services with eligible keys to check that their locks block offline retirement.

#[test]
fn cli_retirement_runbook_with_past_activation_and_real_clock() {
    let _spawn_guard = SPAWN_LOCK.blocking_write();
    let temp = tempfile::tempdir().unwrap();
    let issuer = temp.path().join("issuer");
    let origin = temp.path().join("origin");
    fs::create_dir(&issuer).unwrap();
    fs::create_dir(&origin).unwrap();
    let keys = issuer.join("issuer-keys.sqlite");
    let db = origin.join("origin.sqlite");
    let context = origin.join("context");

    // Use past times with the public APIs so that both stores are eligible for retirement under
    // the CLI's system clock without waiting for a time boundary.
    let started = unix_now();
    let s = (started / 3600 - 24) * 3600;
    let then = s - 3600;
    AdmissionStore::initialize(issuer.join("admission.sqlite"), issuer.join("generation")).unwrap();
    KeyStore::initialize(&keys).unwrap();
    let (genesis_spki, genesis_id) = genesis(&keys, then);
    Origin::initialize(&db, &context, &genesis_spki, genesis_id).unwrap();
    let store = KeyStore::open(&keys).unwrap();
    let next_id = store.stage(then).unwrap();
    let next_spki = store.spki(next_id).unwrap();
    Origin::install_key(&db, &next_spki, next_id, s, then).unwrap();
    store.schedule_activation(s, then).unwrap();
    drop(store);
    let past_origin = Origin::open(&db, &context, ISSUER, ORIGIN).unwrap();
    challenge(&past_origin, s - 1);
    drop(past_origin);
    assert!(started >= s + 420);

    let genesis_hex: String = genesis_id.iter().map(|b| format!("{b:02x}")).collect();
    let next_hex: String = next_id.iter().map(|b| format!("{b:02x}")).collect();
    assert_ne!(genesis_hex, ZERO_ID);
    assert_ne!(next_hex, ZERO_ID);
    let before_issuer = issuer_status(&issuer);
    let before_origin = origin_status(&origin);
    assert_eq!(before_issuer.rows[0].state, "retired-for-issuance");
    assert_eq!(before_origin.rows[0].state, "verifying");

    for (command, state, active_id) in [
        ("retire-issuer-key", &issuer, next_hex.as_str()),
        ("retire-origin-key", &origin, next_hex.as_str()),
    ] {
        for malformed in ["short".to_owned(), "g".repeat(64), "0".repeat(63)] {
            run_refused_with(&[command, p(state), &malformed], "invalid key ID");
        }
        run_refused(&[command, p(state), ZERO_ID]);
        run_refused(&[command, p(state), active_id]);
    }
    assert_eq!(issuer_status(&issuer), before_issuer);
    assert_eq!(origin_status(&origin), before_origin);

    // Each running service holds its store lock, so offline retirement fails even for the eligible key.
    let issuer_addr = free_address();
    let mut issuer_server = spawn_server(&[
        "serve-issuer",
        p(&issuer),
        ISSUER,
        ISSUE_URL,
        &issuer_addr.to_string(),
    ]);
    wait_ready(
        &mut issuer_server,
        issuer_addr,
        "/.well-known/private-token-issuer-directory",
        |text| text.starts_with("HTTP/1.1 200"),
    );
    run_refused_with(
        &["retire-issuer-key", p(&issuer), &genesis_hex],
        "already owned",
    );
    drop(issuer_server);
    assert_eq!(issuer_status(&issuer), before_issuer);
    let origin_addr = free_address();
    let mut origin_server = spawn_server(&[
        "serve-origin",
        p(&origin),
        ISSUER,
        ORIGIN,
        &origin_addr.to_string(),
    ]);
    wait_ready(
        &mut origin_server,
        origin_addr,
        "/private-token/protected",
        |text| text.starts_with("HTTP/1.1 401"),
    );
    run_refused_with(
        &["retire-origin-key", p(&origin), &genesis_hex],
        "already owned",
    );
    drop(origin_server);
    assert_eq!(origin_status(&origin).rows, before_origin.rows);

    for (command, state) in [
        ("retire-issuer-key", &issuer),
        ("retire-origin-key", &origin),
    ] {
        let output = run_ok(&[command, p(state), &genesis_hex]);
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }
    let issuer_output = run_ok(&["issuer-key-status", p(&issuer)]);
    let origin_output = run_ok(&["origin-key-status", p(&origin)]);
    let retired_issuer = parse_status(&issuer_output);
    let retired_origin = parse_status(&origin_output);
    assert!(retired_issuer.high_water >= started);
    assert!(retired_origin.high_water >= started);
    assert_eq!(retired_issuer.rows[0].state, "retired");
    assert_eq!(retired_origin.rows[0].state, "retired");
    assert_eq!(retired_issuer.rows[1].state, "active");
    assert_eq!(retired_origin.rows[1].state, "advertising");
    assert_eq!(
        id_and_activation(&retired_issuer),
        id_and_activation(&retired_origin)
    );
    let mut expected_issuer = before_issuer.rows;
    let mut expected_origin = before_origin.rows;
    expected_issuer[0].state = "retired".to_owned();
    expected_origin[0].state = "retired".to_owned();
    assert_eq!(retired_issuer.rows, expected_issuer);
    assert_eq!(retired_origin.rows, expected_origin);
    println!("retire-issuer-key: exit 0; retire-origin-key: exit 0; S={s}");
    println!(
        "issuer-key-status:\n{}",
        String::from_utf8(issuer_output.stdout).unwrap()
    );
    println!(
        "origin-key-status:\n{}",
        String::from_utf8(origin_output.stdout).unwrap()
    );

    // A retired ID still allows public key export, but attempts to install or retire it again fail.
    let genesis_der = temp.path().join("genesis.der");
    run_ok(&[
        "export-issuer-spki",
        p(&issuer),
        &genesis_hex,
        p(&genesis_der),
    ]);
    assert_eq!(fs::read(&genesis_der).unwrap(), genesis_spki);
    run_refused(&[
        "install-origin-key",
        p(&origin),
        p(&genesis_der),
        &genesis_hex,
        &far_future().to_string(),
    ]);
    run_refused(&["retire-issuer-key", p(&issuer), &genesis_hex]);
    run_refused(&["retire-origin-key", p(&origin), &genesis_hex]);
    assert_eq!(issuer_status(&issuer), retired_issuer);
    assert_eq!(origin_status(&origin), retired_origin);
}

#[test]
fn cli_runbook_rotates_origin_first_and_status_columns_agree() {
    let _spawn_guard = SPAWN_LOCK.blocking_write();
    let temp = tempfile::tempdir().unwrap();
    let issuer = temp.path().join("issuer");
    let origin = temp.path().join("origin");
    let genesis_der = temp.path().join("genesis.der");
    let next_der = temp.path().join("next.der");
    let far = far_future();
    let far_s = far.to_string();
    let far_plus_one = (far + 1).to_string();
    let past_s = ((unix_now() / 3600 - 2) * 3600).to_string();

    run_ok(&["init-issuer", p(&issuer)]);
    let genesis = issuer_status(&issuer).rows[0].clone();
    assert_eq!(genesis.state, "active");
    assert_eq!(genesis.activation, "0");
    assert_eq!(genesis.issuance_end, "-");
    let g = genesis.id.as_str();
    run_ok(&["export-issuer-spki", p(&issuer), g, p(&genesis_der)]);
    // `init-origin` rejects an ID that does not match the public key's SPKI digest before creating the state directory.
    let wrong_key_id = "0".repeat(64);
    run_refused(&[
        "init-origin",
        p(&temp.path().join("bad-origin")),
        p(&genesis_der),
        &wrong_key_id,
    ]);
    assert!(!temp.path().join("bad-origin").exists());
    run_ok(&["init-origin", p(&origin), p(&genesis_der), g]);
    run_refused(&["init-origin", p(&origin), p(&genesis_der), g]);
    let origin0 = origin_status(&origin);
    assert_eq!(origin0.rows, vec![row("advertising", g, "0", "-", "-")]);

    run_ok(&["stage-issuer-key", p(&issuer)]);
    let staged = issuer_status(&issuer);
    assert_eq!(staged.rows.len(), 2);
    assert_eq!(staged.rows[0], genesis);
    assert_eq!(staged.rows[1].state, "staged");
    let next = staged.rows[1].id.clone();
    let n = next.as_str();
    run_ok(&["export-issuer-spki", p(&issuer), n, p(&next_der)]);

    // Invalid commands leave the issuer's staged key and the origin's initial state unchanged.
    run_refused(&["stage-issuer-key", p(&issuer)]);
    run_refused(&[
        "install-origin-key",
        p(&origin),
        p(&next_der),
        n,
        &far_plus_one,
    ]);
    run_refused(&["install-origin-key", p(&origin), p(&next_der), n, &past_s]);
    run_refused(&["install-origin-key", p(&origin), p(&genesis_der), n, &far_s]);
    run_refused(&["install-origin-key", p(&origin), p(&next_der), g, &far_s]);
    run_refused(&["activate-issuer-key", p(&issuer), n, &far_plus_one]);
    run_refused(&["activate-issuer-key", p(&issuer), n, &past_s]);
    run_refused_with(
        &["activate-issuer-key", p(&issuer), &far_s],
        "invalid arguments",
    );
    for wrong in [g, ZERO_ID] {
        run_refused_with(
            &["activate-issuer-key", p(&issuer), wrong, &far_s],
            "key ID does not match",
        );
    }
    assert_eq!(issuer_status(&issuer), staged);
    assert_eq!(origin_status(&origin).rows, origin0.rows);

    // Install the key on the origin first so that both roles are ready for the same activation time.
    run_ok(&["install-origin-key", p(&origin), p(&next_der), n, &far_s]);
    let origin1 = origin_status(&origin);
    assert_eq!(
        origin1.rows,
        vec![
            row("advertising", g, "0", &far_s, &(far + 300).to_string()),
            row("installed", n, &far_s, "-", "-"),
        ]
    );
    run_ok(&["activate-issuer-key", p(&issuer), n, &far_s]);
    let issuer1 = issuer_status(&issuer);
    assert_eq!(
        issuer1.rows,
        vec![
            row("active", g, "0", &far_s, &(far + 300).to_string()),
            row("scheduled", n, &far_s, "-", "-"),
        ]
    );
    assert_eq!(id_and_activation(&issuer1), id_and_activation(&origin1));
    assert_ne!(issuer1.high_water, 0);
    // Supplying the wrong ID fails and leaves the scheduled key's activation unchanged.
    run_refused_with(
        &[
            "activate-issuer-key",
            p(&issuer),
            g,
            &(far + 3600).to_string(),
        ],
        "key ID does not match",
    );
    assert_eq!(issuer_status(&issuer), issuer1);

    // Before activation, the running issuer advertises only the initial public key.
    let issuer_addr = free_address();
    let issuer_name = issuer_addr.to_string();
    let issue_url = format!("https://{issuer_name}/private-token/issue");
    let mut issuer_server = spawn_server(&[
        "serve-issuer",
        p(&issuer),
        &issuer_name,
        &issue_url,
        &issuer_name,
    ]);
    wait_ready(
        &mut issuer_server,
        issuer_addr,
        "/.well-known/private-token-issuer-directory",
        |text| text.starts_with("HTTP/1.1 200") && text.contains("token-keys"),
    );
    let directory = respond(issuer_addr, "/.well-known/private-token-issuer-directory").unwrap();
    assert_eq!(
        directory_keys(&directory),
        vec![fs::read(&genesis_der).unwrap()]
    );
    run_refused_with(
        &["activate-issuer-key", p(&issuer), n, &far_s],
        "already owned",
    );
    run_refused_with(&["issuer-key-status", p(&issuer)], "already owned");
    run_refused_with(&["stage-issuer-key", p(&issuer)], "already owned");
    drop(issuer_server);
    assert_eq!(issuer_status(&issuer).rows, issuer1.rows);

    // The running origin advertises the initial public key that it loaded from its store.
    let origin_addr = free_address();
    let mut origin_server = spawn_server(&[
        "serve-origin",
        p(&origin),
        &issuer_name,
        ORIGIN,
        &origin_addr.to_string(),
    ]);
    wait_ready(
        &mut origin_server,
        origin_addr,
        "/private-token/protected",
        |text| text.starts_with("HTTP/1.1 401") && text.contains("token-key=\""),
    );
    let advertised = respond(origin_addr, "/private-token/protected").unwrap();
    assert_eq!(
        challenge_token_key(&advertised),
        fs::read(&genesis_der).unwrap()
    );
    run_refused_with(
        &["install-origin-key", p(&origin), p(&next_der), n, &far_s],
        "already owned",
    );
    run_refused_with(&["origin-key-status", p(&origin)], "already owned");
    drop(origin_server);
    assert_eq!(origin_status(&origin).rows, origin1.rows);
    assert_eq!(issuer_status(&issuer).rows, issuer1.rows);
}

#[test]
fn loopback_example_passes_against_cli_served_roles() {
    let _spawn_guard = SPAWN_LOCK.blocking_write();
    let temp = tempfile::tempdir().unwrap();
    let issuer = temp.path().join("issuer");
    let origin = temp.path().join("origin");
    let genesis_der = temp.path().join("genesis.der");
    run_ok(&["init-issuer", p(&issuer)]);
    let genesis = issuer_status(&issuer).rows[0].id.clone();
    run_ok(&["export-issuer-spki", p(&issuer), &genesis, p(&genesis_der)]);
    run_ok(&["init-origin", p(&origin), p(&genesis_der), &genesis]);
    let invitation = String::from_utf8(run_ok(&["provision", p(&issuer)]).stdout).unwrap();
    let invitation = invitation.trim_end().to_owned();

    let issuer_addr = free_address();
    let issuer_name = issuer_addr.to_string();
    let mut issuer_server = spawn_server(&[
        "serve-issuer",
        p(&issuer),
        &issuer_name,
        &format!("https://{issuer_name}/private-token/issue"),
        &issuer_name,
    ]);
    wait_ready(
        &mut issuer_server,
        issuer_addr,
        "/.well-known/private-token-issuer-directory",
        |text| text.starts_with("HTTP/1.1 200"),
    );
    let origin_addr = free_address();
    let mut origin_server = spawn_server(&[
        "serve-origin",
        p(&origin),
        &issuer_name,
        ORIGIN,
        &origin_addr.to_string(),
    ]);
    wait_ready(
        &mut origin_server,
        origin_addr,
        "/private-token/protected",
        |text| text.starts_with("HTTP/1.1 401"),
    );

    let mut child = Command::new(example_binary())
        .arg(format!("http://{issuer_addr}"))
        .arg(format!("http://{origin_addr}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{invitation}\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "example failed: {output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim_end(),
        "issuance: 200; redemption: 200; replay: 401; invitation retry: 403"
    );
}

// Check the schema error and compare file digests to verify that the CLI rejects v1 without modifying either database.

fn sha256_of(path: &Path) -> [u8; 32] {
    Sha256::digest(fs::read(path).unwrap()).into()
}

fn v1_key_store(path: &Path) {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    let key = SecretKey::generate().unwrap();
    let public = key.public_key().unwrap();
    let db = Connection::open(path).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
    db.execute_batch(
        "CREATE TABLE metadata (version INTEGER NOT NULL, active_key_id BLOB NOT NULL);
         CREATE TABLE keys (key_id BLOB PRIMARY KEY NOT NULL, spki BLOB NOT NULL,
                            pkcs8 BLOB NOT NULL);",
    )
    .unwrap();
    db.execute(
        "INSERT INTO keys VALUES (?1, ?2, ?3)",
        params![
            public.key_id().as_slice(),
            public.to_spki(),
            key.to_pkcs8().unwrap()
        ],
    )
    .unwrap();
    db.execute(
        "INSERT INTO metadata VALUES (1, ?1)",
        [public.key_id().as_slice()],
    )
    .unwrap();
    drop(db);
}

fn v1_origin(dir: &Path) {
    fs::create_dir(dir).unwrap();
    let db = Connection::open(dir.join("origin.sqlite")).unwrap();
    db.execute_batch(V1_ORIGIN_DDL).unwrap();
    drop(db);
    // Include the lock file and context secret so that the fixture exercises rejection of the schema itself.
    fs::write(dir.join("origin.sqlite.lock"), b"").unwrap();
    fs::write(dir.join("context"), [0u8; 32]).unwrap();
}

#[test]
fn v1_state_is_refused_by_the_cli_for_both_roles_without_touching_files() {
    let _spawn_guard = SPAWN_LOCK.blocking_write();
    let temp = tempfile::tempdir().unwrap();
    let far_s = far_future().to_string();
    let issuer = temp.path().join("issuer");
    run_ok(&["init-issuer", p(&issuer)]);
    // Remove the initialized key database and its SQLite side files so that CLI commands open only the v1 fixture.
    let keys = issuer.join("issuer-keys.sqlite");
    for name in [
        "issuer-keys.sqlite",
        "issuer-keys.sqlite-wal",
        "issuer-keys.sqlite-shm",
    ] {
        let _ = fs::remove_file(issuer.join(name));
    }
    v1_key_store(&keys);
    let issuer_before = sha256_of(&keys);
    let issuer_url = "https://issuer.test/private-token/issue";
    for args in [
        vec!["issuer-key-status", p(&issuer)],
        vec!["stage-issuer-key", p(&issuer)],
        vec!["activate-issuer-key", p(&issuer), ZERO_ID, &far_s],
        vec!["retire-issuer-key", p(&issuer), ZERO_ID],
        vec![
            "export-issuer-spki",
            p(&issuer),
            ZERO_ID,
            p(&temp.path().join("out.der")),
        ],
        vec![
            "serve-issuer",
            p(&issuer),
            ISSUER,
            issuer_url,
            "127.0.0.1:0",
        ],
    ] {
        run_refused_with(&args, KEY_V1);
        assert_eq!(sha256_of(&keys), issuer_before, "{args:?} touched v1 keys");
    }

    let origin = temp.path().join("origin");
    v1_origin(&origin);
    let origin_db = origin.join("origin.sqlite");
    let origin_before = sha256_of(&origin_db);
    let spki_key = SecretKey::generate().unwrap();
    let spki_public = spki_key.public_key().unwrap();
    let next_der = temp.path().join("next.der");
    fs::write(&next_der, spki_public.to_spki()).unwrap();
    let id: String = spki_public
        .key_id()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for args in [
        vec!["origin-key-status", p(&origin)],
        vec!["retire-origin-key", p(&origin), ZERO_ID],
        vec!["install-origin-key", p(&origin), p(&next_der), &id, &far_s],
        vec!["serve-origin", p(&origin), ISSUER, ORIGIN, "127.0.0.1:0"],
    ] {
        run_refused_with(&args, ORIGIN_V1);
        assert_eq!(
            sha256_of(&origin_db),
            origin_before,
            "{args:?} touched v1 origin"
        );
    }
}
