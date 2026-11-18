//! Optional ALTCHA v2 gate: a spent proof is committed before provisioning.
//! Like admission state, unannounced rollback requires offline recovery.
use crate::admission::AdmissionStore;
use altcha::{
    create_challenge, verify_solution, Challenge, CreateChallengeOptions, Payload,
    VerifySolutionOptions,
};
use anyhow::{ensure, Context, Result};
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use fs2::FileExt;
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::Ipv6Addr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

const EXPIRY_SECONDS: i64 = 300;
// Target roughly 1–5 seconds on a typical laptop widget, not a timing guarantee:
// 256 trials on average, each doing 20,000 PBKDF2/SHA-256 iterations. Device
// speed, worker count and the geometric search tail affect actual solve time.
const POW_COST: u32 = 20_000;
const POW_KEY_PREFIX: &str = "00";
const VERIFY_CAPACITY: usize = 2;
const BODY_LIMIT: usize = 8192;
const SCHEMA: &str = "CREATE TABLE spent (challenge_id BLOB PRIMARY KEY NOT NULL CHECK(typeof(challenge_id)='blob' AND length(challenge_id)=32), expires_at INTEGER NOT NULL)";

/// Validated, single browser origin; never wildcard or credentials.
#[derive(Clone)]
pub struct BrowserOrigin(HeaderValue);

impl BrowserOrigin {
    pub fn parse(value: &str) -> Result<Self> {
        let authority = value.strip_prefix("https://").context("invalid origin")?;
        let uri: axum::http::Uri = value.parse()?;
        let parsed = uri.authority().context("invalid origin")?;
        ensure!(
            parsed.as_str() == authority && !authority.contains('@'),
            "invalid origin"
        );
        let host = parsed.host();
        if host.starts_with('[') {
            host.strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .context("invalid origin")?
                .parse::<Ipv6Addr>()?;
        } else {
            ensure!(
                !host.is_empty()
                    && host.len() <= 253
                    && host.split('.').all(|label| {
                        !label.is_empty()
                            && label.len() <= 63
                            && label.as_bytes()[0].is_ascii_alphanumeric()
                            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                            && label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    }),
                "invalid origin"
            );
        }
        let suffix = &authority[host.len()..];
        if !suffix.is_empty() {
            let port = suffix.strip_prefix(':').context("invalid origin")?;
            ensure!(
                !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
                "invalid origin"
            );
            port.parse::<u16>()?;
        }
        Ok(Self(HeaderValue::from_str(value)?))
    }

    pub(crate) fn header(&self) -> &HeaderValue {
        &self.0
    }
}

fn now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

fn random_key() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    OsRng.try_fill_bytes(&mut bytes)?;
    Ok(bytes)
}

fn require_regular(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "invalid PoW state"
    );
    Ok(())
}

fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => anyhow::bail!("PoW state already exists or cannot be inspected"),
    }
}

fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn lock(dir: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join("pow.sqlite.lock"))?;
    ensure!(file.metadata()?.is_file(), "invalid PoW lock");
    FileExt::try_lock_exclusive(&file)?;
    Ok(file)
}

fn read_key(dir: &Path) -> Result<String> {
    let path = dir.join("pow-key");
    require_regular(&path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.len() == 32
            && metadata.permissions().mode() & 0o777 == 0o600,
        "invalid PoW key"
    );
    let mut key = [0; 32];
    file.read_exact(&mut key)?;
    // The crate accepts a UTF-8 string secret, so injectively encode the 32
    // random bytes. This retains all 256 bits of entropy; no custom crypto.
    Ok(Base64UrlUnpadded::encode_string(&key))
}

fn write_key(dir: &Path, key: &[u8; 32], rotate: bool) -> Result<()> {
    let path = dir.join("pow-key");
    let temporary = dir.join(format!(
        ".pow-key-{}",
        Base64UrlUnpadded::encode_string(&random_key()?)
    ));
    let output = if rotate { &temporary } else { &path };
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output)?;
        file.write_all(key)?;
        file.sync_all()?;
        if rotate {
            require_regular(&path)?;
            fs::rename(&temporary, &path)?;
        }
        sync_dir(dir)
    })();
    if result.is_err() && rotate {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn configure(db: &Connection, initialize: bool) -> Result<()> {
    let query = if initialize {
        "PRAGMA journal_mode=WAL"
    } else {
        "PRAGMA journal_mode"
    };
    let mode: String = db.query_row(query, [], |r| r.get(0))?;
    ensure!(mode.eq_ignore_ascii_case("wal"), "WAL unavailable");
    db.pragma_update(None, "synchronous", "FULL")?;
    let synchronous: i64 = db.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    ensure!(synchronous == 2, "FULL synchronization unavailable");
    Ok(())
}

fn require_plain_schema(db: &Connection) -> Result<()> {
    let count: i64 = db.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type IN ('trigger','view')",
        [],
        |r| r.get(0),
    )?;
    ensure!(count == 0, "unexpected schema objects");
    Ok(())
}

fn open_db(dir: &Path) -> Result<Connection> {
    let path = dir.join("pow.sqlite");
    require_regular(&path)?;
    ensure!(
        fs::metadata(&path)?.permissions().mode() & 0o777 == 0o600,
        "invalid PoW database"
    );
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    configure(&db, false)?;
    require_plain_schema(&db)?;
    let integrity: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    ensure!(integrity == "ok", "invalid PoW database");
    let schema: String = db.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='spent'",
        [],
        |r| r.get(0),
    )?;
    ensure!(schema == SCHEMA, "invalid PoW schema");
    Ok(db)
}

/// Explicit, non-resetting initialization. No admission lock is needed.
pub fn initialize(dir: &Path) -> Result<()> {
    let _lock = lock(dir)?;
    require_absent(&dir.join("pow-key"))?;
    require_absent(&dir.join("pow.sqlite"))?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("pow.sqlite"))?
        .sync_all()?;
    sync_dir(dir)?;
    write_key(dir, &random_key()?, false)?;
    let mut db = Connection::open(dir.join("pow.sqlite"))?;
    configure(&db, true)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(SCHEMA)?;
    tx.commit()?;
    db.close().map_err(|(_, error)| error)?;
    sync_dir(dir)
}

/// Offline restore hook. Call while holding admission ownership; absent PoW
/// files preserve old behavior. Rotate before clearing, so a crash never makes
/// old proofs valid against an empty spent table.
pub fn invalidate_for_restore(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir.join("pow-key")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            require_absent(&dir.join("pow.sqlite"))?;
            return Ok(());
        }
        result => {
            result?;
        }
    }
    let _lock = lock(dir)?;
    read_key(dir)?;
    let mut db = open_db(dir)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_plain_schema(&tx)?;
    write_key(dir, &random_key()?, true)?;
    tx.execute("DELETE FROM spent", [])?;
    tx.commit()?;
    Ok(())
}

pub struct Pow {
    secret: String,
    db: Mutex<Connection>,
    admission: Arc<AdmissionStore>,
    workers: Arc<Semaphore>,
    _lock: File,
}

impl Pow {
    pub fn open(dir: &Path, admission: Arc<AdmissionStore>) -> Result<Self> {
        let lock = lock(dir)?;
        Ok(Self {
            secret: read_key(dir)?,
            db: Mutex::new(open_db(dir)?),
            admission,
            workers: Arc::new(Semaphore::new(VERIFY_CAPACITY)),
            _lock: lock,
        })
    }

    fn challenge(&self) -> Result<Challenge> {
        Ok(create_challenge(CreateChallengeOptions {
            cost: POW_COST,
            key_prefix: POW_KEY_PREFIX.to_owned(),
            expires_at: Some(
                now()?
                    .checked_add(EXPIRY_SECONDS)
                    .context("clock overflow")?,
            ),
            hmac_signature_secret: Some(self.secret.clone()),
            ..Default::default()
        })?)
    }

    fn redeem(&self, encoded: &str) -> std::result::Result<String, StatusCode> {
        let bytes = Base64::decode_vec(encoded).map_err(|_| StatusCode::FORBIDDEN)?;
        let payload: Payload = serde_json::from_slice(&bytes).map_err(|_| StatusCode::FORBIDDEN)?;
        let expires_at = payload
            .challenge
            .parameters
            .expires_at
            .filter(|&expiry| expiry > 0)
            .ok_or(StatusCode::FORBIDDEN)?;
        let verified = verify_solution(VerifySolutionOptions::new(
            &payload.challenge,
            &payload.solution,
            &self.secret,
        ))
        .map_err(|_| StatusCode::FORBIDDEN)?;
        if !verified.verified {
            return Err(StatusCode::FORBIDDEN);
        }
        // Hash the authenticated signature BYTES, not the solution/counter:
        // a challenge may have many solutions but must yield only one admission.
        // Every challenge signs fresh random nonce+salt. HMAC authenticates that
        // identity; decoding avoids textual encodings becoming new identities.
        let signature = payload
            .challenge
            .signature
            .as_deref()
            .ok_or(StatusCode::FORBIDDEN)?;
        let mut signature_bytes = [0u8; 32];
        if signature.len() != 64 {
            return Err(StatusCode::FORBIDDEN);
        }
        for (i, byte) in signature_bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&signature[i * 2..i * 2 + 2], 16)
                .map_err(|_| StatusCode::FORBIDDEN)?;
        }
        let challenge_id: [u8; 32] = Sha256::digest(signature_bytes).into();
        let now = now().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if expires_at <= now {
            return Err(StatusCode::FORBIDDEN);
        }
        {
            let mut db = self
                .db
                .lock()
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            let result = (|| -> Result<bool> {
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                require_plain_schema(&tx)?;
                tx.execute("DELETE FROM spent WHERE expires_at<=?1", [now])?;
                let inserted = tx.execute(
                    "INSERT INTO spent(challenge_id,expires_at) VALUES (?1,?2) ON CONFLICT(challenge_id) DO NOTHING",
                    params![challenge_id.as_slice(), expires_at],
                )?;
                tx.commit()?;
                Ok(inserted == 1)
            })().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            if !result {
                return Err(StatusCode::FORBIDDEN);
            }
        }
        // Invariant: one solved challenge yields at most one admission. Commit
        // the spent proof FIRST; provisioning failure/cancellation burns it,
        // without refunds or any change to existing admission semantics.
        self.admission
            .provision(now)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    }
}

pub fn router(pow: Arc<Pow>) -> Router {
    Router::new()
        .route("/freebird/pow/challenge", get(challenge))
        .route("/freebird/pow/admission", post(admission))
        .with_state(pow)
}

fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn challenge(State(pow): State<Arc<Pow>>) -> Response {
    match pow.challenge() {
        Ok(challenge) => no_store(Json(challenge)),
        Err(_) => no_store(StatusCode::SERVICE_UNAVAILABLE),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Submission {
    payload: String,
}

async fn admission(State(pow): State<Arc<Pow>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(_) => return no_store(StatusCode::BAD_REQUEST),
    };
    let mut media = parts.headers.get_all(header::CONTENT_TYPE).iter();
    if media
        .next()
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("application/json"))
        != Some(true)
        || media.next().is_some()
    {
        return no_store(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let submission: Submission = match serde_json::from_slice(&bytes) {
        Ok(submission) => submission,
        Err(_) => return no_store(StatusCode::BAD_REQUEST),
    };
    let permit = match pow.workers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return no_store(StatusCode::TOO_MANY_REQUESTS),
    };
    // Hold capacity even if the HTTP future is cancelled.
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        pow.redeem(&submission.payload)
    })
    .await
    {
        Ok(Ok(code)) => no_store(Json(serde_json::json!({ "admission": code }))),
        Ok(Err(status)) => no_store(status),
        Err(_) => no_store(StatusCode::SERVICE_UNAVAILABLE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::{self, Issuer};
    use altcha::{solve_challenge, SolveChallengeOptions};
    use axum::{body::Body, http::Method};
    use std::os::unix::fs::symlink;
    use tower::Service;

    fn fixture() -> (tempfile::TempDir, Arc<Pow>) {
        let dir = tempfile::tempdir().unwrap();
        AdmissionStore::initialize(
            dir.path().join("admission.sqlite"),
            dir.path().join("generation"),
        )
        .unwrap();
        let admission = Arc::new(
            AdmissionStore::open(
                dir.path().join("admission.sqlite"),
                dir.path().join("generation"),
            )
            .unwrap(),
        );
        initialize(dir.path()).unwrap();
        let pow = Arc::new(Pow::open(dir.path(), admission).unwrap());
        (dir, pow)
    }

    fn solved(pow: &Pow, expires_at: Option<i64>) -> Payload {
        let challenge = create_challenge(CreateChallengeOptions {
            cost: 1,
            key_prefix: String::new(),
            expires_at,
            hmac_signature_secret: Some(pow.secret.clone()),
            ..Default::default()
        })
        .unwrap();
        let solution = solve_challenge(SolveChallengeOptions::new(&challenge))
            .unwrap()
            .unwrap();
        Payload {
            challenge,
            solution,
        }
    }

    fn encoded(payload: &Payload) -> String {
        Base64::encode_string(&serde_json::to_vec(payload).unwrap())
    }

    fn submission(payload: &str) -> Request {
        Request::builder()
            .method("POST")
            .uri("/freebird/pow/admission")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "payload": payload }).to_string(),
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn solved_challenge_admits_once_even_with_another_solution_and_restart() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (dir, pow) = fixture();
        let mut payload = solved(&pow, Some(now().unwrap() + 300));
        let original = encoded(&payload);
        let response = admission(State(pow.clone()), submission(&original)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        let code = value["admission"].as_str().unwrap();
        assert_eq!(code.len(), 43);
        assert!(pow.admission.consume(code, now().unwrap()).unwrap());
        assert!(!pow.admission.consume(code, now().unwrap()).unwrap());
        assert_eq!(
            admission(State(pow.clone()), submission(&original))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut options = SolveChallengeOptions::new(&payload.challenge);
        options.counter_start = payload.solution.counter + 1;
        payload.solution = solve_challenge(options).unwrap().unwrap();
        assert_eq!(pow.redeem(&encoded(&payload)), Err(StatusCode::FORBIDDEN));
        let admission_store = pow.admission.clone();
        drop(pow);
        let pow = Pow::open(dir.path(), admission_store).unwrap();
        assert_eq!(pow.redeem(&original), Err(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn tampered_unsigned_expired_missing_expiry_wrong_key_and_invalid_solution_are_forbidden()
    {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (_dir, pow) = fixture();
        let payload = solved(&pow, Some(now().unwrap() + 300));
        let mut tampered = payload.clone();
        tampered.challenge.parameters.cost += 1;
        let mut unsigned = payload.clone();
        unsigned.challenge.signature = None;
        let mut bad_solution = payload.clone();
        bad_solution.solution.derived_key = "00".repeat(32);
        let mut wrong_key = solved(&pow, Some(now().unwrap() + 300));
        wrong_key.challenge = create_challenge(CreateChallengeOptions {
            cost: 1,
            key_prefix: String::new(),
            expires_at: wrong_key.challenge.parameters.expires_at,
            hmac_signature_secret: Some("wrong key".to_owned()),
            ..Default::default()
        })
        .unwrap();
        wrong_key.solution = solve_challenge(SolveChallengeOptions::new(&wrong_key.challenge))
            .unwrap()
            .unwrap();
        for invalid in [
            tampered,
            unsigned,
            bad_solution,
            wrong_key,
            solved(&pow, Some(now().unwrap() - 1)),
            solved(&pow, Some(0)),
            solved(&pow, None),
        ] {
            assert_eq!(
                admission(State(pow.clone()), submission(&encoded(&invalid)))
                    .await
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(pow.redeem("not a payload"), Err(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn busy_is_429_and_transport_errors_are_bounded() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (_dir, pow) = fixture();
        let payload = encoded(&solved(&pow, Some(now().unwrap() + 300)));
        let permit = pow
            .workers
            .clone()
            .acquire_many_owned(VERIFY_CAPACITY as u32)
            .await
            .unwrap();
        assert_eq!(
            admission(State(pow.clone()), submission(&payload))
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        drop(permit);
        let mut unsupported = submission(&payload);
        unsupported.headers_mut().remove(header::CONTENT_TYPE);
        assert_eq!(
            admission(State(pow.clone()), unsupported).await.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        for body in ["{}".to_owned(), "{".to_owned(), "A".repeat(BODY_LIMIT + 1)] {
            let request = Request::builder()
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap();
            assert_eq!(
                admission(State(pow.clone()), request).await.status(),
                StatusCode::BAD_REQUEST
            );
        }
    }

    #[test]
    fn recovery_rotates_key_clears_spent_and_invalidates_unspent_solution() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (dir, pow) = fixture();
        let old = encoded(&solved(&pow, Some(now().unwrap() + 300)));
        let spent = encoded(&solved(&pow, Some(now().unwrap() + 300)));
        pow.redeem(&spent).unwrap();
        let key = fs::read(dir.path().join("pow-key")).unwrap();
        assert!(
            invalidate_for_restore(dir.path()).is_err(),
            "must exclude serving process"
        );
        let admission_store = pow.admission.clone();
        drop(pow);
        invalidate_for_restore(dir.path()).unwrap();
        assert_ne!(key, fs::read(dir.path().join("pow-key")).unwrap());
        let pow = Pow::open(dir.path(), admission_store).unwrap();
        assert_eq!(pow.redeem(&old), Err(StatusCode::FORBIDDEN));
        let count: i64 = pow
            .db
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM spent", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        pow.redeem(&encoded(&solved(&pow, Some(now().unwrap() + 300))))
            .unwrap();
    }

    #[test]
    fn provision_failure_burns_proof_but_failed_spent_commit_does_not() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (dir, pow) = fixture();
        let payload = encoded(&solved(&pow, Some(now().unwrap() + 300)));
        pow.db.lock().unwrap().commit_hook(Some(|| true)).unwrap();
        assert_eq!(pow.redeem(&payload), Err(StatusCode::SERVICE_UNAVAILABLE));
        pow.db
            .lock()
            .unwrap()
            .commit_hook(None::<fn() -> bool>)
            .unwrap();
        let db = Connection::open(dir.path().join("admission.sqlite")).unwrap();
        db.execute_batch("CREATE VIEW extra AS SELECT * FROM invitations")
            .unwrap();
        assert_eq!(pow.redeem(&payload), Err(StatusCode::SERVICE_UNAVAILABLE));
        db.execute_batch("DROP VIEW extra").unwrap();
        assert_eq!(pow.redeem(&payload), Err(StatusCode::FORBIDDEN));
    }

    #[test]
    fn initialization_permissions_locks_and_bad_files_fail_closed() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (dir, pow) = fixture();
        assert!(initialize(dir.path()).is_err());
        assert!(Pow::open(dir.path(), pow.admission.clone()).is_err());
        for name in ["pow-key", "pow.sqlite", "pow.sqlite.lock"] {
            assert_eq!(
                fs::metadata(dir.path().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let admission_store = pow.admission.clone();
        drop(pow);
        fs::write(dir.path().join("pow-key"), [1; 31]).unwrap();
        assert!(Pow::open(dir.path(), admission_store.clone()).is_err());
        fs::rename(dir.path().join("pow-key"), dir.path().join("other-key")).unwrap();
        symlink(dir.path().join("other-key"), dir.path().join("pow-key")).unwrap();
        assert!(Pow::open(dir.path(), admission_store).is_err());
        assert!(initialize(dir.path()).is_err());
        assert!(invalidate_for_restore(dir.path()).is_err());
        let empty = tempfile::tempdir().unwrap();
        invalidate_for_restore(empty.path()).unwrap();
        assert_eq!(fs::read_dir(empty.path()).unwrap().count(), 0);
    }

    #[test]
    fn browser_origin_is_one_strict_https_authority() {
        for origin in [
            "https://origin.example",
            "https://localhost:8443",
            "https://[::1]:443",
        ] {
            assert!(BrowserOrigin::parse(origin).is_ok(), "{origin}");
        }
        for origin in [
            "",
            "*",
            "null",
            "http://origin.example",
            "https://origin.example/",
            "https://origin.example/path",
            "https://origin.example?x",
            "https://origin.example#x",
            "https://user@origin.example",
            "https://origin.example:65536",
            "https://origin.example:",
            "https://origin.example:abc",
            "https://-bad.example",
            "https://origin..example",
            "https://origin.example https://other.example",
        ] {
            assert!(BrowserOrigin::parse(origin).is_err(), "{origin}");
        }
    }

    #[tokio::test]
    async fn configured_routes_cors_and_legacy_mode_without_pow() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (dir, pow) = fixture();
        let key = dir.path().join("issuer-keys.sqlite");
        Issuer::initialize_key(&key).unwrap();
        let issuer = Arc::new(
            Issuer::open(
                key,
                pow.admission.clone(),
                "issuer.test",
                "https://issuer.test/private-token/issue",
                now().unwrap() as u64,
            )
            .unwrap(),
        );
        let legacy = issuer::router(issuer.clone());
        let configured = issuer::router_with_pow(
            issuer,
            pow,
            BrowserOrigin::parse("https://origin.example").unwrap(),
        );
        for path in [
            "/freebird/pow/challenge",
            "/freebird/pow/admission",
            "/.well-known/private-token-issuer-directory",
            "/private-token/issue",
        ] {
            for origin in ["https://origin.example", "https://other.example"] {
                for method in [Method::OPTIONS, Method::GET, Method::POST] {
                    let response = configured
                        .clone()
                        .call(
                            Request::builder()
                                .method(method.clone())
                                .uri(path)
                                .header(header::ORIGIN, origin)
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
                        (origin == "https://origin.example")
                            .then(|| HeaderValue::from_static("https://origin.example"))
                            .as_ref()
                    );
                    assert_eq!(response.headers()[header::VARY], "Origin");
                    assert!(!response
                        .headers()
                        .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
                    if method == Method::OPTIONS {
                        assert_eq!(response.status(), StatusCode::NO_CONTENT);
                        if origin == "https://origin.example" {
                            assert_eq!(
                                response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
                                "GET, POST"
                            );
                            assert_eq!(
                                response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
                                "Content-Type, Freebird-Admission"
                            );
                            assert_eq!(response.headers()[header::ACCESS_CONTROL_MAX_AGE], "600");
                        }
                    }
                }
            }
            let response = legacy
                .clone()
                .call(
                    Request::builder()
                        .uri(path)
                        .header(header::ORIGIN, "https://origin.example")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(!response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
            if path.starts_with("/freebird/") {
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
            }
        }
        let start = now().unwrap();
        let response = configured
            .clone()
            .call(
                Request::builder()
                    .uri("/freebird/pow/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
        let challenge: Challenge =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(challenge.parameters.algorithm, "PBKDF2/SHA-256");
        assert_eq!(challenge.parameters.cost, POW_COST);
        assert_eq!(challenge.parameters.key_prefix, POW_KEY_PREFIX);
        assert!((start + 300..=now().unwrap() + 300)
            .contains(&challenge.parameters.expires_at.unwrap()));
    }
}
