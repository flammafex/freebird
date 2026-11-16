//! Experimental, single-instance Origin. Key staging/rotation is unsupported.
//! Never restore a replay-store snapshot in place: close the service and provision
//! a fresh store AND separately generated context secret before reopening.
use anyhow::{bail, ensure, Context, Result};
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use freebird_common::privacy_pass::{
    build_challenge_header, parse_authorization_header, Token, TokenChallenge,
};
use freebird_crypto::privacy_pass::PublicKey;
use fs2::FileExt;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub struct Origin {
    db: Mutex<Connection>,
    _ownership: File,
    secret: [u8; 32],
    key: PublicKey,
    issuer: String,
    name: String,
}

fn connect(path: &Path) -> Result<Connection> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    db.busy_timeout(Duration::ZERO)?;
    let mode: String = db.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
    ensure!(mode == "wal", "WAL unavailable");
    db.pragma_update(None, "synchronous", "FULL")?;
    Ok(db)
}

fn ownership(path: &Path, fresh: bool) -> Result<File> {
    // Never lock SQLite's database inode: its own byte-range locks can
    // conflict with flock on supported platforms. Keep this sidecar forever.
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(fresh);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // Opening existing state never creates even a missing ownership sidecar.
    let file = options.open(Path::new(&lock_path))?;
    file.try_lock_exclusive()
        .context("Origin store already owned")?;
    Ok(file)
}

fn sync_parent(path: &Path) -> Result<()> {
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}

impl Origin {
    /// Fresh provisioning only. Partial failure requires operator cleanup, never
    /// automatic replacement of either existing file.
    pub fn initialize(
        db_path: impl AsRef<Path>,
        context_secret_path: impl AsRef<Path>,
    ) -> Result<()> {
        let db_path = db_path.as_ref();
        let secret_path = context_secret_path.as_ref();
        let owner = ownership(db_path, true)?;
        ensure!(
            !db_path.exists() && !secret_path.exists(),
            "state already exists"
        );
        let mut options = OpenOptions::new();
        options.write(true).read(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let db_file = options.open(db_path)?;
        let mut secret_file = options.open(secret_path)?;
        let mut secret = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        secret_file.write_all(&secret)?;
        secret_file.sync_all()?;
        let mut db = connect(db_path)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE metadata (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                version INTEGER NOT NULL CHECK(version=1),
                secret_hash BLOB NOT NULL,
                high_water INTEGER NOT NULL CHECK(high_water>=0),
                binding BLOB);
             CREATE TABLE challenges (
                key_id BLOB NOT NULL, digest BLOB NOT NULL, deadline INTEGER NOT NULL,
                PRIMARY KEY(key_id,digest));
             CREATE TABLE spent (
                key_id BLOB NOT NULL, digest BLOB NOT NULL, nonce BLOB NOT NULL,
                deadline INTEGER NOT NULL,
                PRIMARY KEY(key_id,digest,nonce));",
        )?;
        tx.execute(
            "INSERT INTO metadata VALUES(1,1,?1,0,NULL)",
            params![Sha256::digest(secret).as_slice()],
        )?;
        tx.commit()?;
        db_file.sync_all()?;
        owner.sync_all()?;
        sync_parent(db_path)?;
        sync_parent(secret_path)?;
        Ok(())
    }

    /// Opens existing state only. The first open durably pins names and exact
    /// SPKI; subsequent configuration changes (including rotation) fail closed.
    pub fn open(
        db_path: impl AsRef<Path>,
        context_secret_path: impl AsRef<Path>,
        issuer_name: &str,
        origin_name: &str,
        pinned_spki: &[u8],
    ) -> Result<Self> {
        let owner = ownership(db_path.as_ref(), false)?;
        let key = PublicKey::from_spki(pinned_spki)?;
        TokenChallenge::new(issuer_name, &[0; 32], origin_name)?;
        let secret: [u8; 32] = std::fs::read(context_secret_path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid context secret"))?;
        let mut db = connect(db_path.as_ref())?;
        let integrity: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        ensure!(integrity == "ok", "corrupt Origin store");
        let mut binding = TokenChallenge::new(issuer_name, &[], origin_name)?.serialize();
        binding.extend_from_slice(pinned_spki);
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (version, hash, old, high): (i64, Vec<u8>, Option<Vec<u8>>, i64) = tx.query_row(
            "SELECT version,secret_hash,binding,high_water FROM metadata WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        ensure!(
            version == 1 && high >= 0 && hash == Sha256::digest(secret).as_slice(),
            "invalid Origin metadata"
        );
        if let Some(old) = old {
            ensure!(
                old == binding,
                "key rotation/configuration change unsupported"
            );
        } else {
            tx.execute(
                "UPDATE metadata SET binding=?1 WHERE singleton=1",
                params![binding],
            )?;
        }
        // Validate all required tables even when they currently contain no rows.
        tx.prepare("SELECT key_id,digest,deadline FROM challenges")?;
        tx.prepare("SELECT key_id,digest,nonce,deadline FROM spent")?;
        tx.commit()?;
        Ok(Self {
            db: Mutex::new(db),
            _ownership: owner,
            secret,
            key,
            issuer: issuer_name.into(),
            name: origin_name.into(),
        })
    }

    fn challenge(&self, now: u64) -> Result<(TokenChallenge, u64)> {
        let hour = now / 3600;
        let deadline = hour
            .checked_add(1)
            .and_then(|h| h.checked_mul(3600))
            .and_then(|s| s.checked_add(300))
            .context("clock overflow")?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)?;
        mac.update(b"freebird-pp-context-v1");
        mac.update(&hour.to_be_bytes());
        Ok((
            TokenChallenge::new(&self.issuer, &mac.finalize().into_bytes(), &self.name)?,
            deadline,
        ))
    }

    /// All requests, including invalid credentials, advance the durable clock.
    /// No pruning: retaining spent rows indefinitely is conservative.
    fn request_at(&self, token: Option<&Token>, now: u64) -> Result<Option<String>> {
        let now_sql = i64::try_from(now)?;
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("store poisoned"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let high: i64 = tx.query_row(
            "SELECT high_water FROM metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if now_sql < high {
            bail!("clock regression");
        }
        tx.execute(
            "UPDATE metadata SET high_water=?1 WHERE singleton=1",
            [now_sql],
        )?;
        let mut accepted = false;
        if let Some(token) = token {
            if token.token_key_id == self.key.key_id() {
                let deadline: Option<i64> = {
                    use rusqlite::OptionalExtension;
                    tx.query_row(
                        "SELECT deadline FROM challenges WHERE key_id=?1 AND digest=?2",
                        params![
                            token.token_key_id.as_slice(),
                            token.challenge_digest.as_slice()
                        ],
                        |r| r.get(0),
                    )
                    .optional()?
                };
                if let Some(deadline) = deadline {
                    if now_sql < deadline
                        && self
                            .key
                            .verify(&token.token_input(), &token.authenticator)
                            .is_ok()
                    {
                        accepted = tx.execute(
                            "INSERT OR IGNORE INTO spent VALUES(?1,?2,?3,?4)",
                            params![
                                token.token_key_id.as_slice(),
                                token.challenge_digest.as_slice(),
                                token.nonce.as_slice(),
                                deadline
                            ],
                        )? == 1;
                    }
                }
            }
        }
        let challenge = if accepted {
            None
        } else {
            let (challenge, deadline) = self.challenge(now)?;
            tx.execute(
                "INSERT OR IGNORE INTO challenges VALUES(?1,?2,?3)",
                params![
                    self.key.key_id().as_slice(),
                    challenge.digest().as_slice(),
                    i64::try_from(deadline)?
                ],
            )?;
            Some(build_challenge_header(
                &challenge,
                self.key.to_spki(),
                deadline - now,
            ))
        };
        tx.commit()?;
        Ok(challenge)
    }
}

pub fn router(origin: Arc<Origin>) -> Router {
    Router::new()
        .route("/private-token/protected", get(protected))
        .with_state(origin)
}

async fn protected(State(origin): State<Arc<Origin>>, headers: HeaderMap) -> Response {
    let mut fields = headers.get_all(header::AUTHORIZATION).iter();
    let first = fields.next();
    let token = if fields.next().is_none() {
        first
            .and_then(|v| v.to_str().ok())
            .and_then(|v| parse_authorization_header(v).ok())
    } else {
        None
    };
    let result = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(anyhow::Error::from)
        .and_then(|now| origin.request_at(token.as_ref(), now.as_secs()));
    match result {
        Ok(None) => (StatusCode::OK, "protected resource\n").into_response(),
        Ok(Some(challenge)) => match HeaderValue::from_str(&challenge) {
            Ok(value) => (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, value)],
            )
                .into_response(),
            Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        },
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Signing material exists only in this test harness, never in Origin.
    use freebird_crypto::privacy_pass::SecretKey;

    #[test]
    fn durable_redemption_clock_and_ownership() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("origin.db");
        let secret = dir.path().join("context");
        assert!(Origin::open(&db, &secret, "issuer", "origin", &[]).is_err());
        Origin::initialize(&db, &secret)?;
        assert!(Origin::initialize(&db, &secret).is_err());
        let signer = SecretKey::generate()?;
        let key = signer.public_key()?;
        let missing = dir.path().join("missing.db");
        assert!(Origin::open(&missing, &secret, "issuer", "origin", key.to_spki()).is_err());
        assert!(!missing.exists());
        assert!(!dir.path().join("missing.db.lock").exists());
        assert!(dir.path().join("origin.db.lock").is_file());
        let origin = Origin::open(&db, &secret, "issuer", "origin", key.to_spki())?;
        assert!(Origin::open(&db, &secret, "issuer", "origin", key.to_spki()).is_err());
        assert!(origin.request_at(None, 3601)?.is_some());
        assert!(origin.request_at(None, 3600).is_err()); // same-hour regression
        let (challenge, deadline) = origin.challenge(3601)?;
        let mut token = Token {
            nonce: [7; 32],
            challenge_digest: challenge.digest(),
            token_key_id: key.key_id(),
            authenticator: [0; 256],
        };
        let (blinded, state) = key.blind(&token.token_input())?;
        token.authenticator = key.finalize(state, &signer.blind_sign(&blinded)?)?;
        let mut wrong = token.clone();
        wrong.token_key_id[0] ^= 1;
        assert!(origin.request_at(Some(&wrong), 3601)?.is_some());
        assert!(origin.request_at(Some(&token), 3601)?.is_none());
        assert!(origin.request_at(Some(&token), 3601)?.is_some());
        let mut unspent = token.clone();
        unspent.nonce = [8; 32];
        let (blinded, state) = key.blind(&unspent.token_input())?;
        unspent.authenticator = key.finalize(state, &signer.blind_sign(&blinded)?)?;
        drop(origin);
        let origin = Origin::open(&db, &secret, "issuer", "origin", key.to_spki())?;
        assert!(origin.request_at(Some(&token), 3601)?.is_some());
        assert!(origin.request_at(Some(&unspent), deadline)?.is_some());
        assert!(origin.request_at(None, deadline - 1).is_err());
        drop(origin);
        let origin = Origin::open(&db, &secret, "issuer", "origin", key.to_spki())?;
        assert!(origin.request_at(Some(&token), deadline - 1).is_err());
        origin
            .db
            .lock()
            .unwrap()
            .execute_batch("PRAGMA query_only=ON")?;
        assert!(origin.request_at(None, deadline + 1).is_err());
        assert!(parse_authorization_header("PrivateToken token=\"bad\"").is_err());
        Ok(())
    }

    #[tokio::test]
    async fn http_challenge_and_concurrent_redemption() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("origin.db");
        let secret = dir.path().join("context");
        Origin::initialize(&db, &secret)?;
        let signer = SecretKey::generate()?;
        let key = signer.public_key()?;
        let origin = Arc::new(Origin::open(
            &db,
            &secret,
            "issuer",
            "origin",
            key.to_spki(),
        )?);
        let response = protected(State(origin.clone()), HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers()[header::WWW_AUTHENTICATE]
            .to_str()?
            .starts_with("PrivateToken challenge=\""));
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        // Persist the challenge at the fixed test instant (handles hour rollover).
        origin.request_at(None, now)?;
        let (challenge, _) = origin.challenge(now)?;
        let mut token = Token {
            nonce: [9; 32],
            challenge_digest: challenge.digest(),
            token_key_id: key.key_id(),
            authenticator: [0; 256],
        };
        let (blinded, state) = key.blind(&token.token_input())?;
        token.authenticator = key.finalize(state, &signer.blind_sign(&blinded)?)?;
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let origin = origin.clone();
                let token = token.clone();
                std::thread::spawn(move || origin.request_at(Some(&token), now).unwrap().is_none())
            })
            .collect();
        assert_eq!(
            workers
                .into_iter()
                .map(|w| usize::from(w.join().unwrap()))
                .sum::<usize>(),
            1
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&freebird_common::privacy_pass::build_authorization_header(
                &token,
            ))?,
        );
        assert_eq!(
            protected(State(origin.clone()), headers).await.status(),
            StatusCode::UNAUTHORIZED
        );
        origin
            .db
            .lock()
            .unwrap()
            .execute_batch("PRAGMA query_only=ON")?;
        assert_eq!(
            protected(State(origin), HeaderMap::new()).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        Ok(())
    }
}
