//! Experimental server-to-server application admission. A trusted application
//! server presents its per-application secret and receives one-use admission
//! codes, capped per application per UTC day. Like PoW, this state is a separate
//! SQLite file enabled only by its explicit initialization. Unannounced rollback
//! requires offline recovery, which revokes every application.
use crate::admission::AdmissionStore;
use anyhow::{ensure, Result};
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use fs2::FileExt;
use rand::{rngs::OsRng, RngCore};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::ErrorKind,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

const DB: &str = "app-clients.sqlite";
const DAY: i64 = 86_400;
const MAX_CLIENTS: i64 = 256;
const ISSUE_CAPACITY: usize = 2;
pub const KEY_PREFIX: &str = "fba_";
pub const MAX_DAILY_CAP: i64 = 100_000;
const CLIENTS_SCHEMA: &str = "CREATE TABLE clients (name TEXT PRIMARY KEY NOT NULL CHECK(name GLOB '[a-z0-9]*' AND length(name) BETWEEN 1 AND 64 AND name NOT GLOB '*[^a-z0-9-]*'), key_hash BLOB UNIQUE NOT NULL CHECK(typeof(key_hash)='blob' AND length(key_hash)=32), daily_cap INTEGER NOT NULL CHECK(daily_cap BETWEEN 1 AND 100000), revoked INTEGER NOT NULL CHECK(revoked IN (0,1)))";
// No REFERENCES clause: SQLite does not enforce it without PRAGMA foreign_keys.
const USAGE_SCHEMA: &str =
    "CREATE TABLE usage (name TEXT NOT NULL, day INTEGER NOT NULL, issued INTEGER NOT NULL, PRIMARY KEY(name, day))";

/// Why an admission was refused. Carries no secret material.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Unauthorized,
    Capped { retry_after: i64 },
    Unavailable,
}

/// One row of the operator listing; `issued` counts today's (UTC) admissions.
pub struct AppRow {
    pub name: String,
    pub daily_cap: i64,
    pub issued: i64,
    pub revoked: bool,
}

/// Holds the store's lifetime lock. Deliberately does not implement Debug.
pub struct AppClients {
    db: Mutex<Connection>,
    _lock: File,
}

/// Admission over the shared invitation store. The issuance path is an HTTP
/// route; management goes through `AppClients` (control socket or offline).
pub struct AppAdmission {
    clients: Arc<AppClients>,
    admission: Arc<AdmissionStore>,
    workers: Arc<Semaphore>,
}

/// Names are lowercase DNS-like labels: `[a-z0-9][a-z0-9-]{0,63}`.
pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z' | b'0'..=b'9'))
        && bytes.len() <= 64
        && bytes
            .iter()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

pub fn now_seconds() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
}

/// Enabled iff the store file exists. A non-regular entry is an invalid state,
/// never a silent disable.
pub fn enabled(dir: &Path) -> Result<bool> {
    match fs::symlink_metadata(dir.join(DB)) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file(),
                "invalid app admission state"
            );
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn random_secret() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    OsRng.try_fill_bytes(&mut bytes)?;
    Ok(bytes)
}

fn require_regular(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "invalid app admission state"
    );
    Ok(())
}

fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        _ => anyhow::bail!("app admission state already exists or cannot be inspected"),
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
        .open(dir.join("app-clients.sqlite.lock"))?;
    ensure!(file.metadata()?.is_file(), "invalid app admission lock");
    FileExt::try_lock_exclusive(&file)?;
    Ok(file)
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

fn require_table(db: &Connection, name: &str, sql: &str) -> Result<()> {
    let found: String = db.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
        [name],
        |r| r.get(0),
    )?;
    ensure!(found == sql, "invalid app admission schema");
    Ok(())
}

fn open_db(dir: &Path) -> Result<Connection> {
    let path = dir.join(DB);
    require_regular(&path)?;
    ensure!(
        fs::metadata(&path)?.permissions().mode() & 0o777 == 0o600,
        "invalid app admission database"
    );
    let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    configure(&db, false)?;
    require_plain_schema(&db)?;
    let integrity: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    ensure!(integrity == "ok", "invalid app admission database");
    let tables: i64 = db.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table'",
        [],
        |r| r.get(0),
    )?;
    ensure!(tables == 2, "invalid app admission schema");
    require_table(&db, "clients", CLIENTS_SCHEMA)?;
    require_table(&db, "usage", USAGE_SCHEMA)?;
    Ok(db)
}

fn begin(db: &mut Connection) -> Result<Transaction<'_>> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_plain_schema(&tx)?;
    Ok(tx)
}

/// Explicit, non-resetting initialization of an absent store.
pub fn initialize(dir: &Path) -> Result<()> {
    let _lock = lock(dir)?;
    let path = dir.join(DB);
    require_absent(&path)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?
        .sync_all()?;
    sync_dir(dir)?;
    let mut db = Connection::open(&path)?;
    configure(&db, true)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(CLIENTS_SCHEMA)?;
    tx.execute_batch(USAGE_SCHEMA)?;
    tx.commit()?;
    db.close().map_err(|(_, error)| error)?;
    sync_dir(dir)
}

fn day_of(now: i64) -> i64 {
    now.div_euclid(DAY)
}

fn reserve_in(
    db: &mut Connection,
    key_hash: &[u8; 32],
    now: i64,
) -> Result<std::result::Result<(), Refusal>> {
    let day = day_of(now);
    let tx = begin(db)?;
    // Indexed equality on the SHA-256 of a 256-bit random key. The lookup
    // touches only the digest, never a comparison against the raw secret.
    let client: Option<(String, i64)> = tx
        .query_row(
            "SELECT name, daily_cap FROM clients WHERE key_hash=?1 AND revoked=0",
            params![key_hash.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((name, daily_cap)) = client else {
        return Ok(Err(Refusal::Unauthorized));
    };
    let issued: i64 = tx
        .query_row(
            "SELECT issued FROM usage WHERE name=?1 AND day=?2",
            params![name, day],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    if issued >= daily_cap {
        return Ok(Err(Refusal::Capped {
            retry_after: (day + 1) * DAY - now,
        }));
    }
    // Usage older than two days is no longer needed for any cap decision.
    tx.execute("DELETE FROM usage WHERE day<?1", [day - 2])?;
    tx.execute(
        "INSERT INTO usage(name,day,issued) VALUES(?1,?2,1) ON CONFLICT(name,day) DO UPDATE SET issued=issued+1",
        params![name, day],
    )?;
    // Invariant: the quota is spent durably before any code is provisioned.
    tx.commit()?;
    Ok(Ok(()))
}

impl AppClients {
    /// Opens an existing, strictly checked store under its lifetime lock.
    pub fn open(dir: &Path) -> Result<Self> {
        let lock = lock(dir)?;
        let db = open_db(dir)?;
        Ok(Self {
            db: Mutex::new(db),
            _lock: lock,
        })
    }

    fn db(&self) -> Result<MutexGuard<'_, Connection>> {
        self.db
            .lock()
            .map_err(|_| anyhow::anyhow!("app admission store poisoned"))
    }

    /// Creates a new active application, or re-activates a revoked one with a
    /// fresh key. Re-activation keeps today's usage, so revoke/re-add cannot
    /// bypass the daily cap. Returns `None` for refusals (invalid input, active
    /// name, or the client limit).
    pub fn add(&self, name: &str, daily_cap: i64) -> Result<Option<String>> {
        if !valid_name(name) || !(1..=MAX_DAILY_CAP).contains(&daily_cap) {
            return Ok(None);
        }
        let raw = random_secret()?;
        let key_hash: [u8; 32] = Sha256::digest(raw).into();
        let mut db = self.db()?;
        let tx = begin(&mut db)?;
        let existing: Option<i64> = tx
            .query_row("SELECT revoked FROM clients WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .optional()?;
        let changed = match existing {
            Some(0) => return Ok(None),
            Some(_) => tx.execute(
                "UPDATE clients SET key_hash=?2, daily_cap=?3, revoked=0 WHERE name=?1 AND revoked=1",
                params![name, key_hash.as_slice(), daily_cap],
            )?,
            None => {
                let count: i64 = tx.query_row("SELECT count(*) FROM clients", [], |r| r.get(0))?;
                if count >= MAX_CLIENTS {
                    return Ok(None);
                }
                tx.execute(
                    "INSERT INTO clients(name,key_hash,daily_cap,revoked) VALUES(?1,?2,?3,0)",
                    params![name, key_hash.as_slice(), daily_cap],
                )?
            }
        };
        ensure!(changed == 1, "app admission update failed");
        tx.commit()?;
        Ok(Some(format!(
            "{KEY_PREFIX}{}",
            Base64UrlUnpadded::encode_string(&raw)
        )))
    }

    /// Returns whether a named application existed (revocation is idempotent).
    pub fn revoke(&self, name: &str) -> Result<bool> {
        let mut db = self.db()?;
        let tx = begin(&mut db)?;
        let changed = tx.execute("UPDATE clients SET revoked=1 WHERE name=?1", [name])?;
        tx.commit()?;
        Ok(changed == 1)
    }

    pub fn set_cap(&self, name: &str, daily_cap: i64) -> Result<bool> {
        if !(1..=MAX_DAILY_CAP).contains(&daily_cap) {
            return Ok(false);
        }
        let mut db = self.db()?;
        let tx = begin(&mut db)?;
        let changed = tx.execute(
            "UPDATE clients SET daily_cap=?2 WHERE name=?1",
            params![name, daily_cap],
        )?;
        tx.commit()?;
        Ok(changed == 1)
    }

    pub fn list(&self, now: i64) -> Result<Vec<AppRow>> {
        let db = self.db()?;
        require_plain_schema(&db)?;
        let mut statement = db.prepare(
            "SELECT c.name, c.daily_cap, c.revoked, COALESCE(u.issued, 0) \
             FROM clients c LEFT JOIN usage u ON u.name=c.name AND u.day=?1 ORDER BY c.name",
        )?;
        let rows = statement
            .query_map([day_of(now)], |r| {
                Ok(AppRow {
                    name: r.get(0)?,
                    daily_cap: r.get(1)?,
                    revoked: r.get::<_, i64>(2)? == 1,
                    issued: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Offline restore hook: a restored database could resurrect revoked keys,
    /// so every application is revoked and its usage cleared in one transaction.
    pub fn revoke_all_for_restore(&self) -> Result<()> {
        let mut db = self.db()?;
        let tx = begin(&mut db)?;
        tx.execute("UPDATE clients SET revoked=1", [])?;
        tx.execute("DELETE FROM usage", [])?;
        tx.commit()?;
        Ok(())
    }

    /// Spends one unit of today's quota for the key digest, or refuses.
    fn reserve(&self, key_hash: &[u8; 32], now: i64) -> std::result::Result<(), Refusal> {
        let mut db = self.db().map_err(|_| Refusal::Unavailable)?;
        match reserve_in(&mut db, key_hash, now) {
            Ok(outcome) => outcome,
            Err(_) => Err(Refusal::Unavailable),
        }
    }
}

impl AppAdmission {
    pub fn new(clients: Arc<AppClients>, admission: Arc<AdmissionStore>) -> Self {
        Self {
            clients,
            admission,
            workers: Arc::new(Semaphore::new(ISSUE_CAPACITY)),
        }
    }

    /// Quota is committed BEFORE provisioning. A provisioning failure therefore
    /// burns the unit; nothing is refunded.
    fn issue(&self, key_hash: &[u8; 32], now: i64) -> std::result::Result<String, Refusal> {
        self.clients.reserve(key_hash, now)?;
        self.admission
            .provision(now)
            .map_err(|_| Refusal::Unavailable)
    }
}

pub fn router(app: Arc<AppAdmission>) -> Router {
    Router::new()
        .route("/freebird/app/admission", post(admission))
        .with_state(app)
}

fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn unauthorized() -> Response {
    let mut response = no_store(StatusCode::UNAUTHORIZED);
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// Exactly one `Authorization: Bearer fba_<43 base64url>` with canonical
/// encoding. The scheme is matched exactly; anything else is `None`.
fn bearer_key(headers: &HeaderMap) -> Option<[u8; 32]> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let token = value.strip_prefix("Bearer ")?.strip_prefix(KEY_PREFIX)?;
    if token.len() != 43 {
        return None;
    }
    let raw: [u8; 32] = Base64UrlUnpadded::decode_vec(token).ok()?.try_into().ok()?;
    // Exactly one textual spelling per key.
    (Base64UrlUnpadded::encode_string(&raw) == token).then_some(raw)
}

async fn admission(State(app): State<Arc<AppAdmission>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    // Server-to-server contract: no body at all. Zero-byte limit rejects any byte.
    if to_bytes(body, 0).await.is_err() {
        return no_store(StatusCode::BAD_REQUEST);
    }
    let Some(secret) = bearer_key(&parts.headers) else {
        return unauthorized();
    };
    let key_hash: [u8; 32] = Sha256::digest(secret).into();
    let permit = match app.workers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return no_store(StatusCode::TOO_MANY_REQUESTS),
    };
    // Hold capacity even if the HTTP future is cancelled.
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let now = now_seconds().ok_or(Refusal::Unavailable)?;
        app.issue(&key_hash, now)
    })
    .await;
    match result {
        Ok(Ok(code)) => no_store(Json(serde_json::json!({ "admission": code }))),
        Ok(Err(Refusal::Unauthorized)) => unauthorized(),
        Ok(Err(Refusal::Capped { retry_after })) => {
            let mut response = no_store(StatusCode::TOO_MANY_REQUESTS);
            if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        Ok(Err(Refusal::Unavailable)) | Err(_) => no_store(StatusCode::SERVICE_UNAVAILABLE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::{self, Issuer};
    use crate::pow::{self, BrowserOrigin, Pow};
    use axum::{body::Body, http::Method};
    use std::os::unix::fs::symlink;
    use tower::Service;

    const PATH: &str = "/freebird/app/admission";
    const NOW: i64 = 20_000 * DAY;

    fn fixture() -> (tempfile::TempDir, Arc<AppAdmission>) {
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
        let clients = Arc::new(AppClients::open(dir.path()).unwrap());
        (dir, Arc::new(AppAdmission::new(clients, admission)))
    }

    fn key_for(raw: &[u8; 32]) -> String {
        format!("{KEY_PREFIX}{}", Base64UrlUnpadded::encode_string(raw))
    }

    fn raw_of(key: &str) -> [u8; 32] {
        Base64UrlUnpadded::decode_vec(&key[KEY_PREFIX.len()..])
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn digest(key: &str) -> [u8; 32] {
        Sha256::digest(raw_of(key)).into()
    }

    fn post(authorization: Option<&str>) -> Request {
        let mut builder = Request::builder().method(Method::POST).uri(PATH);
        if let Some(value) = authorization {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        builder.body(Body::empty()).unwrap()
    }

    fn bearer(key: &str) -> String {
        format!("Bearer {key}")
    }

    async fn body_code(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["admission"].as_str().unwrap().to_owned()
    }

    fn list(app: &AppAdmission) -> Vec<(String, i64, i64, bool)> {
        app.clients
            .list(now_seconds().unwrap())
            .unwrap()
            .into_iter()
            .map(|row| (row.name, row.daily_cap, row.issued, row.revoked))
            .collect()
    }

    #[test]
    fn store_is_explicit_refuses_existing_symlinks_and_locked_state() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir().unwrap();
        assert!(!enabled(dir.path()).unwrap());
        assert!(AppClients::open(dir.path()).is_err());
        initialize(dir.path()).unwrap();
        assert!(enabled(dir.path()).unwrap());
        assert!(initialize(dir.path()).is_err());
        let open = AppClients::open(dir.path()).unwrap();
        assert!(AppClients::open(dir.path()).is_err(), "lock must exclude");
        drop(open);
        AppClients::open(dir.path()).unwrap();
        for name in [DB, "app-clients.sqlite.lock"] {
            assert_eq!(
                fs::metadata(dir.path().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_file(dir.path().join(DB)).unwrap();
        fs::write(dir.path().join("target"), b"not state").unwrap();
        symlink(dir.path().join("target"), dir.path().join(DB)).unwrap();
        assert!(enabled(dir.path()).is_err());
        assert!(initialize(dir.path()).is_err());
        assert!(AppClients::open(dir.path()).is_err());
        assert_eq!(fs::read(dir.path().join("target")).unwrap(), b"not state");
    }

    #[test]
    fn strict_schema_refuses_extra_objects_and_altered_tables() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir().unwrap();
        initialize(dir.path()).unwrap();
        let path = dir.path().join(DB);
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE VIEW extra AS SELECT * FROM usage")
            .unwrap();
        assert!(AppClients::open(dir.path()).is_err());
        Connection::open(&path)
            .unwrap()
            .execute_batch("DROP VIEW extra")
            .unwrap();
        AppClients::open(dir.path()).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute_batch("ALTER TABLE usage RENAME TO usage_old")
            .unwrap();
        assert!(AppClients::open(dir.path()).is_err());
    }

    #[test]
    fn names_caps_and_client_count_are_validated() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, app) = fixture();
        for name in ["", "-a", "A", "a_b", "a.b", "a b", &"a".repeat(65)] {
            assert!(!valid_name(name), "{name}");
            assert_eq!(app.clients.add(name, 1).unwrap(), None, "{name}");
        }
        assert!(valid_name("a") && valid_name("0-x") && valid_name(&"a".repeat(64)));
        for cap in [0, -1, MAX_DAILY_CAP + 1] {
            assert_eq!(app.clients.add("alpha", cap).unwrap(), None);
        }
        {
            let mut db = app.clients.db().unwrap();
            let tx = db.transaction().unwrap();
            for index in 0..MAX_CLIENTS {
                let hash: [u8; 32] = Sha256::digest(index.to_le_bytes()).into();
                tx.execute(
                    "INSERT INTO clients(name,key_hash,daily_cap,revoked) VALUES(?1,?2,1,1)",
                    params![format!("c{index}"), hash.as_slice()],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        assert_eq!(app.clients.add("overflow", 1).unwrap(), None);
        // Re-activation of an existing revoked name does not grow the table.
        assert!(app.clients.add("c0", 1).unwrap().is_some());
    }

    #[test]
    fn quota_is_per_app_per_utc_day_and_old_usage_is_pruned() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, app) = fixture();
        let key = app.clients.add("alpha", 2).unwrap().unwrap();
        let hash = digest(&key);
        let day = NOW;
        let first = app.issue(&hash, day + 10).unwrap();
        assert_eq!(first.len(), 43);
        assert!(app.admission.consume(&first, day + 10).unwrap());
        let second = app.issue(&hash, day + 20).unwrap();
        assert_ne!(first, second);
        assert!(app.admission.consume(&second, day + 20).unwrap());
        assert_eq!(
            app.issue(&hash, day + 30),
            Err(Refusal::Capped {
                retry_after: DAY - 30
            })
        );
        assert_eq!(
            app.issue(&hash, day + DAY - 1),
            Err(Refusal::Capped { retry_after: 1 })
        );
        let next = app.issue(&hash, day + DAY).unwrap();
        assert!(app.admission.consume(&next, day + DAY).unwrap());
        // Day 20000 usage is older than two days at day 20003 and is pruned.
        app.issue(&hash, day + 3 * DAY).unwrap();
        let rows: Vec<i64> = {
            let db = app.clients.db().unwrap();
            let mut statement = db.prepare("SELECT day FROM usage ORDER BY day").unwrap();
            statement
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(rows, vec![day_of(day) + 1, day_of(day) + 3]);
        assert_eq!(
            app.clients.reserve(&[9; 32], day),
            Err(Refusal::Unauthorized)
        );
    }

    #[test]
    fn bearer_key_must_be_one_exact_canonical_key() {
        let raw = [7u8; 32];
        let key = key_for(&raw);
        let headers = |values: &[&str]| {
            let mut map = HeaderMap::new();
            for value in values {
                map.append(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
            }
            map
        };
        assert_eq!(bearer_key(&headers(&[&bearer(&key)])), Some(raw));
        let token = &key[KEY_PREFIX.len()..];
        let other_last = if token.ends_with('B') { 'C' } else { 'B' };
        let noncanonical = format!("{}{other_last}", &token[..42]);
        for value in [
            key.clone(),
            format!("Basic {key}"),
            format!("bearer {key}"),
            format!("Bearer  {key}"),
            format!("Bearer {key} "),
            format!("Bearer {}", &key[..key.len() - 1]),
            format!("Bearer {key}A"),
            format!("Bearer fbb_{token}"),
            format!("Bearer fba_{}+", &token[..42]),
            format!("Bearer fba_{}/", &token[..42]),
            format!("Bearer fba_{}=", &token[..42]),
            format!("Bearer fba_{noncanonical}"),
            format!("Bearer fba_{}é", &token[..41]),
        ] {
            assert_eq!(bearer_key(&headers(&[&value])), None, "{value}");
        }
        assert_eq!(bearer_key(&headers(&[])), None);
        assert_eq!(
            bearer_key(&headers(&[&bearer(&key), &bearer(&key)])),
            None,
            "duplicate Authorization headers must be refused"
        );
    }

    #[tokio::test]
    async fn handler_admits_per_request_and_refuses_bad_credentials_generically() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (_dir, app) = fixture();
        let key = app.clients.add("alpha", 5).unwrap().unwrap();
        let response = admission(State(app.clone()), post(Some(&bearer(&key)))).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let code = body_code(response).await;
        assert_eq!(code.len(), 43);
        let response = admission(State(app.clone()), post(Some(&bearer(&key)))).await;
        let second = body_code(response).await;
        assert_ne!(code, second);
        let now = now_seconds().unwrap();
        assert!(app.admission.consume(&code, now).unwrap());
        assert!(!app.admission.consume(&code, now).unwrap());
        assert!(app.admission.consume(&second, now).unwrap());

        let unknown = key_for(&[9; 32]);
        for value in [
            None,
            Some(bearer(&unknown)),
            Some(bearer(&key[..key.len() - 1])),
            Some(key.clone()),
        ] {
            let response = admission(State(app.clone()), post(value.as_deref())).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
        let mut duplicated = post(Some(&bearer(&key)));
        duplicated
            .headers_mut()
            .append(header::AUTHORIZATION, bearer(&key).parse().unwrap());
        assert_eq!(
            admission(State(app.clone()), duplicated).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let with_body = Request::builder()
            .method(Method::POST)
            .uri(PATH)
            .header(header::AUTHORIZATION, bearer(&key))
            .body(Body::from("x"))
            .unwrap();
        assert_eq!(
            admission(State(app.clone()), with_body).await.status(),
            StatusCode::BAD_REQUEST
        );
        // Refusals spent nothing.
        assert_eq!(list(&app)[0].2, 2);

        assert!(app.clients.revoke("alpha").unwrap());
        assert!(!app.clients.revoke("missing").unwrap());
        assert_eq!(
            admission(State(app.clone()), post(Some(&bearer(&key))))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn busy_is_429_without_spending_quota_and_cap_is_429_with_retry_after() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (_dir, app) = fixture();
        let key = app.clients.add("alpha", 1).unwrap().unwrap();
        let permits = app
            .workers
            .clone()
            .acquire_many_owned(ISSUE_CAPACITY as u32)
            .await
            .unwrap();
        assert_eq!(
            admission(State(app.clone()), post(Some(&bearer(&key))))
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        drop(permits);
        assert_eq!(list(&app)[0].2, 0, "busy refusal must not spend quota");
        let response = admission(State(app.clone()), post(Some(&bearer(&key)))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = admission(State(app.clone()), post(Some(&bearer(&key)))).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry: i64 = response.headers()[header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=DAY).contains(&retry), "{retry}");
        assert!(response.headers().get(header::CACHE_CONTROL).is_some());
    }

    #[tokio::test]
    async fn provisioning_failure_burns_quota_and_is_503() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (dir, app) = fixture();
        let key = app.clients.add("beta", 1).unwrap().unwrap();
        let db = Connection::open(dir.path().join("admission.sqlite")).unwrap();
        db.execute_batch("CREATE VIEW extra AS SELECT * FROM invitations")
            .unwrap();
        assert_eq!(
            admission(State(app.clone()), post(Some(&bearer(&key))))
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        db.execute_batch("DROP VIEW extra").unwrap();
        assert_eq!(list(&app)[0].2, 1, "failed provisioning burns the unit");
        assert_eq!(
            admission(State(app.clone()), post(Some(&bearer(&key))))
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn recovery_revokes_everything_and_reactivation_gets_a_new_key() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (_dir, app) = fixture();
        let old = app.clients.add("alpha", 5).unwrap().unwrap();
        let other = app.clients.add("beta", 5).unwrap().unwrap();
        assert!(
            app.clients.add("alpha", 5).unwrap().is_none(),
            "active name"
        );
        assert_eq!(
            admission(State(app.clone()), post(Some(&bearer(&old))))
                .await
                .status(),
            StatusCode::OK
        );
        app.clients.revoke_all_for_restore().unwrap();
        assert_eq!(
            list(&app),
            vec![
                ("alpha".to_owned(), 5, 0, true),
                ("beta".to_owned(), 5, 0, true)
            ]
        );
        for key in [&old, &other] {
            assert_eq!(
                admission(State(app.clone()), post(Some(&bearer(key))))
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let fresh = app.clients.add("alpha", 3).unwrap().unwrap();
        assert_ne!(fresh, old);
        assert_eq!(
            admission(State(app.clone()), post(Some(&bearer(&fresh))))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            admission(State(app.clone()), post(Some(&bearer(&old))))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(list(&app)[0], ("alpha".to_owned(), 3, 1, false));
    }

    #[tokio::test]
    async fn app_route_has_no_browser_cors_even_when_browser_origin_is_configured() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (dir, app) = fixture();
        let key_path = dir.path().join("issuer-keys.sqlite");
        Issuer::initialize_key(&key_path).unwrap();
        pow::initialize(dir.path()).unwrap();
        let pow = Arc::new(Pow::open(dir.path(), app.admission.clone()).unwrap());
        let issuer = Arc::new(
            Issuer::open(
                key_path,
                app.admission.clone(),
                "issuer.test",
                "https://issuer.test/private-token/issue",
                now_seconds().unwrap() as u64,
            )
            .unwrap(),
        );
        let key = app.clients.add("alpha", 10).unwrap().unwrap();
        let origin = BrowserOrigin::parse("https://origin.example").unwrap();
        // Same Issuer and Pow instances (their file locks are single-owner) for
        // both the configured router and the plain router below.
        let plain = issuer::router_with_pow(issuer.clone(), pow.clone(), origin.clone());
        let router = issuer::with_app_admission(
            issuer::router_with_pow(issuer, pow, origin),
            Some(app.clone()),
        );
        for origin in ["https://origin.example", "https://other.example"] {
            for method in [Method::OPTIONS, Method::GET] {
                let response = router
                    .clone()
                    .call(
                        Request::builder()
                            .method(method)
                            .uri(PATH)
                            .header(header::ORIGIN, origin)
                            .header(header::AUTHORIZATION, bearer(&key))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert!(!response
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
                assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            }
            let response = router
                .clone()
                .call(
                    Request::builder()
                        .method(Method::POST)
                        .uri(PATH)
                        .header(header::ORIGIN, origin)
                        .header(header::AUTHORIZATION, bearer(&key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(!response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
            assert!(!response.headers().contains_key(header::VARY));
        }
        // Without the app route merged, the path does not exist at all.
        let response = plain.clone().call(post(Some(&bearer(&key)))).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
