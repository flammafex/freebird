//! One instance of the experimental Origin serves requests for a given store.
//! Take the Origin offline to schedule key activation or retire a key.
//! After restoring a cold snapshot, run `invalidate_context_for_restore`
//! before serving requests to invalidate tokens issued with the restored secret.
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
use rusqlite::{
    params, types::ValueRef, Connection, OpenFlags, OptionalExtension, TransactionBehavior,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const SCHEMA_VERSION: i64 = 2;
const HOUR: u64 = 3600;
/// A challenge expires this many seconds after its issuance hour ends.
const GRACE: u64 = 300;
/// A superseded key cannot be retired until this many seconds after its acceptance deadline.
const RETIRE_MARGIN: u64 = 120;
const PRUNE_BATCH: i64 = 256;
const ORIGIN_CAPACITY: usize = 2;
const V1_REFUSAL: &str = "origin schema v1 unsupported; no migration — initialize fresh state";
const SCHEMA_V2: &str = "CREATE TABLE metadata (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        version INTEGER NOT NULL CHECK(version=2),
        secret_hash BLOB NOT NULL,
        high_water INTEGER NOT NULL CHECK(high_water>=0),
        names BLOB);
     CREATE TABLE origin_keys (
        key_id BLOB PRIMARY KEY NOT NULL CHECK(length(key_id)=32),
        spki BLOB NOT NULL,
        activation_hour INTEGER NOT NULL UNIQUE CHECK(activation_hour>=0),
        retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0,1)));
     CREATE TABLE challenges (
        key_id BLOB NOT NULL, digest BLOB NOT NULL, deadline INTEGER NOT NULL,
        PRIMARY KEY(key_id,digest));
     CREATE TABLE spent (
        key_id BLOB NOT NULL, digest BLOB NOT NULL, nonce BLOB NOT NULL,
        deadline INTEGER NOT NULL,
        PRIMARY KEY(key_id,digest,nonce));";

pub struct Origin {
    db: Mutex<Connection>,
    workers: Arc<tokio::sync::Semaphore>,
    _ownership: File,
    secret: [u8; 32],
    /// Opening the store loads its non-retired keys in ascending order by activation hour.
    keys: Vec<LiveKey>,
    issuer: String,
    name: String,
}

struct LiveKey {
    key_id: [u8; 32],
    key: PublicKey,
    hour: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginKeyState {
    Installed,
    Advertising,
    Verifying,
    Retired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginKeyRecord {
    pub key_id: [u8; 32],
    pub spki: Vec<u8>,
    /// The store records activation in whole hours. Multiply by 3,600 to get seconds.
    pub activation_hour: u64,
    pub state: OriginKeyState,
    /// Issuance ends when the successor activates. If present, the time is in seconds.
    pub issuance_end: Option<u64>,
    /// When `issuance_end` is set, the acceptance deadline is 300 seconds later.
    pub acceptance_deadline: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginStatus {
    /// Key states are based on this supplied time in seconds.
    pub now: u64,
    /// This stored time in seconds is the lower bound for clock readings that update the store.
    pub high_water: u64,
    pub keys: Vec<OriginKeyRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredKey {
    key_id: [u8; 32],
    spki: Vec<u8>,
    hour: u64,
    retired: bool,
}

fn connect(path: &Path, initialize: bool) -> Result<Connection> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            path.metadata()?.permissions().mode() & 0o777 == 0o600,
            "Origin database permissions must be 0600"
        );
    }
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    require_plain_schema(&db)?;
    db.busy_timeout(Duration::ZERO)?;
    let mode: String = if initialize {
        db.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?
    } else {
        db.query_row("PRAGMA journal_mode", [], |r| r.get(0))?
    };
    ensure!(
        mode.eq_ignore_ascii_case("wal"),
        "Origin database must use WAL"
    );
    db.pragma_update(None, "synchronous", "FULL")?;
    let sync: i64 = db.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    ensure!(sync == 2, "FULL synchronization unavailable");
    db.pragma_update(None, "secure_delete", "ON")?;
    let secure: i64 = db.query_row("PRAGMA secure_delete", [], |r| r.get(0))?;
    ensure!(secure == 1, "secure deletion unavailable");
    Ok(db)
}

fn ownership(path: &Path, fresh: bool) -> Result<File> {
    // Lock a separate file so that `flock` cannot conflict with SQLite's byte-range locks.
    // Keep the lock file in place so that all processes lock the same inode.
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(fresh);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // If the lock file is missing, opening an existing store fails.
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

/// Stop the systemd services before restoring a cold snapshot and keep them offline
/// until this function succeeds so that the restored state cannot be used to serve requests.
/// The ownership lock does not prevent a restart between restoration and invalidation.
/// Invalidation clears replay rows and preserves the pinned names and all key records,
/// including records for retired keys.
///
/// The replacement secret is published before the database commit so that a failure
/// between the two blocks startup with a hash mismatch.
/// After such a failure, keep the replacement secret and do not reset the store automatically.
/// An error before publication does not invalidate the restored database and secret.
pub fn invalidate_context_for_restore(
    db_path: impl AsRef<Path>,
    context_secret_path: impl AsRef<Path>,
    now: u64,
) -> Result<()> {
    invalidate_context_for_restore_inner(
        db_path.as_ref(),
        context_secret_path.as_ref(),
        now,
        #[cfg(test)]
        || Ok(()),
    )
}

fn invalidate_context_for_restore_inner(
    db_path: &Path,
    secret_path: &Path,
    now: u64,
    #[cfg(test)] after_publish: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let _owner = ownership(db_path, false)?;
    let secret: [u8; 32] = std::fs::read(secret_path)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid context secret"))?;
    let now_i64 = i64::try_from(now)?;
    require_v2(db_path)?;
    let mut db = connect(db_path, false)?;
    integrity(&db)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_plain_schema(&tx)?;
    // Compare table definitions with `SCHEMA_V2` so that a mismatch stops the
    // restore before any evidence of corruption is erased.
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(SCHEMA_V2)?;
    for table in ["metadata", "origin_keys", "challenges", "spent"] {
        let sql = |db: &Connection| -> Result<String> {
            Ok(db.query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |r| r.get(0),
            )?)
        };
        ensure!(
            sql(&tx)? == sql(&canonical)?,
            "unsupported Origin table schema"
        );
    }
    let (hash, high, names) = read_metadata(&tx)?;
    ensure!(
        hash == Sha256::digest(secret)[..],
        "invalid Origin metadata"
    );
    ensure!(now >= high, "Origin clock regression");
    // Check the replay rows directly so that corruption stops the restore
    // before the secret is replaced or the rows are deleted.
    validate_replay(&tx)?;
    let keys = read_keys(&tx)?;
    let mut fresh = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut fresh);
    let mut suffix = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let mut temporary = secret_path.as_os_str().to_os_string();
    temporary.push(format!(".restore-{:032x}", u128::from_ne_bytes(suffix)));
    let temporary = Path::new(&temporary);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(temporary)?;
    let publish = (|| -> Result<()> {
        file.write_all(&fresh)?;
        file.sync_all()?;
        std::fs::rename(temporary, secret_path)?;
        Ok(())
    })();
    if let Err(error) = publish {
        let _ = std::fs::remove_file(temporary);
        return Err(error);
    }
    sync_parent(secret_path)?;
    #[cfg(test)]
    after_publish()?;
    ensure!(
        tx.execute(
            "UPDATE metadata SET secret_hash=?1 WHERE singleton=1",
            params![&Sha256::digest(fresh)[..]],
        )? == 1,
        "context update did not affect exactly one row"
    );
    tx.execute("DELETE FROM spent", [])?;
    tx.execute("DELETE FROM challenges", [])?;
    advance_high_water(&tx, now_i64, high)?;
    ensure!(read_keys(&tx)? == keys, "Origin keys changed");
    let (hash, floor, pinned) = read_metadata(&tx)?;
    ensure!(
        hash == Sha256::digest(fresh)[..] && floor == now && pinned == names,
        "Origin metadata changed unexpectedly"
    );
    let count: i64 = tx.query_row(
        "SELECT (SELECT count(*) FROM challenges)+(SELECT count(*) FROM spent)",
        [],
        |r| r.get(0),
    )?;
    ensure!(count == 0, "Origin replay rows remain");
    tx.commit()?;
    Ok(())
}

/// Check the schema version with a read-only connection so that an unsupported
/// database is left untouched.
/// For example, switching a v1 database to WAL mode could rewrite its file header.
fn require_v2(path: &Path) -> Result<()> {
    let probe = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let version: i64 = probe
        .query_row("SELECT version FROM metadata WHERE singleton=1", [], |r| {
            r.get(0)
        })
        .context("invalid Origin metadata")?;
    check_version(version)
}

fn check_version(version: i64) -> Result<()> {
    match version {
        SCHEMA_VERSION => Ok(()),
        1 => bail!(V1_REFUSAL),
        _ => bail!("unsupported Origin schema version"),
    }
}

fn integrity(db: &Connection) -> Result<()> {
    let integrity: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    ensure!(integrity == "ok", "corrupt Origin store");
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

/// Return a public key only if the SPKI is canonical and its SHA-256 matches `key_id`.
fn checked_key(spki: &[u8], key_id: [u8; 32]) -> Result<PublicKey> {
    let key = PublicKey::from_spki(spki)?;
    ensure!(key.key_id() == key_id, "origin key id does not match SPKI");
    Ok(key)
}

/// Accept an hour only if its start and the time `GRACE` seconds later fit in an `i64`.
fn hour_fits(hour: u64) -> bool {
    hour.checked_mul(HOUR)
        .and_then(|s| s.checked_add(GRACE))
        .and_then(|s| i64::try_from(s).ok())
        .is_some()
}

/// Return the hash of the secret, the high-water mark, and the pinned names from v2 metadata.
fn read_metadata(db: &Connection) -> Result<(Vec<u8>, u64, Option<Vec<u8>>)> {
    let (version, hash, high, names): (i64, Vec<u8>, i64, Option<Vec<u8>>) = db.query_row(
        "SELECT version,secret_hash,high_water,names FROM metadata WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    check_version(version)?;
    Ok((hash, u64::try_from(high)?, names))
}

/// Return all keys in ascending order by activation hour after checking their structure
/// and replay rows. These checks do not depend on the clock.
fn read_keys(db: &Connection) -> Result<Vec<StoredKey>> {
    let mut stmt = db.prepare(
        "SELECT key_id,spki,activation_hour,retired FROM origin_keys ORDER BY activation_hour",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    let mut keys = Vec::new();
    for row in rows {
        let (key_id, spki, hour, retired) = row?;
        let key_id: [u8; 32] = key_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("corrupt Origin key"))?;
        ensure!(retired == 0 || retired == 1, "corrupt Origin key");
        let hour = u64::try_from(hour).context("corrupt Origin key")?;
        ensure!(hour_fits(hour), "corrupt Origin key");
        ensure!(
            PublicKey::from_spki(&spki)?.key_id() == key_id,
            "corrupt Origin key: key_id is not SHA256(SPKI)"
        );
        keys.push(StoredKey {
            key_id,
            spki,
            hour,
            retired: retired == 1,
        });
    }
    let live = keys.iter().filter(|k| !k.retired).count();
    ensure!((1..=3).contains(&live), "corrupt Origin key set");
    let mut seen_live = false;
    for key in &keys {
        if key.retired {
            ensure!(
                !seen_live,
                "corrupt Origin key set: retired key newer than a live key"
            );
        } else {
            seen_live = true;
        }
    }
    validate_replay(db)?;
    Ok(keys)
}

/// Check replay rows before pruning so that expired rows cannot hide corruption.
/// The function reads key metadata one row at a time and checks replay rules in SQL.
/// Requests use public keys that were parsed when the store opened.
fn validate_replay(db: &Connection) -> Result<()> {
    let exists = |sql: &str| -> Result<bool> { Ok(db.query_row(sql, [], |r| r.get(0))?) };
    for sql in [
        "SELECT EXISTS(SELECT 1 FROM challenges WHERE
         typeof(key_id)<>'blob' OR length(key_id)<>32 OR
         typeof(digest)<>'blob' OR length(digest)<>32 OR typeof(deadline)<>'integer')",
        "SELECT EXISTS(SELECT 1 FROM spent WHERE
         typeof(key_id)<>'blob' OR length(key_id)<>32 OR
         typeof(digest)<>'blob' OR length(digest)<>32 OR
         typeof(nonce)<>'blob' OR length(nonce)<>32 OR typeof(deadline)<>'integer')",
    ] {
        ensure!(!exists(sql)?, "corrupt Origin store: malformed replay row");
    }
    ensure!(
        !exists(
            "SELECT EXISTS(SELECT 1 FROM challenges WHERE key_id NOT IN (SELECT key_id FROM origin_keys))
             OR EXISTS(SELECT 1 FROM spent WHERE key_id NOT IN (SELECT key_id FROM origin_keys))"
        )?,
        "corrupt Origin store: row references unknown key"
    );
    ensure!(
        !exists(
            "SELECT EXISTS(SELECT 1 FROM challenges WHERE key_id IN (SELECT key_id FROM origin_keys WHERE retired=1))
             OR EXISTS(SELECT 1 FROM spent WHERE key_id IN (SELECT key_id FROM origin_keys WHERE retired=1))"
        )?,
        "corrupt Origin store: retired key has rows"
    );
    ensure!(
        !exists(
            "SELECT EXISTS(SELECT 1 FROM spent s JOIN challenges c
             ON c.key_id=s.key_id AND c.digest=s.digest WHERE s.deadline<>c.deadline)"
        )?,
        "corrupt Origin store: inconsistent replay deadlines"
    );
    let mut stmt = db.prepare(
        "SELECT key_id,activation_hour,retired FROM origin_keys ORDER BY activation_hour",
    )?;
    let mut rows = stmt.query([])?;
    let mut previous: Option<([u8; 32], u64)> = None;
    let mut live = 0usize;
    while let Some(row) = rows.next()? {
        let key_id: [u8; 32] = row.get_ref(0)?.as_blob()?.try_into()?;
        let hour = u64::try_from(row.get::<_, i64>(1)?)?;
        let retired: i64 = row.get(2)?;
        ensure!(hour_fits(hour), "corrupt Origin key");
        ensure!(retired == 0 || retired == 1, "corrupt Origin key");
        if retired == 1 {
            ensure!(
                live == 0,
                "corrupt Origin key set: retired key newer than a live key"
            );
        } else {
            live += 1;
        }
        if let Some((previous_id, previous_hour)) = previous {
            ensure!(hour > previous_hour, "corrupt Origin activation order");
            // Use checked Rust arithmetic so that computing the successor's deadline
            // cannot overflow a SQLite integer.
            let limit = i64::try_from(
                hour.checked_mul(HOUR)
                    .and_then(|s| s.checked_add(GRACE))
                    .context("successor deadline overflow")?,
            )?;
            let outlives: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM challenges WHERE key_id=?1 AND deadline>?2)
                 OR EXISTS(SELECT 1 FROM spent WHERE key_id=?1 AND deadline>?2)",
                params![previous_id.as_slice(), limit],
                |r| r.get(0),
            )?;
            ensure!(
                !outlives,
                "corrupt Origin store: superseded key replay row outlives successor grace"
            );
        }
        // A key's first challenge expires one hour and `GRACE` seconds after activation.
        // If that deadline is too large to store, installation is allowed but
        // replay rows for the key are rejected.
        let earliest = hour
            .checked_add(1)
            .and_then(|h| h.checked_mul(HOUR))
            .and_then(|s| s.checked_add(GRACE))
            .and_then(|s| i64::try_from(s).ok());
        let predates: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM challenges WHERE key_id=?1 AND (?2 IS NULL OR deadline<?2))
             OR EXISTS(SELECT 1 FROM spent WHERE key_id=?1 AND (?2 IS NULL OR deadline<?2))",
            params![key_id.as_slice(), earliest],
            |r| r.get(0),
        )?;
        ensure!(
            !predates,
            "corrupt Origin store: row predates key activation"
        );
        previous = Some((key_id, hour));
    }
    ensure!((1..=3).contains(&live), "corrupt Origin key set");
    Ok(())
}

fn advance_high_water(db: &Connection, now: i64, high: u64) -> Result<()> {
    let changed = db.execute(
        "UPDATE metadata SET high_water=?1 WHERE singleton=1 AND version=2 AND high_water=?2",
        params![now, i64::try_from(high)?],
    )?;
    ensure!(changed == 1, "clock update did not affect exactly one row");
    Ok(())
}

fn prune_replay(db: &Connection, now: i64) -> Result<()> {
    let Some(cutoff) = now.checked_sub(i64::try_from(RETIRE_MARGIN)?) else {
        return Ok(());
    };
    if cutoff < 0 {
        return Ok(());
    }
    db.execute(
        "DELETE FROM challenges WHERE (key_id,digest) IN (
           SELECT c.key_id,c.digest FROM challenges AS c WHERE c.deadline<=?1
           AND EXISTS(SELECT 1 FROM origin_keys AS k WHERE k.key_id=c.key_id AND k.retired=0)
           ORDER BY c.key_id,c.digest LIMIT ?2)",
        params![cutoff, PRUNE_BATCH],
    )?;
    db.execute(
        "DELETE FROM spent WHERE (key_id,digest,nonce) IN (
           SELECT s.key_id,s.digest,s.nonce FROM spent AS s WHERE s.deadline<=?1
           AND EXISTS(SELECT 1 FROM origin_keys AS k WHERE k.key_id=s.key_id AND k.retired=0)
           AND NOT EXISTS(SELECT 1 FROM challenges AS c WHERE c.key_id=s.key_id AND c.digest=s.digest)
           ORDER BY s.key_id,s.digest,s.nonce LIMIT ?2)",
        params![cutoff, PRUNE_BATCH],
    )?;
    Ok(())
}

fn key_row_counts(db: &Connection, key_id: [u8; 32]) -> Result<(i64, i64)> {
    Ok(db.query_row(
        "SELECT (SELECT COUNT(*) FROM challenges WHERE key_id=?1),
                (SELECT COUNT(*) FROM spent WHERE key_id=?1)",
        [key_id.as_slice()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}

#[derive(Debug, PartialEq, Eq)]
struct ReplayDigest {
    challenges: u64,
    spent: u64,
    sha256: [u8; 32],
}

fn hash_lp(hash: &mut Sha256, bytes: &[u8]) -> Result<()> {
    hash.update(u64::try_from(bytes.len())?.to_be_bytes());
    hash.update(bytes);
    Ok(())
}

/// Hash the replay rows in a fixed order so that they can be compared using constant memory.
/// The comparison relies on the collision resistance of SHA-256.
fn replay_digest(db: &Connection, excluded_key: Option<[u8; 32]>) -> Result<ReplayDigest> {
    let mut hash = Sha256::new();
    hash_lp(&mut hash, b"freebird-origin-replay-v1")?;
    match excluded_key {
        None => hash.update([0]),
        Some(key) => {
            hash.update([1]);
            hash_lp(&mut hash, &key)?;
        }
    }
    let mut counts = [0u64; 2];
    for (index, (table, columns, sql)) in [
        (
            b"challenges".as_slice(),
            3u32,
            "SELECT key_id,digest,deadline FROM challenges WHERE (?1 IS NULL OR key_id<>?1)
             ORDER BY key_id,digest",
        ),
        (
            b"spent".as_slice(),
            4u32,
            "SELECT key_id,digest,nonce,deadline FROM spent WHERE (?1 IS NULL OR key_id<>?1)
             ORDER BY key_id,digest,nonce",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        hash_lp(&mut hash, table)?;
        hash.update(columns.to_be_bytes());
        let mut stmt = db.prepare(sql)?;
        let mut rows = stmt.query([excluded_key.as_ref().map(|key| key.as_slice())])?;
        while let Some(row) = rows.next()? {
            hash.update([1]);
            for column in 0..columns as usize {
                match row.get_ref(column)? {
                    ValueRef::Blob(bytes) if column + 1 < columns as usize => {
                        hash.update([1]);
                        hash_lp(&mut hash, bytes)?;
                    }
                    ValueRef::Integer(value) if column + 1 == columns as usize => {
                        hash.update([2]);
                        hash_lp(&mut hash, &value.to_be_bytes())?;
                    }
                    _ => bail!("unexpected SQLite replay column type"),
                }
            }
            counts[index] = counts[index]
                .checked_add(1)
                .context("replay count overflow")?;
        }
        hash.update([0]);
        hash.update(counts[index].to_be_bytes());
    }
    Ok(ReplayDigest {
        challenges: counts[0],
        spent: counts[1],
        sha256: hash.finalize().into(),
    })
}

fn ensure_replay_digest(
    db: &Connection,
    excluded_key: Option<[u8; 32]>,
    before: &ReplayDigest,
) -> Result<()> {
    ensure!(
        replay_digest(db, excluded_key)? == *before,
        "operation changed protected replay rows"
    );
    Ok(())
}

/// Use the activation schedule and `hour` to report each key's state without changing the store.
fn derive(keys: &[StoredKey], hour: u64) -> Vec<OriginKeyRecord> {
    let advertising = keys
        .iter()
        .filter(|k| !k.retired && k.hour <= hour)
        .max_by_key(|k| k.hour)
        .map(|k| k.key_id);
    keys.iter()
        .enumerate()
        .map(|(i, key)| {
            let state = if key.retired {
                OriginKeyState::Retired
            } else if key.hour > hour {
                OriginKeyState::Installed
            } else if advertising == Some(key.key_id) {
                OriginKeyState::Advertising
            } else {
                OriginKeyState::Verifying
            };
            let issuance_end = keys.get(i + 1).map(|next| next.hour * HOUR);
            OriginKeyRecord {
                key_id: key.key_id,
                spki: key.spki.clone(),
                activation_hour: key.hour,
                state,
                issuance_end,
                acceptance_deadline: issuance_end.map(|end| end + GRACE),
            }
        })
        .collect()
}

impl Origin {
    /// Create a store only if the first key's SPKI is canonical and its SHA-256
    /// matches `expected_key_id`. Both checks run before any files are created.
    /// If setup fails after creating files, the operator must clean them up before retrying.
    pub fn initialize(
        db_path: impl AsRef<Path>,
        context_secret_path: impl AsRef<Path>,
        genesis_spki: &[u8],
        expected_key_id: [u8; 32],
    ) -> Result<()> {
        let db_path = db_path.as_ref();
        let secret_path = context_secret_path.as_ref();
        checked_key(genesis_spki, expected_key_id)?;
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
        let mut db = connect(db_path, true)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_plain_schema(&tx)?;
        tx.execute_batch(SCHEMA_V2)?;
        tx.execute(
            "INSERT INTO metadata VALUES(1,2,?1,0,NULL)",
            params![&Sha256::digest(secret)[..]],
        )?;
        // Activate the first key at hour 0 in the same transaction so that the
        // store always has a key.
        tx.execute(
            "INSERT INTO origin_keys VALUES(?1,?2,0,0)",
            params![expected_key_id.as_slice(), genesis_spki],
        )?;
        tx.commit()?;
        db_file.sync_all()?;
        owner.sync_all()?;
        sync_parent(db_path)?;
        sync_parent(secret_path)?;
        Ok(())
    }

    /// Open an existing store and pin the issuer and origin names on the first successful open.
    /// The key schedule is loaded at startup, so use `install_key` while the Origin is offline.
    pub fn open(
        db_path: impl AsRef<Path>,
        context_secret_path: impl AsRef<Path>,
        issuer_name: &str,
        origin_name: &str,
    ) -> Result<Self> {
        let db_path = db_path.as_ref();
        let owner = ownership(db_path, false)?;
        TokenChallenge::new(issuer_name, &[0; 32], origin_name)?;
        let names = TokenChallenge::new(issuer_name, &[], origin_name)?.serialize();
        let secret: [u8; 32] = std::fs::read(context_secret_path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid context secret"))?;
        require_v2(db_path)?;
        let mut db = connect(db_path, false)?;
        integrity(&db)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_plain_schema(&tx)?;
        let (hash, _, pinned) = read_metadata(&tx)?;
        ensure!(
            hash == Sha256::digest(secret)[..],
            "invalid Origin metadata"
        );
        match pinned {
            Some(old) => ensure!(old == names, "issuer/origin name change unsupported"),
            None => {
                tx.execute(
                    "UPDATE metadata SET names=?1 WHERE singleton=1",
                    params![names],
                )?;
            }
        }
        let stored = read_keys(&tx)?;
        tx.commit()?;
        let keys = stored
            .iter()
            .filter(|k| !k.retired)
            .map(|k| -> Result<LiveKey> {
                Ok(LiveKey {
                    key_id: k.key_id,
                    key: PublicKey::from_spki(&k.spki)?,
                    hour: k.hour,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            db: Mutex::new(db),
            workers: Arc::new(tokio::sync::Semaphore::new(ORIGIN_CAPACITY)),
            _ownership: owner,
            secret,
            keys,
            issuer: issuer_name.into(),
            name: origin_name.into(),
        })
    }

    /// Read the key schedule under the ownership lock so that inspection fails
    /// while the Origin serves requests.
    pub fn status(db_path: impl AsRef<Path>, now: u64) -> Result<OriginStatus> {
        let db_path = db_path.as_ref();
        let _owner = ownership(db_path, false)?;
        require_v2(db_path)?;
        let mut db = connect(db_path, false)?;
        integrity(&db)?;
        let tx = db.transaction()?;
        let (_, high, _) = read_metadata(&tx)?;
        let keys = read_keys(&tx)?;
        tx.commit()?;
        Ok(OriginStatus {
            now,
            high_water: high,
            keys: derive(&keys, now / HOUR),
        })
    }

    /// Schedule a key to activate at a future hour boundary while the Origin is offline.
    /// To install another key, wait for any scheduled key to activate and retire any
    /// superseded key. To reschedule an installed key, use its key ID before it activates.
    pub fn install_key(
        db_path: impl AsRef<Path>,
        spki: &[u8],
        expected_key_id: [u8; 32],
        at: u64,
        now: u64,
    ) -> Result<()> {
        let db_path = db_path.as_ref();
        checked_key(spki, expected_key_id)?;
        ensure!(at.is_multiple_of(HOUR), "activation must be hour-aligned");
        ensure!(at > now, "activation must be in the future");
        let at_hour = at / HOUR;
        ensure!(hour_fits(at_hour), "activation out of range");
        let now_sql = i64::try_from(now)?;
        let _owner = ownership(db_path, false)?;
        require_v2(db_path)?;
        let mut db = connect(db_path, false)?;
        integrity(&db)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_plain_schema(&tx)?;
        let (_, high, _) = read_metadata(&tx)?;
        ensure!(now >= high, "clock regression");
        let keys = read_keys(&tx)?;
        let replay_before = replay_digest(&tx, None)?;
        let hour = now / HOUR;
        match keys.iter().find(|k| k.key_id == expected_key_id) {
            Some(existing) if existing.retired => {
                bail!("retired origin key cannot be reinstalled")
            }
            Some(existing) if existing.hour <= hour => bail!("origin key already active"),
            Some(existing) => {
                // Move only this key's activation time, and keep it after every
                // other key's activation.
                ensure!(
                    keys.iter()
                        .all(|k| k.key_id == expected_key_id || k.hour < at_hour),
                    "activation must follow existing origin keys"
                );
                if existing.hour != at_hour {
                    let changed = tx.execute(
                        "UPDATE origin_keys SET activation_hour=?1 WHERE key_id=?2",
                        params![i64::try_from(at_hour)?, expected_key_id.as_slice()],
                    )?;
                    ensure!(changed == 1, "installation did not update exactly one key");
                }
            }
            None => {
                let live: Vec<u64> = keys.iter().filter(|k| !k.retired).map(|k| k.hour).collect();
                ensure!(
                    live.iter().all(|h| *h <= hour),
                    "another origin key is installed"
                );
                ensure!(
                    live.iter().filter(|h| **h <= hour).count() == 1,
                    "superseded origin key must be retired first"
                );
                ensure!(
                    keys.iter().all(|k| k.hour < at_hour),
                    "activation must follow existing origin keys"
                );
                let inserted = tx.execute(
                    "INSERT INTO origin_keys VALUES(?1,?2,?3,0)",
                    params![expected_key_id.as_slice(), spki, i64::try_from(at_hour)?],
                )?;
                ensure!(inserted == 1, "installation did not insert exactly one key");
            }
        }
        advance_high_water(&tx, now_sql, high)?;
        let after = read_keys(&tx)?;
        let target = after
            .iter()
            .find(|k| k.key_id == expected_key_id)
            .context("installed key missing")?;
        ensure!(
            target.spki == spki && target.hour == at_hour && !target.retired,
            "installation did not persist target"
        );
        ensure!(
            after
                .iter()
                .filter(|k| k.key_id != expected_key_id)
                .eq(keys.iter().filter(|k| k.key_id != expected_key_id)),
            "installation changed another key"
        );
        ensure!(
            read_metadata(&tx)?.1 == now,
            "installation did not advance high-water mark"
        );
        ensure_replay_digest(&tx, None, &replay_before)?;
        tx.commit()?;
        Ok(())
    }

    /// Retire a key while the Origin is offline, at least 420 seconds after its successor activates.
    /// The transaction deletes the retired key's replay rows and keeps its key record permanently.
    /// Retirement requires the ownership lock, a valid store, and a clock reading at or above
    /// the high-water mark.
    pub fn retire_key(db_path: impl AsRef<Path>, key_id: [u8; 32], now: u64) -> Result<()> {
        let db_path = db_path.as_ref();
        let now_sql = i64::try_from(now)?;
        let _owner = ownership(db_path, false)?;
        require_v2(db_path)?;
        let mut db = connect(db_path, false)?;
        integrity(&db)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_plain_schema(&tx)?;
        let (_, high, _) = read_metadata(&tx)?;
        ensure!(now >= high, "clock regression");
        // Validate replay rows before deleting them so that a deadline beyond the
        // successor's grace period still blocks retirement.
        let keys = read_keys(&tx)?;
        let target = keys
            .iter()
            .find(|k| k.key_id == key_id)
            .context("unknown origin key")?;
        ensure!(!target.retired, "origin key already retired");
        let successor = keys
            .iter()
            .find(|k| !k.retired && k.hour > target.hour && k.hour <= now / HOUR)
            .context("origin key has no active successor")?;
        let retire_at = successor
            .hour
            .checked_mul(HOUR)
            .and_then(|s| s.checked_add(GRACE))
            .and_then(|s| s.checked_add(RETIRE_MARGIN))
            .context("retirement deadline overflow")?;
        ensure!(
            now >= retire_at,
            "origin key retirement safety margin has not elapsed"
        );
        let other_rows = replay_digest(&tx, Some(key_id))?;

        tx.execute("DELETE FROM spent WHERE key_id=?1", [key_id.as_slice()])?;
        tx.execute(
            "DELETE FROM challenges WHERE key_id=?1",
            [key_id.as_slice()],
        )?;
        let changed = tx.execute(
            "UPDATE origin_keys SET retired=1 WHERE key_id=?1",
            [key_id.as_slice()],
        )?;
        ensure!(changed == 1, "retirement did not update exactly one key");
        advance_high_water(&tx, now_sql, high)?;

        let after = read_keys(&tx)?;
        let retired = after
            .iter()
            .find(|k| k.key_id == key_id)
            .context("retired key missing")?;
        ensure!(
            retired.retired && retired.spki == target.spki && retired.hour == target.hour,
            "retirement did not persist retired target"
        );
        ensure!(
            after
                .iter()
                .filter(|k| k.key_id != key_id)
                .eq(keys.iter().filter(|k| k.key_id != key_id)),
            "retirement changed another key"
        );
        ensure!(
            key_row_counts(&tx, key_id)? == (0, 0),
            "retirement left target replay rows"
        );
        ensure!(
            read_metadata(&tx)?.1 == now,
            "retirement did not advance high-water mark"
        );
        ensure_replay_digest(&tx, Some(key_id), &other_rows)?;
        tx.commit()?;
        Ok(())
    }

    fn advertising(&self, hour: u64) -> Option<&LiveKey> {
        self.keys
            .iter()
            .filter(|k| k.hour <= hour)
            .max_by_key(|k| k.hour)
    }

    #[cfg(test)]
    fn challenge(&self, now: u64) -> Result<(TokenChallenge, u64)> {
        self.challenge_scoped(now, None)
    }

    fn challenge_scoped(&self, now: u64, scope: Option<&[u8]>) -> Result<(TokenChallenge, u64)> {
        let hour = now / HOUR;
        let deadline = hour
            .checked_add(1)
            .and_then(|h| h.checked_mul(HOUR))
            .and_then(|s| s.checked_add(GRACE))
            .context("clock overflow")?;
        Ok((self.challenge_for(hour, scope)?, deadline))
    }

    /// Use the same challenge formula for issuance and redemption so that they
    /// produce the same challenge for a given hour and scope.
    ///
    /// Unscoped challenges use the v1 context label, and scoped challenges use the v2
    /// label so that their HMAC inputs cannot match.
    /// Prefix the scope with its length so that its end remains clear if more fields are added.
    fn challenge_for(&self, hour: u64, scope: Option<&[u8]>) -> Result<TokenChallenge> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)?;
        match scope {
            None => {
                mac.update(b"freebird-pp-context-v1");
                mac.update(&hour.to_be_bytes());
            }
            Some(scope) => {
                ensure!(valid_scope(scope), "invalid scope");
                mac.update(b"freebird-pp-context-v2");
                mac.update(&hour.to_be_bytes());
                mac.update(&[u8::try_from(scope.len())?]);
                mac.update(scope);
            }
        }
        Ok(TokenChallenge::new(
            &self.issuer,
            &mac.finalize().into_bytes(),
            &self.name,
        )?)
    }

    /// Use the stored deadline to recover the issuance hour, then require the
    /// digest for that hour and the request's scope.
    /// A token that was issued for one scope cannot be redeemed at another scope
    /// or on an unscoped request.
    fn issued_for(&self, digest: &[u8; 32], deadline: i64, scope: Option<&[u8]>) -> bool {
        u64::try_from(deadline)
            .ok()
            .and_then(issued_hour)
            .and_then(|hour| self.challenge_for(hour, scope).ok())
            .is_some_and(|challenge| challenge.digest() == *digest)
    }

    /// A request that commits records `now` as the high-water mark even if its credentials
    /// are invalid. It prunes up to 256 rows per replay table that expired at least 120 seconds ago.
    /// Verify a token only with the non-retired key that matches its `token_key_id`.
    /// Record each challenge under the advertising key. Keep spent-token records at least
    /// until their challenges expire so that each token can be redeemed at most once.
    ///
    /// Library callers must use a blocking thread and limit their own concurrency because
    /// this synchronous method does not take a worker permit.
    /// The HTTP router limits admission to two workers.
    pub fn request_at(&self, token: Option<&Token>, now: u64) -> Result<Option<String>> {
        self.request_with_clock(token, || Ok(now))
    }

    /// Process a request whose challenge and redemption are bound to the scope supplied by nginx.
    pub fn request_scoped_at(
        &self,
        token: Option<&Token>,
        scope: Option<&[u8]>,
        now: u64,
    ) -> Result<Option<String>> {
        self.request_scoped_with_clock(token, scope, || Ok(now))
    }

    fn request_now(&self, token: Option<&Token>, scope: Option<&[u8]>) -> Result<Option<String>> {
        self.request_scoped_with_clock(token, scope, || {
            Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
        })
    }

    /// Read the clock after locking the connection and starting the transaction
    /// so that jobs do not use a reading that was taken while they waited.
    fn request_with_clock(
        &self,
        token: Option<&Token>,
        clock: impl FnOnce() -> Result<u64>,
    ) -> Result<Option<String>> {
        self.request_scoped_with_clock(token, None, clock)
    }

    fn request_scoped_with_clock(
        &self,
        token: Option<&Token>,
        scope: Option<&[u8]>,
        clock: impl FnOnce() -> Result<u64>,
    ) -> Result<Option<String>> {
        self.request_with_prune_hook(token, scope, clock, |_| Ok(()))
    }

    // Let tests abort the transaction after pruning so that they can check rollback.
    // In production the hook does nothing. Validation and the high-water check
    // run before the hook, and a successful request still requires a commit.
    fn request_with_prune_hook(
        &self,
        token: Option<&Token>,
        scope: Option<&[u8]>,
        clock: impl FnOnce() -> Result<u64>,
        after_prune: impl FnOnce(&Connection) -> Result<()>,
    ) -> Result<Option<String>> {
        ensure!(scope.is_none_or(valid_scope), "invalid scope");
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("store poisoned"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = clock()?;
        let now_sql = i64::try_from(now)?;
        require_plain_schema(&tx)?;
        let (hash, high, pinned) = read_metadata(&tx)?;
        ensure!(
            hash == Sha256::digest(self.secret)[..]
                && pinned.as_deref()
                    == Some(
                        TokenChallenge::new(&self.issuer, &[], &self.name)?
                            .serialize()
                            .as_slice()
                    ),
            "invalid Origin metadata"
        );
        validate_replay(&tx)?;
        ensure!(now >= high, "clock regression");
        advance_high_water(&tx, now_sql, high)?;
        prune_replay(&tx, now_sql)?;
        after_prune(&tx)?;
        let mut accepted = false;
        if let Some(token) = token {
            if let Some(live) = self.keys.iter().find(|k| k.key_id == token.token_key_id) {
                let deadline: Option<i64> = tx
                    .query_row(
                        "SELECT deadline FROM challenges WHERE key_id=?1 AND digest=?2",
                        params![live.key_id.as_slice(), token.challenge_digest.as_slice()],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(deadline) = deadline {
                    if now_sql < deadline
                        && self.issued_for(&token.challenge_digest, deadline, scope)
                        && live
                            .key
                            .verify(&token.token_input(), &token.authenticator)
                            .is_ok()
                    {
                        accepted = tx.execute(
                            "INSERT OR IGNORE INTO spent VALUES(?1,?2,?3,?4)",
                            params![
                                live.key_id.as_slice(),
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
            let advertising = self
                .advertising(now / HOUR)
                .context("no advertising origin key")?;
            let (challenge, deadline) = self.challenge_scoped(now, scope)?;
            tx.execute(
                "INSERT OR IGNORE INTO challenges VALUES(?1,?2,?3)",
                params![
                    advertising.key_id.as_slice(),
                    challenge.digest().as_slice(),
                    i64::try_from(deadline)?
                ],
            )?;
            Some(build_challenge_header(
                &challenge,
                advertising.key.to_spki(),
                deadline - now,
            ))
        };
        ensure!(
            read_metadata(&tx)?.1 == now,
            "request did not advance high-water mark"
        );
        tx.commit()?;
        Ok(challenge)
    }
}

pub fn router(origin: Arc<Origin>) -> Router {
    Router::new()
        .route("/private-token/protected", get(protected))
        .with_state(origin)
}

/// The `Freebird-Scope` header binds a challenge and token to an application scope.
///
/// Keep the Origin on loopback behind nginx so that clients cannot set their own scope.
/// On every protected route, nginx sets or clears this header with `proxy_set_header`
/// in `deploy/nginx/freebird.conf` and discards any value sent by the client.
const SCOPE_HEADER: &str = "freebird-scope";
const MAX_SCOPE: usize = 128;

fn valid_scope(scope: &[u8]) -> bool {
    (1..=MAX_SCOPE).contains(&scope.len()) && scope.iter().all(|b| matches!(b, 0x21..=0x7e))
}

/// Recover the issuance hour from `deadline = (hour + 1) * HOUR + GRACE`.
/// Return `None` if `challenge_scoped` could not have produced the deadline.
fn issued_hour(deadline: u64) -> Option<u64> {
    let base = deadline.checked_sub(GRACE)?;
    if base < HOUR || base % HOUR != 0 {
        return None;
    }
    Some(base / HOUR - 1)
}

/// A missing or empty `Freebird-Scope` header leaves the request unscoped.
/// A duplicate header, a value longer than 128 bytes, or a value with any byte
/// outside visible ASCII results in HTTP 400 with no challenge.
fn scope_header(headers: &HeaderMap) -> std::result::Result<Option<Vec<u8>>, StatusCode> {
    let mut values = headers.get_all(SCOPE_HEADER).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let bytes = first.as_bytes();
    if bytes.is_empty() {
        return Ok(None);
    }
    if !valid_scope(bytes) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Some(bytes.to_vec()))
}

async fn protected(State(origin): State<Arc<Origin>>, headers: HeaderMap) -> Response {
    protected_with_request(origin, headers, |origin, token, scope| {
        origin.request_now(token, scope)
    })
    .await
}

async fn protected_with_request(
    origin: Arc<Origin>,
    headers: HeaderMap,
    request: impl FnOnce(&Origin, Option<&Token>, Option<&[u8]>) -> Result<Option<String>>
        + Send
        + 'static,
) -> Response {
    // Reject malformed scopes before taking a worker permit or accessing the store.
    let scope = match scope_header(&headers) {
        Ok(scope) => scope,
        Err(status) => return status.into_response(),
    };
    let permit = match origin.workers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(tokio::sync::TryAcquireError::NoPermits) => {
            return StatusCode::TOO_MANY_REQUESTS.into_response()
        }
        Err(tokio::sync::TryAcquireError::Closed) => {
            return StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    };
    let mut fields = headers.get_all(header::AUTHORIZATION).iter();
    let first = fields.next();
    let token = if fields.next().is_none() {
        first
            .and_then(|v| v.to_str().ok())
            .and_then(|v| parse_authorization_header(v).ok())
    } else {
        None
    };
    // Keep the permit with the blocking job so that cancelling the HTTP request
    // does not release it before the job finishes.
    // Do not refund a token after a lost response because its redemption may have committed.
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        request(&origin, token.as_ref(), scope.as_deref())
    })
    .await;
    match result {
        Ok(Ok(None)) => (StatusCode::OK, "protected resource\n").into_response(),
        Ok(Ok(Some(challenge))) => match HeaderValue::from_str(&challenge) {
            Ok(value) => (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, value)],
            )
                .into_response(),
            Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        },
        Ok(Err(_)) | Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // The tests sign tokens with private keys. The Origin verifies them with public keys.
    use freebird_crypto::privacy_pass::SecretKey;
    use std::path::PathBuf;

    const H: u64 = 500_000;
    const S: u64 = H * HOUR;

    type ChallengeRow = (Vec<u8>, Vec<u8>, i64);
    type SpentRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64);

    // Tests collect replay rows for direct comparison. Production checks hash
    // them one at a time to keep memory use constant.
    #[derive(Debug, PartialEq, Eq)]
    struct ReplayRows {
        challenges: Vec<ChallengeRow>,
        spent: Vec<SpentRow>,
    }

    /// This fixture creates a v1 store to test rejection without a file change.
    const V1_FIXTURE: &str = "CREATE TABLE metadata (
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

    fn paths(dir: &Path) -> (PathBuf, PathBuf) {
        (dir.join("origin.db"), dir.join("context"))
    }

    fn signer() -> Result<(SecretKey, PublicKey)> {
        let signer = SecretKey::generate()?;
        let key = signer.public_key()?;
        Ok((signer, key))
    }

    fn token(signer: &SecretKey, key: &PublicKey, digest: [u8; 32], nonce: u8) -> Result<Token> {
        let mut token = Token {
            nonce: [nonce; 32],
            challenge_digest: digest,
            token_key_id: key.key_id(),
            authenticator: [0; 256],
        };
        let (blinded, state) = key.blind(&token.token_input())?;
        token.authenticator = key.finalize(state, &signer.blind_sign(&blinded)?)?;
        Ok(token)
    }

    fn raw(db: &Path) -> Result<Connection> {
        Ok(Connection::open(db)?)
    }

    fn read_only(db: &Path) -> Result<Connection> {
        Ok(Connection::open_with_flags(
            db,
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?)
    }

    fn remove_test_schema_objects(db: &Path) -> Result<()> {
        let conn = raw(db)?;
        let objects = conn
            .prepare("SELECT type,name FROM sqlite_master WHERE type IN ('trigger','view')")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (kind, name) in objects {
            conn.execute_batch(&format!("DROP {kind} \"{}\"", name.replace('"', "\"\"")))?;
        }
        Ok(())
    }

    fn plant(db: &Path, key_id: &[u8], digest: [u8; 32], deadline: i64) -> Result<()> {
        raw(db)?.execute(
            "INSERT INTO challenges VALUES(?1,?2,?3)",
            params![key_id, digest.as_slice(), deadline],
        )?;
        Ok(())
    }

    fn plant_spend(
        db: &Connection,
        key_id: [u8; 32],
        digest: [u8; 32],
        nonce: [u8; 32],
        deadline: i64,
    ) -> Result<()> {
        db.execute(
            "INSERT INTO spent VALUES(?1,?2,?3,?4)",
            params![
                key_id.as_slice(),
                digest.as_slice(),
                nonce.as_slice(),
                deadline
            ],
        )?;
        Ok(())
    }

    fn authorization(token: &Token) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&freebird_common::privacy_pass::build_authorization_header(
                token,
            ))?,
        );
        Ok(headers)
    }

    async fn protected_with_clock(
        origin: Arc<Origin>,
        headers: HeaderMap,
        clock: impl FnOnce() -> Result<u64> + Send + 'static,
    ) -> Response {
        protected_with_request(origin, headers, move |origin, token, scope| {
            origin.request_scoped_with_clock(token, scope, clock)
        })
        .await
    }

    fn challenge_rows(db: &Path) -> Result<Vec<ChallengeRow>> {
        let conn = read_only(db)?;
        let mut stmt = conn.prepare(
            "SELECT key_id,digest,deadline FROM challenges ORDER BY deadline,key_id,digest",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn spent_rows(db: &Path) -> Result<Vec<SpentRow>> {
        let conn = read_only(db)?;
        let mut stmt = conn.prepare(
            "SELECT key_id,digest,nonce,deadline FROM spent ORDER BY key_id,digest,nonce",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    #[derive(Debug, PartialEq, Eq)]
    struct StoreSnapshot {
        metadata: (Vec<u8>, u64, Option<Vec<u8>>),
        keys: Vec<StoredKey>,
        replay: ReplayRows,
    }

    fn store_snapshot(db: &Path) -> Result<StoreSnapshot> {
        let conn = read_only(db)?;
        Ok(StoreSnapshot {
            metadata: read_metadata(&conn)?,
            keys: read_keys(&conn)?,
            replay: ReplayRows {
                challenges: challenge_rows(db)?,
                spent: spent_rows(db)?,
            },
        })
    }

    fn plant_retirement_rows(db: &Path, old: &PublicKey, next: &PublicKey) -> Result<()> {
        for (key, deadline) in [(old, S + GRACE), (next, S + HOUR + GRACE)] {
            plant(db, &key.key_id(), [1; 32], deadline as i64)?;
            raw(db)?.execute(
                "INSERT INTO spent VALUES(?1,?2,?3,?4)",
                params![
                    key.key_id().as_slice(),
                    &[1u8; 32],
                    &[2u8; 32],
                    deadline as i64
                ],
            )?;
        }
        Ok(())
    }

    fn states(status: &OriginStatus) -> Vec<OriginKeyState> {
        status.keys.iter().map(|k| k.state).collect()
    }

    fn install(db: &Path, key: &PublicKey, at: u64, now: u64) -> Result<()> {
        Origin::install_key(db, key.to_spki(), key.key_id(), at, now)
    }

    fn refused(db: &Path, secret: &Path) -> Result<()> {
        ensure!(
            Origin::open(db, secret, "issuer", "origin").is_err(),
            "corrupt store accepted"
        );
        Ok(())
    }

    /// Create a store with the first key active at hour 0. If a successor is
    /// supplied, install it at `S - HOUR` to activate at `S`.
    fn fresh(
        dir: &Path,
        genesis: &PublicKey,
        successor: Option<&PublicKey>,
    ) -> Result<(PathBuf, PathBuf)> {
        let (db, secret) = paths(dir);
        Origin::initialize(&db, &secret, genesis.to_spki(), genesis.key_id())?;
        if let Some(next) = successor {
            install(&db, next, S, S - HOUR)?;
        }
        Ok((db, secret))
    }

    #[test]
    fn restore_invalidation_preserves_manifest_and_invalidates_tokens() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (_, old) = signer()?;
        let (signer, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &old, Some(&key))?;
        Origin::retire_key(&db, old.key_id(), S + GRACE + RETIRE_MARGIN)?;
        let now = S + GRACE + RETIRE_MARGIN;
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        origin.request_at(None, now)?;
        let (challenge, _) = origin.challenge(now)?;
        let spent = token(&signer, &key, challenge.digest(), 1)?;
        let unspent = token(&signer, &key, challenge.digest(), 2)?;
        assert!(origin.request_at(Some(&spent), now)?.is_none());
        drop(origin);
        let before = Origin::status(&db, now)?;
        assert!(before
            .keys
            .iter()
            .any(|k| k.state == OriginKeyState::Retired));
        assert!(!challenge_rows(&db)?.is_empty());
        assert!(!spent_rows(&db)?.is_empty());
        let names = read_metadata(&raw(&db)?)?.2;
        invalidate_context_for_restore(&db, &secret, now)?;
        assert_eq!(Origin::status(&db, now)?, before);
        assert_eq!(read_metadata(&raw(&db)?)?.2, names);
        assert!(challenge_rows(&db)?.is_empty());
        assert!(spent_rows(&db)?.is_empty());
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        assert_ne!(origin.challenge(now)?.0.digest(), challenge.digest());
        assert!(origin.request_at(Some(&spent), now)?.is_some());
        assert!(origin.request_at(Some(&unspent), now)?.is_some());
        Ok(())
    }

    #[test]
    fn restore_invalidation_refuses_corrupt_replay_without_changes() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (_, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &key, None)?;
        // A reference to an unknown key makes the replay row invalid even though
        // its fields have the expected types and sizes.
        plant(&db, &[0u8; 32], [1; 32], (HOUR + GRACE) as i64)?;
        let old_secret = std::fs::read(&secret)?;
        let metadata = read_metadata(&read_only(&db)?)?;
        let challenges = challenge_rows(&db)?;
        let spent = spent_rows(&db)?;
        let db_bytes = std::fs::read(&db)?;
        assert!(invalidate_context_for_restore(&db, &secret, 1).is_err());
        assert_eq!(std::fs::read(&secret)?, old_secret);
        assert_eq!(std::fs::read(&db)?, db_bytes);
        assert_eq!(read_metadata(&read_only(&db)?)?, metadata);
        assert_eq!(challenge_rows(&db)?, challenges);
        assert_eq!(spent_rows(&db)?, spent);
        Ok(())
    }

    #[test]
    fn restore_invalidation_post_publish_failure_refuses_open() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (_, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &key, None)?;
        let old_secret = std::fs::read(&secret)?;
        let before = store_snapshot(&db)?;
        assert!(invalidate_context_for_restore_inner(&db, &secret, 1, || {
            bail!("injected after publication")
        })
        .is_err());
        assert_ne!(std::fs::read(&secret)?, old_secret);
        assert_eq!(store_snapshot(&db)?, before);
        refused(&db, &secret)?;
        Ok(())
    }

    #[test]
    fn durable_redemption_clock_and_ownership() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("origin.db");
        let secret = dir.path().join("context");
        let (signer, key) = signer()?;
        assert!(Origin::open(&db, &secret, "issuer", "origin").is_err());
        Origin::initialize(&db, &secret, key.to_spki(), key.key_id())?;
        assert!(Origin::initialize(&db, &secret, key.to_spki(), key.key_id()).is_err());
        let missing = dir.path().join("missing.db");
        assert!(Origin::open(&missing, &secret, "issuer", "origin").is_err());
        assert!(!missing.exists());
        assert!(!dir.path().join("missing.db.lock").exists());
        assert!(dir.path().join("origin.db.lock").is_file());
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        assert!(Origin::open(&db, &secret, "issuer", "origin").is_err());
        assert!(Origin::status(&db, 0).is_err());
        assert!(origin.request_at(None, 3601)?.is_some());
        // Reject clock regression even within the same hour.
        assert!(origin.request_at(None, 3600).is_err());
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
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        assert!(origin.request_at(Some(&token), 3601)?.is_some());
        assert!(origin.request_at(Some(&unspent), deadline)?.is_some());
        assert!(origin.request_at(None, deadline - 1).is_err());
        drop(origin);
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
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
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("origin.db");
        let secret = dir.path().join("context");
        let signer = SecretKey::generate()?;
        let key = signer.public_key()?;
        Origin::initialize(&db, &secret, key.to_spki(), key.key_id())?;
        let origin = Arc::new(Origin::open(&db, &secret, "issuer", "origin")?);
        let response = protected(State(origin.clone()), HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers()[header::WWW_AUTHENTICATE]
            .to_str()?
            .starts_with("PrivateToken challenge=\""));
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        // Record the challenge at the test's fixed time so that crossing an
        // hour boundary after the first request does not invalidate the setup.
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

    #[test]
    fn v1_refusal_leaves_file_unchanged() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (db, secret) = paths(dir.path());
        std::fs::write(dir.path().join("origin.db.lock"), b"")?;
        std::fs::write(&secret, [7u8; 32])?;
        Connection::open(&db)?.execute_batch(V1_FIXTURE)?;
        let (_, key) = signer()?;
        let before = std::fs::read(&db)?;
        let err = Origin::open(&db, &secret, "issuer", "origin")
            .err()
            .context("v1 store accepted")?;
        assert!(err.to_string().contains("v1 unsupported"));
        assert!(Origin::status(&db, 0).is_err());
        assert!(install(&db, &key, S, 0).is_err());
        assert!(Origin::retire_key(&db, key.key_id(), S + 420)
            .unwrap_err()
            .to_string()
            .contains("v1 unsupported"));
        assert_eq!(std::fs::read(&db)?, before);
        Ok(())
    }

    #[test]
    fn initialize_refuses_mismatch_and_noncanonical_without_creating_files() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (db, secret) = paths(dir.path());
        let (_, key) = signer()?;
        let mut noncanonical = key.to_spki().to_vec();
        noncanonical.push(0);
        let id: [u8; 32] = Sha256::digest(&noncanonical).into();
        assert!(Origin::initialize(&db, &secret, &noncanonical, id).is_err());
        assert!(Origin::initialize(&db, &secret, key.to_spki(), [0; 32]).is_err());
        assert!(!db.exists() && !secret.exists());
        assert!(!dir.path().join("origin.db.lock").exists());
        Origin::initialize(&db, &secret, key.to_spki(), key.key_id())?;
        Ok(())
    }

    #[test]
    fn connection_requires_private_wal_and_verified_pragmas() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let (_, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &key, None)?;
        assert_eq!(db.metadata()?.permissions().mode() & 0o777, 0o600);
        let conn = connect(&db, false)?;
        assert_eq!(
            conn.query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0))?,
            2
        );
        assert_eq!(
            conn.query_row("PRAGMA secure_delete", [], |r| r.get::<_, i64>(0))?,
            1
        );
        assert_eq!(
            conn.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))?,
            "wal"
        );
        drop(conn);
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644))?;
        assert!(Origin::open(&db, &secret, "issuer", "origin").is_err());
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600))?;
        raw(&db)?.execute_batch("PRAGMA journal_mode=DELETE;")?;
        let before = std::fs::read(&db)?;
        assert!(Origin::open(&db, &secret, "issuer", "origin").is_err());
        assert_eq!(std::fs::read(&db)?, before);
        Ok(())
    }

    #[test]
    fn names_and_secret_pinned_at_first_open() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (db, secret) = paths(dir.path());
        let (_, key) = signer()?;
        Origin::initialize(&db, &secret, key.to_spki(), key.key_id())?;
        drop(Origin::open(&db, &secret, "issuer", "origin")?);
        assert!(Origin::open(&db, &secret, "other", "origin").is_err());
        assert!(Origin::open(&db, &secret, "issuer", "other").is_err());
        let other = dir.path().join("other-context");
        std::fs::write(&other, [1u8; 32])?;
        assert!(Origin::open(&db, &other, "issuer", "origin").is_err());
        drop(Origin::open(&db, &secret, "issuer", "origin")?);
        Ok(())
    }

    #[test]
    fn corruption_matrix_refuses_open() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let root = tempfile::tempdir()?;
        let (_, k1) = signer()?;
        let (_, k2) = signer()?;
        let (_, k3) = signer()?;
        let (_, k4) = signer()?;
        let dir = |name: &str| -> Result<PathBuf> {
            let path = root.path().join(name);
            std::fs::create_dir(&path)?;
            Ok(path)
        };

        let p = dir("version")?;
        let (db, secret) = fresh(&p, &k1, Some(&k2))?;
        raw(&db)?
            .execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE metadata SET version=3")?;
        refused(&db, &secret)?;

        let p = dir("no-live")?;
        let (db, secret) = fresh(&p, &k1, None)?;
        raw(&db)?.execute("UPDATE origin_keys SET retired=1", [])?;
        refused(&db, &secret)?;

        let p = dir("retired-rows")?;
        let (db, secret) = fresh(&p, &k1, Some(&k2))?;
        raw(&db)?.execute(
            "UPDATE origin_keys SET retired=1 WHERE key_id=?1",
            [k1.key_id().as_slice()],
        )?;
        plant(&db, &k1.key_id(), [1; 32], 300)?;
        refused(&db, &secret)?;

        let p = dir("superseded-deadline")?;
        let (db, secret) = fresh(&p, &k1, Some(&k2))?;
        plant(&db, &k1.key_id(), [1; 32], (S + GRACE + 1) as i64)?;
        refused(&db, &secret)?;

        let p = dir("superseded-spent-deadline")?;
        let (db, secret) = fresh(&p, &k1, Some(&k2))?;
        plant_retirement_rows(&db, &k1, &k2)?;
        raw(&db)?.execute(
            "UPDATE spent SET deadline=?1 WHERE key_id=?2",
            params![(S + GRACE + 1) as i64, k1.key_id().as_slice()],
        )?;
        refused(&db, &secret)?;

        let p = dir("boundary-ok")?;
        let (db, secret) = fresh(&p, &k1, Some(&k2))?;
        plant(&db, &k1.key_id(), [1; 32], (S + GRACE) as i64)?;
        assert!(Origin::open(&db, &secret, "issuer", "origin").is_ok());

        for table in ["challenges", "spent"] {
            let p = dir(&format!("pre-activation-{table}"))?;
            let (db, secret) = fresh(&p, &k1, Some(&k2))?;
            let conn = raw(&db)?;
            let columns = if table == "spent" {
                ",zeroblob(32)"
            } else {
                ""
            };
            let sql = format!("INSERT INTO {table} VALUES(?1,zeroblob(32){columns},?2)");
            conn.execute(
                &sql,
                params![k2.key_id().as_slice(), (S + HOUR + GRACE - 1) as i64],
            )?;
            drop(conn);
            refused(&db, &secret)?;

            // Both tables accept a deadline exactly one hour and `GRACE`
            // seconds after activation.
            raw(&db)?.execute(
                &format!("UPDATE {table} SET deadline=?1"),
                [(S + HOUR + GRACE) as i64],
            )?;
            drop(Origin::open(&db, &secret, "issuer", "origin")?);
        }

        let p = dir("orphan")?;
        let (db, secret) = fresh(&p, &k1, Some(&k2))?;
        plant(&db, &[9; 32], [1; 32], 300)?;
        refused(&db, &secret)?;

        let p = dir("retired-newer-than-live")?;
        let (db, secret) = fresh(&p, &k1, Some(&k2))?;
        raw(&db)?.execute(
            "UPDATE origin_keys SET retired=1 WHERE key_id=?1",
            [k2.key_id().as_slice()],
        )?;
        refused(&db, &secret)?;

        let p = dir("key-id-mismatch")?;
        let (db, secret) = fresh(&p, &k1, None)?;
        raw(&db)?.execute("UPDATE origin_keys SET key_id=?1", [[9u8; 32].as_slice()])?;
        refused(&db, &secret)?;

        let p = dir("four-live")?;
        let (db, secret) = fresh(&p, &k1, Some(&k2))?;
        raw(&db)?.execute(
            "INSERT INTO origin_keys VALUES(?1,?2,?3,0)",
            params![k3.key_id().as_slice(), k3.to_spki(), (2 * H) as i64],
        )?;
        raw(&db)?.execute(
            "INSERT INTO origin_keys VALUES(?1,?2,?3,0)",
            params![k4.key_id().as_slice(), k4.to_spki(), (3 * H) as i64],
        )?;
        refused(&db, &secret)?;
        Ok(())
    }

    #[test]
    fn boundary_drill_keys_zero_and_h() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (db, secret) = paths(dir.path());
        let (k1, p1) = signer()?;
        let (k2, p2) = signer()?;
        Origin::initialize(&db, &secret, p1.to_spki(), p1.key_id())?;
        install(&db, &p2, S, S - HOUR)?;
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;

        // Before `S`, the Origin advertises `p1` and rejects tokens for `p2`.
        let before = S - 1;
        let d_before = origin.challenge(before)?.0.digest();
        assert!(origin.request_at(None, before)?.is_some());
        assert_eq!(
            challenge_rows(&db)?,
            vec![(p1.key_id().to_vec(), d_before.to_vec(), (S + GRACE) as i64)]
        );
        assert!(origin
            .request_at(Some(&token(&k2, &p2, d_before, 1)?), before)?
            .is_some());
        let wrong_id = Token {
            token_key_id: [0xEE; 32],
            ..token(&k1, &p1, d_before, 3)?
        };
        assert!(origin.request_at(Some(&wrong_id), before)?.is_some());

        // At `S`, the Origin advertises `p2` and accepts tokens for `p1` only
        // for a stored challenge before `S + GRACE`.
        let d_h = origin.challenge(S)?.0.digest();
        assert!(origin.request_at(None, S)?.is_some());
        assert_eq!(
            challenge_rows(&db)?,
            vec![
                (p1.key_id().to_vec(), d_before.to_vec(), (S + GRACE) as i64),
                (
                    p2.key_id().to_vec(),
                    d_h.to_vec(),
                    (S + HOUR + GRACE) as i64
                ),
            ]
        );
        assert!(origin
            .request_at(Some(&token(&k1, &p1, d_before, 4)?), S + GRACE - 1)?
            .is_none());
        assert!(origin
            .request_at(Some(&token(&k1, &p1, d_before, 5)?), S + GRACE)?
            .is_some());
        assert!(origin
            .request_at(Some(&token(&k1, &p1, d_h, 6)?), S + 400)?
            .is_some());
        assert!(origin
            .request_at(Some(&token(&k2, &p2, d_before, 7)?), S + 400)?
            .is_some());
        assert!(origin
            .request_at(Some(&token(&k2, &p2, d_h, 8)?), S + 400)?
            .is_none());
        drop(origin);

        // Reopen the store to check that the replay rows pass validation and
        // that the token is still rejected.
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        assert!(origin
            .request_at(Some(&token(&k1, &p1, d_before, 4)?), S + 400)?
            .is_some());
        Ok(())
    }

    #[test]
    fn install_key_refusal_table() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (db, secret) = paths(dir.path());
        let (_, p1) = signer()?;
        let (_, p2) = signer()?;
        let (_, p3) = signer()?;
        let t0 = S - HOUR;
        Origin::initialize(&db, &secret, p1.to_spki(), p1.key_id())?;

        // An invalid SPKI, a mismatched key ID, or an activation time that is
        // not on a future hour boundary leaves the store untouched.
        assert!(Origin::install_key(&db, p2.to_spki(), p3.key_id(), S, t0).is_err());
        let mut noncanonical = p2.to_spki().to_vec();
        noncanonical.push(0);
        let id: [u8; 32] = Sha256::digest(&noncanonical).into();
        assert!(Origin::install_key(&db, &noncanonical, id, S, t0).is_err());
        assert!(install(&db, &p2, S + 1, t0).is_err());
        assert!(install(&db, &p2, S, S).is_err());
        assert!(install(&db, &p2, S, S + 1).is_err());
        assert_eq!(Origin::status(&db, t0)?.high_water, 0);

        // Installing `p2` sets the clock floor to `t0` and blocks installing
        // `p3`. A time below `t0` also blocks rescheduling `p2`.
        install(&db, &p2, S, t0)?;
        assert_eq!(Origin::status(&db, t0)?.high_water, t0);
        assert!(install(&db, &p3, S + HOUR, t0).is_err());
        assert!(install(&db, &p2, S + HOUR, t0 - 1).is_err());
        assert_eq!(Origin::status(&db, t0)?.high_water, t0);

        // Rescheduling before activation changes the activation hour.
        // Repeating the same schedule succeeds and leaves that hour unchanged.
        install(&db, &p2, S + HOUR, t0)?;
        assert_eq!(Origin::status(&db, t0)?.keys[1].activation_hour, H + 1);
        install(&db, &p2, S, t0)?;
        install(&db, &p2, S, t0)?;
        assert_eq!(Origin::status(&db, t0)?.keys[1].activation_hour, H);

        // At `S`, neither the advertising key nor the superseded key can be
        // rescheduled. The superseded key must be retired before installing `p3`.
        assert!(install(&db, &p2, S + HOUR, S).is_err());
        assert!(install(&db, &p1, S + HOUR, S).is_err());
        assert!(install(&db, &p3, S + HOUR, S).is_err());
        assert_eq!(Origin::status(&db, S)?.high_water, t0);

        // Marking `p1` retired prevents its reinstallation and allows `p3` to be installed.
        raw(&db)?.execute(
            "UPDATE origin_keys SET retired=1 WHERE key_id=?1",
            [p1.key_id().as_slice()],
        )?;
        assert!(install(&db, &p1, S + HOUR, S).is_err());
        install(&db, &p3, S + HOUR, S)?;
        let status = Origin::status(&db, S)?;
        assert_eq!(status.high_water, S);
        assert_eq!(
            states(&status),
            vec![
                OriginKeyState::Retired,
                OriginKeyState::Advertising,
                OriginKeyState::Installed,
            ]
        );
        drop(Origin::open(&db, &secret, "issuer", "origin")?);
        Ok(())
    }

    #[test]
    fn activation_range_matches_issuer_i64_deadline_bound() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (_, genesis) = signer()?;
        let (_, next) = signer()?;
        let (db, _) = fresh(dir.path(), &genesis, None)?;
        let max_hour = (i64::MAX as u64 - GRACE) / HOUR;
        assert!(install(&db, &next, (max_hour + 1) * HOUR, 0).is_err());
        assert_eq!(Origin::status(&db, 0)?.keys.len(), 1);
        install(&db, &next, max_hour * HOUR, 0)?;
        assert_eq!(Origin::status(&db, 0)?.keys[1].activation_hour, max_hour);
        Ok(())
    }

    fn assert_install_trigger_rolls_back(trigger: &str, reschedule: bool) -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (_, genesis) = signer()?;
        let (_, next) = signer()?;
        let (db, secret) = fresh(dir.path(), &genesis, reschedule.then_some(&next))?;
        let now = S - HOUR + 1;
        drop(Origin::open(&db, &secret, "issuer", "origin")?);
        plant(&db, &genesis.key_id(), [1; 32], (S + GRACE) as i64)?;
        plant_spend(
            &raw(&db)?,
            genesis.key_id(),
            [1; 32],
            [2; 32],
            (S + GRACE) as i64,
        )?;
        let before = Origin::status(&db, now)?;
        let snapshot = store_snapshot(&db)?;
        raw(&db)?.execute_batch(trigger)?;
        let error = install(&db, &next, S + HOUR, now).unwrap_err();
        assert!(
            error.to_string().contains("unexpected schema objects"),
            "{error:#}"
        );
        assert_eq!(store_snapshot(&db)?, snapshot);
        remove_test_schema_objects(&db)?;
        assert_eq!(Origin::status(&db, now)?, before);
        drop(Origin::open(&db, &secret, "issuer", "origin")?);
        assert_eq!(Origin::status(&db, now)?, before);
        assert_eq!(store_snapshot(&db)?, snapshot);
        Ok(())
    }

    #[test]
    fn ignored_install_insert_rolls_back() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        assert_install_trigger_rolls_back(
            "CREATE TRIGGER ignore_install BEFORE INSERT ON origin_keys
             BEGIN SELECT RAISE(IGNORE); END;",
            false,
        )
    }

    #[test]
    fn ignored_install_reschedule_rolls_back() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        assert_install_trigger_rolls_back(
            "CREATE TRIGGER ignore_reschedule BEFORE UPDATE ON origin_keys
             BEGIN SELECT RAISE(IGNORE); END;",
            true,
        )
    }

    #[test]
    fn install_trigger_altering_another_key_rolls_back() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        assert_install_trigger_rolls_back(
            "CREATE TRIGGER change_other AFTER INSERT ON origin_keys
             BEGIN UPDATE origin_keys SET activation_hour=1 WHERE key_id!=NEW.key_id; END;",
            false,
        )
    }

    #[test]
    fn install_trigger_altering_target_rolls_back() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        assert_install_trigger_rolls_back(
            "CREATE TRIGGER change_target AFTER INSERT ON origin_keys
             BEGIN UPDATE origin_keys SET activation_hour=NEW.activation_hour+1
                   WHERE key_id=NEW.key_id; END;",
            false,
        )
    }

    #[test]
    fn ignored_install_high_water_update_rolls_back() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        assert_install_trigger_rolls_back(
            "CREATE TRIGGER ignore_clock BEFORE UPDATE OF high_water ON metadata
             BEGIN SELECT RAISE(IGNORE); END;",
            false,
        )
    }

    #[test]
    fn install_and_reschedule_replay_rewrite_schema_is_refused() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        for (event, reschedule) in [("INSERT", false), ("UPDATE", true)] {
            assert_install_trigger_rolls_back(
                &format!(
                    "CREATE TRIGGER rewrite_replay AFTER {event} ON origin_keys
                     BEGIN UPDATE spent SET nonce=zeroblob(32); END;"
                ),
                reschedule,
            )?;
        }
        Ok(())
    }

    fn assert_retire_refused(
        db: &Path,
        secret: &Path,
        key_id: [u8; 32],
        now: u64,
        expected_error: &str,
    ) -> Result<()> {
        // Open the store first to pin the names so that the snapshots include them.
        drop(Origin::open(db, secret, "issuer", "origin")?);
        let before = Origin::status(db, now)?;
        let metadata = read_metadata(&raw(db)?)?;
        let challenges = challenge_rows(db)?;
        let spent = spent_rows(db)?;
        let error = Origin::retire_key(db, key_id, now).unwrap_err();
        assert!(error.to_string().contains(expected_error), "{error:#}");
        let unchanged = || -> Result<()> {
            assert_eq!(Origin::status(db, now)?, before);
            assert_eq!(read_metadata(&raw(db)?)?, metadata);
            assert_eq!(challenge_rows(db)?, challenges);
            assert_eq!(spent_rows(db)?, spent);
            Ok(())
        };
        unchanged()?;
        drop(Origin::open(db, secret, "issuer", "origin")?);
        unchanged()
    }

    #[test]
    fn retirement_boundary_deletes_only_target_and_reopens() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (k1, p1) = signer()?;
        let (k2, p2) = signer()?;
        let (db, secret) = fresh(dir.path(), &p1, Some(&p2))?;
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        let error = Origin::retire_key(&db, p1.key_id(), S + 420).unwrap_err();
        assert!(error.to_string().contains("already owned"), "{error:#}");

        origin.request_at(None, S - 1)?;
        let old_digest = origin.challenge(S - 1)?.0.digest();
        let old_spent = token(&k1, &p1, old_digest, 1)?;
        let old_unspent = token(&k1, &p1, old_digest, 2)?;
        assert!(origin.request_at(Some(&old_spent), S - 1)?.is_none());
        origin.request_at(None, S)?;
        let next_digest = origin.challenge(S)?.0.digest();
        let next_spent = token(&k2, &p2, next_digest, 3)?;
        let next_unspent = token(&k2, &p2, next_digest, 4)?;
        assert!(origin.request_at(Some(&next_spent), S)?.is_none());
        drop(origin);

        assert_retire_refused(
            &db,
            &secret,
            p1.key_id(),
            S + 419,
            "safety margin has not elapsed",
        )?;
        let now = S + 420;
        let mut expected = Origin::status(&db, now)?;
        let next_challenges: Vec<_> = challenge_rows(&db)?
            .into_iter()
            .filter(|row| row.0 == p2.key_id())
            .collect();
        let next_rows: Vec<_> = spent_rows(&db)?
            .into_iter()
            .filter(|row| row.0 == p2.key_id())
            .collect();
        assert_eq!(next_challenges.len(), 1);
        assert_eq!(next_rows.len(), 1);
        Origin::retire_key(&db, p1.key_id(), now)?;
        expected.high_water = now;
        expected.keys[0].state = OriginKeyState::Retired;
        assert_eq!(Origin::status(&db, now)?, expected);
        assert_eq!(challenge_rows(&db)?, next_challenges);
        assert_eq!(spent_rows(&db)?, next_rows);

        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        assert_eq!(origin.keys.len(), 1);
        assert_eq!(origin.keys[0].key_id, p2.key_id());
        assert!(origin.request_at(Some(&old_unspent), now)?.is_some());
        assert!(origin.request_at(Some(&next_spent), now)?.is_some());
        assert!(origin.request_at(Some(&next_unspent), now)?.is_none());
        drop(origin);
        assert_eq!(Origin::status(&db, now)?, expected);
        let error = install(&db, &p1, S + HOUR, now).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("retired origin key cannot be reinstalled"),
            "{error:#}"
        );
        assert_eq!(Origin::status(&db, now)?, expected);
        Ok(())
    }

    #[test]
    fn retire_key_refusal_table() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_, p1) = signer()?;
        let (_, p2) = signer()?;
        let solo = tempfile::tempdir()?;
        let (db, secret) = fresh(solo.path(), &p1, None)?;
        assert_retire_refused(&db, &secret, [0; 32], S + 420, "unknown origin key")?;
        assert_retire_refused(&db, &secret, p1.key_id(), S + 420, "no active successor")?;

        let dir = tempfile::tempdir()?;
        let (db, secret) = fresh(dir.path(), &p1, Some(&p2))?;
        plant_retirement_rows(&db, &p1, &p2)?;
        assert_retire_refused(&db, &secret, p1.key_id(), S - 1, "no active successor")?;
        assert_retire_refused(&db, &secret, p2.key_id(), S + 420, "no active successor")?;
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        origin.request_at(None, S + 421)?;
        drop(origin);
        assert_retire_refused(&db, &secret, p1.key_id(), S + 420, "clock regression")?;
        Origin::retire_key(&db, p1.key_id(), S + 421)?;
        assert_retire_refused(&db, &secret, p1.key_id(), S + 422, "already retired")?;
        Ok(())
    }

    #[test]
    fn retirement_refuses_invariant_seven_corruption_without_erasing_it() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (_, p1) = signer()?;
        let (_, p2) = signer()?;
        let (db, secret) = fresh(dir.path(), &p1, Some(&p2))?;
        plant_retirement_rows(&db, &p1, &p2)?;
        plant(&db, &p1.key_id(), [3; 32], (S + GRACE + 1) as i64)?;
        let metadata = read_metadata(&raw(&db)?)?;
        let challenges = challenge_rows(&db)?;
        let spent = spent_rows(&db)?;
        let error = Origin::retire_key(&db, p1.key_id(), S + 420).unwrap_err();
        assert!(
            error.to_string().contains("outlives successor grace"),
            "{error:#}"
        );
        assert_eq!(read_metadata(&raw(&db)?)?, metadata);
        assert_eq!(challenge_rows(&db)?, challenges);
        assert_eq!(spent_rows(&db)?, spent);
        assert_eq!(
            raw(&db)?.query_row(
                "SELECT retired FROM origin_keys WHERE key_id=?1",
                [p1.key_id().as_slice()],
                |r| r.get::<_, i64>(0),
            )?,
            0
        );
        refused(&db, &secret)?;
        assert_eq!(challenge_rows(&db)?, challenges);
        Ok(())
    }

    fn assert_retire_trigger_rolls_back(trigger: &str) -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (_, p1) = signer()?;
        let (_, p2) = signer()?;
        let (db, secret) = fresh(dir.path(), &p1, Some(&p2))?;
        plant_retirement_rows(&db, &p1, &p2)?;
        drop(Origin::open(&db, &secret, "issuer", "origin")?);
        let before = store_snapshot(&db)?;
        raw(&db)?.execute_batch(trigger)?;
        let error = Origin::retire_key(&db, p1.key_id(), S + 420).unwrap_err();
        assert!(
            error.to_string().contains("unexpected schema objects"),
            "{error:#}"
        );
        assert_eq!(store_snapshot(&db)?, before);
        remove_test_schema_objects(&db)?;
        drop(Origin::open(&db, &secret, "issuer", "origin")?);
        assert_eq!(store_snapshot(&db)?, before);
        Ok(())
    }

    #[test]
    fn ignored_retirement_update_rolls_back() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        assert_retire_trigger_rolls_back(
            "CREATE TRIGGER ignore_retire BEFORE UPDATE OF retired ON origin_keys
             BEGIN SELECT RAISE(IGNORE); END;",
        )
    }

    #[test]
    fn retirement_trigger_deleting_successor_spent_rows_rolls_back() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        assert_retire_trigger_rolls_back(
            "CREATE TRIGGER delete_other_spent AFTER DELETE ON spent
             BEGIN DELETE FROM spent WHERE key_id!=OLD.key_id; END;",
        )
    }

    #[test]
    fn retirement_postcondition_trigger_regressions() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        for trigger in [
            "CREATE TRIGGER undo_retire AFTER UPDATE OF retired ON origin_keys
                 WHEN NEW.retired=1 BEGIN
                   UPDATE origin_keys SET retired=0 WHERE key_id=NEW.key_id; END;",
            "CREATE TRIGGER change_target AFTER UPDATE OF retired ON origin_keys
                 BEGIN UPDATE origin_keys SET activation_hour=1 WHERE key_id=NEW.key_id; END;",
            "CREATE TRIGGER change_other AFTER UPDATE OF retired ON origin_keys
                 BEGIN UPDATE origin_keys SET activation_hour=activation_hour-1
                       WHERE key_id!=NEW.key_id; END;",
            "CREATE TRIGGER delete_other_challenges AFTER DELETE ON challenges
                 BEGIN DELETE FROM challenges WHERE key_id!=OLD.key_id; END;",
            "CREATE TRIGGER ignore_clock BEFORE UPDATE OF high_water ON metadata
                 BEGIN SELECT RAISE(IGNORE); END;",
        ] {
            assert_retire_trigger_rolls_back(trigger)?;
        }
        Ok(())
    }

    #[test]
    fn unexpected_schema_objects_refuse_open_and_live_requests() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_, key) = signer()?;
        for object in [
            "CREATE TRIGGER ignore_spent BEFORE INSERT ON spent
             BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE VIEW extra AS SELECT * FROM spent;",
        ] {
            let dir = tempfile::tempdir()?;
            let (db, secret) = fresh(dir.path(), &key, None)?;
            let origin = Origin::open(&db, &secret, "issuer", "origin")?;
            origin.request_at(None, S)?;
            let before = store_snapshot(&db)?;
            origin.db.lock().unwrap().execute_batch(object)?;
            let error = origin.request_at(None, S + 1).unwrap_err();
            assert!(
                error.to_string().contains("unexpected schema objects"),
                "{error:#}"
            );
            assert_eq!(store_snapshot(&db)?, before);
            drop(origin);
            let error = Origin::open(&db, &secret, "issuer", "origin")
                .err()
                .context("unexpected schema object accepted at open")?;
            assert!(
                error.to_string().contains("unexpected schema objects"),
                "{error:#}"
            );
            assert_eq!(store_snapshot(&db)?, before);
            remove_test_schema_objects(&db)?;
            drop(Origin::open(&db, &secret, "issuer", "origin")?);
            assert_eq!(store_snapshot(&db)?, before);
        }
        Ok(())
    }

    #[test]
    fn count_preserving_retirement_trigger_cannot_enable_successor_replay() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (_, old) = signer()?;
        let (signer, next) = signer()?;
        let (db, secret) = fresh(dir.path(), &old, Some(&next))?;
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        origin.request_at(None, S - 1)?;
        origin.request_at(None, S)?;
        let spent = token(&signer, &next, origin.challenge(S)?.0.digest(), 7)?;
        assert!(origin.request_at(Some(&spent), S)?.is_none());
        drop(origin);
        let before = store_snapshot(&db)?;
        raw(&db)?.execute_batch(
            "CREATE TRIGGER rewrite_successor_nonce AFTER UPDATE OF retired ON origin_keys
             BEGIN UPDATE spent SET nonce=zeroblob(32) WHERE key_id<>NEW.key_id; END;",
        )?;
        let error = Origin::retire_key(&db, old.key_id(), S + 420).unwrap_err();
        assert!(
            error.to_string().contains("unexpected schema objects"),
            "{error:#}"
        );
        assert_eq!(store_snapshot(&db)?, before);
        remove_test_schema_objects(&db)?;
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        assert_eq!(store_snapshot(&db)?, before);
        // A returned challenge marks a rejected redemption and leads to HTTP 401.
        assert!(origin.request_at(Some(&spent), S + 420)?.is_some());
        assert_eq!(
            challenge_rows(&db)?,
            before
                .replay
                .challenges
                .into_iter()
                .filter(|row| row.0 == next.key_id())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            spent_rows(&db)?,
            before
                .replay
                .spent
                .into_iter()
                .filter(|row| row.0 == next.key_id())
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn retirement_replay_digest_detects_count_preserving_edits() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (_, old) = signer()?;
        let (_, next) = signer()?;
        let (db, _) = fresh(dir.path(), &old, Some(&next))?;
        plant_retirement_rows(&db, &old, &next)?;
        let mut conn = raw(&db)?;
        let before = replay_digest(&conn, Some(old.key_id()))?;
        let counts = key_row_counts(&conn, next.key_id())?;
        for sql in [
            "UPDATE spent SET nonce=zeroblob(32) WHERE key_id!=?1",
            "UPDATE spent SET digest=zeroblob(32) WHERE key_id!=?1",
            "UPDATE spent SET deadline=deadline+1 WHERE key_id!=?1",
            "UPDATE challenges SET digest=zeroblob(32) WHERE key_id!=?1",
            "UPDATE challenges SET deadline=deadline+1 WHERE key_id!=?1",
        ] {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(sql, [old.key_id().as_slice()])?;
            assert_eq!(key_row_counts(&tx, next.key_id())?, counts);
            let error = ensure_replay_digest(&tx, Some(old.key_id()), &before).unwrap_err();
            assert!(
                error.to_string().contains("changed protected replay rows"),
                "{error:#}"
            );
            tx.rollback()?;
            ensure_replay_digest(&conn, Some(old.key_id()), &before)?;
        }
        Ok(())
    }

    #[test]
    fn pruning_margin_replay_and_clock_floor_survive_restart() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (signer, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &key, None)?;
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        let issued = HOUR + 1;
        origin.request_at(None, issued)?;
        let (challenge, deadline) = origin.challenge(issued)?;
        let spent = token(&signer, &key, challenge.digest(), 1)?;
        let unspent = token(&signer, &key, challenge.digest(), 2)?;
        assert!(origin.request_at(Some(&spent), issued)?.is_none());
        for now in [deadline, deadline + RETIRE_MARGIN - 1] {
            assert!(origin.request_at(Some(&spent), now)?.is_some());
            assert!(origin.request_at(Some(&unspent), now)?.is_some());
            assert!(challenge_rows(&db)?
                .iter()
                .any(|r| r.1 == challenge.digest()));
            assert_eq!(spent_rows(&db)?.len(), 1);
        }
        let now = deadline + RETIRE_MARGIN;
        assert!(origin.request_at(Some(&spent), now)?.is_some());
        assert!(!challenge_rows(&db)?
            .iter()
            .any(|r| r.1 == challenge.digest()));
        assert!(spent_rows(&db)?.is_empty());
        let before = store_snapshot(&db)?;
        assert!(origin.request_at(Some(&unspent), now)?.is_some());
        assert!(origin.request_at(None, now - 1).is_err());
        assert_eq!(store_snapshot(&db)?, before);
        drop(origin);
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        assert!(origin.request_at(None, now - 1).is_err());
        assert!(origin.request_at(Some(&spent), now)?.is_some());
        assert!(origin.request_at(Some(&unspent), now)?.is_some());
        assert_eq!(store_snapshot(&db)?, before);
        assert!(origin.request_at(None, u64::MAX).is_err());
        assert_eq!(store_snapshot(&db)?, before);
        Ok(())
    }

    #[test]
    fn many_hours_prune_without_retiring_the_key() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (_, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &key, None)?;
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        for hour in 0..=48 {
            let now = hour * HOUR + 1;
            origin.request_at(None, now)?;
            let (challenge, deadline) = origin.challenge(now)?;
            plant_spend(
                &raw(&db)?,
                key.key_id(),
                challenge.digest(),
                [1; 32],
                deadline as i64,
            )?;
            assert!(challenge_rows(&db)?.len() <= 2);
            assert!(spent_rows(&db)?.len() <= 2);
        }
        origin.request_at(None, 48 * HOUR + GRACE + RETIRE_MARGIN)?;
        assert_eq!(challenge_rows(&db)?.len(), 1);
        assert_eq!(spent_rows(&db)?.len(), 1);
        drop(origin);
        assert_eq!(
            states(&Origin::status(&db, 48 * HOUR + 420)?),
            vec![OriginKeyState::Advertising]
        );
        Ok(())
    }

    fn numbered(value: u64) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    fn expired_counts(db: &Connection, cutoff: i64) -> Result<(i64, i64)> {
        Ok(db.query_row(
            "SELECT (SELECT count(*) FROM challenges WHERE deadline<=?1),
                    (SELECT count(*) FROM spent WHERE deadline<=?1)",
            [cutoff],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    #[test]
    fn pruning_batches_preserve_unselected_parents_and_drain_orphans() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (signer, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &key, None)?;
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        let mut conn = raw(&db)?;
        let deadline = (HOUR + GRACE) as i64;
        let tx = conn.transaction()?;
        for i in 0..600 {
            tx.execute(
                "INSERT INTO challenges VALUES(?1,?2,?3)",
                params![key.key_id().as_slice(), numbered(i).as_slice(), deadline],
            )?;
            plant_spend(&tx, key.key_id(), numbered(i), numbered(0), deadline)?;
        }
        for i in 1..=300 {
            plant_spend(&tx, key.key_id(), numbered(0), numbered(i), deadline)?;
        }
        let spent = token(&signer, &key, numbered(0), 250)?;
        let unspent = token(&signer, &key, numbered(0), 251)?;
        plant_spend(&tx, key.key_id(), numbered(0), spent.nonce, deadline)?;
        tx.commit()?;
        let now = deadline as u64 + RETIRE_MARGIN;
        origin.request_at(None, now)?;
        assert_eq!(
            expired_counts(&conn, deadline)?,
            (600 - PRUNE_BATCH, 901 - PRUNE_BATCH)
        );
        let parent_and_spend: (bool, bool) = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM challenges WHERE digest=?1),
                    EXISTS(SELECT 1 FROM spent WHERE digest=?1)",
            [numbered(PRUNE_BATCH as u64).as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        assert_eq!(parent_and_spend, (true, true));
        assert!(!challenge_rows(&db)?.iter().any(|r| r.1 == numbered(0)));
        assert!(spent_rows(&db)?.iter().any(|r| r.2 == spent.nonce));
        // Once the challenge row is deleted, neither token can be redeemed
        // even if a spend row remains.
        assert!(origin.request_at(Some(&spent), now)?.is_some());
        assert!(origin.request_at(Some(&unspent), now)?.is_some());
        for _ in 0..5 {
            let before = expired_counts(&conn, deadline)?;
            origin.request_at(None, now)?;
            let after = expired_counts(&conn, deadline)?;
            assert!((0..=PRUNE_BATCH).contains(&(before.0 - after.0)));
            assert!((0..=PRUNE_BATCH).contains(&(before.1 - after.1)));
        }
        assert_eq!(expired_counts(&conn, deadline)?, (0, 0));
        assert_eq!(challenge_rows(&db)?.len(), 1);
        Ok(())
    }

    #[test]
    fn pruning_cutoff_is_checked_and_does_not_overflow_in_sql() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let db = Connection::open_in_memory()?;
        db.execute_batch(SCHEMA_V2)?;
        db.execute("INSERT INTO origin_keys VALUES(zeroblob(32),x'00',0,0)", [])?;
        for (digest, deadline) in [(numbered(0), 0), (numbered(1), i64::MAX)] {
            db.execute(
                "INSERT INTO challenges VALUES(zeroblob(32),?1,?2)",
                params![digest.as_slice(), deadline],
            )?;
        }
        prune_replay(&db, 119)?;
        assert_eq!(key_row_counts(&db, [0; 32])?, (2, 0));
        prune_replay(&db, 120)?;
        assert_eq!(key_row_counts(&db, [0; 32])?, (1, 0));
        prune_replay(&db, i64::MAX)?;
        assert_eq!(key_row_counts(&db, [0; 32])?, (1, 0));
        Ok(())
    }

    fn quoted_replay(db: &Connection) -> Result<(Option<String>, Option<String>)> {
        Ok((
            db.query_row(
                "SELECT group_concat(quote(key_id)||quote(digest)||quote(deadline),'|')
                 FROM (SELECT * FROM challenges ORDER BY key_id,digest)", [], |r| r.get(0),
            )?,
            db.query_row(
                "SELECT group_concat(quote(key_id)||quote(digest)||quote(nonce)||quote(deadline),'|')
                 FROM (SELECT * FROM spent ORDER BY key_id,digest,nonce)", [], |r| r.get(0),
            )?,
        ))
    }

    #[test]
    fn expired_corruption_is_refused_before_pruning_can_hide_it() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_, old) = signer()?;
        let (_, next) = signer()?;
        for statements in [
            vec![
                "UPDATE challenges SET deadline=deadline+1 WHERE key_id=?1",
                "UPDATE spent SET deadline=deadline+1 WHERE key_id=?1",
            ],
            vec!["UPDATE spent SET deadline=deadline-1 WHERE key_id=?1"],
            vec!["UPDATE challenges SET digest=zeroblob(31) WHERE key_id=?1"],
            vec!["UPDATE spent SET digest=zeroblob(31) WHERE key_id=?1"],
            vec!["UPDATE spent SET nonce=zeroblob(31) WHERE key_id=?1"],
            vec!["UPDATE challenges SET key_id=zeroblob(31) WHERE key_id=?1"],
            vec!["UPDATE spent SET key_id=zeroblob(31) WHERE key_id=?1"],
            vec!["UPDATE challenges SET digest='not a blob' WHERE key_id=?1"],
            vec!["UPDATE spent SET nonce='not a blob' WHERE key_id=?1"],
            vec!["UPDATE challenges SET deadline='bad' WHERE key_id=?1"],
            vec!["UPDATE spent SET deadline=3900.5 WHERE key_id=?1"],
            vec!["UPDATE challenges SET key_id=zeroblob(32) WHERE key_id=?1"],
            vec!["UPDATE origin_keys SET retired=1 WHERE key_id=?1"],
            vec![
                "UPDATE challenges SET deadline=1 WHERE key_id=?1",
                "UPDATE spent SET deadline=1 WHERE key_id=?1",
            ],
        ] {
            let dir = tempfile::tempdir()?;
            let (db, secret) = fresh(dir.path(), &old, Some(&next))?;
            plant_retirement_rows(&db, &old, &next)?;
            let origin = Origin::open(&db, &secret, "issuer", "origin")?;
            let conn = raw(&db)?;
            for sql in statements {
                conn.execute(sql, [old.key_id().as_slice()])?;
            }
            let metadata = read_metadata(&conn)?;
            let rows = quoted_replay(&conn)?;
            // The request time makes replay rows with a deadline of `S + GRACE + 1`
            // old enough to prune, but the invalid deadline must block the request.
            assert!(origin.request_at(None, S + HOUR + 1000).is_err());
            assert_eq!(read_metadata(&conn)?, metadata);
            assert_eq!(quoted_replay(&conn)?, rows);
            drop(origin);
            refused(&db, &secret)?;
            assert_eq!(quoted_replay(&conn)?, rows);
        }
        Ok(())
    }

    #[test]
    fn pruned_empty_target_still_requires_retirement_margin_and_tombstone() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (_, old) = signer()?;
        let (_, next) = signer()?;
        let (db, secret) = fresh(dir.path(), &old, Some(&next))?;
        plant(&db, &old.key_id(), [1; 32], (S - HOUR + GRACE) as i64)?;
        plant_spend(
            &raw(&db)?,
            old.key_id(),
            [1; 32],
            [2; 32],
            (S - HOUR + GRACE) as i64,
        )?;
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        origin.request_at(None, S + 419)?;
        assert_eq!(key_row_counts(&raw(&db)?, old.key_id())?, (0, 0));
        drop(origin);
        assert_retire_refused(
            &db,
            &secret,
            old.key_id(),
            S + 419,
            "safety margin has not elapsed",
        )?;
        let next_rows = replay_digest(&raw(&db)?, Some(old.key_id()))?;
        Origin::retire_key(&db, old.key_id(), S + 420)?;
        ensure_replay_digest(&raw(&db)?, Some(old.key_id()), &next_rows)?;
        assert_eq!(
            Origin::status(&db, S + 420)?.keys[0].state,
            OriginKeyState::Retired
        );
        assert!(install(&db, &old, S + HOUR, S + 420).is_err());
        drop(Origin::open(&db, &secret, "issuer", "origin")?);
        assert_eq!(
            Origin::status(&db, S + 420)?.keys[0].state,
            OriginKeyState::Retired
        );
        Ok(())
    }

    #[tokio::test]
    async fn failure_after_pruning_rolls_back_and_never_returns_200() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let dir = tempfile::tempdir()?;
        let (signer, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &key, None)?;
        let origin = Arc::new(Origin::open(&db, &secret, "issuer", "origin")?);
        origin.request_at(None, HOUR + 1)?;
        let redeem = token(&signer, &key, origin.challenge(HOUR + 1)?.0.digest(), 1)?;
        let old_deadline = (HOUR + GRACE) as i64;
        plant(&db, &key.key_id(), [0; 32], old_deadline)?;
        plant_spend(&raw(&db)?, key.key_id(), [0; 32], [2; 32], old_deadline)?;
        let before = store_snapshot(&db)?;
        let now = HOUR + GRACE + RETIRE_MARGIN;
        let response = protected_with_request(
            origin.clone(),
            authorization(&redeem)?,
            move |origin, token, scope| {
                origin.request_with_prune_hook(
                    token,
                    scope,
                    || Ok(now),
                    |tx| {
                        assert_eq!(expired_counts(tx, old_deadline)?, (0, 0));
                        bail!("injected failure after deletion")
                    },
                )
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        assert_eq!(store_snapshot(&db)?, before);
        assert_eq!(
            protected_with_clock(origin.clone(), authorization(&redeem)?, move || Ok(now))
                .await
                .status(),
            StatusCode::OK
        );
        assert!(origin.request_at(Some(&redeem), now)?.is_some());
        Ok(())
    }

    #[test]
    fn replay_digest_is_deterministic_scoped_and_covers_every_column_and_row() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let mut db = Connection::open_in_memory()?;
        db.execute_batch(SCHEMA_V2)?;
        for key in [[1; 32], [2; 32]] {
            db.execute(
                "INSERT INTO challenges VALUES(?1,?2,?3)",
                params![key.as_slice(), &[3u8; 32], -1i64],
            )?;
            plant_spend(&db, key, [3; 32], [4; 32], i64::MAX)?;
        }
        let before = replay_digest(&db, None)?;
        assert_eq!((before.challenges, before.spent), (2, 2));
        assert_eq!(replay_digest(&db, None)?, before);
        let excluded = replay_digest(&db, Some([1; 32]))?;
        assert_eq!((excluded.challenges, excluded.spent), (1, 1));
        assert_ne!(excluded.sha256, before.sha256);
        // An exclusion changes the hash input even if it excludes no rows.
        assert_ne!(replay_digest(&db, Some([9; 32]))?.sha256, before.sha256);
        for sql in [
            "UPDATE challenges SET key_id=zeroblob(32) WHERE key_id=?1",
            "UPDATE challenges SET digest=zeroblob(32) WHERE key_id=?1",
            "UPDATE challenges SET deadline=deadline+1 WHERE key_id=?1",
            "UPDATE spent SET key_id=zeroblob(32) WHERE key_id=?1",
            "UPDATE spent SET digest=zeroblob(32) WHERE key_id=?1",
            "UPDATE spent SET nonce=zeroblob(32) WHERE key_id=?1",
            "UPDATE spent SET deadline=deadline-1 WHERE key_id=?1",
            "INSERT INTO challenges VALUES(?1,zeroblob(32),1)",
            "DELETE FROM challenges WHERE key_id=?1",
            "INSERT INTO spent VALUES(?1,zeroblob(32),zeroblob(32),1)",
            "DELETE FROM spent WHERE key_id=?1",
        ] {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(sql, [[1u8; 32].as_slice()])?;
            assert_ne!(replay_digest(&tx, None)?.sha256, before.sha256, "{sql}");
            assert!(ensure_replay_digest(&tx, None, &before).is_err(), "{sql}");
            tx.rollback()?;
            ensure_replay_digest(&db, None, &before)?;
        }
        // Inserting the rows in reverse order leaves the digest unchanged.
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM challenges", [])?;
        tx.execute("DELETE FROM spent", [])?;
        for key in [[2; 32], [1; 32]] {
            tx.execute(
                "INSERT INTO challenges VALUES(?1,?2,?3)",
                params![key.as_slice(), &[3u8; 32], -1i64],
            )?;
            plant_spend(&tx, key, [3; 32], [4; 32], i64::MAX)?;
        }
        ensure_replay_digest(&tx, None, &before)?;
        tx.rollback()?;
        for sql in [
            "UPDATE challenges SET key_id='text'",
            "UPDATE challenges SET digest=42",
            "UPDATE challenges SET deadline=x'00'",
            "UPDATE spent SET key_id=3.5",
            "UPDATE spent SET digest='text'",
            "UPDATE spent SET nonce=42",
            "UPDATE spent SET deadline='text'",
        ] {
            let tx = db.transaction()?;
            // Limit the rewrite to one row so that it cannot cause a primary key collision.
            tx.execute(&format!("{sql} WHERE key_id=?1"), [[1u8; 32].as_slice()])?;
            assert!(replay_digest(&tx, None).is_err(), "{sql}");
            tx.rollback()?;
        }
        Ok(())
    }

    #[test]
    fn install_and_reschedule_digest_postcondition_detects_replay_rewrites() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (_, genesis) = signer()?;
        let (_, next) = signer()?;
        let (db, _) = fresh(dir.path(), &genesis, None)?;
        plant(&db, &genesis.key_id(), [1; 32], (S + GRACE) as i64)?;
        plant_spend(
            &raw(&db)?,
            genesis.key_id(),
            [1; 32],
            [2; 32],
            (S + GRACE) as i64,
        )?;
        let mut conn = raw(&db)?;
        for reschedule in [false, true] {
            if reschedule {
                install(&db, &next, S, S - HOUR)?;
            }
            let before = store_snapshot(&db)?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let replay_before = replay_digest(&tx, None)?;
            if reschedule {
                tx.execute(
                    "UPDATE origin_keys SET activation_hour=?1 WHERE key_id=?2",
                    params![(H + 1) as i64, next.key_id().as_slice()],
                )?;
            } else {
                tx.execute(
                    "INSERT INTO origin_keys VALUES(?1,?2,?3,0)",
                    params![next.key_id().as_slice(), next.to_spki(), H as i64],
                )?;
            }
            let high = read_metadata(&tx)?.1;
            advance_high_water(&tx, (S - HOUR + 1) as i64, high)?;
            // Update the nonce directly so that the digest check can detect
            // the change in a schema that passes validation.
            tx.execute("UPDATE spent SET nonce=zeroblob(32)", [])?;
            read_keys(&tx)?;
            assert_eq!(replay_digest(&tx, None)?.spent, replay_before.spent);
            assert!(ensure_replay_digest(&tx, None, &replay_before).is_err());
            tx.rollback()?;
            assert_eq!(store_snapshot(&db)?, before);
        }
        Ok(())
    }

    #[tokio::test]
    async fn saturation_and_worker_errors_fail_closed_without_mutation() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let dir = tempfile::tempdir()?;
        let (_, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &key, None)?;
        let origin = Arc::new(Origin::open(&db, &secret, "issuer", "origin")?);
        let before = store_snapshot(&db)?;
        let permits = origin
            .workers
            .clone()
            .acquire_many_owned(ORIGIN_CAPACITY as u32)
            .await?;
        let response = protected_with_clock(origin.clone(), HeaderMap::new(), || {
            panic!("saturated request must not sample the clock")
        })
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        assert_eq!(store_snapshot(&db)?, before);
        drop(permits);
        assert_eq!(
            protected_with_clock(origin.clone(), HeaderMap::new(), || Ok(HOUR + 1))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let before = store_snapshot(&db)?;
        assert_eq!(
            protected_with_clock(origin.clone(), HeaderMap::new(), || bail!(
                "clock unavailable"
            ))
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(store_snapshot(&db)?, before);
        assert_eq!(
            protected_with_clock(origin.clone(), HeaderMap::new(), || panic!(
                "injected worker panic"
            ))
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(origin.workers.available_permits(), ORIGIN_CAPACITY);
        assert_eq!(store_snapshot(&db)?, before);
        origin.workers.close();
        let response = protected(State(origin), HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        assert_eq!(store_snapshot(&db)?, before);
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_http_keeps_worker_permit_until_commit_and_burns_token() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let dir = tempfile::tempdir()?;
        let (signer, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &key, None)?;
        let origin = Arc::new(Origin::open(&db, &secret, "issuer", "origin")?);
        origin.request_now(None, None)?;
        let now = read_metadata(&read_only(&db)?)?.1;
        let redeem = token(&signer, &key, origin.challenge(now)?.0.digest(), 1)?;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let job = tokio::spawn(protected_with_clock(
            origin.clone(),
            authorization(&redeem)?,
            move || {
                entered_tx
                    .send(())
                    .map_err(|_| anyhow::anyhow!("test cancelled"))?;
                release_rx.recv()?;
                Ok(now)
            },
        ));
        entered_rx.await?;
        assert_eq!(origin.workers.available_permits(), ORIGIN_CAPACITY - 1);
        let other = origin.workers.clone().acquire_owned().await?;
        job.abort();
        assert!(job.await.unwrap_err().is_cancelled());
        assert_eq!(origin.workers.available_permits(), 0);
        assert_eq!(
            protected(State(origin.clone()), HeaderMap::new())
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        release_tx.send(())?;
        // Wait for the job's permit so that the transaction has committed before
        // checking the replay rows. Cancelling the HTTP future does not release the permit.
        let completed = origin.workers.clone().acquire_owned().await?;
        assert_eq!(spent_rows(&db)?.len(), 1);
        assert!(read_metadata(&read_only(&db)?)?.1 >= now);
        drop(completed);
        drop(other);
        assert_eq!(
            protected(State(origin.clone()), authorization(&redeem)?)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(spent_rows(&db)?.len(), 1);
        Ok(())
    }

    #[test]
    fn queued_request_samples_clock_only_under_connection_lock() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

        let dir = tempfile::tempdir()?;
        let (_, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &key, None)?;
        let origin = Arc::new(Origin::open(&db, &secret, "issuer", "origin")?);
        let clock = Arc::new(AtomicU64::new(HOUR + 1));
        let sampled = Arc::new(AtomicBool::new(false));
        let guard = origin.db.lock().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let queued = origin.clone();
        let queued_clock = clock.clone();
        let queued_sampled = sampled.clone();
        let job = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            queued.request_with_clock(None, || {
                assert!(queued.db.try_lock().is_err());
                queued_sampled.store(true, Ordering::SeqCst);
                Ok(queued_clock.load(Ordering::SeqCst))
            })
        });
        started_rx.recv()?;
        assert!(!sampled.load(Ordering::SeqCst));
        clock.store(2 * HOUR + 1, Ordering::SeqCst);
        drop(guard);
        assert!(job.join().unwrap()?.is_some());
        assert_eq!(read_metadata(&read_only(&db)?)?.1, 2 * HOUR + 1);
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_http_redemption_has_at_most_one_success() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let dir = tempfile::tempdir()?;
        let (signer, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &key, None)?;
        let origin = Arc::new(Origin::open(&db, &secret, "issuer", "origin")?);
        let now = HOUR + 1;
        origin.request_at(None, now)?;
        let redeem = token(&signer, &key, origin.challenge(now)?.0.digest(), 1)?;
        let mut jobs = Vec::new();
        for _ in 0..8 {
            jobs.push(tokio::spawn(protected_with_clock(
                origin.clone(),
                authorization(&redeem)?,
                move || Ok(now),
            )));
        }
        let mut successes = 0;
        for job in jobs {
            let status = job.await?.status();
            successes += usize::from(status == StatusCode::OK);
            assert!([
                StatusCode::OK,
                StatusCode::UNAUTHORIZED,
                StatusCode::TOO_MANY_REQUESTS
            ]
            .contains(&status));
        }
        assert_eq!(successes, 1);
        assert_eq!(spent_rows(&db)?.len(), 1);
        Ok(())
    }

    #[test]
    fn status_states_lock_and_clock() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (db, secret) = paths(dir.path());
        let (_, p1) = signer()?;
        let (_, p2) = signer()?;
        Origin::initialize(&db, &secret, p1.to_spki(), p1.key_id())?;
        install(&db, &p2, S, S - HOUR)?;

        let before = Origin::status(&db, S - HOUR)?;
        assert_eq!(before.now, S - HOUR);
        assert_eq!(before.high_water, S - HOUR);
        assert_eq!(
            states(&before),
            vec![OriginKeyState::Advertising, OriginKeyState::Installed]
        );
        assert_eq!(before.keys[0].activation_hour, 0);
        assert_eq!(before.keys[0].issuance_end, Some(S));
        assert_eq!(before.keys[0].acceptance_deadline, Some(S + GRACE));
        assert_eq!(before.keys[1].issuance_end, None);
        assert_eq!(before.keys[1].acceptance_deadline, None);

        let after = Origin::status(&db, S)?;
        assert_eq!(
            states(&after),
            vec![OriginKeyState::Verifying, OriginKeyState::Advertising]
        );
        assert_eq!(after.keys[0].acceptance_deadline, Some(S + GRACE));

        // The serving process holds the ownership lock, so `status` fails.
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        assert!(Origin::status(&db, S).is_err());
        drop(origin);
        Ok(())
    }

    #[test]
    fn scoped_token_redeems_once_only_at_its_own_scope() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (signer, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &key, None)?;
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        let now = HOUR + 1;
        let ballot_one: &[u8] = b"ballot:1";
        origin.request_scoped_at(None, Some(ballot_one), now)?;
        let (scoped, _) = origin.challenge_scoped(now, Some(ballot_one))?;
        let scoped_token = token(&signer, &key, scoped.digest(), 1)?;
        origin.request_at(None, now)?;
        let (unscoped, _) = origin.challenge(now)?;
        let unscoped_token = token(&signer, &key, unscoped.digest(), 2)?;

        // The Origin rejects the token and leaves it unspent if the request
        // has a different scope or no scope.
        assert!(origin
            .request_scoped_at(Some(&scoped_token), Some(b"ballot:2"), now)?
            .is_some());
        assert!(origin.request_at(Some(&scoped_token), now)?.is_some());
        // The Origin spends the token on the first request with the matching scope.
        assert!(origin
            .request_scoped_at(Some(&scoped_token), Some(ballot_one), now)?
            .is_none());
        assert!(origin
            .request_scoped_at(Some(&scoped_token), Some(ballot_one), now)?
            .is_some());

        // The Origin rejects an unscoped token on scoped requests and accepts
        // it once on an unscoped request.
        assert!(origin
            .request_scoped_at(Some(&unscoped_token), Some(ballot_one), now)?
            .is_some());
        assert!(origin.request_at(Some(&unscoped_token), now)?.is_none());
        assert!(origin.request_at(Some(&unscoped_token), now)?.is_some());
        Ok(())
    }

    #[test]
    fn unscoped_context_is_v1_and_scoped_context_is_separate_v2() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir()?;
        let (_, key) = signer()?;
        let (db, secret) = fresh(dir.path(), &key, None)?;
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        let raw: [u8; 32] = std::fs::read(&secret)?.try_into().expect("32-byte secret");
        let hour = (HOUR + 1) / HOUR;
        let mut v1 = Hmac::<Sha256>::new_from_slice(&raw)?;
        v1.update(b"freebird-pp-context-v1");
        v1.update(&hour.to_be_bytes());
        let expected_v1 =
            TokenChallenge::new("issuer", &v1.finalize().into_bytes(), "origin")?.digest();
        assert_eq!(origin.challenge(HOUR + 1)?.0.digest(), expected_v1);

        let scope = b"ballot:1";
        let mut v2 = Hmac::<Sha256>::new_from_slice(&raw)?;
        v2.update(b"freebird-pp-context-v2");
        v2.update(&hour.to_be_bytes());
        v2.update(&[scope.len() as u8]);
        v2.update(scope);
        let expected_v2 =
            TokenChallenge::new("issuer", &v2.finalize().into_bytes(), "origin")?.digest();
        let scoped = origin.challenge_scoped(HOUR + 1, Some(scope))?.0.digest();
        assert_eq!(scoped, expected_v2);
        assert_ne!(scoped, expected_v1);
        assert_ne!(
            scoped,
            origin
                .challenge_scoped(HOUR + 1, Some(b"ballot:2"))?
                .0
                .digest()
        );
        assert!(origin.challenge_scoped(HOUR + 1, Some(b"")).is_err());
        assert!(origin
            .challenge_scoped(HOUR + 1, Some(&[b'x'; 129][..]))
            .is_err());
        Ok(())
    }

    #[test]
    fn stored_deadline_pins_the_issuance_hour() {
        for hour in [0u64, 1, 1_000_000] {
            let deadline = (hour + 1) * HOUR + GRACE;
            assert_eq!(issued_hour(deadline), Some(hour));
        }
        for planted in [0u64, 300, HOUR + GRACE - 1, HOUR + GRACE + 1, 2 * HOUR + 7] {
            assert_eq!(issued_hour(planted), None, "{planted}");
        }
        assert!(valid_scope(b"!"));
        assert!(valid_scope(&[b'~'; MAX_SCOPE]));
        for invalid in [&b""[..], b"a b", b"a\tb", b"\x7f", b"\x80", &[b'x'; 129]] {
            assert!(!valid_scope(invalid));
        }
    }

    #[tokio::test]
    async fn scope_header_rules_are_enforced_before_storage() -> Result<()> {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("origin.db");
        let secret = dir.path().join("context");
        let signer = SecretKey::generate()?;
        let key = signer.public_key()?;
        Origin::initialize(&db, &secret, key.to_spki(), key.key_id())?;
        let origin = Arc::new(Origin::open(&db, &secret, "issuer", "origin")?);
        let before = store_snapshot(&db)?;
        let scoped_header = |value: &[u8]| -> Result<HeaderMap> {
            let mut headers = HeaderMap::new();
            headers.insert(SCOPE_HEADER, HeaderValue::from_bytes(value)?);
            Ok(headers)
        };

        for value in [&b"a b"[..], b"a\tb", b"\x80", &[b'x'; 129]] {
            let response = protected(State(origin.clone()), scoped_header(value)?).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{value:?}");
            assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        }
        let mut twice = scoped_header(b"ballot:1")?;
        twice.append(SCOPE_HEADER, HeaderValue::from_static("ballot:1"));
        let response = protected(State(origin.clone()), twice).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        assert_eq!(store_snapshot(&db)?, before);

        // A 128-byte value and an empty value both result in a challenge.
        // The empty value leaves the request unscoped.
        for value in [&[b'x'; 128][..], b""] {
            let response = protected(State(origin.clone()), scoped_header(value)?).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
        }
        Ok(())
    }
}
