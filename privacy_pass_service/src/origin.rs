//! Experimental, single-instance Origin. Key activation and retirement are offline
//! (`install_key`, `retire_key`). Never restore a replay-store snapshot in place:
//! close the service and provision a fresh store AND separately generated context
//! secret before reopening.
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
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
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
/// Seconds an advertised challenge stays redeemable after the next key activates.
const GRACE: u64 = 300;
/// Additional safety margin after the superseded key's acceptance deadline.
const RETIRE_MARGIN: u64 = 120;
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
    _ownership: File,
    secret: [u8; 32],
    /// Non-retired keys, ascending by activation hour. Loaded once at open.
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
    /// Activation in whole hours (the stored form). Multiply by 3600 for seconds.
    pub activation_hour: u64,
    pub state: OriginKeyState,
    /// Seconds. Present only when a successor key exists: successor activation.
    pub issuance_end: Option<u64>,
    /// Seconds. `issuance_end + 300` when present.
    pub acceptance_deadline: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginStatus {
    /// Seconds (injected clock used to derive states).
    pub now: u64,
    /// Seconds (durable clock floor).
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

/// Read-only probe run before any write-capable pragma, so a refused store
/// (for example v1, whose WAL conversion would rewrite the file header) is untouched.
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

/// Canonical SPKI whose SHA-256 equals the operator-supplied key id.
fn checked_key(spki: &[u8], key_id: [u8; 32]) -> Result<PublicKey> {
    let key = PublicKey::from_spki(spki)?;
    ensure!(key.key_id() == key_id, "origin key id does not match SPKI");
    Ok(key)
}

/// Hour whose seconds form and grace deadline both fit in i64 storage.
fn hour_fits(hour: u64) -> bool {
    hour.checked_mul(HOUR)
        .and_then(|s| s.checked_add(GRACE))
        .and_then(|s| i64::try_from(s).ok())
        .is_some()
}

/// Returns (secret_hash, high_water, pinned names).
fn read_metadata(db: &Connection) -> Result<(Vec<u8>, u64, Option<Vec<u8>>)> {
    let (version, hash, high, names): (i64, Vec<u8>, i64, Option<Vec<u8>>) = db.query_row(
        "SELECT version,secret_hash,high_water,names FROM metadata WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    check_version(version)?;
    Ok((hash, u64::try_from(high)?, names))
}

/// Structural invariants (time-independent). Returns all keys ascending by hour.
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
    let count = |sql: &str| -> Result<i64> { Ok(db.query_row(sql, [], |r| r.get(0))?) };
    ensure!(
        count(
            "SELECT COUNT(*) FROM challenges WHERE key_id NOT IN (SELECT key_id FROM origin_keys)"
        )? == 0
            && count(
                "SELECT COUNT(*) FROM spent WHERE key_id NOT IN (SELECT key_id FROM origin_keys)"
            )? == 0,
        "corrupt Origin store: row references unknown key"
    );
    ensure!(
        count(
            "SELECT COUNT(*) FROM challenges WHERE key_id IN (SELECT key_id FROM origin_keys WHERE retired=1)"
        )? == 0
            && count(
                "SELECT COUNT(*) FROM spent WHERE key_id IN (SELECT key_id FROM origin_keys WHERE retired=1)"
            )? == 0,
        "corrupt Origin store: retired key has rows"
    );
    // Even the first challenge for a key must come from its activation hour or later.
    for key in &keys {
        let earliest = (key.hour + 1) * HOUR + GRACE;
        let min: Option<i64> = db.query_row(
            "SELECT MIN(deadline) FROM (
                SELECT deadline FROM challenges WHERE key_id=?1
                UNION ALL SELECT deadline FROM spent WHERE key_id=?1)",
            [key.key_id.as_slice()],
            |r| r.get(0),
        )?;
        if let Some(min) = min {
            ensure!(
                u64::try_from(min).is_ok_and(|m| m >= earliest),
                "corrupt Origin store: row predates key activation"
            );
        }
    }
    // Invariant 7: all superseded-key replay rows expire by successor + grace.
    for pair in keys.windows(2) {
        let (key, successor) = (&pair[0], &pair[1]);
        let limit = successor.hour * HOUR + GRACE;
        let max: Option<i64> = db.query_row(
            "SELECT MAX(deadline) FROM (
                SELECT deadline FROM challenges WHERE key_id=?1
                UNION ALL SELECT deadline FROM spent WHERE key_id=?1)",
            [key.key_id.as_slice()],
            |r| r.get(0),
        )?;
        if let Some(max) = max {
            ensure!(
                u64::try_from(max).is_ok_and(|m| m <= limit),
                "corrupt Origin store: superseded key replay row outlives successor grace"
            );
        }
    }
    Ok(keys)
}

fn key_row_counts(db: &Connection, key_id: [u8; 32]) -> Result<(i64, i64)> {
    Ok(db.query_row(
        "SELECT (SELECT COUNT(*) FROM challenges WHERE key_id=?1),
                (SELECT COUNT(*) FROM spent WHERE key_id=?1)",
        [key_id.as_slice()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}

type ChallengeRow = (Vec<u8>, Vec<u8>, i64);
type SpentRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64);

#[derive(Debug, PartialEq, Eq)]
struct ReplayRows {
    challenges: Vec<ChallengeRow>,
    spent: Vec<SpentRow>,
}

fn other_replay_rows(db: &Connection, target: [u8; 32]) -> Result<ReplayRows> {
    let challenges = db
        .prepare(
            "SELECT key_id,digest,deadline FROM challenges WHERE key_id!=?1
             ORDER BY key_id,digest,deadline",
        )?
        .query_map([target.as_slice()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let spent = db
        .prepare(
            "SELECT key_id,digest,nonce,deadline FROM spent WHERE key_id!=?1
             ORDER BY key_id,digest,nonce,deadline",
        )?
        .query_map([target.as_slice()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(ReplayRows { challenges, spent })
}

fn ensure_other_replay_rows(db: &Connection, target: [u8; 32], before: &ReplayRows) -> Result<()> {
    ensure!(
        other_replay_rows(db, target)? == *before,
        "retirement changed another key's replay rows"
    );
    Ok(())
}

/// Pure derivation of per-key states at `hour` (= now / 3600).
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
    /// Fresh provisioning only. The genesis SPKI must be canonical and hash to
    /// `expected_key_id`; it is validated before any file is created. Partial
    /// failure requires operator cleanup, never automatic replacement.
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
        // Store is never key-less: genesis is activated at hour 0 in this transaction.
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

    /// Opens existing state only. The first open durably pins the names; the key
    /// set is read from the store, so activation happens offline via `install_key`.
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
            _ownership: owner,
            secret,
            keys,
            issuer: issuer_name.into(),
            name: origin_name.into(),
        })
    }

    /// Offline inspection. Takes the ownership lock, so it refuses while serving.
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

    /// Offline activation/rescheduling. `at` must be hour-aligned and in the future.
    /// Installing a new key requires no installed or superseded-unretired key;
    /// rescheduling is allowed only for the same installed key before its activation.
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
        let hour = now / HOUR;
        match keys.iter().find(|k| k.key_id == expected_key_id) {
            Some(existing) if existing.retired => {
                bail!("retired origin key cannot be reinstalled")
            }
            Some(existing) if existing.hour <= hour => bail!("origin key already active"),
            Some(existing) => {
                // Installed and not yet advertising: only its own schedule may move.
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
        tx.execute(
            "UPDATE metadata SET high_water=?1 WHERE singleton=1",
            [now_sql],
        )?;
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
        tx.commit()?;
        Ok(())
    }

    /// Offline retirement, at least 420 seconds after the next live key activates.
    /// Keeps the key record permanently, but atomically deletes its replay rows.
    /// Takes the ownership lock and refuses corrupt state or clock regression.
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
        // Validate before deleting anything: invariant-7 corruption must not be
        // erased by the very operation that would otherwise hide it.
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
        let other_rows = other_replay_rows(&tx, key_id)?;

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
        tx.execute(
            "UPDATE metadata SET high_water=?1 WHERE singleton=1",
            [now_sql],
        )?;

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
        ensure_other_replay_rows(&tx, key_id, &other_rows)?;
        ensure!(
            read_metadata(&tx)?.1 == now,
            "retirement did not advance high-water mark"
        );
        tx.commit()?;
        Ok(())
    }

    fn advertising(&self, hour: u64) -> Option<&LiveKey> {
        self.keys
            .iter()
            .filter(|k| k.hour <= hour)
            .max_by_key(|k| k.hour)
    }

    fn challenge(&self, now: u64) -> Result<(TokenChallenge, u64)> {
        let hour = now / HOUR;
        let deadline = hour
            .checked_add(1)
            .and_then(|h| h.checked_mul(HOUR))
            .and_then(|s| s.checked_add(GRACE))
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
    /// A token is verified only with the non-retired key whose exact key_id it
    /// names (no trial verification across keys). Challenges are recorded under
    /// the advertising key. No pruning: retaining spent rows is conservative.
    pub fn request_at(&self, token: Option<&Token>, now: u64) -> Result<Option<String>> {
        let now_sql = i64::try_from(now)?;
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("store poisoned"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_plain_schema(&tx)?;
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
            let (challenge, deadline) = self.challenge(now)?;
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
    use std::path::PathBuf;

    const H: u64 = 500_000;
    const S: u64 = H * HOUR;

    /// Schema v1 exactly as the previous release created it.
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

    /// Genesis K1 at hour 0, optionally K2 installed at S (installed at S-3600).
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
    fn durable_redemption_clock_and_ownership() -> Result<()> {
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

    #[test]
    fn v1_refusal_leaves_file_unchanged() -> Result<()> {
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

            // The exact first valid deadline is allowed for both row types.
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
        let dir = tempfile::tempdir()?;
        let (db, secret) = paths(dir.path());
        let (k1, p1) = signer()?;
        let (k2, p2) = signer()?;
        Origin::initialize(&db, &secret, p1.to_spki(), p1.key_id())?;
        install(&db, &p2, S, S - HOUR)?;
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;

        // Before S: K1 advertises; K2 is installed and must not be accepted.
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

        // At S: K2 advertises; K1 verifies only persisted rows until S+300.
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

        // Reopen: invariant 7 holds and the accepted K1 token is durably spent.
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        assert!(origin
            .request_at(Some(&token(&k1, &p1, d_before, 4)?), S + 400)?
            .is_some());
        Ok(())
    }

    #[test]
    fn install_key_refusal_table() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (db, secret) = paths(dir.path());
        let (_, p1) = signer()?;
        let (_, p2) = signer()?;
        let (_, p3) = signer()?;
        let t0 = S - HOUR;
        Origin::initialize(&db, &secret, p1.to_spki(), p1.key_id())?;

        // Refusals that leave the store untouched.
        assert!(Origin::install_key(&db, p2.to_spki(), p3.key_id(), S, t0).is_err());
        let mut noncanonical = p2.to_spki().to_vec();
        noncanonical.push(0);
        let id: [u8; 32] = Sha256::digest(&noncanonical).into();
        assert!(Origin::install_key(&db, &noncanonical, id, S, t0).is_err());
        assert!(install(&db, &p2, S + 1, t0).is_err()); // not hour-aligned
        assert!(install(&db, &p2, S, S).is_err()); // S == now
        assert!(install(&db, &p2, S, S + 1).is_err()); // S < now
        assert_eq!(Origin::status(&db, t0)?.high_water, 0);

        // Install, then high-water refusal and another-installed refusal.
        install(&db, &p2, S, t0)?;
        assert_eq!(Origin::status(&db, t0)?.high_water, t0);
        assert!(install(&db, &p3, S + HOUR, t0).is_err()); // another installed
        assert!(install(&db, &p2, S + HOUR, t0 - 1).is_err()); // now < high_water
        assert_eq!(Origin::status(&db, t0)?.high_water, t0);

        // Reschedule before S is allowed; same-S is a no-op success.
        install(&db, &p2, S + HOUR, t0)?;
        assert_eq!(Origin::status(&db, t0)?.keys[1].activation_hour, H + 1);
        install(&db, &p2, S, t0)?;
        install(&db, &p2, S, t0)?;
        assert_eq!(Origin::status(&db, t0)?.keys[1].activation_hour, H);

        // At S: K2 advertises, K1 verifies. Reschedule after S and new keys refused.
        assert!(install(&db, &p2, S + HOUR, S).is_err()); // already active
        assert!(install(&db, &p1, S + HOUR, S).is_err()); // already active
        assert!(install(&db, &p3, S + HOUR, S).is_err()); // superseded K1 unretired
        assert_eq!(Origin::status(&db, S)?.high_water, t0);

        // A retained retired key record must never be reinstalled.
        raw(&db)?.execute(
            "UPDATE origin_keys SET retired=1 WHERE key_id=?1",
            [p1.key_id().as_slice()],
        )?;
        assert!(install(&db, &p1, S + HOUR, S).is_err()); // retired never reinstalled
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
        assert_install_trigger_rolls_back(
            "CREATE TRIGGER ignore_install BEFORE INSERT ON origin_keys
             BEGIN SELECT RAISE(IGNORE); END;",
            false,
        )
    }

    #[test]
    fn ignored_install_reschedule_rolls_back() -> Result<()> {
        assert_install_trigger_rolls_back(
            "CREATE TRIGGER ignore_reschedule BEFORE UPDATE ON origin_keys
             BEGIN SELECT RAISE(IGNORE); END;",
            true,
        )
    }

    #[test]
    fn install_trigger_altering_another_key_rolls_back() -> Result<()> {
        assert_install_trigger_rolls_back(
            "CREATE TRIGGER change_other AFTER INSERT ON origin_keys
             BEGIN UPDATE origin_keys SET activation_hour=1 WHERE key_id!=NEW.key_id; END;",
            false,
        )
    }

    #[test]
    fn install_trigger_altering_target_rolls_back() -> Result<()> {
        assert_install_trigger_rolls_back(
            "CREATE TRIGGER change_target AFTER INSERT ON origin_keys
             BEGIN UPDATE origin_keys SET activation_hour=NEW.activation_hour+1
                   WHERE key_id=NEW.key_id; END;",
            false,
        )
    }

    #[test]
    fn ignored_install_high_water_update_rolls_back() -> Result<()> {
        assert_install_trigger_rolls_back(
            "CREATE TRIGGER ignore_clock BEFORE UPDATE OF high_water ON metadata
             BEGIN SELECT RAISE(IGNORE); END;",
            false,
        )
    }

    fn assert_retire_refused(
        db: &Path,
        secret: &Path,
        key_id: [u8; 32],
        now: u64,
        expected_error: &str,
    ) -> Result<()> {
        // Pin names before taking a complete logical snapshot.
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
        assert_retire_trigger_rolls_back(
            "CREATE TRIGGER ignore_retire BEFORE UPDATE OF retired ON origin_keys
             BEGIN SELECT RAISE(IGNORE); END;",
        )
    }

    #[test]
    fn retirement_trigger_deleting_successor_spent_rows_rolls_back() -> Result<()> {
        assert_retire_trigger_rolls_back(
            "CREATE TRIGGER delete_other_spent AFTER DELETE ON spent
             BEGIN DELETE FROM spent WHERE key_id!=OLD.key_id; END;",
        )
    }

    #[test]
    fn retirement_postcondition_trigger_regressions() -> Result<()> {
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
        // Some(challenge) is the rejected/401 path, not a successful redemption.
        assert!(origin.request_at(Some(&spent), S + 420)?.is_some());
        assert_eq!(challenge_rows(&db)?, before.replay.challenges);
        assert_eq!(spent_rows(&db)?, before.replay.spent);
        Ok(())
    }

    #[test]
    fn retirement_replay_snapshot_detects_count_preserving_edits() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (_, old) = signer()?;
        let (_, next) = signer()?;
        let (db, _) = fresh(dir.path(), &old, Some(&next))?;
        plant_retirement_rows(&db, &old, &next)?;
        let mut conn = raw(&db)?;
        let before = other_replay_rows(&conn, old.key_id())?;
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
            let error = ensure_other_replay_rows(&tx, old.key_id(), &before).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("changed another key's replay rows"),
                "{error:#}"
            );
            tx.rollback()?;
            ensure_other_replay_rows(&conn, old.key_id(), &before)?;
        }
        Ok(())
    }

    #[test]
    fn status_states_lock_and_clock() -> Result<()> {
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

        // Status takes the ownership lock and refuses while the store is served.
        let origin = Origin::open(&db, &secret, "issuer", "origin")?;
        assert!(Origin::status(&db, S).is_err());
        drop(origin);
        Ok(())
    }
}
