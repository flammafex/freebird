//! The issuer selects a signing key from the schedule in the v2 database.
//! Offline changes use the supplied `now` in Unix seconds, so the system clock is not read.
//! Keep the lock file in place so that all processes lock the same inode.
//! The operating system holds the lock while the store is open and releases it if the process exits.
//! There is no check for rollback to an older database snapshot.

use anyhow::{bail, ensure, Context, Result};
use freebird_crypto::privacy_pass::{PublicKey, SecretKey};
use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

const SCHEMA: &str = "
CREATE TABLE metadata (
  singleton   INTEGER PRIMARY KEY CHECK(singleton=1),
  version     INTEGER NOT NULL CHECK(version=2),
  high_water  INTEGER NOT NULL CHECK(high_water>=0));
CREATE TABLE keys (
  key_id          BLOB PRIMARY KEY NOT NULL CHECK(length(key_id)=32),
  spki            BLOB NOT NULL,
  pkcs8           BLOB,
  activation_hour INTEGER UNIQUE CHECK(activation_hour IS NULL OR activation_hour>=0),
  CHECK(pkcs8 IS NOT NULL OR activation_hour IS NOT NULL));
";

const V1_REFUSAL: &str = "key schema v1 unsupported; no migration — initialize fresh state";
const CLOCK_BEHIND: &str = "clock is behind the key store high-water mark";
const SECONDS_PER_HOUR: u64 = 3600;
const ACCEPTANCE_GRACE: u64 = 300;
/// Use the Origin's bound so that the activation time in seconds plus grace fits
/// in a SQLite `i64`.
const MAX_HOUR: u64 = (i64::MAX as u64 - ACCEPTANCE_GRACE) / SECONDS_PER_HOUR;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyState {
    Staged,
    Scheduled,
    Active,
    RetiredForIssuance,
    Retired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    pub key_id: [u8; 32],
    pub spki: Vec<u8>,
    pub activation_hour: Option<u64>,
    pub has_private: bool,
    pub state: KeyState,
    pub issuance_end: Option<u64>,
    pub acceptance_deadline: Option<u64>,
}

/// The manifest lists keys in ascending order by activation hour and puts the staged key last.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub now: u64,
    pub high_water: u64,
    pub keys: Vec<KeyRecord>,
}

/// Omit `Debug` so that this type cannot expose private key material through debug formatting.
pub struct SigningKey {
    pub secret: SecretKey,
    pub public: PublicKey,
    pub activation_hour: u64,
}

/// Omit `Debug` because a validated row can contain private key material.
#[derive(PartialEq, Eq)]
struct Row {
    key_id: [u8; 32],
    spki: Vec<u8>,
    pkcs8: Option<Vec<u8>>,
    hour: Option<u64>,
}

#[derive(PartialEq, Eq)]
struct Snapshot {
    high_water: u64,
    rows: Vec<Row>,
}

/// An exclusive lock is held while the store is open, even when no requests are in progress.
pub struct KeyStore {
    db: Mutex<Connection>,
    _lock: File,
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn lock(path: &Path, initialize: bool) -> Result<File> {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let path = PathBuf::from(name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(initialize)
        .mode(0o600)
        .open(&path)?;
    FileExt::try_lock_exclusive(&file).context("key store already locked")?;
    ensure!(
        file.metadata()?.permissions().mode() & 0o777 == 0o600,
        "key lock permissions must be 0600"
    );
    file.sync_all()?;
    File::open(parent(&path))?.sync_all()?;
    Ok(file)
}

fn connect(path: &Path, initialize: bool) -> Result<Connection> {
    ensure!(
        path.metadata()?.permissions().mode() & 0o777 == 0o600,
        "key database permissions must be 0600"
    );
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    require_plain_schema(&db)?;
    let mode: String = if initialize {
        db.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?
    } else {
        db.query_row("PRAGMA journal_mode", [], |r| r.get(0))?
    };
    ensure!(
        mode.eq_ignore_ascii_case("wal"),
        "key database must use WAL"
    );
    db.pragma_update(None, "synchronous", "FULL")?;
    let sync: i64 = db.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    ensure!(sync == 2, "FULL synchronization unavailable");
    db.pragma_update(None, "secure_delete", "ON")?;
    let secure: i64 = db.query_row("PRAGMA secure_delete", [], |r| r.get(0))?;
    ensure!(secure == 1, "secure deletion unavailable");
    Ok(db)
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

/// Check the schema version with a read-only connection before checking journal
/// mode or permissions so that a v1 database in `DELETE` mode gets the v1 error.
fn require_v2(path: &Path) -> Result<()> {
    let probe = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let legacy: i64 = probe.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('metadata') WHERE name='active_key_id'",
        [],
        |r| r.get(0),
    )?;
    if legacy != 0 {
        bail!(V1_REFUSAL);
    }
    let versions = probe
        .prepare("SELECT version FROM metadata")?
        .query_map([], |r| r.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if versions.contains(&1) {
        bail!(V1_REFUSAL);
    }
    ensure!(versions == [2], "unsupported key schema version");
    Ok(())
}

fn parse_row(
    key_id: Vec<u8>,
    spki: Vec<u8>,
    pkcs8: Option<Vec<u8>>,
    hour: Option<i64>,
) -> Result<Row> {
    let key_id: [u8; 32] = key_id
        .as_slice()
        .try_into()
        .context("invalid key ID length")?;
    let hour = hour
        .map(|h| u64::try_from(h).context("negative activation hour"))
        .transpose()?;
    ensure!(
        pkcs8.is_some() || hour.is_some(),
        "key row has neither private material nor an activation hour"
    );
    let digest: [u8; 32] = Sha256::digest(&spki).into();
    ensure!(digest == key_id, "key ID does not match SPKI digest");
    // `PublicKey::from_spki` rejects encodings outside the required canonical profile.
    let public = PublicKey::from_spki(&spki)?;
    if let Some(pkcs8) = &pkcs8 {
        // `SecretKey::from_pkcs8` rejects private keys that are not in canonical PKCS#8 DER.
        let secret = SecretKey::from_pkcs8(pkcs8)?;
        ensure!(
            secret.public_key()?.to_spki() == public.to_spki(),
            "key material mismatch"
        );
    }
    Ok(Row {
        key_id,
        spki,
        pkcs8,
        hour,
    })
}

/// Check rules that apply across the rows and do not depend on the clock.
/// `parse_row` checks canonical key encodings and matching IDs before these checks run.
fn check_structure(rows: &[Row]) -> Result<()> {
    let mut ids = HashSet::new();
    for row in rows {
        ensure!(ids.insert(row.key_id), "duplicate key ID");
    }
    ensure!(
        rows.iter().all(|r| r.hour.is_none_or(|h| h <= MAX_HOUR)),
        "activation hour out of range"
    );
    // The store allows at most one staged key, which must have private material.
    let staged: Vec<&Row> = rows.iter().filter(|r| r.hour.is_none()).collect();
    ensure!(staged.len() <= 1, "more than one staged key");
    ensure!(
        staged.iter().all(|r| r.pkcs8.is_some()),
        "staged key lacks private material"
    );
    // The store must contain at least one and at most three keys with private material.
    let private: Vec<&Row> = rows.iter().filter(|r| r.pkcs8.is_some()).collect();
    ensure!(
        (1..=3).contains(&private.len()),
        "invalid private key cardinality"
    );
    // At most two keys with private material may have activation hours.
    ensure!(
        private.iter().filter(|r| r.hour.is_some()).count() <= 2,
        "more than two scheduled, active, or retiring keys"
    );
    // Each activation hour must be distinct, and the latest must belong to a key
    // with private material.
    let mut hours = HashSet::new();
    for hour in rows.iter().filter_map(|r| r.hour) {
        ensure!(hours.insert(hour), "duplicate activation hour");
    }
    let newest = rows
        .iter()
        .filter(|r| r.hour.is_some())
        .max_by_key(|r| r.hour)
        .context("no activation hour")?;
    ensure!(
        newest.pkcs8.is_some(),
        "newest activation belongs to a fully retired key"
    );
    // The last byte of each key ID must be unique among keys with private material.
    let mut suffixes = HashSet::new();
    for row in &private {
        ensure!(
            suffixes.insert(row.key_id[31]),
            "truncated key ID collision among private keys"
        );
    }
    Ok(())
}

fn validate(db: &Connection) -> Result<Snapshot> {
    let legacy: i64 = db.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('metadata') WHERE name='active_key_id'",
        [],
        |r| r.get(0),
    )?;
    if legacy != 0 {
        bail!(V1_REFUSAL);
    }
    let metadata = db
        .prepare("SELECT singleton, version, high_water FROM metadata")?
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(metadata.len() == 1, "expected exactly one metadata row");
    let (singleton, version, high_water) = metadata[0];
    ensure!(singleton == 1, "invalid metadata singleton");
    ensure!(version == 2, "unsupported key schema version");
    let high_water = u64::try_from(high_water).context("negative high-water mark")?;
    let raw = db
        .prepare("SELECT key_id, spki, pkcs8, activation_hour FROM keys")?
        .query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
                r.get::<_, Option<i64>>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut rows = Vec::with_capacity(raw.len());
    for (key_id, spki, pkcs8, hour) in raw {
        rows.push(parse_row(key_id, spki, pkcs8, hour)?);
    }
    check_structure(&rows)?;
    Ok(Snapshot { high_water, rows })
}

/// Return the index of the latest activation hour at or before `hour`, or `None`
/// if no activation qualifies.
pub fn select_active(activation_hours: &[u64], hour: u64) -> Option<usize> {
    activation_hours
        .iter()
        .enumerate()
        .filter(|(_, h)| **h <= hour)
        .max_by_key(|(_, h)| **h)
        .map(|(index, _)| index)
}

/// Return the row index of the private key that is active at `now`, if there is one.
fn active_index(snapshot: &Snapshot, now: u64) -> Option<usize> {
    let candidates: Vec<(usize, u64)> = snapshot
        .rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.pkcs8.is_some())
        .filter_map(|(index, r)| r.hour.map(|h| (index, h)))
        .collect();
    let hours: Vec<u64> = candidates.iter().map(|(_, h)| *h).collect();
    select_active(&hours, now / SECONDS_PER_HOUR).map(|pos| candidates[pos].0)
}

fn active_key_id(snapshot: &Snapshot, now: u64) -> Option<[u8; 32]> {
    active_index(snapshot, now).map(|index| snapshot.rows[index].key_id)
}

fn staged_id(snapshot: &Snapshot) -> Option<[u8; 32]> {
    snapshot
        .rows
        .iter()
        .find(|r| r.hour.is_none())
        .map(|r| r.key_id)
}

fn private_suffixes(snapshot: &Snapshot) -> Vec<u8> {
    snapshot
        .rows
        .iter()
        .filter(|r| r.pkcs8.is_some())
        .map(|r| r.key_id[31])
        .collect()
}

/// Use the schedule and `now` to report each key's state without writing it to the store.
fn derive(snapshot: &Snapshot, now: u64) -> Result<Vec<KeyRecord>> {
    let hour = now / SECONDS_PER_HOUR;
    let active = active_index(snapshot, now);
    let hours: Vec<u64> = snapshot.rows.iter().filter_map(|r| r.hour).collect();
    let mut records = Vec::with_capacity(snapshot.rows.len());
    for (index, row) in snapshot.rows.iter().enumerate() {
        let state = match row.hour {
            None => KeyState::Staged,
            Some(_) if row.pkcs8.is_none() => KeyState::Retired,
            Some(h) if h > hour => KeyState::Scheduled,
            Some(_) if active == Some(index) => KeyState::Active,
            Some(_) => KeyState::RetiredForIssuance,
        };
        // Use the next activation hour to find the successor, even if that key is retired.
        let successor = row
            .hour
            .and_then(|h| hours.iter().copied().filter(|&o| o > h).min());
        let issuance_end = successor
            .map(|s| {
                s.checked_mul(SECONDS_PER_HOUR)
                    .context("issuance end overflow")
            })
            .transpose()?;
        let acceptance_deadline = issuance_end
            .map(|end| {
                end.checked_add(ACCEPTANCE_GRACE)
                    .context("acceptance deadline overflow")
            })
            .transpose()?;
        records.push(KeyRecord {
            key_id: row.key_id,
            spki: row.spki.clone(),
            activation_hour: row.hour,
            has_private: row.pkcs8.is_some(),
            state,
            issuance_end,
            acceptance_deadline,
        });
    }
    records.sort_by_key(|r| (r.activation_hour.is_none(), r.activation_hour));
    Ok(records)
}

fn state_of(records: &[KeyRecord], key_id: &[u8; 32]) -> Result<KeyState> {
    records
        .iter()
        .find(|r| &r.key_id == key_id)
        .map(|r| r.state)
        .context("unknown key ID")
}

fn to_i64(value: u64, what: &str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("{what} out of range"))
}

fn ensure_stageable(snapshot: &Snapshot, now: u64) -> Result<()> {
    let records = derive(snapshot, now)?;
    ensure!(
        !records.iter().any(|r| r.state == KeyState::Staged),
        "a staged key already exists"
    );
    ensure!(
        !records.iter().any(|r| r.state == KeyState::Scheduled),
        "a scheduled key exists"
    );
    Ok(())
}

fn ensure_activation(
    before: &Snapshot,
    after: &Snapshot,
    target: [u8; 32],
    hour: u64,
    now: u64,
) -> Result<()> {
    ensure!(
        after.high_water == now,
        "activation did not advance high-water mark"
    );
    ensure!(
        after.rows.len() == before.rows.len(),
        "activation changed key cardinality"
    );
    ensure!(
        after
            .rows
            .iter()
            .filter(|r| r.key_id != target)
            .eq(before.rows.iter().filter(|r| r.key_id != target)),
        "activation changed another key"
    );
    let old = before
        .rows
        .iter()
        .find(|r| r.key_id == target)
        .context("target key missing")?;
    let new = after
        .rows
        .iter()
        .find(|r| r.key_id == target)
        .context("target key missing after activation")?;
    ensure!(
        new.hour == Some(hour) && new.pkcs8 == old.pkcs8 && new.spki == old.spki,
        "activation did not persist target"
    );
    ensure!(
        state_of(&derive(after, now)?, &target)? == KeyState::Scheduled,
        "activation did not persist scheduled state"
    );
    ensure!(
        active_key_id(after, now) == active_key_id(before, now),
        "activation changed active key"
    );
    Ok(())
}

fn ensure_retirement(
    before: &Snapshot,
    after: &Snapshot,
    target: [u8; 32],
    now: u64,
) -> Result<()> {
    ensure!(
        after.high_water == now,
        "retirement did not advance high-water mark"
    );
    ensure!(
        after.rows.len() == before.rows.len(),
        "retirement changed key cardinality"
    );
    ensure!(
        before
            .rows
            .iter()
            .filter(|r| r.key_id != target)
            .all(|old| after.rows.iter().any(|new| new == old)),
        "retirement changed another key"
    );
    let old = before
        .rows
        .iter()
        .find(|r| r.key_id == target)
        .context("target key missing")?;
    let new = after
        .rows
        .iter()
        .find(|r| r.key_id == target)
        .context("target key missing after retirement")?;
    ensure!(
        new.pkcs8.is_none() && new.spki == old.spki && new.hour == old.hour,
        "retirement did not persist target"
    );
    ensure!(
        active_key_id(after, now) == active_key_id(before, now),
        "retirement changed active key"
    );
    Ok(())
}

impl KeyStore {
    /// Create a store with its first key active from hour 0 and its high-water mark set to 0.
    /// The parent directory must exist. If setup fails after reserving files, those
    /// files remain so that retrying cannot replace uncertain state.
    pub fn initialize(path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let _lock = lock(path, true)?;
        let reservation = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .context("reserve fresh key database")?;
        reservation.sync_all()?;
        File::open(parent(path))?.sync_all()?;
        let key = SecretKey::generate()?;
        let public = key.public_key()?;
        let mut db = connect(path, true)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_plain_schema(&tx)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute(
            "INSERT INTO metadata (singleton, version, high_water) VALUES (1, 2, 0)",
            [],
        )?;
        tx.execute(
            "INSERT INTO keys (key_id, spki, pkcs8, activation_hour) VALUES (?1, ?2, ?3, 0)",
            params![
                public.key_id().as_slice(),
                public.to_spki(),
                key.to_pkcs8()?
            ],
        )?;
        validate(&tx)?;
        tx.commit()?;
        File::open(parent(path))?.sync_all()?;
        Ok(())
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        require_v2(path)?;
        let lock = lock(path, false)?;
        let db = connect(path, false)?;
        let integrity = db
            .prepare("PRAGMA integrity_check")?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(
            integrity == ["ok"],
            "key database integrity check failed: {integrity:?}"
        );
        validate(&db)?;
        Ok(Self {
            db: Mutex::new(db),
            _lock: lock,
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.db
            .lock()
            .map_err(|_| anyhow::anyhow!("key store mutex poisoned"))
    }

    /// Report the state at `now` even if it is below the high-water mark, so that
    /// operators can diagnose clock skew. This call leaves the store unchanged.
    pub fn manifest(&self, now: u64) -> Result<Manifest> {
        let db = self.connection()?;
        let snapshot = validate(&db)?;
        Ok(Manifest {
            now,
            high_water: snapshot.high_water,
            keys: derive(&snapshot, now)?,
        })
    }

    /// Commit a candidate only when no staged or scheduled key exists.
    pub fn stage(&self, now: u64) -> Result<[u8; 32]> {
        self.stage_with_generator(now, || Ok(SecretKey::generate()?))
    }

    fn stage_with_generator(
        &self,
        now: u64,
        mut generate: impl FnMut() -> Result<SecretKey>,
    ) -> Result<[u8; 32]> {
        let mut db = self.connection()?;
        let before = validate(&db)?;
        ensure!(now >= before.high_water, CLOCK_BEHIND);
        ensure_stageable(&before, now)?;
        // Generate candidates before starting the transaction. The store lock and
        // mutex protect the snapshot during generation.
        // Skip any candidate whose truncated ID matches that of a private key.
        let suffixes = private_suffixes(&before);
        let mut candidate = None;
        for _ in 0..16 {
            let key = generate()?;
            let public = key.public_key()?;
            if !suffixes.contains(&public.key_id()[31]) {
                candidate = Some((key, public));
                break;
            }
        }
        let (key, public) =
            candidate.context("unable to generate a noncolliding key after 16 attempts")?;
        let id = public.key_id();
        let pkcs8 = key.to_pkcs8()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_plain_schema(&tx)?;
        let snapshot = validate(&tx)?;
        ensure!(
            snapshot == before,
            "key status changed before staging transaction"
        );
        ensure!(now >= snapshot.high_water, CLOCK_BEHIND);
        ensure_stageable(&snapshot, now)?;
        ensure!(
            !private_suffixes(&snapshot).contains(&id[31]),
            "truncated key ID collision"
        );
        let active = active_key_id(&snapshot, now);
        tx.execute(
            "UPDATE metadata SET high_water=?1 WHERE singleton=1",
            [to_i64(now, "time")?],
        )?;
        let inserted = tx.execute(
            "INSERT INTO keys (key_id, spki, pkcs8, activation_hour) VALUES (?1, ?2, ?3, NULL)",
            params![id.as_slice(), public.to_spki(), pkcs8],
        )?;
        ensure!(inserted == 1, "staging did not insert exactly one key");
        let after = validate(&tx)?;
        ensure!(
            after.rows.len() == snapshot.rows.len() + 1
                && after.high_water == now
                && staged_id(&after) == Some(id)
                && active_key_id(&after, now) == active,
            "staging changed active key or failed to persist candidate"
        );
        tx.commit()?;
        Ok(id)
    }

    /// Export the public part of any stored key as canonical SPKI, even after retirement.
    pub fn spki(&self, key_id: [u8; 32]) -> Result<Vec<u8>> {
        let db = self.connection()?;
        validate(&db)?;
        db.query_row(
            "SELECT spki FROM keys WHERE key_id=?1",
            [key_id.as_slice()],
            |r| r.get(0),
        )
        .optional()?
        .context("unknown key ID")
    }

    /// Schedule the staged key to activate at `at`, or change a scheduled key's
    /// activation if there is no staged key. Supply `at` in Unix seconds on a future
    /// hour boundary.
    /// Every successful call records `now` as the high-water mark, even if the
    /// schedule is unchanged.
    pub fn schedule_activation(&self, at: u64, now: u64) -> Result<[u8; 32]> {
        ensure!(
            at.is_multiple_of(SECONDS_PER_HOUR),
            "activation time must be hour-aligned"
        );
        let hour = at / SECONDS_PER_HOUR;
        ensure!(hour <= MAX_HOUR, "activation time out of range");
        ensure!(at > now, "activation time must be after the current time");
        let hour_db = to_i64(hour, "activation hour")?;
        let mut db = self.connection()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_plain_schema(&tx)?;
        let before = validate(&tx)?;
        ensure!(now >= before.high_water, CLOCK_BEHIND);
        let records = derive(&before, now)?;
        ensure!(
            !records
                .iter()
                .any(|r| r.state == KeyState::RetiredForIssuance),
            "a retired-for-issuance key still has private material; retire it first"
        );
        let target = match staged_id(&before) {
            Some(id) => id,
            None => records
                .iter()
                .find(|r| r.state == KeyState::Scheduled)
                .map(|r| r.key_id)
                .context("no staged or scheduled key to activate")?,
        };
        let target_state = state_of(&records, &target)?;
        ensure!(
            matches!(target_state, KeyState::Staged | KeyState::Scheduled),
            "target key is already active"
        );
        let latest_other = before
            .rows
            .iter()
            .filter(|r| r.key_id != target)
            .filter_map(|r| r.hour)
            .max();
        ensure!(
            latest_other.is_none_or(|other| hour > other),
            "activation must follow every existing activation"
        );
        let current_hour = before
            .rows
            .iter()
            .find(|r| r.key_id == target)
            .context("target key missing")?
            .hour;
        tx.execute(
            "UPDATE metadata SET high_water=?1 WHERE singleton=1",
            [to_i64(now, "time")?],
        )?;
        if current_hour != Some(hour) {
            let changed = tx.execute(
                "UPDATE keys SET activation_hour=?1 WHERE key_id=?2",
                params![hour_db, target.as_slice()],
            )?;
            ensure!(changed == 1, "activation did not update exactly one key");
        }
        let after = validate(&tx)?;
        ensure_activation(&before, &after, target, hour, now)?;
        tx.commit()?;
        Ok(target)
    }

    /// Remove private material only after a successor with private material has
    /// activated by `now`.
    /// Try to truncate the WAL after committing retirement. The function still returns
    /// `Ok(())` if the checkpoint fails or reports that the database is busy.
    /// Retirement does not guarantee that private material is erased from backups or memory.
    pub fn retire(&self, key_id: [u8; 32], now: u64) -> Result<()> {
        let mut db = self.connection()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_plain_schema(&tx)?;
        let before = validate(&tx)?;
        ensure!(now >= before.high_water, CLOCK_BEHIND);
        let target = before
            .rows
            .iter()
            .find(|r| r.key_id == key_id)
            .context("unknown key ID")?;
        ensure!(target.pkcs8.is_some(), "key is already retired");
        let hour = target.hour.context("cannot retire a staged key")?;
        ensure!(
            before.rows.iter().any(|r| {
                r.pkcs8.is_some()
                    && r.hour.is_some_and(|successor| {
                        successor > hour
                            && successor
                                .checked_mul(SECONDS_PER_HOUR)
                                .is_some_and(|at| at <= now)
                    })
            }),
            "key has not been superseded by the local clock"
        );
        let changed = tx.execute(
            "UPDATE keys SET pkcs8=NULL WHERE key_id=?1",
            [key_id.as_slice()],
        )?;
        ensure!(changed == 1, "retirement did not update exactly one key");
        tx.execute(
            "UPDATE metadata SET high_water=?1 WHERE singleton=1",
            [to_i64(now, "time")?],
        )?;
        let after = validate(&tx)?;
        ensure_retirement(&before, &after, key_id, now)?;
        tx.commit()?;
        let _ = db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            r.get::<_, i64>(0)
        });
        Ok(())
    }

    /// Return only keys that have both private material and an activation hour,
    /// in ascending order by activation hour.
    pub fn signing_keys(&self, now: u64) -> Result<Vec<SigningKey>> {
        let db = self.connection()?;
        let snapshot = validate(&db)?;
        ensure!(now >= snapshot.high_water, CLOCK_BEHIND);
        let mut keys = Vec::new();
        for row in &snapshot.rows {
            if let (Some(pkcs8), Some(hour)) = (&row.pkcs8, row.hour) {
                let secret = SecretKey::from_pkcs8(pkcs8)?;
                let public = secret.public_key()?;
                keys.push(SigningKey {
                    secret,
                    public,
                    activation_hour: hour,
                });
            }
        }
        keys.sort_by_key(|k| k.activation_hour);
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Transaction;
    use std::fs;

    const T0: u64 = 1_000;
    const H: u64 = 10;
    const S: u64 = H * SECONDS_PER_HOUR;

    fn fresh() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.sqlite");
        KeyStore::initialize(&path).unwrap();
        (dir, path)
    }

    fn raw_snapshot(path: &Path) -> Snapshot {
        let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        validate(&db).unwrap()
    }

    fn remove_test_schema_objects(path: &Path) {
        let db = Connection::open(path).unwrap();
        let objects = db
            .prepare("SELECT type,name FROM sqlite_master WHERE type IN ('trigger','view')")
            .unwrap()
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        for (kind, name) in objects {
            db.execute_batch(&format!("DROP {kind} \"{}\"", name.replace('"', "\"\"")))
                .unwrap();
        }
    }

    /// Create a store with the first key active from hour 0 and a second key staged at `T0`.
    fn staged_fixture() -> (tempfile::TempDir, PathBuf, [u8; 32]) {
        let (dir, path) = fresh();
        let id = KeyStore::open(&path).unwrap().stage(T0).unwrap();
        (dir, path, id)
    }

    /// Schedule the second key to activate at `S`, leaving the first key active until then.
    fn scheduled_fixture() -> (tempfile::TempDir, PathBuf, [u8; 32]) {
        let (dir, path, id) = staged_fixture();
        let scheduled = KeyStore::open(&path)
            .unwrap()
            .schedule_activation(S, T0)
            .unwrap();
        assert_eq!(scheduled, id);
        (dir, path, id)
    }

    fn genesis_id(store: &KeyStore, now: u64) -> [u8; 32] {
        store
            .manifest(now)
            .unwrap()
            .keys
            .iter()
            .find(|k| k.activation_hour == Some(0))
            .unwrap()
            .key_id
    }

    fn state(manifest: &Manifest, id: [u8; 32]) -> KeyState {
        manifest.keys.iter().find(|k| k.key_id == id).unwrap().state
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Generate a key whose truncated ID does not match any suffix in `used`.
    fn material_avoiding(used: &[u8]) -> ([u8; 32], Vec<u8>, Vec<u8>) {
        loop {
            let key = SecretKey::generate().unwrap();
            let public = key.public_key().unwrap();
            if !used.contains(&public.key_id()[31]) {
                return (
                    public.key_id(),
                    public.to_spki().to_vec(),
                    key.to_pkcs8().unwrap(),
                );
            }
        }
    }

    /// Replace the tables with versions that allow tests to insert invalid
    /// metadata and key rows. Roll back the transaction after checking validation.
    fn unconstrain(tx: &Transaction) {
        tx.execute_batch(
            "ALTER TABLE metadata RENAME TO old_metadata;
             CREATE TABLE metadata (singleton INTEGER, version INTEGER, high_water INTEGER);
             INSERT INTO metadata SELECT * FROM old_metadata;
             DROP TABLE old_metadata;
             ALTER TABLE keys RENAME TO old_keys;
             CREATE TABLE keys (key_id BLOB PRIMARY KEY NOT NULL, spki BLOB NOT NULL,
                                pkcs8 BLOB, activation_hour INTEGER);
             INSERT INTO keys SELECT * FROM old_keys;
             DROP TABLE old_keys;",
        )
        .unwrap();
    }

    /// Build a row with `tag` as the first byte so that full IDs can differ even
    /// when `suffix` gives them the same truncated ID.
    fn row(tag: u8, suffix: u8, pkcs8: bool, hour: Option<u64>) -> Row {
        let mut key_id = [0; 32];
        key_id[0] = tag;
        key_id[31] = suffix;
        Row {
            key_id,
            spki: vec![],
            pkcs8: pkcs8.then(Vec::new),
            hour,
        }
    }

    #[test]
    fn initialize_is_genesis_and_fresh_only() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (dir, path) = fresh();
        assert!(KeyStore::initialize(&path).is_err());
        assert!(KeyStore::initialize(dir.path().join("missing/keys")).is_err());
        let store = KeyStore::open(&path).unwrap();
        let manifest = store.manifest(T0).unwrap();
        assert_eq!(manifest.high_water, 0);
        assert_eq!(manifest.keys.len(), 1);
        assert_eq!(manifest.keys[0].activation_hour, Some(0));
        assert_eq!(manifest.keys[0].state, KeyState::Active);
        assert!(manifest.keys[0].has_private);
        assert_eq!(manifest.keys[0].issuance_end, None);
        assert_eq!(manifest.keys[0].acceptance_deadline, None);
    }

    #[test]
    fn missing_state_is_not_created() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent");
        assert!(KeyStore::open(&path).is_err());
        assert!(!path.exists());
        assert!(!dir.path().join("absent.lock").exists());
    }

    #[test]
    fn missing_lock_is_not_recreated() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (dir, path) = fresh();
        let before = fs::read(&path).unwrap();
        let sidecar = dir.path().join("keys.sqlite.lock");
        fs::remove_file(&sidecar).unwrap();
        assert!(KeyStore::open(&path).is_err());
        assert!(!sidecar.exists());
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn v1_state_is_refused_and_bytes_are_untouched() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        for (mode, permissions) in [("WAL", 0o600), ("DELETE", 0o644)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("keys.sqlite");
            drop(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap(),
            );
            let key = SecretKey::generate().unwrap();
            let public = key.public_key().unwrap();
            {
                let db = Connection::open(&path).unwrap();
                db.execute_batch(&format!("PRAGMA journal_mode={mode};"))
                    .unwrap();
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
            }
            // The read-only probe reports the v1 error before checking WAL mode
            // or permissions, and it leaves the missing lock file absent.
            fs::set_permissions(&path, fs::Permissions::from_mode(permissions)).unwrap();
            let before = fs::read(&path).unwrap();
            let error = KeyStore::open(&path).err().expect("v1 must be refused");
            assert_eq!(
                error.to_string(),
                "key schema v1 unsupported; no migration — initialize fresh state"
            );
            assert_eq!(fs::read(&path).unwrap(), before);
            assert!(!dir.path().join("keys.sqlite.lock").exists());
            assert!(KeyStore::initialize(&path).is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }
    }

    #[test]
    fn corruption_matrix_fails_closed() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, _staged) = staged_fixture();
        let used: Vec<u8> = {
            let store = KeyStore::open(&path).unwrap();
            store
                .manifest(T0)
                .unwrap()
                .keys
                .iter()
                .map(|k| k.key_id[31])
                .collect()
        };
        let (extra_id, extra_spki, extra_pkcs8) = material_avoiding(&used);
        let extra_staged = format!(
            "INSERT INTO keys VALUES (x'{}', x'{}', x'{}', NULL)",
            hex(&extra_id),
            hex(&extra_spki),
            hex(&extra_pkcs8)
        );
        let extra_hour6 = format!(
            "INSERT INTO keys VALUES (x'{}', x'{}', x'{}', 6)",
            hex(&extra_id),
            hex(&extra_spki),
            hex(&extra_pkcs8)
        );
        let cases: Vec<Vec<String>> = vec![
            vec!["UPDATE metadata SET version=3".into()],
            vec!["UPDATE metadata SET high_water=-1".into()],
            vec!["INSERT INTO metadata VALUES (2, 2, 0)".into()],
            vec!["UPDATE metadata SET singleton=2".into()],
            // Inserting a second staged key exceeds the limit of one.
            vec![extra_staged],
            // Scheduling the staged key at hour 5 and adding a key at hour 6
            // creates three keys with both private material and activation hours.
            vec![
                "UPDATE keys SET activation_hour=5 WHERE activation_hour IS NULL".into(),
                extra_hour6,
            ],
            // Scheduling the staged key at hour 0 duplicates the first key's activation hour.
            vec!["UPDATE keys SET activation_hour=0 WHERE activation_hour IS NULL".into()],
            // Removing private material from the staged key leaves it with neither
            // private material nor an activation hour.
            vec!["UPDATE keys SET pkcs8=NULL WHERE activation_hour IS NULL".into()],
            // Overwriting the key ID makes it differ from the SHA-256 hash of the SPKI.
            vec!["UPDATE keys SET key_id=zeroblob(32) WHERE activation_hour=0".into()],
            vec!["UPDATE keys SET spki=x'00' WHERE activation_hour=0".into()],
            vec!["UPDATE keys SET activation_hour=-1 WHERE activation_hour=0".into()],
            // Replacing the private key breaks its match with the stored public key.
            vec![format!(
                "UPDATE keys SET pkcs8=x'{}' WHERE activation_hour IS NULL",
                hex(&extra_pkcs8)
            )],
        ];
        let mut db = connect(&path, false).unwrap();
        validate(&db).unwrap();
        for statements in &cases {
            let tx = db.transaction().unwrap();
            unconstrain(&tx);
            for sql in statements {
                tx.execute_batch(sql).unwrap();
            }
            assert!(validate(&tx).is_err(), "{statements:?}");
            tx.rollback().unwrap();
        }
        validate(&db).unwrap();
        // The table permits malformed private key bytes, but validation must reject them.
        db.execute("UPDATE keys SET pkcs8=x'00' WHERE activation_hour=0", [])
            .unwrap();
        drop(db);
        assert!(KeyStore::open(&path).is_err());
        assert!(KeyStore::initialize(&path).is_err());
    }

    #[test]
    fn newest_fully_retired_key_is_refused() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, _k1) = scheduled_fixture();
        let mut db = connect(&path, false).unwrap();
        let tx = db.transaction().unwrap();
        unconstrain(&tx);
        tx.execute_batch("UPDATE keys SET pkcs8=NULL WHERE activation_hour=10")
            .unwrap();
        assert!(validate(&tx).is_err());
        tx.rollback().unwrap();
        validate(&db).unwrap();
    }

    #[test]
    fn structural_invariants_on_synthetic_rows() {
        // Two private keys with distinct suffixes and activation hours pass validation.
        assert!(check_structure(&[row(1, 1, true, Some(0)), row(2, 2, true, Some(H))]).is_ok());
        // Matching suffixes on two keys with private material cause validation to fail.
        assert!(check_structure(&[row(1, 9, true, Some(0)), row(2, 9, true, Some(H))]).is_err());
        // Validation allows a suffix match when one of the keys is fully retired.
        assert!(check_structure(&[row(1, 9, true, Some(H)), row(2, 9, false, Some(0))]).is_ok());
        // A key with the latest activation hour fails validation if it lacks private material.
        assert!(check_structure(&[row(1, 1, true, Some(0)), row(2, 2, false, Some(H))]).is_err());
        // Keys with the same activation hour fail validation.
        assert!(check_structure(&[row(1, 1, true, Some(0)), row(2, 2, true, Some(0))]).is_err());
        // Three keys with private material and activation hours exceed the limit of two.
        assert!(check_structure(&[
            row(1, 1, true, Some(0)),
            row(2, 2, true, Some(5)),
            row(3, 3, true, Some(6)),
        ])
        .is_err());
        // Validation rejects a second staged key or a staged key that lacks private material.
        assert!(check_structure(&[
            row(1, 1, true, Some(0)),
            row(2, 2, true, None),
            row(3, 3, true, None),
        ])
        .is_err());
        assert!(check_structure(&[row(1, 1, true, Some(0)), row(2, 2, false, None)]).is_err());
        // Validation rejects a store with more than three private keys or no private keys.
        assert!(check_structure(&[
            row(1, 1, true, None),
            row(2, 2, true, None),
            row(3, 3, true, None),
            row(4, 4, true, None),
        ])
        .is_err());
        assert!(check_structure(&[row(1, 1, false, Some(0))]).is_err());
        // Validation requires at least one activation hour and rejects hours above `MAX_HOUR`.
        assert!(check_structure(&[row(1, 1, true, None)]).is_err());
        assert!(check_structure(&[row(1, 1, true, Some(u64::MAX))]).is_err());
    }

    #[test]
    fn select_active_table() {
        assert_eq!(select_active(&[0], 0), Some(0));
        assert_eq!(select_active(&[0, H], H - 1), Some(0));
        assert_eq!(select_active(&[0, H], H), Some(1));
        assert_eq!(select_active(&[0, H], H + 1), Some(1));
        assert_eq!(select_active(&[5], 4), None);
        assert_eq!(select_active(&[], 4), None);
    }

    #[test]
    fn derived_states_follow_injected_time() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, k1) = scheduled_fixture();
        let store = KeyStore::open(&path).unwrap();
        let k0 = genesis_id(&store, T0);
        let before = store.manifest(S - 1).unwrap();
        assert_eq!(state(&before, k0), KeyState::Active);
        assert_eq!(state(&before, k1), KeyState::Scheduled);
        assert_eq!(before.keys[0].issuance_end, Some(S));
        assert_eq!(
            before.keys[0].acceptance_deadline,
            Some(S + ACCEPTANCE_GRACE)
        );
        assert_eq!(before.keys[1].issuance_end, None);
        let at = store.manifest(S).unwrap();
        assert_eq!(state(&at, k0), KeyState::RetiredForIssuance);
        assert_eq!(state(&at, k1), KeyState::Active);
        assert_eq!(at.keys[0].issuance_end, Some(S));
        let late = store.manifest(S + 5 * SECONDS_PER_HOUR).unwrap();
        assert_eq!(state(&late, k1), KeyState::Active);
    }

    #[test]
    fn staged_key_is_listed_last_without_schedule() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, staged) = staged_fixture();
        let store = KeyStore::open(&path).unwrap();
        let manifest = store.manifest(T0).unwrap();
        assert_eq!(manifest.keys.len(), 2);
        assert_eq!(manifest.keys[1].key_id, staged);
        assert_eq!(manifest.keys[1].state, KeyState::Staged);
        assert_eq!(manifest.keys[1].activation_hour, None);
        assert_eq!(manifest.keys[1].issuance_end, None);
    }

    #[test]
    fn restart_staging_and_ownership() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, staged) = staged_fixture();
        let store = KeyStore::open(&path).unwrap();
        assert!(KeyStore::open(&path).is_err());
        assert!(KeyStore::initialize(&path).is_err());
        let before = store.manifest(T0).unwrap();
        assert_eq!(state(&before, staged), KeyState::Staged);
        let spki = store.spki(staged).unwrap();
        assert_eq!(PublicKey::from_spki(&spki).unwrap().key_id(), staged);
        assert!(store.stage(T0).is_err());
        drop(store);
        let store = KeyStore::open(&path).unwrap();
        assert_eq!(store.manifest(T0).unwrap(), before);
        assert_eq!(store.spki(staged).unwrap(), spki);
        assert!(store.spki([0; 32]).is_err());
    }

    #[test]
    fn failed_insert_is_atomic() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path) = fresh();
        let store = KeyStore::open(&path).unwrap();
        let before = store.manifest(T0).unwrap();
        let snapshot = raw_snapshot(&path);
        store
            .connection()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_stage AFTER INSERT ON keys
                 BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END;",
            )
            .unwrap();
        let error = store.stage(T0).unwrap_err();
        assert!(
            error.to_string().contains("unexpected schema objects"),
            "{error:#}"
        );
        assert_eq!(store.manifest(T0).unwrap(), before);
        assert!(raw_snapshot(&path) == snapshot);
        remove_test_schema_objects(&path);
        drop(store);
        assert_eq!(KeyStore::open(&path).unwrap().manifest(T0).unwrap(), before);
        assert!(raw_snapshot(&path) == snapshot);
    }

    fn assert_trigger_stage_rolls_back(trigger: &str, now: u64) {
        let (_dir, path) = fresh();
        let store = KeyStore::open(&path).unwrap();
        let before = store.manifest(now).unwrap();
        let snapshot = raw_snapshot(&path);
        store.connection().unwrap().execute_batch(trigger).unwrap();
        let error = store.stage(now).unwrap_err();
        assert!(
            error.to_string().contains("unexpected schema objects"),
            "{error:#}"
        );
        assert_eq!(store.manifest(now).unwrap(), before);
        assert!(raw_snapshot(&path) == snapshot);
        remove_test_schema_objects(&path);
        drop(store);
        let reopened = KeyStore::open(&path).unwrap();
        assert_eq!(reopened.manifest(now).unwrap(), before);
        assert!(raw_snapshot(&path) == snapshot);
    }

    #[test]
    fn ignored_insert_is_rejected_and_rolled_back() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        assert_trigger_stage_rolls_back(
            "CREATE TRIGGER ignore_stage BEFORE INSERT ON keys
             BEGIN SELECT RAISE(IGNORE); END;",
            T0,
        );
    }

    #[test]
    fn trigger_activation_is_rejected_and_rolled_back() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        // At 7,300 seconds, a candidate that was scheduled for hour 1 would
        // already have superseded the first key.
        assert_trigger_stage_rolls_back(
            "CREATE TRIGGER activate_stage AFTER INSERT ON keys
             BEGIN UPDATE keys SET activation_hour=(SELECT MAX(activation_hour)+1 FROM keys)
                   WHERE key_id=NEW.key_id; END;",
            7_300,
        );
    }

    #[test]
    fn stage_refusals_and_high_water() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, _staged) = staged_fixture();
        let store = KeyStore::open(&path).unwrap();
        let before = store.manifest(T0).unwrap();
        assert_eq!(before.high_water, T0);
        let staged_error = store.stage(T0).unwrap_err().to_string();
        assert!(staged_error.contains("staged key already exists"));
        let behind = store.stage(T0 - 1).unwrap_err().to_string();
        assert!(behind.contains("high-water"), "{behind}");
        assert_eq!(store.manifest(T0).unwrap(), before);
    }

    #[test]
    fn stage_refused_while_scheduled_and_allowed_when_predecessor_retired_for_issuance() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, _k1) = scheduled_fixture();
        let store = KeyStore::open(&path).unwrap();
        let scheduled = store.stage(T0 + 1).unwrap_err().to_string();
        assert!(scheduled.contains("a scheduled key exists"), "{scheduled}");
        // At `S`, the second key takes over issuance, so another key can be staged
        // even though the first key retains its private material.
        let id = store.stage(S).unwrap();
        let manifest = store.manifest(S).unwrap();
        assert_eq!(manifest.high_water, S);
        assert_eq!(state(&manifest, id), KeyState::Staged);
        assert_eq!(manifest.keys.len(), 3);
    }

    #[test]
    fn signing_keys_refuse_below_high_water_and_exclude_staged() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, staged) = staged_fixture();
        let store = KeyStore::open(&path).unwrap();
        assert!(store
            .signing_keys(T0 - 1)
            .err()
            .expect("below high-water must refuse")
            .to_string()
            .contains("high-water"));
        let keys = store.signing_keys(T0).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].activation_hour, 0);
        assert_ne!(keys[0].public.key_id(), staged);
    }

    #[test]
    fn signing_keys_sorted_by_hour_across_schedule() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, k1) = scheduled_fixture();
        let store = KeyStore::open(&path).unwrap();
        let keys = store.signing_keys(T0).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].activation_hour, 0);
        assert_eq!(keys[1].activation_hour, H);
        assert_eq!(keys[1].public.key_id(), k1);
    }

    #[test]
    fn schedule_refusals() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, staged) = staged_fixture();
        let store = KeyStore::open(&path).unwrap();
        let before = store.manifest(T0).unwrap();
        // Scheduling fails if the activation time is not on an hour boundary
        // or is at or before `now`.
        assert!(store.schedule_activation(S + 1, T0).is_err());
        assert!(store
            .schedule_activation(SECONDS_PER_HOUR, SECONDS_PER_HOUR)
            .is_err());
        assert!(store
            .schedule_activation(SECONDS_PER_HOUR, 2 * SECONDS_PER_HOUR)
            .is_err());
        // A time below the high-water mark blocks scheduling before the candidate is checked.
        let behind = store
            .schedule_activation(S, T0 - 1)
            .unwrap_err()
            .to_string();
        assert!(behind.contains("high-water"), "{behind}");
        // Rejected requests leave the high-water mark unchanged and the candidate staged.
        assert_eq!(store.manifest(T0).unwrap(), before);
        assert_eq!(state(&before, staged), KeyState::Staged);
        drop(store);
        // Scheduling also fails in a store with neither a staged nor a scheduled key.
        let (_dir2, path2) = fresh();
        let store2 = KeyStore::open(&path2).unwrap();
        let none = store2.schedule_activation(S, T0).unwrap_err().to_string();
        assert!(none.contains("no staged or scheduled key"), "{none}");
    }

    #[test]
    fn schedule_refused_while_predecessor_still_holds_private_material() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, _k1) = scheduled_fixture();
        let store = KeyStore::open(&path).unwrap();
        // The first key retains its private material after `S`, so the staged
        // key cannot be scheduled.
        let id = store.stage(S + 1).unwrap();
        let error = store
            .schedule_activation(S + SECONDS_PER_HOUR, S + 1)
            .unwrap_err()
            .to_string();
        assert!(error.contains("retire it first"), "{error}");
        assert_eq!(state(&store.manifest(S + 1).unwrap(), id), KeyState::Staged);
    }

    #[test]
    fn schedule_refused_after_activation_time_and_reschedule_before_it_allowed() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, k1) = scheduled_fixture();
        let store = KeyStore::open(&path).unwrap();
        // Before `S`, moving activation to an earlier hour succeeds if that
        // hour is still in the future.
        let earlier = 5 * SECONDS_PER_HOUR;
        assert_eq!(store.schedule_activation(earlier, T0).unwrap(), k1);
        assert_eq!(store.manifest(T0).unwrap().keys[1].activation_hour, Some(5));
        // Move activation back to `S` so that the test can check that
        // rescheduling fails once the key has activated.
        assert_eq!(store.schedule_activation(S, T0).unwrap(), k1);
        let refused = store
            .schedule_activation(S + SECONDS_PER_HOUR, S)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("retire it first"), "{refused}");
        // The failed request leaves the high-water mark at `T0`.
        assert_eq!(store.manifest(S).unwrap().high_water, T0);
    }

    #[test]
    fn schedule_same_time_is_successful_no_op_that_advances_high_water() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, k1) = scheduled_fixture();
        let store = KeyStore::open(&path).unwrap();
        assert_eq!(store.schedule_activation(S, T0 + 1).unwrap(), k1);
        let manifest = store.manifest(T0 + 1).unwrap();
        assert_eq!(manifest.high_water, T0 + 1);
        assert_eq!(manifest.keys[1].activation_hour, Some(H));
    }

    #[test]
    fn activation_range_matches_origin_i64_deadline_bound() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, staged) = staged_fixture();
        let store = KeyStore::open(&path).unwrap();
        let before = store.manifest(T0).unwrap();
        let error = store
            .schedule_activation((MAX_HOUR + 1) * SECONDS_PER_HOUR, T0)
            .unwrap_err();
        assert!(error.to_string().contains("out of range"), "{error:#}");
        assert_eq!(store.manifest(T0).unwrap(), before);
        assert_eq!(
            store
                .schedule_activation(MAX_HOUR * SECONDS_PER_HOUR, T0)
                .unwrap(),
            staged
        );
        drop(store);
        assert_eq!(
            KeyStore::open(&path).unwrap().manifest(T0).unwrap().keys[1].activation_hour,
            Some(MAX_HOUR)
        );
        let db = connect(&path, false).unwrap();
        db.execute(
            "UPDATE keys SET activation_hour=?1 WHERE key_id=?2",
            params![(MAX_HOUR + 1) as i64, staged.as_slice()],
        )
        .unwrap();
        drop(db);
        assert!(KeyStore::open(&path).is_err());
    }

    #[test]
    fn ignored_reschedule_update_rolls_back() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, _scheduled) = scheduled_fixture();
        let store = KeyStore::open(&path).unwrap();
        let now = T0 + 9;
        let before = store.manifest(now).unwrap();
        let snapshot = raw_snapshot(&path);
        store
            .connection()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER ignore_schedule BEFORE UPDATE ON keys
                 BEGIN SELECT RAISE(IGNORE); END;",
            )
            .unwrap();
        let error = store
            .schedule_activation(S + SECONDS_PER_HOUR, now)
            .unwrap_err();
        assert!(
            error.to_string().contains("unexpected schema objects"),
            "{error:#}"
        );
        assert_eq!(store.manifest(now).unwrap(), before);
        assert!(raw_snapshot(&path) == snapshot);
        remove_test_schema_objects(&path);
        drop(store);
        assert_eq!(
            KeyStore::open(&path).unwrap().manifest(now).unwrap(),
            before
        );
        assert!(raw_snapshot(&path) == snapshot);
    }

    #[test]
    fn schedule_postcondition_rejects_injected_unschedule() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, staged) = staged_fixture();
        let store = KeyStore::open(&path).unwrap();
        let before = store.manifest(T0).unwrap();
        let snapshot = raw_snapshot(&path);
        store
            .connection()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER unschedule AFTER UPDATE ON keys
                 BEGIN UPDATE keys SET activation_hour=NULL WHERE key_id=NEW.key_id; END;",
            )
            .unwrap();
        let error = store.schedule_activation(S, T0).unwrap_err().to_string();
        assert!(error.contains("unexpected schema objects"), "{error}");
        assert_eq!(store.manifest(T0).unwrap(), before);
        assert_eq!(state(&before, staged), KeyState::Staged);
        assert!(raw_snapshot(&path) == snapshot);
        remove_test_schema_objects(&path);
        drop(store);
        assert_eq!(KeyStore::open(&path).unwrap().manifest(T0).unwrap(), before);
        assert!(raw_snapshot(&path) == snapshot);
    }

    #[test]
    fn schedule_postcondition_revalidates_structure_and_rolls_back() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, _k1) = scheduled_fixture();
        let k0 = genesis_id(&KeyStore::open(&path).unwrap(), T0);
        let (candidate, spki, pkcs8) = {
            let known = KeyStore::open(&path).unwrap();
            let manifest = known.manifest(T0).unwrap();
            let used: Vec<u8> = manifest.keys.iter().map(|k| k.key_id[31]).collect();
            material_avoiding(&used)
        };
        // Insert a staged key directly because `stage` rejects it when a scheduled
        // key exists, even though that combination passes structural validation.
        {
            let db = connect(&path, false).unwrap();
            db.execute(
                "INSERT INTO keys (key_id, spki, pkcs8, activation_hour) VALUES (?1, ?2, ?3, NULL)",
                params![candidate.as_slice(), spki, pkcs8],
            )
            .unwrap();
        }
        let store = KeyStore::open(&path).unwrap();
        let before = store.manifest(T0).unwrap();
        assert_eq!(before.keys.len(), 3);
        // Scheduling fails if the staged key would activate at or before the scheduled key.
        let order = store.schedule_activation(S, T0).unwrap_err().to_string();
        assert!(
            order.contains("must follow every existing activation"),
            "{order}"
        );
        // Scheduling after that hour gives three keys with private material an
        // activation hour, so validation after the update must reject the change.
        let error = store
            .schedule_activation(S + SECONDS_PER_HOUR, T0)
            .unwrap_err()
            .to_string();
        assert!(error.contains("more than two"), "{error}");
        assert_eq!(store.manifest(T0).unwrap(), before);
        assert_eq!(state(&before, candidate), KeyState::Staged);
        assert_eq!(state(&before, k0), KeyState::Active);
    }

    #[test]
    fn schedule_advances_high_water_only_on_success() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, _staged) = staged_fixture();
        let store = KeyStore::open(&path).unwrap();
        assert!(store.schedule_activation(S + 1, T0 + 7).is_err());
        assert_eq!(store.manifest(T0 + 7).unwrap().high_water, T0);
        store.schedule_activation(S, T0 + 7).unwrap();
        assert_eq!(store.manifest(T0 + 7).unwrap().high_water, T0 + 7);
    }

    #[test]
    fn schedule_trigger_failure_rolls_back_all_writes() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, _staged) = staged_fixture();
        let store = KeyStore::open(&path).unwrap();
        let before = store.manifest(T0).unwrap();
        let snapshot = raw_snapshot(&path);
        store
            .connection()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_schedule AFTER UPDATE ON keys
                 BEGIN SELECT RAISE(ABORT, 'injected update failure'); END;",
            )
            .unwrap();
        let error = store.schedule_activation(S, T0 + 9).unwrap_err();
        assert!(
            error.to_string().contains("unexpected schema objects"),
            "{error:#}"
        );
        assert_eq!(store.manifest(T0).unwrap(), before);
        assert!(raw_snapshot(&path) == snapshot);
        remove_test_schema_objects(&path);
        drop(store);
        assert_eq!(KeyStore::open(&path).unwrap().manifest(T0).unwrap(), before);
        assert!(raw_snapshot(&path) == snapshot);
    }

    fn assert_retire_refused(store: &KeyStore, id: [u8; 32], now: u64, expected_error: &str) {
        let before = validate(&store.connection().unwrap()).unwrap();
        let error = store.retire(id, now).unwrap_err();
        assert!(error.to_string().contains(expected_error), "{error:#}");
        assert!(
            validate(&store.connection().unwrap()).unwrap() == before,
            "refused retirement changed stored state"
        );
    }

    #[test]
    fn retire_refuses_active_staged_and_unknown_keys() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, staged) = staged_fixture();
        let store = KeyStore::open(&path).unwrap();
        let k0 = genesis_id(&store, T0);
        let before = store.manifest(T0).unwrap();
        assert_retire_refused(&store, k0, T0, "not been superseded");
        assert_retire_refused(&store, staged, T0, "staged key");
        assert_retire_refused(&store, [0; 32], T0, "unknown key ID");
        drop(store);
        assert_eq!(KeyStore::open(&path).unwrap().manifest(T0).unwrap(), before);
    }

    #[test]
    fn retire_requires_successor_to_be_active_by_local_clock() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, k1) = scheduled_fixture();
        let store = KeyStore::open(&path).unwrap();
        let k0 = genesis_id(&store, S - 1);
        assert_retire_refused(&store, k0, S - 1, "not been superseded");
        assert_retire_refused(&store, k1, S - 1, "not been superseded");
        // The issuer allows retirement at the exact second that the successor activates.
        store.retire(k0, S).unwrap();
        assert_eq!(state(&store.manifest(S).unwrap(), k0), KeyState::Retired);
        assert_retire_refused(&store, k1, S, "not been superseded");
    }

    #[test]
    fn retire_refuses_below_high_water_despite_active_successor() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, _k1) = scheduled_fixture();
        let store = KeyStore::open(&path).unwrap();
        let k0 = genesis_id(&store, S);
        store.stage(S + 1).unwrap();
        assert_retire_refused(&store, k0, S, "high-water");
    }

    #[test]
    fn retirement_preserves_public_row_and_other_keys_across_reopen() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, k1) = scheduled_fixture();
        let store = KeyStore::open(&path).unwrap();
        let k0 = genesis_id(&store, S);
        let spki = store.spki(k0).unwrap();
        let mut expected = validate(&store.connection().unwrap()).unwrap();
        expected.high_water = S;
        expected
            .rows
            .iter_mut()
            .find(|r| r.key_id == k0)
            .unwrap()
            .pkcs8 = None;

        store.retire(k0, S).unwrap();
        assert!(validate(&store.connection().unwrap()).unwrap() == expected);
        let manifest = store.manifest(S).unwrap();
        assert_eq!(manifest.high_water, S);
        let retired = manifest.keys.iter().find(|k| k.key_id == k0).unwrap();
        assert_eq!(retired.state, KeyState::Retired);
        assert!(!retired.has_private);
        assert_eq!(retired.activation_hour, Some(0));
        assert_eq!(retired.spki, spki);
        assert_eq!(retired.issuance_end, Some(S));
        assert_eq!(retired.acceptance_deadline, Some(S + ACCEPTANCE_GRACE));
        assert_eq!(store.spki(k0).unwrap(), spki);
        let signing = store.signing_keys(S).unwrap();
        assert_eq!(signing.len(), 1);
        assert_eq!(signing[0].public.key_id(), k1);
        assert_retire_refused(&store, k0, S + 1, "already retired");
        drop(store);

        let reopened = KeyStore::open(&path).unwrap();
        assert!(validate(&reopened.connection().unwrap()).unwrap() == expected);
        assert_eq!(reopened.manifest(S).unwrap(), manifest);
        assert_eq!(reopened.signing_keys(S).unwrap()[0].public.key_id(), k1);
        assert_retire_refused(&reopened, k0, S + 1, "already retired");
    }

    #[test]
    fn retirement_frees_suffix_for_staging_and_next_activation() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        // Choose the first key from a pair that has matching suffixes so that
        // the test does not have to search for a particular suffix.
        let mut seen = std::collections::HashMap::<u8, SecretKey>::new();
        let (old, candidate, pkcs8) = loop {
            let key = SecretKey::generate().unwrap();
            let id = key.public_key().unwrap().key_id();
            if let Some(old) = seen.remove(&id[31]) {
                break (old, id, key.to_pkcs8().unwrap());
            }
            seen.insert(id[31], key);
        };
        let public = old.public_key().unwrap();
        let k0 = public.key_id();
        assert_ne!(candidate, k0);
        let (_dir, path) = fresh();
        let store = KeyStore::open(&path).unwrap();
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE keys SET key_id=?1, spki=?2, pkcs8=?3 WHERE activation_hour=0",
                params![k0.as_slice(), public.to_spki(), old.to_pkcs8().unwrap()],
            )
            .unwrap();
        let k1 = store.stage(T0).unwrap();
        store.schedule_activation(S, T0).unwrap();
        // Use a fixed generator so that every staging attempt gets the candidate
        // with the colliding suffix.
        let before = store.manifest(S).unwrap();
        let error = store
            .stage_with_generator(S, || Ok(SecretKey::from_pkcs8(&pkcs8)?))
            .unwrap_err();
        assert!(error.to_string().contains("after 16 attempts"), "{error:#}");
        assert_eq!(store.manifest(S).unwrap(), before);

        store.retire(k0, S).unwrap();
        let staged = store
            .stage_with_generator(S, || Ok(SecretKey::from_pkcs8(&pkcs8)?))
            .unwrap();
        assert_eq!(staged, candidate);
        assert_eq!(staged[31], k0[31]);
        assert_eq!(state(&store.manifest(S).unwrap(), staged), KeyState::Staged);
        assert_eq!(
            store.schedule_activation(S + SECONDS_PER_HOUR, S).unwrap(),
            staged
        );
        let manifest = store.manifest(S).unwrap();
        assert_eq!(state(&manifest, k0), KeyState::Retired);
        assert_eq!(state(&manifest, k1), KeyState::Active);
        assert_eq!(state(&manifest, staged), KeyState::Scheduled);
        drop(store);
        assert_eq!(
            KeyStore::open(&path).unwrap().manifest(S).unwrap(),
            manifest
        );
    }

    #[test]
    fn retirement_unblocks_already_staged_rotation() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, _k1) = scheduled_fixture();
        let store = KeyStore::open(&path).unwrap();
        let k0 = genesis_id(&store, S);
        let staged = store.stage(S).unwrap();
        let before = store.manifest(S).unwrap();
        let error = store
            .schedule_activation(S + SECONDS_PER_HOUR, S)
            .unwrap_err();
        assert!(error.to_string().contains("retire it first"), "{error:#}");
        assert_eq!(store.manifest(S).unwrap(), before);
        store.retire(k0, S).unwrap();
        assert_eq!(
            store.schedule_activation(S + SECONDS_PER_HOUR, S).unwrap(),
            staged
        );
    }

    fn assert_trigger_retire_rolls_back(trigger: &str) {
        let (_dir, path, _k1) = scheduled_fixture();
        let store = KeyStore::open(&path).unwrap();
        let now = S + 9;
        let k0 = genesis_id(&store, now);
        let before = validate(&store.connection().unwrap()).unwrap();
        store.connection().unwrap().execute_batch(trigger).unwrap();
        assert_retire_refused(&store, k0, now, "unexpected schema objects");
        assert!(raw_snapshot(&path) == before);
        remove_test_schema_objects(&path);
        drop(store);
        let reopened = KeyStore::open(&path).unwrap();
        assert!(
            validate(&reopened.connection().unwrap()).unwrap() == before,
            "failed retirement changed stored state after reopen"
        );
    }

    #[test]
    fn ignored_retirement_update_rolls_back() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        assert_trigger_retire_rolls_back(
            "CREATE TRIGGER ignore_retire BEFORE UPDATE OF pkcs8 ON keys
             BEGIN SELECT RAISE(IGNORE); END;",
        );
    }

    #[test]
    fn retirement_trigger_nulling_another_key_rolls_back() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        assert_trigger_retire_rolls_back(
            "CREATE TRIGGER null_another AFTER UPDATE OF pkcs8 ON keys
             WHEN OLD.activation_hour=0
             BEGIN UPDATE keys SET pkcs8=NULL WHERE activation_hour=10; END;",
        );
    }

    #[test]
    fn retirement_postconditions_reject_other_valid_changes() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        for trigger in [
            "CREATE TRIGGER change_target AFTER UPDATE OF pkcs8 ON keys
                 BEGIN UPDATE keys SET activation_hour=1 WHERE key_id=NEW.key_id; END;",
            "CREATE TRIGGER restore_private AFTER UPDATE OF pkcs8 ON keys
                 WHEN NEW.pkcs8 IS NULL
                 BEGIN UPDATE keys SET pkcs8=OLD.pkcs8 WHERE key_id=NEW.key_id; END;",
            "CREATE TRIGGER change_another AFTER UPDATE OF pkcs8 ON keys
                 BEGIN UPDATE keys SET activation_hour=11 WHERE activation_hour=10; END;",
            "CREATE TRIGGER ignore_high_water BEFORE UPDATE ON metadata
                 BEGIN SELECT RAISE(IGNORE); END;",
        ] {
            assert_trigger_retire_rolls_back(trigger);
        }
    }

    #[test]
    fn unexpected_schema_objects_refuse_open_and_live_mutations() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        for object in [
            "CREATE TRIGGER ignore_keys BEFORE INSERT ON keys
             BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE VIEW extra AS SELECT key_id FROM keys;",
        ] {
            let (_dir, path) = fresh();
            let store = KeyStore::open(&path).unwrap();
            let k0 = genesis_id(&store, T0);
            let before = raw_snapshot(&path);
            store.connection().unwrap().execute_batch(object).unwrap();
            for error in [
                store.stage(T0).unwrap_err(),
                store.schedule_activation(S, T0).unwrap_err(),
                store.retire(k0, T0).unwrap_err(),
            ] {
                assert!(
                    error.to_string().contains("unexpected schema objects"),
                    "{error:#}"
                );
                assert!(raw_snapshot(&path) == before);
            }
            drop(store);
            let error = KeyStore::open(&path)
                .err()
                .expect("unexpected schema objects must refuse open");
            assert!(
                error.to_string().contains("unexpected schema objects"),
                "{error:#}"
            );
            assert!(raw_snapshot(&path) == before);
            remove_test_schema_objects(&path);
            drop(KeyStore::open(&path).unwrap());
            assert!(raw_snapshot(&path) == before);
        }
    }

    #[test]
    fn retirement_postcondition_requires_unchanged_active_key() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let before = Snapshot {
            high_water: S,
            rows: vec![row(1, 1, true, Some(0)), row(2, 2, true, Some(H))],
        };
        let after = Snapshot {
            high_water: S,
            rows: vec![row(1, 1, false, Some(0)), row(2, 2, true, Some(H))],
        };
        ensure_retirement(&before, &after, before.rows[0].key_id, S).unwrap();
        let after = Snapshot {
            high_water: S,
            rows: vec![row(1, 1, true, Some(0)), row(2, 2, false, Some(H))],
        };
        let error = ensure_retirement(&before, &after, before.rows[1].key_id, S).unwrap_err();
        assert!(
            error.to_string().contains("retirement changed active key"),
            "{error:#}"
        );
    }

    #[test]
    fn busy_checkpoint_does_not_fail_committed_retirement() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (_dir, path, _k1) = scheduled_fixture();
        let store = KeyStore::open(&path).unwrap();
        let k0 = genesis_id(&store, S);
        store
            .connection()
            .unwrap()
            .busy_timeout(std::time::Duration::ZERO)
            .unwrap();
        // Hold a read transaction open so that the `TRUNCATE` checkpoint
        // returns busy immediately.
        let reader = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let count: i64 = reader
            .query_row("SELECT COUNT(*) FROM keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
        store.retire(k0, S).unwrap();
        let busy: i64 = store
            .connection()
            .unwrap()
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))
            .unwrap();
        assert_eq!(busy, 1);
        let manifest = store.manifest(S).unwrap();
        assert_eq!(state(&manifest, k0), KeyState::Retired);
        drop(reader);
        drop(store);
        assert_eq!(
            KeyStore::open(&path).unwrap().manifest(S).unwrap(),
            manifest
        );
    }
}
