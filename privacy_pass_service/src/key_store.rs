//! Authoritative staging-only key state. No activation, rotation, or retirement.
//! The persistent sidecar must never be unlinked: its OS lock is held for the
//! lifetime of this store, and is released automatically after process death.
//! Restoring an older database cannot be detected here.

use anyhow::{ensure, Context, Result};
use freebird_crypto::privacy_pass::{PublicKey, SecretKey};
use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

const SCHEMA: &str = "
CREATE TABLE metadata (version INTEGER NOT NULL, active_key_id BLOB NOT NULL);
CREATE TABLE keys (key_id BLOB PRIMARY KEY NOT NULL, spki BLOB NOT NULL,
                   pkcs8 BLOB NOT NULL);
";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyStatus {
    pub active_key_id: [u8; 32],
    pub staged_key_id: Option<[u8; 32]>,
}

/// Owns an exclusive lifetime lock independent of admission state.
pub struct KeyStore {
    db: Mutex<Connection>,
    _lock: File,
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn lock(path: &Path) -> Result<File> {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let path = PathBuf::from(name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
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
    Ok(db)
}

fn validate(db: &Connection) -> Result<KeyStatus> {
    let metadata = db
        .prepare("SELECT version, active_key_id FROM metadata")?
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(metadata.len() == 1, "expected exactly one metadata row");
    ensure!(metadata[0].0 == 1, "unsupported key schema version");
    let active: [u8; 32] = metadata[0]
        .1
        .as_slice()
        .try_into()
        .context("invalid active key ID length")?;
    let mut statement = db.prepare("SELECT key_id, spki, pkcs8 FROM keys")?;
    let mut rows = statement.query([])?;
    let mut ids = Vec::<[u8; 32]>::new();
    while let Some(row) = rows.next()? {
        let id: Vec<u8> = row.get(0)?;
        let id: [u8; 32] = id.as_slice().try_into().context("invalid key ID length")?;
        let spki: Vec<u8> = row.get(1)?;
        let pkcs8: Vec<u8> = row.get(2)?;
        let key = SecretKey::from_pkcs8(&pkcs8)?;
        ensure!(key.to_pkcs8()? == pkcs8, "noncanonical private key");
        let public = key.public_key()?;
        let parsed = PublicKey::from_spki(&spki)?;
        ensure!(
            parsed.to_spki() == spki.as_slice()
                && public.to_spki() == spki.as_slice()
                && public.key_id() == id,
            "key material mismatch"
        );
        ids.push(id);
    }
    validate_ids(&ids, active)
}

fn validate_ids(ids: &[[u8; 32]], active: [u8; 32]) -> Result<KeyStatus> {
    ensure!((1..=2).contains(&ids.len()), "invalid key cardinality");
    ensure!(ids.contains(&active), "active key missing");
    for (index, id) in ids.iter().enumerate() {
        ensure!(
            !ids[..index]
                .iter()
                .any(|old| old == id || old[31] == id[31]),
            "duplicate key ID or truncated key ID collision"
        );
    }
    Ok(KeyStatus {
        active_key_id: active,
        staged_key_id: ids.iter().copied().find(|id| id != &active),
    })
}

impl KeyStore {
    /// Explicit fresh creation only. A failed initialization leaves its reservation;
    /// retry never resets or regenerates uncertain state. Parent must already exist.
    pub fn initialize(path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let _lock = lock(path)?;
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
        tx.execute_batch(SCHEMA)?;
        tx.execute(
            "INSERT INTO keys VALUES (?1, ?2, ?3)",
            params![
                public.key_id().as_slice(),
                public.to_spki(),
                key.to_pkcs8()?
            ],
        )?;
        tx.execute(
            "INSERT INTO metadata VALUES (1, ?1)",
            [public.key_id().as_slice()],
        )?;
        validate(&tx)?;
        tx.commit()?;
        File::open(parent(path))?.sync_all()?;
        Ok(())
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let lock = lock(path)?;
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

    pub fn active_key(&self) -> Result<SecretKey> {
        let db = self.connection()?;
        let status = validate(&db)?;
        let bytes: Vec<u8> = db.query_row(
            "SELECT pkcs8 FROM keys WHERE key_id=?1",
            [status.active_key_id.as_slice()],
            |r| r.get(0),
        )?;
        Ok(SecretKey::from_pkcs8(&bytes)?)
    }

    pub fn status(&self) -> Result<KeyStatus> {
        let db = self.connection()?;
        validate(&db)
    }

    /// Commits one new candidate, never replacing an existing staged key.
    pub fn stage(&self) -> Result<[u8; 32]> {
        let mut db = self.connection()?;
        let status = validate(&db)?;
        ensure!(
            status.staged_key_id.is_none(),
            "a staged key already exists"
        );
        // Keep generation outside the transaction, while retaining exclusive
        // store ownership and the mutex. Never persist a colliding candidate.
        let mut candidate = None;
        for _ in 0..16 {
            let key = SecretKey::generate()?;
            if key.public_key()?.key_id()[31] != status.active_key_id[31] {
                candidate = Some(key);
                break;
            }
        }
        let key = candidate.context("unable to generate a noncolliding key after 16 attempts")?;
        let public = key.public_key()?;
        let id = public.key_id();
        let pkcs8 = key.to_pkcs8()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let before = validate(&tx)?;
        ensure!(
            before == status,
            "key status changed before staging transaction"
        );
        ensure!(
            before.staged_key_id.is_none(),
            "a staged key already exists"
        );
        ensure!(
            id[31] != before.active_key_id[31],
            "truncated key ID collision"
        );
        let inserted = tx.execute(
            "INSERT INTO keys VALUES (?1, ?2, ?3)",
            params![id.as_slice(), public.to_spki(), pkcs8],
        )?;
        ensure!(inserted == 1, "staging did not insert exactly one key");
        let after = validate(&tx)?;
        ensure!(
            after.active_key_id == before.active_key_id && after.staged_key_id == Some(id),
            "staging changed active key or failed to persist candidate"
        );
        tx.commit()?;
        Ok(id)
    }

    /// Public-only canonical SPKI export; private staged material is never exposed.
    pub fn staged_spki(&self) -> Result<Option<Vec<u8>>> {
        let db = self.connection()?;
        let status = validate(&db)?;
        status
            .staged_key_id
            .map(|id| {
                db.query_row(
                    "SELECT spki FROM keys WHERE key_id=?1",
                    [id.as_slice()],
                    |r| r.get(0),
                )
                .map_err(Into::into)
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.sqlite");
        KeyStore::initialize(&path).unwrap();
        (dir, path)
    }

    fn stage(store: &KeyStore) -> [u8; 32] {
        store.stage().expect("ordinary staging must succeed")
    }

    #[test]
    fn restart_staging_and_ownership() {
        let (_dir, path) = fresh();
        let store = KeyStore::open(&path).unwrap();
        assert!(KeyStore::open(&path).is_err());
        assert!(KeyStore::initialize(&path).is_err());
        let active = store.active_key().unwrap().to_pkcs8().unwrap();
        let before = store.status().unwrap();
        assert_eq!(before.staged_key_id, None);
        assert_eq!(store.staged_spki().unwrap(), None);
        let staged = stage(&store);
        assert_ne!(staged, before.active_key_id);
        assert_ne!(staged[31], before.active_key_id[31]);
        let spki = store.staged_spki().unwrap().unwrap();
        assert_eq!(PublicKey::from_spki(&spki).unwrap().key_id(), staged);
        assert!(store.stage().is_err());
        drop(store);
        let store = KeyStore::open(&path).unwrap();
        assert_eq!(store.active_key().unwrap().to_pkcs8().unwrap(), active);
        assert_eq!(store.status().unwrap().staged_key_id, Some(staged));
        assert_eq!(store.staged_spki().unwrap().unwrap(), spki);
    }

    #[test]
    fn corruption_fails_closed() {
        let (_dir, path) = fresh();
        // Roll each mutation back so the expensive valid key can be reused.
        let mut db = connect(&path, false).unwrap();
        for sql in [
            "UPDATE keys SET pkcs8=x'00'",
            "UPDATE keys SET spki=x'00'",
            "UPDATE keys SET key_id=zeroblob(32)",
            "UPDATE metadata SET version=2",
            "DELETE FROM metadata",
            "INSERT INTO metadata SELECT * FROM metadata",
            "UPDATE metadata SET active_key_id=zeroblob(32)",
            "UPDATE metadata SET active_key_id=x'00'",
            "DELETE FROM keys",
            // Remove the uniqueness constraint to exercise duplicate detection.
            "ALTER TABLE keys RENAME TO old_keys;
             CREATE TABLE keys AS SELECT * FROM old_keys;
             INSERT INTO keys SELECT * FROM old_keys;",
        ] {
            let tx = db.transaction().unwrap();
            tx.execute_batch(sql).unwrap();
            assert!(validate(&tx).is_err(), "{sql}");
            tx.rollback().unwrap();
        }
        db.execute("UPDATE keys SET pkcs8=x'00'", []).unwrap();
        drop(db);
        assert!(KeyStore::open(&path).is_err());
        assert!(KeyStore::initialize(&path).is_err());
    }

    #[test]
    fn failed_insert_is_atomic() {
        let (_dir, path) = fresh();
        let store = KeyStore::open(&path).unwrap();
        let before = store.status().unwrap();
        store
            .connection()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_stage AFTER INSERT ON keys
             BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END;",
            )
            .unwrap();
        assert!(store.stage().is_err());
        assert_eq!(store.status().unwrap(), before);
        assert_eq!(store.staged_spki().unwrap(), None);
        drop(store);
        assert_eq!(KeyStore::open(&path).unwrap().status().unwrap(), before);
    }

    fn assert_trigger_stage_rolls_back(trigger: &str, expected_error: &str) {
        let (_dir, path) = fresh();
        let store = KeyStore::open(&path).unwrap();
        let before = store.status().unwrap();
        let active = store.active_key().unwrap().to_pkcs8().unwrap();
        store.connection().unwrap().execute_batch(trigger).unwrap();
        let error = store.stage().unwrap_err();
        assert!(error.to_string().contains(expected_error), "{error:#}");
        assert_eq!(store.status().unwrap(), before);
        assert_eq!(store.staged_spki().unwrap(), None);
        drop(store);
        let reopened = KeyStore::open(&path).unwrap();
        assert_eq!(reopened.status().unwrap(), before);
        assert_eq!(reopened.staged_spki().unwrap(), None);
        assert_eq!(reopened.active_key().unwrap().to_pkcs8().unwrap(), active);
    }

    #[test]
    fn ignored_insert_is_rejected_and_rolled_back() {
        assert_trigger_stage_rolls_back(
            "CREATE TRIGGER ignore_stage BEFORE INSERT ON keys
             BEGIN SELECT RAISE(IGNORE); END;",
            "staging did not insert exactly one key",
        );
    }

    #[test]
    fn trigger_activation_is_rejected_and_rolled_back() {
        assert_trigger_stage_rolls_back(
            "CREATE TRIGGER activate_stage AFTER INSERT ON keys
             BEGIN UPDATE metadata SET active_key_id=NEW.key_id; END;",
            "staging changed active key or failed to persist candidate",
        );
    }

    #[test]
    fn missing_state_is_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent");
        assert!(KeyStore::open(&path).is_err());
        assert!(!path.exists());
        assert!(KeyStore::initialize(dir.path().join("missing/keys")).is_err());
    }

    #[test]
    fn id_cardinality_and_suffix_validation() {
        let active = [1; 32];
        let mut collision = [2; 32];
        collision[31] = active[31];
        assert!(validate_ids(&[active, collision], active).is_err());
        assert!(validate_ids(&[active, active], active).is_err());
        assert!(validate_ids(&[active, [2; 32], [3; 32]], active).is_err());
        assert!(validate_ids(&[], active).is_err());
        assert!(validate_ids(&[[2; 32]], active).is_err());
    }
}
