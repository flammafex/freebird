//! Crash-durable, single-process invitation admission.
//!
//! Restore procedure: stop the issuer before restoring the database, then open
//! the store for maintenance and rotate its generation before reopening the
//! issuer. Unannounced database rollback cannot be detected by this store.

use anyhow::{ensure, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use fs2::FileExt;
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

const SCHEMA: &str =
    "CREATE TABLE invitations (invite_hash BLOB PRIMARY KEY NOT NULL, expires_at INTEGER NOT NULL)";

struct State {
    db: Connection,
    generation: [u8; 32],
    healthy: bool,
}

/// Holds the exclusive OS lock until dropped. Deliberately does not implement Debug.
pub struct AdmissionStore {
    state: Mutex<State>,
    generation_path: PathBuf,
    _lock: File,
}

fn lock(db: &Path) -> Result<File> {
    let mut name: OsString = db.as_os_str().to_owned();
    name.push(".lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(PathBuf::from(name))?;
    FileExt::try_lock_exclusive(&file).context("admission store already locked")?;
    Ok(file)
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_parent(path: &Path) -> Result<()> {
    File::open(parent(path))?.sync_all()?;
    Ok(())
}

fn random_secret() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    OsRng.try_fill_bytes(&mut bytes)?;
    Ok(bytes)
}

fn write_generation(path: &Path, secret: &[u8; 32]) -> Result<()> {
    let suffix = Base64UrlUnpadded::encode_string(&random_secret()?);
    let tmp = parent(path).join(format!(".admission-generation-{suffix}"));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(secret)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn configure(db: &Connection, initializing: bool) -> Result<()> {
    if initializing {
        let mode: String = db.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        ensure!(mode.eq_ignore_ascii_case("wal"), "WAL unavailable");
    }
    let mode: String = db.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    ensure!(mode.eq_ignore_ascii_case("wal"), "database is not WAL");
    db.pragma_update(None, "synchronous", "FULL")?;
    let synchronous: i64 = db.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    ensure!(synchronous == 2, "FULL synchronization unavailable");
    Ok(())
}

impl AdmissionStore {
    /// Creates fresh state only. Partial initialization must be repaired manually,
    /// never by retrying initialization over existing files.
    pub fn initialize(db_path: impl AsRef<Path>, generation_path: impl AsRef<Path>) -> Result<()> {
        let db_path = db_path.as_ref();
        let generation_path = generation_path.as_ref();
        ensure!(db_path != generation_path, "state paths must differ");
        let _lock = lock(db_path)?;
        ensure!(
            !db_path.try_exists()? && !generation_path.try_exists()?,
            "admission state already exists"
        );
        // Reserve the database before writing either piece of usable state.
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(db_path)?
            .sync_all()?;
        sync_parent(db_path)?;
        write_generation(generation_path, &random_secret()?)?;
        let mut db = Connection::open(db_path)?;
        configure(&db, true)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        tx.commit()?;
        db.close().map_err(|(_, e)| e)?;
        sync_parent(db_path)?;
        Ok(())
    }

    pub fn open(db_path: impl AsRef<Path>, generation_path: impl AsRef<Path>) -> Result<Self> {
        let db_path = db_path.as_ref();
        let generation_path = generation_path.as_ref();
        let lock = lock(db_path)?;
        let mut generation = [0; 32];
        let mut file = File::open(generation_path)?;
        ensure!(file.metadata()?.len() == 32, "invalid generation length");
        file.read_exact(&mut generation)?;
        let db = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure(&db, false)?;
        let integrity: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        ensure!(integrity == "ok", "database integrity check failed");
        let schema: String = db.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='invitations'",
            [],
            |r| r.get(0),
        )?;
        ensure!(schema == SCHEMA, "invalid invitation schema");
        Ok(Self {
            state: Mutex::new(State {
                db,
                generation,
                healthy: true,
            }),
            generation_path: generation_path.to_owned(),
            _lock: lock,
        })
    }

    fn state(&self) -> Result<MutexGuard<'_, State>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("store poisoned"))?;
        ensure!(
            state.healthy,
            "store requires maintenance after failed rotation"
        );
        Ok(state)
    }

    pub fn provision(&self, now: i64) -> Result<String> {
        let expires_at = now.checked_add(86400).context("expiration overflow")?;
        let raw = random_secret()?;
        let mut state = self.state()?;
        let hash = invitation_hash(&state.generation, &raw);
        let tx = state
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO invitations(invite_hash, expires_at) VALUES (?1, ?2)",
            params![hash.as_slice(), expires_at],
        )?;
        tx.commit()?;
        Ok(Base64UrlUnpadded::encode_string(&raw))
    }

    pub fn consume(&self, code: &str, now: i64) -> Result<bool> {
        if code.len() != 43 || !code.is_ascii() {
            return Ok(false);
        }
        let raw = match Base64UrlUnpadded::decode_vec(code) {
            Ok(raw) if raw.len() == 32 && Base64UrlUnpadded::encode_string(&raw) == code => raw,
            _ => return Ok(false),
        };
        let mut state = self.state()?;
        let hash = invitation_hash(&state.generation, &raw);
        let tx = state
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let deleted = tx.execute(
            "DELETE FROM invitations WHERE invite_hash=?1 AND expires_at>?2",
            params![hash.as_slice(), now],
        )?;
        tx.commit()?;
        Ok(deleted == 1)
    }

    /// Maintenance only; caller must keep the issuer stopped during restore.
    /// A failed rotation disables this instance, including ambiguous fsync failures.
    pub fn rotate_generation_for_restore(&self) -> Result<()> {
        let mut state = self.state()?;
        let generation = random_secret()?;
        state.healthy = false;
        write_generation(&self.generation_path, &generation)?;
        state.generation = generation;
        let tx = state
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM invitations", [])?;
        tx.commit()?;
        state.healthy = true;
        Ok(())
    }
}

fn invitation_hash(generation: &[u8; 32], raw: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(generation)
        .chain_update(raw)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("admission.db");
        let generation = dir.path().join("generation");
        AdmissionStore::initialize(&db, &generation).unwrap();
        (dir, db, generation)
    }

    #[test]
    fn init_open_lock_and_restart() {
        let (_dir, db, generation) = setup();
        assert!(AdmissionStore::initialize(&db, &generation).is_err());
        let store = AdmissionStore::open(&db, &generation).unwrap();
        assert!(AdmissionStore::open(&db, &generation).is_err());
        let used = store.provision(100).unwrap();
        let unused = store.provision(100).unwrap();
        assert!(store.consume(&used, 100).unwrap());
        assert!(!store.consume(&used, 100).unwrap());
        drop(store);
        let store = AdmissionStore::open(&db, &generation).unwrap();
        assert!(!store.consume(&used, 100).unwrap());
        assert!(store.consume(&unused, 100).unwrap());
    }

    #[test]
    fn concurrent_one_winner() {
        let (_dir, db, generation) = setup();
        let store = Arc::new(AdmissionStore::open(db, generation).unwrap());
        let code = store.provision(0).unwrap();
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let store = store.clone();
                let code = code.clone();
                std::thread::spawn(move || store.consume(&code, 0).unwrap())
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .filter_map(|t| t.join().unwrap().then_some(()))
                .count(),
            1
        );
    }

    #[test]
    fn expiry_and_malformed() {
        let (_dir, db, generation) = setup();
        let store = AdmissionStore::open(db, generation).unwrap();
        let code = store.provision(10).unwrap();
        assert_eq!(code.len(), 43);
        assert!(!store.consume(&code, 86410).unwrap());
        let code = store.provision(10).unwrap();
        assert!(store.consume(&code, 86409).unwrap());
        for code in [
            "",
            "é",
            &"A".repeat(42),
            &"A".repeat(44),
            &format!("{}B", "A".repeat(42)),
            &"!".repeat(43),
        ] {
            assert!(!store.consume(code, 0).unwrap());
        }
        assert!(store.provision(i64::MAX).is_err());
    }

    #[test]
    fn rotation_invalidates_and_persists() {
        let (_dir, db, generation) = setup();
        let store = AdmissionStore::open(&db, &generation).unwrap();
        let old = store.provision(0).unwrap();
        store.rotate_generation_for_restore().unwrap();
        assert!(!store.consume(&old, 0).unwrap());
        let new = store.provision(0).unwrap();
        drop(store);
        let store = AdmissionStore::open(db, generation).unwrap();
        assert!(!store.consume(&old, 0).unwrap());
        assert!(store.consume(&new, 0).unwrap());
    }

    #[test]
    fn missing_and_corrupt_fail_closed() {
        let (dir, db, generation) = setup();
        assert!(AdmissionStore::open(dir.path().join("missing"), &generation).is_err());
        assert!(AdmissionStore::open(&db, dir.path().join("missing-secret")).is_err());
        fs::write(&generation, [0; 31]).unwrap();
        assert!(AdmissionStore::open(&db, &generation).is_err());
        fs::write(&generation, [0; 32]).unwrap();
        fs::write(&db, b"not sqlite").unwrap();
        assert!(AdmissionStore::open(&db, &generation).is_err());
    }
}
