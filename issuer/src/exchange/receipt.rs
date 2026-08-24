// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{Context, Result};
use base64ct::Encoding;
use ed25519_dalek::{Signature, Signer, Verifier};
use ed25519_dalek::{SigningKey, VerifyingKey};
use freebird_common::api::{NativeExchangeV3Receipt, EXCHANGE_MAX_VALID_UNTIL};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;
const LOCK_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(60);

pub struct ReceiptKey {
    signing: SigningKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptKeyMetadata {
    pub key_id: String,
    pub algorithm: String,
    pub purpose: String,
    pub public_key_b64: String,
    pub valid_from: u64,
    pub valid_until: u64,
}

/// Local binding between immutable public receipt-key metadata and private key
/// material. Only `metadata` may be published.
#[derive(Clone, Debug)]
pub struct ReceiptKeyConfig {
    pub metadata: ReceiptKeyMetadata,
    pub private_key_path: PathBuf,
}

/// Active and retained receipt-only signers, indexed by their immutable public
/// key identifier. Retained keys are never selected for fresh reservations.
#[derive(Clone)]
pub struct ReceiptKeyRing {
    active_id: String,
    keys: HashMap<String, Arc<ReceiptKey>>,
    metadata: HashMap<String, ReceiptKeyMetadata>,
}

impl ReceiptKeyRing {
    /// Load the V7-only exchange receipt key ring. V7 uses a distinct purpose
    /// namespace and never accepts legacy receipt records or metadata.
    pub fn load_v7(active: ReceiptKeyConfig, retained: &[ReceiptKeyConfig]) -> Result<Self> {
        let mut keys = HashMap::new();
        let mut metadata = HashMap::new();
        let active_id = active.metadata.key_id.clone();
        load_configured_key(&active, "exchange_receipt_v7", &mut keys, &mut metadata)
            .context("invalid active V7 receipt key")?;
        for config in retained {
            load_configured_key(config, "exchange_receipt_v7", &mut keys, &mut metadata)
                .context("invalid retained V7 receipt key")?;
        }
        Ok(Self {
            active_id,
            keys,
            metadata,
        })
    }

    pub fn active_id(&self) -> &str {
        &self.active_id
    }

    pub fn active_validity(&self) -> Result<(u64, u64)> {
        let metadata = self
            .metadata
            .get(&self.active_id)
            .context("active receipt key metadata unavailable")?;
        Ok((metadata.valid_from, metadata.valid_until))
    }

    pub fn resolve(&self, key_id: &str) -> Option<&ReceiptKey> {
        self.keys.get(key_id).map(Arc::as_ref)
    }

    /// Select the active signer for newly reserved work. The complete receipt
    /// lifetime must fit inside the key's immutable validity interval.
    pub fn active_signer(&self, created_at: u64, expires_at: u64) -> Result<&ReceiptKey> {
        self.signer_for_interval(&self.active_id, created_at, expires_at)
            .context("active receipt signer is not valid for requested lifetime")
    }

    /// Resolve the signer pinned in persisted work. Retained keys are accepted
    /// here, but never by `active_signer`.
    pub fn recovery_signer(
        &self,
        key_id: &str,
        created_at: u64,
        expires_at: u64,
    ) -> Result<&ReceiptKey> {
        self.signer_for_interval(key_id, created_at, expires_at)
            .context("persisted receipt signer is unavailable or invalid")
    }

    fn signer_for_interval(
        &self,
        key_id: &str,
        created_at: u64,
        expires_at: u64,
    ) -> Result<&ReceiptKey> {
        let metadata = self
            .metadata
            .get(key_id)
            .context("receipt key metadata unavailable")?;
        if created_at < metadata.valid_from
            || expires_at <= created_at
            || expires_at > metadata.valid_until
        {
            anyhow::bail!("receipt lifetime falls outside signer validity")
        }
        self.resolve(key_id)
            .context("receipt private key unavailable")
    }

    pub fn contains(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }
}

pub fn validate_receipt_key_metadata(
    metadata: &ReceiptKeyMetadata,
    expected_purpose: &str,
) -> Result<VerifyingKey> {
    if metadata.key_id.len() != 64 || !metadata.key_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        anyhow::bail!("invalid receipt key identifier")
    }
    if metadata.algorithm != "Ed25519"
        || metadata.purpose != expected_purpose
        || metadata.valid_from == 0
        || metadata.valid_from >= metadata.valid_until
        || metadata.valid_until > EXCHANGE_MAX_VALID_UNTIL as u64
    {
        anyhow::bail!("invalid receipt key algorithm, purpose, or validity")
    }
    let public = base64ct::Base64UrlUnpadded::decode_vec(&metadata.public_key_b64)
        .context("invalid receipt public key encoding")?;
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 receipt public key must be 32 bytes"))?;
    if base64ct::Base64UrlUnpadded::encode_string(&public) != metadata.public_key_b64
        || hex::encode(sha2::Sha256::digest(public)) != metadata.key_id
    {
        anyhow::bail!("receipt public key identity mismatch")
    }
    VerifyingKey::from_bytes(&public).context("invalid Ed25519 receipt public key")
}

fn load_configured_key(
    config: &ReceiptKeyConfig,
    expected_purpose: &str,
    keys: &mut HashMap<String, Arc<ReceiptKey>>,
    metadata: &mut HashMap<String, ReceiptKeyMetadata>,
) -> Result<()> {
    let declared_public = validate_receipt_key_metadata(&config.metadata, expected_purpose)?;
    validate_receipt_key_file(&config.private_key_path)?;
    let key = load_or_generate_receipt_key(&config.private_key_path)?;
    if key.verifying_key() != declared_public || key.key_id() != config.metadata.key_id {
        anyhow::bail!("receipt private key does not match immutable public metadata")
    }
    let id = config.metadata.key_id.clone();
    if let Some(existing) = metadata.get(&id) {
        if existing != &config.metadata {
            anyhow::bail!("conflicting receipt key metadata for {id}")
        }
        anyhow::bail!("duplicate receipt key id {id}")
    }
    metadata.insert(id.clone(), config.metadata.clone());
    keys.insert(id, Arc::new(key));
    Ok(())
}

impl ReceiptKey {
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
    pub fn key_id(&self) -> String {
        hex::encode(sha2::Sha256::digest(self.verifying_key().as_bytes()))
    }
    pub fn sign_receipt_v7(&self, receipt: &NativeExchangeV3Receipt) -> Result<Vec<u8>> {
        let digest = receipt
            .receipt_digest()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok(self.signing.sign(&digest).to_bytes().to_vec())
    }

    pub fn verify_receipt_v7(
        receipt: &NativeExchangeV3Receipt,
        public: &VerifyingKey,
        signature: &[u8],
    ) -> Result<()> {
        let signature = Signature::from_slice(signature).context("invalid V7 receipt signature")?;
        let digest = receipt
            .receipt_digest()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        public
            .verify(&digest, &signature)
            .context("invalid V7 receipt signature")
    }
}

pub fn load_or_generate_receipt_key(path: &Path) -> Result<ReceiptKey> {
    let metadata = fs::symlink_metadata(path).ok();
    if let Some(metadata) = &metadata {
        if !metadata.file_type().is_file() {
            anyhow::bail!("receipt key is not a regular file")
        }
    }
    let existed = metadata.is_some();
    if existed {
        validate_receipt_key_file(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)?.permissions().mode();
            if mode & 0o777 != 0o600 {
                anyhow::bail!("receipt key permissions must be 0600");
            }
        }
    }
    let bytes = if existed {
        Zeroizing::new(
            fs::read(path).with_context(|| format!("read receipt key {}", path.display()))?,
        )
    } else {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Zeroizing::new(key.to_vec())
    };
    if bytes.len() != 32 {
        anyhow::bail!("receipt key must contain exactly 32 bytes")
    }
    if !existed {
        match atomic_write(path, &bytes) {
            Ok(()) => {}
            Err(error) if path.is_file() => {
                // Another process won creation. Never replace its key.
                return load_or_generate_receipt_key(path)
                    .with_context(|| format!("concurrent receipt key creation after {error}"));
            }
            Err(error) => return Err(error),
        }
        if fs::read(path)? != *bytes {
            return load_or_generate_receipt_key(path);
        }
    }
    let raw: Zeroizing<[u8; 32]> =
        Zeroizing::new(bytes.as_slice().try_into().expect("length checked"));
    Ok(ReceiptKey {
        signing: SigningKey::from_bytes(&raw),
    })
}

pub fn validate_receipt_key_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat receipt key {}", path.display()))?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("receipt key is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            anyhow::bail!("receipt key permissions must be 0600");
        }
    }
    if metadata.len() != 32 {
        anyhow::bail!("receipt key must contain exactly 32 bytes");
    }
    Ok(())
}

struct LockGuard(PathBuf);
impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let lock = PathBuf::from(format!("{}.lock", path.display()));
    let _lock_file = loop {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
        {
            Ok(mut file) => {
                file.write_all(std::process::id().to_string().as_bytes())?;
                file.sync_all()?;
                break file;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if path.is_file() {
                    anyhow::bail!("receipt key created concurrently")
                }
                let malformed = fs::read_to_string(&lock)
                    .map(|s| s.parse::<u32>().is_err())
                    .unwrap_or(true);
                if malformed
                    || fs::metadata(&lock)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > LOCK_MAX_AGE)
                {
                    let _ = fs::remove_file(&lock);
                    continue;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => return Err(e.into()),
        }
    };
    let _guard = LockGuard(lock.clone());
    let tmp = PathBuf::from(format!(
        "{}.tmp-{}-{}",
        path.display(),
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}
