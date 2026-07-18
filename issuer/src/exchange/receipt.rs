// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{Context, Result};
use base64ct::Encoding;
use ed25519_dalek::{Signature, Signer, Verifier};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use sha2::Digest;
use std::{
    collections::{HashMap, HashSet},
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

/// Active and retained receipt-only signers, indexed by their immutable public
/// key identifier. Retained keys are never selected for fresh reservations.
#[derive(Clone)]
pub struct ReceiptKeyRing {
    active_id: String,
    keys: HashMap<String, Arc<ReceiptKey>>,
}

impl ReceiptKeyRing {
    pub fn load(active_path: &Path, retained_paths: &[PathBuf]) -> Result<Self> {
        let active = load_or_generate_receipt_key(active_path)?;
        let active_id = active.key_id();
        let mut keys = HashMap::from([(active_id.clone(), Arc::new(active))]);
        for path in retained_paths {
            validate_receipt_key_file(path)
                .with_context(|| format!("invalid retained receipt key {}", path.display()))?;
            let key = load_or_generate_receipt_key(path)?;
            let id = key.key_id();
            if keys.insert(id.clone(), Arc::new(key)).is_some() {
                anyhow::bail!("duplicate receipt key id {id}")
            }
        }
        Ok(Self { active_id, keys })
    }

    pub fn active_id(&self) -> &str {
        &self.active_id
    }

    pub fn resolve(&self, key_id: &str) -> Option<&ReceiptKey> {
        self.keys.get(key_id).map(Arc::as_ref)
    }

    pub fn contains(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    pub fn discovery_metadata(&self) -> Vec<freebird_common::api::ExchangeReceiptKeyInfo> {
        let mut ids = self.keys.keys().cloned().collect::<Vec<_>>();
        ids.sort_unstable();
        if let Some(position) = ids.iter().position(|id| id == &self.active_id) {
            ids.swap(0, position);
        }
        ids.into_iter()
            .map(|id| {
                let key = self.keys.get(&id).expect("ring id came from key map");
                freebird_common::api::ExchangeReceiptKeyInfo {
                    key_id: id,
                    algorithm: "Ed25519".into(),
                    purpose: if key.key_id() == self.active_id {
                        "exchange_receipt_active".into()
                    } else {
                        "exchange_receipt_retained".into()
                    },
                    public_key_b64: base64ct::Base64UrlUnpadded::encode_string(
                        key.verifying_key().as_bytes(),
                    ),
                    valid_from: 0,
                    valid_until: u64::MAX,
                }
            })
            .collect()
    }
}

/// Configuration-time validation. The active key may be absent because issuer
/// startup creates it atomically; retained keys must already exist.
pub fn validate_receipt_key_paths(active_path: &Path, retained_paths: &[PathBuf]) -> Result<()> {
    let mut ids = HashSet::new();
    if active_path.exists() {
        validate_receipt_key_file(active_path)?;
        ids.insert(load_or_generate_receipt_key(active_path)?.key_id());
    }
    for path in retained_paths {
        validate_receipt_key_file(path)
            .with_context(|| format!("invalid retained receipt key {}", path.display()))?;
        let id = load_or_generate_receipt_key(path)?.key_id();
        if !ids.insert(id) {
            anyhow::bail!("duplicate active/retained receipt key id")
        }
    }
    Ok(())
}
impl ReceiptKey {
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
    pub fn key_id(&self) -> String {
        hex::encode(sha2::Sha256::digest(self.verifying_key().as_bytes()))
    }
    pub fn sign_receipt(
        &self,
        receipt: &freebird_common::exchange_api::ExchangeReceipt,
    ) -> Result<Vec<u8>> {
        Ok(self
            .signing
            .sign(&receipt.signing_digest()?)
            .to_bytes()
            .to_vec())
    }
    pub fn verify_receipt(
        receipt: &freebird_common::exchange_api::ExchangeReceipt,
        public: &VerifyingKey,
        signature: &[u8],
    ) -> Result<()> {
        let sig = Signature::from_slice(signature).context("invalid receipt signature")?;
        public
            .verify(&receipt.signing_digest()?, &sig)
            .context("invalid receipt signature")
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
            if mode & 0o077 != 0 {
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
        if metadata.permissions().mode() & 0o077 != 0 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::Encoding;
    #[test]
    fn persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("receipt.key");
        let a = load_or_generate_receipt_key(&p).unwrap();
        assert_eq!(
            a.key_id(),
            load_or_generate_receipt_key(&p).unwrap().key_id()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
    #[test]
    fn rejects_tampered_receipt() {
        let key = ReceiptKey {
            signing: SigningKey::from_bytes(&[7; 32]),
        };
        let mut receipt = freebird_common::exchange_api::ExchangeReceipt {
            operation_id: base64ct::Base64UrlUnpadded::encode_string(&[1; 16]),
            profile: freebird_common::exchange_api::EXCHANGE_PROFILE_V1.into(),
            target_keyset_id: "2".repeat(64),
            result_digest: base64ct::Base64UrlUnpadded::encode_string(&[2; 32]),
            created_at: 1,
            expires_at: 2,
            receipt_key_id: key.key_id(),
            signature: String::new(),
        };
        let signature = key.sign_receipt(&receipt).unwrap();
        assert_eq!(
            hex::encode(receipt.signing_digest().unwrap()),
            "61a1035aeb2606ca01593a94fe37bd6fb519516d0b54507323c2f5c59abd46a3"
        );
        assert_eq!(hex::encode(&signature), "440e5f3fa480712633b34ae4024b0cc964008a36df31c1307552d6ce02ca9c14423b276c27332cfdf9b12fb8ee499c945516b07af82dc2712afe0cf4ac85cb08");
        ReceiptKey::verify_receipt(&receipt, &key.verifying_key(), &signature).unwrap();
        receipt.expires_at = 3;
        assert!(ReceiptKey::verify_receipt(&receipt, &key.verifying_key(), &signature).is_err());
    }
    #[test]
    fn recovers_stale_lock_without_replacing_key() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("r");
        fs::write(format!("{}.lock", p.display()), "stale-process").unwrap();
        let key = load_or_generate_receipt_key(&p).unwrap();
        assert_eq!(
            key.key_id(),
            load_or_generate_receipt_key(&p).unwrap().key_id()
        );
    }

    #[test]
    fn active_and_retained_ring_resolves_persisted_ids() {
        let dir = tempfile::tempdir().unwrap();
        let active_path = dir.path().join("active.key");
        let retained_path = dir.path().join("retained.key");
        let active_id = load_or_generate_receipt_key(&active_path).unwrap().key_id();
        let retained_id = load_or_generate_receipt_key(&retained_path)
            .unwrap()
            .key_id();
        let ring =
            ReceiptKeyRing::load(&active_path, std::slice::from_ref(&retained_path)).unwrap();
        assert_eq!(ring.active_id(), active_id);
        assert!(ring.resolve(&active_id).is_some());
        assert!(ring.resolve(&retained_id).is_some());
        assert!(ring.resolve(&"0".repeat(64)).is_none());
        assert!(ReceiptKeyRing::load(&active_path, &[dir.path().join("missing.key")]).is_err());
        let metadata = ring.discovery_metadata();
        assert_eq!(metadata.len(), 2);
        assert_eq!(metadata[0].key_id, active_id);
        assert_eq!(metadata[0].purpose, "exchange_receipt_active");
        assert_eq!(metadata[1].purpose, "exchange_receipt_retained");
        let active_metadata = metadata[0].clone();
        let mut receipt = freebird_common::exchange_api::ExchangeReceipt {
            operation_id: base64ct::Base64UrlUnpadded::encode_string(&[3; 16]),
            profile: freebird_common::exchange_api::EXCHANGE_PROFILE_V1.into(),
            target_keyset_id: "2".repeat(64),
            result_digest: base64ct::Base64UrlUnpadded::encode_string(&[4; 32]),
            created_at: 10,
            expires_at: 20,
            receipt_key_id: active_id.clone(),
            signature: String::new(),
        };
        let signature = ring
            .resolve(&active_id)
            .unwrap()
            .sign_receipt(&receipt)
            .unwrap();
        receipt.signature = base64ct::Base64UrlUnpadded::encode_string(&signature);
        let public: [u8; 32] =
            base64ct::Base64UrlUnpadded::decode_vec(&active_metadata.public_key_b64)
                .unwrap()
                .try_into()
                .unwrap();
        drop(ring);
        std::fs::remove_file(&active_path).unwrap();
        std::fs::remove_file(&retained_path).unwrap();
        let verifying = VerifyingKey::from_bytes(&public).unwrap();
        ReceiptKey::verify_receipt(&receipt, &verifying, &signature).unwrap();
        for key in metadata {
            let public = base64ct::Base64UrlUnpadded::decode_vec(&key.public_key_b64).unwrap();
            assert_eq!(public.len(), 32);
            assert_eq!(
                base64ct::Base64UrlUnpadded::encode_string(&public),
                key.public_key_b64
            );
            assert!(key.valid_until > key.valid_from);
        }
    }
}
