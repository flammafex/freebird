// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Durable issuer-side persistence for the append-only bearer-key registry.

use anyhow::{Context, Result};
use freebird_common::{
    api::NativeBearerV7KeyInfo,
    v7_registry::{BearerKeyRegistry, BearerKeyReservationStatus},
};
use std::path::{Path, PathBuf};

/// Read the durable registry without creating locks or changing its history.
pub fn load_read_only(path: &Path) -> Result<BearerKeyRegistry> {
    if !path.is_file() {
        anyhow::bail!("bearer registry {} does not exist", path.display());
    }
    serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("read bearer registry {}", path.display()))?,
    )
    .with_context(|| format!("validate bearer registry {}", path.display()))
}

/// Require every durable reservation to belong to the configured issuer.
///
/// This check is deliberately read-only. Loading public exchange history must
/// not acquire the registry lock or extend the append-only history merely to
/// make it compatible.
pub fn validate_issuer_compatibility(registry: &BearerKeyRegistry, issuer_id: &str) -> Result<()> {
    if registry
        .entries()
        .iter()
        .any(|entry| entry.issuer_id != issuer_id)
    {
        anyhow::bail!("V7 bearer registry contains a different issuer identity than {issuer_id}")
    }
    Ok(())
}

/// Load the durable V7-only registry, reserve the currently loaded V7 material,
/// and atomically persist an updated registry when a new reservation appears.
pub fn load_and_reserve(
    path: &Path,
    v7_metadata: &NativeBearerV7KeyInfo,
    v7_binding: &freebird_crypto::V7PublicKeyBinding,
) -> Result<BearerKeyRegistry> {
    load_and_reserve_all(path, &[(v7_metadata, v7_binding)])
}

/// Load the pure V7 registry and reserve every active and retained signer in
/// one locked, atomic registry update.
pub fn load_and_reserve_all(
    path: &Path,
    signers: &[(&NativeBearerV7KeyInfo, &freebird_crypto::V7PublicKeyBinding)],
) -> Result<BearerKeyRegistry> {
    let _lock = ExclusiveRegistryLock::acquire(path)?;
    let mut registry = if path.exists() {
        serde_json::from_slice::<BearerKeyRegistry>(
            &std::fs::read(path)
                .with_context(|| format!("read bearer registry {}", path.display()))?,
        )
        .with_context(|| format!("validate bearer registry {}", path.display()))?
    } else {
        BearerKeyRegistry::new()
    };
    let mut changed = false;

    for (v7_metadata, v7_binding) in signers {
        validate_issuer_compatibility(&registry, &v7_metadata.issuer_id)?;
        changed |= matches!(
            registry.register(
                freebird_common::v7_registry::BearerKeyReservation::from_v7_discovery(
                    v7_metadata,
                    v7_binding,
                )?,
            )?,
            BearerKeyReservationStatus::Inserted
        );
    }

    if changed {
        write_registry(path, &registry)?;
    }
    Ok(registry)
}

/// Project immutable historical registry entries into strict discovery records.
pub fn retained_discovery(
    registry: &BearerKeyRegistry,
    active: &NativeBearerV7KeyInfo,
) -> Result<Vec<NativeBearerV7KeyInfo>> {
    registry
        .entries()
        .iter()
        .filter(|entry| {
            entry.profile_id == active.profile_id && entry.token_key_id != active.token_key_id
        })
        .map(|entry| {
            let metadata = NativeBearerV7KeyInfo {
                profile_id: entry.profile_id.clone(),
                issuer_id: entry.issuer_id.clone(),
                descriptor_id: entry.descriptor_id.clone(),
                token_key_id: entry.token_key_id.clone(),
                asset_id: entry.asset_id.clone(),
                amount_minor: entry.amount_minor,
                suite: entry.suite.clone(),
                modulus_bits: freebird_common::api::NATIVE_BEARER_V7_MODULUS_BITS,
                exponent: freebird_common::api::NATIVE_BEARER_V7_EXPONENT,
                pubkey_spki_b64: entry.pubkey_spki_b64.clone(),
                spki_fingerprint: entry.spki_fingerprint.clone(),
                valid_from: entry.valid_from,
                valid_until: entry.valid_until,
            };
            metadata.validate().map_err(anyhow::Error::msg)?;
            Ok(metadata)
        })
        .collect()
}

struct ExclusiveRegistryLock {
    path: PathBuf,
}

impl ExclusiveRegistryLock {
    fn acquire(registry_path: &Path) -> Result<Self> {
        let lock_path = lock_path(registry_path);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut lock = options
            .open(&lock_path)
            .with_context(|| format!("acquire bearer registry lock {}", lock_path.display()))?;
        use std::io::Write;
        writeln!(lock, "pid={}", std::process::id())?;
        lock.sync_all()?;
        Ok(Self { path: lock_path })
    }
}

impl Drop for ExclusiveRegistryLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn write_registry(path: &Path, registry: &BearerKeyRegistry) -> Result<()> {
    let tmp_path = temporary_path(path);
    let bytes = serde_json::to_vec_pretty(registry).context("serialize bearer registry")?;
    let mut file = std::fs::File::create(&tmp_path)
        .with_context(|| format!("open bearer registry temporary file {}", tmp_path.display()))?;
    use std::io::Write;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("replace bearer registry {}", path.display()))?;
    if let Some(parent) = path.parent() {
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

fn lock_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.lock", path.display()))
}

fn temporary_path(path: &Path) -> PathBuf {
    PathBuf::from(format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("registry"),
        std::process::id()
    ))
    .with_parent(path)
}

trait WithParent {
    fn with_parent(self, path: &Path) -> PathBuf;
}

impl WithParent for PathBuf {
    fn with_parent(self, path: &Path) -> PathBuf {
        path.parent()
            .map_or(self.clone(), |parent| parent.join(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freebird_common::api::NativeBearerV7KeyInfo;
    use freebird_crypto::{V7KeyIdentity, V7TokenKeyId};
    use tempfile::tempdir;

    fn binding(id: u8) -> freebird_crypto::V7PublicKeyBinding {
        let identity = V7KeyIdentity::new("issuer:test", V7TokenKeyId::new([id; 32])).unwrap();
        freebird_crypto::provider::software::SoftwareV7BlindRsaProvider::generate(identity)
            .unwrap()
            .binding()
            .clone()
    }

    #[test]
    fn restart_loads_and_preserves_registry_identity() {
        let root = tempdir().unwrap();
        let current = binding(41);
        let policy = freebird_crypto::V7BodyPolicy::new("USD", 42).unwrap();
        let metadata = NativeBearerV7KeyInfo::from_binding(
            &current,
            freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID,
            &"10".repeat(32),
            &policy,
            1,
            2,
        )
        .unwrap();
        let path = root.path().join("registry.json");
        let first = load_and_reserve(&path, &metadata, &current).unwrap();
        let second = load_and_reserve(&path, &metadata, &current).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            second.lookup_v7(current.token_key_id()).unwrap(),
            &first.entries()[0]
        );
    }

    #[test]
    fn malformed_or_colliding_history_is_rejected_before_installation() {
        let root = tempdir().unwrap();
        let path = root.path().join("registry.json");
        std::fs::write(&path, br#"{"entries":[{"bad":true}]}"#).unwrap();
        let current = binding(42);
        let policy = freebird_crypto::V7BodyPolicy::new("USD", 42).unwrap();
        let metadata = NativeBearerV7KeyInfo::from_binding(
            &current,
            freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID,
            &"11".repeat(32),
            &policy,
            1,
            2,
        )
        .unwrap();
        assert!(load_and_reserve(&path, &metadata, &current).is_err());
    }

    #[test]
    fn mixed_issuer_history_is_rejected_without_mutation() -> Result<()> {
        let first_binding = binding(47);
        let second_identity = V7KeyIdentity::new("issuer:other", V7TokenKeyId::new([48; 32]))
            .map_err(|error| anyhow::anyhow!("invalid test identity: {error:?}"))?;
        let second_binding =
            freebird_crypto::provider::software::SoftwareV7BlindRsaProvider::generate(
                second_identity,
            )?
            .binding()
            .clone();
        let policy = freebird_crypto::V7BodyPolicy::new("USD", 42)
            .map_err(|error| anyhow::anyhow!("invalid test policy: {error:?}"))?;
        let first = NativeBearerV7KeyInfo::from_binding(
            &first_binding,
            freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID,
            &"16".repeat(32),
            &policy,
            1,
            2,
        )
        .map_err(anyhow::Error::msg)?;
        let second = NativeBearerV7KeyInfo::from_binding(
            &second_binding,
            freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID,
            &"17".repeat(32),
            &policy,
            1,
            2,
        )
        .map_err(anyhow::Error::msg)?;
        let registry = BearerKeyRegistry::from_entries([
            freebird_common::v7_registry::BearerKeyReservation::from_v7_discovery(
                &first,
                &first_binding,
            )?,
            freebird_common::v7_registry::BearerKeyReservation::from_v7_discovery(
                &second,
                &second_binding,
            )?,
        ])?;

        let error = validate_issuer_compatibility(&registry, "issuer:test").unwrap_err();
        assert!(error.to_string().contains("different issuer identity"));
        Ok(())
    }

    #[test]
    fn retained_projection_excludes_other_v7_profiles() -> Result<()> {
        let root = tempdir()?;
        let path = root.path().join("registry.json");
        let policy = freebird_crypto::V7BodyPolicy::new("USD", 42).unwrap();
        let direct_binding = binding(43);
        let exchange_binding = binding(44);
        let direct = NativeBearerV7KeyInfo::from_binding(
            &direct_binding,
            freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID,
            &"12".repeat(32),
            &policy,
            1,
            2,
        )
        .unwrap();
        let exchange_descriptor = freebird_common::api::derive_native_exchange_v3_descriptor_id(
            freebird_common::api::NATIVE_EXCHANGE_V3_PROFILE_ID,
            exchange_binding.issuer_id(),
            &hex::encode(exchange_binding.token_key_id().as_bytes()),
            policy.asset_id(),
            policy.amount_minor(),
            freebird_common::api::NATIVE_EXCHANGE_V3_SUITE,
            3_072,
            65_537,
            exchange_binding.public_key_spki(),
            &hex::encode(exchange_binding.spki_fingerprint()),
            1,
            2,
        )
        .unwrap();
        let exchange = NativeBearerV7KeyInfo::from_binding(
            &exchange_binding,
            freebird_common::api::NATIVE_EXCHANGE_V3_PROFILE_ID,
            &exchange_descriptor,
            &policy,
            1,
            2,
        )
        .unwrap();
        let registry = load_and_reserve_all(
            &path,
            &[(&direct, &direct_binding), (&exchange, &exchange_binding)],
        )?;

        assert!(retained_discovery(&registry, &direct)?.is_empty());
        Ok(())
    }

    #[test]
    fn direct_rotation_retains_original_canonical_descriptor_for_discovery() -> Result<()> {
        let root = tempdir()?;
        let path = root.path().join("registry.json");
        let policy = freebird_crypto::V7BodyPolicy::new("USD", 42)
            .map_err(|error| anyhow::anyhow!("invalid policy: {error:?}"))?;
        let old_binding = binding(45);
        let active_binding = binding(46);
        let old = NativeBearerV7KeyInfo::from_binding(
            &old_binding,
            freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID,
            &"14".repeat(32),
            &policy,
            1,
            2,
        )
        .map_err(anyhow::Error::msg)?;
        let active = NativeBearerV7KeyInfo::from_binding(
            &active_binding,
            freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID,
            &"15".repeat(32),
            &policy,
            3,
            10,
        )
        .map_err(anyhow::Error::msg)?;
        let original_descriptor = old.descriptor_id.clone();
        let registry =
            load_and_reserve_all(&path, &[(&old, &old_binding), (&active, &active_binding)])?;
        let retained = retained_discovery(&registry, &active)?;
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].descriptor_id, original_descriptor);
        freebird_common::api::validate_native_bearer_v7_discovery(
            "issuer:test",
            &active,
            &retained,
        )
        .map_err(anyhow::Error::msg)?;
        Ok(())
    }
}
