// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Direct-issuance facade over the shared V7 signer inventory.

use anyhow::Result;
use freebird_common::api::NativeBearerV7KeyInfo;
use freebird_crypto::{V7BlindMessage, V7BlindSignature, V7KeyIdentity, V7PublicKeyBinding};
use std::sync::Arc;

use crate::{
    config::NativeBearerV7Config,
    v7_signers::{V7PreflightError, V7SignerIdentity, V7SignerInventory, V7SignerSpec},
};

/// Direct V7 issuance facade backed by the shared signer inventory.
pub struct NativeBearerV7Issuer {
    inventory: Arc<V7SignerInventory>,
    active_identity: V7SignerIdentity,
    crypto_identity: V7KeyIdentity,
}

impl NativeBearerV7Issuer {
    pub(crate) fn from_inventory(
        inventory: Arc<V7SignerInventory>,
        config: &NativeBearerV7Config,
        issuer_id: &str,
    ) -> Result<Self> {
        validate_direct_profile(config)?;
        let spec = V7SignerSpec::from_native_config(config, issuer_id)?;
        let active = inventory.active();
        if active.identity().issuer_id() != issuer_id
            || active.identity().profile_id() != config.profile_id
            || active.identity().token_key_id() != spec.identity.token_key_id()
            || (!config.descriptor_id.trim().is_empty()
                && active.identity().descriptor_id() != config.descriptor_id)
        {
            anyhow::bail!("configured direct V7 signer is not the active inventory signer");
        }
        let active_identity = active.identity().clone();
        let crypto_identity = active_identity.crypto_identity()?;
        Ok(Self {
            inventory,
            active_identity,
            crypto_identity,
        })
    }

    /// Load or create the direct signer and reserve it in the V7 registry.
    pub fn load_or_generate(config: &NativeBearerV7Config, issuer_id: &str) -> Result<Self> {
        validate_direct_profile(config)?;
        let spec = V7SignerSpec::from_native_config(config, issuer_id)?;
        let inventory =
            V7SignerInventory::load_or_generate(spec, Vec::new(), &config.registry_path)?;
        let active_identity = inventory.active().identity().clone();
        let crypto_identity = active_identity.crypto_identity()?;
        Ok(Self {
            inventory: Arc::new(inventory),
            active_identity,
            crypto_identity,
        })
    }

    /// Load existing direct material without creating or reserving files.
    pub fn load_existing(config: &NativeBearerV7Config, issuer_id: &str) -> Result<Self> {
        validate_direct_profile(config)?;
        let spec = V7SignerSpec::from_native_config(config, issuer_id)?;
        let signer = Arc::new(crate::v7_signers::V7Signer::load_existing(&spec, false)?);
        let inventory = V7SignerInventory::from_signers(signer.clone(), vec![signer], None)?;
        let active_identity = inventory.active().identity().clone();
        let crypto_identity = active_identity.crypto_identity()?;
        Ok(Self {
            inventory: Arc::new(inventory),
            active_identity,
            crypto_identity,
        })
    }

    /// Return the shared inventory used by direct issuance.
    pub fn inventory(&self) -> &V7SignerInventory {
        &self.inventory
    }

    /// Sign one V7 blind message through the inventory lookup.
    pub async fn sign(
        &self,
        identity: &V7KeyIdentity,
        message: &V7BlindMessage,
    ) -> Result<V7BlindSignature> {
        let identity = self.signer_identity(identity)?;
        self.inventory.sign(&identity, message).await
    }

    fn signer_identity(&self, identity: &V7KeyIdentity) -> Result<V7SignerIdentity> {
        V7SignerIdentity::new(
            identity.issuer_id(),
            self.active_identity.profile_id().to_owned(),
            self.active_identity.descriptor_id().to_owned(),
            *identity.token_key_id(),
        )
    }

    /// Resolve exactly the direct signing identity and preflight without signing.
    pub fn preflight_at(
        &self,
        identity: &V7KeyIdentity,
        message: &V7BlindMessage,
        now: i64,
    ) -> Result<(), V7PreflightError> {
        let identity = self
            .signer_identity(identity)
            .map_err(|_| V7PreflightError::Unavailable)?;
        self.inventory
            .lookup(&identity)
            .map_err(|_| V7PreflightError::Unavailable)?
            .preflight_at(message, now)
    }

    #[cfg(test)]
    pub(crate) fn set_test_validity(&mut self, from: i64, until: i64) {
        Arc::get_mut(&mut self.inventory)
            .unwrap()
            .set_test_validity(from, until);
    }

    pub fn metadata(&self) -> &NativeBearerV7KeyInfo {
        self.active().metadata()
    }
    pub fn binding(&self) -> &V7PublicKeyBinding {
        self.active().binding()
    }
    pub fn identity(&self) -> &V7KeyIdentity {
        &self.crypto_identity
    }
    pub fn retained_discovery(&self) -> Result<Vec<NativeBearerV7KeyInfo>> {
        crate::v7_registry::retained_discovery(self.inventory.registry(), self.metadata())
    }

    fn active(&self) -> &crate::v7_signers::V7Signer {
        self.inventory
            .lookup(&self.active_identity)
            .expect("active V7 signer disappeared")
    }
}

fn validate_direct_profile(config: &NativeBearerV7Config) -> Result<()> {
    if config.profile_id != freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID {
        anyhow::bail!(
            "direct native V7 issuer requires profile {}",
            freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn facade_uses_inventory_for_direct_material() {
        let root = tempdir().unwrap();
        let config = NativeBearerV7Config {
            sk_path: root.path().join("v7.der"),
            metadata_path: root.path().join("v7.json"),
            registry_path: root.path().join("registry.json"),
            profile_id: freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID.into(),
            descriptor_id: String::new(),
            token_key_id: "11".repeat(32),
            asset_id: "USD".into(),
            amount_minor: 1,
            validity_secs: 3600,
        };
        let issuer = NativeBearerV7Issuer::load_or_generate(&config, "issuer:test").unwrap();
        assert_eq!(issuer.inventory().len(), 1);
        assert_eq!(issuer.metadata().token_key_id, "11".repeat(32));
        let mut bytes = [0; 384];
        bytes[383] = 1;
        let message = V7BlindMessage::from_bytes(&bytes).unwrap();
        let now = issuer.metadata().valid_from;
        assert_eq!(
            issuer.preflight_at(issuer.identity(), &message, now),
            Ok(())
        );
        let missing = V7KeyIdentity::new(
            "issuer:test",
            freebird_crypto::V7TokenKeyId::new([0x22; 32]),
        )
        .unwrap();
        assert_eq!(
            issuer.preflight_at(&missing, &message, now),
            Err(V7PreflightError::Unavailable)
        );
        assert_eq!(issuer.inventory().active().sign_attempts(), 0);
    }

    #[test]
    fn direct_descriptor_bootstrap_restart_and_pin_contract() {
        let root = tempdir().unwrap();
        let config = NativeBearerV7Config {
            sk_path: root.path().join("v7.der"),
            metadata_path: root.path().join("v7.json"),
            registry_path: root.path().join("registry.json"),
            profile_id: freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID.into(),
            descriptor_id: String::new(),
            token_key_id: "21".repeat(32),
            asset_id: "USD".into(),
            amount_minor: 7,
            validity_secs: 3600,
        };
        let first = NativeBearerV7Issuer::load_or_generate(&config, "issuer:test").unwrap();
        let descriptor = first.metadata().descriptor_id.clone();
        let validity = (first.metadata().valid_from, first.metadata().valid_until);

        let restarted = NativeBearerV7Issuer::load_or_generate(&config, "issuer:test").unwrap();
        assert_eq!(restarted.metadata().descriptor_id, descriptor);
        assert_eq!(
            (
                restarted.metadata().valid_from,
                restarted.metadata().valid_until
            ),
            validity
        );

        let mut pinned = config.clone();
        pinned.descriptor_id = descriptor;
        assert!(NativeBearerV7Issuer::load_or_generate(&pinned, "issuer:test").is_ok());

        let mut mismatched = pinned.clone();
        mismatched.descriptor_id = "ff".repeat(32);
        assert!(NativeBearerV7Issuer::load_or_generate(&mismatched, "issuer:test").is_err());

        std::fs::remove_file(&pinned.metadata_path).unwrap();
        assert!(NativeBearerV7Issuer::load_or_generate(&pinned, "issuer:test").is_err());
        assert!(pinned.sk_path.is_file());

        let mut wrong_profile = config.clone();
        wrong_profile.profile_id = "freebird/native-exchange/v3".into();
        assert!(NativeBearerV7Issuer::load_or_generate(&wrong_profile, "issuer:test").is_err());

        let fresh_root = tempdir().unwrap();
        let mut fresh_pinned = config;
        fresh_pinned.sk_path = fresh_root.path().join("v7.der");
        fresh_pinned.metadata_path = fresh_root.path().join("v7.json");
        fresh_pinned.registry_path = fresh_root.path().join("registry.json");
        fresh_pinned.descriptor_id = "01".repeat(32);
        let error = match NativeBearerV7Issuer::load_or_generate(&fresh_pinned, "issuer:test") {
            Ok(_) => panic!("fresh bootstrap with a descriptor pin must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("pin, not a bootstrap value"));
        assert!(!fresh_pinned.sk_path.exists());
        assert!(!fresh_pinned.metadata_path.exists());
    }
}
