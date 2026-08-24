// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Direct-issuance facade over the shared V7 signer inventory.

use anyhow::Result;
use freebird_common::api::NativeBearerV7KeyInfo;
use freebird_crypto::{V7BlindMessage, V7BlindSignature, V7KeyIdentity, V7PublicKeyBinding};
use std::sync::Arc;

use crate::{
    config::NativeBearerV7Config,
    v7_signers::{V7SignerIdentity, V7SignerInventory, V7SignerSpec},
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
        let spec = V7SignerSpec::from_native_config(config, issuer_id)?;
        inventory.lookup(&spec.identity)?;
        let crypto_identity = spec.identity.crypto_identity()?;
        Ok(Self {
            inventory,
            active_identity: spec.identity,
            crypto_identity,
        })
    }

    /// Load or create the direct signer and reserve it in the V7 registry.
    pub fn load_or_generate(config: &NativeBearerV7Config, issuer_id: &str) -> Result<Self> {
        let spec = V7SignerSpec::from_native_config(config, issuer_id)?;
        let active_identity = spec.identity.clone();
        let crypto_identity = spec.identity.crypto_identity()?;
        let inventory =
            V7SignerInventory::load_or_generate(spec, Vec::new(), &config.registry_path)?;
        Ok(Self {
            inventory: Arc::new(inventory),
            active_identity,
            crypto_identity,
        })
    }

    /// Load existing direct material without creating or reserving files.
    pub fn load_existing(config: &NativeBearerV7Config, issuer_id: &str) -> Result<Self> {
        let spec = V7SignerSpec::from_native_config(config, issuer_id)?;
        let signer = Arc::new(crate::v7_signers::V7Signer::load_existing(&spec, false)?);
        let active_identity = spec.identity.clone();
        let crypto_identity = spec.identity.crypto_identity()?;
        let inventory = V7SignerInventory::from_signers(signer.clone(), vec![signer], None)?;
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
        let identity = V7SignerIdentity::new(
            identity.issuer_id(),
            self.active().identity().profile_id().to_owned(),
            self.active().identity().descriptor_id().to_owned(),
            *identity.token_key_id(),
        )?;
        self.inventory.sign(&identity, message).await
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
            descriptor_id: "10".repeat(32),
            token_key_id: "11".repeat(32),
            asset_id: "USD".into(),
            amount_minor: 1,
            validity_secs: 3600,
        };
        let issuer = NativeBearerV7Issuer::load_or_generate(&config, "issuer:test").unwrap();
        assert_eq!(issuer.inventory().len(), 1);
        assert_eq!(issuer.metadata().token_key_id, "11".repeat(32));
    }
}
