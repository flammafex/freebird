// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::Context;
use std::{sync::Arc, time::Duration};
use time::OffsetDateTime;
use tracing::warn;

pub(super) struct KeyMaterial {
    pub(super) secret_guard: zeroize::Zeroizing<[u8; 32]>,
    pub(super) kid: String,
    pub(super) pubkey_b64: String,
    pub(super) voprf: Arc<crate::multi_key_voprf::MultiKeyVoprfCore>,
    pub(super) native_bearer_v7: Arc<crate::native_bearer_v7::NativeBearerV7Issuer>,
    pub(super) native_bearer_v7_retained: Vec<freebird_common::api::NativeBearerV7KeyInfo>,
    pub(super) v7_signer_inventory: Arc<crate::v7_signers::V7SignerInventory>,
}

impl KeyMaterial {
    pub(super) async fn build(config: &crate::config::Config) -> anyhow::Result<Self> {
        let (sk_bytes, pubkey_b64, kid_from_key) =
            crate::keys::load_or_generate_keypair_b64_at(&config.key_config.sk_path)
                .context("Failed to load or generate issuer keypair")?;

        let kid = config
            .key_config
            .kid_override
            .as_ref()
            .map(|k| {
                if !k.starts_with(&kid_from_key) {
                    warn!(provided=%k, derived=%kid_from_key, "KID mismatch; using derived prefix");
                    format!("{}-{}", kid_from_key, OffsetDateTime::now_utc().date())
                } else {
                    k.clone()
                }
            })
            .unwrap_or_else(|| format!("{}-{}", kid_from_key, OffsetDateTime::now_utc().date()));

        let ctx = freebird_crypto::VOPRF_CONTEXT_V4;
        let voprf = Arc::new(
            crate::multi_key_voprf::MultiKeyVoprfCore::load_or_create(
                *sk_bytes,
                pubkey_b64.clone(),
                kid.clone(),
                ctx,
                Some(config.key_config.rotation_state_path.clone()),
            )
            .await
            .context("Failed to initialize VOPRF core")?,
        );

        let cleanup_voprf = Arc::clone(&voprf);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                if let Err(e) = cleanup_voprf.cleanup_expired_keys().await {
                    warn!("Automatic key cleanup failed: {}", e);
                }
            }
        });

        let signer_spec = crate::v7_signers::V7SignerSpec::from_native_config(
            &config.native_bearer_v7_config,
            &config.issuer_id,
        )?;
        let retained_specs = crate::config::load_v7_additional_signer_configs()?
            .into_iter()
            .map(|signer_config| {
                crate::v7_signers::V7SignerSpec::from_native_config(
                    &signer_config,
                    &config.issuer_id,
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let v7_signer_inventory = Arc::new(
            crate::v7_signers::V7SignerInventory::load_or_generate(
                signer_spec,
                retained_specs,
                &config.native_bearer_v7_config.registry_path,
            )
            .context("Failed to initialize V7 signer inventory")?,
        );
        let native_bearer_v7 = Arc::new(
            crate::native_bearer_v7::NativeBearerV7Issuer::from_inventory(
                v7_signer_inventory.clone(),
                &config.native_bearer_v7_config,
                &config.issuer_id,
            )
            .context("Failed to initialize V7 native bearer issuer")?,
        );
        let native_bearer_v7_retained = native_bearer_v7.retained_discovery()?;

        Ok(Self {
            secret_guard: sk_bytes,
            kid,
            pubkey_b64,
            voprf,
            native_bearer_v7,
            native_bearer_v7_retained,
            v7_signer_inventory,
        })
    }
}
