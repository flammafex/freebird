// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::Context;
use std::{sync::Arc, time::Duration};
use time::OffsetDateTime;
use tracing::{info, warn};

pub(super) struct KeyMaterial {
    pub(super) secret_guard: zeroize::Zeroizing<[u8; 32]>,
    pub(super) kid: String,
    pub(super) pubkey_b64: String,
    pub(super) voprf: Arc<crate::multi_key_voprf::MultiKeyVoprfCore>,
    pub(super) public_issuer: Option<Arc<crate::public_tokens::PublicTokenIssuer>>,
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

        let public_issuer = crate::public_tokens::PublicTokenIssuer::load_or_generate(
            &config.public_key_config,
            &config.issuer_id,
        )
        .context("Failed to initialize V5 public bearer issuer")?
        .map(Arc::new);
        if let Some(public_issuer) = &public_issuer {
            info!(
                token_key_id = %public_issuer.token_key_id_hex(),
                "✅ V5 public bearer issuer initialized"
            );
        }

        Ok(Self {
            secret_guard: sk_bytes,
            kid,
            pubkey_b64,
            voprf,
            public_issuer,
        })
    }
}
