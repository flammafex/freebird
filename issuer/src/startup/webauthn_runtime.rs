// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use crate::webauthn;
use anyhow::{bail, Context};
use std::sync::Arc;
use tracing::{info, warn};

pub(super) fn build(
    config: Option<&crate::config::WebAuthnConfig>,
    behind_proxy: bool,
) -> anyhow::Result<Option<Arc<crate::webauthn::WebAuthnState>>> {
    let Some(wa_conf) = config else {
        return Ok(None);
    };

    info!(
        target: "freebird_issuer::startup",
        "🔐 Initializing WebAuthn subsystem for RP: {}",
        wa_conf.rp_id
    );

    // Security: Enforce WEBAUTHN_PROOF_SECRET when WebAuthn is enabled
    if std::env::var("WEBAUTHN_PROOF_SECRET").is_err() {
        bail!("WEBAUTHN_PROOF_SECRET must be set when WebAuthn is enabled");
    }

    let ctx = webauthn::WebAuthnCtx::new(
        wa_conf.rp_id.clone(),
        wa_conf.rp_name.clone(),
        wa_conf.rp_origin.clone(),
    )
    .context("Failed to create WebAuthn context")?;

    let store = if let Some(url) = &wa_conf.redis_url {
        info!(target: "freebird_issuer::startup", "Using Redis for WebAuthn credentials");
        webauthn::CredentialStore::Redis(
            webauthn::RedisCredStore::new(url, wa_conf.cred_ttl)
                .context("Failed to connect to WebAuthn Redis")?,
        )
    } else {
        warn!(
            target: "freebird_issuer::startup",
            "⚠️  Using in-memory WebAuthn credential storage"
        );
        webauthn::CredentialStore::InMemory(webauthn::InMemoryCredStore::new())
    };

    Ok(Some(webauthn::WebAuthnState::new(ctx, store, behind_proxy)))
}

#[cfg(all(test, feature = "human-gate-webauthn"))]
mod tests {
    use super::build;
    use crate::config::WebAuthnConfig;
    use crate::webauthn;
    use serial_test::serial;
    use std::env;
    use std::ffi::OsString;

    const PROOF_SECRET: &str = "webauthn-runtime-test-proof-secret";

    struct ProofSecretGuard {
        previous: Option<OsString>,
    }

    impl ProofSecretGuard {
        fn set(value: Option<OsString>) -> Self {
            let previous = env::var_os("WEBAUTHN_PROOF_SECRET");
            match value {
                Some(value) => env::set_var("WEBAUTHN_PROOF_SECRET", value),
                None => env::remove_var("WEBAUTHN_PROOF_SECRET"),
            }
            Self { previous }
        }
    }

    impl Drop for ProofSecretGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => env::set_var("WEBAUTHN_PROOF_SECRET", value),
                None => env::remove_var("WEBAUTHN_PROOF_SECRET"),
            }
        }
    }

    fn config(redis_url: Option<&str>) -> WebAuthnConfig {
        WebAuthnConfig {
            rp_id: "localhost".into(),
            rp_name: "Freebird WebAuthn Runtime Tests".into(),
            rp_origin: "http://localhost".into(),
            redis_url: redis_url.map(str::to_owned),
            cred_ttl: Some(3600),
        }
    }

    #[test]
    #[serial]
    fn none_ignores_secret() {
        let _secret = ProofSecretGuard::set(None);

        assert!(build(None, false)
            .expect("disabled WebAuthn should succeed")
            .is_none());
    }

    #[test]
    #[serial]
    fn in_memory_config_preserves_fields_and_secret() {
        let original = OsString::from(PROOF_SECRET);
        let _secret = ProofSecretGuard::set(Some(original.clone()));
        let config = config(None);

        let state = build(Some(&config), true)
            .expect("in-memory WebAuthn should build")
            .expect("WebAuthn state should be present");

        assert_eq!(state.webauthn.rp_id, config.rp_id);
        assert_eq!(state.webauthn.rp_name, config.rp_name);
        assert_eq!(state.webauthn.rp_origin, config.rp_origin);
        assert!(state.behind_proxy);
        assert!(matches!(
            &state.cred_store,
            webauthn::CredentialStore::InMemory(_)
        ));
        assert_eq!(env::var_os("WEBAUTHN_PROOF_SECRET"), Some(original));
    }

    #[test]
    #[serial]
    fn valid_redis_url_selects_redis_without_connecting() {
        let _secret = ProofSecretGuard::set(Some(OsString::from(PROOF_SECRET)));
        let config = config(Some("redis://127.0.0.1:1/"));

        let state = build(Some(&config), false)
            .expect("valid Redis URL should build without connecting")
            .expect("WebAuthn state should be present");

        assert!(matches!(
            &state.cred_store,
            webauthn::CredentialStore::Redis(_)
        ));
    }

    #[test]
    #[serial]
    fn missing_proof_secret_yields_exact_redacted_error() {
        let _secret = ProofSecretGuard::set(None);
        let config = config(None);

        let error = match build(Some(&config), false) {
            Ok(_) => panic!("missing proof secret should fail"),
            Err(error) => error,
        };

        assert_eq!(
            error.to_string(),
            "WEBAUTHN_PROOF_SECRET must be set when WebAuthn is enabled"
        );
        assert!(!error.to_string().contains(PROOF_SECRET));
    }
}
