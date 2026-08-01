// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use anyhow::{anyhow, Context};
use std::net::SocketAddr;
use tracing::{info, warn};

use crate::readiness::TokenFamily;
use crate::replay_authority::ReplayAuthorityConfig;
use crate::store::StoreBackend;

/// Startup settings which are available before the replay store is built.
///
/// The remaining settings are deliberately read by `complete_after_store`.
/// This preserves the verifier's staged startup behavior: replay-store
/// construction still happens before issuer, admin, and TLS configuration is
/// parsed.
pub struct Settings {
    pub(crate) epoch_duration_sec: u64,
    pub(crate) epoch_retention: u32,
    pub(crate) accepted_token_families: Vec<TokenFamily>,
    pub(crate) backend: Option<StoreBackend>,
    pub(crate) store_backend_name: String,
}

pub(crate) struct LoadedSettings {
    pub(crate) epoch_duration_sec: u64,
    pub(crate) epoch_retention: u32,
    pub(crate) accepted_token_families: Vec<TokenFamily>,
    pub(crate) issuer_urls: Vec<String>,
    pub(crate) refresh_interval_min: u64,
    pub(crate) verifier_id: String,
    pub(crate) audience: String,
    pub(crate) scope_digest: [u8; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
    pub(crate) replay_authority_config: ReplayAuthorityConfig,
}

pub(crate) struct AdminSettings {
    pub(crate) admin_api_key: String,
    pub(crate) behind_proxy: bool,
}

impl Settings {
    pub fn from_env() -> anyhow::Result<Self> {
        // ---------- Epoch Configuration ----------
        // Kept for admin config display; V4 tokens rely on key acceptance windows.
        let epoch_duration_sec = std::env::var("EPOCH_DURATION_SEC")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(86400); // Default: 1 day

        let epoch_retention = std::env::var("EPOCH_RETENTION")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2); // Default: accept 2 previous epochs

        // ---------- Backend selection ----------
        let accepted_raw = std::env::var("VERIFIER_ACCEPTED_TOKEN_VERSIONS")
            .context("VERIFIER_ACCEPTED_TOKEN_VERSIONS is required")?;
        let accepted_token_families = parse_accepted_token_families(&accepted_raw)?;

        let memory_opt_in =
            parse_in_memory_replay_store(std::env::var("IN_MEMORY_REPLAY_STORE").ok().as_deref())?;
        let redis_url = std::env::var("REDIS_URL").ok();
        let (backend, store_backend_name) = select_store_backend(
            redis_url,
            memory_opt_in,
            std::env::var("VERIFIER_ENV").ok().as_deref(),
            std::env::var("VERIFIER_ALLOW_UNSAFE").as_deref() == Ok("true"),
        )?;
        if store_backend_name == "memory" {
            warn!("IN_MEMORY_REPLAY_STORE is enabled; this instance is unsafe for production");
        }

        Ok(Self {
            epoch_duration_sec,
            epoch_retention,
            accepted_token_families,
            backend: Some(backend),
            store_backend_name,
        })
    }

    /// Read the settings which historically followed replay-store creation.
    pub(crate) fn complete_after_store(&self) -> anyhow::Result<LoadedSettings> {
        // ---------- Issuer metadata refresh ----------
        // Support multiple issuer URLs (comma-separated) with backward compatibility
        let issuer_urls: Vec<String> = std::env::var("ISSUER_URLS")
            .or_else(|_| std::env::var("ISSUER_URL")) // backward compat
            .unwrap_or_else(|_| "http://127.0.0.1:8081/.well-known/issuer".into())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        info!(
            "Configured {} issuer URL(s): {:?}",
            issuer_urls.len(),
            issuer_urls
        );

        let refresh_interval_min: u64 = std::env::var("REFRESH_INTERVAL_MIN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        let verifier_id = std::env::var("VERIFIER_ID")
            .context("VERIFIER_ID is required so V4 tokens are bound to a verifier scope")?;
        let audience = std::env::var("VERIFIER_AUDIENCE").unwrap_or_else(|_| verifier_id.clone());
        let scope_digest = freebird_crypto::build_scope_digest(&verifier_id, &audience)
            .map_err(|e| anyhow!("invalid verifier scope: {:?}", e))?;
        let replay_authority_config = ReplayAuthorityConfig::from_env()?;

        Ok(LoadedSettings {
            epoch_duration_sec: self.epoch_duration_sec,
            epoch_retention: self.epoch_retention,
            accepted_token_families: self.accepted_token_families.clone(),
            issuer_urls,
            refresh_interval_min,
            verifier_id,
            audience,
            scope_digest,
            replay_authority_config,
        })
    }

    pub(crate) fn complete_admin(&self) -> anyhow::Result<AdminSettings> {
        // ---------- Admin API Configuration ----------
        let admin_api_key = match std::env::var("ADMIN_API_KEY") {
            Ok(key) if key.len() >= 32 => key,
            Ok(key) => anyhow::bail!(
                "ADMIN_API_KEY must be at least 32 characters, got {}",
                key.len()
            ),
            Err(_) => anyhow::bail!("ADMIN_API_KEY must be set (minimum 32 characters)"),
        };
        let behind_proxy = std::env::var("BEHIND_PROXY")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        Ok(AdminSettings {
            admin_api_key,
            behind_proxy,
        })
    }

    pub(crate) fn take_backend(&mut self) -> anyhow::Result<StoreBackend> {
        self.backend
            .take()
            .ok_or_else(|| anyhow!("verifier settings backend was already consumed"))
    }

    /// BIND_ADDR is intentionally read after application construction.
    pub fn bind_addr() -> anyhow::Result<SocketAddr> {
        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8082".into());
        Ok(bind_addr.parse()?)
    }
}

pub(crate) fn parse_accepted_token_families(raw: &str) -> anyhow::Result<Vec<TokenFamily>> {
    let mut families = Vec::new();
    for value in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        let family = match value.to_ascii_lowercase().as_str() {
            "v4" => TokenFamily::V4,
            "v5" => TokenFamily::V5,
            _ => anyhow::bail!("VERIFIER_ACCEPTED_TOKEN_VERSIONS must contain only v4 and/or v5"),
        };
        if !families.contains(&family) {
            families.push(family);
        }
    }
    if families.is_empty() {
        anyhow::bail!("VERIFIER_ACCEPTED_TOKEN_VERSIONS must enable at least one token family");
    }
    Ok(families)
}

pub(crate) fn parse_in_memory_replay_store(raw: Option<&str>) -> anyhow::Result<bool> {
    match raw {
        None => Ok(false),
        Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        Some(_) => anyhow::bail!("IN_MEMORY_REPLAY_STORE must be true or false"),
    }
}

pub(crate) fn in_memory_replay_allowed(
    store_enabled: bool,
    environment: Option<&str>,
    _unsafe_override: bool,
) -> bool {
    // An unsafe override can never turn production into a memory-backed
    // verifier; both the explicit opt-in and development environment are
    // mandatory.
    store_enabled && environment == Some("development")
}

pub(crate) fn select_store_backend(
    redis_url: Option<String>,
    memory_opt_in: bool,
    environment: Option<&str>,
    unsafe_override: bool,
) -> anyhow::Result<(StoreBackend, String)> {
    if let Some(url) = redis_url {
        Ok((StoreBackend::Redis(url), "redis".to_string()))
    } else if in_memory_replay_allowed(memory_opt_in, environment, unsafe_override) {
        Ok((StoreBackend::InMemory, "memory".to_string()))
    } else if memory_opt_in {
        anyhow::bail!(
            "in-memory replay requires IN_MEMORY_REPLAY_STORE=true and VERIFIER_ENV=development"
        )
    } else {
        anyhow::bail!("REDIS_URL is required; development memory replay requires IN_MEMORY_REPLAY_STORE=true and VERIFIER_ENV=development")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        in_memory_replay_allowed, parse_accepted_token_families, parse_in_memory_replay_store,
        select_store_backend,
    };
    use crate::readiness::TokenFamily;

    #[test]
    fn token_family_configuration_is_explicit_and_rejects_disabled() {
        assert!(parse_accepted_token_families("").is_err());
        let accepted = parse_accepted_token_families("v4").unwrap();
        assert!(accepted.contains(&TokenFamily::V4));
        assert!(!accepted.contains(&TokenFamily::V5));
        assert!(!in_memory_replay_allowed(true, Some("production"), false));
        assert!(!in_memory_replay_allowed(false, Some("development"), false));
        assert!(!in_memory_replay_allowed(true, Some("production"), true));
        assert!(in_memory_replay_allowed(true, Some("development"), false));
    }

    #[test]
    fn parsed_backend_policy_is_fail_closed() {
        assert!(!parse_in_memory_replay_store(None).unwrap());
        assert!(!parse_in_memory_replay_store(Some("false")).unwrap());
        assert!(parse_in_memory_replay_store(Some("invalid")).is_err());

        assert!(select_store_backend(None, false, Some("development"), false).is_err());
        assert!(select_store_backend(None, false, Some("production"), false).is_err());
        assert!(matches!(
            select_store_backend(None, true, Some("development"), false)
                .unwrap()
                .0,
            crate::store::StoreBackend::InMemory
        ));
        assert!(select_store_backend(None, true, Some("production"), true).is_err());
    }

    #[test]
    fn redis_backend_selection_has_no_graph_authority_url_policy() {
        assert!(matches!(
            select_store_backend(
                Some("redis://verifier-store:6379/1".into()),
                false,
                Some("production"),
                false,
            )
            .unwrap()
            .0,
            crate::store::StoreBackend::Redis(_)
        ));
    }
}
