// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use anyhow::{Context, Result};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    pub issuer_id: String,
    pub bind_addr: SocketAddr,
    pub token_ttl_min: u64,
    pub require_tls: bool,
    pub behind_proxy: bool,
    pub key_config: KeyConfig,
    pub sybil_config: SybilConfig,
    pub webauthn_config: Option<WebAuthnConfig>,
    pub admin_api_key: Option<String>,
    pub epoch_duration_sec: u64,
    pub epoch_retention: u32,
}

#[derive(Clone, Debug)]
pub struct KeyConfig {
    pub sk_path: PathBuf,
    pub rotation_state_path: PathBuf,
    pub kid_override: Option<String>,
    pub hsm: Option<HsmConfig>,
}

#[derive(Clone, Debug)]
pub struct HsmConfig {
    /// Path to PKCS#11 module (e.g., /usr/lib/softhsm/libsofthsm2.so)
    pub module_path: String,
    /// HSM slot number
    pub slot: u64,
    /// HSM PIN for authentication
    pub pin: String,
    /// Key label in HSM
    pub key_label: String,
    /// Mode: "storage" (key in HSM, ops in software) or "full" (all ops in HSM, not yet supported)
    pub mode: HsmMode,
}

#[derive(Clone, Debug, PartialEq)]
pub enum HsmMode {
    /// Keys stored in HSM, extracted for software VOPRF operations
    /// Provides: Key protection at rest, fast operations
    Storage,
    /// All operations in HSM (not yet implemented)
    /// Provides: Full HSM protection, slower operations
    Full,
}

#[derive(Clone, Debug)]
pub struct SybilConfig {
    pub mode: String, // "none", "invitation", "pow", "rate_limit", "progressive_trust", "combined"
    pub pow_difficulty: u32,
    pub rate_limit_secs: u64,
    pub invite_per_user: u32,
    pub invite_cooldown_secs: u64,
    pub invite_expires_secs: u64,
    pub invite_new_user_wait_secs: u64,
    pub invite_persistence_path: PathBuf,
    pub invite_autosave_interval_secs: u64,
    pub bootstrap_users: Option<String>,
    pub webauthn_max_proof_age: Option<i64>,
    // Progressive Trust configuration
    pub progressive_trust_levels: Vec<String>, // Format: "age_secs:tokens:cooldown_secs"
    pub progressive_trust_persistence_path: PathBuf,
    pub progressive_trust_autosave_interval: u64,
    pub progressive_trust_hmac_secret: Option<String>,
    pub progressive_trust_salt: String,
    // Proof of Diversity configuration
    pub proof_of_diversity_min_score: u8,
    pub proof_of_diversity_persistence_path: PathBuf,
    pub proof_of_diversity_autosave_interval: u64,
    pub proof_of_diversity_hmac_secret: Option<String>,
    pub proof_of_diversity_fingerprint_salt: String,
    // Multi-Party Vouching configuration
    pub multi_party_vouching_required_vouchers: u32,
    pub multi_party_vouching_cooldown_secs: u64,
    pub multi_party_vouching_expires_secs: u64,
    pub multi_party_vouching_new_user_wait_secs: u64,
    pub multi_party_vouching_persistence_path: PathBuf,
    pub multi_party_vouching_autosave_interval: u64,
    pub multi_party_vouching_hmac_secret: Option<String>,
    pub multi_party_vouching_salt: String,
    // Federated Trust configuration
    pub federated_trust_enabled: bool,
    pub federated_trust_max_depth: u32,
    pub federated_trust_min_paths: u32,
    pub federated_trust_require_direct: bool,
    pub federated_trust_min_trust_level: u8,
    pub federated_trust_cache_ttl_secs: u64,
    pub federated_trust_max_token_age_secs: i64,
    pub federated_trust_trusted_roots: Vec<String>,
    pub federated_trust_blocked_issuers: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub redis_url: Option<String>,
    pub cred_ttl: Option<u64>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let issuer_id = env::var("ISSUER_ID").unwrap_or_else(|_| "issuer:freebird:v1".to_string());
        
        let bind_str = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".to_string());
        let bind_addr: SocketAddr = bind_str.parse()
            .context(format!("Invalid BIND_ADDR: {}", bind_str))?;

        let token_ttl_min = env::var("TOKEN_TTL_MIN")
            .ok().and_then(|s| s.parse().ok()).unwrap_or(10).clamp(1, 24 * 60);

        let require_tls = env_bool("REQUIRE_TLS");
        let behind_proxy = env_bool("BEHIND_PROXY");
        let admin_api_key = env::var("ADMIN_API_KEY").ok().filter(|k| !k.is_empty());

        // Epoch configuration for key rotation
        let epoch_duration_sec = env_u64("EPOCH_DURATION_SEC", 86400); // Default: 1 day
        let epoch_retention = env_u32("EPOCH_RETENTION", 2); // Default: accept 2 previous epochs

        Ok(Self {
            issuer_id,
            bind_addr,
            token_ttl_min,
            require_tls,
            behind_proxy,
            key_config: KeyConfig::from_env(),
            sybil_config: SybilConfig::from_env(),
            webauthn_config: WebAuthnConfig::from_env(),
            admin_api_key,
            epoch_duration_sec,
            epoch_retention,
        })
    }
}

impl KeyConfig {
    fn from_env() -> Self {
        Self {
            sk_path: env::var("ISSUER_SK_PATH").map(PathBuf::from).unwrap_or_else(|_| "issuer_sk.bin".into()),
            rotation_state_path: env::var("KEY_ROTATION_STATE_PATH").map(PathBuf::from).unwrap_or_else(|_| "key_rotation_state.json".into()),
            kid_override: env::var("KID").ok(),
            hsm: HsmConfig::from_env(),
        }
    }
}

impl HsmConfig {
    fn from_env() -> Option<Self> {
        // Only create HSM config if HSM_ENABLE is set to true
        if !env_bool("HSM_ENABLE") {
            return None;
        }

        // Parse HSM mode
        let mode_str = env::var("HSM_MODE").unwrap_or_else(|_| "storage".to_string());
        let mode = match mode_str.to_lowercase().as_str() {
            "full" => HsmMode::Full,
            "storage" | _ => HsmMode::Storage,
        };

        // Get required HSM configuration
        let module_path = env::var("HSM_MODULE_PATH")
            .expect("HSM_MODULE_PATH required when HSM_ENABLE=true");

        let slot = env::var("HSM_SLOT")
            .expect("HSM_SLOT required when HSM_ENABLE=true")
            .parse()
            .expect("HSM_SLOT must be a valid u64");

        let pin = env::var("HSM_PIN")
            .expect("HSM_PIN required when HSM_ENABLE=true");

        let key_label = env::var("HSM_KEY_LABEL")
            .expect("HSM_KEY_LABEL required when HSM_ENABLE=true");

        Some(Self {
            module_path,
            slot,
            pin,
            key_label,
            mode,
        })
    }
}

impl SybilConfig {
    fn from_env() -> Self {
        // Parse progressive trust levels from env
        let progressive_trust_levels = env::var("SYBIL_PROGRESSIVE_TRUST_LEVELS")
            .unwrap_or_else(|_| "0:1:86400,2592000:10:3600,7776000:100:60".to_string())
            .split(',')
            .map(|s| s.to_string())
            .collect();

        Self {
            mode: env::var("SYBIL_RESISTANCE").unwrap_or_else(|_| "none".to_string()),
            pow_difficulty: env_u32("SYBIL_POW_DIFFICULTY", 20),
            rate_limit_secs: env_u64("SYBIL_RATE_LIMIT_SECS", 3600),
            invite_per_user: env_u32("SYBIL_INVITE_PER_USER", 5),
            invite_cooldown_secs: env_u64("SYBIL_INVITE_COOLDOWN_SECS", 3600),
            invite_expires_secs: env_u64("SYBIL_INVITE_EXPIRES_SECS", 30 * 24 * 3600),
            invite_new_user_wait_secs: env_u64("SYBIL_INVITE_NEW_USER_WAIT_SECS", 30 * 24 * 3600),
            invite_persistence_path: env::var("SYBIL_INVITE_PERSISTENCE_PATH").map(PathBuf::from).unwrap_or_else(|_| "invitations.json".into()),
            invite_autosave_interval_secs: env_u64("SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS", 300),
            bootstrap_users: env::var("SYBIL_INVITE_BOOTSTRAP_USERS").ok(),
            webauthn_max_proof_age: env::var("WEBAUTHN_MAX_PROOF_AGE").ok().and_then(|s| s.parse().ok()),
            // Progressive Trust
            progressive_trust_levels,
            progressive_trust_persistence_path: env::var("SYBIL_PROGRESSIVE_TRUST_PERSISTENCE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "progressive_trust.json".into()),
            progressive_trust_autosave_interval: env_u64("SYBIL_PROGRESSIVE_TRUST_AUTOSAVE_SECS", 300),
            progressive_trust_hmac_secret: env::var("SYBIL_PROGRESSIVE_TRUST_SECRET").ok(),
            progressive_trust_salt: env::var("SYBIL_PROGRESSIVE_TRUST_SALT")
                .unwrap_or_else(|_| "default-salt-change-in-production".to_string()),
            // Proof of Diversity
            proof_of_diversity_min_score: env_u32("SYBIL_PROOF_OF_DIVERSITY_MIN_SCORE", 40) as u8,
            proof_of_diversity_persistence_path: env::var("SYBIL_PROOF_OF_DIVERSITY_PERSISTENCE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "proof_of_diversity.json".into()),
            proof_of_diversity_autosave_interval: env_u64("SYBIL_PROOF_OF_DIVERSITY_AUTOSAVE_SECS", 300),
            proof_of_diversity_hmac_secret: env::var("SYBIL_PROOF_OF_DIVERSITY_SECRET").ok(),
            proof_of_diversity_fingerprint_salt: env::var("SYBIL_PROOF_OF_DIVERSITY_SALT")
                .unwrap_or_else(|_| "default-salt-change-in-production".to_string()),
            // Multi-Party Vouching
            multi_party_vouching_required_vouchers: env_u32("SYBIL_MULTI_PARTY_VOUCHING_REQUIRED", 3),
            multi_party_vouching_cooldown_secs: env_u64("SYBIL_MULTI_PARTY_VOUCHING_COOLDOWN_SECS", 3600),
            multi_party_vouching_expires_secs: env_u64("SYBIL_MULTI_PARTY_VOUCHING_EXPIRES_SECS", 2592000),
            multi_party_vouching_new_user_wait_secs: env_u64("SYBIL_MULTI_PARTY_VOUCHING_NEW_USER_WAIT_SECS", 2592000),
            multi_party_vouching_persistence_path: env::var("SYBIL_MULTI_PARTY_VOUCHING_PERSISTENCE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "multi_party_vouching.json".into()),
            multi_party_vouching_autosave_interval: env_u64("SYBIL_MULTI_PARTY_VOUCHING_AUTOSAVE_SECS", 300),
            multi_party_vouching_hmac_secret: env::var("SYBIL_MULTI_PARTY_VOUCHING_SECRET").ok(),
            multi_party_vouching_salt: env::var("SYBIL_MULTI_PARTY_VOUCHING_SALT")
                .unwrap_or_else(|_| "default-salt-change-in-production".to_string()),
            // Federated Trust
            federated_trust_enabled: env_bool("SYBIL_FEDERATED_TRUST_ENABLED"),
            federated_trust_max_depth: env_u32("SYBIL_FEDERATED_TRUST_MAX_DEPTH", 2),
            federated_trust_min_paths: env_u32("SYBIL_FEDERATED_TRUST_MIN_PATHS", 1),
            federated_trust_require_direct: env_bool("SYBIL_FEDERATED_TRUST_REQUIRE_DIRECT"),
            federated_trust_min_trust_level: env_u32("SYBIL_FEDERATED_TRUST_MIN_TRUST_LEVEL", 50) as u8,
            federated_trust_cache_ttl_secs: env_u64("SYBIL_FEDERATED_TRUST_CACHE_TTL_SECS", 3600),
            federated_trust_max_token_age_secs: env_u64("SYBIL_FEDERATED_TRUST_MAX_TOKEN_AGE_SECS", 600) as i64,
            federated_trust_trusted_roots: env::var("SYBIL_FEDERATED_TRUST_TRUSTED_ROOTS")
                .ok()
                .map(|s| s.split(',').map(|s| s.to_string()).collect())
                .unwrap_or_default(),
            federated_trust_blocked_issuers: env::var("SYBIL_FEDERATED_TRUST_BLOCKED_ISSUERS")
                .ok()
                .map(|s| s.split(',').map(|s| s.to_string()).collect())
                .unwrap_or_default(),
        }
    }
}

impl WebAuthnConfig {
    fn from_env() -> Option<Self> {
        // Only return config if RP_ID and ORIGIN are set
        if let (Ok(rp_id), Ok(rp_origin)) = (env::var("WEBAUTHN_RP_ID"), env::var("WEBAUTHN_RP_ORIGIN")) {
            Some(Self {
                rp_id,
                rp_origin,
                rp_name: env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "Freebird".to_string()),
                redis_url: env::var("WEBAUTHN_REDIS_URL").ok(),
                cred_ttl: env::var("WEBAUTHN_CRED_TTL_SECS").ok().and_then(|s| s.parse().ok()),
            })
        } else {
            None
        }
    }
}

// Helpers
fn env_bool(key: &str) -> bool {
    env::var(key).map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false)
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

fn env_u32(key: &str, default: u32) -> u32 {
    env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_hsm_config_disabled_by_default() {
        // Clear HSM environment variables
        env::remove_var("HSM_ENABLE");
        env::remove_var("HSM_MODULE_PATH");
        env::remove_var("HSM_SLOT");
        env::remove_var("HSM_PIN");
        env::remove_var("HSM_KEY_LABEL");

        let hsm_config = HsmConfig::from_env();
        assert!(hsm_config.is_none(), "HSM should be disabled by default");
    }

    #[test]
    #[serial]
    fn test_hsm_config_storage_mode() {
        // Set HSM environment variables
        env::set_var("HSM_ENABLE", "true");
        env::set_var("HSM_MODE", "storage");
        env::set_var("HSM_MODULE_PATH", "/usr/lib/softhsm/libsofthsm2.so");
        env::set_var("HSM_SLOT", "0");
        env::set_var("HSM_PIN", "1234");
        env::set_var("HSM_KEY_LABEL", "test-key");

        let hsm_config = HsmConfig::from_env();
        assert!(hsm_config.is_some(), "HSM should be enabled");

        let config = hsm_config.unwrap();
        assert_eq!(config.mode, HsmMode::Storage);
        assert_eq!(config.module_path, "/usr/lib/softhsm/libsofthsm2.so");
        assert_eq!(config.slot, 0);
        assert_eq!(config.pin, "1234");
        assert_eq!(config.key_label, "test-key");

        // Cleanup
        env::remove_var("HSM_ENABLE");
        env::remove_var("HSM_MODE");
        env::remove_var("HSM_MODULE_PATH");
        env::remove_var("HSM_SLOT");
        env::remove_var("HSM_PIN");
        env::remove_var("HSM_KEY_LABEL");
    }

    #[test]
    #[serial]
    fn test_hsm_config_full_mode() {
        env::set_var("HSM_ENABLE", "true");
        env::set_var("HSM_MODE", "full");
        env::set_var("HSM_MODULE_PATH", "/usr/lib/libykcs11.so");
        env::set_var("HSM_SLOT", "1");
        env::set_var("HSM_PIN", "5678");
        env::set_var("HSM_KEY_LABEL", "yubikey");

        let hsm_config = HsmConfig::from_env().expect("Should parse HSM config");
        assert_eq!(hsm_config.mode, HsmMode::Full);

        // Cleanup
        env::remove_var("HSM_ENABLE");
        env::remove_var("HSM_MODE");
        env::remove_var("HSM_MODULE_PATH");
        env::remove_var("HSM_SLOT");
        env::remove_var("HSM_PIN");
        env::remove_var("HSM_KEY_LABEL");
    }

    #[test]
    #[serial]
    fn test_hsm_config_defaults_to_storage() {
        // Clear all HSM vars first to avoid test pollution
        env::remove_var("HSM_ENABLE");
        env::remove_var("HSM_MODE");
        env::remove_var("HSM_MODULE_PATH");
        env::remove_var("HSM_SLOT");
        env::remove_var("HSM_PIN");
        env::remove_var("HSM_KEY_LABEL");

        // Now set required vars (but not HSM_MODE)
        env::set_var("HSM_ENABLE", "true");
        env::set_var("HSM_MODULE_PATH", "/usr/lib/softhsm/libsofthsm2.so");
        env::set_var("HSM_SLOT", "0");
        env::set_var("HSM_PIN", "1234");
        env::set_var("HSM_KEY_LABEL", "test");

        let hsm_config = HsmConfig::from_env().expect("Should parse HSM config");
        assert_eq!(hsm_config.mode, HsmMode::Storage, "Should default to Storage mode");

        // Cleanup
        env::remove_var("HSM_ENABLE");
        env::remove_var("HSM_MODE");
        env::remove_var("HSM_MODULE_PATH");
        env::remove_var("HSM_SLOT");
        env::remove_var("HSM_PIN");
        env::remove_var("HSM_KEY_LABEL");
    }

    #[test]
    #[serial]
    #[should_panic(expected = "HSM_MODULE_PATH required")]
    fn test_hsm_config_missing_module_path() {
        env::set_var("HSM_ENABLE", "true");
        env::remove_var("HSM_MODULE_PATH");
        env::set_var("HSM_SLOT", "0");
        env::set_var("HSM_PIN", "1234");
        env::set_var("HSM_KEY_LABEL", "test");

        HsmConfig::from_env();
    }

    #[test]
    #[serial]
    #[should_panic(expected = "HSM_SLOT required")]
    fn test_hsm_config_missing_slot() {
        env::set_var("HSM_ENABLE", "true");
        env::set_var("HSM_MODULE_PATH", "/usr/lib/softhsm/libsofthsm2.so");
        env::remove_var("HSM_SLOT");
        env::set_var("HSM_PIN", "1234");
        env::set_var("HSM_KEY_LABEL", "test");

        HsmConfig::from_env();
    }
}