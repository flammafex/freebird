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
}

#[derive(Clone, Debug)]
pub struct SybilConfig {
    pub mode: String, // "none", "invitation", "pow", "rate_limit", "combined"
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
        }
    }
}

impl SybilConfig {
    fn from_env() -> Self {
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