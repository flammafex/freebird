// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use anyhow::{Context, Result};
use freebird_common::duration::env_duration;
use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

pub(crate) const HSM_ENABLE_UNSUPPORTED_MESSAGE: &str =
    "HSM_ENABLE=true is unsupported: issuer startup provider integration is not implemented; set HSM_ENABLE=false or omit HSM_ENABLE";

#[derive(Clone, Debug)]
pub struct Config {
    pub issuer_id: String,
    pub bind_addr: SocketAddr,
    pub require_tls: bool,
    pub behind_proxy: bool,
    pub key_config: KeyConfig,
    pub sybil_config: SybilConfig,
    pub webauthn_config: Option<WebAuthnConfig>,
    pub admin_api_key: Option<String>,
    pub epoch_duration_sec: u64,
    pub epoch_retention: u32,
    /// V4 key rotation is deliberately restricted to development environments.
    pub allow_unsafe_v4_rotation: bool,
    pub audit_log_path: PathBuf,
    /// Explicit development-only mode which permits non-persistent dependencies.
    pub unsafe_development_mode: bool,
}

#[derive(Clone, Debug)]
pub struct KeyConfig {
    pub sk_path: PathBuf,
    pub rotation_state_path: PathBuf,
    pub kid_override: Option<String>,
    pub hsm: Option<HsmConfig>,
}

impl KeyConfig {
    fn from_env() -> Result<Self> {
        Ok(Self {
            sk_path: env::var("ISSUER_SK_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "issuer_sk.bin".into()),
            rotation_state_path: env::var("KEY_ROTATION_STATE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "key_rotation_state.json".into()),
            kid_override: env::var("KID").ok(),
            hsm: HsmConfig::from_env()?,
        })
    }
}

#[derive(Clone)]
pub struct HsmConfig {
    /// Reserved path to a PKCS#11 module (e.g., /usr/lib/softhsm/libsofthsm2.so).
    /// Issuer startup currently rejects HSM_ENABLE=true.
    pub module_path: String,
    /// Reserved HSM slot number.
    pub slot: u64,
    /// Reserved HSM PIN for authentication.
    pub pin: String,
    /// Reserved key label in HSM.
    pub key_label: String,
    /// Reserved mode: "storage" or "full". Neither is available through issuer startup.
    pub mode: HsmMode,
}

impl fmt::Debug for HsmConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HsmConfig")
            .field("module_path", &self.module_path)
            .field("slot", &self.slot)
            .field("pin", &"[REDACTED]")
            .field("key_label", &self.key_label)
            .field("mode", &self.mode)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum HsmMode {
    /// Reserved storage mode; issuer startup integration is not implemented.
    Storage,
    /// Reserved full mode; issuer startup integration is not implemented.
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
    pub invite_signing_key_path: PathBuf,
    pub bootstrap_users: Option<String>,
    pub webauthn_max_proof_age: Option<i64>,
    // Progressive Trust configuration
    pub progressive_trust_levels: Vec<String>, // Format: "age_secs:tokens:cooldown_secs"
    pub progressive_trust_persistence_path: PathBuf,
    pub progressive_trust_autosave_interval: u64,
    pub progressive_trust_hmac_secret: Option<String>,
    pub progressive_trust_hmac_secret_path: PathBuf,
    pub progressive_trust_salt: String,
    pub progressive_trust_allow_insecure: bool,
    // Proof of Diversity configuration
    pub proof_of_diversity_min_score: u8,
    pub proof_of_diversity_persistence_path: PathBuf,
    pub proof_of_diversity_autosave_interval: u64,
    pub proof_of_diversity_hmac_secret: Option<String>,
    pub proof_of_diversity_hmac_secret_path: PathBuf,
    pub proof_of_diversity_fingerprint_salt: String,
    pub proof_of_diversity_allow_insecure: bool,
    // Multi-Party Vouching configuration
    pub multi_party_vouching_required_vouchers: u32,
    pub multi_party_vouching_cooldown_secs: u64,
    pub multi_party_vouching_expires_secs: u64,
    pub multi_party_vouching_new_user_wait_secs: u64,
    pub multi_party_vouching_persistence_path: PathBuf,
    pub multi_party_vouching_autosave_interval: u64,
    pub multi_party_vouching_hmac_secret: Option<String>,
    pub multi_party_vouching_hmac_secret_path: PathBuf,
    pub multi_party_vouching_salt: String,
    pub multi_party_vouching_allow_insecure: bool,
    // Social Graph configuration
    pub social_graph_attesters_path: PathBuf,
    pub social_graph_jwks_url: Option<String>,
    pub social_graph_key_refresh_interval_secs: u64,
    pub social_graph_min_level: u8,
    pub social_graph_accepted_policy_ids: Vec<String>,
    pub social_graph_attestation_max_age_secs: u64,
    pub social_graph_clock_skew_secs: u64,
    pub social_graph_require_request_binding: bool,
    pub social_graph_require_quota_nullifier: bool,
    pub social_graph_replay_ttl_secs: u64,
    pub social_graph_state_path: PathBuf,
    pub social_graph_fail_closed: bool,
    // Combined mode configuration
    pub combined_mechanisms: Vec<String>, // e.g., ["pow", "rate_limit", "progressive_trust"]
    pub combined_mode: String,            // "or", "and", "threshold"
    pub combined_threshold: u32,          // Required number of mechanisms for threshold mode
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
        let issuer_id = env::var("ISSUER_ID").unwrap_or_else(|_| "issuer:freebird:v4".to_string());

        let bind_str = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".to_string());
        let bind_addr: SocketAddr = bind_str
            .parse()
            .context(format!("Invalid BIND_ADDR: {}", bind_str))?;

        let require_tls = env_bool("REQUIRE_TLS");
        let behind_proxy = env_bool("BEHIND_PROXY");
        if behind_proxy {
            freebird_common::tls_enforcement::TlsEnforcementLayer::from_env()
                .map_err(|e| anyhow::anyhow!(e))?;
        }
        let admin_api_key = env::var("ADMIN_API_KEY").ok().filter(|k| !k.is_empty());
        let freebird_env = env::var("FREEBIRD_ENV").unwrap_or_else(|_| "production".to_string());
        let unsafe_development_mode = env_bool("FREEBIRD_UNSAFE_DEVELOPMENT_MODE");
        if unsafe_development_mode && freebird_env != "development" {
            anyhow::bail!("FREEBIRD_UNSAFE_DEVELOPMENT_MODE=true is only permitted when FREEBIRD_ENV=development");
        }
        let unsafe_rotation_override = env_bool("ALLOW_UNSAFE_V4_ROTATION");
        if unsafe_rotation_override && freebird_env != "development" {
            anyhow::bail!(
                "ALLOW_UNSAFE_V4_ROTATION=true is only permitted when FREEBIRD_ENV=development"
            );
        }
        let hsm_enabled = parse_hsm_enable()?;
        if hsm_enabled {
            anyhow::bail!(HSM_ENABLE_UNSUPPORTED_MESSAGE);
        }

        // Epoch configuration for key rotation (supports human-readable: "1d", "24h", etc.)
        let epoch_duration_sec = env_duration("EPOCH_DURATION", 86400); // Default: 1 day
        let epoch_retention = env_u32("EPOCH_RETENTION", 2); // Default: accept 2 previous epochs

        Ok(Self {
            issuer_id,
            bind_addr,
            require_tls,
            behind_proxy,
            key_config: KeyConfig::from_env()?,
            sybil_config: SybilConfig::from_env()?,
            webauthn_config: WebAuthnConfig::from_env(),
            admin_api_key,
            epoch_duration_sec,
            epoch_retention,
            allow_unsafe_v4_rotation: freebird_env == "development" && unsafe_rotation_override,
            audit_log_path: env::var("AUDIT_LOG_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "/var/lib/freebird/issuer/audit_log.json".into()),
            unsafe_development_mode,
        })
    }
}

impl HsmConfig {
    fn from_env() -> Result<Option<Self>> {
        // Only create HSM config if HSM_ENABLE is set to true
        if !parse_hsm_enable()? {
            return Ok(None);
        }

        // Parse HSM mode
        let mode_str = env::var("HSM_MODE").unwrap_or_else(|_| "storage".to_string());
        let mode = match mode_str.to_lowercase().as_str() {
            "full" => HsmMode::Full,
            _ => HsmMode::Storage,
        };

        // Get required HSM configuration
        let module_path =
            env::var("HSM_MODULE_PATH").expect("HSM_MODULE_PATH required when HSM_ENABLE=true");

        let slot = env::var("HSM_SLOT")
            .expect("HSM_SLOT required when HSM_ENABLE=true")
            .parse()
            .expect("HSM_SLOT must be a valid u64");

        let pin = env::var("HSM_PIN").expect("HSM_PIN required when HSM_ENABLE=true");

        let key_label =
            env::var("HSM_KEY_LABEL").expect("HSM_KEY_LABEL required when HSM_ENABLE=true");

        Ok(Some(Self {
            module_path,
            slot,
            pin,
            key_label,
            mode,
        }))
    }
}

impl SybilConfig {
    fn from_env() -> Result<Self> {
        let mode = env::var("SYBIL_RESISTANCE").map_err(|_| {
            anyhow::anyhow!(
                "SYBIL_RESISTANCE must be explicitly set; use SYBIL_RESISTANCE=none only for a deliberate no-checker opt-out"
            )
        })?;

        // Parse progressive trust levels from env
        // Format supports human-readable durations: "0:1:1d,30d:10:1h,90d:100:1m"
        let progressive_trust_levels = env::var("SYBIL_PROGRESSIVE_TRUST_LEVELS")
            .unwrap_or_else(|_| "0:1:1d,30d:10:1h,90d:100:1m".to_string())
            .split(',')
            .map(|s| s.to_string())
            .collect();

        Ok(Self {
            mode,
            pow_difficulty: env_u32("SYBIL_POW_DIFFICULTY", 20),
            // Duration fields now support human-readable formats: "1h", "30m", "1d", etc.
            rate_limit_secs: env_duration("SYBIL_RATE_LIMIT", 3600), // Default: 1h
            invite_per_user: env_u32("SYBIL_INVITE_PER_USER", 5),
            invite_cooldown_secs: env_duration("SYBIL_INVITE_COOLDOWN", 3600), // Default: 1h
            invite_expires_secs: env_duration("SYBIL_INVITE_EXPIRES", 30 * 24 * 3600), // Default: 30d
            invite_new_user_wait_secs: env_duration("SYBIL_INVITE_NEW_USER_WAIT", 30 * 24 * 3600), // Default: 30d
            invite_persistence_path: env::var("SYBIL_INVITE_PERSISTENCE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "invitations.json".into()),
            invite_autosave_interval_secs: env_duration("SYBIL_INVITE_AUTOSAVE_INTERVAL", 300), // Default: 5m
            invite_signing_key_path: env::var("SYBIL_INVITE_SIGNING_KEY_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "invitation_signing_key.bin".into()),
            bootstrap_users: env::var("SYBIL_INVITE_BOOTSTRAP_USERS").ok(),
            webauthn_max_proof_age: env::var("WEBAUTHN_MAX_PROOF_AGE")
                .ok()
                .and_then(|s| freebird_common::duration::parse_duration(&s).ok())
                .map(|d| d as i64),
            // Progressive Trust
            progressive_trust_levels,
            progressive_trust_persistence_path: env::var(
                "SYBIL_PROGRESSIVE_TRUST_PERSISTENCE_PATH",
            )
            .map(PathBuf::from)
            .unwrap_or_else(|_| "progressive_trust.json".into()),
            progressive_trust_autosave_interval: env_duration(
                "SYBIL_PROGRESSIVE_TRUST_AUTOSAVE",
                300,
            ), // Default: 5m
            progressive_trust_hmac_secret: env::var("SYBIL_PROGRESSIVE_TRUST_SECRET").ok(),
            progressive_trust_hmac_secret_path: env::var("SYBIL_PROGRESSIVE_TRUST_SECRET_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "progressive_trust_secret.bin".into()),
            progressive_trust_salt: env::var("SYBIL_PROGRESSIVE_TRUST_SALT")
                .unwrap_or_else(|_| generate_random_salt()),
            progressive_trust_allow_insecure: env_bool("SYBIL_PROGRESSIVE_TRUST_ALLOW_INSECURE"),
            // Proof of Diversity
            proof_of_diversity_min_score: env_u32("SYBIL_PROOF_OF_DIVERSITY_MIN_SCORE", 40) as u8,
            proof_of_diversity_persistence_path: env::var(
                "SYBIL_PROOF_OF_DIVERSITY_PERSISTENCE_PATH",
            )
            .map(PathBuf::from)
            .unwrap_or_else(|_| "proof_of_diversity.json".into()),
            proof_of_diversity_autosave_interval: env_duration(
                "SYBIL_PROOF_OF_DIVERSITY_AUTOSAVE",
                300,
            ), // Default: 5m
            proof_of_diversity_hmac_secret: env::var("SYBIL_PROOF_OF_DIVERSITY_SECRET").ok(),
            proof_of_diversity_hmac_secret_path: env::var("SYBIL_PROOF_OF_DIVERSITY_SECRET_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "proof_of_diversity_secret.bin".into()),
            proof_of_diversity_fingerprint_salt: env::var("SYBIL_PROOF_OF_DIVERSITY_SALT")
                .unwrap_or_else(|_| generate_random_salt()),
            proof_of_diversity_allow_insecure: env_bool("SYBIL_PROOF_OF_DIVERSITY_ALLOW_INSECURE"),
            // Multi-Party Vouching
            multi_party_vouching_required_vouchers: env_u32(
                "SYBIL_MULTI_PARTY_VOUCHING_REQUIRED",
                3,
            ),
            multi_party_vouching_cooldown_secs: env_duration(
                "SYBIL_MULTI_PARTY_VOUCHING_COOLDOWN",
                3600,
            ), // Default: 1h
            multi_party_vouching_expires_secs: env_duration(
                "SYBIL_MULTI_PARTY_VOUCHING_EXPIRES",
                2592000,
            ), // Default: 30d
            multi_party_vouching_new_user_wait_secs: env_duration(
                "SYBIL_MULTI_PARTY_VOUCHING_NEW_USER_WAIT",
                2592000,
            ), // Default: 30d
            multi_party_vouching_persistence_path: env::var(
                "SYBIL_MULTI_PARTY_VOUCHING_PERSISTENCE_PATH",
            )
            .map(PathBuf::from)
            .unwrap_or_else(|_| "multi_party_vouching.json".into()),
            multi_party_vouching_autosave_interval: env_duration(
                "SYBIL_MULTI_PARTY_VOUCHING_AUTOSAVE",
                300,
            ), // Default: 5m
            multi_party_vouching_hmac_secret: env::var("SYBIL_MULTI_PARTY_VOUCHING_SECRET").ok(),
            multi_party_vouching_hmac_secret_path: env::var(
                "SYBIL_MULTI_PARTY_VOUCHING_SECRET_PATH",
            )
            .map(PathBuf::from)
            .unwrap_or_else(|_| "multi_party_vouching_secret.bin".into()),
            multi_party_vouching_salt: env::var("SYBIL_MULTI_PARTY_VOUCHING_SALT")
                .unwrap_or_else(|_| generate_random_salt()),
            multi_party_vouching_allow_insecure: env_bool(
                "SYBIL_MULTI_PARTY_VOUCHING_ALLOW_INSECURE",
            ),
            // Social Graph
            social_graph_attesters_path: env::var("SOCIAL_GRAPH_ATTESTERS_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "social_graph_attesters.json".into()),
            social_graph_jwks_url: env::var("SOCIAL_GRAPH_JWKS_URL").ok(),
            social_graph_key_refresh_interval_secs: env_duration(
                "SOCIAL_GRAPH_KEY_REFRESH_INTERVAL",
                3600,
            ),
            social_graph_min_level: env_u32("SOCIAL_GRAPH_MIN_LEVEL", 1) as u8,
            social_graph_accepted_policy_ids: env::var("SOCIAL_GRAPH_ACCEPTED_POLICY_IDS")
                .ok()
                .map(|s| {
                    s.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            social_graph_attestation_max_age_secs: env_duration(
                "SOCIAL_GRAPH_ATTESTATION_MAX_AGE",
                300,
            ),
            social_graph_clock_skew_secs: env_duration("SOCIAL_GRAPH_CLOCK_SKEW_SECS", 30),
            social_graph_require_request_binding: env::var("SOCIAL_GRAPH_REQUIRE_REQUEST_BINDING")
                .map(|v| {
                    !matches!(
                        v.to_ascii_lowercase().as_str(),
                        "0" | "false" | "no" | "off"
                    )
                })
                .unwrap_or(true),
            social_graph_require_quota_nullifier: env_bool("SOCIAL_GRAPH_REQUIRE_QUOTA_NULLIFIER"),
            social_graph_replay_ttl_secs: env_duration("SOCIAL_GRAPH_REPLAY_TTL", 600),
            social_graph_state_path: env::var("SOCIAL_GRAPH_STATE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "social_graph_state.json".into()),
            social_graph_fail_closed: env::var("SOCIAL_GRAPH_FAIL_CLOSED")
                .map(|v| {
                    !matches!(
                        v.to_ascii_lowercase().as_str(),
                        "0" | "false" | "no" | "off"
                    )
                })
                .unwrap_or(true),
            // Combined mode configuration
            combined_mechanisms: env::var("SYBIL_COMBINED_MECHANISMS")
                .ok()
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_else(|| vec!["pow".to_string(), "rate_limit".to_string()]),
            combined_mode: env::var("SYBIL_COMBINED_MODE").unwrap_or_else(|_| "or".to_string()),
            combined_threshold: env_u32("SYBIL_COMBINED_THRESHOLD", 2),
        })
    }
}

impl WebAuthnConfig {
    fn from_env() -> Option<Self> {
        // Only return config if RP_ID and ORIGIN are set
        if let (Ok(rp_id), Ok(rp_origin)) =
            (env::var("WEBAUTHN_RP_ID"), env::var("WEBAUTHN_RP_ORIGIN"))
        {
            Some(Self {
                rp_id,
                rp_origin,
                rp_name: env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "Freebird".to_string()),
                redis_url: env::var("WEBAUTHN_REDIS_URL").ok(),
                // Supports human-readable durations: "30d", "1h", etc.
                cred_ttl: env::var("WEBAUTHN_CRED_TTL")
                    .ok()
                    .and_then(|s| freebird_common::duration::parse_duration(&s).ok()),
            })
        } else {
            None
        }
    }
}

// Helpers
/// Parse the issuer's HSM enable flag without applying the permissive parsing
/// used by unrelated boolean configuration.
pub fn parse_hsm_enable() -> Result<bool> {
    match env::var("HSM_ENABLE") {
        Ok(value) if value.eq_ignore_ascii_case("true") || value == "1" => Ok(true),
        Ok(value) if value.eq_ignore_ascii_case("false") || value == "0" => Ok(false),
        Ok(value) => anyhow::bail!(
            "HSM_ENABLE must be one of true, false, 1, or 0; got {:?}",
            value
        ),
        Err(env::VarError::NotPresent) => Ok(false),
        Err(env::VarError::NotUnicode(_)) => {
            anyhow::bail!("HSM_ENABLE must be one of true, false, 1, or 0")
        }
    }
}

fn env_bool(key: &str) -> bool {
    env_bool_default(key, false)
}

fn env_bool_default(key: &str, default: bool) -> bool {
    env::var(key)
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(default)
}

fn env_u32(key: &str, default: u32) -> u32 {
    env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn generate_random_salt() -> String {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    hex::encode(salt)
}
