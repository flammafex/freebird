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
    pub native_bearer_v7_config: NativeBearerV7Config,
    pub exchange_config: ExchangeConfig,
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

/// Separate startup configuration for the native randomized V7 bearer issuer.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct NativeBearerV7Config {
    pub sk_path: PathBuf,
    pub metadata_path: PathBuf,
    pub registry_path: PathBuf,
    pub profile_id: String,
    #[serde(default)]
    pub descriptor_id: String,
    /// Explicit lowercase hexadecimal encoding of the raw 32-byte V7 key ID.
    pub token_key_id: String,
    pub asset_id: String,
    pub amount_minor: u64,
    pub validity_secs: u64,
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

impl NativeBearerV7Config {
    fn from_env() -> Result<Self> {
        if env::var("NATIVE_BEARER_V7_ENABLE")
            .ok()
            .is_some_and(|value| value.eq_ignore_ascii_case("false") || value == "0")
        {
            anyhow::bail!("native V7 bearer issuance is mandatory")
        }
        let config = Self {
            sk_path: required_path("NATIVE_BEARER_V7_SK_PATH")?,
            metadata_path: required_path("NATIVE_BEARER_V7_METADATA_PATH")?,
            registry_path: required_path("NATIVE_BEARER_V7_REGISTRY_PATH")?,
            profile_id: env::var("NATIVE_BEARER_V7_PROFILE_ID")
                .unwrap_or_else(|_| freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID.into()),
            descriptor_id: env::var("NATIVE_BEARER_V7_DESCRIPTOR_ID")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_default(),
            token_key_id: env::var("NATIVE_BEARER_V7_TOKEN_KEY_ID")
                .context("NATIVE_BEARER_V7_TOKEN_KEY_ID is required")?,
            asset_id: env::var("NATIVE_BEARER_V7_ASSET_ID")
                .context("NATIVE_BEARER_V7_ASSET_ID is required")?,
            amount_minor: env::var("NATIVE_BEARER_V7_AMOUNT_MINOR")
                .context("NATIVE_BEARER_V7_AMOUNT_MINOR is required")?
                .parse()
                .context("NATIVE_BEARER_V7_AMOUNT_MINOR must be an integer")?,
            validity_secs: env::var("NATIVE_BEARER_V7_VALIDITY")
                .ok()
                .map(|value| freebird_common::duration::parse_duration(&value))
                .transpose()?
                .unwrap_or(30 * 24 * 3600),
        };
        if config.validity_secs == 0
            || config.profile_id.trim().is_empty()
            || config.token_key_id.len() != 64
            || !config
                .token_key_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            anyhow::bail!("invalid NATIVE_BEARER_V7 configuration")
        }
        if config.profile_id != freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID {
            anyhow::bail!(
                "NATIVE_BEARER_V7_PROFILE_ID must be {}",
                freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID
            )
        }
        if !config.descriptor_id.is_empty() {
            freebird_common::api::validate_v7_canonical_id(&config.descriptor_id, "descriptor_id")
                .map_err(anyhow::Error::msg)?;
        }
        freebird_crypto::V7BodyPolicy::new(config.asset_id.clone(), config.amount_minor)
            .map_err(|error| anyhow::anyhow!("invalid V7 body policy: {error:?}"))?;
        Ok(config)
    }
}

pub(crate) fn load_v7_additional_signer_configs() -> Result<Vec<NativeBearerV7Config>> {
    let paths = parse_v7_additional_signer_config_paths(
        env::var("NATIVE_V7_SIGNER_CONFIG_PATHS").ok().as_deref(),
    )?;
    let mut configs = Vec::new();
    for path in paths {
        let value: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&path)
                .with_context(|| format!("read V7 signer config {}", path.display()))?,
        )?;
        let mut parsed = match value {
            serde_json::Value::Array(_) => {
                serde_json::from_value::<Vec<NativeBearerV7Config>>(value)?
            }
            value => vec![serde_json::from_value::<NativeBearerV7Config>(value)?],
        };
        for config in &parsed {
            validate_v7_signer_config(config)?;
        }
        configs.append(&mut parsed);
    }
    Ok(configs)
}

fn parse_v7_additional_signer_config_paths(raw_paths: Option<&str>) -> Result<Vec<PathBuf>> {
    let Some(raw_paths) = raw_paths.filter(|paths| !paths.trim().is_empty()) else {
        return Ok(Vec::new());
    };

    raw_paths
        .split(',')
        .map(|raw_path| {
            let path = PathBuf::from(raw_path.trim());
            if path.as_os_str().is_empty() {
                anyhow::bail!("NATIVE_V7_SIGNER_CONFIG_PATHS contains an empty path")
            }
            Ok(path)
        })
        .collect()
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
        load_v7_additional_signer_configs()?;

        // Epoch configuration for key rotation (supports human-readable: "1d", "24h", etc.)
        let epoch_duration_sec = env_duration("EPOCH_DURATION", 86400); // Default: 1 day
        let epoch_retention = env_u32("EPOCH_RETENTION", 2); // Default: accept 2 previous epochs

        Ok(Self {
            issuer_id,
            bind_addr,
            require_tls,
            behind_proxy,
            key_config: KeyConfig::from_env()?,
            native_bearer_v7_config: NativeBearerV7Config::from_env()?,
            exchange_config: ExchangeConfig::from_env()?,
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

#[derive(Clone, Debug)]
pub struct ExchangeConfig {
    pub enabled: bool,
    pub active_graph_path: PathBuf,
    pub retained_graph_paths: Vec<PathBuf>,
    pub active_receipt_key_path: PathBuf,
    pub active_receipt_metadata_path: PathBuf,
    pub retained_receipt_key_paths: Vec<PathBuf>,
    pub retained_receipt_metadata_paths: Vec<PathBuf>,
    pub redis_url: Option<String>,
    pub receipt_lifetime_secs: u64,
    pub request_body_limit: usize,
    pub request_timeout_secs: u64,
    pub graph_issuance: GraphIssuanceConfig,
}

#[derive(Clone)]
pub struct GraphIssuanceConfig {
    pub enabled: bool,
    pub policy_path: PathBuf,
    pub v7_verifier_id: String,
    pub v7_audience: String,
    pub authorization: GraphIssuanceAuthorizationConfig,
}

#[derive(Clone)]
pub enum GraphIssuanceAuthorizationConfig {
    HmacSha256(Vec<u8>),
    V4Local {
        keys: Vec<GraphIssuanceV4VerificationKey>,
    },
    DevelopmentMock,
    Disabled,
}

#[derive(Clone)]
pub struct GraphIssuanceV4VerificationKey {
    pub issuer_id: String,
    pub kid: String,
    pub secret_key: [u8; 32],
}

impl fmt::Debug for GraphIssuanceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphIssuanceConfig")
            .field("enabled", &self.enabled)
            .field("policy_path", &self.policy_path)
            .field("authorization", &self.authorization)
            .finish()
    }
}

impl fmt::Debug for GraphIssuanceAuthorizationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HmacSha256(_) => formatter.write_str("HmacSha256([REDACTED])"),
            Self::V4Local { keys } => formatter
                .debug_struct("V4Local")
                .field("trusted_key_count", &keys.len())
                .finish(),
            Self::DevelopmentMock => formatter.write_str("DevelopmentMock"),
            Self::Disabled => formatter.write_str("Disabled"),
        }
    }
}

impl ExchangeConfig {
    pub fn from_env() -> Result<Self> {
        let enabled = env_bool("NATIVE_EXCHANGE_V7_ENABLE");
        let comma_paths = |name: &str| -> Result<Vec<PathBuf>> {
            let Some(value) = env::var(name).ok() else {
                return Ok(Vec::new());
            };
            if value.trim().is_empty() {
                return Ok(Vec::new());
            }
            value
                .split(',')
                .map(|path| {
                    let path = path.trim();
                    if path.is_empty() {
                        anyhow::bail!("{name} contains an empty path")
                    }
                    Ok(PathBuf::from(path))
                })
                .collect()
        };
        let active_graph_path = env::var("NATIVE_EXCHANGE_V7_DISCOVERY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| "native_exchange_v7_discovery.json".into());
        let retained_graph_paths = comma_paths("NATIVE_EXCHANGE_V7_RETAINED_DISCOVERY_PATHS")?;
        let config = Self {
            enabled,
            active_graph_path,
            retained_graph_paths,
            active_receipt_key_path: env::var("NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_KEY_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "native_exchange_v7_receipt.key".into()),
            active_receipt_metadata_path: env::var(
                "NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_METADATA_PATH",
            )
            .map(PathBuf::from)
            .unwrap_or_else(|_| "native_exchange_v7_receipt_metadata.json".into()),
            retained_receipt_key_paths: comma_paths(
                "NATIVE_EXCHANGE_V7_RETAINED_RECEIPT_KEY_PATHS",
            )?,
            retained_receipt_metadata_paths: comma_paths(
                "NATIVE_EXCHANGE_V7_RETAINED_RECEIPT_METADATA_PATHS",
            )?,
            redis_url: env::var("NATIVE_EXCHANGE_V7_REDIS_URL").ok(),
            receipt_lifetime_secs: env::var("NATIVE_EXCHANGE_V7_RECEIPT_LIFETIME")
                .ok()
                .map(|value| freebird_common::duration::parse_duration(&value))
                .transpose()?
                .unwrap_or(86_400),
            request_body_limit: env::var("NATIVE_EXCHANGE_V7_MAX_BODY_BYTES")
                .ok()
                .map(|value| value.parse::<usize>())
                .transpose()?
                .unwrap_or(3 * 1024 * 1024),
            request_timeout_secs: env::var("NATIVE_EXCHANGE_V7_TIMEOUT")
                .ok()
                .map(|value| freebird_common::duration::parse_duration(&value))
                .transpose()?
                .unwrap_or(30),
            graph_issuance: GraphIssuanceConfig::from_env()?,
        };
        if config.enabled {
            if config.active_graph_path.as_os_str().is_empty()
                || config.active_receipt_key_path.as_os_str().is_empty()
                || config.active_receipt_metadata_path.as_os_str().is_empty()
            {
                anyhow::bail!("exchange paths must not be empty")
            }
            if config.retained_receipt_key_paths.len()
                != config.retained_receipt_metadata_paths.len()
            {
                anyhow::bail!("retained exchange receipt key and metadata path counts must match")
            }
            if config.redis_url.as_deref().is_none_or(str::is_empty) {
                anyhow::bail!("NATIVE_EXCHANGE_V7_REDIS_URL is required")
            }
            if config.receipt_lifetime_secs == 0
                || !(1024..=4 * 1024 * 1024).contains(&config.request_body_limit)
                || config.request_timeout_secs == 0
                || config.request_timeout_secs > 120
            {
                anyhow::bail!("exchange lifetime/body/timeout bounds are invalid")
            }
        }
        if config.graph_issuance.enabled && !config.enabled {
            anyhow::bail!("V7 graph issuance requires NATIVE_EXCHANGE_V7_ENABLE=true")
        }
        Ok(config)
    }

    pub async fn validate_redis_durability(&self) -> Result<()> {
        let client = redis::Client::open(
            self.redis_url
                .as_deref()
                .context("V7 exchange Redis URL missing")?,
        )?;
        let mut connection = client.get_async_connection().await?;
        let _: String = redis::cmd("PING").query_async(&mut connection).await?;
        Ok(())
    }
}

impl GraphIssuanceConfig {
    fn from_env() -> Result<Self> {
        use base64ct::{Base64UrlUnpadded, Encoding};

        let enabled = env_bool("NATIVE_GRAPH_ISSUANCE_V7_ENABLE");
        let policy_path = env::var("NATIVE_GRAPH_ISSUANCE_V7_POLICY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| "native_graph_issuance_v7_discovery.json".into());
        if !enabled {
            return Ok(Self {
                enabled,
                policy_path,
                v7_verifier_id: String::new(),
                v7_audience: String::new(),
                authorization: GraphIssuanceAuthorizationConfig::Disabled,
            });
        }
        if policy_path.as_os_str().is_empty() {
            anyhow::bail!("NATIVE_GRAPH_ISSUANCE_V7_POLICY_PATH must not be empty")
        }
        if !env_bool("NATIVE_EXCHANGE_V7_ENABLE") {
            anyhow::bail!("V7 graph issuance requires NATIVE_EXCHANGE_V7_ENABLE=true")
        }
        let mode = env::var("NATIVE_GRAPH_ISSUANCE_V7_AUTHORIZATION")
            .unwrap_or_else(|_| "v4_local".into());
        let (v7_verifier_id, v7_audience) = if mode == "v4_local" {
            (
                env::var("NATIVE_GRAPH_ISSUANCE_V7_VERIFIER_ID")
                    .context("NATIVE_GRAPH_ISSUANCE_V7_VERIFIER_ID is required")?,
                env::var("NATIVE_GRAPH_ISSUANCE_V7_AUDIENCE")
                    .context("NATIVE_GRAPH_ISSUANCE_V7_AUDIENCE is required")?,
            )
        } else {
            (String::new(), String::new())
        };
        let authorization = match mode.as_str() {
            "v4_local" => {
                let raw = env::var("NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64")
                    .context("NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64 is required")?;
                let encoded: std::collections::BTreeMap<
                    String,
                    std::collections::BTreeMap<String, String>,
                > = serde_json::from_str(&raw).context("parse graph issuance V4 keyring JSON")?;
                let mut keys = Vec::new();
                for (issuer_id, issuer_keys) in encoded {
                    if issuer_id.is_empty() || issuer_id.len() > 255 || issuer_keys.is_empty() {
                        anyhow::bail!("invalid graph issuance V4 issuer keyring")
                    }
                    for (kid, encoded_key) in issuer_keys {
                        let bytes = Base64UrlUnpadded::decode_vec(&encoded_key)
                            .context("invalid graph issuance V4 verification key encoding")?;
                        if kid.is_empty()
                            || kid.len() > 255
                            || bytes.len() != 32
                            || Base64UrlUnpadded::encode_string(&bytes) != encoded_key
                        {
                            anyhow::bail!("invalid graph issuance V4 verification key")
                        }
                        keys.push(GraphIssuanceV4VerificationKey {
                            issuer_id: issuer_id.clone(),
                            kid,
                            secret_key: bytes
                                .try_into()
                                .map_err(|_| anyhow::anyhow!("invalid V4 key length"))?,
                        });
                    }
                }
                if keys.is_empty() {
                    anyhow::bail!("graph issuance V4 keyring cannot be empty")
                }
                GraphIssuanceAuthorizationConfig::V4Local { keys }
            }
            "hmac_sha256" | "development_mock" => anyhow::bail!(
                "V7 graph issuance authorization must be v4_local; {mode} is not supported"
            ),
            _ => anyhow::bail!("unsupported V7 graph issuance authorization verifier"),
        };
        Ok(Self {
            enabled,
            policy_path,
            v7_verifier_id,
            v7_audience,
            authorization,
        })
    }
}

fn validate_v7_signer_config(config: &NativeBearerV7Config) -> Result<()> {
    if config.sk_path.as_os_str().is_empty()
        || config.metadata_path.as_os_str().is_empty()
        || config.registry_path.as_os_str().is_empty()
        || config.profile_id.trim().is_empty()
    {
        anyhow::bail!("V7 signer paths and profile must not be empty")
    }
    if config.validity_secs == 0 {
        anyhow::bail!("V7 signer validity must be positive")
    }
    if config.token_key_id.len() != 64
        || !config
            .token_key_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("V7 signer token key ID must be 64 lowercase hexadecimal characters")
    }
    if !config.descriptor_id.trim().is_empty() {
        freebird_common::api::validate_v7_canonical_id(&config.descriptor_id, "descriptor_id")
            .map_err(anyhow::Error::msg)?;
    }
    if !config.descriptor_id.is_empty() && config.descriptor_id == config.token_key_id {
        anyhow::bail!("V7 signer token and descriptor identifiers must be distinct")
    }
    freebird_crypto::V7BodyPolicy::new(config.asset_id.clone(), config.amount_minor)
        .map_err(|error| anyhow::anyhow!("invalid V7 signer body policy: {error:?}"))?;
    Ok(())
}

fn required_path(name: &str) -> Result<PathBuf> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    if value.trim().is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    Ok(PathBuf::from(value))
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

#[cfg(test)]
mod tests {
    use super::{
        parse_v7_additional_signer_config_paths, validate_v7_signer_config, NativeBearerV7Config,
    };
    use std::path::PathBuf;

    #[test]
    fn unset_v7_additional_signer_config_paths_are_empty() {
        assert_eq!(
            parse_v7_additional_signer_config_paths(None).unwrap(),
            Vec::<PathBuf>::new()
        );
    }

    #[test]
    fn empty_v7_additional_signer_config_paths_are_empty() {
        assert_eq!(
            parse_v7_additional_signer_config_paths(Some("")).unwrap(),
            Vec::<PathBuf>::new()
        );
    }

    #[test]
    fn whitespace_only_v7_additional_signer_config_paths_are_empty() {
        assert_eq!(
            parse_v7_additional_signer_config_paths(Some(" \t\n ")).unwrap(),
            Vec::<PathBuf>::new()
        );
    }

    #[test]
    fn internal_empty_v7_additional_signer_config_path_is_rejected() {
        assert!(parse_v7_additional_signer_config_paths(Some("first,,second")).is_err());
    }

    #[test]
    fn graph_signer_descriptor_may_be_bootstrapped_or_pinned() {
        let base = PathBuf::from("graph-v7-test");
        let config = NativeBearerV7Config {
            sk_path: base.join("signer.der"),
            metadata_path: base.join("signer.json"),
            registry_path: base.join("registry.json"),
            profile_id: freebird_common::api::NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
            descriptor_id: String::new(),
            token_key_id: "01".repeat(32),
            asset_id: "USD".into(),
            amount_minor: 1,
            validity_secs: 3600,
        };
        assert!(validate_v7_signer_config(&config).is_ok());
    }
}
