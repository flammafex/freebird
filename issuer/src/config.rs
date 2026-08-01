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

pub(crate) const EXCHANGE_DISABLED_PUBLICATION_ACK_VERSION: &str =
    "freebird/exchange-disabled-publication-ack/v1";
pub(crate) const HSM_ENABLE_UNSUPPORTED_MESSAGE: &str =
    "HSM_ENABLE=true is unsupported: issuer startup provider integration is not implemented; set HSM_ENABLE=false or omit HSM_ENABLE";

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExchangeDisabledPublicationAcknowledgementV1 {
    pub version: String,
    pub issuer_id: String,
    pub graph_id: String,
    pub disabled_transition_ids: Vec<String>,
    pub acknowledged_admission_state: String,
    pub operator: String,
    pub acknowledged_at_unix: u64,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub issuer_id: String,
    pub bind_addr: SocketAddr,
    pub require_tls: bool,
    pub behind_proxy: bool,
    pub key_config: KeyConfig,
    pub public_key_config: PublicKeyConfig,
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

#[derive(Clone, Debug)]
pub struct PublicKeyConfig {
    pub enabled: bool,
    pub sk_path: PathBuf,
    pub metadata_path: PathBuf,
    pub validity_secs: u64,
    pub audience: Option<String>,
    pub modulus_bits: usize,
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
            public_key_config: PublicKeyConfig::from_env(),
            exchange_config: ExchangeConfig::from_env()?,
            sybil_config: SybilConfig::from_env(),
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
    pub public_history_path: Option<PathBuf>,
    pub disabled_publication_ack_paths: Vec<PathBuf>,
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

pub struct LoadedExchangeConfigV2 {
    pub active_graph: crate::exchange::profiles::ExchangeProfileV2,
    pub retained_graphs: Vec<crate::exchange::profiles::ExchangeProfileV2>,
    pub receipt_keys: crate::exchange::ReceiptKeyRing,
    pub public_history: Option<crate::exchange::history::ExchangePublicHistoryV2>,
}

impl ExchangeConfig {
    pub fn from_env() -> Result<Self> {
        reject_removed_v1_exchange_env()?;
        let enabled = env_bool("PUBLIC_BEARER_EXCHANGE_ENABLE");
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
        let active_graph_path = env::var("PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| "public_bearer_exchange_graph_v2.json".into());
        let retained_graph_paths = comma_paths("PUBLIC_BEARER_EXCHANGE_RETAINED_GRAPH_PATHS")?;
        let config = Self {
            enabled,
            active_graph_path,
            retained_graph_paths,
            public_history_path: env::var("PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH")
                .ok()
                .filter(|path| !path.trim().is_empty())
                .map(PathBuf::from),
            disabled_publication_ack_paths: comma_paths(
                "PUBLIC_BEARER_EXCHANGE_DISABLED_PUBLICATION_ACK_PATHS",
            )?,
            active_receipt_key_path: env::var("PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_KEY_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "public_bearer_exchange_receipt.key".into()),
            active_receipt_metadata_path: env::var(
                "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_METADATA_PATH",
            )
            .map(PathBuf::from)
            .unwrap_or_else(|_| "public_bearer_exchange_receipt_metadata.json".into()),
            retained_receipt_key_paths: comma_paths(
                "PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_KEY_PATHS",
            )?,
            retained_receipt_metadata_paths: comma_paths(
                "PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_METADATA_PATHS",
            )?,
            redis_url: env::var("PUBLIC_BEARER_EXCHANGE_REDIS_URL").ok(),
            receipt_lifetime_secs: env::var("PUBLIC_BEARER_EXCHANGE_RECEIPT_LIFETIME")
                .ok()
                .map(|value| freebird_common::duration::parse_duration(&value))
                .transpose()?
                .unwrap_or(86_400),
            request_body_limit: env::var("PUBLIC_BEARER_EXCHANGE_MAX_BODY_BYTES")
                .ok()
                .map(|value| value.parse::<usize>())
                .transpose()?
                .unwrap_or(3 * 1024 * 1024),
            request_timeout_secs: env::var("PUBLIC_BEARER_EXCHANGE_TIMEOUT")
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
                anyhow::bail!("PUBLIC_BEARER_EXCHANGE_REDIS_URL is required")
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
            anyhow::bail!("graph issuance requires PUBLIC_BEARER_EXCHANGE_ENABLE=true")
        }
        Ok(config)
    }

    pub fn load_v2(
        &self,
        issuer_id: &str,
        direct_v5_spki: Option<&[u8]>,
    ) -> Result<LoadedExchangeConfigV2> {
        use crate::exchange::profiles::{
            validate_exchange_profile_set_v2, ExchangeProfileV2, ExchangeProfileValidationModeV2,
        };

        let active_graph = ExchangeProfileV2::load(
            &self.active_graph_path,
            ExchangeProfileValidationModeV2::Active,
            issuer_id,
            direct_v5_spki,
        )
        .context("invalid active V2 exchange graph")?;
        let retained_graphs = self
            .retained_graph_paths
            .iter()
            .map(|path| {
                ExchangeProfileV2::load(
                    path,
                    ExchangeProfileValidationModeV2::Retained,
                    issuer_id,
                    direct_v5_spki,
                )
                .with_context(|| format!("invalid retained V2 exchange graph {}", path.display()))
            })
            .collect::<Result<Vec<_>>>()?;
        validate_exchange_profile_set_v2(
            &active_graph,
            &retained_graphs,
            issuer_id,
            direct_v5_spki,
        )
        .context("invalid active/retained V2 exchange graph set")?;

        let load_metadata =
            |path: &PathBuf| -> Result<freebird_common::api::ExchangeReceiptKeyInfo> {
                serde_json::from_slice(
                    &std::fs::read(path)
                        .with_context(|| format!("read receipt metadata {}", path.display()))?,
                )
                .with_context(|| format!("parse receipt metadata {}", path.display()))
            };
        let active_receipt = crate::exchange::ReceiptKeyConfig {
            metadata: load_metadata(&self.active_receipt_metadata_path)?,
            private_key_path: self.active_receipt_key_path.clone(),
        };
        let retained_receipts = self
            .retained_receipt_key_paths
            .iter()
            .zip(&self.retained_receipt_metadata_paths)
            .map(|(key, metadata)| {
                Ok(crate::exchange::ReceiptKeyConfig {
                    metadata: load_metadata(metadata)?,
                    private_key_path: key.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let receipt_keys =
            crate::exchange::ReceiptKeyRing::load_v2(active_receipt, &retained_receipts)
                .context("invalid active/retained V2 exchange receipt signers")?;
        let public_history = self
            .public_history_path
            .as_deref()
            .map(crate::exchange::history::load_public_history_v2)
            .transpose()
            .context("invalid V2 exchange public history")?;

        Ok(LoadedExchangeConfigV2 {
            active_graph,
            retained_graphs,
            receipt_keys,
            public_history,
        })
    }

    pub async fn validate_redis_durability(&self) -> Result<()> {
        let store = crate::exchange::store::ExchangeStore::new(
            self.redis_url
                .as_deref()
                .context("exchange Redis URL missing")?,
        )?;
        store.validate_durable_standalone().await
    }

    pub(crate) fn load_disabled_publication_acknowledgements(
        &self,
    ) -> Result<Vec<ExchangeDisabledPublicationAcknowledgementV1>> {
        load_disabled_publication_acknowledgements(&self.disabled_publication_ack_paths)
    }
}

/// V1 fixed-profile exchange configuration was removed. Reject its former
/// aliases instead of silently interpreting or ignoring them.
pub fn reject_removed_v1_exchange_env() -> Result<()> {
    for name in [
        "PUBLIC_BEARER_EXCHANGE_PROFILE_PATH",
        "PUBLIC_BEARER_EXCHANGE_RETAINED_PROFILE_PATHS",
        "PUBLIC_BEARER_EXCHANGE_RECEIPT_KEY_PATH",
    ] {
        if env::var_os(name).is_some() {
            anyhow::bail!("{name} was removed with V1 fixed-profile exchange")
        }
    }
    Ok(())
}

impl GraphIssuanceConfig {
    fn from_env() -> Result<Self> {
        use base64ct::{Base64UrlUnpadded, Encoding};

        let enabled = env_bool("PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE");
        let policy_path = env::var("PUBLIC_BEARER_GRAPH_ISSUANCE_POLICY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| "public_bearer_graph_issuance_policy_v2.json".into());
        if !enabled {
            return Ok(Self {
                enabled,
                policy_path,
                authorization: GraphIssuanceAuthorizationConfig::Disabled,
            });
        }
        if policy_path.as_os_str().is_empty() {
            anyhow::bail!("PUBLIC_BEARER_GRAPH_ISSUANCE_POLICY_PATH must not be empty")
        }
        let mode = env::var("PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION")
            .unwrap_or_else(|_| "hmac_sha256".into());
        let authorization = match mode.as_str() {
            "hmac_sha256" => {
                let encoded = env::var("PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64")
                    .context("PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64 is required")?;
                let secret = Base64UrlUnpadded::decode_vec(&encoded)
                    .context("invalid graph issuance HMAC secret encoding")?;
                if secret.len() < 32 || Base64UrlUnpadded::encode_string(&secret) != encoded {
                    anyhow::bail!("graph issuance HMAC secret must be canonical base64url for at least 32 bytes")
                }
                GraphIssuanceAuthorizationConfig::HmacSha256(secret)
            }
            "v4_local" => {
                let raw = env::var("PUBLIC_BEARER_GRAPH_ISSUANCE_V4_KEYRING_B64")
                    .context("PUBLIC_BEARER_GRAPH_ISSUANCE_V4_KEYRING_B64 is required")?;
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
            "development_mock" => {
                if env::var("FREEBIRD_ENV").as_deref() != Ok("development")
                    || !env_bool("FREEBIRD_UNSAFE_DEVELOPMENT_MODE")
                    || !env_bool("PUBLIC_BEARER_GRAPH_ISSUANCE_ALLOW_DEVELOPMENT_MOCK")
                {
                    anyhow::bail!("development graph issuance authorization requires all development safety fences")
                }
                GraphIssuanceAuthorizationConfig::DevelopmentMock
            }
            _ => anyhow::bail!("unsupported graph issuance authorization verifier"),
        };
        Ok(Self {
            enabled,
            policy_path,
            authorization,
        })
    }
}

pub(crate) fn load_disabled_publication_acknowledgements(
    paths: &[PathBuf],
) -> Result<Vec<ExchangeDisabledPublicationAcknowledgementV1>> {
    paths
        .iter()
        .map(|path| {
            let acknowledgement: ExchangeDisabledPublicationAcknowledgementV1 =
                serde_json::from_slice(&std::fs::read(path).with_context(|| {
                    format!(
                        "read disabled-publication acknowledgement {}",
                        path.display()
                    )
                })?)
                .with_context(|| {
                    format!(
                        "parse disabled-publication acknowledgement {}",
                        path.display()
                    )
                })?;
            validate_disabled_publication_acknowledgement(&acknowledgement)
                .with_context(|| path.display().to_string())?;
            Ok(acknowledgement)
        })
        .collect()
}

fn validate_disabled_publication_acknowledgement(
    acknowledgement: &ExchangeDisabledPublicationAcknowledgementV1,
) -> Result<()> {
    use std::collections::HashSet;

    let canonical_id = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    };
    let mut transitions = HashSet::new();
    if acknowledgement.version != EXCHANGE_DISABLED_PUBLICATION_ACK_VERSION
        || acknowledgement.issuer_id.is_empty()
        || acknowledgement.issuer_id.len() > 256
        || !acknowledgement.issuer_id.is_ascii()
        || !canonical_id(&acknowledgement.graph_id)
        || acknowledgement.disabled_transition_ids.is_empty()
        || acknowledgement
            .disabled_transition_ids
            .iter()
            .any(|id| !canonical_id(id) || !transitions.insert(id))
        || acknowledgement.acknowledged_admission_state != "disabled"
        || acknowledgement.operator.trim().is_empty()
        || acknowledgement.acknowledged_at_unix == 0
    {
        anyhow::bail!("invalid disabled-publication acknowledgement")
    }
    Ok(())
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

impl PublicKeyConfig {
    fn from_env() -> Self {
        Self {
            enabled: env_bool_default("PUBLIC_BEARER_ENABLE", true),
            sk_path: env::var("PUBLIC_BEARER_SK_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "public_bearer_sk.der".into()),
            metadata_path: env::var("PUBLIC_BEARER_METADATA_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "public_bearer_metadata.json".into()),
            validity_secs: env_duration("PUBLIC_BEARER_VALIDITY", 30 * 24 * 3600),
            audience: env::var("PUBLIC_BEARER_AUDIENCE")
                .ok()
                .filter(|v| !v.is_empty()),
            modulus_bits: env::var("PUBLIC_BEARER_MODULUS_BITS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2048),
        }
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
    fn from_env() -> Self {
        // Parse progressive trust levels from env
        // Format supports human-readable durations: "0:1:1d,30d:10:1h,90d:100:1m"
        let progressive_trust_levels = env::var("SYBIL_PROGRESSIVE_TRUST_LEVELS")
            .unwrap_or_else(|_| "0:1:1d,30d:10:1h,90d:100:1m".to_string())
            .split(',')
            .map(|s| s.to_string())
            .collect();

        Self {
            mode: env::var("SYBIL_RESISTANCE").unwrap_or_else(|_| "none".to_string()),
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
        }
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
    use super::*;
    use serial_test::serial;

    struct EnvGuard {
        values: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn new() -> Self {
            let keys = [
                "FREEBIRD_ENV",
                "FREEBIRD_UNSAFE_DEVELOPMENT_MODE",
                "ALLOW_UNSAFE_V4_ROTATION",
                "ISSUER_ID",
                "BIND_ADDR",
                "REQUIRE_TLS",
                "BEHIND_PROXY",
                "TRUSTED_PROXY_CIDRS",
                "ADMIN_API_KEY",
                "AUDIT_LOG_PATH",
                "ISSUER_SK_PATH",
                "KEY_ROTATION_STATE_PATH",
                "KID",
                "HSM_ENABLE",
                "HSM_MODE",
                "HSM_MODULE_PATH",
                "HSM_SLOT",
                "HSM_PIN",
                "HSM_KEY_LABEL",
                "PUBLIC_BEARER_ENABLE",
                "PUBLIC_BEARER_SK_PATH",
                "PUBLIC_BEARER_METADATA_PATH",
                "PUBLIC_BEARER_VALIDITY",
                "PUBLIC_BEARER_AUDIENCE",
                "PUBLIC_BEARER_MODULUS_BITS",
                "PUBLIC_BEARER_EXCHANGE_ENABLE",
                "PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH",
                "PUBLIC_BEARER_EXCHANGE_RETAINED_GRAPH_PATHS",
                "PUBLIC_BEARER_EXCHANGE_PROFILE_PATH",
                "PUBLIC_BEARER_EXCHANGE_RETAINED_PROFILE_PATHS",
                "PUBLIC_BEARER_EXCHANGE_RECEIPT_KEY_PATH",
                "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_KEY_PATH",
                "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_METADATA_PATH",
                "PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_KEY_PATHS",
                "PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_METADATA_PATHS",
                "PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH",
                "PUBLIC_BEARER_EXCHANGE_DISABLED_PUBLICATION_ACK_PATHS",
                "PUBLIC_BEARER_EXCHANGE_REDIS_URL",
                "PUBLIC_BEARER_EXCHANGE_RECEIPT_LIFETIME",
                "PUBLIC_BEARER_EXCHANGE_MAX_BODY_BYTES",
                "PUBLIC_BEARER_EXCHANGE_TIMEOUT",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_POLICY_PATH",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_V4_REPLAY_REDIS_URL",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_V4_KEYRING_B64",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_ALLOW_DEVELOPMENT_MOCK",
                "SYBIL_RESISTANCE",
                "SYBIL_PROGRESSIVE_TRUST_SALT",
                "SYBIL_PROOF_OF_DIVERSITY_SALT",
                "SYBIL_MULTI_PARTY_VOUCHING_SALT",
                "WEBAUTHN_RP_ID",
                "WEBAUTHN_RP_NAME",
                "WEBAUTHN_RP_ORIGIN",
                "WEBAUTHN_REDIS_URL",
                "WEBAUTHN_CRED_TTL",
                "WEBAUTHN_MAX_PROOF_AGE",
            ];
            Self {
                values: keys
                    .into_iter()
                    .map(|key| (key, env::var(key).ok()))
                    .collect(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.values {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
    }

    fn clear_rotation_env() {
        env::remove_var("FREEBIRD_ENV");
        env::remove_var("ALLOW_UNSAFE_V4_ROTATION");
    }

    fn clean_config_env() -> EnvGuard {
        let guard = EnvGuard::new();
        for key in [
            "FREEBIRD_ENV",
            "FREEBIRD_UNSAFE_DEVELOPMENT_MODE",
            "ALLOW_UNSAFE_V4_ROTATION",
            "ISSUER_ID",
            "BIND_ADDR",
            "REQUIRE_TLS",
            "BEHIND_PROXY",
            "TRUSTED_PROXY_CIDRS",
            "ADMIN_API_KEY",
            "AUDIT_LOG_PATH",
            "ISSUER_SK_PATH",
            "KEY_ROTATION_STATE_PATH",
            "KID",
            "HSM_ENABLE",
            "HSM_MODE",
            "HSM_MODULE_PATH",
            "HSM_SLOT",
            "HSM_PIN",
            "HSM_KEY_LABEL",
            "PUBLIC_BEARER_ENABLE",
            "PUBLIC_BEARER_SK_PATH",
            "PUBLIC_BEARER_METADATA_PATH",
            "PUBLIC_BEARER_VALIDITY",
            "PUBLIC_BEARER_AUDIENCE",
            "PUBLIC_BEARER_MODULUS_BITS",
            "PUBLIC_BEARER_EXCHANGE_ENABLE",
            "PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH",
            "PUBLIC_BEARER_EXCHANGE_RETAINED_GRAPH_PATHS",
            "PUBLIC_BEARER_EXCHANGE_PROFILE_PATH",
            "PUBLIC_BEARER_EXCHANGE_RETAINED_PROFILE_PATHS",
            "PUBLIC_BEARER_EXCHANGE_RECEIPT_KEY_PATH",
            "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_KEY_PATH",
            "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_METADATA_PATH",
            "PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_KEY_PATHS",
            "PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_METADATA_PATHS",
            "PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH",
            "PUBLIC_BEARER_EXCHANGE_DISABLED_PUBLICATION_ACK_PATHS",
            "PUBLIC_BEARER_EXCHANGE_REDIS_URL",
            "PUBLIC_BEARER_EXCHANGE_RECEIPT_LIFETIME",
            "PUBLIC_BEARER_EXCHANGE_MAX_BODY_BYTES",
            "PUBLIC_BEARER_EXCHANGE_TIMEOUT",
            "PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE",
            "PUBLIC_BEARER_GRAPH_ISSUANCE_POLICY_PATH",
            "PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION",
            "PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64",
            "PUBLIC_BEARER_GRAPH_ISSUANCE_V4_REPLAY_REDIS_URL",
            "PUBLIC_BEARER_GRAPH_ISSUANCE_V4_KEYRING_B64",
            "PUBLIC_BEARER_GRAPH_ISSUANCE_ALLOW_DEVELOPMENT_MOCK",
            "SYBIL_RESISTANCE",
            "SYBIL_PROGRESSIVE_TRUST_SALT",
            "SYBIL_PROOF_OF_DIVERSITY_SALT",
            "SYBIL_MULTI_PARTY_VOUCHING_SALT",
            "WEBAUTHN_RP_ID",
            "WEBAUTHN_RP_NAME",
            "WEBAUTHN_RP_ORIGIN",
            "WEBAUTHN_REDIS_URL",
            "WEBAUTHN_CRED_TTL",
            "WEBAUTHN_MAX_PROOF_AGE",
        ] {
            env::remove_var(key);
        }
        env::set_var("BIND_ADDR", "127.0.0.1:0");
        env::set_var("REQUIRE_TLS", "false");
        env::set_var("BEHIND_PROXY", "false");
        env::set_var("HSM_ENABLE", "false");
        guard
    }

    #[test]
    #[serial]
    fn v4_rotation_is_disabled_by_default() {
        let _env = EnvGuard::new();
        clear_rotation_env();
        let config = Config::from_env().expect("default config should parse");
        assert!(!config.allow_unsafe_v4_rotation);
    }

    #[test]
    #[serial]
    fn unsafe_v4_rotation_requires_development_environment() {
        let _env = EnvGuard::new();
        env::set_var("ALLOW_UNSAFE_V4_ROTATION", "true");
        env::set_var("FREEBIRD_ENV", "production");
        let error = Config::from_env().expect_err("production override must be rejected");
        assert!(error.to_string().contains("only permitted"));

        env::set_var("FREEBIRD_ENV", "development");
        let config = Config::from_env().expect("development override should parse");
        assert!(config.allow_unsafe_v4_rotation);
        clear_rotation_env();
    }

    #[test]
    #[serial]
    fn config_from_env_rejects_unsafe_development_mode_outside_development() {
        let _env = clean_config_env();
        env::set_var("FREEBIRD_ENV", "production");
        env::set_var("FREEBIRD_UNSAFE_DEVELOPMENT_MODE", "true");

        let error = Config::from_env().expect_err("unsafe development mode must be rejected");
        assert!(error
            .to_string()
            .contains("FREEBIRD_UNSAFE_DEVELOPMENT_MODE=true is only permitted"));
    }

    #[test]
    #[serial]
    fn config_from_env_rejects_graph_issuance_without_exchange() {
        use base64ct::{Base64UrlUnpadded, Encoding};

        let _env = clean_config_env();
        env::set_var("PUBLIC_BEARER_EXCHANGE_ENABLE", "false");
        env::set_var("PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE", "true");
        env::set_var("PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION", "hmac_sha256");
        env::set_var(
            "PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64",
            Base64UrlUnpadded::encode_string(&[0x31; 32]),
        );

        let error = Config::from_env().expect_err("graph issuance requires exchange");
        assert!(error
            .to_string()
            .contains("graph issuance requires PUBLIC_BEARER_EXCHANGE_ENABLE=true"));
    }

    #[test]
    #[serial]
    fn config_from_env_rejects_malformed_disabled_exchange_inputs() {
        let _env = clean_config_env();
        for (name, value, graph_enabled, message) in [
            (
                "PUBLIC_BEARER_EXCHANGE_RECEIPT_LIFETIME",
                "not-a-duration",
                false,
                "invalid duration",
            ),
            (
                "PUBLIC_BEARER_EXCHANGE_TIMEOUT",
                "not-a-duration",
                false,
                "invalid duration",
            ),
            (
                "PUBLIC_BEARER_EXCHANGE_MAX_BODY_BYTES",
                "not-a-number",
                false,
                "invalid digit",
            ),
            (
                "PUBLIC_BEARER_EXCHANGE_RETAINED_GRAPH_PATHS",
                "/one.json,",
                false,
                "contains an empty path",
            ),
            (
                "PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION",
                "unsupported",
                true,
                "unsupported graph issuance authorization verifier",
            ),
        ] {
            env::remove_var("PUBLIC_BEARER_EXCHANGE_ENABLE");
            env::remove_var("PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE");
            for candidate in [
                "PUBLIC_BEARER_EXCHANGE_RECEIPT_LIFETIME",
                "PUBLIC_BEARER_EXCHANGE_TIMEOUT",
                "PUBLIC_BEARER_EXCHANGE_MAX_BODY_BYTES",
                "PUBLIC_BEARER_EXCHANGE_RETAINED_GRAPH_PATHS",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION",
            ] {
                env::remove_var(candidate);
            }
            env::set_var(name, value);
            if graph_enabled {
                env::set_var("PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE", "true");
            }

            let error = Config::from_env().expect_err("malformed exchange input must fail");
            assert!(error.to_string().contains(message));
        }
    }

    #[test]
    #[serial]
    fn config_from_env_parses_require_tls_one_as_enabled() {
        let _env = clean_config_env();
        env::set_var("REQUIRE_TLS", "1");

        let config = Config::from_env().expect("REQUIRE_TLS=1 must parse");
        assert!(config.require_tls);
    }

    #[test]
    #[serial]
    fn config_parser_failure_is_fail_fast_before_runtime_preflight_side_effects() {
        let _env = clean_config_env();
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let issuer_key = root.join("issuer.key");
        let v5_key = root.join("public-bearer.der");
        let exchange_graph = root.join("exchange.json");
        let v5_metadata = root.join("public-bearer.json");
        let receipt_key = root.join("receipt.key");
        let receipt_metadata = root.join("receipt.json");
        let invalid_issuer_key = b"not-an-issuer-key";
        let invalid_v5_key = b"not-a-v5-key";
        let invalid_graph = b"not-an-exchange-graph";
        std::fs::write(&issuer_key, invalid_issuer_key).unwrap();
        std::fs::write(&v5_key, invalid_v5_key).unwrap();
        std::fs::write(&exchange_graph, invalid_graph).unwrap();

        env::set_var("BIND_ADDR", "not-an-address");
        env::set_var("PUBLIC_BEARER_ENABLE", "true");
        env::set_var("PUBLIC_BEARER_SK_PATH", &v5_key);
        env::set_var("PUBLIC_BEARER_METADATA_PATH", &v5_metadata);
        env::set_var("ISSUER_SK_PATH", &issuer_key);
        env::set_var("PUBLIC_BEARER_EXCHANGE_ENABLE", "true");
        env::set_var("PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH", &exchange_graph);
        env::set_var("PUBLIC_BEARER_EXCHANGE_REDIS_URL", "redis://127.0.0.1:1/");
        env::set_var(
            "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_KEY_PATH",
            &receipt_key,
        );
        env::set_var(
            "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_METADATA_PATH",
            &receipt_metadata,
        );

        let error = Config::from_env().expect_err("invalid bind address must fail first");
        assert!(error.to_string().contains("Invalid BIND_ADDR"));
        assert!(std::fs::read(&issuer_key).unwrap() == invalid_issuer_key);
        assert!(std::fs::read(&v5_key).unwrap() == invalid_v5_key);
        assert!(std::fs::read(&exchange_graph).unwrap() == invalid_graph);
        assert!(!v5_metadata.exists());
        assert!(!receipt_key.exists());
        assert!(!receipt_metadata.exists());
    }

    #[test]
    #[serial]
    fn config_from_env_preserves_raw_admin_salt_and_webauthn_boundaries() {
        let _env = clean_config_env();

        let missing = Config::from_env().expect("missing raw values should parse");
        assert!(missing.admin_api_key.is_none());
        assert_eq!(missing.sybil_config.progressive_trust_salt.len(), 64);
        assert_eq!(
            missing
                .sybil_config
                .proof_of_diversity_fingerprint_salt
                .len(),
            64
        );
        assert_eq!(missing.sybil_config.multi_party_vouching_salt.len(), 64);
        assert!(missing.webauthn_config.is_none());

        env::set_var("ADMIN_API_KEY", "");
        env::set_var("SYBIL_PROGRESSIVE_TRUST_SALT", "");
        env::set_var("SYBIL_PROOF_OF_DIVERSITY_SALT", "");
        env::set_var("SYBIL_MULTI_PARTY_VOUCHING_SALT", "");
        let empty = Config::from_env().expect("empty raw values should parse");
        assert!(empty.admin_api_key.is_none());
        assert!(empty.sybil_config.progressive_trust_salt.is_empty());
        assert!(empty
            .sybil_config
            .proof_of_diversity_fingerprint_salt
            .is_empty());
        assert!(empty.sybil_config.multi_party_vouching_salt.is_empty());

        env::set_var("WEBAUTHN_RP_ID", "example.test");
        let partial_id = Config::from_env().expect("partial WebAuthn fields should parse");
        assert!(partial_id.webauthn_config.is_none());
        env::remove_var("WEBAUTHN_RP_ID");
        env::set_var("WEBAUTHN_RP_ORIGIN", "https://example.test");
        let partial_origin = Config::from_env().expect("partial WebAuthn fields should parse");
        assert!(partial_origin.webauthn_config.is_none());
        env::set_var("SYBIL_RESISTANCE", "webauthn");
        let selected_without_rp = Config::from_env().expect("selected WebAuthn should parse");
        assert!(selected_without_rp.webauthn_config.is_none());
    }

    #[test]
    #[serial]
    fn test_hsm_config_disabled_by_default() {
        let _env = EnvGuard::new();
        // Clear HSM environment variables
        env::remove_var("HSM_ENABLE");
        env::remove_var("HSM_MODULE_PATH");
        env::remove_var("HSM_SLOT");
        env::remove_var("HSM_PIN");
        env::remove_var("HSM_KEY_LABEL");

        let hsm_config = HsmConfig::from_env().expect("disabled HSM should parse");
        assert!(hsm_config.is_none(), "HSM should be disabled by default");
    }

    #[test]
    #[serial]
    fn runtime_rejects_enabled_hsm_until_startup_integration_exists() {
        let _env = EnvGuard::new();
        for value in ["true", "1"] {
            env::set_var("HSM_ENABLE", value);

            let error = Config::from_env().expect_err("enabled HSM must be rejected");
            assert!(error
                .to_string()
                .contains("issuer startup provider integration is not implemented"));
        }
    }

    #[test]
    #[serial]
    fn runtime_rejects_malformed_hsm_enable_value() {
        let _env = EnvGuard::new();
        env::set_var("HSM_ENABLE", "yes");

        let error = Config::from_env().expect_err("malformed HSM_ENABLE must be rejected");
        assert!(error.to_string().contains("HSM_ENABLE must be one of"));
        assert!(error.to_string().contains("yes"));
    }

    #[test]
    #[serial]
    fn runtime_accepts_zero_as_disabled_hsm() {
        let _env = EnvGuard::new();
        env::set_var("HSM_ENABLE", "0");

        let config = Config::from_env().expect("HSM_ENABLE=0 must preserve software startup");
        assert!(config.key_config.hsm.is_none());
    }

    #[test]
    #[serial]
    fn runtime_uses_software_key_configuration_when_hsm_is_disabled() {
        let _env = EnvGuard::new();
        env::set_var("HSM_ENABLE", "false");
        env::set_var("HSM_MODULE_PATH", "/reserved/unused/pkcs11.so");
        env::set_var("HSM_SLOT", "7");
        env::set_var("HSM_PIN", "reserved");
        env::set_var("HSM_KEY_LABEL", "reserved-key");

        let config = Config::from_env().expect("disabled HSM must preserve software startup");
        assert!(config.key_config.hsm.is_none());
    }

    #[test]
    #[serial]
    fn config_from_env_preserves_top_level_first_error_precedence() {
        let _env = clean_config_env();

        env::set_var("BIND_ADDR", "not-an-address");
        env::set_var("REQUIRE_TLS", "true");
        env::set_var("BEHIND_PROXY", "true");
        env::remove_var("TRUSTED_PROXY_CIDRS");
        env::set_var("HSM_ENABLE", "yes");
        let error = Config::from_env().expect_err("BIND_ADDR must be the first error");
        assert!(error.to_string().contains("Invalid BIND_ADDR"));

        env::set_var("BIND_ADDR", "127.0.0.1:0");
        let error = Config::from_env().expect_err("proxy configuration must precede safety fences");
        assert!(error
            .to_string()
            .contains("TRUSTED_PROXY_CIDRS is required"));

        env::set_var("TRUSTED_PROXY_CIDRS", "127.0.0.0/8");
        env::set_var("FREEBIRD_ENV", "production");
        env::set_var("FREEBIRD_UNSAFE_DEVELOPMENT_MODE", "true");
        let error = Config::from_env().expect_err("development safety fence must precede HSM");
        assert!(error
            .to_string()
            .contains("only permitted when FREEBIRD_ENV=development"));

        env::remove_var("FREEBIRD_UNSAFE_DEVELOPMENT_MODE");
        env::set_var("HSM_ENABLE", "true");
        let error = Config::from_env().expect_err("HSM must precede downstream configuration");
        assert!(error
            .to_string()
            .contains("issuer startup provider integration is not implemented"));

        env::remove_var("HSM_ENABLE");
        env::set_var("PUBLIC_BEARER_EXCHANGE_PROFILE_PATH", "/removed/v1");
        let error = Config::from_env().expect_err("removed aliases must remain a hard error");
        assert!(error
            .to_string()
            .contains("was removed with V1 fixed-profile exchange"));
    }

    #[test]
    #[serial]
    fn unsafe_rotation_precedes_downstream_graph_configuration() {
        use base64ct::{Base64UrlUnpadded, Encoding};

        let _env = clean_config_env();
        env::set_var("BIND_ADDR", "127.0.0.1:0");
        env::set_var("REQUIRE_TLS", "false");
        env::set_var("BEHIND_PROXY", "false");
        env::remove_var("TRUSTED_PROXY_CIDRS");
        env::set_var("FREEBIRD_ENV", "production");
        env::remove_var("FREEBIRD_UNSAFE_DEVELOPMENT_MODE");
        env::set_var("ALLOW_UNSAFE_V4_ROTATION", "true");
        env::set_var("HSM_ENABLE", "false");
        env::set_var("PUBLIC_BEARER_EXCHANGE_ENABLE", "true");
        env::set_var("PUBLIC_BEARER_EXCHANGE_REDIS_URL", "redis://127.0.0.1:1/");
        env::set_var("PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE", "true");
        env::set_var("PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION", "hmac_sha256");
        env::remove_var("PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64");

        let error = Config::from_env().expect_err("production rotation must precede graph parsing");
        assert!(error.to_string().contains("ALLOW_UNSAFE_V4_ROTATION=true"));

        env::set_var("FREEBIRD_ENV", "development");
        let error = Config::from_env().expect_err("graph authorization must be the next error");
        assert!(error
            .to_string()
            .contains("PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64 is required"));

        env::set_var(
            "PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64",
            Base64UrlUnpadded::encode_string(&[0x55; 32]),
        );
        let config = Config::from_env().expect("valid downstream graph configuration");
        assert!(config.allow_unsafe_v4_rotation);
        assert!(matches!(
            config.exchange_config.graph_issuance.authorization,
            GraphIssuanceAuthorizationConfig::HmacSha256(_)
        ));
    }

    #[test]
    #[serial]
    fn enabled_exchange_requires_a_valid_profile() {
        let _env = EnvGuard::new();
        env::set_var("PUBLIC_BEARER_EXCHANGE_ENABLE", "true");
        env::set_var("PUBLIC_BEARER_EXCHANGE_REDIS_URL", "redis://127.0.0.1/");
        env::set_var(
            "PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH",
            "/definitely/missing/exchange-profile.json",
        );
        let config = Config::from_env().expect("environment shape should parse");
        assert!(config
            .exchange_config
            .load_v2(&config.issuer_id, None)
            .is_err());
        env::remove_var("PUBLIC_BEARER_EXCHANGE_ENABLE");
        env::remove_var("PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH");
    }

    #[test]
    #[serial]
    fn exchange_config_parses_active_and_retained_signer_paths() {
        let _env = EnvGuard::new();
        env::remove_var("PUBLIC_BEARER_EXCHANGE_ENABLE");
        env::set_var(
            "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_KEY_PATH",
            "/keys/active.key",
        );
        env::set_var(
            "PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_KEY_PATHS",
            "/keys/old-1.key, /keys/old-2.key",
        );
        env::set_var(
            "PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_METADATA_PATHS",
            "/keys/old-1.json, /keys/old-2.json",
        );
        env::set_var(
            "PUBLIC_BEARER_EXCHANGE_RETAINED_GRAPH_PATHS",
            "/profiles/old-1.json,/profiles/old-2.json",
        );
        let config = ExchangeConfig::from_env().unwrap();
        assert_eq!(
            config.active_receipt_key_path,
            PathBuf::from("/keys/active.key")
        );
        assert_eq!(config.retained_receipt_key_paths.len(), 2);
        assert_eq!(config.retained_receipt_metadata_paths.len(), 2);
        assert_eq!(config.retained_graph_paths.len(), 2);
    }

    #[test]
    #[serial]
    fn removed_v1_exchange_aliases_are_rejected() {
        let _env = EnvGuard::new();
        for name in [
            "PUBLIC_BEARER_EXCHANGE_PROFILE_PATH",
            "PUBLIC_BEARER_EXCHANGE_RETAINED_PROFILE_PATHS",
            "PUBLIC_BEARER_EXCHANGE_RECEIPT_KEY_PATH",
        ] {
            env::set_var(name, "/removed/v1");
            let error = ExchangeConfig::from_env().expect_err("removed V1 alias must be rejected");
            assert!(error.to_string().contains("was removed"));
            env::remove_var(name);
        }
    }

    #[test]
    #[serial]
    fn exchange_config_loads_strict_durable_publication_acknowledgement() {
        let _env = EnvGuard::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disabled-publication.json");
        let acknowledgement = ExchangeDisabledPublicationAcknowledgementV1 {
            version: EXCHANGE_DISABLED_PUBLICATION_ACK_VERSION.into(),
            issuer_id: "issuer:test".into(),
            graph_id: "a".repeat(64),
            disabled_transition_ids: vec!["b".repeat(64)],
            acknowledged_admission_state: "disabled".into(),
            operator: "operator@example.test".into(),
            acknowledged_at_unix: 1,
        };
        std::fs::write(&path, serde_json::to_vec(&acknowledgement).unwrap()).unwrap();
        env::set_var(
            "PUBLIC_BEARER_EXCHANGE_DISABLED_PUBLICATION_ACK_PATHS",
            &path,
        );

        let config = ExchangeConfig::from_env().unwrap();
        assert_eq!(
            config.load_disabled_publication_acknowledgements().unwrap(),
            vec![acknowledgement.clone()]
        );

        let mut wrong_state = acknowledgement;
        wrong_state.acknowledged_admission_state = "accepting_new".into();
        std::fs::write(&path, serde_json::to_vec(&wrong_state).unwrap()).unwrap();
        assert!(config.load_disabled_publication_acknowledgements().is_err());
    }

    #[test]
    #[serial]
    fn enabled_v2_exchange_accepts_public_history_path_and_rejects_unpaired_private_receipts() {
        let _env = EnvGuard::new();
        env::set_var("PUBLIC_BEARER_EXCHANGE_ENABLE", "true");
        env::set_var("PUBLIC_BEARER_EXCHANGE_REDIS_URL", "redis://127.0.0.1/");
        env::set_var(
            "PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH",
            "/history/v2.json",
        );
        let config = ExchangeConfig::from_env().unwrap();
        assert_eq!(
            config.public_history_path,
            Some(PathBuf::from("/history/v2.json"))
        );
        env::remove_var("PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH");
        env::set_var(
            "PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_KEY_PATHS",
            "/keys/retained.key",
        );
        assert!(ExchangeConfig::from_env().is_err());
    }

    #[test]
    #[serial]
    fn graph_issuance_has_no_permissive_production_authorizer_default() {
        let _env = EnvGuard::new();
        env::set_var("PUBLIC_BEARER_EXCHANGE_ENABLE", "true");
        env::set_var("PUBLIC_BEARER_EXCHANGE_REDIS_URL", "redis://127.0.0.1/");
        env::set_var("PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE", "true");
        env::remove_var("PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64");
        assert!(ExchangeConfig::from_env().is_err());

        env::set_var(
            "PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION",
            "development_mock",
        );
        env::set_var("FREEBIRD_ENV", "production");
        env::set_var("FREEBIRD_UNSAFE_DEVELOPMENT_MODE", "true");
        env::set_var(
            "PUBLIC_BEARER_GRAPH_ISSUANCE_ALLOW_DEVELOPMENT_MOCK",
            "true",
        );
        assert!(ExchangeConfig::from_env().is_err());
    }

    #[test]
    #[serial]
    fn v4_local_uses_the_exchange_redis_authority_and_private_keyring() {
        use base64ct::{Base64UrlUnpadded, Encoding};

        let _env = EnvGuard::new();
        env::set_var("PUBLIC_BEARER_EXCHANGE_ENABLE", "true");
        env::set_var(
            "PUBLIC_BEARER_EXCHANGE_REDIS_URL",
            "redis://127.0.0.1:6379/4",
        );
        env::set_var("PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE", "true");
        env::set_var("PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION", "v4_local");
        env::set_var(
            "PUBLIC_BEARER_GRAPH_ISSUANCE_V4_KEYRING_B64",
            serde_json::json!({
                "issuer:test": {
                    "kid:test": Base64UrlUnpadded::encode_string(&[7; 32])
                }
            })
            .to_string(),
        );
        env::remove_var("PUBLIC_BEARER_GRAPH_ISSUANCE_V4_REPLAY_REDIS_URL");
        let config = ExchangeConfig::from_env().unwrap();
        assert!(matches!(
            config.graph_issuance.authorization,
            GraphIssuanceAuthorizationConfig::V4Local { .. }
        ));
        env::set_var(
            "PUBLIC_BEARER_GRAPH_ISSUANCE_V4_REPLAY_REDIS_URL",
            "redis://127.0.0.1:6379/5",
        );
        let config = ExchangeConfig::from_env().unwrap();
        assert!(matches!(
            config.graph_issuance.authorization,
            GraphIssuanceAuthorizationConfig::V4Local { .. }
        ));
    }

    #[test]
    #[serial]
    fn test_hsm_config_storage_mode() {
        let _env = EnvGuard::new();
        // Set HSM environment variables
        env::set_var("HSM_ENABLE", "true");
        env::set_var("HSM_MODE", "storage");
        env::set_var("HSM_MODULE_PATH", "/usr/lib/softhsm/libsofthsm2.so");
        env::set_var("HSM_SLOT", "0");
        env::set_var("HSM_PIN", "1234");
        env::set_var("HSM_KEY_LABEL", "test-key");

        let hsm_config = HsmConfig::from_env().expect("HSM config should parse");
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
        let _env = EnvGuard::new();
        env::set_var("HSM_ENABLE", "true");
        env::set_var("HSM_MODE", "full");
        env::set_var("HSM_MODULE_PATH", "/usr/lib/libykcs11.so");
        env::set_var("HSM_SLOT", "1");
        env::set_var("HSM_PIN", "5678");
        env::set_var("HSM_KEY_LABEL", "yubikey");

        let hsm_config = HsmConfig::from_env()
            .expect("HSM config should parse")
            .expect("HSM config should be enabled");
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
        let _env = EnvGuard::new();
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

        let hsm_config = HsmConfig::from_env()
            .expect("HSM config should parse")
            .expect("HSM config should be enabled");
        assert_eq!(
            hsm_config.mode,
            HsmMode::Storage,
            "Should default to Storage mode"
        );

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
        let _env = EnvGuard::new();
        env::set_var("HSM_ENABLE", "true");
        env::remove_var("HSM_MODULE_PATH");
        env::set_var("HSM_SLOT", "0");
        env::set_var("HSM_PIN", "1234");
        env::set_var("HSM_KEY_LABEL", "test");

        let _ = HsmConfig::from_env();
    }

    #[test]
    #[serial]
    #[should_panic(expected = "HSM_SLOT required")]
    fn test_hsm_config_missing_slot() {
        let _env = EnvGuard::new();
        env::set_var("HSM_ENABLE", "true");
        env::set_var("HSM_MODULE_PATH", "/usr/lib/softhsm/libsofthsm2.so");
        env::remove_var("HSM_SLOT");
        env::set_var("HSM_PIN", "1234");
        env::set_var("HSM_KEY_LABEL", "test");

        let _ = HsmConfig::from_env();
    }
}
