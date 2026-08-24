// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Configuration validation tool for Freebird issuer
//!
//! This tool validates your configuration before starting the issuer,
//! helping catch configuration errors early.
//!
//! # Usage
//!
//! ```bash
//! # Validate configuration from environment
//! freebird-validate-config
//!
//! # Load from .env file first
//! source .env && freebird-validate-config
//! ```

use freebird_common::duration::format_duration;
use freebird_issuer::config::Config;
use std::env;
use std::fs;
use std::path::Path;

const EXCHANGE_DISABLED_PUBLICATION_ACK_VERSION: &str =
    "freebird/exchange-disabled-publication-ack/v1";

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExchangeDisabledPublicationAcknowledgementV1 {
    version: String,
    issuer_id: String,
    graph_id: String,
    disabled_transition_ids: Vec<String>,
    acknowledged_admission_state: String,
    operator: String,
    acknowledged_at_unix: u64,
}

fn load_disabled_publication_acknowledgements(
    paths: &[std::path::PathBuf],
) -> anyhow::Result<Vec<ExchangeDisabledPublicationAcknowledgementV1>> {
    use anyhow::Context;

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
) -> anyhow::Result<()> {
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

fn validate_disabled_publication_acknowledgements_v2(
    issuer_id: &str,
    discovery: &freebird_common::api::ExchangeDiscoveryV2,
    acknowledgements: &[ExchangeDisabledPublicationAcknowledgementV1],
) -> anyhow::Result<()> {
    use anyhow::Context;

    let graphs = std::iter::once(&discovery.active_graph)
        .chain(&discovery.retained_graphs)
        .collect::<Vec<_>>();
    let mut acknowledged = std::collections::HashSet::new();
    for acknowledgement in acknowledgements {
        if acknowledgement.issuer_id != issuer_id {
            anyhow::bail!("disabled-publication acknowledgement issuer mismatch")
        }
        let graph = graphs
            .iter()
            .find(|graph| graph.graph_id == acknowledgement.graph_id)
            .context("disabled-publication acknowledgement graph mismatch")?;
        for transition_id in &acknowledgement.disabled_transition_ids {
            if !graph
                .transitions
                .iter()
                .any(|transition| transition.transition_id == *transition_id)
            {
                anyhow::bail!("disabled-publication acknowledgement transition mismatch")
            }
            if !acknowledged.insert((graph.graph_id.as_str(), transition_id.as_str())) {
                anyhow::bail!("duplicate disabled-publication acknowledgement")
            }
        }
    }
    for graph in graphs {
        for transition in &graph.transitions {
            if transition.admission_state
                == freebird_common::api::ExchangeAdmissionStateV2::AcceptingNew
                && !acknowledged
                    .contains(&(graph.graph_id.as_str(), transition.transition_id.as_str()))
            {
                anyhow::bail!(
                    "accepting V2 transition lacks an explicit disabled-publication acknowledgement for this graph"
                )
            }
        }
    }
    Ok(())
}

/// Validation result for a single check
#[derive(Debug)]
enum CheckResult {
    Ok(String),
    Warning(String),
    Error(String),
}

impl CheckResult {
    fn is_error(&self) -> bool {
        matches!(self, CheckResult::Error(_))
    }
}

/// Configuration section being validated
struct ValidationSection {
    name: String,
    checks: Vec<CheckResult>,
}

impl ValidationSection {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            checks: Vec::new(),
        }
    }

    fn add(&mut self, result: CheckResult) {
        self.checks.push(result);
    }

    fn has_errors(&self) -> bool {
        self.checks.iter().any(|c| c.is_error())
    }

    fn print(&self) {
        println!("\n{}", self.name);
        println!("{}", "─".repeat(self.name.len()));
        for check in &self.checks {
            match check {
                CheckResult::Ok(msg) => println!("  ✓ {}", msg),
                CheckResult::Warning(msg) => println!("  ⚠ {}", msg),
                CheckResult::Error(msg) => println!("  ✗ {}", msg),
            }
        }
    }
}

fn validation_sections(config: &Config) -> Vec<ValidationSection> {
    let mut sections = vec![
        validate_core_config(config),
        validate_key_config(config),
        validate_native_bearer_v7_config(config),
        validate_exchange_config(config),
        validate_sybil_config(config),
    ];

    // Validate WebAuthn configuration (if enabled)
    if let Some(section) = validate_webauthn_config(config) {
        sections.push(section);
    }

    // Validate HSM configuration (if enabled)
    if let Some(section) = validate_hsm_config(config) {
        sections.push(section);
    }

    sections
}

fn main() {
    println!("🔍 Freebird Configuration Validator");
    println!("====================================");

    let sections = match Config::from_env() {
        Ok(config) => validation_sections(&config),
        Err(error) => vec![ValidationSection {
            name: "Configuration Parsing".into(),
            checks: vec![CheckResult::Error(error.to_string())],
        }],
    };
    let mut has_errors = false;

    // Print all sections
    for section in &sections {
        section.print();
        if section.has_errors() {
            has_errors = true;
        }
    }

    // Summary
    println!("\n====================================");
    if has_errors {
        println!("❌ Configuration has errors. Please fix them before starting the issuer.");
        std::process::exit(1);
    } else {
        println!("✅ Configuration is valid!");
        std::process::exit(0);
    }
}

fn validate_core_config(config: &Config) -> ValidationSection {
    let mut section = ValidationSection::new("Core Configuration");

    // ISSUER_ID
    let issuer_id = &config.issuer_id;
    section.add(CheckResult::Ok(format!("ISSUER_ID = {}", issuer_id)));

    // BIND_ADDR
    section.add(CheckResult::Ok(format!("BIND_ADDR = {}", config.bind_addr)));

    // EPOCH_DURATION
    section.add(CheckResult::Ok(format!(
        "EPOCH_DURATION = {} ({})",
        format_duration(config.epoch_duration_sec),
        config.epoch_duration_sec
    )));

    // EPOCH_RETENTION
    section.add(CheckResult::Ok(format!(
        "EPOCH_RETENTION = {} epochs",
        config.epoch_retention
    )));

    // REQUIRE_TLS
    if config.require_tls {
        section.add(CheckResult::Ok("REQUIRE_TLS = true".to_string()));
    } else {
        section.add(CheckResult::Warning(
            "REQUIRE_TLS = false (enable in production)".to_string(),
        ));
    }

    if config.require_tls && !config.behind_proxy {
        section.add(CheckResult::Error(
            "REQUIRE_TLS=true requires BEHIND_PROXY=true and a trusted proxy boundary".into(),
        ));
    }
    if config.behind_proxy {
        section.add(CheckResult::Ok("TRUSTED_PROXY_CIDRS is configured".into()));
    }

    // ADMIN_API_KEY
    match env::var("ADMIN_API_KEY") {
        Ok(key) if key.len() >= 32 => {
            section.add(CheckResult::Ok(format!(
                "ADMIN_API_KEY = [set, {} chars]",
                key.len()
            )));
        }
        Ok(key) => {
            section.add(CheckResult::Error(format!(
                "ADMIN_API_KEY = [set, {} chars] (minimum 32 required)",
                key.len()
            )));
        }
        Err(_) => {
            section.add(CheckResult::Warning(
                "ADMIN_API_KEY = [not set] (admin API disabled)".to_string(),
            ));
        }
    }

    section
}

fn validate_key_config(config: &Config) -> ValidationSection {
    let mut section = ValidationSection::new("Key Configuration");

    // ISSUER_SK_PATH
    let sk_path = &config.key_config.sk_path;
    let sk_path_obj = sk_path.as_path();

    if sk_path_obj.exists() {
        // Check file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(sk_path) {
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 {
                    section.add(CheckResult::Warning(format!(
                        "ISSUER_SK_PATH = {} (exists, but permissions {:o} are too open - recommend 0600)",
                        sk_path.display(), mode & 0o777
                    )));
                } else {
                    section.add(CheckResult::Ok(format!(
                        "ISSUER_SK_PATH = {} (exists, permissions {:o})",
                        sk_path.display(),
                        mode & 0o777
                    )));
                }
            }
        }
        #[cfg(not(unix))]
        {
            section.add(CheckResult::Ok(format!(
                "ISSUER_SK_PATH = {} (exists)",
                sk_path.display()
            )));
        }
    } else {
        // Check if parent directory exists and is writable
        if let Some(parent) = sk_path_obj.parent() {
            if parent.as_os_str().is_empty() || parent.exists() {
                section.add(CheckResult::Ok(format!(
                    "ISSUER_SK_PATH = {} (will be created on first run)",
                    sk_path.display()
                )));
            } else {
                section.add(CheckResult::Error(format!(
                    "ISSUER_SK_PATH = {} (parent directory {} does not exist)",
                    sk_path.display(),
                    parent.display()
                )));
            }
        } else {
            section.add(CheckResult::Ok(format!(
                "ISSUER_SK_PATH = {} (will be created)",
                sk_path.display()
            )));
        }
    }

    // KEY_ROTATION_STATE_PATH
    let rotation_path = &config.key_config.rotation_state_path;
    let rotation_path_obj = rotation_path.as_path();

    if rotation_path_obj.exists() {
        section.add(CheckResult::Ok(format!(
            "KEY_ROTATION_STATE_PATH = {} (exists)",
            rotation_path.display()
        )));
    } else if let Some(parent) = rotation_path_obj.parent() {
        if parent.as_os_str().is_empty() || parent.exists() {
            section.add(CheckResult::Ok(format!(
                "KEY_ROTATION_STATE_PATH = {} (will be created)",
                rotation_path.display()
            )));
        } else {
            section.add(CheckResult::Error(format!(
                "KEY_ROTATION_STATE_PATH = {} (parent directory {} does not exist)",
                rotation_path.display(),
                parent.display()
            )));
        }
    }

    // V4 deprecated secret keys are currently retained in memory only.  The
    // rotation state file does not make rotation restart-safe, so surface
    // this limitation rather than presenting the path as a production-safe
    // rotation facility.
    section.add(CheckResult::Warning(
        "V4 key rotation is unsafe: deprecated V4 keys are not persisted across restart; do not rely on rotation for production".to_string(),
    ));

    if config.allow_unsafe_v4_rotation {
        section.add(CheckResult::Warning(
            "Unsafe V4 admin key rotation is enabled for development".to_string(),
        ));
    } else {
        section.add(CheckResult::Ok(
            "V4 admin key rotation is disabled".to_string(),
        ));
    }

    // KID override
    if let Some(kid) = &config.key_config.kid_override {
        section.add(CheckResult::Ok(format!("KID = {} (override)", kid)));
    }

    section
}

fn validate_native_bearer_v7_config(config: &Config) -> ValidationSection {
    let mut section = ValidationSection::new("Native V7 Bearer Configuration");
    let v7 = &config.native_bearer_v7_config;

    match freebird_crypto::V7BodyPolicy::new(v7.asset_id.clone(), v7.amount_minor) {
        Ok(policy) => section.add(CheckResult::Ok(format!(
            "fixed V7 body policy = {}:{}",
            policy.asset_id(),
            policy.amount_minor()
        ))),
        Err(error) => section.add(CheckResult::Error(format!(
            "invalid V7 fixed body policy: {error:?}"
        ))),
    }

    if v7.sk_path.is_file() && v7.metadata_path.is_file() {
        match freebird_issuer::native_bearer_v7::NativeBearerV7Issuer::load_existing(
            v7,
            &config.issuer_id,
        ) {
            Ok(issuer) => section.add(CheckResult::Ok(format!(
                "V7 key, metadata, identity, and fixed policy are valid (key ID {})",
                issuer.metadata().token_key_id
            ))),
            Err(error) => section.add(CheckResult::Error(format!(
                "V7 key/metadata validation failed: {error:#}"
            ))),
        }
    } else {
        for (name, path) in [
            ("NATIVE_BEARER_V7_SK_PATH", &v7.sk_path),
            ("NATIVE_BEARER_V7_METADATA_PATH", &v7.metadata_path),
        ] {
            if path.is_file() {
                section.add(CheckResult::Ok(format!(
                    "{name} = {} (exists)",
                    path.display()
                )));
            } else {
                section.add(CheckResult::Warning(format!(
                    "{name} = {} (will be created on first startup)",
                    path.display()
                )));
            }
        }
    }

    if v7.registry_path.is_file() {
        match fs::read(&v7.registry_path)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| {
                serde_json::from_slice::<freebird_common::v7_registry::BearerKeyRegistry>(&bytes)
                    .map_err(anyhow::Error::from)
            }) {
            Ok(registry) => {
                let result = if v7.sk_path.is_file() && v7.metadata_path.is_file() {
                    freebird_issuer::native_bearer_v7::NativeBearerV7Issuer::load_existing(
                        v7,
                        &config.issuer_id,
                    )
                    .and_then(|issuer| {
                        registry
                            .validate_v7_discovery(issuer.metadata(), issuer.binding())
                            .map_err(anyhow::Error::msg)
                    })
                } else {
                    registry.validate().map_err(anyhow::Error::msg)
                };
                match result {
                    Ok(()) => section.add(CheckResult::Ok(format!(
                        "V7 registry {} is valid and compatible with the configured binding",
                        v7.registry_path.display()
                    ))),
                    Err(error) => section.add(CheckResult::Error(format!(
                        "V7 registry validation failed: {error:#}"
                    ))),
                }
            }
            Err(error) => section.add(CheckResult::Error(format!(
                "V7 registry validation failed: {error:#}"
            ))),
        }
    } else {
        section.add(CheckResult::Warning(format!(
            "NATIVE_BEARER_V7_REGISTRY_PATH = {} (will be created on first startup)",
            v7.registry_path.display()
        )));
    }

    section
}

fn validate_exchange_config(config: &Config) -> ValidationSection {
    let mut section = ValidationSection::new("Native V7 Exchange Configuration");
    let exchange_config = &config.exchange_config;
    if !exchange_config.enabled {
        section.add(CheckResult::Ok("NATIVE_EXCHANGE_V7_ENABLE = false".into()));
        return section;
    }
    section.add(CheckResult::Ok(format!(
        "active V7 discovery = {}",
        exchange_config.active_graph_path.display()
    )));
    let discovery_result = (|| -> anyhow::Result<()> {
        freebird_issuer::startup::validate_v7_runtime_config(config)
    })();
    match discovery_result {
        Ok(()) => section.add(CheckResult::Ok(
            "V7 descriptors, graph identity, receipt signer, and discovery metadata are valid"
                .into(),
        )),
        Err(error) => section.add(CheckResult::Error(format!(
            "V7 exchange discovery is invalid: {error:#}"
        ))),
    }

    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| runtime.block_on(exchange_config.validate_redis_durability()))
    {
        Ok(()) => section.add(CheckResult::Ok(
            "V7 exchange Redis is reachable and durable".into(),
        )),
        Err(error) => section.add(CheckResult::Error(format!(
            "V7 exchange Redis durability validation failed: {error:#}"
        ))),
    }
    section
}

fn validate_sybil_config(config: &Config) -> ValidationSection {
    let mut section = ValidationSection::new("Sybil Resistance Configuration");
    let sybil = &config.sybil_config;

    let mode = &sybil.mode;
    section.add(CheckResult::Ok(format!("SYBIL_RESISTANCE = {}", mode)));

    match mode.as_str() {
        "none" => {
            section.add(CheckResult::Warning(
                "No Sybil resistance enabled - not recommended for production".to_string(),
            ));
        }
        "invitation" => {
            validate_invitation_config(sybil, &mut section);
        }
        "pow" => {
            section.add(CheckResult::Ok(format!(
                "SYBIL_POW_DIFFICULTY = {} leading zero bits",
                sybil.pow_difficulty
            )));
        }
        "proof_of_work" => {
            section.add(CheckResult::Ok(format!(
                "SYBIL_POW_DIFFICULTY = {} leading zero bits",
                sybil.pow_difficulty
            )));
        }
        "rate_limit" => {
            section.add(CheckResult::Ok(format!(
                "SYBIL_RATE_LIMIT = {}",
                format_duration(sybil.rate_limit_secs)
            )));
        }
        "progressive_trust" => {
            section.add(CheckResult::Warning(
                "Progressive Trust is experimental and has not been reviewed as a production Sybil boundary".to_string(),
            ));
            validate_progressive_trust_config(sybil, &mut section);
        }
        "proof_of_diversity" => {
            validate_proof_of_diversity_config(&mut section);
        }
        "multi_party_vouching" => {
            validate_multi_party_vouching_config(&mut section);
        }
        "social_graph" => {
            section.add(CheckResult::Warning(
                "Social Graph Sybil resistance is experimental and depends on an external attester trust boundary".to_string(),
            ));
            validate_social_graph_config(sybil, &mut section);
        }
        "webauthn" => {
            if config.webauthn_config.is_none() {
                section.add(CheckResult::Error(
                    "WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN are required when SYBIL_RESISTANCE=webauthn".to_string(),
                ));
            } else if env::var("WEBAUTHN_PROOF_SECRET").is_err() {
                section.add(CheckResult::Error(
                    "WEBAUTHN_PROOF_SECRET is required when SYBIL_RESISTANCE=webauthn".to_string(),
                ));
            } else {
                section.add(CheckResult::Ok(
                    "WebAuthn configuration is present".to_string(),
                ));
            }
        }
        "combined" => {
            let mechanisms = sybil.combined_mechanisms.join(",");
            let mode = &sybil.combined_mode;
            section.add(CheckResult::Ok(format!(
                "SYBIL_COMBINED_MECHANISMS = {}",
                mechanisms
            )));
            section.add(CheckResult::Ok(format!("SYBIL_COMBINED_MODE = {}", mode)));

            if !matches!(
                mode.to_ascii_lowercase().as_str(),
                "or" | "and" | "threshold"
            ) {
                section.add(CheckResult::Error(
                    "SYBIL_COMBINED_MODE must be one of or, and, or threshold".to_string(),
                ));
            }

            // Validate salts for any combined mechanisms that use them
            let mechanisms: Vec<&str> = sybil
                .combined_mechanisms
                .iter()
                .map(|mechanism| mechanism.trim())
                .collect();
            if mechanisms.is_empty() || mechanisms.iter().all(|mechanism| mechanism.is_empty()) {
                section.add(CheckResult::Error(
                    "SYBIL_COMBINED_MECHANISMS must contain at least one mechanism".to_string(),
                ));
            }
            for mechanism in &mechanisms {
                if !matches!(
                    *mechanism,
                    "pow"
                        | "proof_of_work"
                        | "rate_limit"
                        | "invitation"
                        | "webauthn"
                        | "progressive_trust"
                        | "social_graph"
                        | "proof_of_diversity"
                        | "multi_party_vouching"
                ) {
                    section.add(CheckResult::Error(format!(
                        "Unknown SYBIL_COMBINED_MECHANISMS mechanism: {}",
                        mechanism
                    )));
                }
            }
            if mechanisms.contains(&"progressive_trust") {
                section.add(CheckResult::Warning(
                    "Progressive Trust is experimental and has not been reviewed as a production Sybil boundary".to_string(),
                ));
                validate_progressive_trust_config(sybil, &mut section);
            }
            if mechanisms.contains(&"proof_of_diversity") {
                validate_proof_of_diversity_config(&mut section);
            }
            if mechanisms.contains(&"multi_party_vouching") {
                validate_multi_party_vouching_config(&mut section);
            }
            if mechanisms.contains(&"social_graph") {
                section.add(CheckResult::Warning(
                    "Social Graph Sybil resistance is experimental and depends on an external attester trust boundary".to_string(),
                ));
                validate_social_graph_config(sybil, &mut section);
            }
            if mechanisms.contains(&"webauthn") {
                if config.webauthn_config.is_none() {
                    section.add(CheckResult::Error(
                        "WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN are required when combined includes webauthn"
                            .to_string(),
                    ));
                } else if env::var("WEBAUTHN_PROOF_SECRET").is_err() {
                    section.add(CheckResult::Error(
                        "WEBAUTHN_PROOF_SECRET is required when combined includes webauthn"
                            .to_string(),
                    ));
                }
            }
        }
        other => {
            section.add(CheckResult::Error(format!(
                "Unknown SYBIL_RESISTANCE mode: {}",
                other
            )));
        }
    }

    section
}

fn validate_invitation_config(
    sybil: &freebird_issuer::config::SybilConfig,
    section: &mut ValidationSection,
) {
    section.add(CheckResult::Ok(format!(
        "SYBIL_INVITE_PER_USER = {}",
        sybil.invite_per_user
    )));

    section.add(CheckResult::Ok(format!(
        "SYBIL_INVITE_COOLDOWN = {}",
        format_duration(sybil.invite_cooldown_secs)
    )));

    section.add(CheckResult::Ok(format!(
        "SYBIL_INVITE_EXPIRES = {}",
        format_duration(sybil.invite_expires_secs)
    )));

    validate_persistence_path(
        section,
        "SYBIL_INVITE_PERSISTENCE_PATH",
        &sybil.invite_persistence_path,
    );

    // Check bootstrap users
    if let Some(bootstrap) = &sybil.bootstrap_users {
        let count = bootstrap.split(',').count();
        section.add(CheckResult::Ok(format!(
            "SYBIL_INVITE_BOOTSTRAP_USERS = {} user(s) configured",
            count
        )));
    } else {
        section.add(CheckResult::Warning(
            "SYBIL_INVITE_BOOTSTRAP_USERS not set - no initial invite capacity".to_string(),
        ));
    }
}

fn validate_progressive_trust_config(
    sybil: &freebird_issuer::config::SybilConfig,
    section: &mut ValidationSection,
) {
    section.add(CheckResult::Ok(format!(
        "SYBIL_PROGRESSIVE_TRUST_LEVELS = {}",
        sybil.progressive_trust_levels.join(",")
    )));

    validate_persistence_path(
        section,
        "SYBIL_PROGRESSIVE_TRUST_PERSISTENCE_PATH",
        &sybil.progressive_trust_persistence_path,
    );

    // Check for insecure default salt
    let salt = env::var("SYBIL_PROGRESSIVE_TRUST_SALT")
        .unwrap_or_else(|_| "default-salt-change-in-production".to_string());
    if salt.contains("default") || salt.contains("change") {
        section.add(CheckResult::Error(
            "SYBIL_PROGRESSIVE_TRUST_SALT uses insecure default value - must be changed for production".to_string(),
        ));
    } else {
        section.add(CheckResult::Ok(
            "SYBIL_PROGRESSIVE_TRUST_SALT = [custom]".to_string(),
        ));
    }
}

fn validate_social_graph_config(
    sybil: &freebird_issuer::config::SybilConfig,
    section: &mut ValidationSection,
) {
    validate_persistence_path(
        section,
        "SOCIAL_GRAPH_ATTESTERS_PATH",
        &sybil.social_graph_attesters_path,
    );

    if !sybil.social_graph_accepted_policy_ids.is_empty() {
        section.add(CheckResult::Ok(
            "SOCIAL_GRAPH_ACCEPTED_POLICY_IDS = [configured]".to_string(),
        ));
    } else {
        section.add(CheckResult::Error(
            "SOCIAL_GRAPH_ACCEPTED_POLICY_IDS is required for social_graph and must not be empty"
                .to_string(),
        ));
    }

    if sybil.social_graph_jwks_url.is_some() {
        section.add(CheckResult::Warning(
            "SOCIAL_GRAPH_JWKS_URL is configured, but JWKS key refresh is not implemented; local attester keys remain authoritative".to_string(),
        ));
    }

    section.add(CheckResult::Warning(format!(
        "SOCIAL_GRAPH_STATE_PATH = {} (local revocation state is not implemented)",
        sybil.social_graph_state_path.display()
    )));
}

fn validate_proof_of_diversity_config(section: &mut ValidationSection) {
    let salt = env::var("SYBIL_PROOF_OF_DIVERSITY_SALT")
        .unwrap_or_else(|_| "default-salt-change-in-production".to_string());
    if salt.contains("default") || salt.contains("change") {
        section.add(CheckResult::Error(
            "SYBIL_PROOF_OF_DIVERSITY_SALT uses insecure default value - must be changed for production".to_string(),
        ));
    } else {
        section.add(CheckResult::Ok(
            "SYBIL_PROOF_OF_DIVERSITY_SALT = [custom]".to_string(),
        ));
    }
}

fn validate_multi_party_vouching_config(section: &mut ValidationSection) {
    let salt = env::var("SYBIL_MULTI_PARTY_VOUCHING_SALT")
        .unwrap_or_else(|_| "default-salt-change-in-production".to_string());
    if salt.contains("default") || salt.contains("change") {
        section.add(CheckResult::Error(
            "SYBIL_MULTI_PARTY_VOUCHING_SALT uses insecure default value - must be changed for production".to_string(),
        ));
    } else {
        section.add(CheckResult::Ok(
            "SYBIL_MULTI_PARTY_VOUCHING_SALT = [custom]".to_string(),
        ));
    }
}

fn validate_persistence_path(section: &mut ValidationSection, name: &str, path: &Path) {
    let path_obj = path;
    if path_obj.exists() {
        section.add(CheckResult::Ok(format!(
            "{} = {} (exists)",
            name,
            path.display()
        )));
    } else if let Some(parent) = path_obj.parent() {
        if parent.as_os_str().is_empty() || parent.exists() {
            section.add(CheckResult::Ok(format!(
                "{} = {} (will be created)",
                name,
                path.display()
            )));
        } else {
            section.add(CheckResult::Error(format!(
                "{} = {} (parent directory {} does not exist)",
                name,
                path.display(),
                parent.display()
            )));
        }
    }
}

fn validate_webauthn_config(config: &Config) -> Option<ValidationSection> {
    let rp_id = env::var("WEBAUTHN_RP_ID").ok();
    let rp_origin = env::var("WEBAUTHN_RP_ORIGIN").ok();

    if rp_id.is_none() && rp_origin.is_none() {
        return None;
    }

    let mut section = ValidationSection::new("WebAuthn Configuration");

    match (&rp_id, &rp_origin) {
        (Some(_), Some(_)) => {
            let webauthn = config.webauthn_config.as_ref()?;
            let id = &webauthn.rp_id;
            let origin = &webauthn.rp_origin;
            section.add(CheckResult::Ok(format!("WEBAUTHN_RP_ID = {}", id)));
            section.add(CheckResult::Ok(format!("WEBAUTHN_RP_ORIGIN = {}", origin)));

            // Validate origin matches RP ID
            if !origin.contains(id) {
                section.add(CheckResult::Warning(format!(
                    "WEBAUTHN_RP_ORIGIN ({}) should contain WEBAUTHN_RP_ID ({})",
                    origin, id
                )));
            }
        }
        (Some(_), None) => {
            section.add(CheckResult::Error(
                "WEBAUTHN_RP_ID is set but WEBAUTHN_RP_ORIGIN is missing".to_string(),
            ));
        }
        (None, Some(_)) => {
            section.add(CheckResult::Error(
                "WEBAUTHN_RP_ORIGIN is set but WEBAUTHN_RP_ID is missing".to_string(),
            ));
        }
        _ => unreachable!(),
    }

    if let Some(webauthn) = &config.webauthn_config {
        section.add(CheckResult::Ok(format!(
            "WEBAUTHN_RP_NAME = {}",
            webauthn.rp_name
        )));

        if env::var("WEBAUTHN_PROOF_SECRET").is_err() {
            section.add(CheckResult::Error(
                "WEBAUTHN_PROOF_SECRET is required whenever the WebAuthn subsystem is enabled"
                    .to_string(),
            ));
        }

        if let Some(redis_url) = &webauthn.redis_url {
            section.add(CheckResult::Ok(format!(
                "WEBAUTHN_REDIS_URL = {}",
                redis_url.split('@').next_back().unwrap_or(redis_url) // Hide credentials
            )));
        }
    }

    Some(section)
}

fn validate_hsm_config(config: &Config) -> Option<ValidationSection> {
    let hsm = config.key_config.hsm.as_ref()?;
    let mut section = ValidationSection::new("HSM Configuration");
    section.add(CheckResult::Error(
        "HSM_ENABLE=true is unsupported: issuer startup provider integration is not implemented; set HSM_ENABLE=false or omit HSM_ENABLE"
            .to_string(),
    ));

    // Check required HSM variables
    if Path::new(&hsm.module_path).exists() {
        section.add(CheckResult::Ok(format!(
            "HSM_MODULE_PATH = {} (exists)",
            hsm.module_path
        )));
    } else {
        section.add(CheckResult::Error(format!(
            "HSM_MODULE_PATH = {} (file does not exist)",
            hsm.module_path
        )));
    }
    section.add(CheckResult::Ok(format!("HSM_SLOT = {}", hsm.slot)));
    section.add(CheckResult::Ok("HSM_PIN = [set]".to_string()));
    section.add(CheckResult::Ok(format!(
        "HSM_KEY_LABEL = {}",
        hsm.key_label
    )));
    match hsm.mode {
        freebird_issuer::config::HsmMode::Full => section.add(CheckResult::Warning(
            "HSM_MODE = full is reserved and unavailable until issuer startup provider integration is implemented"
                .to_string(),
        )),
        freebird_issuer::config::HsmMode::Storage => {
            section.add(CheckResult::Ok("HSM_MODE = storage".to_string()))
        }
    }

    Some(section)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use freebird_common::api::{ExchangeReceiptKeyInfo, PublicKeyInfo};
    use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};
    use freebird_issuer::config::{HsmConfig, HsmMode};
    use freebird_issuer::exchange::profiles::{
        ExchangeAdmissionStateV2, ExchangeDescriptorV2, ExchangeKeyV2, ExchangeKeysetV2,
        ExchangeProfileV2, ExchangeTransitionSlotV2, ExchangeTransitionV2,
    };
    use serial_test::serial;

    struct EnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl EnvGuard {
        fn clear(names: &[&'static str]) -> Self {
            let values = names
                .iter()
                .map(|name| {
                    let value = std::env::var_os(name);
                    std::env::remove_var(name);
                    (*name, value)
                })
                .collect();
            std::env::set_var("SYBIL_RESISTANCE", "none");
            Self(values)
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (name, value) in &self.0 {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    fn set_mode(mode: &str) {
        std::env::set_var("SYBIL_RESISTANCE", mode);
        std::env::remove_var("SOCIAL_GRAPH_ACCEPTED_POLICY_IDS");
        std::env::remove_var("SOCIAL_GRAPH_JWKS_URL");
    }

    fn clean_validator_env() -> EnvGuard {
        let guard = EnvGuard::clear(&[
            "FREEBIRD_ENV",
            "FREEBIRD_UNSAFE_DEVELOPMENT_MODE",
            "ALLOW_UNSAFE_V4_ROTATION",
            "ISSUER_ID",
            "BIND_ADDR",
            "REQUIRE_TLS",
            "BEHIND_PROXY",
            "TRUSTED_PROXY_CIDRS",
            "ADMIN_API_KEY",
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
            "NATIVE_BEARER_V7_ENABLE",
            "NATIVE_BEARER_V7_SK_PATH",
            "NATIVE_BEARER_V7_METADATA_PATH",
            "NATIVE_BEARER_V7_REGISTRY_PATH",
            "NATIVE_BEARER_V7_PROFILE_ID",
            "NATIVE_BEARER_V7_DESCRIPTOR_ID",
            "NATIVE_BEARER_V7_TOKEN_KEY_ID",
            "NATIVE_BEARER_V7_ASSET_ID",
            "NATIVE_BEARER_V7_AMOUNT_MINOR",
            "NATIVE_BEARER_V7_VALIDITY",
            "NATIVE_V7_SIGNER_CONFIG_PATHS",
            "NATIVE_EXCHANGE_V7_ENABLE",
            "NATIVE_EXCHANGE_V7_REDIS_URL",
            "NATIVE_EXCHANGE_V7_DISCOVERY_PATH",
            "NATIVE_EXCHANGE_V7_RETAINED_DISCOVERY_PATHS",
            "NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_KEY_PATH",
            "NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_METADATA_PATH",
            "NATIVE_EXCHANGE_V7_RETAINED_RECEIPT_KEY_PATHS",
            "NATIVE_EXCHANGE_V7_RETAINED_RECEIPT_METADATA_PATHS",
            "NATIVE_EXCHANGE_V7_RECEIPT_LIFETIME",
            "NATIVE_EXCHANGE_V7_MAX_BODY_BYTES",
            "NATIVE_EXCHANGE_V7_TIMEOUT",
            "NATIVE_GRAPH_ISSUANCE_V7_ENABLE",
            "NATIVE_GRAPH_ISSUANCE_V7_POLICY_PATH",
            "NATIVE_GRAPH_ISSUANCE_V7_AUTHORIZATION",
            "NATIVE_GRAPH_ISSUANCE_V7_VERIFIER_ID",
            "NATIVE_GRAPH_ISSUANCE_V7_AUDIENCE",
            "NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64",
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
            "SYBIL_COMBINED_MECHANISMS",
            "SYBIL_COMBINED_MODE",
            "SYBIL_COMBINED_THRESHOLD",
            "SYBIL_PROGRESSIVE_TRUST_SALT",
            "SYBIL_PROOF_OF_DIVERSITY_SALT",
            "SYBIL_MULTI_PARTY_VOUCHING_SALT",
            "SOCIAL_GRAPH_ACCEPTED_POLICY_IDS",
            "SOCIAL_GRAPH_JWKS_URL",
            "SOCIAL_GRAPH_ATTESTERS_PATH",
            "SOCIAL_GRAPH_STATE_PATH",
            "EPOCH_DURATION",
            "EPOCH_RETENTION",
            "AUDIT_LOG_PATH",
            "WEBAUTHN_RP_ID",
            "WEBAUTHN_RP_NAME",
            "WEBAUTHN_RP_ORIGIN",
            "WEBAUTHN_PROOF_SECRET",
            "WEBAUTHN_REDIS_URL",
            "WEBAUTHN_CRED_TTL",
            "WEBAUTHN_MAX_PROOF_AGE",
        ]);
        std::env::set_var("SYBIL_RESISTANCE", "none");
        std::env::set_var("NATIVE_BEARER_V7_SK_PATH", "native_bearer_v7_sk.der");
        std::env::set_var(
            "NATIVE_BEARER_V7_METADATA_PATH",
            "native_bearer_v7_metadata.json",
        );
        std::env::set_var(
            "NATIVE_BEARER_V7_REGISTRY_PATH",
            "native_bearer_v7_registry.json",
        );
        std::env::set_var(
            "NATIVE_BEARER_V7_PROFILE_ID",
            freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID,
        );
        std::env::set_var("NATIVE_BEARER_V7_DESCRIPTOR_ID", "22".repeat(32));
        std::env::set_var("NATIVE_BEARER_V7_TOKEN_KEY_ID", "00".repeat(32));
        std::env::set_var("NATIVE_BEARER_V7_ASSET_ID", "USD");
        std::env::set_var("NATIVE_BEARER_V7_AMOUNT_MINOR", "1");
        guard
    }

    fn rendered_output(section: &ValidationSection) -> String {
        section
            .checks
            .iter()
            .map(|check| match check {
                CheckResult::Ok(message) => format!("ok: {message}"),
                CheckResult::Warning(message) => format!("warning: {message}"),
                CheckResult::Error(message) => format!("error: {message}"),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn current_config() -> Config {
        Config::from_env().expect("validator test environment must parse")
    }

    fn run_authoritative_validation() -> anyhow::Result<Vec<ValidationSection>> {
        let config = freebird_issuer::config::Config::from_env()?;
        Ok(validation_sections(&config))
    }

    #[test]
    #[serial]
    fn recognizes_social_graph_and_reports_required_policy_ids() {
        let _env = clean_validator_env();
        set_mode("social_graph");
        let section = validate_sybil_config(&current_config());

        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Warning(message) if message.contains("Social Graph") && message.contains("experimental")
        )));
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message) if message.contains("SOCIAL_GRAPH_ACCEPTED_POLICY_IDS")
        )));
        std::env::remove_var("SYBIL_RESISTANCE");
    }

    #[test]
    #[serial]
    fn accepts_social_graph_with_policy_ids() {
        let _env = clean_validator_env();
        set_mode("social_graph");
        std::env::set_var("SOCIAL_GRAPH_ACCEPTED_POLICY_IDS", "clout-trust-v1");
        let section = validate_sybil_config(&current_config());

        assert!(!section.has_errors());
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Ok(message) if message.contains("SOCIAL_GRAPH_ACCEPTED_POLICY_IDS")
        )));
        std::env::remove_var("SYBIL_RESISTANCE");
        std::env::remove_var("SOCIAL_GRAPH_ACCEPTED_POLICY_IDS");
    }

    #[test]
    #[serial]
    fn recognizes_runtime_alias_and_experimental_progressive_trust_warning() {
        let _env = clean_validator_env();
        set_mode("proof_of_work");
        assert!(!validate_sybil_config(&current_config()).has_errors());

        set_mode("progressive_trust");
        let section = validate_sybil_config(&current_config());
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Warning(message) if message.contains("Progressive Trust") && message.contains("experimental")
        )));
        std::env::remove_var("SYBIL_RESISTANCE");
    }

    #[test]
    #[serial]
    fn rejects_enabled_hsm_until_startup_integration_exists() {
        let _env = clean_validator_env();
        for value in ["true", "1"] {
            std::env::set_var("HSM_ENABLE", value);
            std::env::set_var("HSM_MODE", "full");
            std::env::set_var("HSM_MODULE_PATH", "/reserved/pkcs11.so");
            std::env::set_var("HSM_SLOT", "0");
            std::env::set_var("HSM_PIN", "reserved-pin");
            std::env::set_var("HSM_KEY_LABEL", "reserved-label");
            let error = Config::from_env().expect_err("enabled HSM must be rejected");
            assert!(error.to_string().contains("startup provider integration"));
        }
    }

    #[test]
    #[serial]
    fn rejects_malformed_hsm_enable_value() {
        let _env = clean_validator_env();
        std::env::set_var("HSM_ENABLE", "yes");

        let error = Config::from_env().expect_err("malformed HSM_ENABLE must be rejected");
        assert!(error.to_string().contains("HSM_ENABLE must be one of"));
    }

    #[test]
    #[serial]
    fn leaves_hsm_disabled_baseline_without_a_validation_section() {
        let _env = clean_validator_env();
        std::env::set_var("HSM_ENABLE", "false");

        assert!(validate_hsm_config(&current_config()).is_none());
    }

    #[test]
    #[serial]
    fn treats_zero_hsm_enable_as_disabled() {
        let _env = clean_validator_env();
        std::env::set_var("HSM_ENABLE", "0");

        assert!(validate_hsm_config(&current_config()).is_none());
    }

    #[test]
    #[serial]
    fn warns_when_v4_rotation_is_not_restart_safe() {
        let _env = clean_validator_env();
        let section = validate_key_config(&current_config());
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Warning(message) if message.contains("V4 key rotation") && message.contains("not persisted")
        )));
    }

    #[test]
    #[serial]
    fn rejects_unsafe_v4_rotation_outside_development() {
        let _env = clean_validator_env();
        std::env::set_var("ALLOW_UNSAFE_V4_ROTATION", "true");
        std::env::set_var("FREEBIRD_ENV", "production");
        let error = Config::from_env().expect_err("unsafe rotation must be rejected by parser");
        assert!(error.to_string().contains("ALLOW_UNSAFE_V4_ROTATION=true"));
        std::env::remove_var("ALLOW_UNSAFE_V4_ROTATION");
        std::env::remove_var("FREEBIRD_ENV");
    }

    #[test]
    #[serial]
    fn validator_rejects_unsafe_development_mode_outside_development() {
        let _env = clean_validator_env();
        std::env::set_var("FREEBIRD_ENV", "production");
        std::env::set_var("FREEBIRD_UNSAFE_DEVELOPMENT_MODE", "true");

        let error = match run_authoritative_validation() {
            Ok(_) => panic!("unsafe development mode must be rejected by parser"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("FREEBIRD_UNSAFE_DEVELOPMENT_MODE=true is only permitted"));
    }

    #[test]
    #[serial]
    fn validator_rejects_graph_issuance_when_exchange_is_disabled() {
        let _env = clean_validator_env();
        std::env::set_var("NATIVE_EXCHANGE_V7_ENABLE", "false");
        std::env::set_var("NATIVE_GRAPH_ISSUANCE_V7_ENABLE", "true");
        std::env::set_var("NATIVE_GRAPH_ISSUANCE_V7_AUTHORIZATION", "v4_local");
        std::env::set_var(
            "NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64",
            r#"{"issuer:test":{"kid":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#,
        );

        let error = Config::from_env().expect_err("graph issuance must require exchange");
        assert!(error
            .to_string()
            .contains("graph issuance requires NATIVE_EXCHANGE_V7_ENABLE=true"));
    }

    #[test]
    #[serial]
    fn validator_rejects_malformed_disabled_exchange_inputs() {
        let _env = clean_validator_env();
        for (name, value, graph_enabled, message) in [
            (
                "NATIVE_EXCHANGE_V7_RECEIPT_LIFETIME",
                "not-a-duration",
                false,
                "invalid duration",
            ),
            (
                "NATIVE_EXCHANGE_V7_TIMEOUT",
                "not-a-duration",
                false,
                "invalid duration",
            ),
            (
                "NATIVE_EXCHANGE_V7_MAX_BODY_BYTES",
                "not-a-number",
                false,
                "invalid digit",
            ),
            (
                "NATIVE_EXCHANGE_V7_RETAINED_DISCOVERY_PATHS",
                "/one.json,",
                false,
                "contains an empty path",
            ),
            (
                "NATIVE_GRAPH_ISSUANCE_V7_AUTHORIZATION",
                "unsupported",
                true,
                "unsupported V7 graph issuance authorization verifier",
            ),
        ] {
            std::env::remove_var("NATIVE_EXCHANGE_V7_ENABLE");
            std::env::remove_var("NATIVE_GRAPH_ISSUANCE_V7_ENABLE");
            for candidate in [
                "NATIVE_EXCHANGE_V7_RECEIPT_LIFETIME",
                "NATIVE_EXCHANGE_V7_TIMEOUT",
                "NATIVE_EXCHANGE_V7_MAX_BODY_BYTES",
                "NATIVE_EXCHANGE_V7_RETAINED_DISCOVERY_PATHS",
                "NATIVE_GRAPH_ISSUANCE_V7_AUTHORIZATION",
            ] {
                std::env::remove_var(candidate);
            }
            std::env::set_var(name, value);
            if graph_enabled {
                std::env::set_var("NATIVE_EXCHANGE_V7_ENABLE", "true");
                std::env::set_var("NATIVE_EXCHANGE_V7_REDIS_URL", "redis://127.0.0.1:1/");
                std::env::set_var("NATIVE_GRAPH_ISSUANCE_V7_ENABLE", "true");
            }

            let error = Config::from_env().expect_err("malformed exchange input must fail");
            assert!(error.to_string().contains(message));
        }
    }

    #[test]
    #[serial]
    fn validator_reports_require_tls_one_as_true_while_config_enables_it() {
        let _env = clean_validator_env();
        std::env::set_var("REQUIRE_TLS", "1");

        let config = freebird_issuer::config::Config::from_env().expect("REQUIRE_TLS=1 parses");
        assert!(config.require_tls);

        let section = validate_core_config(&config);
        let output = rendered_output(&section);
        assert!(output.contains("REQUIRE_TLS = true"));
        assert!(section.has_errors());
    }

    #[test]
    #[serial]
    fn validator_preserves_raw_admin_salt_and_webauthn_source_policies() {
        let _env = clean_validator_env();

        let missing_admin = validate_core_config(&current_config());
        let missing_admin_output = rendered_output(&missing_admin);
        assert!(missing_admin_output.contains("ADMIN_API_KEY = [not set]"));
        assert!(!missing_admin.has_errors());

        std::env::set_var("ADMIN_API_KEY", "");
        let empty_admin = validate_core_config(&current_config());
        let empty_admin_output = rendered_output(&empty_admin);
        assert!(empty_admin_output.contains("ADMIN_API_KEY = [set, 0 chars]"));
        assert!(empty_admin.has_errors());

        for (mode, salt_name, message) in [
            (
                "progressive_trust",
                "SYBIL_PROGRESSIVE_TRUST_SALT",
                "SYBIL_PROGRESSIVE_TRUST_SALT uses insecure default value",
            ),
            (
                "proof_of_diversity",
                "SYBIL_PROOF_OF_DIVERSITY_SALT",
                "SYBIL_PROOF_OF_DIVERSITY_SALT uses insecure default value",
            ),
            (
                "multi_party_vouching",
                "SYBIL_MULTI_PARTY_VOUCHING_SALT",
                "SYBIL_MULTI_PARTY_VOUCHING_SALT uses insecure default value",
            ),
        ] {
            std::env::set_var("SYBIL_RESISTANCE", mode);
            std::env::remove_var(salt_name);
            let missing_salt = validate_sybil_config(&current_config());
            assert!(rendered_output(&missing_salt).contains(message));

            std::env::set_var(salt_name, "default-sentinel");
            let sentinel_salt = validate_sybil_config(&current_config());
            assert!(rendered_output(&sentinel_salt).contains(message));
        }

        std::env::set_var("SYBIL_RESISTANCE", "none");
        std::env::set_var("WEBAUTHN_RP_ID", "example.test");
        let partial_id =
            validate_webauthn_config(&current_config()).expect("partial WebAuthn needs a section");
        assert!(rendered_output(&partial_id).contains("WEBAUTHN_RP_ORIGIN is missing"));

        std::env::remove_var("WEBAUTHN_RP_ID");
        std::env::set_var("WEBAUTHN_RP_ORIGIN", "https://example.test");
        let partial_origin =
            validate_webauthn_config(&current_config()).expect("partial WebAuthn needs a section");
        assert!(rendered_output(&partial_origin).contains("WEBAUTHN_RP_ID is missing"));

        std::env::remove_var("WEBAUTHN_RP_ORIGIN");
        std::env::set_var("SYBIL_RESISTANCE", "webauthn");
        let selected_without_rp = validate_sybil_config(&current_config());
        assert!(rendered_output(&selected_without_rp)
            .contains("WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN are required"));
    }

    #[test]
    #[serial]
    fn validator_redacts_unique_secrets_from_full_output_and_errors() {
        const ADMIN_SENTINEL: &str = "admin-api-sentinel-phase-4c-unique";
        const SALT_SENTINEL: &str = "salt-sentinel-phase-4c-unique";
        const REDIS_SENTINEL: &str = "redis-password-sentinel-phase-4c-unique";
        const PIN_SENTINEL: &str = "hsm-pin-sentinel-phase-4c-unique";

        let _env = clean_validator_env();
        std::env::set_var("ADMIN_API_KEY", ADMIN_SENTINEL);
        std::env::set_var("SYBIL_RESISTANCE", "progressive_trust");
        std::env::set_var("SYBIL_PROGRESSIVE_TRUST_SALT", SALT_SENTINEL);
        std::env::set_var("WEBAUTHN_RP_ID", "example.test");
        std::env::set_var("WEBAUTHN_RP_ORIGIN", "https://example.test");
        std::env::set_var(
            "WEBAUTHN_REDIS_URL",
            format!("redis://:{REDIS_SENTINEL}@127.0.0.1:6379/4"),
        );
        let mut config = current_config();
        std::env::set_var("HSM_ENABLE", "true");
        std::env::set_var("HSM_MODE", "storage");
        std::env::set_var("HSM_MODULE_PATH", "/missing/pkcs11.so");
        std::env::set_var("HSM_SLOT", "0");
        std::env::set_var("HSM_PIN", PIN_SENTINEL);
        std::env::set_var("HSM_KEY_LABEL", "phase-4c-label");
        config.key_config.hsm = Some(HsmConfig {
            module_path: "/missing/pkcs11.so".into(),
            slot: 0,
            pin: PIN_SENTINEL.into(),
            key_label: "phase-4c-label".into(),
            mode: HsmMode::Storage,
        });

        let sections = validation_sections(&config);
        let output = sections
            .iter()
            .map(rendered_output)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(output.contains("SYBIL_PROGRESSIVE_TRUST_SALT = [custom]"));
        assert!(output.contains("HSM_PIN = [set]"));
        for sentinel in [ADMIN_SENTINEL, SALT_SENTINEL, REDIS_SENTINEL, PIN_SENTINEL] {
            assert!(!output.contains(sentinel));
        }

        let parser_error =
            freebird_issuer::config::Config::from_env().expect_err("enabled HSM is rejected");
        for sentinel in [ADMIN_SENTINEL, SALT_SENTINEL, REDIS_SENTINEL, PIN_SENTINEL] {
            assert!(!parser_error.to_string().contains(sentinel));
        }
    }

    #[test]
    #[serial]
    #[ignore = "legacy V5 validator fixture retired at the V7 cutover"]
    fn validator_parser_error_precedes_retired_v5_material() {
        let _env = clean_validator_env();
        let fixture = ExchangeValidatorFixture::new(None);
        let key_path = fixture._dir.path().join("parser-gated.der");
        let metadata_path = fixture._dir.path().join("parser-gated.json");
        let graph_path = std::path::PathBuf::from(
            std::env::var_os("PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH")
                .expect("exchange fixture graph path"),
        );
        let graph_before = fs::read(&graph_path).unwrap();
        let provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
        write_provider(&key_path, &provider);
        std::env::set_var("PUBLIC_BEARER_ENABLE", "true");
        std::env::set_var("PUBLIC_BEARER_SK_PATH", &key_path);
        std::env::set_var("PUBLIC_BEARER_METADATA_PATH", &metadata_path);
        std::env::set_var("PUBLIC_BEARER_MODULUS_BITS", "2048");
        std::env::set_var("BIND_ADDR", "not-an-address");
        assert!(!metadata_path.exists());

        let error = match run_authoritative_validation() {
            Ok(_) => panic!("authoritative parser error must stop validator orchestration"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("Invalid BIND_ADDR"));
        assert!(!metadata_path.exists());
        assert!(fs::read(&graph_path).unwrap() == graph_before);

        std::env::set_var("BIND_ADDR", "127.0.0.1:0");
        let _ = validation_sections(&current_config());
        assert!(!metadata_path.exists());
    }

    #[test]
    #[serial]
    fn rejects_unknown_sybil_mode() {
        let _env = clean_validator_env();
        set_mode("not-a-runtime-mode");
        let section = validate_sybil_config(&current_config());
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message) if message.contains("Unknown SYBIL_RESISTANCE mode")
        )));
        std::env::remove_var("SYBIL_RESISTANCE");
    }

    #[test]
    #[serial]
    fn validator_rejects_missing_sybil_selection() {
        let _env = clean_validator_env();
        std::env::remove_var("SYBIL_RESISTANCE");

        let error = match run_authoritative_validation() {
            Ok(_) => panic!("missing SYBIL_RESISTANCE must stop validator parsing"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("SYBIL_RESISTANCE must be explicitly set"));
    }

    #[test]
    #[serial]
    fn validator_requires_webauthn_secret_for_selected_and_nonselected_modes() {
        let _env = clean_validator_env();
        std::env::set_var("WEBAUTHN_RP_ID", "example.test");
        std::env::set_var("WEBAUTHN_RP_ORIGIN", "https://example.test");
        std::env::remove_var("WEBAUTHN_PROOF_SECRET");

        set_mode("webauthn");
        let selected = validation_sections(&current_config());
        assert!(selected.iter().any(|section| {
            rendered_output(section).contains("WEBAUTHN_PROOF_SECRET is required")
        }));

        set_mode("progressive_trust");
        std::env::set_var("SYBIL_PROGRESSIVE_TRUST_SALT", "validator-safe-salt");
        let nonselected = validation_sections(&current_config());
        assert!(nonselected.iter().any(|section| {
            rendered_output(section).contains("WEBAUTHN_PROOF_SECRET is required")
        }));
    }

    #[test]
    #[serial]
    fn rejects_invalid_combined_sybil_configuration() {
        let _env = clean_validator_env();
        set_mode("combined");

        std::env::set_var("SYBIL_COMBINED_MECHANISMS", "pow,not-a-mechanism");
        let unknown_mechanism = validate_sybil_config(&current_config());
        assert!(unknown_mechanism.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("Unknown SYBIL_COMBINED_MECHANISMS mechanism")
        )));

        std::env::set_var("SYBIL_COMBINED_MECHANISMS", "pow");
        std::env::set_var("SYBIL_COMBINED_MODE", "not-a-combiner");
        let unknown_mode = validate_sybil_config(&current_config());
        assert!(unknown_mode.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("SYBIL_COMBINED_MODE must be one of")
        )));

        std::env::remove_var("SYBIL_COMBINED_MODE");
        let mut empty_config = current_config();
        empty_config.sybil_config.combined_mechanisms = vec![];
        let empty_set = validate_sybil_config(&empty_config);
        assert!(empty_set.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("SYBIL_COMBINED_MECHANISMS must contain at least one")
        )));
    }

    #[test]
    #[serial]
    fn rejects_unavailable_selected_and_combined_webauthn() {
        let _env = clean_validator_env();

        set_mode("webauthn");
        let selected = validate_sybil_config(&current_config());
        assert!(selected.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN are required")
        )));

        set_mode("combined");
        std::env::set_var("SYBIL_COMBINED_MECHANISMS", "pow, webauthn");
        let combined = validate_sybil_config(&current_config());
        assert!(combined.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN are required when combined")
        )));
    }

    #[test]
    #[serial]
    fn preserves_valid_combined_mechanisms_and_modes() {
        let _env = clean_validator_env();
        set_mode("combined");
        std::env::set_var("SYBIL_COMBINED_MECHANISMS", "pow, rate_limit");

        for mode in ["or", "and", "threshold", "OR", "And", "THRESHOLD"] {
            std::env::set_var("SYBIL_COMBINED_MODE", mode);
            assert!(
                !validate_sybil_config(&current_config()).has_errors(),
                "combined mode {mode} should remain valid"
            );
        }
    }

    const TEST_ISSUER_ID: &str = "issuer:freebird:v4";

    fn write_provider(path: &Path, provider: &SoftwareBlindRsaProvider) {
        fs::write(path, provider.to_der().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn exchange_descriptor(
        provider: &SoftwareBlindRsaProvider,
        audience: &str,
    ) -> ExchangeDescriptorV2 {
        let mut descriptor = ExchangeDescriptorV2 {
            id: String::new(),
            profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V2.into(),
            issuer_id: TEST_ISSUER_ID.into(),
            kid: hex::encode(provider.token_key_id()),
            audience: Some(audience.into()),
            spki_b64: Base64UrlUnpadded::encode_string(provider.public_key_spki()),
            suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
            valid_from: 10,
            valid_until: 20,
        };
        descriptor.id = descriptor.canonical_id().unwrap();
        descriptor
    }

    fn exchange_keyset(
        provider: &SoftwareBlindRsaProvider,
        audience: &str,
        private_key_path: Option<&Path>,
    ) -> ExchangeKeysetV2 {
        let mut keyset = ExchangeKeysetV2 {
            id: String::new(),
            keys: vec![ExchangeKeyV2 {
                descriptor: exchange_descriptor(provider, audience),
                private_key_path: private_key_path.map(|path| path.display().to_string()),
            }],
        };
        keyset.id = keyset.canonical_id();
        keyset
    }

    fn exchange_graph(
        source: ExchangeKeysetV2,
        target: ExchangeKeysetV2,
        admission_state: ExchangeAdmissionStateV2,
        budget_id: &str,
    ) -> ExchangeProfileV2 {
        let mut transition = ExchangeTransitionV2 {
            id: String::new(),
            source_keyset_id: source.id.clone(),
            target_keyset_id: target.id.clone(),
            sources: vec![ExchangeTransitionSlotV2 {
                descriptor_id: source.keys[0].descriptor.id.clone(),
                slot_id: "input".into(),
                class: "bearer".into(),
                quantity: 1,
            }],
            outputs: vec![ExchangeTransitionSlotV2 {
                descriptor_id: target.keys[0].descriptor.id.clone(),
                slot_id: "output".into(),
                class: "bearer".into(),
                quantity: 1,
            }],
            budget_id: budget_id.into(),
            budget_limit: 1,
            admission_state,
        };
        transition.id = transition.canonical_id();
        let mut graph = ExchangeProfileV2 {
            profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V2.into(),
            graph_id: String::new(),
            keysets: vec![source, target],
            transitions: vec![transition],
        };
        graph.graph_id = graph.canonical_graph_id();
        graph
    }

    struct ExchangeValidatorFixture {
        _env: EnvGuard,
        _dir: tempfile::TempDir,
        history_path: std::path::PathBuf,
        receipt_metadata: ExchangeReceiptKeyInfo,
        direct_provider: Option<SoftwareBlindRsaProvider>,
        active_graph_id: String,
        active_transition_id: String,
    }

    impl ExchangeValidatorFixture {
        fn new(direct_audience: Option<&str>) -> Self {
            let env = EnvGuard::clear(&[
                "PUBLIC_BEARER_EXCHANGE_ENABLE",
                "PUBLIC_BEARER_EXCHANGE_REDIS_URL",
                "PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH",
                "PUBLIC_BEARER_EXCHANGE_PROFILE_PATH",
                "PUBLIC_BEARER_EXCHANGE_RETAINED_GRAPH_PATHS",
                "PUBLIC_BEARER_EXCHANGE_RETAINED_PROFILE_PATHS",
                "PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH",
                "PUBLIC_BEARER_EXCHANGE_DISABLED_PUBLICATION_ACK_PATHS",
                "PUBLIC_BEARER_EXCHANGE_RECEIPT_LIFETIME",
                "PUBLIC_BEARER_EXCHANGE_MAX_BODY_BYTES",
                "PUBLIC_BEARER_EXCHANGE_TIMEOUT",
                "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_KEY_PATH",
                "PUBLIC_BEARER_EXCHANGE_RECEIPT_KEY_PATH",
                "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_METADATA_PATH",
                "PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_KEY_PATHS",
                "PUBLIC_BEARER_EXCHANGE_RETAINED_RECEIPT_METADATA_PATHS",
                "PUBLIC_BEARER_ENABLE",
                "PUBLIC_BEARER_SK_PATH",
                "PUBLIC_BEARER_METADATA_PATH",
                "PUBLIC_BEARER_VALIDITY",
                "PUBLIC_BEARER_AUDIENCE",
                "PUBLIC_BEARER_MODULUS_BITS",
                "NATIVE_BEARER_V7_ENABLE",
                "NATIVE_BEARER_V7_SK_PATH",
                "NATIVE_BEARER_V7_METADATA_PATH",
                "NATIVE_BEARER_V7_REGISTRY_PATH",
                "NATIVE_BEARER_V7_TOKEN_KEY_ID",
                "NATIVE_BEARER_V7_ASSET_ID",
                "NATIVE_BEARER_V7_AMOUNT_MINOR",
                "NATIVE_BEARER_V7_VALIDITY",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_POLICY_PATH",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_V4_REPLAY_REDIS_URL",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_V4_KEYRING_B64",
                "PUBLIC_BEARER_GRAPH_ISSUANCE_ALLOW_DEVELOPMENT_MOCK",
                "HSM_ENABLE",
                "HSM_MODE",
                "HSM_MODULE_PATH",
                "HSM_SLOT",
                "HSM_PIN",
                "HSM_KEY_LABEL",
                "ISSUER_ID",
            ]);
            let dir = tempfile::tempdir().unwrap();
            let source_provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
            let target_provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
            let source_path = dir.path().join("source.der");
            let target_path = dir.path().join("target.der");
            write_provider(&source_path, &source_provider);
            write_provider(&target_path, &target_provider);
            let graph = exchange_graph(
                exchange_keyset(&source_provider, "exchange", Some(&source_path)),
                exchange_keyset(&target_provider, "exchange", Some(&target_path)),
                ExchangeAdmissionStateV2::AcceptingNew,
                "active-budget",
            );
            let active_graph_id = graph.graph_id.clone();
            let active_transition_id = graph.transitions[0].id.clone();
            let graph_path = dir.path().join("graph.json");
            fs::write(&graph_path, serde_json::to_vec(&graph).unwrap()).unwrap();

            let receipt_path = dir.path().join("receipt.key");
            let receipt =
                freebird_issuer::exchange::receipt::load_or_generate_receipt_key(&receipt_path)
                    .unwrap();
            let receipt_metadata = ExchangeReceiptKeyInfo {
                key_id: receipt.key_id(),
                algorithm: "Ed25519".into(),
                purpose: "exchange_receipt_active".into(),
                public_key_b64: Base64UrlUnpadded::encode_string(
                    receipt.verifying_key().as_bytes(),
                ),
                valid_from: 10,
                valid_until: 20,
            };
            let receipt_metadata_path = dir.path().join("receipt.json");
            fs::write(
                &receipt_metadata_path,
                serde_json::to_vec(&receipt_metadata).unwrap(),
            )
            .unwrap();
            let history_path = dir.path().join("history.json");

            std::env::set_var("PUBLIC_BEARER_EXCHANGE_ENABLE", "true");
            std::env::set_var("PUBLIC_BEARER_EXCHANGE_REDIS_URL", "redis://127.0.0.1/");
            std::env::set_var("PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH", &graph_path);
            std::env::set_var(
                "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_KEY_PATH",
                &receipt_path,
            );
            std::env::set_var(
                "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_METADATA_PATH",
                &receipt_metadata_path,
            );
            std::env::set_var("PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH", &history_path);
            std::env::set_var("ISSUER_ID", TEST_ISSUER_ID);

            let direct_provider = direct_audience.map(|audience| {
                let provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
                let key_path = dir.path().join("direct.der");
                let metadata_path = dir.path().join("direct.json");
                write_provider(&key_path, &provider);
                let now = time::OffsetDateTime::now_utc().unix_timestamp();
                let metadata = PublicKeyInfo {
                    token_key_id: hex::encode(provider.token_key_id()),
                    token_type: freebird_crypto::PUBLIC_BEARER_TOKEN_TYPE.into(),
                    rfc9474_variant: freebird_crypto::PUBLIC_BEARER_RFC9474_VARIANT.into(),
                    modulus_bits: provider.modulus_bits(),
                    pubkey_spki_b64: Base64UrlUnpadded::encode_string(provider.public_key_spki()),
                    issuer_id: TEST_ISSUER_ID.into(),
                    valid_from: now - 60,
                    valid_until: now + 3600,
                    audience: Some(audience.into()),
                    spend_policy: freebird_crypto::PUBLIC_BEARER_SPEND_POLICY_SINGLE_USE.into(),
                    max_uses: None,
                };
                fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
                std::env::set_var("PUBLIC_BEARER_ENABLE", "true");
                std::env::set_var("PUBLIC_BEARER_SK_PATH", key_path);
                std::env::set_var("PUBLIC_BEARER_METADATA_PATH", metadata_path);
                std::env::set_var("PUBLIC_BEARER_AUDIENCE", audience);
                std::env::set_var(
                    "PUBLIC_BEARER_MODULUS_BITS",
                    provider.modulus_bits().to_string(),
                );
                provider
            });
            if direct_provider.is_none() {
                std::env::set_var("PUBLIC_BEARER_ENABLE", "false");
            }
            std::env::set_var("NATIVE_BEARER_V7_SK_PATH", "native_bearer_v7_sk.der");
            std::env::set_var(
                "NATIVE_BEARER_V7_METADATA_PATH",
                "native_bearer_v7_metadata.json",
            );
            std::env::set_var(
                "NATIVE_BEARER_V7_REGISTRY_PATH",
                "native_bearer_v7_registry.json",
            );
            std::env::set_var("NATIVE_BEARER_V7_TOKEN_KEY_ID", "00".repeat(32));
            std::env::set_var("NATIVE_BEARER_V7_ASSET_ID", "USD");
            std::env::set_var("NATIVE_BEARER_V7_AMOUNT_MINOR", "1");

            Self {
                _env: env,
                _dir: dir,
                history_path,
                receipt_metadata,
                direct_provider,
                active_graph_id,
                active_transition_id,
            }
        }

        fn acknowledgement(&self) -> ExchangeDisabledPublicationAcknowledgementV1 {
            ExchangeDisabledPublicationAcknowledgementV1 {
                version: EXCHANGE_DISABLED_PUBLICATION_ACK_VERSION.into(),
                issuer_id: TEST_ISSUER_ID.into(),
                graph_id: self.active_graph_id.clone(),
                disabled_transition_ids: vec![self.active_transition_id.clone()],
                acknowledged_admission_state: "disabled".into(),
                operator: "test-operator".into(),
                acknowledged_at_unix: 1,
            }
        }

        fn write_acknowledgement(
            &self,
            acknowledgement: &ExchangeDisabledPublicationAcknowledgementV1,
        ) -> std::path::PathBuf {
            let path = self._dir.path().join("publication-ack.json");
            fs::write(&path, serde_json::to_vec(acknowledgement).unwrap()).unwrap();
            std::env::set_var(
                "PUBLIC_BEARER_EXCHANGE_DISABLED_PUBLICATION_ACK_PATHS",
                &path,
            );
            path
        }

        fn write_history(
            &self,
            retained_graphs: serde_json::Value,
            receipt_keys: serde_json::Value,
        ) {
            fs::write(
                &self.history_path,
                serde_json::json!({
                    "retained_graphs": retained_graphs,
                    "retained_receipt_keys": receipt_keys,
                })
                .to_string(),
            )
            .unwrap();
        }

        fn retained_graph(
            &self,
            source: ExchangeKeysetV2,
            target: ExchangeKeysetV2,
            budget_id: &str,
        ) -> freebird_common::api::ExchangeGraphDiscoveryV2 {
            let graph = exchange_graph(
                source,
                target,
                ExchangeAdmissionStateV2::RecoveryOnly,
                budget_id,
            );
            freebird_issuer::startup::exchange_discovery_v2(
                &graph,
                &[],
                std::slice::from_ref(&self.receipt_metadata),
            )
            .unwrap()
            .active_graph
        }
    }

    #[test]
    #[serial]
    #[ignore = "legacy V5 validator fixture retired at the V7 cutover"]
    fn validator_does_not_make_a_direct_v5_issuer_authoritative() {
        let _env = clean_validator_env();
        let fixture = ExchangeValidatorFixture::new(None);
        let key_path = fixture._dir.path().join("direct-existing.der");
        let metadata_path = fixture._dir.path().join("direct-existing.json");
        let provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
        write_provider(&key_path, &provider);
        std::env::set_var("PUBLIC_BEARER_ENABLE", "true");
        std::env::set_var("PUBLIC_BEARER_SK_PATH", &key_path);
        std::env::set_var("PUBLIC_BEARER_METADATA_PATH", &metadata_path);
        std::env::set_var("PUBLIC_BEARER_MODULUS_BITS", "2048");
        let section = validate_exchange_config(&current_config());
        assert!(!metadata_path.exists());
        assert!(!section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message) if message.contains("direct V5")
        )));
        std::fs::remove_file(&key_path).unwrap();
        assert!(!metadata_path.exists());
    }

    #[test]
    #[serial]
    fn validator_checks_v7_key_metadata_policy_and_registry() {
        let _env = clean_validator_env();
        let fixture_dir = tempfile::tempdir().unwrap();
        std::env::set_var("ISSUER_ID", TEST_ISSUER_ID);
        let v7_config = freebird_issuer::config::NativeBearerV7Config {
            sk_path: fixture_dir.path().join("v7.der"),
            metadata_path: fixture_dir.path().join("v7.json"),
            registry_path: fixture_dir.path().join("v7-registry.json"),
            profile_id: freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID.into(),
            descriptor_id: "77".repeat(32),
            token_key_id: "44".repeat(32),
            asset_id: "USD".into(),
            amount_minor: 7,
            validity_secs: 3600,
        };
        let issuer = freebird_issuer::native_bearer_v7::NativeBearerV7Issuer::load_or_generate(
            &v7_config,
            TEST_ISSUER_ID,
        )
        .unwrap();
        freebird_issuer::v7_registry::load_and_reserve(
            &v7_config.registry_path,
            issuer.metadata(),
            issuer.binding(),
        )
        .unwrap();
        std::env::set_var("NATIVE_BEARER_V7_SK_PATH", &v7_config.sk_path);
        std::env::set_var("NATIVE_BEARER_V7_METADATA_PATH", &v7_config.metadata_path);
        std::env::set_var("NATIVE_BEARER_V7_REGISTRY_PATH", &v7_config.registry_path);
        std::env::set_var("NATIVE_BEARER_V7_TOKEN_KEY_ID", &v7_config.token_key_id);
        std::env::set_var("NATIVE_BEARER_V7_DESCRIPTOR_ID", &v7_config.descriptor_id);
        std::env::set_var("NATIVE_BEARER_V7_PROFILE_ID", &v7_config.profile_id);
        std::env::set_var("NATIVE_BEARER_V7_ASSET_ID", &v7_config.asset_id);
        std::env::set_var("NATIVE_BEARER_V7_AMOUNT_MINOR", "7");

        let section = validate_native_bearer_v7_config(&current_config());
        assert!(!section.has_errors(), "{}", rendered_output(&section));
        assert!(rendered_output(&section).contains("registry"));
    }

    #[test]
    #[serial]
    #[ignore = "legacy V5 validator fixture retired at the V7 cutover"]
    fn exchange_validator_rejects_semantically_invalid_v2_public_history() {
        let fixture = ExchangeValidatorFixture::new(None);
        fixture.write_history(
            serde_json::json!([]),
            serde_json::json!([fixture.receipt_metadata]),
        );

        let section = validate_exchange_config(&current_config());
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("V2 public history receipt key is not retained")
        )));
        assert!(!section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Ok(message) if message.contains("discovery metadata are valid")
        )));
    }

    #[test]
    #[serial]
    #[ignore = "legacy V5 validator fixture retired at the V7 cutover"]
    fn exchange_validator_does_not_compare_history_to_retired_direct_v5_metadata() {
        let fixture = ExchangeValidatorFixture::new(Some("direct-audience"));
        let direct = fixture.direct_provider.as_ref().unwrap();
        let other = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let graph = fixture.retained_graph(
            exchange_keyset(direct, "history-audience", None),
            exchange_keyset(&other, "exchange", None),
            "history-audience-budget",
        );
        fixture.write_history(serde_json::json!([graph]), serde_json::json!([]));

        let section = validate_exchange_config(&current_config());
        assert!(!section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message) if message.contains("direct V5")
        )));
    }

    #[test]
    #[serial]
    #[ignore = "legacy V5 validator fixture retired at the V7 cutover"]
    fn exchange_validator_does_not_treat_retired_direct_v5_as_authority() {
        let fixture = ExchangeValidatorFixture::new(Some("direct-audience"));
        let direct = fixture.direct_provider.as_ref().unwrap();
        let other = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let graph = fixture.retained_graph(
            exchange_keyset(&other, "exchange", None),
            exchange_keyset(direct, "direct-audience", None),
            "history-output-budget",
        );
        fixture.write_history(serde_json::json!([graph]), serde_json::json!([]));

        let section = validate_exchange_config(&current_config());
        assert!(!section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message) if message.contains("direct V5")
        )));
    }

    #[test]
    #[serial]
    #[ignore = "legacy V5 validator fixture retired at the V7 cutover"]
    fn exchange_validator_requires_acknowledgement_for_accepting_transition() {
        let fixture = ExchangeValidatorFixture::new(None);
        fixture.write_history(serde_json::json!([]), serde_json::json!([]));

        let section = validate_exchange_config(&current_config());
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("accepting V2 transition lacks an explicit disabled-publication acknowledgement for this graph")
        )));
        assert!(!section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Ok(message) if message.contains("discovery metadata are valid")
        )));
    }

    #[test]
    #[serial]
    #[ignore = "legacy V5 validator fixture retired at the V7 cutover"]
    fn exchange_validator_rejects_missing_and_malformed_acknowledgement_files() {
        let fixture = ExchangeValidatorFixture::new(None);
        fixture.write_history(serde_json::json!([]), serde_json::json!([]));
        let path = fixture._dir.path().join("missing-publication-ack.json");
        std::env::set_var(
            "PUBLIC_BEARER_EXCHANGE_DISABLED_PUBLICATION_ACK_PATHS",
            &path,
        );

        let missing = validate_exchange_config(&current_config());
        assert!(missing.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("read disabled-publication acknowledgement")
        )));

        fs::write(&path, b"not-json").unwrap();
        let malformed = validate_exchange_config(&current_config());
        assert!(malformed.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("parse disabled-publication acknowledgement")
        )));
    }

    #[test]
    #[serial]
    #[ignore = "legacy V5 validator fixture retired at the V7 cutover"]
    fn exchange_validator_rejects_acknowledgement_identity_and_state_mismatches() {
        let fixture = ExchangeValidatorFixture::new(None);
        fixture.write_history(serde_json::json!([]), serde_json::json!([]));

        let mut acknowledgement = fixture.acknowledgement();
        acknowledgement.issuer_id = "issuer:other".into();
        fixture.write_acknowledgement(&acknowledgement);
        let issuer_mismatch = validate_exchange_config(&current_config());
        assert!(issuer_mismatch.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("disabled-publication acknowledgement issuer mismatch")
        )));

        let mut acknowledgement = fixture.acknowledgement();
        acknowledgement.graph_id = "f".repeat(64);
        fixture.write_acknowledgement(&acknowledgement);
        let graph_mismatch = validate_exchange_config(&current_config());
        assert!(graph_mismatch.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("disabled-publication acknowledgement graph mismatch")
        )));

        let mut acknowledgement = fixture.acknowledgement();
        acknowledgement.disabled_transition_ids = vec!["f".repeat(64)];
        fixture.write_acknowledgement(&acknowledgement);
        let transition_mismatch = validate_exchange_config(&current_config());
        assert!(transition_mismatch.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("disabled-publication acknowledgement transition mismatch")
        )));

        let mut acknowledgement = fixture.acknowledgement();
        acknowledgement.acknowledged_admission_state = "accepting_new".into();
        fixture.write_acknowledgement(&acknowledgement);
        let state_mismatch = validate_exchange_config(&current_config());
        assert!(state_mismatch.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("invalid disabled-publication acknowledgement")
        )));
    }

    #[test]
    #[serial]
    #[ignore = "legacy V5 validator fixture retired at the V7 cutover"]
    fn exchange_validator_accepts_exact_disabled_publication_acknowledgement() {
        let fixture = ExchangeValidatorFixture::new(None);
        fixture.write_history(serde_json::json!([]), serde_json::json!([]));
        fixture.write_acknowledgement(&fixture.acknowledgement());

        let section = validate_exchange_config(&current_config());
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Ok(message) if message.contains("discovery metadata are valid")
        )));
        assert!(!section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("disabled-publication acknowledgement")
        )));
    }
}
