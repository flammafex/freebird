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
    let discovery_result = freebird_issuer::startup::validate_v7_runtime_config(config);
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
