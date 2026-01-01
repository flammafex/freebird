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

fn main() {
    println!("🔍 Freebird Configuration Validator");
    println!("====================================");

    let mut sections = Vec::new();
    let mut has_errors = false;

    // Validate core configuration
    sections.push(validate_core_config());

    // Validate key configuration
    sections.push(validate_key_config());

    // Validate sybil configuration
    sections.push(validate_sybil_config());

    // Validate WebAuthn configuration (if enabled)
    if let Some(section) = validate_webauthn_config() {
        sections.push(section);
    }

    // Validate HSM configuration (if enabled)
    if let Some(section) = validate_hsm_config() {
        sections.push(section);
    }

    // Validate federation configuration
    sections.push(validate_federation_config());

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

fn validate_core_config() -> ValidationSection {
    let mut section = ValidationSection::new("Core Configuration");

    // ISSUER_ID
    let issuer_id = env::var("ISSUER_ID").unwrap_or_else(|_| "issuer:freebird:v1".to_string());
    section.add(CheckResult::Ok(format!("ISSUER_ID = {}", issuer_id)));

    // BIND_ADDR
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".to_string());
    match bind_addr.parse::<std::net::SocketAddr>() {
        Ok(_) => section.add(CheckResult::Ok(format!("BIND_ADDR = {}", bind_addr))),
        Err(e) => section.add(CheckResult::Error(format!(
            "BIND_ADDR = {} (invalid: {})",
            bind_addr, e
        ))),
    }

    // TOKEN_TTL_MIN
    let token_ttl = env::var("TOKEN_TTL_MIN")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(10);
    if token_ttl < 1 || token_ttl > 24 * 60 {
        section.add(CheckResult::Warning(format!(
            "TOKEN_TTL_MIN = {} (will be clamped to 1-1440)",
            token_ttl
        )));
    } else {
        section.add(CheckResult::Ok(format!("TOKEN_TTL_MIN = {} minutes", token_ttl)));
    }

    // EPOCH_DURATION
    let epoch_duration = freebird_common::duration::env_duration("EPOCH_DURATION", 86400);
    section.add(CheckResult::Ok(format!(
        "EPOCH_DURATION = {} ({})",
        format_duration(epoch_duration),
        epoch_duration
    )));

    // EPOCH_RETENTION
    let epoch_retention = env::var("EPOCH_RETENTION")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(2);
    section.add(CheckResult::Ok(format!(
        "EPOCH_RETENTION = {} epochs",
        epoch_retention
    )));

    // REQUIRE_TLS
    let require_tls = env::var("REQUIRE_TLS")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if require_tls {
        section.add(CheckResult::Ok("REQUIRE_TLS = true".to_string()));
    } else {
        section.add(CheckResult::Warning(
            "REQUIRE_TLS = false (enable in production)".to_string(),
        ));
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

fn validate_key_config() -> ValidationSection {
    let mut section = ValidationSection::new("Key Configuration");

    // ISSUER_SK_PATH
    let sk_path = env::var("ISSUER_SK_PATH").unwrap_or_else(|_| "issuer_sk.bin".to_string());
    let sk_path_obj = Path::new(&sk_path);

    if sk_path_obj.exists() {
        // Check file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(&sk_path) {
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 {
                    section.add(CheckResult::Warning(format!(
                        "ISSUER_SK_PATH = {} (exists, but permissions {:o} are too open - recommend 0600)",
                        sk_path, mode & 0o777
                    )));
                } else {
                    section.add(CheckResult::Ok(format!(
                        "ISSUER_SK_PATH = {} (exists, permissions {:o})",
                        sk_path, mode & 0o777
                    )));
                }
            }
        }
        #[cfg(not(unix))]
        {
            section.add(CheckResult::Ok(format!("ISSUER_SK_PATH = {} (exists)", sk_path)));
        }
    } else {
        // Check if parent directory exists and is writable
        if let Some(parent) = sk_path_obj.parent() {
            if parent.as_os_str().is_empty() || parent.exists() {
                section.add(CheckResult::Ok(format!(
                    "ISSUER_SK_PATH = {} (will be created on first run)",
                    sk_path
                )));
            } else {
                section.add(CheckResult::Error(format!(
                    "ISSUER_SK_PATH = {} (parent directory {} does not exist)",
                    sk_path,
                    parent.display()
                )));
            }
        } else {
            section.add(CheckResult::Ok(format!(
                "ISSUER_SK_PATH = {} (will be created)",
                sk_path
            )));
        }
    }

    // KEY_ROTATION_STATE_PATH
    let rotation_path = env::var("KEY_ROTATION_STATE_PATH")
        .unwrap_or_else(|_| "key_rotation_state.json".to_string());
    let rotation_path_obj = Path::new(&rotation_path);

    if rotation_path_obj.exists() {
        section.add(CheckResult::Ok(format!(
            "KEY_ROTATION_STATE_PATH = {} (exists)",
            rotation_path
        )));
    } else if let Some(parent) = rotation_path_obj.parent() {
        if parent.as_os_str().is_empty() || parent.exists() {
            section.add(CheckResult::Ok(format!(
                "KEY_ROTATION_STATE_PATH = {} (will be created)",
                rotation_path
            )));
        } else {
            section.add(CheckResult::Error(format!(
                "KEY_ROTATION_STATE_PATH = {} (parent directory {} does not exist)",
                rotation_path,
                parent.display()
            )));
        }
    }

    // KID override
    if let Ok(kid) = env::var("KID") {
        section.add(CheckResult::Ok(format!("KID = {} (override)", kid)));
    }

    section
}

fn validate_sybil_config() -> ValidationSection {
    let mut section = ValidationSection::new("Sybil Resistance Configuration");

    let mode = env::var("SYBIL_RESISTANCE").unwrap_or_else(|_| "none".to_string());
    section.add(CheckResult::Ok(format!("SYBIL_RESISTANCE = {}", mode)));

    match mode.as_str() {
        "none" => {
            section.add(CheckResult::Warning(
                "No Sybil resistance enabled - not recommended for production".to_string(),
            ));
        }
        "invitation" => {
            validate_invitation_config(&mut section);
        }
        "pow" => {
            let difficulty = env::var("SYBIL_POW_DIFFICULTY")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(20);
            section.add(CheckResult::Ok(format!(
                "SYBIL_POW_DIFFICULTY = {} leading zero bits",
                difficulty
            )));
        }
        "rate_limit" => {
            let rate_limit = freebird_common::duration::env_duration("SYBIL_RATE_LIMIT", 3600);
            section.add(CheckResult::Ok(format!(
                "SYBIL_RATE_LIMIT = {}",
                format_duration(rate_limit)
            )));
        }
        "progressive_trust" => {
            validate_progressive_trust_config(&mut section);
        }
        "combined" => {
            let mechanisms = env::var("SYBIL_COMBINED_MECHANISMS")
                .unwrap_or_else(|_| "pow,rate_limit".to_string());
            let mode = env::var("SYBIL_COMBINED_MODE").unwrap_or_else(|_| "or".to_string());
            section.add(CheckResult::Ok(format!(
                "SYBIL_COMBINED_MECHANISMS = {}",
                mechanisms
            )));
            section.add(CheckResult::Ok(format!("SYBIL_COMBINED_MODE = {}", mode)));
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

fn validate_invitation_config(section: &mut ValidationSection) {
    let per_user = env::var("SYBIL_INVITE_PER_USER")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(5);
    section.add(CheckResult::Ok(format!(
        "SYBIL_INVITE_PER_USER = {}",
        per_user
    )));

    let cooldown = freebird_common::duration::env_duration("SYBIL_INVITE_COOLDOWN", 3600);
    section.add(CheckResult::Ok(format!(
        "SYBIL_INVITE_COOLDOWN = {}",
        format_duration(cooldown)
    )));

    let expires = freebird_common::duration::env_duration("SYBIL_INVITE_EXPIRES", 30 * 24 * 3600);
    section.add(CheckResult::Ok(format!(
        "SYBIL_INVITE_EXPIRES = {}",
        format_duration(expires)
    )));

    let persistence_path = env::var("SYBIL_INVITE_PERSISTENCE_PATH")
        .unwrap_or_else(|_| "invitations.json".to_string());
    validate_persistence_path(section, "SYBIL_INVITE_PERSISTENCE_PATH", &persistence_path);

    // Check bootstrap users
    if let Ok(bootstrap) = env::var("SYBIL_INVITE_BOOTSTRAP_USERS") {
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

fn validate_progressive_trust_config(section: &mut ValidationSection) {
    let levels = env::var("SYBIL_PROGRESSIVE_TRUST_LEVELS")
        .unwrap_or_else(|_| "0:1:1d,30d:10:1h,90d:100:1m".to_string());
    section.add(CheckResult::Ok(format!(
        "SYBIL_PROGRESSIVE_TRUST_LEVELS = {}",
        levels
    )));

    let persistence_path = env::var("SYBIL_PROGRESSIVE_TRUST_PERSISTENCE_PATH")
        .unwrap_or_else(|_| "progressive_trust.json".to_string());
    validate_persistence_path(section, "SYBIL_PROGRESSIVE_TRUST_PERSISTENCE_PATH", &persistence_path);

    // Check for insecure default salt
    let salt = env::var("SYBIL_PROGRESSIVE_TRUST_SALT")
        .unwrap_or_else(|_| "default-salt-change-in-production".to_string());
    if salt.contains("default") || salt.contains("change") {
        section.add(CheckResult::Warning(
            "SYBIL_PROGRESSIVE_TRUST_SALT uses default value - change in production".to_string(),
        ));
    } else {
        section.add(CheckResult::Ok("SYBIL_PROGRESSIVE_TRUST_SALT = [custom]".to_string()));
    }
}

fn validate_persistence_path(section: &mut ValidationSection, name: &str, path: &str) {
    let path_obj = Path::new(path);
    if path_obj.exists() {
        section.add(CheckResult::Ok(format!("{} = {} (exists)", name, path)));
    } else if let Some(parent) = path_obj.parent() {
        if parent.as_os_str().is_empty() || parent.exists() {
            section.add(CheckResult::Ok(format!(
                "{} = {} (will be created)",
                name, path
            )));
        } else {
            section.add(CheckResult::Error(format!(
                "{} = {} (parent directory {} does not exist)",
                name,
                path,
                parent.display()
            )));
        }
    }
}

fn validate_webauthn_config() -> Option<ValidationSection> {
    let rp_id = env::var("WEBAUTHN_RP_ID").ok();
    let rp_origin = env::var("WEBAUTHN_RP_ORIGIN").ok();

    if rp_id.is_none() && rp_origin.is_none() {
        return None;
    }

    let mut section = ValidationSection::new("WebAuthn Configuration");

    match (&rp_id, &rp_origin) {
        (Some(id), Some(origin)) => {
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

    let rp_name = env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "Freebird".to_string());
    section.add(CheckResult::Ok(format!("WEBAUTHN_RP_NAME = {}", rp_name)));

    if let Ok(redis_url) = env::var("WEBAUTHN_REDIS_URL") {
        section.add(CheckResult::Ok(format!(
            "WEBAUTHN_REDIS_URL = {}",
            redis_url.split('@').last().unwrap_or(&redis_url) // Hide credentials
        )));
    }

    Some(section)
}

fn validate_hsm_config() -> Option<ValidationSection> {
    let hsm_enabled = env::var("HSM_ENABLE")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !hsm_enabled {
        return None;
    }

    let mut section = ValidationSection::new("HSM Configuration");
    section.add(CheckResult::Ok("HSM_ENABLE = true".to_string()));

    // Check required HSM variables
    let required_vars = [
        ("HSM_MODULE_PATH", "path to PKCS#11 module"),
        ("HSM_SLOT", "HSM slot number"),
        ("HSM_PIN", "HSM PIN"),
        ("HSM_KEY_LABEL", "key label in HSM"),
    ];

    for (var, desc) in &required_vars {
        match env::var(var) {
            Ok(val) => {
                if *var == "HSM_PIN" {
                    section.add(CheckResult::Ok(format!("{} = [set]", var)));
                } else if *var == "HSM_MODULE_PATH" {
                    // Check if module exists
                    if Path::new(&val).exists() {
                        section.add(CheckResult::Ok(format!("{} = {} (exists)", var, val)));
                    } else {
                        section.add(CheckResult::Error(format!(
                            "{} = {} (file does not exist)",
                            var, val
                        )));
                    }
                } else {
                    section.add(CheckResult::Ok(format!("{} = {}", var, val)));
                }
            }
            Err(_) => {
                section.add(CheckResult::Error(format!(
                    "{} is required when HSM_ENABLE=true ({})",
                    var, desc
                )));
            }
        }
    }

    let mode = env::var("HSM_MODE").unwrap_or_else(|_| "storage".to_string());
    if mode == "full" {
        section.add(CheckResult::Warning(
            "HSM_MODE = full (not yet implemented, will fall back to storage)".to_string(),
        ));
    } else {
        section.add(CheckResult::Ok(format!("HSM_MODE = {}", mode)));
    }

    Some(section)
}

fn validate_federation_config() -> ValidationSection {
    let mut section = ValidationSection::new("Federation Configuration");

    let federation_path = env::var("FEDERATION_DATA_PATH")
        .unwrap_or_else(|_| "/data/federation".to_string());
    let federation_path_obj = Path::new(&federation_path);

    if federation_path_obj.exists() {
        section.add(CheckResult::Ok(format!(
            "FEDERATION_DATA_PATH = {} (exists)",
            federation_path
        )));
    } else if let Some(parent) = federation_path_obj.parent() {
        if parent.exists() || parent.as_os_str().is_empty() {
            section.add(CheckResult::Ok(format!(
                "FEDERATION_DATA_PATH = {} (will be created)",
                federation_path
            )));
        } else {
            section.add(CheckResult::Warning(format!(
                "FEDERATION_DATA_PATH = {} (parent directory does not exist)",
                federation_path
            )));
        }
    }

    // Federated trust configuration
    let federated_enabled = env::var("SYBIL_FEDERATED_TRUST_ENABLED")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if federated_enabled {
        section.add(CheckResult::Ok("SYBIL_FEDERATED_TRUST_ENABLED = true".to_string()));

        if let Ok(roots) = env::var("SYBIL_FEDERATED_TRUST_TRUSTED_ROOTS") {
            let count = roots.split(',').filter(|s| !s.trim().is_empty()).count();
            section.add(CheckResult::Ok(format!(
                "SYBIL_FEDERATED_TRUST_TRUSTED_ROOTS = {} issuer(s)",
                count
            )));
        } else {
            section.add(CheckResult::Warning(
                "SYBIL_FEDERATED_TRUST_TRUSTED_ROOTS not set - no trusted roots configured"
                    .to_string(),
            ));
        }
    }

    section
}
