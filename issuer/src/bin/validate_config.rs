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

fn main() {
    println!("🔍 Freebird Configuration Validator");
    println!("====================================");

    let mut sections = Vec::new();
    let mut has_errors = false;

    // Validate core configuration
    sections.push(validate_core_config());

    // Validate key configuration
    sections.push(validate_key_config());
    sections.push(validate_exchange_config());

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
    let issuer_id = env::var("ISSUER_ID").unwrap_or_else(|_| "issuer:freebird:v4".to_string());
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

    let behind_proxy = env::var("BEHIND_PROXY")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    if require_tls && !behind_proxy {
        section.add(CheckResult::Error(
            "REQUIRE_TLS=true requires BEHIND_PROXY=true and a trusted proxy boundary".into(),
        ));
    }
    if behind_proxy {
        match env::var("TRUSTED_PROXY_CIDRS") {
            Ok(value) => {
                match freebird_common::tls_enforcement::validate_trusted_proxy_cidrs(&value) {
                    Ok(()) => {
                        section.add(CheckResult::Ok("TRUSTED_PROXY_CIDRS is configured".into()))
                    }
                    Err(error) => section.add(CheckResult::Error(format!(
                        "TRUSTED_PROXY_CIDRS invalid: {error}"
                    ))),
                }
            }
            _ => section.add(CheckResult::Error(
                "BEHIND_PROXY=true requires non-empty TRUSTED_PROXY_CIDRS".into(),
            )),
        }
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
                        sk_path,
                        mode & 0o777
                    )));
                }
            }
        }
        #[cfg(not(unix))]
        {
            section.add(CheckResult::Ok(format!(
                "ISSUER_SK_PATH = {} (exists)",
                sk_path
            )));
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

    // V4 deprecated secret keys are currently retained in memory only.  The
    // rotation state file does not make rotation restart-safe, so surface
    // this limitation rather than presenting the path as a production-safe
    // rotation facility.
    section.add(CheckResult::Warning(
        "V4 key rotation is unsafe: deprecated V4 keys are not persisted across restart; do not rely on rotation for production".to_string(),
    ));

    let environment = env::var("FREEBIRD_ENV").unwrap_or_else(|_| "production".to_string());
    let unsafe_rotation = env::var("ALLOW_UNSAFE_V4_ROTATION")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false);
    if unsafe_rotation && environment != "development" {
        section.add(CheckResult::Error(
            "ALLOW_UNSAFE_V4_ROTATION=true requires FREEBIRD_ENV=development".to_string(),
        ));
    } else if unsafe_rotation {
        section.add(CheckResult::Warning(
            "Unsafe V4 admin key rotation is enabled for development".to_string(),
        ));
    } else {
        section.add(CheckResult::Ok(
            "V4 admin key rotation is disabled".to_string(),
        ));
    }

    // KID override
    if let Ok(kid) = env::var("KID") {
        section.add(CheckResult::Ok(format!("KID = {} (override)", kid)));
    }

    section
}

fn validate_exchange_config() -> ValidationSection {
    let mut section = ValidationSection::new("Public Bearer Exchange Configuration");
    let enabled = env::var("PUBLIC_BEARER_EXCHANGE_ENABLE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    if !enabled {
        section.add(CheckResult::Ok(
            "PUBLIC_BEARER_EXCHANGE_ENABLE = false".into(),
        ));
        return section;
    }
    let config = match freebird_issuer::config::ExchangeConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            section.add(CheckResult::Error(format!(
                "V2 exchange environment is invalid: {error:#}"
            )));
            return section;
        }
    };
    section.add(CheckResult::Ok(format!(
        "active V2 graph = {}",
        config.active_graph_path.display()
    )));
    section.add(CheckResult::Ok(format!(
        "retained V2 graph history = {} graph(s)",
        config.retained_graph_paths.len()
    )));

    let issuer_id = env::var("ISSUER_ID").unwrap_or_else(|_| "issuer:freebird:v4".into());
    let direct_v5_metadata = if env::var("PUBLIC_BEARER_ENABLE")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(true)
    {
        let path =
            env::var("PUBLIC_BEARER_SK_PATH").unwrap_or_else(|_| "public_bearer_sk.der".into());
        if Path::new(&path).is_file() {
            let public_config = freebird_issuer::config::PublicKeyConfig {
                enabled: true,
                sk_path: path.into(),
                metadata_path: env::var("PUBLIC_BEARER_METADATA_PATH")
                    .map(Into::into)
                    .unwrap_or_else(|_| "public_bearer_metadata.json".into()),
                validity_secs: freebird_common::duration::env_duration(
                    "PUBLIC_BEARER_VALIDITY",
                    30 * 24 * 3600,
                ),
                audience: env::var("PUBLIC_BEARER_AUDIENCE")
                    .ok()
                    .filter(|value| !value.is_empty()),
                modulus_bits: env::var("PUBLIC_BEARER_MODULUS_BITS")
                    .ok()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(2048),
            };
            match freebird_issuer::public_tokens::PublicTokenIssuer::load_or_generate(
                &public_config,
                &issuer_id,
            ) {
                Ok(Some(issuer)) => Some(issuer.metadata().clone()),
                Ok(None) => {
                    section.add(CheckResult::Error(
                        "authoritative direct V5 issuer is unexpectedly disabled".into(),
                    ));
                    return section;
                }
                Err(error) => {
                    section.add(CheckResult::Error(format!(
                        "authoritative direct V5 key is invalid: {error}"
                    )));
                    return section;
                }
            }
        } else {
            section.add(CheckResult::Warning(format!(
                "direct V5 key {path} does not exist yet; collision validation will be repeated after startup creates it"
            )));
            None
        }
    } else {
        None
    };
    let direct_v5_spki = direct_v5_metadata
        .as_ref()
        .map(|metadata| {
            use base64ct::Encoding;
            base64ct::Base64UrlUnpadded::decode_vec(&metadata.pubkey_spki_b64)
                .map_err(anyhow::Error::from)
        })
        .transpose();
    let direct_v5_spki = match direct_v5_spki {
        Ok(spki) => spki,
        Err(error) => {
            section.add(CheckResult::Error(format!(
                "authoritative direct V5 metadata is invalid: {error}"
            )));
            return section;
        }
    };
    match config.load_v2(&issuer_id, direct_v5_spki.as_deref()) {
        Ok(loaded) => {
            let discovery = freebird_issuer::startup::exchange_discovery_v2(
                &loaded.active_graph,
                &loaded.retained_graphs,
                &loaded.receipt_keys.discovery_metadata(),
            );
            match discovery.and_then(|mut discovery| {
                if let Some(history) = loaded.public_history {
                    freebird_issuer::exchange::history::merge_public_history_v2(
                        &mut discovery,
                        history,
                    )?;
                }
                freebird_common::api::validate_exchange_discovery_v2(&issuer_id, &discovery)
                    .map_err(anyhow::Error::msg)?;
                if config.graph_issuance.enabled {
                    let document = freebird_issuer::graph_issuance::GraphIssuancePolicyDocument::load(
                        &config.graph_issuance.policy_path,
                        &loaded.active_graph,
                        &loaded.retained_graphs,
                    )?;
                    freebird_issuer::graph_issuance::validate_configured_authorizer(
                        &config.graph_issuance.authorization,
                        &document,
                    )?;
                    freebird_issuer::graph_issuance::validate_runtime_graph_issuance_signers(
                        &loaded.active_graph,
                        &loaded.retained_graphs,
                        &document,
                    )?;
                    use base64ct::Encoding;
                    let scopes = document
                        .policies
                        .iter()
                        .filter_map(|policy| policy.v4_local.as_ref())
                        .map(|v4| {
                            freebird_crypto::build_scope_digest(&v4.verifier_id, &v4.audience)
                                .map(|scope| {
                                    base64ct::Base64UrlUnpadded::encode_string(&scope)
                                })
                                .map_err(|_| anyhow::anyhow!("invalid V4 graph issuance scope"))
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?;
                    let authority = base64ct::Base64UrlUnpadded::encode_string(&[0u8; 32]);
                    freebird_common::api::validate_graph_issuance_discovery_v2(
                        &discovery,
                        &document.discovery(&authority, &scopes),
                    )
                    .map_err(anyhow::Error::msg)?;
                }
                freebird_issuer::exchange::history::global_key_identities_v2(
                    &issuer_id,
                    direct_v5_metadata.as_ref(),
                    &discovery,
                )?;
                let acknowledgements = load_disabled_publication_acknowledgements(
                    &config.disabled_publication_ack_paths,
                )?;
                validate_disabled_publication_acknowledgements_v2(
                    &issuer_id,
                    &discovery,
                    &acknowledgements,
                )?;
                Ok(())
            }) {
                Ok(()) => section.add(CheckResult::Ok(
                    "active/retained V2 graphs, target signers, receipt signers, and discovery metadata are valid".into(),
                )),
                Err(error) => section.add(CheckResult::Error(format!(
                    "V2 exchange discovery is invalid: {error:#}"
                ))),
            }
        }
        Err(error) => section.add(CheckResult::Error(format!(
            "V2 graph or signer history is invalid: {error:#}"
        ))),
    }

    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| runtime.block_on(config.validate_redis_durability()))
    {
        Ok(()) => section.add(CheckResult::Ok(
            "exchange Redis is reachable, standalone, authoritative, AOF-backed, and non-evicting"
                .into(),
        )),
        Err(error) => section.add(CheckResult::Error(format!(
            "exchange Redis durability validation failed: {error:#}"
        ))),
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
        "proof_of_work" => {
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
            section.add(CheckResult::Warning(
                "Progressive Trust is experimental and has not been reviewed as a production Sybil boundary".to_string(),
            ));
            validate_progressive_trust_config(&mut section);
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
            validate_social_graph_config(&mut section);
        }
        "webauthn" => {
            if env::var("WEBAUTHN_RP_ID").is_err() || env::var("WEBAUTHN_RP_ORIGIN").is_err() {
                section.add(CheckResult::Error(
                    "WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN are required when SYBIL_RESISTANCE=webauthn".to_string(),
                ));
            } else {
                section.add(CheckResult::Ok(
                    "WebAuthn configuration is present (feature-gated at runtime)".to_string(),
                ));
            }
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

            // Validate salts for any combined mechanisms that use them
            let mechanisms: Vec<&str> = mechanisms.split(',').map(str::trim).collect();
            if mechanisms.contains(&"progressive_trust") {
                section.add(CheckResult::Warning(
                    "Progressive Trust is experimental and has not been reviewed as a production Sybil boundary".to_string(),
                ));
                validate_progressive_trust_config(&mut section);
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
                validate_social_graph_config(&mut section);
            }
            if mechanisms.contains(&"webauthn")
                && (env::var("WEBAUTHN_RP_ID").is_err() || env::var("WEBAUTHN_RP_ORIGIN").is_err())
            {
                section.add(CheckResult::Error(
                    "WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN are required when combined includes webauthn".to_string(),
                ));
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
    validate_persistence_path(
        section,
        "SYBIL_PROGRESSIVE_TRUST_PERSISTENCE_PATH",
        &persistence_path,
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

fn validate_social_graph_config(section: &mut ValidationSection) {
    let attesters_path = env::var("SOCIAL_GRAPH_ATTESTERS_PATH")
        .unwrap_or_else(|_| "social_graph_attesters.json".to_string());
    validate_persistence_path(section, "SOCIAL_GRAPH_ATTESTERS_PATH", &attesters_path);

    match env::var("SOCIAL_GRAPH_ACCEPTED_POLICY_IDS") {
        Ok(value) if value.split(',').any(|id| !id.trim().is_empty()) => section.add(
            CheckResult::Ok("SOCIAL_GRAPH_ACCEPTED_POLICY_IDS = [configured]".to_string()),
        ),
        _ => section.add(CheckResult::Error(
            "SOCIAL_GRAPH_ACCEPTED_POLICY_IDS is required for social_graph and must not be empty"
                .to_string(),
        )),
    }

    if env::var("SOCIAL_GRAPH_JWKS_URL").is_ok() {
        section.add(CheckResult::Warning(
            "SOCIAL_GRAPH_JWKS_URL is configured, but JWKS key refresh is not implemented; local attester keys remain authoritative".to_string(),
        ));
    }

    let state_path = env::var("SOCIAL_GRAPH_STATE_PATH")
        .unwrap_or_else(|_| "social_graph_state.json".to_string());
    section.add(CheckResult::Warning(format!(
        "SOCIAL_GRAPH_STATE_PATH = {} (local revocation state is not implemented)",
        state_path
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
            redis_url.split('@').next_back().unwrap_or(&redis_url) // Hide credentials
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
            "HSM_MODE = full is unsupported: VOPRF evaluation remains in software; HSM protects key storage only".to_string(),
        ));
    } else {
        section.add(CheckResult::Ok(format!("HSM_MODE = {}", mode)));
    }

    Some(section)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use freebird_common::api::{ExchangeReceiptKeyInfo, PublicKeyInfo};
    use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};
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

    #[test]
    #[serial]
    fn recognizes_social_graph_and_reports_required_policy_ids() {
        set_mode("social_graph");
        let section = validate_sybil_config();

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
        set_mode("social_graph");
        std::env::set_var("SOCIAL_GRAPH_ACCEPTED_POLICY_IDS", "clout-trust-v1");
        let section = validate_sybil_config();

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
        set_mode("proof_of_work");
        assert!(!validate_sybil_config().has_errors());

        set_mode("progressive_trust");
        let section = validate_sybil_config();
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Warning(message) if message.contains("Progressive Trust") && message.contains("experimental")
        )));
        std::env::remove_var("SYBIL_RESISTANCE");
    }

    #[test]
    #[serial]
    fn warns_for_unsupported_hsm_native_voprf() {
        std::env::set_var("HSM_ENABLE", "true");
        std::env::set_var("HSM_MODE", "full");
        let section = validate_hsm_config().expect("HSM section should be present");
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Warning(message) if message.contains("unsupported") && message.contains("VOPRF")
        )));
        std::env::remove_var("HSM_ENABLE");
        std::env::remove_var("HSM_MODE");
    }

    #[test]
    #[serial]
    fn warns_when_v4_rotation_is_not_restart_safe() {
        let section = validate_key_config();
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Warning(message) if message.contains("V4 key rotation") && message.contains("not persisted")
        )));
    }

    #[test]
    #[serial]
    fn rejects_unsafe_v4_rotation_outside_development() {
        std::env::set_var("ALLOW_UNSAFE_V4_ROTATION", "true");
        std::env::set_var("FREEBIRD_ENV", "production");
        let section = validate_key_config();
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message) if message.contains("FREEBIRD_ENV=development")
        )));
        std::env::remove_var("ALLOW_UNSAFE_V4_ROTATION");
        std::env::remove_var("FREEBIRD_ENV");
    }

    #[test]
    #[serial]
    fn rejects_unknown_sybil_mode() {
        set_mode("not-a-runtime-mode");
        let section = validate_sybil_config();
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message) if message.contains("Unknown SYBIL_RESISTANCE mode")
        )));
        std::env::remove_var("SYBIL_RESISTANCE");
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
    fn exchange_validator_rejects_semantically_invalid_v2_public_history() {
        let fixture = ExchangeValidatorFixture::new(None);
        fixture.write_history(
            serde_json::json!([]),
            serde_json::json!([fixture.receipt_metadata]),
        );

        let section = validate_exchange_config();
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
    fn exchange_validator_rejects_history_direct_key_audience_conflict() {
        let fixture = ExchangeValidatorFixture::new(Some("direct-audience"));
        let direct = fixture.direct_provider.as_ref().unwrap();
        let other = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let graph = fixture.retained_graph(
            exchange_keyset(direct, "history-audience", None),
            exchange_keyset(&other, "exchange", None),
            "history-audience-budget",
        );
        fixture.write_history(serde_json::json!([graph]), serde_json::json!([]));

        let section = validate_exchange_config();
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("conflicting global V5 key identity metadata")
        )));
        assert!(!section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Ok(message) if message.contains("discovery metadata are valid")
        )));
    }

    #[test]
    #[serial]
    fn exchange_validator_rejects_historical_output_direct_issuance_collision() {
        let fixture = ExchangeValidatorFixture::new(Some("direct-audience"));
        let direct = fixture.direct_provider.as_ref().unwrap();
        let other = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let graph = fixture.retained_graph(
            exchange_keyset(&other, "exchange", None),
            exchange_keyset(direct, "direct-audience", None),
            "history-output-budget",
        );
        fixture.write_history(serde_json::json!([graph]), serde_json::json!([]));

        let section = validate_exchange_config();
        assert!(section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("exchange output overlaps direct V5 issuance key")
        )));
        assert!(!section.checks.iter().any(|check| matches!(
            check,
            CheckResult::Ok(message) if message.contains("discovery metadata are valid")
        )));
    }

    #[test]
    #[serial]
    fn exchange_validator_requires_acknowledgement_for_accepting_transition() {
        let fixture = ExchangeValidatorFixture::new(None);
        fixture.write_history(serde_json::json!([]), serde_json::json!([]));

        let section = validate_exchange_config();
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
    fn exchange_validator_rejects_missing_and_malformed_acknowledgement_files() {
        let fixture = ExchangeValidatorFixture::new(None);
        fixture.write_history(serde_json::json!([]), serde_json::json!([]));
        let path = fixture._dir.path().join("missing-publication-ack.json");
        std::env::set_var(
            "PUBLIC_BEARER_EXCHANGE_DISABLED_PUBLICATION_ACK_PATHS",
            &path,
        );

        let missing = validate_exchange_config();
        assert!(missing.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("read disabled-publication acknowledgement")
        )));

        fs::write(&path, b"not-json").unwrap();
        let malformed = validate_exchange_config();
        assert!(malformed.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("parse disabled-publication acknowledgement")
        )));
    }

    #[test]
    #[serial]
    fn exchange_validator_rejects_acknowledgement_identity_and_state_mismatches() {
        let fixture = ExchangeValidatorFixture::new(None);
        fixture.write_history(serde_json::json!([]), serde_json::json!([]));

        let mut acknowledgement = fixture.acknowledgement();
        acknowledgement.issuer_id = "issuer:other".into();
        fixture.write_acknowledgement(&acknowledgement);
        let issuer_mismatch = validate_exchange_config();
        assert!(issuer_mismatch.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("disabled-publication acknowledgement issuer mismatch")
        )));

        let mut acknowledgement = fixture.acknowledgement();
        acknowledgement.graph_id = "f".repeat(64);
        fixture.write_acknowledgement(&acknowledgement);
        let graph_mismatch = validate_exchange_config();
        assert!(graph_mismatch.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("disabled-publication acknowledgement graph mismatch")
        )));

        let mut acknowledgement = fixture.acknowledgement();
        acknowledgement.disabled_transition_ids = vec!["f".repeat(64)];
        fixture.write_acknowledgement(&acknowledgement);
        let transition_mismatch = validate_exchange_config();
        assert!(transition_mismatch.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("disabled-publication acknowledgement transition mismatch")
        )));

        let mut acknowledgement = fixture.acknowledgement();
        acknowledgement.acknowledged_admission_state = "accepting_new".into();
        fixture.write_acknowledgement(&acknowledgement);
        let state_mismatch = validate_exchange_config();
        assert!(state_mismatch.checks.iter().any(|check| matches!(
            check,
            CheckResult::Error(message)
                if message.contains("invalid disabled-publication acknowledgement")
        )));
    }

    #[test]
    #[serial]
    fn exchange_validator_accepts_exact_disabled_publication_acknowledgement() {
        let fixture = ExchangeValidatorFixture::new(None);
        fixture.write_history(serde_json::json!([]), serde_json::json!([]));
        fixture.write_acknowledgement(&fixture.acknowledgement());

        let section = validate_exchange_config();
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
