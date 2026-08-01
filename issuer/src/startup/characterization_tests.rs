// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::Application;
#[cfg(feature = "human-gate-webauthn")]
use crate::config::WebAuthnConfig;
use crate::config::{
    Config, ExchangeConfig, GraphIssuanceAuthorizationConfig, GraphIssuanceConfig, HsmConfig,
    HsmMode, KeyConfig, PublicKeyConfig, SybilConfig,
};
use crate::exchange::profiles::{ExchangeAdmissionStateV2, ExchangeProfileValidationModeV2};
use anyhow::{bail, Context, Result};
use axum::{extract::ConnectInfo, routing::get, Router};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::ExchangeReceiptKeyInfo;
use p256::ecdsa::SigningKey;
use reqwest::{Client, Response};
use serial_test::serial;
use sha2::{Digest, Sha256};
use std::{
    env,
    net::{SocketAddr, TcpStream as StdTcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use time::OffsetDateTime;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

const ADMIN_KEY: &str = "characterization-admin-key-at-least-32-chars";

struct RedisHarness {
    child: Option<Child>,
    url: String,
    port: u16,
    _dir: tempfile::TempDir,
}

impl RedisHarness {
    fn start_if_available() -> Result<Option<Self>> {
        if !Command::new("redis-server")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            eprintln!(
                "skipping TLS startup ordering characterization: redis-server is unavailable"
            );
            return Ok(None);
        }

        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let mut harness = Self {
            child: None,
            url: format!("redis://127.0.0.1:{port}/"),
            port,
            _dir: tempfile::tempdir()?,
        };
        harness.spawn()?;
        Ok(Some(harness))
    }

    fn spawn(&mut self) -> Result<()> {
        self.child = Some(
            Command::new("redis-server")
                .args([
                    "--port",
                    &self.port.to_string(),
                    "--bind",
                    "127.0.0.1",
                    "--dir",
                    self._dir.path().to_str().context("non-UTF8 Redis path")?,
                    "--appendonly",
                    "yes",
                    "--appendfsync",
                    "always",
                    "--save",
                    "",
                    "--maxmemory-policy",
                    "noeviction",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        for _ in 0..250 {
            if StdTcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return Ok(());
            }
            if self
                .child
                .as_mut()
                .is_some_and(|child| child.try_wait().ok().flatten().is_some())
            {
                bail!("redis-server exited during startup")
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        bail!("redis-server did not become reachable")
    }
}

impl Drop for RedisHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct EnvGuard {
    values: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    fn new() -> Self {
        let keys = [
            "SYBIL_REPLAY_STORE",
            "SYBIL_REPLAY_REDIS_URL",
            "REDIS_URL",
            "REQUIRE_TLS",
            "BEHIND_PROXY",
            "TRUSTED_PROXY_CIDRS",
            "WEBAUTHN_PROOF_SECRET",
            "WEBAUTHN_REQUIRE_ATTESTATION",
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

fn prepare_env() {
    env::set_var("SYBIL_REPLAY_STORE", "memory");
    env::remove_var("SYBIL_REPLAY_REDIS_URL");
    env::remove_var("REDIS_URL");
    env::set_var("REQUIRE_TLS", "false");
    env::set_var("BEHIND_PROXY", "false");
    env::remove_var("TRUSTED_PROXY_CIDRS");
    env::remove_var("WEBAUTHN_PROOF_SECRET");
    env::set_var("WEBAUTHN_REQUIRE_ATTESTATION", "false");
}

fn minimal_config(root: &Path) -> Config {
    Config {
        issuer_id: "issuer:test:startup-characterization".into(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        require_tls: false,
        behind_proxy: false,
        key_config: KeyConfig {
            sk_path: root.join("issuer.key"),
            rotation_state_path: root.join("rotation.json"),
            kid_override: None,
            hsm: None,
        },
        public_key_config: PublicKeyConfig {
            enabled: false,
            sk_path: root.join("public-bearer.der"),
            metadata_path: root.join("public-bearer.json"),
            validity_secs: 3600,
            audience: Some("startup-characterization".into()),
            modulus_bits: 2048,
        },
        exchange_config: ExchangeConfig {
            enabled: false,
            active_graph_path: root.join("active-graph.json"),
            retained_graph_paths: vec![],
            public_history_path: None,
            disabled_publication_ack_paths: vec![],
            active_receipt_key_path: root.join("receipt.key"),
            active_receipt_metadata_path: root.join("receipt.json"),
            retained_receipt_key_paths: vec![],
            retained_receipt_metadata_paths: vec![],
            redis_url: None,
            receipt_lifetime_secs: 300,
            request_body_limit: 64 * 1024,
            request_timeout_secs: 5,
            graph_issuance: GraphIssuanceConfig {
                enabled: false,
                policy_path: root.join("graph-policy.json"),
                authorization: GraphIssuanceAuthorizationConfig::Disabled,
            },
        },
        sybil_config: SybilConfig {
            mode: "none".into(),
            pow_difficulty: 20,
            rate_limit_secs: 3600,
            invite_per_user: 5,
            invite_cooldown_secs: 3600,
            invite_expires_secs: 86_400,
            invite_new_user_wait_secs: 86_400,
            invite_persistence_path: root.join("invitations.json"),
            invite_autosave_interval_secs: 300,
            invite_signing_key_path: root.join("invitation.key"),
            bootstrap_users: None,
            webauthn_max_proof_age: None,
            progressive_trust_levels: vec!["0:1:1m".into()],
            progressive_trust_persistence_path: root.join("progressive.json"),
            progressive_trust_autosave_interval: 300,
            progressive_trust_hmac_secret: None,
            progressive_trust_hmac_secret_path: root.join("progressive.secret"),
            progressive_trust_salt: "startup-progressive-salt".into(),
            progressive_trust_allow_insecure: false,
            proof_of_diversity_min_score: 40,
            proof_of_diversity_persistence_path: root.join("diversity.json"),
            proof_of_diversity_autosave_interval: 300,
            proof_of_diversity_hmac_secret: None,
            proof_of_diversity_hmac_secret_path: root.join("diversity.secret"),
            proof_of_diversity_fingerprint_salt: "startup-diversity-salt".into(),
            proof_of_diversity_allow_insecure: false,
            multi_party_vouching_required_vouchers: 3,
            multi_party_vouching_cooldown_secs: 3600,
            multi_party_vouching_expires_secs: 86_400,
            multi_party_vouching_new_user_wait_secs: 86_400,
            multi_party_vouching_persistence_path: root.join("vouching.json"),
            multi_party_vouching_autosave_interval: 300,
            multi_party_vouching_hmac_secret: None,
            multi_party_vouching_hmac_secret_path: root.join("vouching.secret"),
            multi_party_vouching_salt: "startup-vouching-salt".into(),
            multi_party_vouching_allow_insecure: false,
            social_graph_attesters_path: root.join("attesters.json"),
            social_graph_jwks_url: None,
            social_graph_key_refresh_interval_secs: 3600,
            social_graph_min_level: 1,
            social_graph_accepted_policy_ids: vec![],
            social_graph_attestation_max_age_secs: 300,
            social_graph_clock_skew_secs: 30,
            social_graph_require_request_binding: true,
            social_graph_require_quota_nullifier: false,
            social_graph_replay_ttl_secs: 600,
            social_graph_state_path: root.join("social.json"),
            social_graph_fail_closed: true,
            combined_mechanisms: vec!["pow".into(), "rate_limit".into()],
            combined_mode: "or".into(),
            combined_threshold: 2,
        },
        webauthn_config: None,
        admin_api_key: Some(ADMIN_KEY.into()),
        epoch_duration_sec: 86_400,
        epoch_retention: 2,
        allow_unsafe_v4_rotation: false,
        audit_log_path: root.join("audit.json"),
        unsafe_development_mode: true,
    }
}

fn write_valid_exchange_fixture(root: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let mut graph: crate::exchange::profiles::ExchangeProfileV2 = serde_json::from_str(
        include_str!("../../../docs/examples/public-bearer-exchange-profile.json"),
    )?;
    for keyset in &mut graph.keysets {
        for key in &mut keyset.keys {
            key.private_key_path = None;
        }
    }
    for transition in &mut graph.transitions {
        transition.admission_state = ExchangeAdmissionStateV2::Disabled;
    }
    graph.validate(
        ExchangeProfileValidationModeV2::Active,
        "issuer:docker:v4",
        None,
    )?;

    let graph_path = root.join("active-graph.json");
    std::fs::write(&graph_path, serde_json::to_vec_pretty(&graph)?)?;

    let receipt_path = root.join("receipt.key");
    let receipt_key = crate::exchange::load_or_generate_receipt_key(&receipt_path)?;
    let receipt_metadata = ExchangeReceiptKeyInfo {
        key_id: receipt_key.key_id(),
        algorithm: "Ed25519".into(),
        purpose: "exchange_receipt_active".into(),
        public_key_b64: Base64UrlUnpadded::encode_string(receipt_key.verifying_key().as_bytes()),
        valid_from: 1_700_000_000,
        valid_until: 4_102_444_800,
    };
    let receipt_metadata_path = root.join("receipt.json");
    std::fs::write(
        &receipt_metadata_path,
        serde_json::to_vec_pretty(&receipt_metadata)?,
    )?;

    Ok((graph_path, receipt_path, receipt_metadata_path))
}

async fn build_error(config: Config) -> String {
    match Application::build(config).await {
        Ok(application) => {
            drop(application);
            "application unexpectedly built".into()
        }
        Err(error) => format!("{error:#}"),
    }
}

fn assert_preflight_left_key_paths_empty(root: &Path) {
    for path in [
        root.join("issuer.key"),
        root.join("rotation.json"),
        root.join("public-bearer.der"),
        root.join("public-bearer.json"),
        root.join("audit.json"),
        root.join("invitation.key"),
    ] {
        assert!(!path.exists(), "preflight created {}", path.display());
    }
}

fn deterministic_issuer_material() -> ([u8; 32], String, String) {
    let raw = [1u8; 32];
    let signing_key = SigningKey::from_bytes((&raw).into()).expect("test P-256 key is valid");
    let public_key = signing_key.verifying_key().to_encoded_point(true);
    let public_key_b64 = Base64UrlUnpadded::encode_string(public_key.as_bytes());
    let mut digest = Sha256::new();
    digest.update(b"freebird:issuer:pk:");
    digest.update(public_key.as_bytes());
    let mut kid_prefix = Base64UrlUnpadded::encode_string(&digest.finalize());
    kid_prefix.truncate(24);
    (raw, public_key_b64, kid_prefix)
}

fn key_material_stage_config(root: &Path) -> Config {
    let mut config = minimal_config(root);
    config.public_key_config.enabled = true;
    config.exchange_config.enabled = true;
    config.exchange_config.redis_url = Some("redis://127.0.0.1:1/".into());
    config
}

fn utc_date() -> String {
    OffsetDateTime::now_utc().date().to_string()
}

#[tokio::test]
#[serial]
async fn key_material_failures_preserve_stage_precedence_and_side_effects() -> Result<()> {
    let _env = EnvGuard::new();
    prepare_env();

    const INVALID_ISSUER_KEY: &[u8] = b"invalid-issuer-key";
    const INVALID_ROTATION: &[u8] = b"invalid-rotation-json";
    const INVALID_V5_DER: &[u8] = b"invalid-v5-der";
    const INVALID_EXCHANGE_GRAPH: &[u8] = b"invalid-exchange-graph";

    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let config = key_material_stage_config(root);
    std::fs::write(&config.key_config.sk_path, INVALID_ISSUER_KEY)?;
    std::fs::write(&config.key_config.rotation_state_path, INVALID_ROTATION)?;
    std::fs::write(&config.public_key_config.sk_path, INVALID_V5_DER)?;
    std::fs::write(
        &config.exchange_config.active_graph_path,
        INVALID_EXCHANGE_GRAPH,
    )?;

    let error = build_error(config).await;
    assert!(error.contains("Failed to load or generate issuer keypair"));
    assert!(std::fs::read(root.join("issuer.key"))? == INVALID_ISSUER_KEY);
    assert!(std::fs::read(root.join("rotation.json"))? == INVALID_ROTATION);
    assert!(std::fs::read(root.join("public-bearer.der"))? == INVALID_V5_DER);
    assert!(std::fs::read(root.join("active-graph.json"))? == INVALID_EXCHANGE_GRAPH);
    assert!(!root.join("public-bearer.json").exists());

    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let (issuer_key, _, _) = deterministic_issuer_material();
    let config = key_material_stage_config(root);
    std::fs::write(&config.key_config.sk_path, issuer_key)?;
    std::fs::write(&config.key_config.rotation_state_path, INVALID_ROTATION)?;
    std::fs::write(&config.public_key_config.sk_path, INVALID_V5_DER)?;
    std::fs::write(
        &config.exchange_config.active_graph_path,
        INVALID_EXCHANGE_GRAPH,
    )?;

    let error = build_error(config).await;
    assert!(error.contains("Failed to initialize VOPRF core"));
    assert!(std::fs::read(root.join("issuer.key"))? == issuer_key);
    assert!(std::fs::read(root.join("rotation.json"))? == INVALID_ROTATION);
    assert!(std::fs::read(root.join("public-bearer.der"))? == INVALID_V5_DER);
    assert!(std::fs::read(root.join("active-graph.json"))? == INVALID_EXCHANGE_GRAPH);
    assert!(!root.join("public-bearer.json").exists());

    for with_existing_rotation in [false, true] {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let (issuer_key, _, kid_prefix) = deterministic_issuer_material();
        let config = key_material_stage_config(root);
        std::fs::write(&config.key_config.sk_path, issuer_key)?;
        if with_existing_rotation {
            std::fs::write(
                &config.key_config.rotation_state_path,
                serde_json::to_vec(&serde_json::json!({
                    "active_kid": format!("{kid_prefix}-{}", utc_date()),
                    "deprecated_keys": [],
                    "version": 1,
                }))?,
            )?;
        }
        std::fs::write(&config.public_key_config.sk_path, INVALID_V5_DER)?;
        std::fs::write(
            &config.exchange_config.active_graph_path,
            INVALID_EXCHANGE_GRAPH,
        )?;

        let error = build_error(config).await;
        assert!(error.contains("Failed to initialize V5 public bearer issuer"));
        assert!(std::fs::read(root.join("issuer.key"))? == issuer_key);
        assert!(std::fs::read(root.join("public-bearer.der"))? == INVALID_V5_DER);
        assert!(std::fs::read(root.join("active-graph.json"))? == INVALID_EXCHANGE_GRAPH);
        assert!(!root.join("public-bearer.json").exists());

        let rotation_path = root.join("rotation.json");
        assert!(rotation_path.exists());
        let rotation: serde_json::Value = serde_json::from_slice(&std::fs::read(rotation_path)?)?;
        assert_eq!(rotation["version"], 1);
        assert!(rotation["active_kid"].as_str().is_some());
    }

    Ok(())
}

#[tokio::test]
#[serial]
async fn kid_override_and_mismatch_fallback_are_preserved() -> Result<()> {
    let _env = EnvGuard::new();
    prepare_env();

    let (issuer_key, expected_pubkey, kid_prefix) = deterministic_issuer_material();
    let matching_override = format!("{kid_prefix}-operator");
    let scenarios = [
        (Some(matching_override), true),
        (Some("unrelated-kid".to_string()), false),
        (None, false),
    ];

    for (kid_override, is_matching_override) in scenarios {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let mut config = minimal_config(root);
        config.key_config.kid_override = kid_override.clone();
        std::fs::write(&config.key_config.sk_path, issuer_key)?;

        let date_before_startup = utc_date();
        let running = start_application(config).await?;
        let date_after_startup = utc_date();
        let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
        let response = client
            .get(format!("{}/.well-known/issuer", running.base))
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let issuer: serde_json::Value = response.json().await?;

        if is_matching_override {
            assert_eq!(issuer["voprf"]["kid"], kid_override.unwrap());
        } else {
            let published_kid = issuer["voprf"]["kid"].as_str().unwrap_or_default();
            let allowed_kids = [
                format!("{}-{}", kid_prefix, date_before_startup),
                format!("{}-{}", kid_prefix, date_after_startup),
            ];
            assert!(allowed_kids.contains(&published_kid.to_string()));
        }
        assert_eq!(issuer["voprf"]["pubkey"], expected_pubkey);
        running.stop().await?;
    }

    Ok(())
}

#[tokio::test]
#[serial]
async fn application_preflight_order_has_no_key_file_side_effects() {
    let _env = EnvGuard::new();
    prepare_env();

    let cases = [
        "hsm",
        "progressive_salt",
        "proof_diversity_salt",
        "vouching_salt",
        "short_admin",
        "missing_admin",
    ];
    for case in cases {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let mut config = minimal_config(root);
        config.key_config.hsm = Some(HsmConfig {
            module_path: "/reserved/pkcs11.so".into(),
            slot: 0,
            pin: "reserved".into(),
            key_label: "reserved-key".into(),
            mode: HsmMode::Storage,
        });
        config.sybil_config.progressive_trust_salt = "default-salt-change-in-production".into();
        config.sybil_config.proof_of_diversity_fingerprint_salt =
            "default-salt-change-in-production".into();
        config.sybil_config.multi_party_vouching_salt = "default-salt-change-in-production".into();
        config.admin_api_key = Some("short".into());
        match case {
            "hsm" => {}
            "progressive_salt" => config.key_config.hsm = None,
            "proof_diversity_salt" => {
                config.key_config.hsm = None;
                config.sybil_config.progressive_trust_salt = "progressive-safe-salt".into();
            }
            "vouching_salt" => {
                config.key_config.hsm = None;
                config.sybil_config.progressive_trust_salt = "progressive-safe-salt".into();
                config.sybil_config.proof_of_diversity_fingerprint_salt =
                    "diversity-safe-salt".into();
            }
            "short_admin" => {
                config.key_config.hsm = None;
                config.sybil_config.progressive_trust_salt = "progressive-safe-salt".into();
                config.sybil_config.proof_of_diversity_fingerprint_salt =
                    "diversity-safe-salt".into();
                config.sybil_config.multi_party_vouching_salt = "vouching-safe-salt".into();
            }
            "missing_admin" => {
                config.key_config.hsm = None;
                config.sybil_config.progressive_trust_salt = "progressive-safe-salt".into();
                config.sybil_config.proof_of_diversity_fingerprint_salt =
                    "diversity-safe-salt".into();
                config.sybil_config.multi_party_vouching_salt = "vouching-safe-salt".into();
                config.admin_api_key = None;
            }
            _ => unreachable!(),
        }

        let error = build_error(config).await;
        match case {
            "hsm" => {
                assert!(error.contains("issuer startup provider integration is not implemented"))
            }
            "progressive_salt" => assert!(error.contains("SYBIL_PROGRESSIVE_TRUST_SALT")),
            "proof_diversity_salt" => {
                assert!(error.contains("SYBIL_PROOF_OF_DIVERSITY_SALT"))
            }
            "vouching_salt" => assert!(error.contains("SYBIL_MULTI_PARTY_VOUCHING_SALT")),
            "short_admin" => {
                assert!(error.contains("ADMIN_API_KEY must be at least 32 characters"))
            }
            "missing_admin" => assert!(error.contains("ADMIN_API_KEY must be set")),
            _ => unreachable!(),
        }
        assert_preflight_left_key_paths_empty(root);
    }
}

#[tokio::test]
#[serial]
async fn audit_replay_and_sybil_stages_precede_shutdown_registration() -> Result<()> {
    let _env = EnvGuard::new();
    prepare_env();

    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let blocker = root.join("audit-parent");
    std::fs::write(&blocker, b"not a directory")?;
    let proof_state = root.join("proof-diversity.json");
    std::fs::write(&proof_state, b"not-json")?;
    let vouching_state = root.join("vouching.json");
    std::fs::write(&vouching_state, b"not-json")?;

    let mut staged = minimal_config(root);
    staged.audit_log_path = blocker.join("audit.json");
    staged.sybil_config.mode = "proof_of_diversity".into();
    staged.sybil_config.proof_of_diversity_hmac_secret = Some("proof-test-secret".into());
    staged.sybil_config.proof_of_diversity_persistence_path = proof_state;
    env::set_var("SYBIL_REPLAY_STORE", "unsupported");
    let error = build_error(staged.clone()).await;
    assert!(error.contains("Failed to initialize audit log"), "{error}");

    staged.audit_log_path = root.join("audit.json");
    let error = build_error(staged.clone()).await;
    assert!(error.contains("unknown SYBIL_REPLAY_STORE"), "{error}");

    env::set_var("SYBIL_REPLAY_STORE", "memory");
    let error = build_error(staged).await;
    assert!(
        error.contains("Failed to initialize Proof of Diversity")
            || error.contains("proof-diversity.json"),
        "{error}"
    );

    let mut vouching = minimal_config(root);
    vouching.sybil_config.mode = "multi_party_vouching".into();
    vouching.sybil_config.multi_party_vouching_hmac_secret = Some("vouching-test-secret".into());
    vouching.sybil_config.multi_party_vouching_persistence_path = vouching_state;
    let error = build_error(vouching).await;
    assert!(
        error.contains("Failed to initialize Multi-Party Vouching")
            || error.contains("vouching.json"),
        "{error}"
    );

    let mut combined = minimal_config(root);
    combined.sybil_config.mode = "combined".into();
    combined.sybil_config.combined_mode = "and".into();
    combined.sybil_config.combined_mechanisms = vec![
        "invitation".into(),
        "progressive_trust".into(),
        "proof_of_diversity".into(),
        "multi_party_vouching".into(),
    ];
    combined.sybil_config.progressive_trust_hmac_secret = Some("progressive-test-secret".into());
    combined.sybil_config.proof_of_diversity_hmac_secret = Some("diversity-test-secret".into());
    combined.sybil_config.multi_party_vouching_hmac_secret = Some("vouching-test-secret".into());
    combined.sybil_config.proof_of_diversity_persistence_path =
        root.join("combined-diversity.json");
    combined.sybil_config.multi_party_vouching_persistence_path =
        root.join("combined-vouching.json");
    let application = Application::build(combined.clone()).await?;
    assert_eq!(
        application.test_shutdown_names(),
        [
            "audit",
            "invitations",
            "progressive_trust",
            "proof_of_diversity",
            "multi_party_vouching",
            "rotation_metadata",
        ]
    );
    drop(application);

    let running = start_application(combined).await?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let mut readiness = serde_json::Value::Null;
    for _ in 0..100 {
        readiness = client
            .get(format!("{}/admin/readiness", running.base))
            .header("x-admin-key", ADMIN_KEY)
            .send()
            .await?
            .json()
            .await?;
        if readiness["stores"]
            .as_object()
            .is_some_and(|stores| stores.len() == 6)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let stores = readiness["stores"]
        .as_object()
        .context("combined readiness stores missing")?;
    assert_eq!(
        stores.keys().cloned().collect::<Vec<_>>(),
        vec![
            "audit",
            "invitation",
            "progressive_trust",
            "proof_of_diversity",
            "rotation",
            "vouching",
        ]
    );
    running.stop().await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn application_binds_after_runtime_initialization() {
    let _env = EnvGuard::new();
    prepare_env();

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = blocker.local_addr().unwrap();
    let mut config = minimal_config(root);
    config.bind_addr = address;
    config.exchange_config.enabled = true;
    config.exchange_config.redis_url = Some("redis://127.0.0.1:1/".into());
    config.exchange_config.active_graph_path = root.join("missing-graph.json");

    let error = build_error(config).await;
    assert!(
        error.contains("invalid active V2 exchange graph"),
        "{error}"
    );
    assert!(!error.contains("Failed to bind TCP listener"), "{error}");
    drop(blocker);
}

#[tokio::test]
#[serial]
async fn valid_runtime_initialization_precedes_an_occupied_bind() {
    let _env = EnvGuard::new();
    prepare_env();

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = blocker.local_addr().unwrap();
    let mut config = minimal_config(root);
    config.bind_addr = address;

    let error = build_error(config).await;
    assert!(error.contains("Failed to bind TCP listener"), "{error}");
    for path in [
        root.join("issuer.key"),
        root.join("rotation.json"),
        root.join("invitation.key"),
    ] {
        assert!(
            path.exists(),
            "runtime did not initialize {}",
            path.display()
        );
    }
    drop(blocker);
}

#[tokio::test]
#[serial]
async fn malformed_trusted_proxy_config_fails_after_durable_runtime_before_bind() -> Result<()> {
    let _env = EnvGuard::new();
    prepare_env();
    let Some(redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };

    env::set_var("REQUIRE_TLS", "true");
    env::set_var("BEHIND_PROXY", "true");
    env::set_var("TRUSTED_PROXY_CIDRS", "not-a-cidr");

    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let (graph_path, receipt_path, receipt_metadata_path) = write_valid_exchange_fixture(root)?;
    let blocker = TcpListener::bind("127.0.0.1:0").await?;
    let mut config = minimal_config(root);
    config.issuer_id = "issuer:docker:v4".into();
    config.bind_addr = blocker.local_addr()?;
    config.require_tls = true;
    config.behind_proxy = true;
    config.exchange_config.enabled = true;
    config.exchange_config.active_graph_path = graph_path;
    config.exchange_config.redis_url = Some(redis.url.clone());
    config.exchange_config.active_receipt_key_path = receipt_path;
    config.exchange_config.active_receipt_metadata_path = receipt_metadata_path;

    let error = build_error(config).await;
    assert!(
        error.contains("invalid TRUSTED_PROXY_CIDRS entry"),
        "{error}"
    );
    assert!(!error.contains("Failed to bind TCP listener"), "{error}");

    for path in [
        root.join("issuer.key"),
        root.join("rotation.json"),
        root.join("invitation.key"),
    ] {
        assert!(
            path.exists(),
            "runtime did not initialize {} before TLS validation",
            path.display()
        );
    }

    let client = redis::Client::open(redis.url.as_str())?;
    let mut connection = client.get_multiplexed_async_connection().await?;
    let registry_exists: bool = redis::cmd("EXISTS")
        .arg("freebird:exchange:v2:key-registry:root")
        .query_async(&mut connection)
        .await?;
    assert!(
        registry_exists,
        "exchange key registry was not durably initialized before TLS validation"
    );
    Ok(())
}

struct RunningApplication {
    base: String,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<()>>,
}

impl Drop for RunningApplication {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RunningApplication {
    async fn stop(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let task = std::mem::replace(&mut self.task, tokio::spawn(async { Ok(()) }));
        task.await.context("application task join")??;
        Ok(())
    }
}

async fn wait_get(client: &Client, url: &str) -> Result<Response> {
    for _ in 0..100 {
        if let Ok(response) = client.get(url).send().await {
            return Ok(response);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    bail!("server did not answer GET {url}")
}

async fn start_application(config: Config) -> Result<RunningApplication> {
    let application = Application::build(config).await?;
    let address = application.test_local_addr()?;
    let (stop, signal) = oneshot::channel();
    let task = tokio::spawn(application.run_with_signal_timeout(
        async move {
            let _ = signal.await;
        },
        Duration::from_secs(2),
    ));
    let running = RunningApplication {
        base: format!("http://{address}"),
        stop: Some(stop),
        task,
    };
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = wait_get(&client, &format!("{}/healthz", running.base)).await?;
    anyhow::ensure!(response.status() == reqwest::StatusCode::OK);
    Ok(running)
}

#[tokio::test]
#[serial]
async fn minimal_application_freezes_routes_readiness_discovery_and_metrics() -> Result<()> {
    let _env = EnvGuard::new();
    prepare_env();

    let directory = tempfile::tempdir()?;
    let running = start_application(minimal_config(directory.path())).await?;
    assert!(!directory.path().join("public-bearer.der").exists());
    assert!(!directory.path().join("public-bearer.json").exists());
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;

    let response = client
        .get(format!("{}/healthz", running.base))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>().await?,
        serde_json::json!({"status": "alive"})
    );

    let response = client
        .get(format!("{}/readyz", running.base))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.json::<serde_json::Value>().await?,
        serde_json::json!({"status": "not_ready"})
    );

    let response = client
        .get(format!("{}/.well-known/issuer", running.base))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let issuer: serde_json::Value = response.json().await?;
    assert!(issuer.get("public").is_none());

    let response = client
        .get(format!("{}/.well-known/keys", running.base))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let discovery: serde_json::Value = response.json().await?;
    assert!(discovery.get("exchange").is_none());
    assert!(discovery.get("graph_issuance").is_none());

    let mut readiness = serde_json::Value::Null;
    for _ in 0..100 {
        readiness = client
            .get(format!("{}/admin/readiness", running.base))
            .header("x-admin-key", ADMIN_KEY)
            .send()
            .await?
            .json()
            .await?;
        if readiness["stores"]
            .as_object()
            .is_some_and(|stores| stores.len() == 3)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let stores = readiness["stores"]
        .as_object()
        .context("readiness stores missing")?;
    assert_eq!(
        stores.keys().cloned().collect::<Vec<_>>(),
        vec!["audit", "invitation", "rotation"]
    );
    assert!(stores.values().all(|ready| ready == true));

    let public_routes = [
        ("/healthz", reqwest::Method::GET),
        ("/readyz", reqwest::Method::GET),
        ("/.well-known/issuer", reqwest::Method::GET),
        ("/.well-known/keys", reqwest::Method::GET),
        ("/v1/oprf/issue", reqwest::Method::POST),
        ("/v1/oprf/renew", reqwest::Method::POST),
        ("/v1/oprf/issue/batch", reqwest::Method::POST),
        ("/v1/public/issue", reqwest::Method::POST),
        ("/v1/public/issue/batch", reqwest::Method::POST),
        (
            "/v2/public/exchange/status?public_operation_id=AgICAgICAgICAgICAgICAg",
            reqwest::Method::GET,
        ),
        ("/v2/public/exchange", reqwest::Method::POST),
        (
            "/v1/public/graph/issue/status?public_operation_id=AwMDAwMDAwMDAwMDAwMDAw",
            reqwest::Method::GET,
        ),
        ("/v1/public/graph/issue", reqwest::Method::POST),
        (
            "/v1/public/graph/replay-authority/probe",
            reqwest::Method::POST,
        ),
    ];
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    for (path, method) in public_routes {
        let mut request = client.request(method.clone(), format!("{}{path}", running.base));
        if method == reqwest::Method::POST {
            request = request
                .header("content-type", "application/json")
                .body("{}");
        }
        let response = request.send().await?;
        assert_ne!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "{method} {path}"
        );
        assert_ne!(
            response.status(),
            reqwest::StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path}"
        );
    }

    for (path, method) in [
        ("/healthz", reqwest::Method::GET),
        ("/v1/public/issue", reqwest::Method::POST),
        (
            "/v2/public/exchange/status?public_operation_id=AgICAgICAgICAgICAgICAg",
            reqwest::Method::GET,
        ),
        ("/v1/public/graph/issue", reqwest::Method::POST),
    ] {
        let head = client
            .head(format!("{}{path}", running.base))
            .send()
            .await?;
        if method == reqwest::Method::GET {
            assert_ne!(head.status(), reqwest::StatusCode::NOT_FOUND, "HEAD {path}");
            assert_ne!(
                head.status(),
                reqwest::StatusCode::METHOD_NOT_ALLOWED,
                "HEAD {path}"
            );
        } else {
            assert_eq!(
                head.status(),
                reqwest::StatusCode::METHOD_NOT_ALLOWED,
                "HEAD {path}"
            );
        }

        let unsupported = client
            .request(reqwest::Method::PATCH, format!("{}{path}", running.base))
            .send()
            .await?;
        assert_eq!(
            unsupported.status(),
            reqwest::StatusCode::METHOD_NOT_ALLOWED,
            "PATCH {path}"
        );
    }

    for (path, custom_header) in [
        ("/healthz", "content-type"),
        (
            "/v2/public/exchange",
            "content-type,exchange-status-capability",
        ),
        (
            "/v1/public/graph/issue",
            "content-type,graph-issuance-status-capability",
        ),
    ] {
        let response = client
            .request(reqwest::Method::OPTIONS, format!("{}{path}", running.base))
            .header("origin", "https://client.example")
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", custom_header)
            .send()
            .await?;
        assert!(response.status().is_success(), "OPTIONS {path}");
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert!(response.headers()["access-control-allow-methods"]
            .to_str()?
            .contains("POST"));
        assert!(response.headers()["access-control-allow-headers"]
            .to_str()?
            .to_ascii_lowercase()
            .contains(custom_header.split(',').next_back().unwrap()));
    }

    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let response = client
        .get(format!("{}/admin/health", running.base))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.json::<serde_json::Value>().await?["error"],
        "unauthorized"
    );

    let capability = Base64UrlUnpadded::encode_string(&[1; 32]);
    let response = client
        .get(format!(
            "{}/v2/public/exchange/status?public_operation_id={}",
            running.base,
            Base64UrlUnpadded::encode_string(&[2; 16])
        ))
        .header("exchange-status-capability", &capability)
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.json::<serde_json::Value>().await?["error"],
        "exchange_unavailable"
    );

    let graph_request = serde_json::json!({
        "version": 2,
        "public_operation_id": Base64UrlUnpadded::encode_string(&[3; 16]),
        "issuance_policy_id": "disabled-policy",
        "graph_id": "a".repeat(64),
        "keyset_id": "b".repeat(64),
        "descriptor_id": "c".repeat(64),
        "blinded_message": "AQ",
        "authorization": Base64UrlUnpadded::encode_string(&[4; 32]),
    });
    let response = client
        .post(format!("{}/v1/public/graph/issue", running.base))
        .header("graph-issuance-status-capability", &capability)
        .json(&graph_request)
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.json::<serde_json::Value>().await?["error"],
        "graph_issuance_unavailable"
    );

    assert_eq!(
        client
            .get(format!("{}/v1/public/graph/issue", running.base))
            .send()
            .await?
            .status(),
        reqwest::StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        client
            .post(format!("{}/healthz", running.base))
            .send()
            .await?
            .status(),
        reqwest::StatusCode::METHOD_NOT_ALLOWED
    );

    let response = client
        .get(format!("{}/admin/metrics", running.base))
        .header("x-admin-key", ADMIN_KEY)
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(response
        .text()
        .await?
        .contains("freebird_request_duration_seconds"));

    running.stop().await
}

async fn peer_handler(ConnectInfo(address): ConnectInfo<SocketAddr>) -> String {
    address.ip().to_string()
}

async fn panic_handler() -> &'static str {
    panic!("characterization panic secret")
}

async fn serve_test_router(app: Router) -> Result<(String, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    Ok((format!("http://{address}"), task))
}

#[tokio::test]
#[serial]
async fn public_layers_preserve_connect_info_tls_rejection_and_panic_suppression() -> Result<()> {
    let _env = EnvGuard::new();
    prepare_env();
    freebird_common::metrics::register_metrics();

    let app = super::apply_public_layers(
        Router::new()
            .route("/peer", get(peer_handler))
            .route("/panic", get(panic_handler)),
    )?;
    let (base, task) = serve_test_router(app).await?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let response = wait_get(&client, &format!("{base}/peer")).await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await?, "127.0.0.1");
    let metrics = freebird_common::metrics::encode_metrics();
    assert!(metrics.contains("path=\"/peer\""));

    let response = client.get(format!("{base}/panic")).send().await?;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = response.text().await?;
    assert!(body.contains("INTERNAL_ERROR"));
    assert!(!body.contains("characterization panic secret"));
    task.abort();

    env::set_var("REQUIRE_TLS", "true");
    env::set_var("BEHIND_PROXY", "true");
    env::set_var("TRUSTED_PROXY_CIDRS", "127.0.0.0/8");
    let app = super::apply_public_layers(Router::new().route("/peer", get(peer_handler)))?;
    let (base, task) = serve_test_router(app).await?;
    let response = wait_get(&client, &format!("{base}/peer")).await?;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(freebird_common::metrics::encode_metrics().contains(
        "freebird_request_errors_total{method=\"GET\",path=\"/peer\",status_code=\"400\"}"
    ));

    let response = client
        .get(format!("{base}/peer"))
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", "192.0.2.1")
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await?, "127.0.0.1");
    task.abort();
    Ok(())
}

#[cfg(feature = "human-gate-webauthn")]
#[tokio::test]
#[serial]
async fn missing_webauthn_secret_precedes_audit_replay_and_sybil() -> Result<()> {
    let _env = EnvGuard::new();
    prepare_env();

    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let blocker = root.join("audit-parent");
    std::fs::write(&blocker, b"not a directory")?;
    let mut config = minimal_config(root);
    config.audit_log_path = blocker.join("audit.json");
    config.sybil_config.mode = "progressive_trust".into();
    config.sybil_config.progressive_trust_levels = vec!["invalid".into()];
    config.webauthn_config = Some(WebAuthnConfig {
        rp_id: "localhost".into(),
        rp_name: "Freebird characterization".into(),
        rp_origin: "http://localhost".into(),
        redis_url: None,
        cred_ttl: Some(3600),
    });

    env::set_var("SYBIL_REPLAY_STORE", "unsupported");
    let error = build_error(config.clone()).await;
    assert!(
        error.contains("WEBAUTHN_PROOF_SECRET must be set"),
        "{error}"
    );

    env::set_var("WEBAUTHN_PROOF_SECRET", "startup-webauthn-proof-secret");
    let error = build_error(config.clone()).await;
    assert!(error.contains("Failed to initialize audit log"), "{error}");

    let mut replay = config.clone();
    replay.audit_log_path = root.join("audit.json");
    let error = build_error(replay.clone()).await;
    assert!(error.contains("unknown SYBIL_REPLAY_STORE"), "{error}");

    env::set_var("SYBIL_REPLAY_STORE", "memory");
    let error = build_error(replay).await;
    assert!(
        error.contains("Invalid progressive trust level configuration"),
        "{error}"
    );
    Ok(())
}

#[cfg(feature = "human-gate-webauthn")]
#[tokio::test]
#[serial]
async fn webauthn_startup_branch_initializes_before_routes_and_shutdown() -> Result<()> {
    let _env = EnvGuard::new();
    prepare_env();
    env::set_var("WEBAUTHN_PROOF_SECRET", "startup-webauthn-proof-secret");

    let directory = tempfile::tempdir()?;
    let mut config = minimal_config(directory.path());
    config.webauthn_config = Some(WebAuthnConfig {
        rp_id: "localhost".into(),
        rp_name: "Freebird characterization".into(),
        rp_origin: "http://localhost".into(),
        redis_url: None,
        cred_ttl: Some(3600),
    });
    config.sybil_config.mode = "webauthn".into();
    config.sybil_config.webauthn_max_proof_age = Some(300);

    let running = start_application(config).await?;
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = client
        .get(format!("{}/webauthn", running.base))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(response.text().await?.contains("WebAuthn"));

    let response = client
        .get(format!("{}/webauthn/", running.base))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::PERMANENT_REDIRECT);
    assert_eq!(response.headers()["location"], "/webauthn");

    running.stop().await
}
