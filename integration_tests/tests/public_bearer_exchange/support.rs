// SPDX-License-Identifier: Apache-2.0 OR MIT

pub(super) use anyhow::{bail, Context, Result};
use axum::{extract::Json as AxumJson, routing::post, Router};
pub(super) use base64ct::{Base64UrlUnpadded, Encoding};
use blind_rsa_signatures::{
    BlindSignature, BlindingResult, DefaultRng, KeyPairSha384PSSDeterministic,
};
pub(super) use freebird_common::api::{
    validate_exchange_discovery_v2, ExchangeDiscoveryV2, ExchangeReceiptKeyInfo, KeyDiscoveryResp,
};
pub(super) use freebird_common::exchange_api::EXCHANGE_PROFILE_V2;
pub(super) use freebird_common::graph_issuance_api::{
    GraphIssuanceRequestV2, GraphIssuanceResultV2, GRAPH_ISSUANCE_VERSION_V2,
};
pub(super) use freebird_common::spend_key::v5_spend_key;
use freebird_common::{
    api::ExchangeGraphDiscoveryV2,
    exchange_api::{
        ExchangeOutput, ExchangeReceiptV2, ExchangeRequestV2, ExchangeResultV2, ExchangeSlot,
        ExchangeSource, EXCHANGE_VERSION_V2,
    },
    graph_issuance_api::{
        build_hmac_authorization_v2, ReplayAuthorityProbeV1, ReplayAuthorityProofV1,
        REPLAY_AUTHORITY_VERSION_V1,
    },
    spend_key::v4_spend_key,
};
use freebird_crypto::{
    build_private_token_input, build_public_bearer_message_from_parts, build_public_bearer_pass,
    PublicBearerPass, RedemptionToken, Server, VOPRF_CONTEXT_V4,
};
pub(super) use freebird_crypto::{
    build_redemption_token, build_scope_digest, nullifier_key_v4, nullifier_key_v5,
    parse_public_bearer_pass, parse_redemption_token, token_key_id_from_spki,
};
use freebird_issuer::{
    config::{
        Config, ExchangeConfig, GraphIssuanceAuthorizationConfig, GraphIssuanceConfig,
        GraphIssuanceV4VerificationKey, KeyConfig, PublicKeyConfig, SybilConfig,
    },
    exchange::profiles::{
        ExchangeAdmissionStateV2, ExchangeDescriptorV2, ExchangeKeyV2, ExchangeKeysetV2,
        ExchangeProfileV2, ExchangeTransitionSlotV2, ExchangeTransitionV2,
    },
};
pub(super) use freebird_issuer::{
    exchange::profiles::ExchangeProfileValidationModeV2,
    exchange::{load_or_generate_receipt_key, ReceiptKey},
    graph_issuance::{
        DevelopmentMockAuthorizer, GraphIssuanceEngine, GraphIssuancePolicyDocument,
        ProcessDecision, REPLAY_AUTHORITY_ID_KEY,
    },
    startup::{exchange_discovery_v2, Application},
};
pub(super) use freebird_verifier::{
    discovery::trusted_public_keys,
    replay_authority::{ReplayAuthorityConfig, ReplayAuthorityHealth},
    store::{RedisStore, SpendStore},
};
use freebird_verifier::{routes::admin::IssuerInfo, verify::verify_v4_token};
use serde::Deserialize;
pub(super) use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use std::{
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Instant,
};

pub(super) const ISSUER_ID: &str = "issuer:test:exchange-v2-integration";
const AUDIENCE: &str = "exchange-integration";
pub(super) const V4_ADMISSION_ISSUER: &str = "issuer:test:v4-admission";
pub(super) const V4_ADMISSION_KID: &str = "kid-v4-admission";
pub(super) const V4_ADMISSION_VERIFIER: &str = "verifier:test:graph-issuance";
pub(super) const V4_ADMISSION_AUDIENCE: &str = "graph-issuance";
pub(super) const V4_ADMISSION_SECRET: [u8; 32] = [0x45; 32];
pub(super) const HMAC_ISSUANCE_SECRET: [u8; 32] = [0x56; 32];
pub(super) const VERIFIER_V4_SECRET: [u8; 32] = [0x67; 32];
const REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY: &str =
    "freebird:v4-replay-authority:v1:scope-tombstones";

pub(super) struct RedisHarness {
    child: Option<Child>,
    pub(super) url: String,
    port: u16,
    dir: tempfile::TempDir,
}

impl RedisHarness {
    pub(super) fn start_if_available() -> Result<Option<Self>> {
        if !Command::new("redis-server")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            eprintln!("skipping V2 exchange HTTP integration: redis-server is unavailable");
            return Ok(None);
        }
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let mut harness = Self {
            child: None,
            url: format!("redis://127.0.0.1:{port}/"),
            port,
            dir: tempfile::tempdir()?,
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
                    self.dir.path().to_str().context("non-UTF8 Redis path")?,
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
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return Ok(());
            }
            if self
                .child
                .as_mut()
                .is_some_and(|child| child.try_wait().ok().flatten().is_some())
            {
                anyhow::bail!("redis-server exited during startup");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        anyhow::bail!("redis-server did not become reachable")
    }

    pub(super) fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    pub(super) fn restart(&mut self) -> Result<()> {
        self.stop();
        self.spawn()
    }
}

impl Drop for RedisHarness {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(super) struct GraphFixture {
    pub(super) _dir: tempfile::TempDir,
    pub(super) keys: Vec<KeyPairSha384PSSDeterministic>,
    pub(super) graph: ExchangeProfileV2,
    pub(super) retained: ExchangeProfileV2,
    graph_path: PathBuf,
    retained_path: PathBuf,
    pub(super) receipt_path: PathBuf,
    receipt_metadata_path: PathBuf,
    acknowledgement_path: PathBuf,
    pub(super) graph_issuance_policy_path: PathBuf,
}

impl GraphFixture {
    pub(super) fn new(budget_limit: u64) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut rng = DefaultRng;
        let keys = (0..4)
            .map(|_| KeyPairSha384PSSDeterministic::generate(&mut rng, 2048))
            .collect::<Result<Vec<_>, _>>()?;
        let mut keysets = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            let path = dir.path().join(format!("exchange-{index}.der"));
            write_secret(&path, &key.sk.to_der()?)?;
            let spki = key.pk.to_spki()?;
            let mut descriptor = ExchangeDescriptorV2 {
                id: String::new(),
                profile_id: EXCHANGE_PROFILE_V2.into(),
                issuer_id: ISSUER_ID.into(),
                kid: freebird_crypto::encode_token_key_id_hex(&token_key_id_from_spki(&spki)),
                audience: Some(AUDIENCE.into()),
                spki_b64: Base64UrlUnpadded::encode_string(&spki),
                suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
                valid_from: now - 60,
                valid_until: now + 86_400,
            };
            descriptor.id = descriptor.canonical_id()?;
            let mut keyset = ExchangeKeysetV2 {
                id: String::new(),
                keys: vec![ExchangeKeyV2 {
                    descriptor,
                    private_key_path: Some(path.display().to_string()),
                }],
            };
            keyset.id = keyset.canonical_id();
            keysets.push(keyset);
        }
        let transitions = vec![
            transition(&keysets[0], &keysets[1], "budget-a-b", budget_limit),
            transition(&keysets[1], &keysets[0], "budget-b-a", budget_limit),
            transition(&keysets[0], &keysets[2], "budget-a-c", budget_limit),
            transition(&keysets[3], &keysets[2], "budget-direct-c", budget_limit),
        ];
        let mut graph = ExchangeProfileV2 {
            profile_id: EXCHANGE_PROFILE_V2.into(),
            graph_id: String::new(),
            keysets,
            transitions,
        };
        graph.graph_id = graph.canonical_graph_id();
        graph.validate(ExchangeProfileValidationModeV2::Active, ISSUER_ID, None)?;

        let mut retained = graph.clone();
        for transition in &mut retained.transitions {
            transition.budget_id = format!("retained-{}", transition.budget_id);
            transition.admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
            transition.id = transition.canonical_id();
        }
        retained.graph_id = retained.canonical_graph_id();
        retained.validate(ExchangeProfileValidationModeV2::Retained, ISSUER_ID, None)?;

        let graph_path = dir.path().join("active-graph.json");
        let retained_path = dir.path().join("retained-graph.json");
        std::fs::write(&graph_path, serde_json::to_vec_pretty(&graph)?)?;
        std::fs::write(&retained_path, serde_json::to_vec_pretty(&retained)?)?;

        let receipt_path = dir.path().join("receipt.key");
        let receipt_key = load_or_generate_receipt_key(&receipt_path)?;
        let receipt_metadata = ExchangeReceiptKeyInfo {
            key_id: receipt_key.key_id(),
            algorithm: "Ed25519".into(),
            purpose: "exchange_receipt_active".into(),
            public_key_b64: Base64UrlUnpadded::encode_string(
                receipt_key.verifying_key().as_bytes(),
            ),
            valid_from: u64::try_from(now - 60)?,
            valid_until: u64::try_from(now + 86_400)?,
        };
        let receipt_metadata_path = dir.path().join("receipt.json");
        std::fs::write(
            &receipt_metadata_path,
            serde_json::to_vec_pretty(&receipt_metadata)?,
        )?;

        let acknowledgement_path = dir.path().join("publication-ack.json");
        std::fs::write(
            &acknowledgement_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": "freebird/exchange-disabled-publication-ack/v1",
                "issuer_id": ISSUER_ID,
                "graph_id": graph.graph_id,
                "disabled_transition_ids": graph.transitions.iter().map(|edge| &edge.id).collect::<Vec<_>>(),
                "acknowledged_admission_state": "disabled",
                "operator": "integration-test",
                "acknowledged_at_unix": u64::try_from(now)?,
            }))?,
        )?;

        let graph_issuance_policy_path = dir.path().join("graph-issuance-policy.json");
        std::fs::write(
            &graph_issuance_policy_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": "freebird/graph-blind-issuance-policy/v2",
                "policies": [{
                    "issuance_policy_id": "integration-bootstrap-v1",
                    "graph_id": graph.graph_id,
                    "keyset_id": graph.keysets[0].id,
                    "descriptor_id": graph.keysets[0].keys[0].descriptor.id,
                    "budget_id": "integration-graph-issuance-budget",
                    "budget_limit": 3,
                    "quantity": 1,
                    "admission_state": "accepting_new",
                    "authorization_scheme": "development_mock"
                }]
            }))?,
        )?;

        Ok(Self {
            _dir: dir,
            keys,
            graph,
            retained,
            graph_path,
            retained_path,
            receipt_path,
            receipt_metadata_path,
            acknowledgement_path,
            graph_issuance_policy_path,
        })
    }

    pub(super) fn config(&self, redis_url: String) -> Config {
        let root = self._dir.path();
        Config {
            issuer_id: ISSUER_ID.into(),
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
                enabled: true,
                sk_path: root.join("exchange-3.der"),
                metadata_path: root.join("direct-v5.json"),
                validity_secs: 3600,
                audience: Some(AUDIENCE.into()),
                modulus_bits: 2048,
            },
            exchange_config: ExchangeConfig {
                enabled: true,
                active_graph_path: self.graph_path.clone(),
                retained_graph_paths: vec![self.retained_path.clone()],
                public_history_path: None,
                disabled_publication_ack_paths: vec![self.acknowledgement_path.clone()],
                active_receipt_key_path: self.receipt_path.clone(),
                active_receipt_metadata_path: self.receipt_metadata_path.clone(),
                retained_receipt_key_paths: vec![],
                retained_receipt_metadata_paths: vec![],
                redis_url: Some(redis_url),
                receipt_lifetime_secs: 300,
                request_body_limit: 64 * 1024,
                request_timeout_secs: 5,
                graph_issuance: GraphIssuanceConfig {
                    enabled: true,
                    policy_path: self.graph_issuance_policy_path.clone(),
                    authorization: GraphIssuanceAuthorizationConfig::DevelopmentMock,
                },
            },
            sybil_config: test_sybil_config(root),
            webauthn_config: None,
            admin_api_key: Some("integration-admin-key-at-least-32-characters".into()),
            epoch_duration_sec: 86_400,
            epoch_retention: 2,
            allow_unsafe_v4_rotation: false,
            audit_log_path: root.join("audit.json"),
            unsafe_development_mode: true,
        }
    }

    pub(super) fn write_recovery_only_graph(&mut self) -> Result<()> {
        for transition in &mut self.graph.transitions {
            transition.admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
        }
        // The committed graph issuance result no longer needs the original signer snapshot.
        // Retiring this now-recovery-only key proves recovery is result-based, not re-signing.
        self.graph.keysets[0].keys[0].private_key_path = None;
        self.retained.keysets[0].keys[0].private_key_path = None;
        std::fs::write(&self.graph_path, serde_json::to_vec_pretty(&self.graph)?)?;
        std::fs::write(
            &self.retained_path,
            serde_json::to_vec_pretty(&self.retained)?,
        )?;
        let mut policy: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&self.graph_issuance_policy_path)?)?;
        policy["policies"][0]["admission_state"] = serde_json::json!("recovery_only");
        std::fs::write(
            &self.graph_issuance_policy_path,
            serde_json::to_vec_pretty(&policy)?,
        )?;
        Ok(())
    }

    pub(super) fn write_v4_local_policies(&self) -> Result<()> {
        let policy = |id: &str, budget: &str| {
            serde_json::json!({
                "issuance_policy_id": id,
                "graph_id": self.graph.graph_id,
                "keyset_id": self.graph.keysets[0].id,
                "descriptor_id": self.graph.keysets[0].keys[0].descriptor.id,
                "budget_id": budget,
                "budget_limit": 20,
                "quantity": 1,
                "admission_state": "accepting_new",
                "authorization_scheme": "v4_local",
                "v4_local": {
                    "verifier_id": V4_ADMISSION_VERIFIER,
                    "audience": V4_ADMISSION_AUDIENCE,
                    "trusted_issuers": [{
                        "issuer_id": V4_ADMISSION_ISSUER,
                        "key_ids": [V4_ADMISSION_KID]
                    }]
                }
            })
        };
        std::fs::write(
            &self.graph_issuance_policy_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": "freebird/graph-blind-issuance-policy/v2",
                "policies": [
                    policy("v4-bootstrap-one", "v4-bootstrap-budget-one"),
                    policy("v4-bootstrap-two", "v4-bootstrap-budget-two")
                ]
            }))?,
        )?;
        Ok(())
    }

    pub(super) fn config_v4_local(&self, redis_url: String) -> Config {
        let mut config = self.config(redis_url.clone());
        config.exchange_config.graph_issuance.authorization =
            GraphIssuanceAuthorizationConfig::V4Local {
                keys: vec![GraphIssuanceV4VerificationKey {
                    issuer_id: V4_ADMISSION_ISSUER.into(),
                    kid: V4_ADMISSION_KID.into(),
                    secret_key: V4_ADMISSION_SECRET,
                }],
            };
        config
    }

    pub(super) fn config_exchange_only(&self, redis_url: String) -> Config {
        let mut config = self.config(redis_url);
        config.exchange_config.graph_issuance.enabled = false;
        config.exchange_config.graph_issuance.authorization =
            GraphIssuanceAuthorizationConfig::Disabled;
        config
    }

    pub(super) fn config_disabled(&self) -> Config {
        let mut config = self.config("redis://127.0.0.1:1/".into());
        config.exchange_config.enabled = false;
        config.exchange_config.redis_url = None;
        config.exchange_config.graph_issuance.enabled = false;
        config.exchange_config.graph_issuance.authorization =
            GraphIssuanceAuthorizationConfig::Disabled;
        config
    }

    pub(super) fn write_hmac_policies(&self) -> Result<()> {
        let policy = |id: &str, budget: &str| {
            serde_json::json!({
                "issuance_policy_id": id,
                "graph_id": self.graph.graph_id,
                "keyset_id": self.graph.keysets[0].id,
                "descriptor_id": self.graph.keysets[0].keys[0].descriptor.id,
                "budget_id": budget,
                "budget_limit": 20,
                "quantity": 1,
                "admission_state": "accepting_new",
                "authorization_scheme": "hmac_sha256"
            })
        };
        std::fs::write(
            &self.graph_issuance_policy_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": "freebird/graph-blind-issuance-policy/v2",
                "policies": [
                    policy("hmac-policy-a", "hmac-budget-a"),
                    policy("hmac-policy-b", "hmac-budget-b")
                ]
            }))?,
        )?;
        Ok(())
    }

    pub(super) fn config_hmac(&self, redis_url: String) -> Config {
        let mut config = self.config(redis_url);
        config.exchange_config.graph_issuance.authorization =
            GraphIssuanceAuthorizationConfig::HmacSha256(HMAC_ISSUANCE_SECRET.to_vec());
        config
    }

    pub(super) fn write_disabled_v4_policies(&self) -> Result<()> {
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&self.graph_issuance_policy_path)?)?;
        for policy in document["policies"]
            .as_array_mut()
            .context("policy document is not an array")?
        {
            policy["admission_state"] = serde_json::json!("disabled");
        }
        std::fs::write(
            &self.graph_issuance_policy_path,
            serde_json::to_vec_pretty(&document)?,
        )?;
        Ok(())
    }

    pub(super) fn write_removed_policies(&self) -> Result<()> {
        std::fs::write(
            &self.graph_issuance_policy_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": "freebird/graph-blind-issuance-policy/v2",
                "policies": []
            }))?,
        )?;
        Ok(())
    }
}

pub(super) fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn transition(
    source: &ExchangeKeysetV2,
    target: &ExchangeKeysetV2,
    budget_id: &str,
    budget_limit: u64,
) -> ExchangeTransitionV2 {
    let mut transition = ExchangeTransitionV2 {
        id: String::new(),
        source_keyset_id: source.id.clone(),
        target_keyset_id: target.id.clone(),
        sources: vec![ExchangeTransitionSlotV2 {
            descriptor_id: source.keys[0].descriptor.id.clone(),
            slot_id: "source".into(),
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
        budget_limit,
        admission_state: ExchangeAdmissionStateV2::AcceptingNew,
    };
    transition.id = transition.canonical_id();
    transition
}

fn test_sybil_config(root: &Path) -> SybilConfig {
    SybilConfig {
        mode: "none".into(),
        pow_difficulty: 20,
        rate_limit_secs: 3600,
        invite_per_user: 5,
        invite_cooldown_secs: 3600,
        invite_expires_secs: 86_400,
        invite_new_user_wait_secs: 86_400,
        invite_persistence_path: root.join("invites.json"),
        invite_autosave_interval_secs: 300,
        invite_signing_key_path: root.join("invite.key"),
        bootstrap_users: None,
        webauthn_max_proof_age: None,
        progressive_trust_levels: vec!["0:1:1d".into()],
        progressive_trust_persistence_path: root.join("progressive.json"),
        progressive_trust_autosave_interval: 300,
        progressive_trust_hmac_secret: None,
        progressive_trust_hmac_secret_path: root.join("progressive.key"),
        progressive_trust_salt: "integration-progressive-salt".into(),
        progressive_trust_allow_insecure: false,
        proof_of_diversity_min_score: 40,
        proof_of_diversity_persistence_path: root.join("diversity.json"),
        proof_of_diversity_autosave_interval: 300,
        proof_of_diversity_hmac_secret: None,
        proof_of_diversity_hmac_secret_path: root.join("diversity.key"),
        proof_of_diversity_fingerprint_salt: "integration-diversity-salt".into(),
        proof_of_diversity_allow_insecure: false,
        multi_party_vouching_required_vouchers: 3,
        multi_party_vouching_cooldown_secs: 3600,
        multi_party_vouching_expires_secs: 86_400,
        multi_party_vouching_new_user_wait_secs: 86_400,
        multi_party_vouching_persistence_path: root.join("vouching.json"),
        multi_party_vouching_autosave_interval: 300,
        multi_party_vouching_hmac_secret: None,
        multi_party_vouching_hmac_secret_path: root.join("vouching.key"),
        multi_party_vouching_salt: "integration-vouching-salt".into(),
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
    }
}

pub(super) struct TestServer {
    pub(super) base: String,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl TestServer {
    pub(super) async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

pub(super) async fn start_server(mut config: Config) -> Result<TestServer> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    config.bind_addr = address;
    let application = Application::build(config).await?;
    let task = tokio::spawn(application.run());
    Ok(TestServer {
        base: format!("http://{address}"),
        task,
    })
}

pub(super) async fn wait_for_issuer_status(
    server: &TestServer,
    path: &str,
    expected: reqwest::StatusCode,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(300))
        .build()?;
    for _ in 0..250 {
        if let Ok(response) = client.get(format!("{}{path}", server.base)).send().await {
            if response.status() == expected {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("issuer did not return {expected} from {path}")
}

pub(super) struct VerifierProcess {
    pub(super) base: String,
    child: Option<Child>,
}

impl VerifierProcess {
    pub(super) fn stop(mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for VerifierProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn verifier_binary() -> Result<PathBuf> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("integration test workspace path missing")?;
    let mut target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace.join("target"));
    if target.is_relative() {
        target = workspace.join(target);
    }
    let profile = option_env!("PROFILE").unwrap_or("debug");
    let binary = target.join(profile).join("freebird-verifier");
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace)
        .args([
            "build",
            "-p",
            "freebird-verifier",
            "--bin",
            "freebird-verifier",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if profile == "release" {
        command.arg("--release");
    }
    let status = command.status()?;
    anyhow::ensure!(status.success(), "failed to build freebird-verifier binary");
    anyhow::ensure!(binary.exists(), "freebird-verifier binary was not built");
    Ok(binary)
}

pub(super) async fn start_verifier(
    redis_url: &str,
    issuer_base: &str,
    verifier_secret: [u8; 32],
) -> Result<VerifierProcess> {
    let binary = verifier_binary()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    let mut child = Command::new(binary)
        .env("BIND_ADDR", address.to_string())
        .env("REDIS_URL", redis_url)
        .env("ISSUER_URL", format!("{issuer_base}/.well-known/keys"))
        .env("VERIFIER_GRAPH_ISSUANCE_ISSUER_URL", issuer_base)
        .env("VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL", "1s")
        .env("VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS", "2s")
        .env("VERIFIER_ACCEPTED_TOKEN_VERSIONS", "v4")
        .env("VERIFIER_ID", V4_ADMISSION_VERIFIER)
        .env("VERIFIER_AUDIENCE", V4_ADMISSION_AUDIENCE)
        .env(
            "VERIFIER_SK_B64",
            Base64UrlUnpadded::encode_string(&verifier_secret),
        )
        .env("REFRESH_INTERVAL_MIN", "1")
        .env("REQUIRE_TLS", "false")
        .env(
            "ADMIN_API_KEY",
            "integration-verifier-admin-key-at-least-32-chars",
        )
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let base = format!("http://{address}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(300))
        .build()?;
    for _ in 0..250 {
        if let Ok(response) = client.get(format!("{base}/health")).send().await {
            if response.status() == reqwest::StatusCode::OK {
                return Ok(VerifierProcess {
                    base,
                    child: Some(child),
                });
            }
        }
        if child.try_wait()?.is_some() {
            anyhow::bail!("freebird-verifier exited during startup");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    anyhow::bail!("freebird-verifier did not become reachable")
}

pub(super) async fn wait_for_verifier_status(
    verifier: &VerifierProcess,
    path: &str,
    expected: reqwest::StatusCode,
) -> Result<()> {
    let client = reqwest::Client::new();
    for _ in 0..250 {
        if let Ok(response) = client.get(format!("{}{path}", verifier.base)).send().await {
            if response.status() == expected {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("verifier did not return {expected} from {path}")
}

pub(super) fn mint_artifact(
    key: &KeyPairSha384PSSDeterministic,
    nonce: [u8; 32],
) -> Result<String> {
    let spki = key.pk.to_spki()?;
    let token_key_id = token_key_id_from_spki(&spki);
    let message = build_public_bearer_message_from_parts(&nonce, &token_key_id, ISSUER_ID)
        .map_err(|error| anyhow::anyhow!("build source message: {error:?}"))?;
    let mut rng = DefaultRng;
    let blinding = key.pk.blind(&mut rng, message)?;
    let blind_signature = key.sk.blind_sign(&blinding.blind_message)?;
    let signature = key.pk.finalize(&blind_signature, &blinding, message)?.0;
    let pass = PublicBearerPass {
        nonce,
        token_key_id,
        issuer_id: ISSUER_ID.into(),
        signature,
    };
    Ok(Base64UrlUnpadded::encode_string(
        &build_public_bearer_pass(&pass)
            .map_err(|error| anyhow::anyhow!("build source artifact: {error:?}"))?,
    ))
}

pub(super) struct PendingOutput {
    nonce: [u8; 32],
    token_key_id: [u8; 32],
    message: Vec<u8>,
    blinding: BlindingResult,
}

pub(super) fn request_from_discovery(
    graph: &ExchangeGraphDiscoveryV2,
    transition_index: usize,
    artifact: String,
    target_key: &KeyPairSha384PSSDeterministic,
    operation: [u8; 16],
    nonce: [u8; 32],
) -> Result<(ExchangeRequestV2, PendingOutput)> {
    let transition = &graph.transitions[transition_index];
    let source = &transition.source_slots[0];
    let output = &transition.output_slots[0];
    let target_spki = target_key.pk.to_spki()?;
    let token_key_id = token_key_id_from_spki(&target_spki);
    let message = build_public_bearer_message_from_parts(&nonce, &token_key_id, ISSUER_ID)
        .map_err(|error| anyhow::anyhow!("build output message: {error:?}"))?
        .to_vec();
    let mut rng = DefaultRng;
    let blinding = target_key.pk.blind(&mut rng, &message)?;
    let request = ExchangeRequestV2 {
        version: EXCHANGE_VERSION_V2,
        public_operation_id: Base64UrlUnpadded::encode_string(&operation),
        graph_id: graph.graph_id.clone(),
        transition_id: transition.transition_id.clone(),
        source_keyset_id: transition.source_keyset_id.clone(),
        target_keyset_id: transition.target_keyset_id.clone(),
        sources: vec![ExchangeSource {
            slot: ExchangeSlot {
                descriptor_id: source.descriptor_id.clone(),
                keyset_id: transition.source_keyset_id.clone(),
                slot_id: source.slot_id.clone(),
                quantity: source.quantity,
            },
            artifact,
        }],
        outputs: vec![ExchangeOutput {
            slot: ExchangeSlot {
                descriptor_id: output.descriptor_id.clone(),
                keyset_id: transition.target_keyset_id.clone(),
                slot_id: output.slot_id.clone(),
                quantity: output.quantity,
            },
            blinded_value: Base64UrlUnpadded::encode_string(&blinding.blind_message.0),
        }],
    };
    request.validate().map_err(|error| anyhow::anyhow!(error))?;
    Ok((
        request,
        PendingOutput {
            nonce,
            token_key_id,
            message,
            blinding,
        },
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExchangeResponseV2 {
    pub(super) result: ExchangeResultV2,
    pub(super) receipt: ExchangeReceiptV2,
}

pub(super) fn finalize_output(
    response: &ExchangeResponseV2,
    pending: PendingOutput,
    target_key: &KeyPairSha384PSSDeterministic,
) -> Result<String> {
    let signature = BlindSignature(Base64UrlUnpadded::decode_vec(
        &response.result.outputs[0].blind_signature,
    )?);
    let signature = target_key
        .pk
        .finalize(&signature, &pending.blinding, &pending.message)?
        .0;
    let pass = PublicBearerPass {
        nonce: pending.nonce,
        token_key_id: pending.token_key_id,
        issuer_id: ISSUER_ID.into(),
        signature,
    };
    Ok(Base64UrlUnpadded::encode_string(
        &build_public_bearer_pass(&pass)
            .map_err(|error| anyhow::anyhow!("build exchange output: {error:?}"))?,
    ))
}

pub(super) async fn post_exchange(
    client: &reqwest::Client,
    base: &str,
    request: &ExchangeRequestV2,
    capability: &[u8; 32],
) -> Result<reqwest::Response> {
    let body = serde_json::to_vec(request)?;
    Ok(client
        .post(format!("{base}/v2/public/exchange"))
        .header(
            "exchange-status-capability",
            Base64UrlUnpadded::encode_string(capability),
        )
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await?)
}

pub(super) fn graph_issuance_request(
    graph: &ExchangeGraphDiscoveryV2,
    key: &KeyPairSha384PSSDeterministic,
    operation: [u8; 16],
    nonce: [u8; 32],
    authorization: [u8; 32],
) -> Result<(GraphIssuanceRequestV2, PendingOutput)> {
    graph_issuance_request_with_authorization(
        graph,
        key,
        operation,
        nonce,
        "integration-bootstrap-v1",
        Base64UrlUnpadded::encode_string(&authorization),
    )
}

pub(super) fn graph_issuance_request_with_authorization(
    graph: &ExchangeGraphDiscoveryV2,
    key: &KeyPairSha384PSSDeterministic,
    operation: [u8; 16],
    nonce: [u8; 32],
    policy_id: &str,
    authorization: String,
) -> Result<(GraphIssuanceRequestV2, PendingOutput)> {
    let keyset = &graph.keysets[0];
    let descriptor = graph
        .descriptors
        .iter()
        .find(|descriptor| descriptor.descriptor_id == keyset.descriptor_ids[0])
        .context("graph issuance descriptor missing")?;
    let token_key_id = token_key_id_from_spki(&key.pk.to_spki()?);
    let message = build_public_bearer_message_from_parts(&nonce, &token_key_id, ISSUER_ID)
        .map_err(|error| anyhow::anyhow!("build graph issuance message: {error:?}"))?
        .to_vec();
    let mut rng = DefaultRng;
    let blinding = key.pk.blind(&mut rng, &message)?;
    Ok((
        GraphIssuanceRequestV2 {
            version: freebird_common::graph_issuance_api::GRAPH_ISSUANCE_VERSION_V2,
            public_operation_id: Base64UrlUnpadded::encode_string(&operation),
            issuance_policy_id: policy_id.into(),
            graph_id: graph.graph_id.clone(),
            keyset_id: keyset.keyset_id.clone(),
            descriptor_id: descriptor.descriptor_id.clone(),
            blinded_message: Base64UrlUnpadded::encode_string(&blinding.blind_message.0),
            authorization,
        },
        PendingOutput {
            nonce,
            token_key_id,
            message,
            blinding,
        },
    ))
}

pub(super) fn hmac_graph_issuance_request(
    graph: &ExchangeGraphDiscoveryV2,
    key: &KeyPairSha384PSSDeterministic,
    operation: [u8; 16],
    nonce: [u8; 32],
    policy_id: &str,
) -> Result<(GraphIssuanceRequestV2, PendingOutput)> {
    let (mut request, pending) = graph_issuance_request_with_authorization(
        graph,
        key,
        operation,
        nonce,
        policy_id,
        Base64UrlUnpadded::encode_string(&[0; 32]),
    )?;
    let binding = request.authorization_binding_digest()?;
    request.authorization =
        build_hmac_authorization_v2(&HMAC_ISSUANCE_SECRET, &nonce, policy_id, &binding)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok((request, pending))
}

pub(super) fn retimed_graph_fixture(
    fixture: &GraphFixture,
    valid_from: i64,
    valid_until: i64,
) -> Result<(ExchangeProfileV2, GraphIssuancePolicyDocument)> {
    let mut graph = fixture.graph.clone();
    let old_graph_id = graph.graph_id.clone();
    let old_keyset_id = graph.keysets[0].id.clone();
    let old_descriptor_id = graph.keysets[0].keys[0].descriptor.id.clone();
    let descriptor = &mut graph.keysets[0].keys[0].descriptor;
    descriptor.valid_from = valid_from;
    descriptor.valid_until = valid_until;
    descriptor.id = descriptor.canonical_id()?;
    let new_descriptor_id = descriptor.id.clone();
    graph.keysets[0].id = graph.keysets[0].canonical_id();
    let new_keyset_id = graph.keysets[0].id.clone();
    for transition in &mut graph.transitions {
        if transition.source_keyset_id == old_keyset_id {
            transition.source_keyset_id = new_keyset_id.clone();
        }
        if transition.target_keyset_id == old_keyset_id {
            transition.target_keyset_id = new_keyset_id.clone();
        }
        for slot in transition
            .sources
            .iter_mut()
            .chain(transition.outputs.iter_mut())
        {
            if slot.descriptor_id == old_descriptor_id {
                slot.descriptor_id = new_descriptor_id.clone();
            }
        }
        transition.id = transition.canonical_id();
    }
    graph.graph_id = graph.canonical_graph_id();

    let mut document: GraphIssuancePolicyDocument =
        serde_json::from_slice(&std::fs::read(&fixture.graph_issuance_policy_path)?)?;
    for policy in &mut document.policies {
        if policy.graph_id == old_graph_id {
            policy.graph_id = graph.graph_id.clone();
        }
        if policy.keyset_id == old_keyset_id {
            policy.keyset_id = new_keyset_id.clone();
        }
        if policy.descriptor_id == old_descriptor_id {
            policy.descriptor_id = new_descriptor_id.clone();
        }
    }
    graph.validate(ExchangeProfileValidationModeV2::Active, ISSUER_ID, None)?;
    Ok((graph, document))
}

pub(super) fn engine_request(
    graph: &ExchangeProfileV2,
    document: &GraphIssuancePolicyDocument,
    key: &KeyPairSha384PSSDeterministic,
    operation: [u8; 16],
) -> Result<GraphIssuanceRequestV2> {
    let policy = document
        .policies
        .first()
        .context("graph issuance policy missing")?;
    let token_key_id = token_key_id_from_spki(&key.pk.to_spki()?);
    let message = build_public_bearer_message_from_parts(&[0x90; 32], &token_key_id, ISSUER_ID)
        .map_err(|error| anyhow::anyhow!("build validity-window message: {error:?}"))?;
    let mut rng = DefaultRng;
    let blinding = key.pk.blind(&mut rng, message)?;
    Ok(GraphIssuanceRequestV2 {
        version: GRAPH_ISSUANCE_VERSION_V2,
        public_operation_id: Base64UrlUnpadded::encode_string(&operation),
        issuance_policy_id: policy.issuance_policy_id.clone(),
        graph_id: graph.graph_id.clone(),
        keyset_id: policy.keyset_id.clone(),
        descriptor_id: policy.descriptor_id.clone(),
        blinded_message: Base64UrlUnpadded::encode_string(&blinding.blind_message.0),
        authorization: Base64UrlUnpadded::encode_string(&[0x92; 32]),
    })
}

pub(super) async fn clone_replay_authority_state(
    source_url: &str,
    destination_url: &str,
) -> Result<()> {
    let mut source = ::redis::Client::open(source_url)?
        .get_async_connection()
        .await?;
    let authority: Vec<u8> = ::redis::cmd("GET")
        .arg(REPLAY_AUTHORITY_ID_KEY)
        .query_async(&mut source)
        .await?;
    let tombstones: HashMap<Vec<u8>, Vec<u8>> = ::redis::cmd("HGETALL")
        .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
        .query_async(&mut source)
        .await?;
    drop(source);

    let mut destination = ::redis::Client::open(destination_url)?
        .get_async_connection()
        .await?;
    let _: String = ::redis::cmd("SET")
        .arg(REPLAY_AUTHORITY_ID_KEY)
        .arg(authority)
        .query_async(&mut destination)
        .await?;
    for (scope, value) in tombstones {
        let _: i64 = ::redis::cmd("HSET")
            .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
            .arg(scope)
            .arg(value)
            .query_async(&mut destination)
            .await?;
    }
    Ok(())
}

pub(super) async fn redis_keys(url: &str, pattern: &str) -> Result<Vec<String>> {
    let mut connection = ::redis::Client::open(url)?.get_async_connection().await?;
    Ok(::redis::cmd("KEYS")
        .arg(pattern)
        .query_async(&mut connection)
        .await?)
}

pub(super) async fn redis_config_set(url: &str, name: &str, value: &str) -> Result<()> {
    let mut connection = ::redis::Client::open(url)?.get_async_connection().await?;
    let result: String = ::redis::cmd("CONFIG")
        .arg("SET")
        .arg(name)
        .arg(value)
        .query_async(&mut connection)
        .await?;
    anyhow::ensure!(result == "OK", "CONFIG SET {name} failed: {result}");
    Ok(())
}

fn encode_field(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn encode_pending_outputs(
    descriptor_id: &str,
    keyset_id: &str,
    slot_id: &str,
    quantity: u32,
) -> Vec<u8> {
    let mut encoded = Vec::new();
    encode_field(&mut encoded, descriptor_id.as_bytes());
    encode_field(&mut encoded, keyset_id.as_bytes());
    encode_field(&mut encoded, slot_id.as_bytes());
    encoded.extend_from_slice(&quantity.to_be_bytes());
    encode_field(&mut encoded, &[0x42; 8]);
    encoded
}

fn encode_pending_strings(values: &[&str]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for value in values {
        encode_field(&mut encoded, value.as_bytes());
    }
    encoded
}

pub(super) async fn seed_pending_exchange_record(
    redis_url: &str,
    fixture: &GraphFixture,
    operation: [u8; 16],
) -> Result<()> {
    let transition = &fixture.graph.transitions[0];
    let output = &transition.outputs[0];
    let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())?;
    let operation_key = format!("freebird:exchange:v2:op:{}", hex::encode(operation));
    let outputs = encode_pending_outputs(
        &output.descriptor_id,
        &transition.target_keyset_id,
        &output.slot_id,
        output.quantity,
    );
    let signer_refs = encode_pending_strings(&["freebird:exchange:v2:signer-ref:pending"]);
    let receipt_ref = "freebird:exchange:v2:receipt-ref:pending";
    let budget_id = transition.budget_id.as_str();
    let public_operation_id = Base64UrlUnpadded::encode_string(&operation);
    let source_keyset_id = transition.source_keyset_id.as_str();
    let target_keyset_id = transition.target_keyset_id.as_str();
    let mut connection = ::redis::Client::open(redis_url)?
        .get_async_connection()
        .await?;
    let _: i64 = ::redis::cmd("HSET")
        .arg(&operation_key)
        .arg("public_operation_id")
        .arg(public_operation_id)
        .arg("status_capability_digest")
        .arg(vec![0x11; 32])
        .arg("request_hash")
        .arg(vec![0x12; 32])
        .arg("graph_id")
        .arg(&fixture.graph.graph_id)
        .arg("transition_id")
        .arg(&transition.id)
        .arg("source_keyset_id")
        .arg(source_keyset_id)
        .arg("target_keyset_id")
        .arg(target_keyset_id)
        .arg("receipt_key_id")
        .arg("a".repeat(64))
        .arg("outputs")
        .arg(outputs)
        .arg("signer_refs")
        .arg(signer_refs)
        .arg("receipt_ref")
        .arg(receipt_ref)
        .arg("budget_id")
        .arg(budget_id)
        .arg("budget_policy_digest")
        .arg(vec![0x13; 32])
        .arg("budget_charge")
        .arg(u64::from(output.quantity))
        .arg("state")
        .arg("1")
        .arg("fence")
        .arg(vec![0x14; 32])
        .arg("lease_until")
        .arg(now + 30)
        .arg("created_at")
        .arg(now)
        .arg("receipt_expires_at")
        .arg(now + 300)
        .query_async(&mut connection)
        .await?;
    Ok(())
}

async fn bad_replay_probe(
    AxumJson(request): AxumJson<ReplayAuthorityProbeV1>,
) -> AxumJson<ReplayAuthorityProofV1> {
    AxumJson(ReplayAuthorityProofV1 {
        version: REPLAY_AUTHORITY_VERSION_V1,
        authority_id: request.authority_id,
        probe_id: request.probe_id,
        proof: Base64UrlUnpadded::encode_string(&[0xaa; 32]),
    })
}

pub(super) async fn start_bad_replay_probe_server() -> Result<(String, tokio::task::JoinHandle<()>)>
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let router = Router::new().route(
        "/v1/public/graph/replay-authority/probe",
        post(bad_replay_probe),
    );
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok((format!("http://{address}"), task))
}

pub(super) fn v4_admission_token(
    issuer_id: &str,
    kid: &str,
    verifier_id: &str,
    audience: &str,
    secret: [u8; 32],
    nonce: [u8; 32],
) -> Result<String> {
    let scope_digest = build_scope_digest(verifier_id, audience)
        .map_err(|error| anyhow::anyhow!("build V4 scope: {error:?}"))?;
    let input = build_private_token_input(issuer_id, kid, &nonce, &scope_digest)
        .map_err(|error| anyhow::anyhow!("build V4 input: {error:?}"))?;
    let server = Server::from_secret_key(secret, VOPRF_CONTEXT_V4)
        .map_err(|error| anyhow::anyhow!("build V4 server: {error:?}"))?;
    let token = RedemptionToken {
        nonce,
        scope_digest,
        kid: kid.into(),
        issuer_id: issuer_id.into(),
        authenticator: server
            .evaluate_unblinded(&input)
            .map_err(|error| anyhow::anyhow!("evaluate V4 credential: {error:?}"))?,
    };
    Ok(Base64UrlUnpadded::encode_string(
        &build_redemption_token(&token)
            .map_err(|error| anyhow::anyhow!("encode V4 credential: {error:?}"))?,
    ))
}

pub(super) fn v4_spend_from_token(token_b64: &str) -> Result<String> {
    let token = parse_redemption_token(&Base64UrlUnpadded::decode_vec(token_b64)?)
        .map_err(|error| anyhow::anyhow!("parse V4 credential: {error:?}"))?;
    let nullifier = nullifier_key_v4(&token, V4_ADMISSION_VERIFIER, V4_ADMISSION_AUDIENCE)
        .map_err(|error| anyhow::anyhow!("derive V4 nullifier: {error:?}"))?;
    Ok(v4_spend_key(&nullifier))
}

fn v4_issuer_info(secret: [u8; 32]) -> Result<IssuerInfo> {
    let server = Server::from_secret_key(secret, VOPRF_CONTEXT_V4)
        .map_err(|error| anyhow::anyhow!("build V4 verifier key: {error:?}"))?;
    Ok(IssuerInfo {
        pubkey_bytes: server.public_key_sec1_compressed().to_vec(),
        kid: V4_ADMISSION_KID.into(),
        ctx: VOPRF_CONTEXT_V4.to_vec(),
        verification_key: Some(secret),
        deprecated_verification_keys: HashMap::new(),
        public_keys: HashMap::new(),
        last_refreshed: Some(Instant::now()),
    })
}

pub(super) async fn ordinary_v4_verify_and_consume(
    store: &RedisStore,
    credential: &str,
) -> Result<bool> {
    let expected_scope = build_scope_digest(V4_ADMISSION_VERIFIER, V4_ADMISSION_AUDIENCE)
        .map_err(|error| anyhow::anyhow!("build ordinary verifier scope: {error:?}"))?;
    let issuers = HashMap::from([(
        V4_ADMISSION_ISSUER.to_string(),
        v4_issuer_info(V4_ADMISSION_SECRET)?,
    )]);
    let (token, _) = verify_v4_token(credential, &issuers, &expected_scope)
        .map_err(|error| anyhow::anyhow!("ordinary V4 verifier rejected credential: {error:?}"))?;
    let nullifier = nullifier_key_v4(&token, V4_ADMISSION_VERIFIER, V4_ADMISSION_AUDIENCE)
        .map_err(|error| anyhow::anyhow!("derive ordinary V4 nullifier: {error:?}"))?;
    store.mark_spent(&v4_spend_key(&nullifier), None).await
}

pub(super) async fn post_graph_issuance(
    client: &reqwest::Client,
    base: &str,
    request: &GraphIssuanceRequestV2,
    capability: &[u8; 32],
) -> Result<reqwest::Response> {
    Ok(client
        .post(format!("{base}/v1/public/graph/issue"))
        .header(
            "graph-issuance-status-capability",
            Base64UrlUnpadded::encode_string(capability),
        )
        .json(request)
        .send()
        .await?)
}

pub(super) fn finalize_graph_issuance(
    result: &GraphIssuanceResultV2,
    pending: PendingOutput,
    key: &KeyPairSha384PSSDeterministic,
) -> Result<String> {
    result.validate().map_err(anyhow::Error::msg)?;
    let signature = BlindSignature(Base64UrlUnpadded::decode_vec(&result.blind_signature)?);
    let signature = key
        .pk
        .finalize(&signature, &pending.blinding, &pending.message)?
        .0;
    let pass = PublicBearerPass {
        nonce: pending.nonce,
        token_key_id: pending.token_key_id,
        issuer_id: ISSUER_ID.into(),
        signature,
    };
    Ok(Base64UrlUnpadded::encode_string(
        &build_public_bearer_pass(&pass)
            .map_err(|error| anyhow::anyhow!("build issued graph artifact: {error:?}"))?,
    ))
}
