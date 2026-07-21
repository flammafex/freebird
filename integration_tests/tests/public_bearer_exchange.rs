// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use blind_rsa_signatures::{
    BlindSignature, BlindingResult, DefaultRng, KeyPairSha384PSSDeterministic,
};
use freebird_common::{
    api::{
        validate_exchange_discovery_v2, ExchangeDiscoveryV2, ExchangeGraphDiscoveryV2,
        ExchangeReceiptKeyInfo, KeyDiscoveryResp,
    },
    exchange_api::{
        ExchangeOutput, ExchangeReceiptV2, ExchangeRequestV2, ExchangeResultV2, ExchangeSlot,
        ExchangeSource, EXCHANGE_PROFILE_V2, EXCHANGE_VERSION_V2,
    },
    spend_key::v5_spend_key,
};
use freebird_crypto::{
    build_public_bearer_message_from_parts, build_public_bearer_pass, nullifier_key_v5,
    parse_public_bearer_pass, token_key_id_from_spki, PublicBearerPass,
};
use freebird_issuer::{
    config::{Config, ExchangeConfig, KeyConfig, PublicKeyConfig, SybilConfig},
    exchange::{
        load_or_generate_receipt_key,
        profiles::{
            ExchangeAdmissionStateV2, ExchangeDescriptorV2, ExchangeKeyV2, ExchangeKeysetV2,
            ExchangeProfileV2, ExchangeProfileValidationModeV2, ExchangeTransitionSlotV2,
            ExchangeTransitionV2,
        },
        ReceiptKey,
    },
    startup::{exchange_discovery_v2, Application},
};
use freebird_verifier::{
    discovery::trusted_public_keys,
    store::{RedisStore, SpendStore},
};
use serde::Deserialize;
use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

const ISSUER_ID: &str = "issuer:test:exchange-v2-integration";
const AUDIENCE: &str = "exchange-integration";

struct RedisHarness {
    child: Option<Child>,
    url: String,
    port: u16,
    dir: tempfile::TempDir,
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

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn restart(&mut self) -> Result<()> {
        self.stop();
        self.spawn()
    }
}

impl Drop for RedisHarness {
    fn drop(&mut self) {
        self.stop();
    }
}

struct GraphFixture {
    _dir: tempfile::TempDir,
    keys: Vec<KeyPairSha384PSSDeterministic>,
    graph: ExchangeProfileV2,
    retained: ExchangeProfileV2,
    graph_path: PathBuf,
    retained_path: PathBuf,
    receipt_path: PathBuf,
    receipt_metadata_path: PathBuf,
    acknowledgement_path: PathBuf,
}

impl GraphFixture {
    fn new(budget_limit: u64) -> Result<Self> {
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
        })
    }

    fn config(&self, redis_url: String) -> Config {
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

    fn write_recovery_only_graph(&mut self) -> Result<()> {
        for transition in &mut self.graph.transitions {
            transition.admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
        }
        std::fs::write(&self.graph_path, serde_json::to_vec_pretty(&self.graph)?)?;
        Ok(())
    }
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
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

struct TestServer {
    base: String,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl TestServer {
    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn start_server(mut config: Config) -> Result<TestServer> {
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

fn mint_artifact(key: &KeyPairSha384PSSDeterministic, nonce: [u8; 32]) -> Result<String> {
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

struct PendingOutput {
    nonce: [u8; 32],
    token_key_id: [u8; 32],
    message: Vec<u8>,
    blinding: BlindingResult,
}

fn request_from_discovery(
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
struct ExchangeResponseV2 {
    result: ExchangeResultV2,
    receipt: ExchangeReceiptV2,
}

fn finalize_output(
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

async fn post_exchange(
    client: &reqwest::Client,
    base: &str,
    request: &ExchangeRequestV2,
    capability: &[u8; 32],
) -> Result<reqwest::Response> {
    Ok(client
        .post(format!("{base}/v2/public/exchange"))
        .header(
            "exchange-status-capability",
            Base64UrlUnpadded::encode_string(capability),
        )
        .json(request)
        .send()
        .await?)
}

#[test]
fn v2_graph_config_rejects_self_edges_and_conflicting_key_metadata() -> Result<()> {
    let fixture = GraphFixture::new(4)?;
    let mut self_edge = fixture.graph.clone();
    self_edge.transitions[0].target_keyset_id = self_edge.transitions[0].source_keyset_id.clone();
    self_edge.transitions[0].outputs[0].descriptor_id =
        self_edge.keysets[0].keys[0].descriptor.id.clone();
    self_edge.transitions[0].id = self_edge.transitions[0].canonical_id();
    self_edge.graph_id = self_edge.canonical_graph_id();
    assert!(self_edge
        .validate(ExchangeProfileValidationModeV2::Active, ISSUER_ID, None)
        .is_err());

    let mut conflicting = fixture.graph.clone();
    let mut duplicate = conflicting.keysets[0].keys[0].clone();
    duplicate.descriptor.audience = Some("conflicting-audience".into());
    duplicate.descriptor.id = duplicate.descriptor.canonical_id()?;
    conflicting.keysets[0].keys.push(duplicate);
    conflicting.keysets[0].id = conflicting.keysets[0].canonical_id();
    conflicting.graph_id = conflicting.canonical_graph_id();
    assert!(conflicting
        .validate(ExchangeProfileValidationModeV2::Active, ISSUER_ID, None)
        .is_err());
    Ok(())
}

#[tokio::test]
async fn disabled_v2_exchange_routes_are_generic_and_require_status_capability() -> Result<()> {
    use freebird_crypto::VOPRF_CONTEXT_V4;
    use freebird_issuer::{
        multi_key_voprf::MultiKeyVoprfCore,
        startup::{apply_public_layers, exchange_router},
        AppStateWithSybil,
    };
    use std::sync::Arc;

    let state = Arc::new(AppStateWithSybil {
        issuer_id: ISSUER_ID.into(),
        kid: "kid".into(),
        pubkey_b64: "public".into(),
        require_tls: false,
        behind_proxy: false,
        sybil_checker: None,
        invitation_system: None,
        public_issuer: None,
        exchange_engine: None,
        exchange_metadata: None,
        epoch_duration_sec: 86_400,
        epoch_retention: 2,
        admin_api_key: None,
    });
    let voprf = Arc::new(MultiKeyVoprfCore::new(
        [7; 32],
        "public".into(),
        "kid".into(),
        VOPRF_CONTEXT_V4,
    )?);
    let app = apply_public_layers(exchange_router(64 * 1024, 5).with_state((state, voprf)))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let client = reqwest::Client::new();
    let capability = Base64UrlUnpadded::encode_string(&[9; 32]);
    let response = client
        .get(format!(
            "http://{address}/v2/public/exchange/status?public_operation_id={}",
            Base64UrlUnpadded::encode_string(&[1; 16])
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

    let response = client
        .post(format!("http://{address}/v2/public/exchange"))
        .json(&serde_json::json!({}))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<serde_json::Value>().await?["error"],
        "invalid_status_capability"
    );
    task.abort();
    Ok(())
}

#[tokio::test]
async fn v2_graph_http_exchange_atomicity_binding_cycles_and_restart() -> Result<()> {
    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let mut fixture = GraphFixture::new(4)?;
    let config = fixture.config(redis.url.clone());
    let server = start_server(config.clone()).await?;
    let client = reqwest::Client::new();

    let discovery_response = client
        .get(format!("{}/.well-known/keys", server.base))
        .send()
        .await?;
    assert_eq!(discovery_response.status(), reqwest::StatusCode::OK);
    let discovery_bytes = discovery_response.bytes().await?;
    let discovery_text = std::str::from_utf8(&discovery_bytes)?;
    for sensitive in [
        "private_key",
        "private_key_path",
        "redis_url",
        "status_capability",
        "source_artifact",
    ] {
        assert!(!discovery_text.contains(sensitive));
    }
    let issuer: KeyDiscoveryResp = serde_json::from_slice(&discovery_bytes)?;
    let trusted_keys = trusted_public_keys(ISSUER_ID, issuer.clone())?;
    let exchange = issuer
        .exchange
        .clone()
        .context("V2 exchange discovery missing")?;
    validate_exchange_discovery_v2(ISSUER_ID, &exchange).map_err(anyhow::Error::msg)?;
    assert_eq!(exchange.active_graph.profile_id, EXCHANGE_PROFILE_V2);
    assert_eq!(exchange.active_graph.transitions.len(), 4);
    assert_eq!(exchange.retained_graphs.len(), 1);
    assert_eq!(
        exchange.retained_graphs[0].graph_id,
        fixture.retained.graph_id
    );
    assert!(exchange
        .retained_graphs
        .iter()
        .flat_map(|graph| &graph.transitions)
        .all(|edge| edge.admission_state
            == freebird_common::api::ExchangeAdmissionStateV2::RecoveryOnly));
    assert_eq!(
        client
            .post(format!("{}/v1/public/exchange", server.base))
            .send()
            .await?
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );

    // The verifier and exchange must use one V5 spend namespace. The direct issuance key is also
    // a source-only graph alias with a longer validity, so verifier discovery must extend replay
    // retention through the graph's global identity horizon before writing the shared marker.
    let direct_spki = fixture.keys[3].pk.to_spki()?;
    let direct_key_id = token_key_id_from_spki(&direct_spki);
    let direct_metadata = issuer
        .public
        .iter()
        .find(|key| key.token_key_id == freebird_crypto::encode_token_key_id_hex(&direct_key_id))
        .context("direct V5 discovery key missing")?;
    let alias_metadata = exchange
        .active_graph
        .descriptors
        .iter()
        .find(|descriptor| {
            descriptor.token_key_id == freebird_crypto::encode_token_key_id_hex(&direct_key_id)
        })
        .context("source-only graph alias missing")?;
    let global_horizon = trusted_keys
        .get(&direct_key_id)
        .context("verifier did not trust direct V5 key")?
        .valid_until;
    assert!(direct_metadata.valid_until < alias_metadata.valid_until);
    assert_eq!(global_horizon, alias_metadata.valid_until);

    let verifier_first_artifact = mint_artifact(&fixture.keys[3], [0x0d; 32])?;
    let verifier_first_token =
        parse_public_bearer_pass(&Base64UrlUnpadded::decode_vec(&verifier_first_artifact)?)
            .map_err(|error| anyhow::anyhow!("parse verifier-first V5 token: {error:?}"))?;
    let verifier_spend_key = v5_spend_key(
        &nullifier_key_v5(&verifier_first_token)
            .map_err(|error| anyhow::anyhow!("derive verifier-first nullifier: {error:?}"))?,
    );
    let verifier_store = RedisStore::new(&redis.url)?;
    verifier_store.health_check().await?;
    assert!(
        verifier_store
            .mark_spent_through(&verifier_spend_key, global_horizon)
            .await?
    );
    let (verifier_first_exchange, _) = request_from_discovery(
        &exchange.active_graph,
        3,
        verifier_first_artifact,
        &fixture.keys[2],
        [0x0d; 16],
        [0x0e; 32],
    )?;
    assert_eq!(
        post_exchange(&client, &server.base, &verifier_first_exchange, &[0x0f; 32],)
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a verifier-first V5 replay marker must reject exchange of the same token"
    );

    // One source is raced over two independently authorized outgoing graph edges.
    let raced_artifact = mint_artifact(&fixture.keys[0], [0x11; 32])?;
    let (request_ab, _) = request_from_discovery(
        &exchange.active_graph,
        0,
        raced_artifact.clone(),
        &fixture.keys[1],
        [0x11; 16],
        [0x21; 32],
    )?;
    let (request_ac, _) = request_from_discovery(
        &exchange.active_graph,
        2,
        raced_artifact,
        &fixture.keys[2],
        [0x12; 16],
        [0x22; 32],
    )?;
    let capability_ab = [0x31; 32];
    let capability_ac = [0x32; 32];
    let (response_ab, response_ac) = tokio::join!(
        post_exchange(&client, &server.base, &request_ab, &capability_ab),
        post_exchange(&client, &server.base, &request_ac, &capability_ac),
    );
    let statuses = [response_ab?.status(), response_ac?.status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == reqwest::StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == reqwest::StatusCode::BAD_REQUEST)
            .count(),
        1
    );

    // Unknown edges and selector/artifact/output tampering fail before spending the source.
    let tamper_artifact = mint_artifact(&fixture.keys[0], [0x13; 32])?;
    let (valid_tamper_request, valid_tamper_pending) = request_from_discovery(
        &exchange.active_graph,
        2,
        tamper_artifact,
        &fixture.keys[2],
        [0x20; 16],
        [0x23; 32],
    )?;
    let mut tampered = Vec::new();
    tampered.push({
        let mut value = valid_tamper_request.clone();
        value.graph_id = "f".repeat(64);
        value
    });
    tampered.push({
        let mut value = valid_tamper_request.clone();
        value.transition_id = "e".repeat(64);
        value
    });
    tampered.push({
        let mut value = valid_tamper_request.clone();
        value.source_keyset_id = exchange.active_graph.transitions[1]
            .source_keyset_id
            .clone();
        value.sources[0].slot.keyset_id = value.source_keyset_id.clone();
        value
    });
    tampered.push({
        let mut value = valid_tamper_request.clone();
        value.target_keyset_id = exchange.active_graph.transitions[0]
            .target_keyset_id
            .clone();
        value.outputs[0].slot.keyset_id = value.target_keyset_id.clone();
        value
    });
    tampered.push({
        let mut value = valid_tamper_request.clone();
        value.sources[0].artifact = Base64UrlUnpadded::encode_string(b"tampered-source");
        value
    });
    tampered.push({
        let mut value = valid_tamper_request.clone();
        value.outputs[0].blinded_value = Base64UrlUnpadded::encode_string(b"tampered-output");
        value
    });
    for (index, mut request) in tampered.into_iter().enumerate() {
        request.public_operation_id = Base64UrlUnpadded::encode_string(&[0x30 + index as u8; 16]);
        assert_eq!(
            post_exchange(&client, &server.base, &request, &[0x40 + index as u8; 32])
                .await?
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
    }
    let authorized_after_tamper =
        post_exchange(&client, &server.base, &valid_tamper_request, &[0x4f; 32]).await?;
    assert_eq!(
        authorized_after_tamper.status(),
        reqwest::StatusCode::OK,
        "400 responses on unauthorized/tampered edges must not spend the source"
    );
    let authorized_after_tamper: ExchangeResponseV2 = authorized_after_tamper.json().await?;
    let _ = finalize_output(
        &authorized_after_tamper,
        valid_tamper_pending,
        &fixture.keys[2],
    )?;

    // A -> B -> A can repeat without process restarts, but each edge has finite lifetime budget.
    let mut artifact_a = mint_artifact(&fixture.keys[0], [0x50; 32])?;
    let mut first_request = None;
    let mut first_capability = None;
    let mut first_response_bytes = None;
    let mut completed_cycles = 0usize;
    for cycle in 0..5u8 {
        let (request, pending) = request_from_discovery(
            &exchange.active_graph,
            0,
            artifact_a,
            &fixture.keys[1],
            [0x60 + cycle; 16],
            [0x70 + cycle; 32],
        )?;
        let capability = [0x80 + cycle; 32];
        let response = post_exchange(&client, &server.base, &request, &capability).await?;
        if response.status() == reqwest::StatusCode::BAD_REQUEST {
            break;
        }
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let bytes = response.bytes().await?.to_vec();
        let exchange_response: ExchangeResponseV2 = serde_json::from_slice(&bytes)?;
        exchange_response
            .receipt
            .validate_result(&exchange_response.result)?;
        let artifact_b = finalize_output(&exchange_response, pending, &fixture.keys[1])?;

        if first_request.is_none() {
            first_request = Some(request.clone());
            first_capability = Some(capability);
            first_response_bytes = Some(bytes.clone());
        }

        let (request_back, pending_back) = request_from_discovery(
            &exchange.active_graph,
            1,
            artifact_b,
            &fixture.keys[0],
            [0x90 + cycle; 16],
            [0xa0 + cycle; 32],
        )?;
        let response_back =
            post_exchange(&client, &server.base, &request_back, &[0xb0 + cycle; 32]).await?;
        assert_eq!(response_back.status(), reqwest::StatusCode::OK);
        let response_back: ExchangeResponseV2 = response_back.json().await?;
        artifact_a = finalize_output(&response_back, pending_back, &fixture.keys[0])?;
        completed_cycles += 1;
    }
    assert!((3..=4).contains(&completed_cycles));

    let first_request = first_request.context("cycle never committed")?;
    let first_capability = first_capability.unwrap();
    let first_response_bytes = first_response_bytes.unwrap();
    let first_response: ExchangeResponseV2 = serde_json::from_slice(&first_response_bytes)?;
    let original_request_digest = first_request.request_digest()?;
    let mut changed_request = first_request.clone();
    changed_request.outputs[0].blinded_value = Base64UrlUnpadded::encode_string(b"changed");
    assert_ne!(changed_request.request_digest()?, original_request_digest);
    assert_eq!(
        post_exchange(&client, &server.base, &changed_request, &first_capability)
            .await?
            .status(),
        reqwest::StatusCode::CONFLICT
    );

    // Exact idempotency, status authorization, malformed input, and no capability disclosure.
    let replay = post_exchange(&client, &server.base, &first_request, &first_capability).await?;
    assert_eq!(replay.status(), reqwest::StatusCode::OK);
    assert_eq!(
        replay.bytes().await?.as_ref(),
        first_response_bytes.as_slice()
    );
    let status_url = format!(
        "{}/v2/public/exchange/status?public_operation_id={}",
        server.base, first_request.public_operation_id
    );
    let status = client
        .get(&status_url)
        .header(
            "exchange-status-capability",
            Base64UrlUnpadded::encode_string(&first_capability),
        )
        .send()
        .await?;
    assert_eq!(status.status(), reqwest::StatusCode::OK);
    let status_bytes = status.bytes().await?;
    assert_eq!(status_bytes.as_ref(), first_response_bytes.as_slice());
    assert!(!std::str::from_utf8(&status_bytes)?.contains("status_capability"));
    assert_eq!(
        client
            .get(&status_url)
            .header(
                "exchange-status-capability",
                Base64UrlUnpadded::encode_string(&[0xee; 32]),
            )
            .send()
            .await?
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .get(format!(
                "{}/v2/public/exchange/status?public_operation_id={}",
                server.base,
                Base64UrlUnpadded::encode_string(&[0xef; 16])
            ))
            .header(
                "exchange-status-capability",
                Base64UrlUnpadded::encode_string(&[0xef; 32]),
            )
            .send()
            .await?
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    assert_eq!(
        client
            .post(format!("{}/v2/public/exchange", server.base))
            .header(
                "exchange-status-capability",
                Base64UrlUnpadded::encode_string(&[1; 32]),
            )
            .header("content-type", "application/json")
            .body("{")
            .send()
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .post(format!("{}/v2/public/exchange", server.base))
            .header(
                "exchange-status-capability",
                Base64UrlUnpadded::encode_string(&[1; 16]),
            )
            .json(&first_request)
            .send()
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let mut duplicate_capability = reqwest::header::HeaderMap::new();
    duplicate_capability.append(
        "exchange-status-capability",
        Base64UrlUnpadded::encode_string(&first_capability).parse()?,
    );
    duplicate_capability.append(
        "exchange-status-capability",
        Base64UrlUnpadded::encode_string(&first_capability).parse()?,
    );
    assert_eq!(
        client
            .post(format!("{}/v2/public/exchange", server.base))
            .headers(duplicate_capability)
            .json(&first_request)
            .send()
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .get(format!("{}/v2/public/exchange/status", server.base))
            .header(
                "exchange-status-capability",
                Base64UrlUnpadded::encode_string(&[1; 32]),
            )
            .send()
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    // Result and receipt selectors/digests/signatures bind graph, edge, source, target and output.
    let mut result_mutations = Vec::new();
    for field in 0..5 {
        let mut value = first_response.result.clone();
        match field {
            0 => value.graph_id = "1".repeat(64),
            1 => value.transition_id = "2".repeat(64),
            2 => value.source_keyset_id = "3".repeat(64),
            3 => {
                value.target_keyset_id = "4".repeat(64);
                value.outputs[0].slot.keyset_id = value.target_keyset_id.clone();
            }
            _ => value.outputs[0].blind_signature = Base64UrlUnpadded::encode_string(&[5; 256]),
        }
        result_mutations.push(value);
    }
    assert!(result_mutations
        .iter()
        .all(|result| result.canonical_bytes().is_err()));

    let receipt_key = load_or_generate_receipt_key(&fixture.receipt_path)?;
    let receipt_signature = Base64UrlUnpadded::decode_vec(&first_response.receipt.signature)?;
    ReceiptKey::verify_receipt_v2(
        &first_response.receipt,
        &receipt_key.verifying_key(),
        &receipt_signature,
    )?;
    for field in 0..5 {
        let mut receipt = first_response.receipt.clone();
        match field {
            0 => receipt.graph_id = "1".repeat(64),
            1 => receipt.transition_id = "2".repeat(64),
            2 => receipt.source_keyset_id = "3".repeat(64),
            3 => receipt.target_keyset_id = "4".repeat(64),
            _ => receipt.result_digest = Base64UrlUnpadded::encode_string(&[5; 32]),
        }
        assert!(receipt.validate_result(&first_response.result).is_err());
        assert!(ReceiptKey::verify_receipt_v2(
            &receipt,
            &receipt_key.verifying_key(),
            &receipt_signature,
        )
        .is_err());
    }

    // Simulate a process crash plus durable Redis restart. Recovery-only state still serves the
    // exact committed operation, while refusing a new operation on the same edge.
    server.stop().await;
    redis.restart()?;
    fixture.write_recovery_only_graph()?;
    let restarted = start_server(fixture.config(redis.url.clone())).await?;
    let recovered =
        post_exchange(&client, &restarted.base, &first_request, &first_capability).await?;
    assert_eq!(recovered.status(), reqwest::StatusCode::OK);
    assert_eq!(
        recovered.bytes().await?.as_ref(),
        first_response_bytes.as_slice()
    );

    let recovery_discovery: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", restarted.base))
        .send()
        .await?
        .json()
        .await?;
    let recovery_graph = recovery_discovery.exchange.unwrap().active_graph;
    assert!(recovery_graph.transitions.iter().all(|edge| {
        edge.admission_state == freebird_common::api::ExchangeAdmissionStateV2::RecoveryOnly
    }));
    let fresh_artifact = mint_artifact(&fixture.keys[0], [0xf1; 32])?;
    let (fresh_request, _) = request_from_discovery(
        &recovery_graph,
        0,
        fresh_artifact,
        &fixture.keys[1],
        [0xf1; 16],
        [0xf2; 32],
    )?;
    assert_eq!(
        post_exchange(&client, &restarted.base, &fresh_request, &[0xf3; 32])
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    restarted.stop().await;
    Ok(())
}

#[test]
fn discovery_constructor_is_public_only_and_sufficient_for_graph_clients() -> Result<()> {
    let fixture = GraphFixture::new(4)?;
    let key = load_or_generate_receipt_key(&fixture.receipt_path)?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    let metadata = ExchangeReceiptKeyInfo {
        key_id: key.key_id(),
        algorithm: "Ed25519".into(),
        purpose: "exchange_receipt_active".into(),
        public_key_b64: Base64UrlUnpadded::encode_string(key.verifying_key().as_bytes()),
        valid_from: now - 60,
        valid_until: now + 3600,
    };
    let discovery: ExchangeDiscoveryV2 = exchange_discovery_v2(
        &fixture.graph,
        std::slice::from_ref(&fixture.retained),
        &[metadata],
    )?;
    validate_exchange_discovery_v2(ISSUER_ID, &discovery).map_err(anyhow::Error::msg)?;
    let json = serde_json::to_string(&discovery)?;
    assert!(!json.contains("private_key"));
    assert!(!json.contains("status_capability"));
    let (request, _) = request_from_discovery(
        &discovery.active_graph,
        0,
        mint_artifact(&fixture.keys[0], [7; 32])?,
        &fixture.keys[1],
        [8; 16],
        [9; 32],
    )?;
    assert!(request.validate().is_ok());
    Ok(())
}
