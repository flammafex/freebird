use super::support::*;
use freebird_common::api::{
    NativeBearerV7KeyInfo, NativeExchangeV3Descriptor, NativeExchangeV3Discovery,
    NativeExchangeV3Keyset, NativeExchangeV3Output, NativeExchangeV3Request, NativeExchangeV3Slot,
    NativeExchangeV3Source, NativeExchangeV3Transition, NativeGraphIssuanceV7Policy,
    NativeGraphIssuanceV7Request, V7KeyDiscoveryResp, NATIVE_BEARER_V7_PROFILE_ID,
    NATIVE_EXCHANGE_V3_PROFILE_ID, NATIVE_EXCHANGE_V3_SUITE, NATIVE_EXCHANGE_V3_VERSION,
    NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID, NATIVE_GRAPH_ISSUANCE_V7_VERSION,
};
use freebird_issuer::config::{
    Config, ExchangeConfig, GraphIssuanceAuthorizationConfig, GraphIssuanceConfig,
    GraphIssuanceV4VerificationKey, KeyConfig, NativeBearerV7Config, PublicKeyConfig,
};
use freebird_issuer::v7_signers::{V7SignerInventory, V7SignerSpec};
use std::{env, path::PathBuf};
use time::OffsetDateTime;

const ADMIN_KEY: &str = "integration-v7-admin-key-at-least-32-characters";
const GRAPH_ID: &str = "ab";

struct V7Fixture {
    dir: tempfile::TempDir,
    direct: NativeBearerV7Config,
    additional_path: PathBuf,
    exchange_path: PathBuf,
    retained_exchange_path: PathBuf,
    policy_path: PathBuf,
    receipt_key_path: PathBuf,
    receipt_metadata_path: PathBuf,
}

impl V7Fixture {
    fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let registry_path = root.join("native-v7-registry.json");
        let config =
            |name: &str, profile: &str, descriptor: u8, token_key: u8| NativeBearerV7Config {
                sk_path: root.join(format!("{name}.der")),
                metadata_path: root.join(format!("{name}.json")),
                registry_path: registry_path.clone(),
                profile_id: profile.into(),
                descriptor_id: format!("{descriptor:02x}").repeat(32),
                token_key_id: format!("{token_key:02x}").repeat(32),
                asset_id: "USD".into(),
                amount_minor: 1,
                validity_secs: 3600,
            };
        let direct = config("direct", NATIVE_BEARER_V7_PROFILE_ID, 0x11, 0x12);
        let additional = vec![
            config("direct-retained", NATIVE_BEARER_V7_PROFILE_ID, 0x13, 0x14),
            config("exchange-a", NATIVE_EXCHANGE_V3_PROFILE_ID, 0x21, 0x22),
            config("exchange-b", NATIVE_EXCHANGE_V3_PROFILE_ID, 0x23, 0x24),
            config(
                "exchange-retained",
                NATIVE_EXCHANGE_V3_PROFILE_ID,
                0x25,
                0x26,
            ),
            config("graph", NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID, 0x31, 0x32),
        ];
        let active = V7SignerSpec::from_native_config(&direct, ISSUER_ID)?;
        let retained = additional
            .iter()
            .map(|config| V7SignerSpec::from_native_config(config, ISSUER_ID))
            .collect::<Result<Vec<_>>>()?;
        let inventory = V7SignerInventory::load_or_generate(active, retained, &registry_path)?;
        assert_eq!(inventory.len(), 6);

        let additional_path = root.join("additional-v7-signers.json");
        std::fs::write(&additional_path, serde_json::to_vec_pretty(&additional)?)?;

        let metadata = |config: &NativeBearerV7Config| -> Result<NativeBearerV7KeyInfo> {
            Ok(serde_json::from_slice(&std::fs::read(
                &config.metadata_path,
            )?)?)
        };
        let exchange_a = metadata(&additional[1])?;
        let exchange_b = metadata(&additional[2])?;
        let exchange_retained = metadata(&additional[3])?;
        let graph = metadata(&additional[4])?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let graph_id = GRAPH_ID.repeat(32);
        let keyset_a = "a1".repeat(32);
        let keyset_b = "b1".repeat(32);
        let keyset_retained = "c1".repeat(32);
        let descriptor = |metadata: &NativeBearerV7KeyInfo| NativeExchangeV3Descriptor {
            descriptor_id: metadata.descriptor_id.clone(),
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            issuer_id: metadata.issuer_id.clone(),
            token_key_id: metadata.token_key_id.clone(),
            asset_id: metadata.asset_id.clone(),
            amount_minor: metadata.amount_minor.to_string(),
            suite: NATIVE_EXCHANGE_V3_SUITE.into(),
            modulus_bits: metadata.modulus_bits,
            exponent: metadata.exponent,
            pubkey_spki_b64: metadata.pubkey_spki_b64.clone(),
            spki_fingerprint: metadata.spki_fingerprint.clone(),
            valid_from: metadata.valid_from as u64,
            valid_until: metadata.valid_until as u64,
        };
        let slot = |descriptor_id: String, keyset_id: String, slot_id: &str| NativeExchangeV3Slot {
            descriptor_id,
            keyset_id,
            slot_id: slot_id.into(),
            quantity: 1,
        };
        let active_transition = NativeExchangeV3Transition {
            transition_id: "d1".repeat(32),
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            source_keyset_id: keyset_a.clone(),
            target_keyset_id: keyset_b.clone(),
            source_slots: vec![slot(
                exchange_a.descriptor_id.clone(),
                keyset_a.clone(),
                "source",
            )],
            output_slots: vec![slot(
                exchange_b.descriptor_id.clone(),
                keyset_b.clone(),
                "output",
            )],
        };
        let retained_transition = NativeExchangeV3Transition {
            transition_id: "d2".repeat(32),
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            source_keyset_id: keyset_b.clone(),
            target_keyset_id: keyset_retained.clone(),
            source_slots: vec![slot(
                exchange_b.descriptor_id.clone(),
                keyset_b.clone(),
                "source",
            )],
            output_slots: vec![slot(
                exchange_retained.descriptor_id.clone(),
                keyset_retained.clone(),
                "output",
            )],
        };
        let profile = freebird_common::api::NativeExchangeV3Profile {
            version: NATIVE_EXCHANGE_V3_VERSION,
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            graph_id: graph_id.clone(),
            suite: NATIVE_EXCHANGE_V3_SUITE.into(),
            modulus_bits: 3072,
            exponent: 65_537,
        };
        let discovery = NativeExchangeV3Discovery {
            version: NATIVE_EXCHANGE_V3_VERSION,
            profile: profile.clone(),
            active_descriptors: vec![descriptor(&exchange_a), descriptor(&exchange_b)],
            retained_descriptors: vec![],
            active_keysets: vec![
                NativeExchangeV3Keyset {
                    keyset_id: keyset_a.clone(),
                    profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                    descriptor_ids: vec![exchange_a.descriptor_id.clone()],
                },
                NativeExchangeV3Keyset {
                    keyset_id: keyset_b.clone(),
                    profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                    descriptor_ids: vec![exchange_b.descriptor_id.clone()],
                },
            ],
            retained_keysets: vec![],
            transitions: vec![active_transition],
        };
        let retained_discovery = NativeExchangeV3Discovery {
            version: NATIVE_EXCHANGE_V3_VERSION,
            profile,
            active_descriptors: vec![descriptor(&exchange_retained)],
            retained_descriptors: vec![],
            active_keysets: vec![NativeExchangeV3Keyset {
                keyset_id: keyset_retained.clone(),
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                descriptor_ids: vec![exchange_retained.descriptor_id.clone()],
            }],
            retained_keysets: vec![],
            transitions: vec![retained_transition],
        };
        discovery
            .validate()
            .map_err(|error| anyhow::anyhow!(error))?;
        retained_discovery
            .validate()
            .map_err(|error| anyhow::anyhow!(error))?;
        let exchange_path = root.join("active-exchange-v7.json");
        let retained_exchange_path = root.join("retained-exchange-v7.json");
        std::fs::write(&exchange_path, serde_json::to_vec_pretty(&discovery)?)?;
        std::fs::write(
            &retained_exchange_path,
            serde_json::to_vec_pretty(&retained_discovery)?,
        )?;

        let policy = NativeGraphIssuanceV7Policy {
            policy_id: "f1".repeat(32),
            profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
            graph_id: graph_id.clone(),
            keyset_id: "e1".repeat(32),
            descriptor_id: graph.descriptor_id.clone(),
            token_key_id: graph.token_key_id.clone(),
            issuer_id: graph.issuer_id.clone(),
            asset_id: graph.asset_id.clone(),
            amount_minor: graph.amount_minor.to_string(),
            suite: graph.suite.clone(),
            modulus_bits: graph.modulus_bits,
            exponent: graph.exponent,
            quantity: 1,
            pubkey_spki_b64: graph.pubkey_spki_b64.clone(),
            spki_fingerprint: graph.spki_fingerprint.clone(),
            valid_from: graph.valid_from,
            valid_until: graph.valid_until,
        };
        policy.validate().map_err(|error| anyhow::anyhow!(error))?;
        let policy_path = root.join("graph-policy-v7.json");
        std::fs::write(&policy_path, serde_json::to_vec_pretty(&vec![policy])?)?;

        let receipt_key_path = root.join("receipt.key");
        let receipt_key = load_or_generate_receipt_key(&receipt_key_path)?;
        let receipt_metadata = ExchangeReceiptKeyInfo {
            key_id: receipt_key.key_id(),
            algorithm: "Ed25519".into(),
            purpose: "exchange_receipt_v7".into(),
            public_key_b64: Base64UrlUnpadded::encode_string(
                receipt_key.verifying_key().as_bytes(),
            ),
            valid_from: (now - 60) as u64,
            valid_until: (now + 3600) as u64,
        };
        let receipt_metadata_path = root.join("receipt.json");
        std::fs::write(
            &receipt_metadata_path,
            serde_json::to_vec_pretty(&receipt_metadata)?,
        )?;

        Ok(Self {
            dir,
            direct,
            additional_path,
            exchange_path,
            retained_exchange_path,
            policy_path,
            receipt_key_path,
            receipt_metadata_path,
        })
    }

    fn config(&self, redis_url: String) -> Config {
        let root = self.dir.path();
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
                enabled: false,
                sk_path: root.join("legacy-public.key"),
                metadata_path: root.join("legacy-public.json"),
                validity_secs: 3600,
                audience: None,
                modulus_bits: 2048,
            },
            native_bearer_v7_config: self.direct.clone(),
            exchange_config: ExchangeConfig {
                enabled: true,
                active_graph_path: self.exchange_path.clone(),
                retained_graph_paths: vec![self.retained_exchange_path.clone()],
                public_history_path: None,
                disabled_publication_ack_paths: vec![],
                active_receipt_key_path: self.receipt_key_path.clone(),
                active_receipt_metadata_path: self.receipt_metadata_path.clone(),
                retained_receipt_key_paths: vec![],
                retained_receipt_metadata_paths: vec![],
                redis_url: Some(redis_url),
                receipt_lifetime_secs: 300,
                request_body_limit: 3 * 1024 * 1024,
                request_timeout_secs: 5,
                graph_issuance: GraphIssuanceConfig {
                    enabled: true,
                    policy_path: self.policy_path.clone(),
                    v7_verifier_id: V4_ADMISSION_VERIFIER.into(),
                    v7_audience: V4_ADMISSION_AUDIENCE.into(),
                    authorization: GraphIssuanceAuthorizationConfig::V4Local {
                        keys: vec![GraphIssuanceV4VerificationKey {
                            issuer_id: V4_ADMISSION_ISSUER.into(),
                            kid: V4_ADMISSION_KID.into(),
                            secret_key: V4_ADMISSION_SECRET,
                        }],
                    },
                },
            },
            sybil_config: test_sybil_config(root),
            webauthn_config: None,
            admin_api_key: Some(ADMIN_KEY.into()),
            epoch_duration_sec: 86_400,
            epoch_retention: 2,
            allow_unsafe_v4_rotation: false,
            audit_log_path: root.join("audit.json"),
            unsafe_development_mode: false,
        }
    }

    fn graph_request(&self) -> NativeGraphIssuanceV7Request {
        let graph_metadata: NativeBearerV7KeyInfo =
            serde_json::from_slice(&std::fs::read(self.dir.path().join("graph.json")).unwrap())
                .unwrap();
        NativeGraphIssuanceV7Request {
            version: NATIVE_GRAPH_ISSUANCE_V7_VERSION,
            profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
            issuer_id: ISSUER_ID.into(),
            public_operation_id: Base64UrlUnpadded::encode_string(&[3; 16]),
            graph_id: GRAPH_ID.repeat(32),
            policy_id: "f1".repeat(32),
            keyset_id: "e1".repeat(32),
            descriptor_id: graph_metadata.descriptor_id,
            token_key_id: graph_metadata.token_key_id,
            asset_id: "USD".into(),
            amount_minor: "1".into(),
            quantity: 1,
            blinded_message: Base64UrlUnpadded::encode_string(&[1; 384]),
            request_commitment: "00".repeat(32),
            authorization: Base64UrlUnpadded::encode_string(&[1]),
            authorization_proof: Base64UrlUnpadded::encode_string(&[0; 64]),
        }
    }

    fn exchange_request(&self) -> NativeExchangeV3Request {
        let exchange_a: NativeBearerV7KeyInfo = serde_json::from_slice(
            &std::fs::read(self.dir.path().join("exchange-a.json")).unwrap(),
        )
        .unwrap();
        let exchange_b: NativeBearerV7KeyInfo = serde_json::from_slice(
            &std::fs::read(self.dir.path().join("exchange-b.json")).unwrap(),
        )
        .unwrap();
        NativeExchangeV3Request {
            version: NATIVE_EXCHANGE_V3_VERSION,
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            issuer_or_federation_id: ISSUER_ID.into(),
            public_operation_id: Base64UrlUnpadded::encode_string(&[4; 16]),
            graph_id: GRAPH_ID.repeat(32),
            transition_id: "d1".repeat(32),
            source_keyset_id: "a1".repeat(32),
            target_keyset_id: "b1".repeat(32),
            asset_id: "USD".into(),
            source_count: 1,
            output_count: 1,
            source_total_minor: "1".into(),
            output_total_minor: "1".into(),
            source_root: "00".repeat(32),
            request_output_root: "00".repeat(32),
            sources: vec![NativeExchangeV3Source {
                artifact: Base64UrlUnpadded::encode_string(&[7]),
                source_artifact_digest: "00".repeat(32),
                descriptor_id: exchange_a.descriptor_id,
                keyset_id: "a1".repeat(32),
                slot_id: "source".into(),
            }],
            outputs: vec![NativeExchangeV3Output {
                output_id: Base64UrlUnpadded::encode_string(&[2; 16]),
                descriptor_id: exchange_b.descriptor_id,
                keyset_id: "b1".repeat(32),
                slot_id: "output".into(),
                asset_id: "USD".into(),
                amount_minor: "1".into(),
                blinded_message: Base64UrlUnpadded::encode_string(&[1; 384]),
                handoff_commitment: "00".repeat(32),
                request_output_commitment: "00".repeat(32),
                request_output_proof: Base64UrlUnpadded::encode_string(&[0; 192]),
            }],
        }
    }
}

struct EnvironmentGuard {
    values: Vec<(&'static str, Option<String>)>,
}

impl EnvironmentGuard {
    fn install(path: &PathBuf, redis_url: &str) -> Self {
        let keys = [
            "NATIVE_V7_SIGNER_CONFIG_PATHS",
            "SYBIL_REPLAY_STORE",
            "SYBIL_REPLAY_REDIS_URL",
        ];
        let values = keys
            .into_iter()
            .map(|key| (key, env::var(key).ok()))
            .collect();
        env::set_var("NATIVE_V7_SIGNER_CONFIG_PATHS", path);
        env::set_var("SYBIL_REPLAY_STORE", "redis");
        env::set_var("SYBIL_REPLAY_REDIS_URL", redis_url);
        Self { values }
    }
}

impl Drop for EnvironmentGuard {
    fn drop(&mut self) {
        for (key, value) in &self.values {
            match value {
                Some(value) => env::set_var(key, value),
                None => env::remove_var(key),
            }
        }
    }
}

pub(super) async fn v7_enabled_runtime_cutover_characterization() -> Result<()> {
    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let fixture = V7Fixture::new()?;
    let _environment = EnvironmentGuard::install(&fixture.additional_path, &redis.url);
    let server = start_server(fixture.config(redis.url.clone())).await?;
    wait_for_issuer_status(&server, "/readyz", reqwest::StatusCode::OK).await?;
    let client = reqwest::Client::new();
    let readiness = client
        .get(format!("{}/admin/readiness", server.base))
        .header("x-admin-key", ADMIN_KEY)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    assert_eq!(readiness["ready"], true);
    assert_eq!(readiness["exchange"], true);
    assert_eq!(readiness["graph_issuance"], true);

    let direct_key = fixture.direct.token_key_id.clone();
    let discovery = client
        .get(format!("{}/.well-known/keys", server.base))
        .send()
        .await?
        .error_for_status()?
        .json::<V7KeyDiscoveryResp>()
        .await?;
    assert!(discovery.native_exchange_v7.is_some());
    discovery
        .native_graph_issuance_v7
        .as_ref()
        .context("V7 graph discovery missing")?;
    let v7_json = serde_json::to_string(&discovery).unwrap();
    assert!(!v7_json.contains("\"public\""));
    assert!(!v7_json.contains("\"exchange\""));
    assert!(!v7_json.contains("\"graph_issuance\""));
    assert!(!v7_json.contains("\"token_type\""));
    assert!(!v7_json.contains("\"rfc9474_variant\""));
    let authority_discovery = client
        .get(format!("{}/.well-known/replay-authority", server.base))
        .send()
        .await?
        .error_for_status()?
        .json::<freebird_common::api::KeyDiscoveryResp>()
        .await?;
    let authority_graph = authority_discovery
        .graph_issuance
        .as_ref()
        .context("V4 graph authority discovery missing")?;
    assert!(!authority_graph.replay_authority.authority_id.is_empty());
    assert_eq!(authority_graph.policies.len(), 1);
    assert_eq!(authority_graph.policies[0].authorization_scheme, "v4_local");
    let scope_digest = build_scope_digest(V4_ADMISSION_VERIFIER, V4_ADMISSION_AUDIENCE)
        .map_err(|error| anyhow::anyhow!("build V4 scope digest: {error:?}"))?;
    let scope = Base64UrlUnpadded::encode_string(&scope_digest);
    assert!(authority_graph
        .replay_authority
        .v4_scope_digest_tombstones
        .contains(&scope));

    let verifier_store = Arc::new(RedisStore::new(&redis.url)?);
    let health = ReplayAuthorityHealth::new(
        verifier_store,
        ReplayAuthorityConfig {
            graph_issuer_urls: vec![server.base.clone()],
            probe_interval: Duration::from_secs(30),
            max_staleness: Duration::from_secs(60),
        },
        scope_digest,
    )?;
    health.refresh_and_probe().await;
    assert!(health.healthy().await);

    let direct = client
        .post(format!("{}/v7/native-bearer/issue", server.base))
        .json(&serde_json::json!({
            "token_key_id": direct_key,
            "blinded_msg_b64": Base64UrlUnpadded::encode_string(&[1; 384])
        }))
        .send()
        .await?;
    assert_eq!(direct.status(), reqwest::StatusCode::OK);
    assert!(direct.json::<serde_json::Value>().await?["blind_signature_b64"].is_string());

    let capability = Base64UrlUnpadded::encode_string(&[9; 32]);
    let exchange = client
        .post(format!("{}/v7/public/exchange", server.base))
        .header("exchange-status-capability", &capability)
        .json(&fixture.exchange_request())
        .send()
        .await?;
    assert_eq!(exchange.status(), reqwest::StatusCode::BAD_REQUEST);
    let exchange_status = client
        .get(format!(
            "{}/v7/public/exchange/status?public_operation_id={}",
            server.base,
            Base64UrlUnpadded::encode_string(&[4; 16])
        ))
        .header("exchange-status-capability", &capability)
        .send()
        .await?;
    assert_eq!(exchange_status.status(), reqwest::StatusCode::NOT_FOUND);

    let graph = client
        .post(format!("{}/v7/public/graph/issue", server.base))
        .json(&fixture.graph_request())
        .send()
        .await?;
    assert_eq!(graph.status(), reqwest::StatusCode::BAD_REQUEST);
    let graph_status = client
        .get(format!(
            "{}/v7/public/graph/issue/status?public_operation_id={}",
            server.base,
            Base64UrlUnpadded::encode_string(&[3; 16])
        ))
        .send()
        .await?;
    assert_eq!(graph_status.status(), reqwest::StatusCode::NOT_FOUND);

    for path in [
        "/v1/public/issue",
        "/v1/public/issue/batch",
        "/v2/public/issue",
        "/v2/public/issue/batch",
        "/v5/public/issue",
        "/v5/public/issue/batch",
        "/v1/public/exchange",
        "/v2/public/exchange",
        "/v5/public/exchange",
        "/v1/public/graph/issue",
        "/v2/public/graph/issue",
        "/v5/public/graph/issue",
    ] {
        let response = client
            .post(format!("{}{path}", server.base))
            .header("content-type", "application/json")
            .header("exchange-status-capability", &capability)
            .body("{}")
            .send()
            .await?;
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "POST {path}"
        );
    }
    for path in [
        "/v1/public/exchange/status",
        "/v2/public/exchange/status",
        "/v5/public/exchange/status",
        "/v1/public/graph/issue/status",
        "/v2/public/graph/issue/status",
        "/v5/public/graph/issue/status",
    ] {
        let response = client
            .get(format!(
                "{}{path}?public_operation_id={}",
                server.base,
                Base64UrlUnpadded::encode_string(&[1; 16])
            ))
            .header("exchange-status-capability", &capability)
            .send()
            .await?;
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "GET {path}"
        );
    }
    let issuer = client
        .get(format!("{}/.well-known/issuer", server.base))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    assert!(issuer.get("public").is_none());

    redis.stop();
    let mut readiness = serde_json::Value::Null;
    for _ in 0..400 {
        readiness = client
            .get(format!("{}/admin/readiness", server.base))
            .header("x-admin-key", ADMIN_KEY)
            .send()
            .await?
            .json()
            .await?;
        if readiness["exchange"] == false && readiness["graph_issuance"] == false {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(readiness["exchange"], false);
    assert_eq!(readiness["graph_issuance"], false);
    wait_for_issuer_status(&server, "/readyz", reqwest::StatusCode::SERVICE_UNAVAILABLE).await?;
    server.stop().await;
    Ok(())
}
