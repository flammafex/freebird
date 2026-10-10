// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{bail, Context, Result};
use std::sync::Arc;

pub(super) struct ExchangeRuntime {
    pub(super) native_exchange_v7: Option<Arc<crate::exchange::v7::V7ExchangeEngine>>,
    pub(super) native_exchange_v7_discovery:
        Option<freebird_common::api::NativeExchangeV3Discovery>,
    pub(super) native_graph_issuance_v7: Option<Arc<crate::graph_issuance::V7GraphIssuanceEngine>>,
    pub(super) native_graph_issuance_v7_discovery:
        Option<freebird_common::api::NativeGraphIssuanceV7Discovery>,
    pub(super) native_exchange_v7_readiness: Option<crate::readiness::V7ExchangeReadinessState>,
    pub(super) native_graph_issuance_v7_readiness:
        Option<crate::readiness::V7GraphIssuanceReadinessState>,
    pub(super) replay_authority: Option<Arc<crate::replay_authority::ReplayAuthority>>,
}

impl ExchangeRuntime {
    pub(super) async fn build(
        config: &crate::config::Config,
        inventory: Arc<crate::v7_signers::V7SignerInventory>,
    ) -> Result<Self> {
        validate_graph_exchange_enablement(
            config.exchange_config.enabled,
            config.exchange_config.graph_issuance.enabled,
        )?;
        if !config.exchange_config.enabled {
            return Ok(Self {
                native_exchange_v7: None,
                native_exchange_v7_discovery: None,
                native_graph_issuance_v7: None,
                native_graph_issuance_v7_discovery: None,
                native_exchange_v7_readiness: None,
                native_graph_issuance_v7_readiness: None,
                replay_authority: None,
            });
        }
        let redis_url = config
            .exchange_config
            .redis_url
            .as_deref()
            .context("V7 exchange Redis URL missing")?;

        let (discovery, engine_discovery) = load_v7_discovery_pair(config)?;
        let registry =
            crate::v7_registry::load_read_only(&config.native_bearer_v7_config.registry_path)?;
        crate::v7_registry::validate_issuer_compatibility(&registry, &config.issuer_id)?;
        discovery
            .validate()
            .map_err(|error| anyhow::anyhow!(error.0))?;
        let receipt_keys = load_v7_receipt_keys(config)?;
        let store = crate::exchange::v7_store::V7ExchangeStore::new(redis_url)?;
        validate_v7_exchange_inventory_with_registry(&discovery, &inventory, &registry)?;
        let graph_id = discovery.profile.graph_id.clone();
        let exchange = Arc::new(
            crate::exchange::v7::V7ExchangeEngine::new(
                engine_discovery,
                store,
                inventory.clone(),
                receipt_keys,
                config.issuer_id.clone(),
                graph_id,
            )
            .await?,
        );
        let exchange_readiness = Some(crate::readiness::V7ExchangeReadinessState::new(
            exchange.clone(),
            inventory.clone(),
            discovery.clone(),
        ));

        let (graph, graph_discovery, graph_readiness, replay_authority) =
            if config.exchange_config.graph_issuance.enabled {
                let graph_config = load_v7_graph_discovery(config)?;
                crate::graph_issuance::V7GraphIssuanceEngine::validate_configuration(
                    &config.issuer_id,
                    &graph_config,
                    &discovery,
                    &inventory,
                )?;
                let authorization = match &config.exchange_config.graph_issuance.authorization {
                    crate::config::GraphIssuanceAuthorizationConfig::V4Local { keys } => Arc::new(
                        crate::graph_issuance::V4LocalGraphIssuanceAuthorizer::new(keys.clone())?,
                    ),
                    _ => bail!("V7 graph issuance requires v4_local authorization"),
                };
                let first = graph_config
                    .active_policies
                    .first()
                    .or_else(|| graph_config.retained_policies.first())
                    .context("V7 graph policy list is empty")?;
                let auth_policy = v7_authorization_policy(config, first)?;
                let graph = Arc::new(
                    crate::graph_issuance::V7GraphIssuanceEngine::new_with_authorization(
                        config.issuer_id.clone(),
                        graph_config,
                        Arc::new(discovery.clone()),
                        inventory.clone(),
                        redis_url,
                        auth_policy,
                        authorization,
                    )?,
                );
                graph.validate_bindings()?;
                let replay_authority = if matches!(
                    config.exchange_config.graph_issuance.authorization,
                    crate::config::GraphIssuanceAuthorizationConfig::V4Local { .. }
                ) {
                    let scope = freebird_crypto::build_scope_digest(
                        &config.exchange_config.graph_issuance.v7_verifier_id,
                        &config.exchange_config.graph_issuance.v7_audience,
                    )
                    .map_err(|error| anyhow::anyhow!("invalid V4 replay scope: {error:?}"))?;
                    let authority =
                        Arc::new(crate::replay_authority::ReplayAuthority::new(redis_url)?);
                    authority.initialize(&[scope]).await?;
                    Some(authority)
                } else {
                    None
                };
                let discovery = graph.discovery(time::OffsetDateTime::now_utc().unix_timestamp());
                discovery
                    .validate()
                    .map_err(|error| anyhow::anyhow!(error.0))?;
                let readiness =
                    crate::readiness::V7GraphIssuanceReadinessState::new(graph.clone(), true);
                (
                    Some(graph),
                    Some(discovery),
                    Some(readiness),
                    replay_authority,
                )
            } else {
                (None, None, None, None)
            };

        Ok(Self {
            native_exchange_v7: Some(exchange),
            native_exchange_v7_discovery: Some(discovery),
            native_graph_issuance_v7: graph,
            native_graph_issuance_v7_discovery: graph_discovery,
            native_exchange_v7_readiness: exchange_readiness,
            native_graph_issuance_v7_readiness: graph_readiness,
            replay_authority,
        })
    }
}

pub fn validate_v7_runtime_config(config: &crate::config::Config) -> Result<()> {
    validate_graph_exchange_enablement(
        config.exchange_config.enabled,
        config.exchange_config.graph_issuance.enabled,
    )?;
    if !config.exchange_config.enabled {
        return Ok(());
    }
    let discovery = load_v7_discovery(config)?;
    let registry =
        crate::v7_registry::load_read_only(&config.native_bearer_v7_config.registry_path)?;
    crate::v7_registry::validate_issuer_compatibility(&registry, &config.issuer_id)?;
    discovery
        .validate()
        .map_err(|error| anyhow::anyhow!(error.0))?;
    let signer_configs = std::iter::once(config.native_bearer_v7_config.clone())
        .chain(crate::config::load_v7_additional_signer_configs()?)
        .collect::<Vec<_>>();
    let mut signers = Vec::with_capacity(signer_configs.len());
    for (index, signer_config) in signer_configs.iter().enumerate() {
        let spec =
            crate::v7_signers::V7SignerSpec::from_native_config(signer_config, &config.issuer_id)?;
        if index != 0 && (!spec.sk_path.is_file() || !spec.metadata_path.is_file()) {
            continue;
        }
        signers.push(Arc::new(crate::v7_signers::V7Signer::load_existing(
            &spec, true,
        )?));
    }
    let inventory = Arc::new(crate::v7_signers::V7SignerInventory::from_signers(
        signers
            .first()
            .cloned()
            .context("V7 signer inventory is empty")?,
        signers,
        None,
    )?);
    validate_v7_exchange_inventory_with_registry(&discovery, &inventory, &registry)?;
    let _receipt_keys = load_v7_receipt_keys(config)?;

    if config.exchange_config.graph_issuance.enabled {
        validate_v7_graph_redis_url(config)?;
        if !matches!(
            config.exchange_config.graph_issuance.authorization,
            crate::config::GraphIssuanceAuthorizationConfig::V4Local { .. }
        ) {
            bail!("V7 graph issuance requires v4_local authorization")
        }
        let graph = load_v7_graph_discovery(config)?;
        crate::graph_issuance::V7GraphIssuanceEngine::validate_configuration(
            &config.issuer_id,
            &graph,
            &discovery,
            &inventory,
        )?;
        let first = graph
            .active_policies
            .first()
            .or_else(|| graph.retained_policies.first())
            .context("V7 graph policy list is empty")?;
        let auth_policy = v7_authorization_policy(config, first)?;
        auth_policy.validate()?;
        let authorization = match &config.exchange_config.graph_issuance.authorization {
            crate::config::GraphIssuanceAuthorizationConfig::V4Local { keys } => Arc::new(
                crate::graph_issuance::V4LocalGraphIssuanceAuthorizer::new(keys.clone())?,
            ),
            _ => unreachable!("V7 graph authorization was checked above"),
        };
        crate::graph_issuance::GraphIssuanceAuthorizer::validate_policy_configuration(
            authorization.as_ref(),
            &auth_policy,
        )?;
    }
    Ok(())
}

fn validate_v7_graph_redis_url(config: &crate::config::Config) -> Result<()> {
    let redis_url = config
        .exchange_config
        .redis_url
        .as_deref()
        .context("V7 graph Redis URL missing")?;
    redis::Client::open(redis_url).context("invalid V7 graph Redis URL")?;
    Ok(())
}

fn validate_graph_exchange_enablement(exchange_enabled: bool, graph_enabled: bool) -> Result<()> {
    if graph_enabled && !exchange_enabled {
        bail!("V7 graph issuance requires the V7 exchange runtime")
    }
    Ok(())
}

fn load_v7_discovery(
    config: &crate::config::Config,
) -> Result<freebird_common::api::NativeExchangeV3Discovery> {
    Ok(load_v7_discovery_pair(config)?.0)
}

/// Load the complete public discovery and the private engine projection.
/// Retained descriptors/keysets remain available to recovery, but retained
/// transitions are deliberately absent from the fresh-issuance lookup table.
fn load_v7_discovery_pair(
    config: &crate::config::Config,
) -> Result<(
    freebird_common::api::NativeExchangeV3Discovery,
    freebird_common::api::NativeExchangeV3Discovery,
)> {
    let mut discovery: freebird_common::api::NativeExchangeV3Discovery = serde_json::from_slice(
        &std::fs::read(&config.exchange_config.active_graph_path).with_context(|| {
            format!(
                "read V7 exchange discovery {}",
                config.exchange_config.active_graph_path.display()
            )
        })?,
    )
    .context("parse V7 exchange discovery")?;
    let retained_snapshots = config
        .exchange_config
        .retained_graph_paths
        .iter()
        .map(|path| {
            serde_json::from_slice(&std::fs::read(path).with_context(|| {
                format!("read retained V7 exchange discovery {}", path.display())
            })?)
            .context("parse retained V7 exchange discovery")
        })
        .collect::<Result<Vec<freebird_common::api::NativeExchangeV3Discovery>>>()?;
    let active_transitions = discovery.transitions.clone();
    merge_v7_discovery(&mut discovery, retained_snapshots)?;
    let mut engine_discovery = discovery.clone();
    engine_discovery.transitions = active_transitions;
    Ok((discovery, engine_discovery))
}

fn merge_v7_discovery(
    discovery: &mut freebird_common::api::NativeExchangeV3Discovery,
    retained_snapshots: Vec<freebird_common::api::NativeExchangeV3Discovery>,
) -> Result<()> {
    for retained in retained_snapshots {
        if retained.version != discovery.version || retained.profile != discovery.profile {
            bail!("retained V7 exchange discovery profile is incompatible with the active profile")
        }
        discovery
            .retained_descriptors
            .extend(retained.active_descriptors);
        discovery
            .retained_descriptors
            .extend(retained.retained_descriptors);
        discovery.retained_keysets.extend(retained.active_keysets);
        discovery.retained_keysets.extend(retained.retained_keysets);
        discovery.transitions.extend(retained.transitions);
    }
    Ok(())
}

fn load_v7_receipt_keys(config: &crate::config::Config) -> Result<crate::exchange::ReceiptKeyRing> {
    let read = |path: &std::path::Path| -> Result<crate::exchange::ReceiptKeyMetadata> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    };
    let active = crate::exchange::ReceiptKeyConfig {
        metadata: read(&config.exchange_config.active_receipt_metadata_path)?,
        private_key_path: config.exchange_config.active_receipt_key_path.clone(),
    };
    let retained = config
        .exchange_config
        .retained_receipt_key_paths
        .iter()
        .zip(&config.exchange_config.retained_receipt_metadata_paths)
        .map(|(key, metadata)| {
            Ok(crate::exchange::ReceiptKeyConfig {
                metadata: read(metadata)?,
                private_key_path: key.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    crate::exchange::ReceiptKeyRing::load_v7(active, &retained)
}

pub(crate) fn validate_v7_exchange_inventory(
    discovery: &freebird_common::api::NativeExchangeV3Discovery,
    inventory: &crate::v7_signers::V7SignerInventory,
) -> Result<()> {
    validate_v7_exchange_inventory_with_registry(discovery, inventory, inventory.registry())
}

pub(crate) fn validate_v7_exchange_inventory_with_registry(
    discovery: &freebird_common::api::NativeExchangeV3Discovery,
    inventory: &crate::v7_signers::V7SignerInventory,
    registry: &freebird_common::v7_registry::BearerKeyRegistry,
) -> Result<()> {
    crate::v7_registry::validate_issuer_compatibility(
        registry,
        inventory.active().identity().issuer_id(),
    )?;
    let descriptors = discovery
        .active_descriptors
        .iter()
        .chain(discovery.retained_descriptors.iter())
        .map(|descriptor| (descriptor.descriptor_id.as_str(), descriptor))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut required = std::collections::BTreeSet::new();
    for transition in &discovery.transitions {
        required.extend(
            transition
                .output_slots
                .iter()
                .map(|slot| slot.descriptor_id.as_str()),
        );
    }
    for descriptor in discovery
        .active_descriptors
        .iter()
        .chain(discovery.retained_descriptors.iter())
    {
        descriptor
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        registry
            .validate_exchange_descriptor(descriptor)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    }
    for descriptor_id in required {
        if !descriptors.contains_key(descriptor_id) {
            bail!("V7 exchange output references unknown descriptor")
        }
        let descriptor = descriptors[descriptor_id];
        let token_key_id: [u8; 32] = hex::decode(&descriptor.token_key_id)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid V7 exchange token key ID"))?;
        let identity = crate::v7_signers::V7SignerIdentity::new(
            descriptor.issuer_id.clone(),
            descriptor.profile_id.clone(),
            descriptor.descriptor_id.clone(),
            freebird_crypto::V7TokenKeyId::new(token_key_id),
        )?;
        let signer = inventory.lookup(&identity).map_err(|_| {
            anyhow::anyhow!(
                "V7 exchange output descriptor {} requires private signer material",
                descriptor_id
            )
        })?;
        if !exchange_descriptor_matches_signer(descriptor, signer) {
            bail!("V7 exchange output descriptor does not match private signer inventory")
        }
    }
    Ok(())
}

fn exchange_descriptor_matches_signer(
    descriptor: &freebird_common::api::NativeExchangeV3Descriptor,
    signer: &crate::v7_signers::V7Signer,
) -> bool {
    let metadata = signer.metadata();
    metadata.profile_id == descriptor.profile_id
        && metadata.issuer_id == descriptor.issuer_id
        && metadata.descriptor_id == descriptor.descriptor_id
        && metadata.token_key_id == descriptor.token_key_id
        && metadata.asset_id == descriptor.asset_id
        && metadata.amount_minor.to_string() == descriptor.amount_minor
        && metadata.suite == descriptor.suite
        && metadata.modulus_bits == descriptor.modulus_bits
        && metadata.exponent == descriptor.exponent
        && metadata.pubkey_spki_b64 == descriptor.pubkey_spki_b64
        && metadata.spki_fingerprint == descriptor.spki_fingerprint
        && u64::try_from(metadata.valid_from).ok() == Some(descriptor.valid_from)
        && u64::try_from(metadata.valid_until).ok() == Some(descriptor.valid_until)
}

fn load_v7_graph_discovery(
    config: &crate::config::Config,
) -> Result<freebird_common::api::NativeGraphIssuanceV7Discovery> {
    let bytes = std::fs::read(&config.exchange_config.graph_issuance.policy_path)?;
    parse_v7_graph_discovery(&bytes)
}

fn parse_v7_graph_discovery(
    bytes: &[u8],
) -> Result<freebird_common::api::NativeGraphIssuanceV7Discovery> {
    let discovery =
        match serde_json::from_slice::<freebird_common::api::NativeGraphIssuanceV7Discovery>(bytes)
        {
            Ok(discovery) => discovery,
            Err(_) => {
                let policies: Vec<freebird_common::api::NativeGraphIssuanceV7Policy> =
                    serde_json::from_slice(bytes).context("parse V7 graph policy list")?;
                freebird_common::api::NativeGraphIssuanceV7Discovery {
                    version: freebird_common::api::NATIVE_GRAPH_ISSUANCE_V7_VERSION,
                    profile_id: freebird_common::api::NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
                    active_policies: policies,
                    retained_policies: Vec::new(),
                }
            }
        };
    discovery
        .validate()
        .map_err(|error| anyhow::anyhow!(error.0))?;
    if discovery.active_policies.is_empty() && discovery.retained_policies.is_empty() {
        bail!("V7 graph policy list is empty")
    }
    Ok(discovery)
}

fn v7_authorization_policy(
    config: &crate::config::Config,
    policy: &freebird_common::api::NativeGraphIssuanceV7Policy,
) -> Result<crate::graph_issuance::GraphIssuancePolicy> {
    let keys = match &config.exchange_config.graph_issuance.authorization {
        crate::config::GraphIssuanceAuthorizationConfig::V4Local { keys } => keys,
        _ => bail!("V7 graph issuance requires v4_local authorization"),
    };
    let mut trusted = std::collections::BTreeMap::<String, Vec<String>>::new();
    for key in keys {
        trusted
            .entry(key.issuer_id.clone())
            .or_default()
            .push(key.kid.clone());
    }
    Ok(crate::graph_issuance::GraphIssuancePolicy {
        issuance_policy_id: policy.policy_id.clone(),
        graph_id: policy.graph_id.clone(),
        keyset_id: policy.keyset_id.clone(),
        descriptor_id: policy.descriptor_id.clone(),
        budget_id: format!("v7:{}", policy.policy_id),
        budget_limit: 1,
        quantity: 1,
        admission_state: crate::graph_issuance::GraphIssuanceAdmissionState::AcceptingNew,
        authorization_scheme: "v4_local".into(),
        v4_local: Some(crate::graph_issuance::GraphIssuanceV4LocalPolicy {
            verifier_id: config.exchange_config.graph_issuance.v7_verifier_id.clone(),
            audience: config.exchange_config.graph_issuance.v7_audience.clone(),
            trusted_issuers: trusted
                .into_iter()
                .map(
                    |(issuer_id, key_ids)| crate::graph_issuance::GraphIssuanceV4TrustedIssuer {
                        issuer_id,
                        key_ids,
                    },
                )
                .collect(),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{
            Config, ExchangeConfig, GraphIssuanceAuthorizationConfig, GraphIssuanceConfig,
            GraphIssuanceV4VerificationKey, KeyConfig, NativeBearerV7Config, SybilConfig,
        },
        v7_signers::{V7Signer, V7SignerInventory, V7SignerSpec},
    };
    use base64ct::{Base64UrlUnpadded, Encoding};
    use ed25519_dalek::SigningKey;
    use freebird_common::api::{
        NativeExchangeV3Descriptor, NativeExchangeV3Discovery, NativeExchangeV3Keyset,
        NativeExchangeV3Profile, NativeExchangeV3Slot, NativeExchangeV3Transition,
        NativeGraphIssuanceV7Discovery, NativeGraphIssuanceV7Policy, NATIVE_EXCHANGE_V3_PROFILE_ID,
        NATIVE_EXCHANGE_V3_SUITE, NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID,
    };
    use sha2::{Digest, Sha256};
    use std::{collections::BTreeMap, path::Path, sync::Arc};
    use tempfile::{tempdir, TempDir};

    fn signer_config(root: &Path, byte: u8) -> NativeBearerV7Config {
        NativeBearerV7Config {
            sk_path: root.join(format!("{byte}.der")),
            metadata_path: root.join(format!("{byte}.json")),
            registry_path: root.join("registry.json"),
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            descriptor_id: String::new(),
            token_key_id: format!("{byte:02x}").repeat(32),
            asset_id: "USD".into(),
            amount_minor: 1,
            validity_secs: 86_400,
        }
    }

    fn descriptor(signer: &crate::v7_signers::V7Signer) -> NativeExchangeV3Descriptor {
        let metadata = signer.metadata();
        NativeExchangeV3Descriptor {
            descriptor_id: metadata.descriptor_id.clone(),
            profile_id: metadata.profile_id.clone(),
            issuer_id: metadata.issuer_id.clone(),
            token_key_id: metadata.token_key_id.clone(),
            asset_id: metadata.asset_id.clone(),
            amount_minor: metadata.amount_minor.to_string(),
            suite: metadata.suite.clone(),
            modulus_bits: metadata.modulus_bits,
            exponent: metadata.exponent,
            pubkey_spki_b64: metadata.pubkey_spki_b64.clone(),
            spki_fingerprint: metadata.spki_fingerprint.clone(),
            valid_from: metadata.valid_from as u64,
            valid_until: metadata.valid_until as u64,
        }
    }

    struct Fixture {
        _directory: TempDir,
        source: NativeExchangeV3Descriptor,
        output: NativeExchangeV3Descriptor,
        source_inventory: Arc<V7SignerInventory>,
        output_inventory: Arc<V7SignerInventory>,
        registry: freebird_common::v7_registry::BearerKeyRegistry,
        registry_path: std::path::PathBuf,
    }

    fn fixture() -> Fixture {
        let directory = tempdir().unwrap();
        let registry_path = directory.path().join("registry.json");
        let source_inventory = Arc::new(
            V7SignerInventory::load_or_generate(
                crate::v7_signers::V7SignerSpec::from_native_config(
                    &signer_config(directory.path(), 0x11),
                    "issuer:test",
                )
                .unwrap(),
                Vec::new(),
                &registry_path,
            )
            .unwrap(),
        );
        let source = descriptor(source_inventory.active());
        std::fs::remove_file(&signer_config(directory.path(), 0x11).sk_path).unwrap();
        std::fs::remove_file(&signer_config(directory.path(), 0x11).metadata_path).unwrap();
        let output_inventory = Arc::new(
            V7SignerInventory::load_or_generate(
                crate::v7_signers::V7SignerSpec::from_native_config(
                    &signer_config(directory.path(), 0x22),
                    "issuer:test",
                )
                .unwrap(),
                Vec::new(),
                &registry_path,
            )
            .unwrap(),
        );
        let output = descriptor(output_inventory.active());
        Fixture {
            _directory: directory,
            source,
            output,
            source_inventory,
            registry: output_inventory.registry().clone(),
            output_inventory,
            registry_path,
        }
    }

    fn discovery(
        source: &NativeExchangeV3Descriptor,
        output: &NativeExchangeV3Descriptor,
    ) -> NativeExchangeV3Discovery {
        NativeExchangeV3Discovery {
            version: 3,
            profile: freebird_common::api::NativeExchangeV3Profile {
                version: 3,
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                graph_id: "00".repeat(32),
                suite: freebird_common::api::NATIVE_EXCHANGE_V3_SUITE.into(),
                modulus_bits: 3_072,
                exponent: 65_537,
            },
            active_descriptors: vec![output.clone()],
            retained_descriptors: vec![source.clone()],
            active_keysets: Vec::new(),
            retained_keysets: Vec::new(),
            transitions: vec![NativeExchangeV3Transition {
                transition_id: "11".repeat(32),
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                source_keyset_id: "22".repeat(32),
                target_keyset_id: "33".repeat(32),
                source_slots: vec![NativeExchangeV3Slot {
                    descriptor_id: source.descriptor_id.clone(),
                    keyset_id: "22".repeat(32),
                    slot_id: "source".into(),
                    quantity: 1,
                }],
                output_slots: vec![NativeExchangeV3Slot {
                    descriptor_id: output.descriptor_id.clone(),
                    keyset_id: "33".repeat(32),
                    slot_id: "output".into(),
                    quantity: 1,
                }],
            }],
        }
    }

    #[test]
    fn retained_source_descriptor_needs_registry_history_not_private_key() {
        let fixture = fixture();
        validate_v7_exchange_inventory_with_registry(
            &discovery(&fixture.source, &fixture.output),
            &fixture.output_inventory,
            &fixture.registry,
        )
        .unwrap();
    }

    #[test]
    fn public_only_retained_source_validation_is_read_only() {
        let fixture = fixture();
        let before = std::fs::read(&fixture.registry_path).unwrap();
        let registry = crate::v7_registry::load_read_only(&fixture.registry_path).unwrap();
        crate::v7_registry::validate_issuer_compatibility(&registry, "issuer:test").unwrap();
        validate_v7_exchange_inventory_with_registry(
            &discovery(&fixture.source, &fixture.output),
            &fixture.output_inventory,
            &registry,
        )
        .unwrap();
        assert_eq!(before, std::fs::read(&fixture.registry_path).unwrap());
        assert!(
            !std::path::PathBuf::from(format!("{}.lock", fixture.registry_path.display())).exists()
        );
        let temporary_prefix = format!(
            ".{}.tmp.",
            fixture
                .registry_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap()
        );
        assert!(std::fs::read_dir(fixture.registry_path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| {
                !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&temporary_prefix)
            }));
    }

    #[test]
    fn missing_output_signer_is_rejected() {
        let fixture = fixture();
        let error = validate_v7_exchange_inventory_with_registry(
            &discovery(&fixture.source, &fixture.output),
            &fixture.source_inventory,
            &fixture.registry,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("requires private signer material"));
    }

    #[test]
    fn missing_retained_transition_output_signer_is_rejected() {
        let fixture = fixture();
        let mut discovery = discovery(&fixture.source, &fixture.output);
        discovery.active_descriptors.clear();
        discovery.retained_descriptors = vec![fixture.source.clone(), fixture.output.clone()];
        let error = validate_v7_exchange_inventory_with_registry(
            &discovery,
            &fixture.source_inventory,
            &fixture.registry,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("requires private signer material"));
    }

    #[test]
    fn descriptor_must_match_durable_registry_history() {
        let fixture = fixture();
        let mut mismatch = fixture.source.clone();
        mismatch.asset_id = "EUR".into();
        mismatch.descriptor_id = freebird_common::api::derive_native_exchange_v3_descriptor_id(
            &mismatch.profile_id,
            &mismatch.issuer_id,
            &mismatch.token_key_id,
            &mismatch.asset_id,
            mismatch.amount_minor.parse().unwrap(),
            &mismatch.suite,
            mismatch.modulus_bits,
            mismatch.exponent,
            &base64ct::Base64UrlUnpadded::decode_vec(&mismatch.pubkey_spki_b64).unwrap(),
            &mismatch.spki_fingerprint,
            mismatch.valid_from,
            mismatch.valid_until,
        )
        .unwrap();
        let error = validate_v7_exchange_inventory_with_registry(
            &discovery(&mismatch, &fixture.output),
            &fixture.output_inventory,
            &fixture.registry,
        )
        .unwrap_err();
        assert!(error.to_string().contains("durable registry history"));
    }

    #[test]
    fn graph_policy_container_and_vector_forms_share_collection_validation() {
        let document: serde_json::Value = serde_json::from_str(include_str!(
            "../../../common/test-fixtures/v7-graph-reference.json"
        ))
        .unwrap();
        let mut graph = document["native_graph_issuance_v7"].clone();
        graph["retained_policies"] = serde_json::json!([graph["active_policies"][0].clone()]);
        graph["active_policies"] = serde_json::json!([]);
        let container_bytes = serde_json::to_vec(&graph).unwrap();
        let vector_bytes = serde_json::to_vec(&graph["retained_policies"]).unwrap();
        let container = parse_v7_graph_discovery(&container_bytes).unwrap();
        let vector = parse_v7_graph_discovery(&vector_bytes).unwrap();
        assert_eq!(container.retained_policies, vector.active_policies);
        assert!(vector.retained_policies.is_empty());
        assert!(container.active_policies.is_empty());
        assert_eq!(container.retained_policies.len(), 1);

        let mut duplicate = graph.clone();
        duplicate["active_policies"] = duplicate["retained_policies"].clone();
        assert!(parse_v7_graph_discovery(&serde_json::to_vec(&duplicate).unwrap()).is_err());
        let duplicate_vector = serde_json::json!([
            duplicate["retained_policies"][0].clone(),
            duplicate["retained_policies"][0].clone()
        ]);
        assert!(parse_v7_graph_discovery(&serde_json::to_vec(&duplicate_vector).unwrap()).is_err());

        let mut changed_id = graph;
        changed_id["retained_policies"][0]["policy_id"] = "00".repeat(32).into();
        assert!(parse_v7_graph_discovery(&serde_json::to_vec(&changed_id).unwrap()).is_err());
    }

    #[test]
    fn graph_issuance_cannot_be_enabled_without_exchange_runtime() {
        assert!(validate_graph_exchange_enablement(false, true).is_err());
        assert!(validate_graph_exchange_enablement(false, false).is_ok());
        assert!(validate_graph_exchange_enablement(true, true).is_ok());
    }

    struct OfflineGraphFixture {
        directory: TempDir,
        config: Config,
        exchange_config: NativeBearerV7Config,
        exchange_discovery: NativeExchangeV3Discovery,
        graph_discovery: NativeGraphIssuanceV7Discovery,
        inventory: Arc<V7SignerInventory>,
        extra_signer_config_path: std::path::PathBuf,
    }

    fn lp32(transcript: &mut Vec<u8>, bytes: &[u8]) {
        transcript.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        transcript.extend_from_slice(bytes);
    }

    fn canonical_keyset_id(descriptor_ids: &[String]) -> String {
        let mut transcript = Vec::new();
        for descriptor_id in descriptor_ids {
            lp32(&mut transcript, descriptor_id.as_bytes());
        }
        hex::encode(Sha256::digest(
            [
                b"freebird native exchange keyset v3\0".as_slice(),
                transcript.as_slice(),
            ]
            .concat(),
        ))
    }

    fn canonical_graph_id(exchange: &NativeExchangeV3Discovery) -> String {
        let mut transcript = Vec::new();
        lp32(&mut transcript, exchange.profile.profile_id.as_bytes());
        for keyset in exchange
            .active_keysets
            .iter()
            .chain(&exchange.retained_keysets)
        {
            lp32(&mut transcript, keyset.keyset_id.as_bytes());
        }
        for transition in &exchange.transitions {
            lp32(&mut transcript, transition.transition_id.as_bytes());
        }
        hex::encode(Sha256::digest(
            [
                b"freebird native exchange graph v3\0".as_slice(),
                transcript.as_slice(),
            ]
            .concat(),
        ))
    }

    fn canonical_policy_id(policy: &NativeGraphIssuanceV7Policy) -> String {
        let mut transcript = Vec::new();
        for value in [
            &policy.profile_id,
            &policy.graph_id,
            &policy.keyset_id,
            &policy.descriptor_id,
            &policy.token_key_id,
            &policy.issuer_id,
            &policy.asset_id,
            &policy.amount_minor,
            &policy.suite,
        ] {
            lp32(&mut transcript, value.as_bytes());
        }
        transcript.extend_from_slice(&policy.modulus_bits.to_be_bytes());
        transcript.extend_from_slice(&policy.exponent.to_be_bytes());
        transcript.extend_from_slice(&policy.quantity.to_be_bytes());
        let spki = Base64UrlUnpadded::decode_vec(&policy.pubkey_spki_b64).unwrap();
        lp32(&mut transcript, &spki);
        lp32(&mut transcript, policy.spki_fingerprint.as_bytes());
        transcript.extend_from_slice(&(policy.valid_from as u64).to_be_bytes());
        transcript.extend_from_slice(&(policy.valid_until as u64).to_be_bytes());
        hex::encode(Sha256::digest(
            [
                b"freebird native graph issuance policy v7\0".as_slice(),
                transcript.as_slice(),
            ]
            .concat(),
        ))
    }

    fn offline_graph_fixture() -> OfflineGraphFixture {
        let directory = tempdir().unwrap();
        let registry_path = directory.path().join("registry.json");
        let mut direct_config = signer_config(directory.path(), 0x31);
        direct_config.profile_id = freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID.into();
        direct_config.amount_minor = 42;
        direct_config.registry_path = registry_path.clone();
        let mut exchange_config = signer_config(directory.path(), 0x32);
        exchange_config.amount_minor = 42;
        exchange_config.validity_secs = 1;
        exchange_config.registry_path = registry_path.clone();

        let direct_spec = V7SignerSpec::from_native_config(&direct_config, "issuer:test").unwrap();
        let exchange_spec =
            V7SignerSpec::from_native_config(&exchange_config, "issuer:test").unwrap();
        let _direct_created =
            V7SignerInventory::load_or_generate(direct_spec.clone(), Vec::new(), &registry_path)
                .unwrap();
        let _exchange_created =
            V7SignerInventory::load_or_generate(exchange_spec.clone(), Vec::new(), &registry_path)
                .unwrap();
        let direct = Arc::new(V7Signer::load_existing(&direct_spec, true).unwrap());
        let exchange_signer = Arc::new(V7Signer::load_existing(&exchange_spec, true).unwrap());
        let inventory = Arc::new(
            V7SignerInventory::from_signers(
                direct.clone(),
                vec![direct, exchange_signer.clone()],
                None,
            )
            .unwrap(),
        );
        let descriptor = descriptor(&exchange_signer);
        let keyset_id = canonical_keyset_id(std::slice::from_ref(&descriptor.descriptor_id));
        let exchange = NativeExchangeV3Discovery {
            version: 3,
            profile: NativeExchangeV3Profile {
                version: 3,
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                graph_id: String::new(),
                suite: NATIVE_EXCHANGE_V3_SUITE.into(),
                modulus_bits: 3072,
                exponent: 65_537,
            },
            active_descriptors: vec![descriptor.clone()],
            retained_descriptors: Vec::new(),
            active_keysets: vec![NativeExchangeV3Keyset {
                keyset_id: keyset_id.clone(),
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                descriptor_ids: vec![descriptor.descriptor_id.clone()],
            }],
            retained_keysets: Vec::new(),
            transitions: Vec::new(),
        };
        let mut exchange = exchange;
        exchange.profile.graph_id = canonical_graph_id(&exchange);
        let mut policy = NativeGraphIssuanceV7Policy {
            policy_id: String::new(),
            profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
            graph_id: exchange.profile.graph_id.clone(),
            keyset_id,
            descriptor_id: descriptor.descriptor_id.clone(),
            token_key_id: descriptor.token_key_id.clone(),
            issuer_id: descriptor.issuer_id.clone(),
            asset_id: descriptor.asset_id.clone(),
            amount_minor: descriptor.amount_minor.clone(),
            suite: descriptor.suite.clone(),
            modulus_bits: descriptor.modulus_bits,
            exponent: descriptor.exponent,
            quantity: 1,
            pubkey_spki_b64: descriptor.pubkey_spki_b64.clone(),
            spki_fingerprint: descriptor.spki_fingerprint.clone(),
            valid_from: descriptor.valid_from as i64,
            valid_until: descriptor.valid_until as i64,
        };
        policy.policy_id = canonical_policy_id(&policy);
        let graph = NativeGraphIssuanceV7Discovery {
            version: 7,
            profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
            active_policies: vec![policy],
            retained_policies: Vec::new(),
        };

        let receipt_key_path = directory.path().join("receipt.key");
        let receipt_signing = SigningKey::from_bytes(&[0x77; 32]);
        std::fs::write(&receipt_key_path, [0x77; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&receipt_key_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let receipt_metadata = crate::exchange::ReceiptKeyMetadata {
            key_id: hex::encode(Sha256::digest(receipt_signing.verifying_key().as_bytes())),
            algorithm: "Ed25519".into(),
            purpose: "exchange_receipt_v7".into(),
            public_key_b64: Base64UrlUnpadded::encode_string(
                receipt_signing.verifying_key().as_bytes(),
            ),
            valid_from: 1,
            valid_until: freebird_common::api::EXCHANGE_MAX_VALID_UNTIL as u64,
        };
        let receipt_metadata_path = directory.path().join("receipt.json");
        std::fs::write(
            &receipt_metadata_path,
            serde_json::to_vec(&receipt_metadata).unwrap(),
        )
        .unwrap();
        let exchange_path = directory.path().join("exchange.json");
        std::fs::write(&exchange_path, serde_json::to_vec(&exchange).unwrap()).unwrap();
        let policy_path = directory.path().join("graph-policy.json");
        std::fs::write(&policy_path, serde_json::to_vec(&graph).unwrap()).unwrap();
        let extra_signer_config_path = directory.path().join("additional-signers.json");
        std::fs::write(
            &extra_signer_config_path,
            serde_json::to_vec(&vec![exchange_config.clone()]).unwrap(),
        )
        .unwrap();
        let config = Config {
            issuer_id: "issuer:test".into(),
            bind_addr: "127.0.0.1:8081".parse().unwrap(),
            require_tls: false,
            behind_proxy: false,
            key_config: KeyConfig {
                sk_path: directory.path().join("voprf.key"),
                rotation_state_path: directory.path().join("rotation.json"),
                kid_override: None,
                hsm: None,
            },
            native_bearer_v7_config: direct_config.clone(),
            exchange_config: ExchangeConfig {
                enabled: true,
                active_graph_path: exchange_path,
                retained_graph_paths: Vec::new(),
                active_receipt_key_path: receipt_key_path,
                active_receipt_metadata_path: receipt_metadata_path,
                retained_receipt_key_paths: Vec::new(),
                retained_receipt_metadata_paths: Vec::new(),
                redis_url: Some("redis://127.0.0.1:1".into()),
                receipt_lifetime_secs: 2_592_000,
                request_body_limit: 1_048_576,
                request_timeout_secs: 30,
                graph_issuance: GraphIssuanceConfig {
                    enabled: true,
                    policy_path,
                    v7_verifier_id: "verifier:test".into(),
                    v7_audience: "audience:test".into(),
                    authorization: GraphIssuanceAuthorizationConfig::V4Local {
                        keys: vec![GraphIssuanceV4VerificationKey {
                            issuer_id: "v4-issuer:test".into(),
                            kid: "v4-kid:test".into(),
                            secret_key: [0x55; 32],
                        }],
                    },
                },
            },
            sybil_config: SybilConfig {
                mode: "none".into(),
                pow_difficulty: 0,
                rate_limit_secs: 0,
                invite_per_user: 0,
                invite_cooldown_secs: 0,
                invite_expires_secs: 0,
                invite_new_user_wait_secs: 0,
                invite_persistence_path: directory.path().join("invites.json"),
                invite_autosave_interval_secs: 0,
                invite_signing_key_path: directory.path().join("invite.key"),
                bootstrap_users: None,
                webauthn_max_proof_age: None,
                progressive_trust_levels: Vec::new(),
                progressive_trust_persistence_path: directory.path().join("trust.json"),
                progressive_trust_autosave_interval: 0,
                progressive_trust_hmac_secret: None,
                progressive_trust_hmac_secret_path: directory.path().join("trust.secret"),
                progressive_trust_salt: String::new(),
                progressive_trust_allow_insecure: false,
                proof_of_diversity_min_score: 0,
                proof_of_diversity_persistence_path: directory.path().join("diversity.json"),
                proof_of_diversity_autosave_interval: 0,
                proof_of_diversity_hmac_secret: None,
                proof_of_diversity_hmac_secret_path: directory.path().join("diversity.secret"),
                proof_of_diversity_fingerprint_salt: String::new(),
                proof_of_diversity_allow_insecure: false,
                multi_party_vouching_required_vouchers: 0,
                multi_party_vouching_cooldown_secs: 0,
                multi_party_vouching_expires_secs: 0,
                multi_party_vouching_new_user_wait_secs: 0,
                multi_party_vouching_persistence_path: directory.path().join("vouches.json"),
                multi_party_vouching_autosave_interval: 0,
                multi_party_vouching_hmac_secret: None,
                multi_party_vouching_hmac_secret_path: directory.path().join("vouches.secret"),
                multi_party_vouching_salt: String::new(),
                multi_party_vouching_allow_insecure: false,
                social_graph_attesters_path: directory.path().join("attesters.json"),
                social_graph_jwks_url: None,
                social_graph_key_refresh_interval_secs: 0,
                social_graph_min_level: 0,
                social_graph_accepted_policy_ids: Vec::new(),
                social_graph_attestation_max_age_secs: 0,
                social_graph_clock_skew_secs: 0,
                social_graph_require_request_binding: false,
                social_graph_require_quota_nullifier: false,
                social_graph_replay_ttl_secs: 0,
                social_graph_state_path: directory.path().join("social.json"),
                social_graph_fail_closed: false,
                combined_mechanisms: Vec::new(),
                combined_mode: "or".into(),
                combined_threshold: 0,
            },
            webauthn_config: None,
            admin_api_key: None,
            epoch_duration_sec: 86_400,
            epoch_retention: 2,
            allow_unsafe_v4_rotation: false,
            audit_log_path: directory.path().join("audit.json"),
            unsafe_development_mode: false,
        };
        OfflineGraphFixture {
            directory,
            config,
            exchange_config,
            exchange_discovery: exchange,
            graph_discovery: graph,
            inventory,
            extra_signer_config_path,
        }
    }

    fn directory_snapshot(path: &Path) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
        std::fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect()
    }

    struct EnvRestore(Option<std::ffi::OsString>);
    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var("NATIVE_V7_SIGNER_CONFIG_PATHS", value),
                None => std::env::remove_var("NATIVE_V7_SIGNER_CONFIG_PATHS"),
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn enabled_offline_validation_is_read_only_for_both_policy_file_shapes() {
        let fixture = offline_graph_fixture();
        let previous = std::env::var_os("NATIVE_V7_SIGNER_CONFIG_PATHS");
        std::env::set_var(
            "NATIVE_V7_SIGNER_CONFIG_PATHS",
            &fixture.extra_signer_config_path,
        );
        let _restore = EnvRestore(previous);

        let policy_path = &fixture.config.exchange_config.graph_issuance.policy_path;
        std::fs::write(
            policy_path,
            serde_json::to_vec(&fixture.graph_discovery).unwrap(),
        )
        .unwrap();
        let container_snapshot = directory_snapshot(fixture.directory.path());
        validate_v7_runtime_config(&fixture.config).unwrap();
        assert_eq!(
            directory_snapshot(fixture.directory.path()),
            container_snapshot
        );

        let policies = fixture
            .graph_discovery
            .active_policies
            .iter()
            .chain(&fixture.graph_discovery.retained_policies)
            .cloned()
            .collect::<Vec<_>>();
        std::fs::write(policy_path, serde_json::to_vec(&policies).unwrap()).unwrap();
        let vector_snapshot = directory_snapshot(fixture.directory.path());
        validate_v7_runtime_config(&fixture.config).unwrap();
        assert_eq!(
            directory_snapshot(fixture.directory.path()),
            vector_snapshot
        );

        let mut malformed_redis = fixture.config.clone();
        malformed_redis.exchange_config.redis_url = Some("not-a-redis-url".into());
        assert!(validate_v7_runtime_config(&malformed_redis).is_err());
        let unreachable_redis = redis::Client::open("redis://127.0.0.1:1").unwrap();
        drop(unreachable_redis);

        let first_policy = &fixture.graph_discovery.active_policies[0];
        let auth_policy = v7_authorization_policy(&fixture.config, first_policy).unwrap();
        let authorizer = Arc::new(
            crate::graph_issuance::V4LocalGraphIssuanceAuthorizer::new(vec![
                GraphIssuanceV4VerificationKey {
                    issuer_id: "v4-issuer:test".into(),
                    kid: "v4-kid:test".into(),
                    secret_key: [0x55; 32],
                },
            ])
            .unwrap(),
        );
        std::thread::sleep(std::time::Duration::from_secs(2));
        let engine = crate::graph_issuance::V7GraphIssuanceEngine::new_with_authorization(
            "issuer:test",
            fixture.graph_discovery.clone(),
            Arc::new(fixture.exchange_discovery.clone()),
            fixture.inventory.clone(),
            "redis://127.0.0.1:1",
            auth_policy,
            authorizer,
        )
        .unwrap();
        engine.validate_bindings().unwrap();
        let policy = &fixture.graph_discovery.active_policies[0];
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        assert!(now > policy.valid_until);
        let retained = engine.discovery(now);
        assert!(retained.active_policies.is_empty());
        assert_eq!(retained.retained_policies.len(), 1);
        retained.validate().unwrap();
        let token_key: [u8; 32] = hex::decode(&policy.token_key_id)
            .unwrap()
            .try_into()
            .unwrap();
        let identity = crate::v7_signers::V7SignerIdentity::new(
            policy.issuer_id.clone(),
            NATIVE_EXCHANGE_V3_PROFILE_ID,
            policy.descriptor_id.clone(),
            freebird_crypto::V7TokenKeyId::new(token_key),
        )
        .unwrap();
        assert!(!fixture
            .inventory
            .lookup(&identity)
            .unwrap()
            .is_valid_at(now));

        let exchange_signer_path = &fixture.exchange_config.sk_path;
        let _public_only_metadata = std::fs::read(&fixture.exchange_config.metadata_path).unwrap();
        std::fs::remove_file(exchange_signer_path).unwrap();
        let after_removal = directory_snapshot(fixture.directory.path());
        assert!(validate_v7_runtime_config(&fixture.config).is_err());
        assert_eq!(directory_snapshot(fixture.directory.path()), after_removal);
    }
}
