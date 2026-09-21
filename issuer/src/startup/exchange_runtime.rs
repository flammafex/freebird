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
        if config.exchange_config.graph_issuance.enabled && !config.exchange_config.enabled {
            bail!("V7 graph issuance requires the V7 exchange runtime")
        }
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
                let policies = load_v7_graph_policies(config)?;
                let authorization = match &config.exchange_config.graph_issuance.authorization {
                    crate::config::GraphIssuanceAuthorizationConfig::V4Local { keys } => Arc::new(
                        crate::graph_issuance::V4LocalGraphIssuanceAuthorizer::new(keys.clone())?,
                    ),
                    _ => bail!("V7 graph issuance requires v4_local authorization"),
                };
                let first = policies.first().context("V7 graph policy list is empty")?;
                let auth_policy = v7_authorization_policy(config, first)?;
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
                let graph = Arc::new(
                    crate::graph_issuance::V7GraphIssuanceEngine::new_with_authorization(
                        config.issuer_id.clone(),
                        policies,
                        inventory.clone(),
                        redis_url,
                        auth_policy,
                        authorization,
                    )?,
                );
                let discovery = graph.discovery(time::OffsetDateTime::now_utc().unix_timestamp());
                discovery
                    .validate()
                    .map_err(|error| anyhow::anyhow!(error.0))?;
                let readiness = crate::readiness::V7GraphIssuanceReadinessState::new(
                    graph.clone(),
                    inventory.clone(),
                    discovery.clone(),
                    true,
                );
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
        if !matches!(
            config.exchange_config.graph_issuance.authorization,
            crate::config::GraphIssuanceAuthorizationConfig::V4Local { .. }
        ) {
            bail!("V7 graph issuance requires v4_local authorization")
        }
        let policies = load_v7_graph_policies(config)?;
        let first = policies.first().context("V7 graph policy list is empty")?;
        let auth_policy = v7_authorization_policy(config, first)?;
        let authorization = match &config.exchange_config.graph_issuance.authorization {
            crate::config::GraphIssuanceAuthorizationConfig::V4Local { keys } => Arc::new(
                crate::graph_issuance::V4LocalGraphIssuanceAuthorizer::new(keys.clone())?,
            ),
            _ => unreachable!("V7 graph authorization was checked above"),
        };
        let graph = crate::graph_issuance::V7GraphIssuanceEngine::new_with_authorization(
            config.issuer_id.clone(),
            policies,
            inventory,
            config
                .exchange_config
                .redis_url
                .as_deref()
                .unwrap_or_default(),
            auth_policy,
            authorization,
        )?;
        graph
            .discovery(time::OffsetDateTime::now_utc().unix_timestamp())
            .validate()
            .map_err(|error| anyhow::anyhow!(error.0))?;
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

fn load_v7_graph_policies(
    config: &crate::config::Config,
) -> Result<Vec<freebird_common::api::NativeGraphIssuanceV7Policy>> {
    let bytes = std::fs::read(&config.exchange_config.graph_issuance.policy_path)?;
    if let Ok(discovery) =
        serde_json::from_slice::<freebird_common::api::NativeGraphIssuanceV7Discovery>(&bytes)
    {
        discovery
            .validate()
            .map_err(|error| anyhow::anyhow!(error.0))?;
        return Ok(discovery
            .active_policies
            .into_iter()
            .chain(discovery.retained_policies)
            .collect());
    }
    let policies: Vec<freebird_common::api::NativeGraphIssuanceV7Policy> =
        serde_json::from_slice(&bytes).context("parse V7 graph policy list")?;
    for policy in &policies {
        policy
            .validate()
            .map_err(|error| anyhow::anyhow!(error.0))?;
    }
    Ok(policies)
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
    use crate::{config::NativeBearerV7Config, v7_signers::V7SignerInventory};
    use base64ct::Encoding;
    use freebird_common::api::{
        NativeExchangeV3Descriptor, NativeExchangeV3Discovery, NativeExchangeV3Slot,
        NativeExchangeV3Transition, NATIVE_EXCHANGE_V3_PROFILE_ID,
    };
    use std::{path::Path, sync::Arc};
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
}
