// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{bail, Context, Result};
use std::sync::Arc;

pub(super) struct ExchangeRuntime {
    pub(super) exchange_engine: Option<Arc<crate::exchange::ExchangeEngine>>,
    pub(super) exchange_metadata: Option<freebird_common::api::ExchangeDiscoveryV2>,
    pub(super) exchange_readiness: Option<crate::readiness::ExchangeReadinessState>,
    pub(super) graph_issuance_engine: Option<Arc<crate::graph_issuance::GraphIssuanceEngine>>,
    pub(super) graph_issuance_readiness: Option<crate::readiness::GraphIssuanceReadinessState>,
    pub(super) native_exchange_v7: Option<Arc<crate::exchange::v7::V7ExchangeEngine>>,
    pub(super) native_exchange_v7_discovery:
        Option<freebird_common::api::NativeExchangeV3Discovery>,
    pub(super) native_graph_issuance_v7: Option<Arc<crate::graph_issuance::V7GraphIssuanceEngine>>,
    pub(super) native_graph_issuance_v7_discovery:
        Option<freebird_common::api::NativeGraphIssuanceV7Discovery>,
    pub(super) native_exchange_v7_readiness: Option<crate::readiness::V7ExchangeReadinessState>,
    pub(super) native_graph_issuance_v7_readiness:
        Option<crate::readiness::V7GraphIssuanceReadinessState>,
}

impl ExchangeRuntime {
    pub(super) async fn build(
        config: &crate::config::Config,
        inventory: Arc<crate::v7_signers::V7SignerInventory>,
    ) -> Result<Self> {
        // Cutover terminalization is unconditional.  A disabled V7 runtime
        // must not silently leave durable V5 work resumable.
        let terminalization_redis_url = legacy_terminalization_redis_url(config)?;
        terminalize_legacy_exchange_work(&terminalization_redis_url).await?;
        if config.exchange_config.graph_issuance.enabled && !config.exchange_config.enabled {
            bail!("V7 graph issuance requires the V7 exchange runtime")
        }
        if !config.exchange_config.enabled {
            return Ok(Self {
                exchange_engine: None,
                exchange_metadata: None,
                exchange_readiness: None,
                graph_issuance_engine: None,
                graph_issuance_readiness: None,
                native_exchange_v7: None,
                native_exchange_v7_discovery: None,
                native_graph_issuance_v7: None,
                native_graph_issuance_v7_discovery: None,
                native_exchange_v7_readiness: None,
                native_graph_issuance_v7_readiness: None,
            });
        }
        let redis_url = terminalization_redis_url.as_str();

        let (discovery, engine_discovery) = load_v7_discovery_pair(config)?;
        discovery
            .validate()
            .map_err(|error| anyhow::anyhow!(error.0))?;
        let receipt_keys = load_v7_receipt_keys(config)?;
        let v4_receipt_metadata = receipt_keys.discovery_metadata().into_iter().next();
        let store = crate::exchange::v7_store::V7ExchangeStore::new(redis_url)?;
        validate_v7_exchange_inventory(&discovery, &inventory)?;
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

        let (graph, graph_discovery, graph_readiness) =
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
                (Some(graph), Some(discovery), Some(readiness))
            } else {
                (None, None, None)
            };

        // The V7 producer is the only public issuance lane, but V4-local
        // graph authorization still needs the durable replay authority which
        // the verifier probes.  Keep that authority engine separate from the
        // V7 producer engine and expose only its discovery/probe surface.
        let (v4_exchange_metadata, v4_graph, v4_graph_readiness) = if config
            .exchange_config
            .graph_issuance
            .enabled
            && matches!(
                config.exchange_config.graph_issuance.authorization,
                crate::config::GraphIssuanceAuthorizationConfig::V4Local { .. }
            ) {
            let receipt_metadata = v4_receipt_metadata
                .context("V4 replay-authority receipt metadata is unavailable")?;
            let (exchange_metadata, graph, readiness) =
                build_v4_authority_runtime(config, &discovery, receipt_metadata, redis_url).await?;
            (Some(exchange_metadata), Some(graph), Some(readiness))
        } else {
            (None, None, None)
        };

        Ok(Self {
            exchange_engine: None,
            exchange_metadata: v4_exchange_metadata,
            exchange_readiness: None,
            graph_issuance_engine: v4_graph,
            graph_issuance_readiness: v4_graph_readiness,
            native_exchange_v7: Some(exchange),
            native_exchange_v7_discovery: Some(discovery),
            native_graph_issuance_v7: graph,
            native_graph_issuance_v7_discovery: graph_discovery,
            native_exchange_v7_readiness: exchange_readiness,
            native_graph_issuance_v7_readiness: graph_readiness,
        })
    }
}

async fn build_v4_authority_runtime(
    config: &crate::config::Config,
    discovery: &freebird_common::api::NativeExchangeV3Discovery,
    mut receipt_metadata: freebird_common::api::ExchangeReceiptKeyInfo,
    redis_url: &str,
) -> Result<(
    freebird_common::api::ExchangeDiscoveryV2,
    Arc<crate::graph_issuance::GraphIssuanceEngine>,
    crate::readiness::GraphIssuanceReadinessState,
)> {
    let active = v4_authority_profile(discovery, &config.issuer_id)?;
    let authority_descriptor = active
        .keysets
        .first()
        .and_then(|keyset| keyset.keys.first())
        .context("V4 replay-authority graph has no descriptor")?;
    let authorization = match &config.exchange_config.graph_issuance.authorization {
        crate::config::GraphIssuanceAuthorizationConfig::V4Local { keys } => keys,
        _ => bail!("V4 replay authority requires v4_local authorization"),
    };
    let trusted_issuers = authorization
        .iter()
        .map(|key| crate::graph_issuance::GraphIssuanceV4TrustedIssuer {
            issuer_id: key.issuer_id.clone(),
            key_ids: vec![key.kid.clone()],
        })
        .collect();
    let policy = crate::graph_issuance::GraphIssuancePolicy {
        issuance_policy_id: "v4-replay-authority".into(),
        graph_id: active.graph_id.clone(),
        keyset_id: active
            .keysets
            .first()
            .map(|keyset| keyset.id.clone())
            .context("V4 replay-authority graph has no keyset")?,
        descriptor_id: authority_descriptor.descriptor.id.clone(),
        budget_id: "v4-replay-authority-budget".into(),
        budget_limit: 1,
        quantity: freebird_common::graph_issuance_api::GRAPH_ISSUANCE_QUANTITY,
        admission_state: crate::graph_issuance::GraphIssuanceAdmissionState::RecoveryOnly,
        authorization_scheme:
            freebird_common::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL.into(),
        v4_local: Some(crate::graph_issuance::GraphIssuanceV4LocalPolicy {
            verifier_id: config.exchange_config.graph_issuance.v7_verifier_id.clone(),
            audience: config.exchange_config.graph_issuance.v7_audience.clone(),
            trusted_issuers,
        }),
    };
    let document = crate::graph_issuance::GraphIssuancePolicyDocument {
        version: crate::graph_issuance::POLICY_DOCUMENT_VERSION.into(),
        policies: vec![policy],
    };
    let authorizer = Arc::new(crate::graph_issuance::V4LocalGraphIssuanceAuthorizer::new(
        authorization.clone(),
    )?);
    let mut engine = crate::graph_issuance::GraphIssuanceEngine::new_with_enabled(
        &active,
        &[],
        document,
        redis_url,
        authorizer,
        false,
    )?;
    let graph_discovery = engine.initialize().await?;

    receipt_metadata.purpose = "exchange_receipt_active".into();
    let exchange_metadata =
        crate::startup::exchange_discovery_v2(&active, &[], &[receipt_metadata])?;
    freebird_common::api::validate_exchange_discovery_v2(&config.issuer_id, &exchange_metadata)
        .map_err(anyhow::Error::msg)?;
    freebird_common::api::validate_graph_issuance_discovery_v2(
        &exchange_metadata,
        &graph_discovery,
    )
    .map_err(anyhow::Error::msg)?;

    let engine = Arc::new(engine);
    let readiness = crate::readiness::GraphIssuanceReadinessState::new(engine.clone());
    Ok((exchange_metadata, engine, readiness))
}

fn v4_authority_profile(
    discovery: &freebird_common::api::NativeExchangeV3Discovery,
    issuer_id: &str,
) -> Result<crate::exchange::profiles::ExchangeProfileV2> {
    use crate::exchange::profiles::{
        ExchangeAdmissionStateV2, ExchangeDescriptorV2, ExchangeKeyV2, ExchangeKeysetV2,
        ExchangeProfileV2, ExchangeTransitionSlotV2, ExchangeTransitionV2, PROFILE_ID_V2,
    };
    use base64ct::{Base64UrlUnpadded, Encoding};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;

    let native_descriptors = discovery
        .active_descriptors
        .iter()
        .chain(discovery.retained_descriptors.iter())
        .collect::<Vec<_>>();
    if native_descriptors.is_empty() {
        bail!("V4 replay-authority graph has no exchange descriptors")
    }
    let mut descriptor_ids = HashMap::new();
    let mut descriptors = HashMap::new();
    for native in native_descriptors {
        let spki = Base64UrlUnpadded::decode_vec(&native.pubkey_spki_b64)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let mut descriptor = ExchangeDescriptorV2 {
            id: String::new(),
            profile_id: PROFILE_ID_V2.into(),
            issuer_id: issuer_id.into(),
            kid: hex::encode(Sha256::digest(&spki)),
            audience: None,
            spki_b64: Base64UrlUnpadded::encode_string(&spki),
            suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
            valid_from: native.valid_from as i64,
            valid_until: native.valid_until as i64,
        };
        descriptor.id = descriptor.canonical_id()?;
        descriptor_ids.insert(native.descriptor_id.clone(), descriptor.id.clone());
        descriptors.insert(descriptor.id.clone(), descriptor);
    }

    let native_keysets = discovery
        .active_keysets
        .iter()
        .chain(discovery.retained_keysets.iter())
        .collect::<Vec<_>>();
    let mut keyset_ids = HashMap::new();
    let mut keysets = Vec::new();
    for native in native_keysets {
        let mut keys = native
            .descriptor_ids
            .iter()
            .filter_map(|id| descriptor_ids.get(id))
            .filter_map(|id| descriptors.get(id))
            .cloned()
            .map(|descriptor| ExchangeKeyV2 {
                descriptor,
                private_key_path: None,
            })
            .collect::<Vec<_>>();
        keys.sort_by(|left, right| left.descriptor.id.cmp(&right.descriptor.id));
        keys.dedup_by(|left, right| left.descriptor.id == right.descriptor.id);
        if keys.is_empty() {
            continue;
        }
        let keyset = ExchangeKeysetV2 {
            id: String::new(),
            keys,
        };
        let id = keyset.canonical_id();
        keyset_ids.insert(native.keyset_id.clone(), id.clone());
        keysets.push(ExchangeKeysetV2 { id, ..keyset });
    }
    if keysets.len() < 2 {
        bail!("V4 replay-authority graph needs two exchange keysets")
    }

    let mut transitions = Vec::new();
    for (index, native) in discovery.transitions.iter().enumerate() {
        let Some(source_keyset_id) = keyset_ids.get(&native.source_keyset_id) else {
            continue;
        };
        let Some(target_keyset_id) = keyset_ids.get(&native.target_keyset_id) else {
            continue;
        };
        if source_keyset_id == target_keyset_id {
            continue;
        }
        let map_slots = |slots: &[freebird_common::api::NativeExchangeV3Slot],
                         keyset_id: &str|
         -> Vec<ExchangeTransitionSlotV2> {
            slots
                .iter()
                .filter_map(|slot| {
                    Some(ExchangeTransitionSlotV2 {
                        descriptor_id: descriptor_ids.get(&slot.descriptor_id)?.clone(),
                        slot_id: slot.slot_id.clone(),
                        class: "v4-authority".into(),
                        quantity: slot.quantity,
                    })
                })
                .filter(|slot| {
                    keysets
                        .iter()
                        .find(|keyset| keyset.id == keyset_id)
                        .is_some_and(|keyset| {
                            keyset
                                .keys
                                .iter()
                                .any(|key| key.descriptor.id == slot.descriptor_id)
                        })
                })
                .collect()
        };
        let sources = map_slots(&native.source_slots, source_keyset_id);
        let outputs = map_slots(&native.output_slots, target_keyset_id);
        if sources.is_empty() || outputs.is_empty() {
            continue;
        }
        let mut transition = ExchangeTransitionV2 {
            id: String::new(),
            source_keyset_id: source_keyset_id.clone(),
            target_keyset_id: target_keyset_id.clone(),
            sources,
            outputs,
            budget_id: format!("v4-authority-budget-{index}"),
            budget_limit: 1,
            admission_state: ExchangeAdmissionStateV2::Disabled,
        };
        transition.id = transition.canonical_id();
        transitions.push(transition);
    }
    if transitions.is_empty() {
        let source = &keysets[0];
        let target = &keysets[1];
        let source_descriptor = source.keys[0].descriptor.id.clone();
        let target_descriptor = target.keys[0].descriptor.id.clone();
        let mut transition = ExchangeTransitionV2 {
            id: String::new(),
            source_keyset_id: source.id.clone(),
            target_keyset_id: target.id.clone(),
            sources: vec![ExchangeTransitionSlotV2 {
                descriptor_id: source_descriptor,
                slot_id: "source".into(),
                class: "v4-authority".into(),
                quantity: 1,
            }],
            outputs: vec![ExchangeTransitionSlotV2 {
                descriptor_id: target_descriptor,
                slot_id: "output".into(),
                class: "v4-authority".into(),
                quantity: 1,
            }],
            budget_id: "v4-authority-budget-fallback".into(),
            budget_limit: 1,
            admission_state: ExchangeAdmissionStateV2::Disabled,
        };
        transition.id = transition.canonical_id();
        transitions.push(transition);
    }
    let mut profile = ExchangeProfileV2 {
        profile_id: PROFILE_ID_V2.into(),
        graph_id: String::new(),
        keysets,
        transitions,
    };
    profile.graph_id = profile.canonical_graph_id();
    Ok(profile)
}

fn legacy_terminalization_redis_url(config: &crate::config::Config) -> Result<String> {
    config
        .exchange_config
        .redis_url
        .clone()
        .or_else(|| std::env::var("REDIS_URL").ok())
        .filter(|url| !url.trim().is_empty())
        .context(
            "durable Redis authority is required to terminalize legacy exchange work ".to_owned()
                + "(NATIVE_EXCHANGE_V7_REDIS_URL or REDIS_URL)",
        )
}

/// Validate the file-backed V7 runtime, signer inventory, graph policies, and
/// active/retained receipt signers before the issuer is started.
pub fn validate_v7_runtime_config(config: &crate::config::Config) -> Result<()> {
    if !config.exchange_config.enabled {
        return Ok(());
    }
    let discovery = load_v7_discovery(config)?;
    discovery
        .validate()
        .map_err(|error| anyhow::anyhow!(error.0))?;
    let signer_configs = std::iter::once(config.native_bearer_v7_config.clone())
        .chain(crate::config::load_v7_additional_signer_configs()?)
        .collect::<Vec<_>>();
    let mut signers = Vec::with_capacity(signer_configs.len());
    for signer_config in &signer_configs {
        let spec =
            crate::v7_signers::V7SignerSpec::from_native_config(signer_config, &config.issuer_id)?;
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
    validate_v7_exchange_inventory(&discovery, &inventory)?;
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
    let read = |path: &std::path::Path| -> Result<freebird_common::api::ExchangeReceiptKeyInfo> {
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
    Ok(crate::exchange::ReceiptKeyRing::load_v7(active, &retained)?)
}

pub(crate) fn validate_v7_exchange_inventory(
    discovery: &freebird_common::api::NativeExchangeV3Discovery,
    inventory: &crate::v7_signers::V7SignerInventory,
) -> Result<()> {
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
        let token_key_id: [u8; 32] = hex::decode(&descriptor.token_key_id)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid V7 exchange token key ID"))?;
        let identity = crate::v7_signers::V7SignerIdentity::new(
            descriptor.issuer_id.clone(),
            descriptor.profile_id.clone(),
            descriptor.descriptor_id.clone(),
            freebird_crypto::V7TokenKeyId::new(token_key_id),
        )?;
        let signer = inventory.lookup(&identity)?;
        if signer.metadata().pubkey_spki_b64 != descriptor.pubkey_spki_b64
            || signer.metadata().spki_fingerprint != descriptor.spki_fingerprint
            || signer.metadata().asset_id != descriptor.asset_id
            || signer.metadata().amount_minor.to_string() != descriptor.amount_minor
        {
            bail!("V7 exchange descriptor does not match shared signer inventory")
        }
    }
    for descriptor_id in required {
        if !descriptors.contains_key(descriptor_id) {
            bail!("V7 exchange output references unknown descriptor")
        }
    }
    Ok(())
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

/// The cutover policy is deliberately destructive for unfinished V5 producer
/// work: it is terminalized and can never be recovered or signed after V7
/// startup. Committed historical records are left intact for auditability.
async fn terminalize_legacy_exchange_work(redis_url: &str) -> Result<()> {
    let client = redis::Client::open(redis_url)?;
    let mut connection = client.get_async_connection().await?;
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("freebird:exchange:v2:op:*")
        .query_async(&mut connection)
        .await?;
    for key in keys {
        let state: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg("state")
            .query_async(&mut connection)
            .await?;
        if matches!(state.as_deref(), Some(state) if state != "3" && state != "4") {
            let _: () = redis::cmd("HSET")
                .arg(&key)
                .arg("state")
                .arg("4")
                .arg("terminal_reason")
                .arg("v7_cutover_no_compatibility")
                .query_async(&mut connection)
                .await?;
        }
    }
    let graph_keys: Vec<String> = redis::cmd("KEYS")
        .arg("freebird:graph-issuance:v2:op:*")
        .query_async(&mut connection)
        .await?;
    for key in graph_keys {
        let state: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg("state")
            .query_async(&mut connection)
            .await?;
        if state.as_deref() != Some("committed") {
            let _: () = redis::cmd("HSET")
                .arg(&key)
                .arg("state")
                .arg("terminal")
                .arg("terminal_reason")
                .arg("v7_cutover_no_compatibility")
                .query_async(&mut connection)
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{merge_v7_discovery, terminalize_legacy_exchange_work};
    use anyhow::Result;
    use std::process::{Child, Command, Stdio};
    use tokio::time::{sleep, Duration};

    struct RedisProcess {
        child: Child,
        url: String,
    }

    impl RedisProcess {
        async fn start() -> Result<Self> {
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            let port = listener.local_addr()?.port();
            drop(listener);
            let child = Command::new("redis-server")
                .args([
                    "--save",
                    "",
                    "--appendonly",
                    "no",
                    "--bind",
                    "127.0.0.1",
                    "--port",
                    &port.to_string(),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let url = format!("redis://127.0.0.1:{port}/");
            for _ in 0..50 {
                if redis::Client::open(url.as_str())?
                    .get_async_connection()
                    .await
                    .is_ok()
                {
                    return Ok(Self { child, url });
                }
                sleep(Duration::from_millis(20)).await;
            }
            anyhow::bail!("redis-server did not become ready")
        }
    }

    impl Drop for RedisProcess {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[tokio::test]
    async fn cutover_terminalizes_every_uncommitted_legacy_operation() -> Result<()> {
        let redis = RedisProcess::start().await?;
        let client = redis::Client::open(redis.url.as_str())?;
        let mut connection = client.get_async_connection().await?;
        for (key, state) in [
            ("freebird:exchange:v2:op:pending", "1"),
            ("freebird:exchange:v2:op:unknown", "9"),
            ("freebird:exchange:v2:op:committed", "3"),
        ] {
            let _: () = redis::cmd("HSET")
                .arg(key)
                .arg("state")
                .arg(state)
                .query_async(&mut connection)
                .await?;
        }
        let _: () = redis::cmd("HSET")
            .arg("freebird:graph-issuance:v2:op:pending")
            .arg("state")
            .arg("reserved")
            .query_async(&mut connection)
            .await?;

        terminalize_legacy_exchange_work(&redis.url).await?;

        for (key, expected) in [
            ("freebird:exchange:v2:op:pending", "4"),
            ("freebird:exchange:v2:op:unknown", "4"),
            ("freebird:exchange:v2:op:committed", "3"),
        ] {
            let state: String = redis::cmd("HGET")
                .arg(key)
                .arg("state")
                .query_async(&mut connection)
                .await?;
            assert_eq!(state, expected);
        }
        let graph_state: String = redis::cmd("HGET")
            .arg("freebird:graph-issuance:v2:op:pending")
            .arg("state")
            .query_async(&mut connection)
            .await?;
        assert_eq!(graph_state, "terminal");
        Ok(())
    }

    fn discovery(
        graph_id: &str,
        descriptor_id: &str,
    ) -> freebird_common::api::NativeExchangeV3Discovery {
        freebird_common::api::NativeExchangeV3Discovery {
            version: freebird_common::api::NATIVE_EXCHANGE_V3_VERSION,
            profile: freebird_common::api::NativeExchangeV3Profile {
                version: freebird_common::api::NATIVE_EXCHANGE_V3_VERSION,
                profile_id: freebird_common::api::NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                graph_id: graph_id.into(),
                suite: freebird_common::api::NATIVE_EXCHANGE_V3_SUITE.into(),
                modulus_bits: 3072,
                exponent: 65_537,
            },
            active_descriptors: vec![freebird_common::api::NativeExchangeV3Descriptor {
                descriptor_id: descriptor_id.into(),
                profile_id: freebird_common::api::NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                issuer_id: "issuer:test".into(),
                token_key_id: format!("{descriptor_id}00")[..64].into(),
                asset_id: "USD".into(),
                amount_minor: "1".into(),
                suite: freebird_common::api::NATIVE_EXCHANGE_V3_SUITE.into(),
                modulus_bits: 3072,
                exponent: 65_537,
                pubkey_spki_b64: "AA".into(),
                spki_fingerprint: "bb".repeat(32),
                valid_from: 1,
                valid_until: 2,
            }],
            retained_descriptors: Vec::new(),
            active_keysets: Vec::new(),
            retained_keysets: Vec::new(),
            transitions: Vec::new(),
        }
    }

    #[test]
    fn retained_discovery_snapshots_remain_retained_and_cannot_mix_graphs() {
        let mut active = discovery("aa".repeat(32).as_str(), "11".repeat(32).as_str());
        let retained = discovery("aa".repeat(32).as_str(), "22".repeat(32).as_str());
        merge_v7_discovery(&mut active, vec![retained]).unwrap();
        assert_eq!(active.active_descriptors.len(), 1);
        assert_eq!(active.retained_descriptors.len(), 1);
        assert_eq!(
            active.retained_descriptors[0].descriptor_id,
            "22".repeat(32)
        );

        let mut active = discovery("aa".repeat(32).as_str(), "11".repeat(32).as_str());
        let mismatched = discovery("bb".repeat(32).as_str(), "22".repeat(32).as_str());
        assert!(merge_v7_discovery(&mut active, vec![mismatched]).is_err());

        let mut active = discovery("aa".repeat(32).as_str(), "11".repeat(32).as_str());
        let mut incompatible = discovery("aa".repeat(32).as_str(), "22".repeat(32).as_str());
        incompatible.profile.suite = "different-suite".into();
        assert!(merge_v7_discovery(&mut active, vec![incompatible]).is_err());
    }

    #[test]
    fn shared_inventory_loads_direct_exchange_graph_and_retained_signers() -> Result<()> {
        let root = tempfile::tempdir()?;
        let config = |name: &str, profile: &str, descriptor: u8, token: u8| {
            crate::config::NativeBearerV7Config {
                sk_path: root.path().join(format!("{name}.der")),
                metadata_path: root.path().join(format!("{name}.json")),
                registry_path: root.path().join("registry.json"),
                profile_id: profile.into(),
                descriptor_id: format!("{descriptor:02x}").repeat(32),
                token_key_id: format!("{token:02x}").repeat(32),
                asset_id: "USD".into(),
                amount_minor: 1,
                validity_secs: 3600,
            }
        };
        let direct = config(
            "direct",
            freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID,
            0x11,
            0x12,
        );
        let exchange = config("exchange", "freebird/native-exchange/v3", 0x21, 0x22);
        let graph = config("graph", "freebird/native-graph-issuance/v7", 0x31, 0x32);
        let direct_spec =
            crate::v7_signers::V7SignerSpec::from_native_config(&direct, "issuer:test")?;
        let retained_specs = [exchange.clone(), graph.clone()]
            .iter()
            .map(|config| {
                crate::v7_signers::V7SignerSpec::from_native_config(config, "issuer:test")
            })
            .collect::<Result<Vec<_>>>()?;
        let inventory = crate::v7_signers::V7SignerInventory::load_or_generate(
            direct_spec,
            retained_specs,
            &direct.registry_path,
        )?;
        assert_eq!(inventory.len(), 3);
        for config in [&direct, &exchange, &graph] {
            let spec = crate::v7_signers::V7SignerSpec::from_native_config(config, "issuer:test")?;
            assert!(inventory.lookup(&spec.identity).is_ok());
        }
        let retained_specs = [exchange, graph]
            .iter()
            .map(|config| {
                crate::v7_signers::V7SignerSpec::from_native_config(config, "issuer:test")
            })
            .collect::<Result<Vec<_>>>()?;
        let recovered = crate::v7_signers::V7SignerInventory::load_or_generate(
            direct_spec_from_config(&direct)?,
            retained_specs,
            &direct.registry_path,
        )?;
        assert_eq!(recovered.len(), 3);
        Ok(())
    }

    fn direct_spec_from_config(
        config: &crate::config::NativeBearerV7Config,
    ) -> Result<crate::v7_signers::V7SignerSpec> {
        crate::v7_signers::V7SignerSpec::from_native_config(config, "issuer:test")
    }
}

fn graph_discovery_v2(
    graph: &crate::exchange::profiles::ExchangeProfileV2,
) -> freebird_common::api::ExchangeGraphDiscoveryV2 {
    use freebird_common::api::{
        ExchangeAdmissionStateV2, ExchangeDescriptorDiscoveryV2, ExchangeKeysetDiscoveryV2,
        ExchangeTransitionDiscoveryV2, ExchangeTransitionSlotDiscoveryV2,
    };

    let slots = |slots: &[crate::exchange::profiles::ExchangeTransitionSlotV2]| {
        slots
            .iter()
            .map(|slot| ExchangeTransitionSlotDiscoveryV2 {
                descriptor_id: slot.descriptor_id.clone(),
                slot_id: slot.slot_id.clone(),
                class: slot.class.clone(),
                quantity: slot.quantity,
            })
            .collect()
    };
    freebird_common::api::ExchangeGraphDiscoveryV2 {
        profile_id: graph.profile_id.clone(),
        graph_id: graph.graph_id.clone(),
        descriptors: graph
            .keysets
            .iter()
            .flat_map(|keyset| &keyset.keys)
            .map(|key| ExchangeDescriptorDiscoveryV2 {
                descriptor_id: key.descriptor.id.clone(),
                profile_id: key.descriptor.profile_id.clone(),
                issuer_id: key.descriptor.issuer_id.clone(),
                token_key_id: key.descriptor.kid.clone(),
                audience: key.descriptor.audience.clone(),
                pubkey_spki_b64: key.descriptor.spki_b64.clone(),
                suite: key.descriptor.suite.clone(),
                valid_from: key.descriptor.valid_from,
                valid_until: key.descriptor.valid_until,
            })
            .collect(),
        keysets: graph
            .keysets
            .iter()
            .map(|keyset| ExchangeKeysetDiscoveryV2 {
                keyset_id: keyset.id.clone(),
                descriptor_ids: keyset
                    .keys
                    .iter()
                    .map(|key| key.descriptor.id.clone())
                    .collect(),
            })
            .collect(),
        transitions: graph
            .transitions
            .iter()
            .map(|transition| ExchangeTransitionDiscoveryV2 {
                transition_id: transition.id.clone(),
                source_keyset_id: transition.source_keyset_id.clone(),
                target_keyset_id: transition.target_keyset_id.clone(),
                source_slots: slots(&transition.sources),
                output_slots: slots(&transition.outputs),
                budget_id: transition.budget_id.clone(),
                budget_limit: transition.budget_limit,
                admission_state: match transition.admission_state {
                    crate::exchange::profiles::ExchangeAdmissionStateV2::AcceptingNew => {
                        ExchangeAdmissionStateV2::AcceptingNew
                    }
                    crate::exchange::profiles::ExchangeAdmissionStateV2::RecoveryOnly => {
                        ExchangeAdmissionStateV2::RecoveryOnly
                    }
                    crate::exchange::profiles::ExchangeAdmissionStateV2::Disabled => {
                        ExchangeAdmissionStateV2::Disabled
                    }
                },
            })
            .collect(),
    }
}

pub fn exchange_discovery_v2(
    active: &crate::exchange::profiles::ExchangeProfileV2,
    retained: &[crate::exchange::profiles::ExchangeProfileV2],
    receipt_keys: &[freebird_common::api::ExchangeReceiptKeyInfo],
) -> Result<freebird_common::api::ExchangeDiscoveryV2> {
    let active_receipt_key = receipt_keys
        .iter()
        .find(|key| key.purpose == "exchange_receipt_active")
        .cloned()
        .context("active V2 receipt discovery metadata is unavailable")?;
    let retained_receipt_keys = receipt_keys
        .iter()
        .filter(|key| key.purpose == "exchange_receipt_retained")
        .cloned()
        .collect();
    Ok(freebird_common::api::ExchangeDiscoveryV2 {
        active_graph: graph_discovery_v2(active),
        retained_graphs: retained.iter().map(graph_discovery_v2).collect(),
        active_receipt_key,
        retained_receipt_keys,
    })
}

fn exchange_registry_entries_v2(
    identities: &std::collections::BTreeMap<String, crate::exchange::history::GlobalV5KeyIdentity>,
) -> Vec<crate::exchange::store::KeyRegistryEntry> {
    identities
        .values()
        .map(|identity| crate::exchange::store::KeyRegistryEntry {
            key_id: identity.key_id.clone(),
            canonical_metadata: identity.canonical_bytes(),
        })
        .collect()
}

pub(crate) fn validate_disabled_publication_acknowledgements_v2(
    issuer_id: &str,
    discovery: &freebird_common::api::ExchangeDiscoveryV2,
    acknowledgements: &[crate::config::ExchangeDisabledPublicationAcknowledgementV1],
) -> Result<()> {
    let graphs = std::iter::once(&discovery.active_graph)
        .chain(&discovery.retained_graphs)
        .collect::<Vec<_>>();
    let mut acknowledged = std::collections::HashSet::new();
    for acknowledgement in acknowledgements {
        if acknowledgement.issuer_id != issuer_id {
            bail!("disabled-publication acknowledgement issuer mismatch")
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
                bail!("disabled-publication acknowledgement transition mismatch")
            }
            if !acknowledged.insert((graph.graph_id.as_str(), transition_id.as_str())) {
                bail!("duplicate disabled-publication acknowledgement")
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
                bail!(
                    "accepting V2 transition lacks an explicit disabled-publication acknowledgement for this graph"
                )
            }
        }
    }
    Ok(())
}

async fn validate_pending_graph_references_v2(
    store: &crate::exchange::store::ExchangeStore,
    active: &crate::exchange::profiles::ExchangeProfileV2,
    retained: &[crate::exchange::profiles::ExchangeProfileV2],
) -> Result<()> {
    for record in store.pending_records_v2().await? {
        let graph = std::iter::once(active)
            .chain(retained)
            .find(|graph| graph.graph_id == record.graph_id)
            .context("pending V2 exchange references an unavailable graph")?;
        let transition = graph
            .transitions
            .iter()
            .find(|transition| {
                transition.id == record.transition_id
                    && transition.source_keyset_id == record.source_keyset_id
                    && transition.target_keyset_id == record.target_keyset_id
            })
            .context("pending V2 exchange references an unavailable transition")?;
        if !transition.allows_recovery() {
            bail!("disabled V2 exchange transition still has pending references")
        }
    }
    Ok(())
}
