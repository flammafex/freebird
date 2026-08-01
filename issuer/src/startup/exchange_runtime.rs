// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{bail, Context, Result};
use base64ct::Encoding;
use std::sync::Arc;

pub(super) struct ExchangeRuntime {
    pub(super) exchange_engine: Option<Arc<crate::exchange::ExchangeEngine>>,
    pub(super) exchange_metadata: Option<freebird_common::api::ExchangeDiscoveryV2>,
    pub(super) exchange_readiness: Option<crate::readiness::ExchangeReadinessState>,
    pub(super) graph_issuance_engine: Option<Arc<crate::graph_issuance::GraphIssuanceEngine>>,
    pub(super) graph_issuance_readiness: Option<crate::readiness::GraphIssuanceReadinessState>,
}

impl ExchangeRuntime {
    pub(super) async fn build(
        config: &crate::config::Config,
        public_issuer: Option<&crate::public_tokens::PublicTokenIssuer>,
    ) -> Result<Self> {
        if !config.exchange_config.enabled {
            return Ok(Self {
                exchange_engine: None,
                exchange_metadata: None,
                exchange_readiness: None,
                graph_issuance_engine: None,
                graph_issuance_readiness: None,
            });
        }

        let direct_v5_metadata = public_issuer.map(|issuer| issuer.metadata());
        let direct_v5_spki = direct_v5_metadata
            .as_ref()
            .map(|metadata| base64ct::Base64UrlUnpadded::decode_vec(&metadata.pubkey_spki_b64))
            .transpose()
            .context("invalid authoritative direct V5 public key metadata")?;
        let loaded = config
            .exchange_config
            .load_v2(&config.issuer_id, direct_v5_spki.as_deref())
            .context("Failed to load V2 exchange graph and signer configuration")?;
        let store = crate::exchange::store::ExchangeStore::new(
            config
                .exchange_config
                .redis_url
                .as_deref()
                .context("exchange Redis URL missing")?,
        )?;
        store
            .validate_durable_standalone()
            .await
            .context("exchange Redis durability check failed")?;
        validate_pending_graph_references_v2(&store, &loaded.active_graph, &loaded.retained_graphs)
            .await
            .context("invalid pending V2 exchange graph references")?;
        let mut metadata = exchange_discovery_v2(
            &loaded.active_graph,
            &loaded.retained_graphs,
            &loaded.receipt_keys.discovery_metadata(),
        )?;
        if let Some(history) = loaded.public_history.clone() {
            crate::exchange::history::merge_public_history_v2(&mut metadata, history)?;
        }
        freebird_common::api::validate_exchange_discovery_v2(&config.issuer_id, &metadata)
            .map_err(anyhow::Error::msg)?;
        let global_identities = crate::exchange::history::global_key_identities_v2(
            &config.issuer_id,
            direct_v5_metadata,
            &metadata,
        )?;
        let registry_entries = exchange_registry_entries_v2(&global_identities);
        match store.initialize_key_registry_v2(&registry_entries).await? {
            crate::exchange::store::KeyRegistryOutcome::Initialized
            | crate::exchange::store::KeyRegistryOutcome::Equal => {}
            crate::exchange::store::KeyRegistryOutcome::Conflict
            | crate::exchange::store::KeyRegistryOutcome::Missing => {
                bail!("V2 durable key registry conflicts with configured graph history")
            }
        }
        let publication_acknowledgements = config
            .exchange_config
            .load_disabled_publication_acknowledgements()?;
        validate_disabled_publication_acknowledgements_v2(
            &config.issuer_id,
            &metadata,
            &publication_acknowledgements,
        )?;
        let source_valid_until = global_identities
            .into_iter()
            .map(|(key_id, identity)| (key_id, identity.longest_valid_until))
            .collect();
        let graph_issuance_enabled = config.exchange_config.graph_issuance.enabled;
        let (document, authorizer): (
            crate::graph_issuance::GraphIssuancePolicyDocument,
            Arc<dyn crate::graph_issuance::GraphIssuanceAuthorizer>,
        ) = if graph_issuance_enabled {
            let document = crate::graph_issuance::GraphIssuancePolicyDocument::load(
                &config.exchange_config.graph_issuance.policy_path,
                &loaded.active_graph,
                &loaded.retained_graphs,
            )?;
            let configured_scheme = match &config.exchange_config.graph_issuance.authorization {
                crate::config::GraphIssuanceAuthorizationConfig::HmacSha256(_) => "hmac_sha256",
                crate::config::GraphIssuanceAuthorizationConfig::V4Local { .. } => "v4_local",
                crate::config::GraphIssuanceAuthorizationConfig::DevelopmentMock => {
                    "development_mock"
                }
                crate::config::GraphIssuanceAuthorizationConfig::Disabled => {
                    bail!("graph issuance authorization verifier is disabled")
                }
            };
            if document.policies.iter().any(|policy| {
                policy.admission_state
                    == crate::graph_issuance::GraphIssuanceAdmissionState::AcceptingNew
                    && policy.authorization_scheme != configured_scheme
            }) {
                bail!("accepting graph issuance policy authorization scheme mismatch")
            }
            let authorizer: Arc<dyn crate::graph_issuance::GraphIssuanceAuthorizer> = match &config
                .exchange_config
                .graph_issuance
                .authorization
            {
                crate::config::GraphIssuanceAuthorizationConfig::HmacSha256(secret) => Arc::new(
                    crate::graph_issuance::HmacGraphIssuanceAuthorizer::new(secret.clone())?,
                ),
                crate::config::GraphIssuanceAuthorizationConfig::V4Local { keys } => Arc::new(
                    crate::graph_issuance::V4LocalGraphIssuanceAuthorizer::new(keys.clone())?,
                ),
                crate::config::GraphIssuanceAuthorizationConfig::DevelopmentMock
                    if config.unsafe_development_mode =>
                {
                    tracing::warn!("UNSAFE development-only graph issuance authorization enabled");
                    Arc::new(crate::graph_issuance::DevelopmentMockAuthorizer)
                }
                _ => bail!("graph issuance authorization verifier is unavailable"),
            };
            (document, authorizer)
        } else {
            (
                crate::graph_issuance::GraphIssuancePolicyDocument {
                    version: crate::graph_issuance::POLICY_DOCUMENT_VERSION.into(),
                    policies: Vec::new(),
                },
                Arc::new(crate::graph_issuance::DisabledGraphIssuanceAuthorizer),
            )
        };
        let mut graph_engine = crate::graph_issuance::GraphIssuanceEngine::new_with_enabled(
            &loaded.active_graph,
            &loaded.retained_graphs,
            document,
            config
                .exchange_config
                .redis_url
                .as_deref()
                .context("exchange Redis URL missing")?,
            authorizer,
            graph_issuance_enabled,
        )?;
        let issuance_metadata = graph_engine.initialize().await?;
        freebird_common::api::validate_graph_issuance_discovery_v2(&metadata, &issuance_metadata)
            .map_err(anyhow::Error::msg)?;
        let graph_engine = Arc::new(graph_engine);
        let graph_readiness =
            crate::readiness::GraphIssuanceReadinessState::new(graph_engine.clone());
        let graph_issuance_engine = Some(graph_engine);
        let graph_issuance_readiness = Some(graph_readiness);
        let engine = crate::exchange::ExchangeEngine::new_v2_with_source_validity(
            loaded.active_graph,
            loaded.retained_graphs,
            store.clone(),
            config.issuer_id.clone(),
            loaded.receipt_keys,
            config.exchange_config.receipt_lifetime_secs,
            source_valid_until,
        )
        .await?;
        let engine = Arc::new(engine);
        let readiness = crate::readiness::ExchangeReadinessState::new(
            engine.clone(),
            store,
            registry_entries,
            config.issuer_id.clone(),
            metadata.clone(),
            config
                .exchange_config
                .disabled_publication_ack_paths
                .clone(),
        );

        Ok(Self {
            exchange_engine: Some(engine),
            exchange_metadata: Some(metadata),
            exchange_readiness: Some(readiness),
            graph_issuance_engine,
            graph_issuance_readiness,
        })
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
