// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{anyhow, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{ExchangeDiscoveryV2, KeyDiscoveryResp, PublicKeyInfo};
use std::collections::{HashMap, HashSet};

use crate::routes::admin::PublicIssuerKey;

pub fn trusted_public_keys(
    issuer_id: &str,
    discovery: KeyDiscoveryResp,
) -> Result<HashMap<[u8; freebird_crypto::PUBLIC_BEARER_TOKEN_KEY_ID_LEN], PublicIssuerKey>> {
    if discovery.issuer_id != issuer_id {
        return Err(anyhow!("issuer key discovery issuer_id mismatch"));
    }
    let mut keys = HashMap::new();
    for info in discovery.public {
        match parse_legacy_public_key(issuer_id, info) {
            Ok(key) => {
                if let Err(error) = insert_unique(&mut keys, key) {
                    tracing::warn!(?error, "dropping conflicting legacy public bearer key");
                }
            }
            Err(error) => tracing::warn!(?error, "dropping invalid legacy public bearer key"),
        }
    }
    if let Some(exchange) = discovery.exchange {
        let exchange_trust = validated_exchange_v2_trust(issuer_id, exchange)?;
        if exchange_trust
            .outputs
            .keys()
            .any(|key_id| keys.contains_key(key_id))
        {
            return Err(anyhow!(
                "exchange output key collides with a direct V5 issuance key"
            ));
        }
        let mut global_identities = HashMap::new();
        for key in keys.values().chain(exchange_trust.aliases.values()) {
            merge_identity_horizon(&mut global_identities, key.clone())?;
        }
        // The graph is fully validated and materialized before production
        // trust is changed, so malformed metadata can never be partly merged.
        keys.extend(exchange_trust.outputs);
        for key in keys.values_mut() {
            key.valid_until = global_identities
                .get(&key.token_key_id)
                .context("trusted V5 key has no global identity horizon")?
                .valid_until;
        }
    }
    Ok(keys)
}

struct ValidatedExchangeTrust {
    outputs: HashMap<[u8; freebird_crypto::PUBLIC_BEARER_TOKEN_KEY_ID_LEN], PublicIssuerKey>,
    /// Every graph descriptor participates in the global identity horizon,
    /// including descriptors which appear only as transition sources.
    aliases: HashMap<[u8; freebird_crypto::PUBLIC_BEARER_TOKEN_KEY_ID_LEN], PublicIssuerKey>,
}

/// Validate a complete V2 discovery container before exposing any graph output
/// key. Any malformed active or retained graph rejects the complete container.
#[cfg(test)]
fn validated_exchange_v2_public_keys(
    issuer_id: &str,
    discovery: ExchangeDiscoveryV2,
) -> Result<HashMap<[u8; freebird_crypto::PUBLIC_BEARER_TOKEN_KEY_ID_LEN], PublicIssuerKey>> {
    Ok(validated_exchange_v2_trust(issuer_id, discovery)?.outputs)
}

fn validated_exchange_v2_trust(
    issuer_id: &str,
    discovery: ExchangeDiscoveryV2,
) -> Result<ValidatedExchangeTrust> {
    freebird_common::api::validate_exchange_discovery_v2(issuer_id, &discovery)
        .map_err(anyhow::Error::msg)?;
    let mut outputs = HashMap::new();
    let mut aliases = HashMap::new();
    for graph in std::iter::once(discovery.active_graph).chain(discovery.retained_graphs) {
        let output_ids: HashSet<_> = graph
            .transitions
            .iter()
            .flat_map(|transition| &transition.output_slots)
            .map(|slot| slot.descriptor_id.clone())
            .collect();
        for descriptor in graph.descriptors {
            let is_output = output_ids.contains(&descriptor.descriptor_id);
            let key = build_key(
                issuer_id,
                descriptor.token_key_id,
                descriptor.pubkey_spki_b64,
                descriptor.valid_from,
                descriptor.valid_until,
                descriptor.audience,
            )?;
            merge_identity_horizon(&mut aliases, key.clone())?;
            if is_output {
                merge_identity_horizon(&mut outputs, key)?;
            }
        }
    }
    Ok(ValidatedExchangeTrust { outputs, aliases })
}

/// Merge validity endpoints only after pinning all cryptographic identity and
/// audience fields. `valid_from` belongs to the trusted direct/output record;
/// every alias of that identity contributes to its replay horizon.
fn merge_identity_horizon(
    keys: &mut HashMap<[u8; 32], PublicIssuerKey>,
    candidate: PublicIssuerKey,
) -> Result<()> {
    if let Some(existing) = keys.get_mut(&candidate.token_key_id) {
        if existing.pubkey_spki != candidate.pubkey_spki
            || existing.issuer_id != candidate.issuer_id
            || existing.audience != candidate.audience
        {
            return Err(anyhow!("conflicting global V5 key identity metadata"));
        }
        existing.valid_until = existing.valid_until.max(candidate.valid_until);
    } else {
        keys.insert(candidate.token_key_id, candidate);
    }
    Ok(())
}

fn insert_unique(
    keys: &mut HashMap<[u8; 32], PublicIssuerKey>,
    key: PublicIssuerKey,
) -> Result<()> {
    if let Some(existing) = keys.get(&key.token_key_id) {
        if existing.pubkey_spki != key.pubkey_spki
            || existing.issuer_id != key.issuer_id
            || existing.valid_from != key.valid_from
            || existing.valid_until != key.valid_until
            || existing.audience != key.audience
        {
            return Err(anyhow!("conflicting public bearer key metadata"));
        }
        return Ok(());
    }
    keys.insert(key.token_key_id, key);
    Ok(())
}

fn parse_legacy_public_key(issuer_id: &str, info: PublicKeyInfo) -> Result<PublicIssuerKey> {
    if info.issuer_id != issuer_id
        || info.token_type != freebird_crypto::PUBLIC_BEARER_TOKEN_TYPE
        || info.rfc9474_variant != freebird_crypto::PUBLIC_BEARER_RFC9474_VARIANT
        || info.spend_policy != freebird_crypto::PUBLIC_BEARER_SPEND_POLICY_SINGLE_USE
        || matches!(info.max_uses, Some(max_uses) if max_uses != 1)
        || !(2048..=4096).contains(&info.modulus_bits)
        || info.valid_from >= info.valid_until
    {
        return Err(anyhow!("invalid legacy public bearer key metadata"));
    }
    build_key(
        issuer_id,
        info.token_key_id,
        info.pubkey_spki_b64,
        info.valid_from,
        info.valid_until,
        info.audience,
    )
}

fn build_key(
    issuer_id: &str,
    token_key_id_hex: String,
    spki_b64: String,
    valid_from: i64,
    valid_until: i64,
    audience: Option<String>,
) -> Result<PublicIssuerKey> {
    let token_key_id = freebird_crypto::decode_token_key_id_hex(&token_key_id_hex)
        .map_err(|_| anyhow!("invalid token_key_id"))?;
    let pubkey_spki = Base64UrlUnpadded::decode_vec(&spki_b64).context("decode SPKI")?;
    if Base64UrlUnpadded::encode_string(&pubkey_spki) != spki_b64 {
        return Err(anyhow!("non-canonical SPKI encoding"));
    }
    freebird_crypto::validate_public_bearer_spki(&pubkey_spki)
        .map_err(|_| anyhow!("invalid public bearer SPKI"))?;
    if freebird_crypto::token_key_id_from_spki(&pubkey_spki) != token_key_id {
        return Err(anyhow!("token_key_id does not match SPKI"));
    }
    Ok(PublicIssuerKey {
        token_key_id,
        token_key_id_hex,
        pubkey_spki,
        issuer_id: issuer_id.into(),
        valid_from,
        valid_until,
        audience,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use freebird_common::api::{
        ExchangeAdmissionStateV2, ExchangeDescriptorDiscoveryV2, ExchangeGraphDiscoveryV2,
        ExchangeKeysetDiscoveryV2, ExchangeReceiptKeyInfo, ExchangeTransitionDiscoveryV2,
        ExchangeTransitionSlotDiscoveryV2, VoprfKeyInfo, EXCHANGE_MAX_BUDGET_LIMIT,
        EXCHANGE_MAX_VALID_UNTIL,
    };
    use freebird_common::exchange_api::EXCHANGE_PROFILE_V2;
    use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};

    fn discovery() -> KeyDiscoveryResp {
        let provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
        KeyDiscoveryResp {
            issuer_id: "issuer:test:exchange".into(),
            current_epoch: 1,
            valid_epochs: vec![1],
            epoch_duration_sec: 86_400,
            voprf: VoprfKeyInfo {
                suite: "suite".into(),
                kid: "kid".into(),
                pubkey: "public".into(),
            },
            public: vec![PublicKeyInfo {
                token_key_id: hex::encode(provider.token_key_id()),
                token_type: freebird_crypto::PUBLIC_BEARER_TOKEN_TYPE.into(),
                rfc9474_variant: freebird_crypto::PUBLIC_BEARER_RFC9474_VARIANT.into(),
                modulus_bits: provider.modulus_bits(),
                pubkey_spki_b64: Base64UrlUnpadded::encode_string(provider.public_key_spki()),
                issuer_id: "issuer:test:exchange".into(),
                valid_from: 1,
                valid_until: EXCHANGE_MAX_VALID_UNTIL,
                audience: Some("audience".into()),
                spend_policy: freebird_crypto::PUBLIC_BEARER_SPEND_POLICY_SINGLE_USE.into(),
                max_uses: Some(1),
            }],
            exchange: None,
        }
    }

    fn descriptor_v2(provider: &SoftwareBlindRsaProvider) -> ExchangeDescriptorDiscoveryV2 {
        let mut descriptor = ExchangeDescriptorDiscoveryV2 {
            descriptor_id: String::new(),
            profile_id: EXCHANGE_PROFILE_V2.into(),
            issuer_id: "issuer:test:exchange".into(),
            token_key_id: hex::encode(provider.token_key_id()),
            audience: Some("audience".into()),
            pubkey_spki_b64: Base64UrlUnpadded::encode_string(provider.public_key_spki()),
            suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
            valid_from: 1,
            valid_until: EXCHANGE_MAX_VALID_UNTIL,
        };
        descriptor.descriptor_id = descriptor.canonical_descriptor_id().unwrap();
        descriptor
    }

    fn graph_v2_from_descriptors(
        descriptors: Vec<ExchangeDescriptorDiscoveryV2>,
    ) -> ExchangeGraphDiscoveryV2 {
        let keysets: Vec<_> = descriptors
            .iter()
            .map(|descriptor| {
                let mut keyset = ExchangeKeysetDiscoveryV2 {
                    keyset_id: String::new(),
                    descriptor_ids: vec![descriptor.descriptor_id.clone()],
                };
                keyset.keyset_id = keyset.canonical_keyset_id();
                keyset
            })
            .collect();
        let transition = |source: usize, target: usize, budget_id: &str| {
            let mut transition = ExchangeTransitionDiscoveryV2 {
                transition_id: String::new(),
                source_keyset_id: keysets[source].keyset_id.clone(),
                target_keyset_id: keysets[target].keyset_id.clone(),
                source_slots: vec![ExchangeTransitionSlotDiscoveryV2 {
                    descriptor_id: descriptors[source].descriptor_id.clone(),
                    slot_id: "input".into(),
                    class: "bearer".into(),
                    quantity: 1,
                }],
                output_slots: vec![ExchangeTransitionSlotDiscoveryV2 {
                    descriptor_id: descriptors[target].descriptor_id.clone(),
                    slot_id: "output".into(),
                    class: "bearer".into(),
                    quantity: 1,
                }],
                budget_id: budget_id.into(),
                budget_limit: 100,
                admission_state: ExchangeAdmissionStateV2::AcceptingNew,
            };
            transition.transition_id = transition.canonical_transition_id();
            transition
        };
        let transitions = vec![transition(0, 1, "a-to-b"), transition(1, 0, "b-to-a")];
        let mut graph = ExchangeGraphDiscoveryV2 {
            profile_id: EXCHANGE_PROFILE_V2.into(),
            graph_id: String::new(),
            descriptors,
            keysets,
            transitions,
        };
        graph.graph_id = graph.canonical_graph_id();
        graph
    }

    fn one_way_graph_v2_from_descriptors(
        descriptors: Vec<ExchangeDescriptorDiscoveryV2>,
    ) -> ExchangeGraphDiscoveryV2 {
        let mut graph = graph_v2_from_descriptors(descriptors);
        graph.transitions.truncate(1);
        graph.graph_id = graph.canonical_graph_id();
        graph
    }

    fn graph_v2() -> ExchangeGraphDiscoveryV2 {
        let a = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let b = SoftwareBlindRsaProvider::generate(2048).unwrap();
        graph_v2_from_descriptors(vec![descriptor_v2(&a), descriptor_v2(&b)])
    }

    fn discovery_v2(graph: ExchangeGraphDiscoveryV2) -> ExchangeDiscoveryV2 {
        ExchangeDiscoveryV2 {
            active_graph: graph,
            retained_graphs: vec![],
            active_receipt_key: receipt_key("exchange_receipt_active", 1),
            retained_receipt_keys: vec![],
        }
    }

    fn receipt_key(purpose: &str, byte: u8) -> ExchangeReceiptKeyInfo {
        use sha2::{Digest, Sha256};

        let public = [byte; 32];
        ExchangeReceiptKeyInfo {
            key_id: hex::encode(Sha256::digest(public)),
            algorithm: "Ed25519".into(),
            purpose: purpose.into(),
            public_key_b64: Base64UrlUnpadded::encode_string(&public),
            valid_from: 1,
            valid_until: EXCHANGE_MAX_VALID_UNTIL as u64,
        }
    }

    #[test]
    fn direct_v5_discovery_remains_trusted_without_exchange_metadata() {
        let keys = trusted_public_keys("issuer:test:exchange", discovery()).unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn trusts_valid_bidirectional_v2_graph() {
        let keys =
            validated_exchange_v2_public_keys("issuer:test:exchange", discovery_v2(graph_v2()))
                .unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn production_merge_is_atomic_and_rejects_direct_v5_collisions() {
        let graph = graph_v2();
        let mut combined = discovery();
        combined.exchange = Some(discovery_v2(graph.clone()));
        assert_eq!(
            trusted_public_keys("issuer:test:exchange", combined.clone())
                .unwrap()
                .len(),
            3
        );

        combined.public[0].token_key_id = graph.descriptors[1].token_key_id.clone();
        combined.public[0].pubkey_spki_b64 = graph.descriptors[1].pubkey_spki_b64.clone();
        assert!(trusted_public_keys("issuer:test:exchange", combined).is_err());

        let mut malformed = discovery();
        let mut graph = graph_v2();
        graph.transitions[1].transition_id = "a".repeat(64);
        malformed.exchange = Some(discovery_v2(graph));
        assert!(trusted_public_keys("issuer:test:exchange", malformed).is_err());
    }

    #[test]
    fn source_only_alias_extends_direct_key_to_global_identity_horizon() {
        let mut combined = discovery();
        combined.public[0].valid_until = 100;
        let direct = &combined.public[0];
        let mut source_alias = ExchangeDescriptorDiscoveryV2 {
            descriptor_id: String::new(),
            profile_id: EXCHANGE_PROFILE_V2.into(),
            issuer_id: direct.issuer_id.clone(),
            token_key_id: direct.token_key_id.clone(),
            audience: direct.audience.clone(),
            pubkey_spki_b64: direct.pubkey_spki_b64.clone(),
            suite: freebird_crypto::PUBLIC_BEARER_RFC9474_VARIANT.into(),
            valid_from: direct.valid_from,
            valid_until: 200,
        };
        source_alias.descriptor_id = source_alias.canonical_descriptor_id().unwrap();
        let output = descriptor_v2(&SoftwareBlindRsaProvider::generate(2048).unwrap());
        let graph = one_way_graph_v2_from_descriptors(vec![source_alias.clone(), output]);
        combined.exchange = Some(discovery_v2(graph));

        let keys = trusted_public_keys("issuer:test:exchange", combined.clone()).unwrap();
        let direct_id = freebird_crypto::decode_token_key_id_hex(&direct.token_key_id).unwrap();
        assert_eq!(keys.len(), 2, "source-only aliases must not add trust");
        assert_eq!(keys[&direct_id].valid_until, source_alias.valid_until);

        let mut conflicting_audience = source_alias;
        conflicting_audience.audience = Some("different-audience".into());
        conflicting_audience.descriptor_id =
            conflicting_audience.canonical_descriptor_id().unwrap();
        let output = descriptor_v2(&SoftwareBlindRsaProvider::generate(2048).unwrap());
        combined.exchange = Some(discovery_v2(one_way_graph_v2_from_descriptors(vec![
            conflicting_audience,
            output,
        ])));
        assert!(trusted_public_keys("issuer:test:exchange", combined).is_err());
    }

    #[test]
    fn rejects_tampered_v2_ids_and_selectors() {
        let valid = graph_v2();

        let mut bad_descriptor_id = valid.clone();
        bad_descriptor_id.descriptors[0].descriptor_id = "a".repeat(64);
        assert!(validated_exchange_v2_public_keys(
            "issuer:test:exchange",
            discovery_v2(bad_descriptor_id),
        )
        .is_err());

        let mut bad_transition_id = valid.clone();
        bad_transition_id.transitions[0].transition_id = "b".repeat(64);
        assert!(validated_exchange_v2_public_keys(
            "issuer:test:exchange",
            discovery_v2(bad_transition_id),
        )
        .is_err());

        let mut bad_selector = valid;
        bad_selector.transitions[0].source_keyset_id = "c".repeat(64);
        bad_selector.transitions[0].transition_id =
            bad_selector.transitions[0].canonical_transition_id();
        bad_selector.graph_id = bad_selector.canonical_graph_id();
        assert!(validated_exchange_v2_public_keys(
            "issuer:test:exchange",
            discovery_v2(bad_selector),
        )
        .is_err());
    }

    #[test]
    fn rejects_conflicting_reused_v2_key_metadata() {
        let valid = graph_v2();
        let first = valid.descriptors[0].clone();
        let mut conflicting = first.clone();
        conflicting.valid_from += 1;
        conflicting.descriptor_id = conflicting.canonical_descriptor_id().unwrap();
        let graph = graph_v2_from_descriptors(vec![first, conflicting]);

        assert!(
            validated_exchange_v2_public_keys("issuer:test:exchange", discovery_v2(graph),)
                .is_err()
        );
    }

    #[test]
    fn malformed_v2_graph_never_returns_partial_output_trust() {
        let mut graph = graph_v2();
        graph.transitions[1].output_slots[0].descriptor_id =
            graph.descriptors[1].descriptor_id.clone();
        graph.transitions[1].transition_id = graph.transitions[1].canonical_transition_id();
        graph.graph_id = graph.canonical_graph_id();

        let result = validated_exchange_v2_public_keys("issuer:test:exchange", discovery_v2(graph));
        assert!(result.is_err());
    }

    #[test]
    fn rejects_self_edges_and_accepting_retained_graphs() {
        let mut self_edge = graph_v2();
        self_edge.transitions[0].target_keyset_id =
            self_edge.transitions[0].source_keyset_id.clone();
        self_edge.transitions[0].output_slots[0].descriptor_id = self_edge.transitions[0]
            .source_slots[0]
            .descriptor_id
            .clone();
        self_edge.transitions[0].transition_id = self_edge.transitions[0].canonical_transition_id();
        self_edge.graph_id = self_edge.canonical_graph_id();
        assert!(
            validated_exchange_v2_public_keys("issuer:test:exchange", discovery_v2(self_edge),)
                .is_err()
        );

        let active = graph_v2();
        let retained = graph_v2();
        assert!(validated_exchange_v2_public_keys(
            "issuer:test:exchange",
            ExchangeDiscoveryV2 {
                active_graph: active,
                retained_graphs: vec![retained],
                active_receipt_key: receipt_key("exchange_receipt_active", 1),
                retained_receipt_keys: vec![receipt_key("exchange_receipt_retained", 2)],
            },
        )
        .is_err());
    }

    #[test]
    fn v2_trust_is_atomic_for_receipts_and_container_budget_contracts() {
        let active = graph_v2();
        let mut retained = active.clone();
        retained.transitions[0].source_slots[0].class = "retained".into();
        retained.transitions[0].budget_id = "retained-revision-budget".into();
        retained.transitions[0].transition_id = retained.transitions[0].canonical_transition_id();
        for transition in &mut retained.transitions {
            transition.admission_state =
                freebird_common::api::ExchangeAdmissionStateV2::RecoveryOnly;
        }
        retained.graph_id = retained.canonical_graph_id();
        let valid = ExchangeDiscoveryV2 {
            active_graph: active,
            retained_graphs: vec![retained],
            active_receipt_key: receipt_key("exchange_receipt_active", 1),
            retained_receipt_keys: vec![receipt_key("exchange_receipt_retained", 2)],
        };
        assert_eq!(
            validated_exchange_v2_public_keys("issuer:test:exchange", valid.clone())
                .unwrap()
                .len(),
            2
        );

        let mut bad_receipt = valid.clone();
        bad_receipt.active_receipt_key.key_id = "a".repeat(64);
        assert!(validated_exchange_v2_public_keys("issuer:test:exchange", bad_receipt).is_err());

        let mut bad_budget = valid;
        bad_budget.retained_graphs[0].transitions[1].budget_limit += 1;
        bad_budget.retained_graphs[0].transitions[1].transition_id =
            bad_budget.retained_graphs[0].transitions[1].canonical_transition_id();
        bad_budget.retained_graphs[0].graph_id = bad_budget.retained_graphs[0].canonical_graph_id();
        assert!(validated_exchange_v2_public_keys("issuer:test:exchange", bad_budget).is_err());
    }

    #[test]
    fn v2_rejects_values_outside_redis_exact_ranges() {
        let mut graph = graph_v2();
        graph.descriptors[0].valid_until = i64::MAX;
        graph.descriptors[0].descriptor_id =
            graph.descriptors[0].canonical_descriptor_id().unwrap();
        assert!(
            validated_exchange_v2_public_keys("issuer:test:exchange", discovery_v2(graph),)
                .is_err()
        );

        let mut graph = graph_v2();
        graph.transitions[0].budget_limit = EXCHANGE_MAX_BUDGET_LIMIT;
        graph.transitions[0].transition_id = graph.transitions[0].canonical_transition_id();
        graph.graph_id = graph.canonical_graph_id();
        assert!(
            validated_exchange_v2_public_keys("issuer:test:exchange", discovery_v2(graph),).is_ok()
        );

        let mut graph = graph_v2();
        graph.transitions[0].budget_limit = EXCHANGE_MAX_BUDGET_LIMIT + 1;
        graph.transitions[0].transition_id = graph.transitions[0].canonical_transition_id();
        graph.graph_id = graph.canonical_graph_id();
        assert!(
            validated_exchange_v2_public_keys("issuer:test:exchange", discovery_v2(graph),)
                .is_err()
        );
    }
}
