// SPDX-License-Identifier: Apache-2.0 OR MIT
use serde::{Deserialize, Serialize};

/// Largest positive integer represented exactly by Redis Lua numbers.
pub const EXCHANGE_LUA_MAX_EXACT_INTEGER: u64 = (1u64 << 53) - 1;
/// Largest inclusive exchange validity timestamp accepted by Redis/Lua paths.
pub const EXCHANGE_MAX_VALID_UNTIL: i64 = EXCHANGE_LUA_MAX_EXACT_INTEGER as i64;
/// Largest exchange budget represented exactly by Redis/Lua paths.
pub const EXCHANGE_MAX_BUDGET_LIMIT: u64 = EXCHANGE_LUA_MAX_EXACT_INTEGER;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphIssuanceReplayAuthorityDiscoveryV1 {
    /// The permanent Redis-backed replay authority identity.
    pub authority_id: String,
    /// Scope identities are retained forever once a V4-local policy could have
    /// consumed a non-expiring V4 replay marker.
    #[serde(default)]
    pub v4_scope_digest_tombstones: Vec<String>,
}

pub type ReplayAuthorityDiscoveryV1 = GraphIssuanceReplayAuthorityDiscoveryV1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphIssuanceDiscoveryV2 {
    pub version: u8,
    pub policies: Vec<GraphIssuancePolicyDiscoveryV2>,
    pub replay_authority: GraphIssuanceReplayAuthorityDiscoveryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphIssuancePolicyDiscoveryV2 {
    pub issuance_policy_id: String,
    pub graph_id: String,
    pub keyset_id: String,
    pub descriptor_id: String,
    pub budget_id: String,
    pub budget_limit: u64,
    pub quantity: u32,
    pub admission_state: ExchangeAdmissionStateV2,
    pub authorization_scheme: String,
    /// Present exactly for `v4_local`.  The value is public because it is a
    /// verifier replay namespace selector, not a raw verifier scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_scope_digest_b64: Option<String>,
}

pub type GraphIssuancePolicyDiscovery = GraphIssuancePolicyDiscoveryV2;
pub type GraphIssuanceDiscovery = GraphIssuanceDiscoveryV2;

fn validate_graph_issuance_replay_authority(
    authority: &GraphIssuanceReplayAuthorityDiscoveryV1,
) -> Result<std::collections::HashSet<[u8; 32]>, String> {
    use base64ct::Encoding;

    crate::graph_issuance_api::decode_authority_id(&authority.authority_id)
        .map_err(|error| error.to_string())?;
    if authority.v4_scope_digest_tombstones.len() > crate::exchange_api::MAX_ITEMS {
        return Err("invalid graph issuance replay authority metadata".into());
    }
    let mut tombstones = std::collections::HashSet::new();
    for digest in &authority.v4_scope_digest_tombstones {
        let raw =
            crate::graph_issuance_api::decode_digest(digest).map_err(|error| error.to_string())?;
        if !tombstones.insert(raw) || base64ct::Base64UrlUnpadded::encode_string(&raw) != *digest {
            return Err("invalid graph issuance V4 scope tombstone".into());
        }
    }
    Ok(tombstones)
}

fn validate_graph_issuance_policy_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= crate::exchange_api::MAX_ID && value.is_ascii()
}

fn validate_graph_issuance_authorization_metadata(
    policy: &GraphIssuancePolicyDiscoveryV2,
    tombstones: &std::collections::HashSet<[u8; 32]>,
) -> Result<(), String> {
    use base64ct::Encoding;

    let supported = matches!(
        policy.authorization_scheme.as_str(),
        crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_HMAC_SHA256
            | crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL
            | crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_DEVELOPMENT_MOCK
    );
    if !supported {
        return Err("invalid graph issuance authorization scheme".into());
    }
    match (
        policy.authorization_scheme.as_str(),
        policy.authorization_scope_digest_b64.as_deref(),
    ) {
        (crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL, Some(scope)) => {
            let raw = crate::graph_issuance_api::decode_digest(scope)
                .map_err(|error| error.to_string())?;
            if !tombstones.contains(&raw)
                || base64ct::Base64UrlUnpadded::encode_string(&raw) != scope
            {
                return Err("V4 graph issuance scope is not retained by replay authority".into());
            }
        }
        (crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL, None) => {
            return Err("V4 graph issuance scope metadata is missing".into());
        }
        (_, Some(_)) => {
            return Err("non-V4 graph issuance policy contains V4 scope metadata".into());
        }
        (_, None) => {}
    }
    Ok(())
}

pub fn validate_graph_issuance_discovery_v2(
    exchange: &ExchangeDiscoveryV2,
    issuance: &GraphIssuanceDiscoveryV2,
) -> Result<(), String> {
    use std::collections::HashSet;

    if issuance.version != crate::graph_issuance_api::GRAPH_ISSUANCE_VERSION_V2
        || issuance.policies.len() > crate::exchange_api::MAX_ITEMS
    {
        return Err("invalid graph issuance discovery bounds".into());
    }
    let tombstones = validate_graph_issuance_replay_authority(&issuance.replay_authority)?;
    let mut policy_ids = HashSet::new();
    let mut budget_ids = HashSet::new();
    for policy in &issuance.policies {
        let graph = std::iter::once((&exchange.active_graph, true))
            .chain(exchange.retained_graphs.iter().map(|graph| (graph, false)))
            .find(|(graph, _)| graph.graph_id == policy.graph_id)
            .ok_or_else(|| "graph issuance policy references an unknown graph".to_string())?;
        let keyset = graph
            .0
            .keysets
            .iter()
            .find(|keyset| keyset.keyset_id == policy.keyset_id)
            .ok_or_else(|| "graph issuance policy references an unknown keyset".to_string())?;
        if crate::graph_issuance_api::validate_lowercase_hex_id(&policy.graph_id).is_err()
            || crate::graph_issuance_api::validate_lowercase_hex_id(&policy.keyset_id).is_err()
            || crate::graph_issuance_api::validate_lowercase_hex_id(&policy.descriptor_id).is_err()
            || !validate_graph_issuance_policy_id(&policy.issuance_policy_id)
            || !validate_graph_issuance_policy_id(&policy.budget_id)
            || !validate_graph_issuance_policy_id(&policy.authorization_scheme)
            || policy.budget_limit == 0
            || policy.budget_limit > EXCHANGE_MAX_BUDGET_LIMIT
            || policy.quantity != crate::graph_issuance_api::GRAPH_ISSUANCE_QUANTITY
            || !keyset.descriptor_ids.contains(&policy.descriptor_id)
            || !policy_ids.insert(policy.issuance_policy_id.as_str())
            || !budget_ids.insert(policy.budget_id.as_str())
            || (policy.admission_state == ExchangeAdmissionStateV2::AcceptingNew && !graph.1)
        {
            return Err("invalid graph issuance policy metadata".into());
        }
        validate_graph_issuance_authorization_metadata(policy, &tombstones)?;
    }
    Ok(())
}

/// Validate a discovery lifecycle update without allowing the replay authority
/// or its V4 scope tombstone set to move backwards.
///
/// Only `next` is validated against `current_exchange`.  The previous
/// discovery may legitimately refer to a graph which has since been retired
/// or replaced; callers which have the historical exchange snapshot may
/// validate it separately.  The replay-authority container itself is
/// permanent, so an existing container may not disappear.
pub fn validate_graph_issuance_discovery_v2_update(
    current_exchange: &ExchangeDiscoveryV2,
    previous: Option<&GraphIssuanceDiscoveryV2>,
    next: Option<&GraphIssuanceDiscoveryV2>,
) -> Result<(), String> {
    let Some(next) = next else {
        if previous.is_some() {
            return Err("graph issuance replay authority container was removed".into());
        }
        return Ok(());
    };

    validate_graph_issuance_discovery_v2(current_exchange, next)?;
    let Some(previous) = previous else {
        return Ok(());
    };

    // Validate only the durable authority container from the historical
    // snapshot.  Revalidating its policy graph against the current exchange
    // would reject legitimate retirement/replacement transitions.
    if previous.version != crate::graph_issuance_api::GRAPH_ISSUANCE_VERSION_V2 {
        return Err("invalid previous graph issuance discovery version".into());
    }
    validate_graph_issuance_replay_authority(&previous.replay_authority)?;
    if previous.replay_authority.authority_id != next.replay_authority.authority_id {
        return Err("graph issuance replay authority changed".into());
    }
    let old = previous
        .replay_authority
        .v4_scope_digest_tombstones
        .iter()
        .collect::<std::collections::HashSet<_>>();
    if !old.iter().all(|digest| {
        next.replay_authority
            .v4_scope_digest_tombstones
            .contains(digest)
    }) {
        return Err("graph issuance replay authority tombstones are not append-only".into());
    }
    Ok(())
}

#[cfg(test)]
mod graph_issuance_discovery_tests {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};

    fn exchange() -> ExchangeDiscoveryV2 {
        ExchangeDiscoveryV2 {
            active_graph: ExchangeGraphDiscoveryV2 {
                profile_id: String::new(),
                graph_id: "1".repeat(64),
                descriptors: Vec::new(),
                keysets: vec![ExchangeKeysetDiscoveryV2 {
                    keyset_id: "2".repeat(64),
                    descriptor_ids: vec!["3".repeat(64)],
                }],
                transitions: Vec::new(),
            },
            retained_graphs: Vec::new(),
            active_receipt_key: ExchangeReceiptKeyInfo {
                key_id: String::new(),
                algorithm: String::new(),
                purpose: String::new(),
                public_key_b64: String::new(),
                valid_from: 0,
                valid_until: 0,
            },
            retained_receipt_keys: Vec::new(),
        }
    }

    fn discovery(
        authorization_scheme: &str,
        scope: Option<String>,
        tombstones: Vec<String>,
    ) -> GraphIssuanceDiscoveryV2 {
        GraphIssuanceDiscoveryV2 {
            version: crate::graph_issuance_api::GRAPH_ISSUANCE_VERSION_V2,
            policies: vec![GraphIssuancePolicyDiscoveryV2 {
                issuance_policy_id: "policy-v2".into(),
                graph_id: "1".repeat(64),
                keyset_id: "2".repeat(64),
                descriptor_id: "3".repeat(64),
                budget_id: "budget-v2".into(),
                budget_limit: 1,
                quantity: 1,
                admission_state: ExchangeAdmissionStateV2::RecoveryOnly,
                authorization_scheme: authorization_scheme.into(),
                authorization_scope_digest_b64: scope,
            }],
            replay_authority: GraphIssuanceReplayAuthorityDiscoveryV1 {
                authority_id: Base64UrlUnpadded::encode_string(&[9; 32]),
                v4_scope_digest_tombstones: tombstones,
            },
        }
    }

    #[test]
    fn discovery_requires_exact_scope_presence_and_combination() {
        let scope = Base64UrlUnpadded::encode_string(&[8; 32]);
        let valid_v4 = discovery(
            crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL,
            Some(scope.clone()),
            vec![scope.clone()],
        );
        assert!(validate_graph_issuance_discovery_v2(&exchange(), &valid_v4).is_ok());

        let missing_scope = discovery(
            crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL,
            None,
            vec![],
        );
        assert!(validate_graph_issuance_discovery_v2(&exchange(), &missing_scope).is_err());

        let hmac_with_scope = discovery(
            crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_HMAC_SHA256,
            Some(scope),
            vec![],
        );
        assert!(validate_graph_issuance_discovery_v2(&exchange(), &hmac_with_scope).is_err());

        let unknown_scheme = discovery("other", None, vec![]);
        assert!(validate_graph_issuance_discovery_v2(&exchange(), &unknown_scheme).is_err());
    }

    #[test]
    fn discovery_requires_one_artifact_and_replay_authority_tombstones_are_canonical() {
        let mut valid = discovery(
            crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_HMAC_SHA256,
            None,
            vec![],
        );
        assert!(validate_graph_issuance_discovery_v2(&exchange(), &valid).is_ok());
        valid.policies[0].quantity = 2;
        assert!(validate_graph_issuance_discovery_v2(&exchange(), &valid).is_err());

        let mut malformed = discovery(
            crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_HMAC_SHA256,
            None,
            vec![Base64UrlUnpadded::encode_string(&[7; 31])],
        );
        assert!(validate_graph_issuance_discovery_v2(&exchange(), &malformed).is_err());
        malformed = discovery(
            crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_HMAC_SHA256,
            None,
            vec![Base64UrlUnpadded::encode_string(&[7; 32]); 2],
        );
        assert!(validate_graph_issuance_discovery_v2(&exchange(), &malformed).is_err());
    }

    #[test]
    fn discovery_tombstones_are_append_only_and_authority_is_permanent() {
        let scope = Base64UrlUnpadded::encode_string(&[8; 32]);
        let previous = discovery(
            crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL,
            Some(scope.clone()),
            vec![scope.clone()],
        );
        let mut next = previous.clone();
        next.replay_authority
            .v4_scope_digest_tombstones
            .push(Base64UrlUnpadded::encode_string(&[7; 32]));
        assert!(validate_graph_issuance_discovery_v2_update(
            &exchange(),
            Some(&previous),
            Some(&next)
        )
        .is_ok());

        let mut removed = previous.clone();
        removed.replay_authority.v4_scope_digest_tombstones.clear();
        assert!(validate_graph_issuance_discovery_v2_update(
            &exchange(),
            Some(&previous),
            Some(&removed)
        )
        .is_err());

        let mut changed_authority = previous;
        changed_authority.replay_authority.authority_id =
            Base64UrlUnpadded::encode_string(&[6; 32]);
        assert!(validate_graph_issuance_discovery_v2_update(
            &exchange(),
            Some(&changed_authority),
            Some(&next)
        )
        .is_err());

        let mut retired = next;
        retired.policies.clear();
        assert!(validate_graph_issuance_discovery_v2(&exchange(), &retired).is_ok());
    }

    #[test]
    fn lifecycle_validates_next_against_current_exchange_but_allows_retired_previous_graphs() {
        let scope = Base64UrlUnpadded::encode_string(&[8; 32]);
        let mut previous = discovery(
            crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL,
            Some(scope.clone()),
            vec![scope.clone()],
        );
        previous.policies[0].graph_id = "4".repeat(64);
        let next = discovery(
            crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL,
            Some(scope),
            vec![Base64UrlUnpadded::encode_string(&[8; 32])],
        );
        assert!(validate_graph_issuance_discovery_v2_update(
            &exchange(),
            Some(&previous),
            Some(&next)
        )
        .is_ok());

        let mut bad_next = next.clone();
        bad_next.policies[0].graph_id = "5".repeat(64);
        assert!(validate_graph_issuance_discovery_v2_update(
            &exchange(),
            Some(&previous),
            Some(&bad_next)
        )
        .is_err());
    }

    #[test]
    fn lifecycle_rejects_permanent_authority_container_removal() {
        let previous = discovery(
            crate::graph_issuance_api::GRAPH_ISSUANCE_AUTHORIZATION_HMAC_SHA256,
            None,
            vec![],
        );
        assert!(
            validate_graph_issuance_discovery_v2_update(&exchange(), Some(&previous), None)
                .is_err()
        );
        assert!(validate_graph_issuance_discovery_v2_update(&exchange(), None, None).is_ok());
        assert!(
            validate_graph_issuance_discovery_v2_update(&exchange(), None, Some(&previous)).is_ok()
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeReceiptKeyInfo {
    pub key_id: String,
    pub algorithm: String,
    pub purpose: String,
    pub public_key_b64: String,
    pub valid_from: u64,
    pub valid_until: u64,
}

/// Public, immutable V2 exchange graph metadata. The active graph is kept
/// separate from retained graphs so consumers never have to infer lifecycle
/// state from graph contents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeDiscoveryV2 {
    pub active_graph: ExchangeGraphDiscoveryV2,
    #[serde(default)]
    pub retained_graphs: Vec<ExchangeGraphDiscoveryV2>,
    pub active_receipt_key: ExchangeReceiptKeyInfo,
    #[serde(default)]
    pub retained_receipt_keys: Vec<ExchangeReceiptKeyInfo>,
}

/// A role-neutral exchange graph. Descriptors and keysets can appear on either
/// side of a transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeGraphDiscoveryV2 {
    pub profile_id: String,
    pub graph_id: String,
    pub descriptors: Vec<ExchangeDescriptorDiscoveryV2>,
    pub keysets: Vec<ExchangeKeysetDiscoveryV2>,
    pub transitions: Vec<ExchangeTransitionDiscoveryV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeDescriptorDiscoveryV2 {
    pub descriptor_id: String,
    pub profile_id: String,
    pub issuer_id: String,
    pub token_key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    pub pubkey_spki_b64: String,
    pub suite: String,
    pub valid_from: i64,
    pub valid_until: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeKeysetDiscoveryV2 {
    pub keyset_id: String,
    /// Canonical ordered descriptor membership.
    pub descriptor_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeTransitionSlotDiscoveryV2 {
    pub descriptor_id: String,
    pub slot_id: String,
    pub class: String,
    pub quantity: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeAdmissionStateV2 {
    AcceptingNew,
    RecoveryOnly,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeTransitionDiscoveryV2 {
    pub transition_id: String,
    pub source_keyset_id: String,
    pub target_keyset_id: String,
    pub source_slots: Vec<ExchangeTransitionSlotDiscoveryV2>,
    pub output_slots: Vec<ExchangeTransitionSlotDiscoveryV2>,
    pub budget_id: String,
    pub budget_limit: u64,
    pub admission_state: ExchangeAdmissionStateV2,
}

// Alternate `Info` names keep these discovery DTOs consistent with the other
// public API models without duplicating wire models.
pub type ExchangeGraphInfoV2 = ExchangeGraphDiscoveryV2;
pub type ExchangeDescriptorInfoV2 = ExchangeDescriptorDiscoveryV2;
pub type ExchangeKeysetInfoV2 = ExchangeKeysetDiscoveryV2;
pub type ExchangeTransitionInfoV2 = ExchangeTransitionDiscoveryV2;
pub type ExchangeTransitionSlotInfoV2 = ExchangeTransitionSlotDiscoveryV2;

fn put_exchange_v2(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn put_optional_exchange_v2(output: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            output.push(1);
            put_exchange_v2(output, value.as_bytes());
        }
        None => {
            output.push(0);
            put_exchange_v2(output, &[]);
        }
    }
}

impl ExchangeDescriptorDiscoveryV2 {
    pub fn canonical_descriptor_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        for value in [
            &self.profile_id,
            &self.issuer_id,
            &self.token_key_id,
            &self.suite,
        ] {
            put_exchange_v2(&mut bytes, value.as_bytes());
        }
        put_optional_exchange_v2(&mut bytes, self.audience.as_deref());
        let spki = crate::exchange_api::decode_base64url(&self.pubkey_spki_b64, 4096)
            .map_err(|error| error.to_string())?;
        put_exchange_v2(&mut bytes, &spki);
        bytes.extend_from_slice(&self.valid_from.to_be_bytes());
        bytes.extend_from_slice(&self.valid_until.to_be_bytes());
        Ok(bytes)
    }

    pub fn canonical_descriptor_id(&self) -> Result<String, String> {
        Ok(crate::exchange_api::descriptor_id_v2(
            &self.canonical_descriptor_bytes()?,
        ))
    }
}

impl ExchangeKeysetDiscoveryV2 {
    pub fn canonical_keyset_id(&self) -> String {
        crate::exchange_api::keyset_id_v2(&self.descriptor_ids)
    }
}

impl ExchangeTransitionDiscoveryV2 {
    pub fn stable_contract_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_exchange_v2(&mut bytes, self.source_keyset_id.as_bytes());
        put_exchange_v2(&mut bytes, self.target_keyset_id.as_bytes());
        put_exchange_transition_slots_v2(&mut bytes, &self.source_slots);
        put_exchange_transition_slots_v2(&mut bytes, &self.output_slots);
        put_exchange_v2(&mut bytes, self.budget_id.as_bytes());
        bytes.extend_from_slice(&self.budget_limit.to_be_bytes());
        bytes
    }

    pub fn canonical_transition_id(&self) -> String {
        crate::exchange_api::transition_id_v2(&self.stable_contract_bytes())
    }

    /// The immutable transition and policy contract pinned by `budget_id`.
    /// Admission state is deliberately excluded so lifecycle-only revisions
    /// can reuse the same lifetime budget.
    pub fn budget_contract_bytes(&self) -> Vec<u8> {
        self.stable_contract_bytes()
    }
}

fn put_exchange_transition_slots_v2(
    output: &mut Vec<u8>,
    slots: &[ExchangeTransitionSlotDiscoveryV2],
) {
    output.extend_from_slice(&(slots.len() as u32).to_be_bytes());
    for slot in slots {
        put_exchange_v2(output, slot.descriptor_id.as_bytes());
        put_exchange_v2(output, slot.slot_id.as_bytes());
        put_exchange_v2(output, slot.class.as_bytes());
        output.extend_from_slice(&slot.quantity.to_be_bytes());
    }
}

impl ExchangeGraphDiscoveryV2 {
    pub fn canonical_graph_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_exchange_v2(&mut bytes, self.profile_id.as_bytes());
        for keyset in &self.keysets {
            put_exchange_v2(&mut bytes, keyset.keyset_id.as_bytes());
        }
        for transition in &self.transitions {
            put_exchange_v2(&mut bytes, transition.transition_id.as_bytes());
        }
        bytes
    }

    pub fn canonical_graph_id(&self) -> String {
        crate::exchange_api::graph_id_v2(&self.canonical_graph_bytes())
    }
}

impl ExchangeReceiptKeyInfo {
    pub fn canonical_key_id(&self) -> Result<String, String> {
        use sha2::{Digest, Sha256};

        let public = crate::exchange_api::decode_base64url(&self.public_key_b64, 32)
            .map_err(|error| error.to_string())?;
        if public.len() != 32 {
            return Err("Ed25519 receipt verification key must be 32 bytes".into());
        }
        Ok(hex::encode(Sha256::digest(public)))
    }
}

/// Validate one complete V2 discovery trust container. No graph or receipt key
/// is trustworthy unless this all-or-nothing validation succeeds.
pub fn validate_exchange_discovery_v2(
    issuer_id: &str,
    discovery: &ExchangeDiscoveryV2,
) -> Result<(), String> {
    use std::collections::{HashMap, HashSet};

    if discovery.retained_graphs.len() >= crate::exchange_api::MAX_ITEMS
        || discovery.retained_receipt_keys.len() >= crate::exchange_api::MAX_ITEMS
    {
        return Err("too many retained V2 exchange trust objects".into());
    }

    let mut graph_ids = HashSet::new();
    let mut descriptor_contracts = HashMap::new();
    let mut budget_contracts = HashMap::<String, Vec<u8>>::new();
    for (graph, retained) in std::iter::once((&discovery.active_graph, false))
        .chain(discovery.retained_graphs.iter().map(|graph| (graph, true)))
    {
        if !graph_ids.insert(graph.graph_id.as_str()) {
            return Err("duplicate active or retained V2 exchange graph".into());
        }
        validate_exchange_graph_v2(
            issuer_id,
            graph,
            retained,
            &mut descriptor_contracts,
            &mut budget_contracts,
        )?;
    }

    let mut receipt_ids = HashSet::new();
    validate_exchange_receipt_key_v2(
        &discovery.active_receipt_key,
        "exchange_receipt_active",
        &mut receipt_ids,
    )?;
    for key in &discovery.retained_receipt_keys {
        validate_exchange_receipt_key_v2(key, "exchange_receipt_retained", &mut receipt_ids)?;
    }
    Ok(())
}

fn validate_exchange_receipt_key_v2<'a>(
    key: &'a ExchangeReceiptKeyInfo,
    purpose: &str,
    ids: &mut std::collections::HashSet<&'a str>,
) -> Result<(), String> {
    crate::exchange_api::validate_receipt_key_id(&key.key_id).map_err(|error| error.to_string())?;
    if key.algorithm != "Ed25519"
        || key.purpose != purpose
        || key.valid_from == 0
        || key.valid_from >= key.valid_until
        || key.valid_until > EXCHANGE_MAX_VALID_UNTIL as u64
        || key.canonical_key_id()? != key.key_id
        || !ids.insert(key.key_id.as_str())
    {
        return Err("invalid V2 exchange receipt verification key".into());
    }
    Ok(())
}

fn validate_exchange_graph_v2<'a>(
    issuer_id: &str,
    graph: &'a ExchangeGraphDiscoveryV2,
    retained: bool,
    descriptor_contracts: &mut std::collections::HashMap<
        &'a str,
        &'a ExchangeDescriptorDiscoveryV2,
    >,
    budget_contracts: &mut std::collections::HashMap<String, Vec<u8>>,
) -> Result<(), String> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, HashSet};

    let max_items = crate::exchange_api::MAX_ITEMS;
    if graph.profile_id != crate::exchange_api::EXCHANGE_PROFILE_V2
        || graph.descriptors.is_empty()
        || graph.descriptors.len() > max_items
        || graph.keysets.is_empty()
        || graph.keysets.len() > max_items
        || graph.transitions.is_empty()
        || graph.transitions.len() > max_items
    {
        return Err("invalid V2 exchange graph bounds".into());
    }
    crate::exchange_api::validate_graph_id(&graph.graph_id).map_err(|error| error.to_string())?;
    if graph.graph_id != graph.canonical_graph_id() {
        return Err("non-canonical V2 exchange graph id".into());
    }

    let mut descriptors = HashMap::new();
    let mut graph_key_ids = HashSet::new();
    for descriptor in &graph.descriptors {
        crate::exchange_api::validate_descriptor_id(&descriptor.descriptor_id)
            .map_err(|error| error.to_string())?;
        let spki = crate::exchange_api::decode_base64url(&descriptor.pubkey_spki_b64, 4096)
            .map_err(|error| error.to_string())?;
        if descriptor.profile_id != crate::exchange_api::EXCHANGE_PROFILE_V2
            || descriptor.issuer_id != issuer_id
            || descriptor.suite != "RSABSSA-SHA384-PSS-Deterministic"
            || descriptor.valid_from <= 0
            || descriptor.valid_from >= descriptor.valid_until
            || descriptor.valid_until > EXCHANGE_MAX_VALID_UNTIL
            || descriptor.audience.as_ref().is_some_and(|audience| {
                audience.is_empty()
                    || audience.len() > crate::exchange_api::MAX_ID
                    || !audience.is_ascii()
            })
            || descriptor.canonical_descriptor_id()? != descriptor.descriptor_id
            || Base64UrlUnpadded::encode_string(&spki) != descriptor.pubkey_spki_b64
            || hex::encode(Sha256::digest(&spki)) != descriptor.token_key_id
            || freebird_crypto::validate_public_bearer_spki(&spki).is_err()
            || !graph_key_ids.insert(descriptor.token_key_id.as_str())
            || descriptors
                .insert(descriptor.descriptor_id.as_str(), descriptor)
                .is_some()
        {
            return Err("invalid immutable V2 exchange descriptor".into());
        }
        if let Some(existing) =
            descriptor_contracts.insert(descriptor.token_key_id.as_str(), descriptor)
        {
            if existing != descriptor {
                return Err("conflicting reused V2 exchange key metadata".into());
            }
        }
    }

    let mut keysets = HashMap::new();
    let mut memberships = HashSet::new();
    for keyset in &graph.keysets {
        crate::exchange_api::validate_keyset_id(&keyset.keyset_id)
            .map_err(|error| error.to_string())?;
        if keyset.descriptor_ids.is_empty()
            || keyset.descriptor_ids.len() > max_items
            || keyset.keyset_id != keyset.canonical_keyset_id()
        {
            return Err("invalid canonical V2 exchange keyset".into());
        }
        let mut members = HashSet::new();
        for descriptor_id in &keyset.descriptor_ids {
            if !descriptors.contains_key(descriptor_id.as_str())
                || !members.insert(descriptor_id.as_str())
                || !memberships.insert(descriptor_id.as_str())
            {
                return Err("invalid V2 exchange keyset membership".into());
            }
        }
        if keysets.insert(keyset.keyset_id.as_str(), members).is_some() {
            return Err("duplicate V2 exchange keyset id".into());
        }
    }
    if memberships.len() != descriptors.len() {
        return Err("unpublished V2 exchange keyset membership".into());
    }

    let mut transition_ids = HashSet::new();
    let mut graph_budget_ids = HashSet::new();
    for transition in &graph.transitions {
        crate::exchange_api::validate_transition_id(&transition.transition_id)
            .map_err(|error| error.to_string())?;
        validate_exchange_ascii_v2("transition budget", &transition.budget_id)?;
        let source_members = keysets
            .get(transition.source_keyset_id.as_str())
            .ok_or_else(|| "unknown V2 source keyset selector".to_string())?;
        let target_members = keysets
            .get(transition.target_keyset_id.as_str())
            .ok_or_else(|| "unknown V2 target keyset selector".to_string())?;
        if transition.source_keyset_id == transition.target_keyset_id
            || transition.transition_id != transition.canonical_transition_id()
            || !transition_ids.insert(transition.transition_id.as_str())
            || transition.budget_limit == 0
            || transition.budget_limit > EXCHANGE_MAX_BUDGET_LIMIT
            || !graph_budget_ids.insert(transition.budget_id.as_str())
            || retained && transition.admission_state == ExchangeAdmissionStateV2::AcceptingNew
        {
            return Err("invalid stable V2 exchange transition metadata".into());
        }
        let budget_contract = transition.budget_contract_bytes();
        if let Some(existing) = budget_contracts.get(&transition.budget_id) {
            if existing != &budget_contract {
                return Err("conflicting reused V2 exchange budget contract".into());
            }
        } else {
            budget_contracts.insert(transition.budget_id.clone(), budget_contract);
        }
        validate_exchange_slots_v2(&transition.source_slots, source_members)?;
        validate_exchange_slots_v2(&transition.output_slots, target_members)?;
        let output_quantity = transition.output_slots.iter().try_fold(0u64, |sum, slot| {
            sum.checked_add(u64::from(slot.quantity))
                .ok_or_else(|| "V2 output quantity overflow".to_string())
        })?;
        if output_quantity > transition.budget_limit {
            return Err("V2 output quantity exceeds static budget".into());
        }
    }
    Ok(())
}

fn validate_exchange_slots_v2(
    slots: &[ExchangeTransitionSlotDiscoveryV2],
    keyset_members: &std::collections::HashSet<&str>,
) -> Result<(), String> {
    use std::collections::HashSet;

    if slots.is_empty() || slots.len() > crate::exchange_api::MAX_ITEMS {
        return Err("invalid V2 transition slot bounds".into());
    }
    let mut slot_ids = HashSet::new();
    let mut descriptor_ids = HashSet::new();
    for slot in slots {
        crate::exchange_api::validate_descriptor_id(&slot.descriptor_id)
            .map_err(|error| error.to_string())?;
        validate_exchange_ascii_v2("transition slot id", &slot.slot_id)?;
        validate_exchange_ascii_v2("transition slot class", &slot.class)?;
        if slot.quantity == 0
            || slot.quantity > 64
            || !keyset_members.contains(slot.descriptor_id.as_str())
            || !slot_ids.insert(slot.slot_id.as_str())
            || !descriptor_ids.insert(slot.descriptor_id.as_str())
        {
            return Err("invalid V2 transition slot membership".into());
        }
    }
    Ok(())
}

fn validate_exchange_ascii_v2(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > crate::exchange_api::MAX_ID || !value.is_ascii() {
        return Err(format!("invalid {name}"));
    }
    Ok(())
}

#[cfg(test)]
mod exchange_metadata_tests {
    use super::super::key_discovery::KeyDiscoveryResp;
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};
    use sha2::{Digest, Sha256};

    fn graph_v2() -> ExchangeGraphDiscoveryV2 {
        let mut descriptors = Vec::new();
        for _ in 0..2 {
            let provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
            let spki = provider.public_key_spki();
            let mut descriptor = ExchangeDescriptorDiscoveryV2 {
                descriptor_id: String::new(),
                profile_id: crate::exchange_api::EXCHANGE_PROFILE_V2.into(),
                issuer_id: "issuer:test".into(),
                token_key_id: hex::encode(Sha256::digest(spki)),
                audience: Some("audience".into()),
                pubkey_spki_b64: Base64UrlUnpadded::encode_string(spki),
                suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
                valid_from: 1,
                valid_until: 2,
            };
            descriptor.descriptor_id = descriptor.canonical_descriptor_id().unwrap();
            descriptors.push(descriptor);
        }
        let mut keysets: Vec<_> = descriptors
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
        let transition = |source: usize, target: usize, budget: &str| {
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
                budget_id: budget.into(),
                budget_limit: 100,
                admission_state: ExchangeAdmissionStateV2::AcceptingNew,
            };
            transition.transition_id = transition.canonical_transition_id();
            transition
        };
        let transitions = vec![transition(0, 1, "a-to-b"), transition(1, 0, "b-to-a")];
        let mut graph = ExchangeGraphDiscoveryV2 {
            profile_id: crate::exchange_api::EXCHANGE_PROFILE_V2.into(),
            graph_id: String::new(),
            descriptors,
            keysets: std::mem::take(&mut keysets),
            transitions,
        };
        graph.graph_id = graph.canonical_graph_id();
        graph
    }

    fn receipt_key(purpose: &str) -> ExchangeReceiptKeyInfo {
        let public = [if purpose == "exchange_receipt_active" {
            7u8
        } else {
            8u8
        }; 32];
        ExchangeReceiptKeyInfo {
            key_id: hex::encode(Sha256::digest(public)),
            algorithm: "Ed25519".into(),
            purpose: purpose.into(),
            public_key_b64: Base64UrlUnpadded::encode_string(&public),
            valid_from: 1,
            valid_until: EXCHANGE_MAX_VALID_UNTIL as u64,
        }
    }

    fn assert_no_sensitive_keys(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    assert!(![
                        "artifact",
                        "artifacts",
                        "source_value",
                        "source_values",
                        "status_capability",
                        "private_key_path",
                        "pending_references",
                        "spent_count",
                        "issued_count",
                    ]
                    .contains(&key.as_str()));
                    assert_no_sensitive_keys(value);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    assert_no_sensitive_keys(value);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn receipt_metadata_round_trips_and_unrelated_discovery_remains_compatible() {
        let key = ExchangeReceiptKeyInfo {
            key_id: "a".repeat(64),
            algorithm: "Ed25519".into(),
            purpose: "exchange_receipt_active".into(),
            public_key_b64: "AQ".into(),
            valid_from: 0,
            valid_until: u64::MAX,
        };
        assert_eq!(
            serde_json::from_value::<ExchangeReceiptKeyInfo>(serde_json::to_value(&key).unwrap())
                .unwrap(),
            key
        );
        let unrelated = serde_json::json!({
            "issuer_id":"issuer:test",
            "current_epoch":1,
            "valid_epochs":[1],
            "epoch_duration_sec":86400,
            "voprf":{"suite":"suite","kid":"kid","pubkey":"key"},
            "public":[]
        });
        assert!(serde_json::from_value::<KeyDiscoveryResp>(unrelated)
            .unwrap()
            .exchange
            .is_none());
    }

    #[test]
    fn v2_graph_model_is_role_neutral_stable_and_public_only() {
        let graph = graph_v2();
        assert_eq!(graph.graph_id, graph.canonical_graph_id());
        assert_eq!(graph.transitions.len(), 2);
        assert_ne!(
            graph.transitions[0].transition_id,
            graph.transitions[1].transition_id
        );

        let discovery = ExchangeDiscoveryV2 {
            active_graph: graph.clone(),
            retained_graphs: vec![ExchangeGraphDiscoveryV2 {
                transitions: graph
                    .transitions
                    .iter()
                    .cloned()
                    .map(|mut transition| {
                        transition.admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
                        transition
                    })
                    .collect(),
                ..graph
            }],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![receipt_key("exchange_receipt_retained")],
        };
        assert_eq!(
            discovery.retained_graphs[0].graph_id,
            discovery.retained_graphs[0].canonical_graph_id()
        );
        assert_no_sensitive_keys(&serde_json::to_value(discovery).unwrap());
    }

    #[test]
    fn v2_discovery_validates_graphs_receipts_and_shared_budget_contracts_atomically() {
        let active = graph_v2();
        let mut retained = active.clone();
        retained.transitions[0].source_slots[0].class = "retained-bearer".into();
        retained.transitions[0].budget_id = "retained-a-to-b".into();
        retained.transitions[0].transition_id = retained.transitions[0].canonical_transition_id();
        for transition in &mut retained.transitions {
            transition.admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
        }
        retained.graph_id = retained.canonical_graph_id();
        let valid = ExchangeDiscoveryV2 {
            active_graph: active,
            retained_graphs: vec![retained],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![receipt_key("exchange_receipt_retained")],
        };
        assert!(validate_exchange_discovery_v2("issuer:test", &valid).is_ok());

        let mut bad_budget = valid.clone();
        bad_budget.retained_graphs[0].transitions[1].budget_limit += 1;
        bad_budget.retained_graphs[0].transitions[1].transition_id =
            bad_budget.retained_graphs[0].transitions[1].canonical_transition_id();
        bad_budget.retained_graphs[0].graph_id = bad_budget.retained_graphs[0].canonical_graph_id();
        assert!(validate_exchange_discovery_v2("issuer:test", &bad_budget).is_err());

        let mut bad_receipt = valid.clone();
        bad_receipt.active_receipt_key.algorithm = "operator-selected".into();
        assert!(validate_exchange_discovery_v2("issuer:test", &bad_receipt).is_err());

        let mut bad_receipt = valid.clone();
        bad_receipt.active_receipt_key.purpose = "exchange_receipt_retained".into();
        assert!(validate_exchange_discovery_v2("issuer:test", &bad_receipt).is_err());

        let mut bad_receipt = valid.clone();
        bad_receipt.active_receipt_key.public_key_b64.push('=');
        assert!(validate_exchange_discovery_v2("issuer:test", &bad_receipt).is_err());

        let mut bad_receipt = valid.clone();
        bad_receipt.active_receipt_key.valid_until = i64::MAX as u64;
        assert!(validate_exchange_discovery_v2("issuer:test", &bad_receipt).is_err());

        let mut bad_retained = valid;
        bad_retained.retained_graphs[0].transitions[0].admission_state =
            ExchangeAdmissionStateV2::AcceptingNew;
        assert!(validate_exchange_discovery_v2("issuer:test", &bad_retained).is_err());
    }

    #[test]
    fn v2_budget_ids_are_unique_per_graph_and_pin_the_full_contract_across_revisions() {
        let active = graph_v2();
        let mut duplicate = active.clone();
        duplicate.transitions[1].budget_id = duplicate.transitions[0].budget_id.clone();
        duplicate.transitions[1].transition_id = duplicate.transitions[1].canonical_transition_id();
        duplicate.graph_id = duplicate.canonical_graph_id();
        let discovery = ExchangeDiscoveryV2 {
            active_graph: duplicate,
            retained_graphs: vec![],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![],
        };
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_err());

        let mut retained = active.clone();
        for transition in &mut retained.transitions {
            transition.admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
        }
        retained.transitions[0].budget_id = "revision-only-budget".into();
        retained.transitions[0].transition_id = retained.transitions[0].canonical_transition_id();
        retained.graph_id = retained.canonical_graph_id();
        let mut discovery = ExchangeDiscoveryV2 {
            active_graph: active,
            retained_graphs: vec![retained],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![receipt_key("exchange_receipt_retained")],
        };
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_ok());
        discovery.retained_graphs[0].transitions[1].source_slots[0].class = "changed".into();
        discovery.retained_graphs[0].transitions[1].transition_id =
            discovery.retained_graphs[0].transitions[1].canonical_transition_id();
        discovery.retained_graphs[0].graph_id = discovery.retained_graphs[0].canonical_graph_id();
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_err());
    }

    #[test]
    fn v2_uses_the_lua_exact_positive_integer_bound_for_all_numeric_trust() {
        let mut discovery = ExchangeDiscoveryV2 {
            active_graph: graph_v2(),
            retained_graphs: vec![],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![],
        };
        discovery.active_graph.transitions[0].budget_limit = EXCHANGE_MAX_BUDGET_LIMIT;
        discovery.active_graph.transitions[0].transition_id =
            discovery.active_graph.transitions[0].canonical_transition_id();
        discovery.active_graph.graph_id = discovery.active_graph.canonical_graph_id();
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_ok());

        discovery.active_graph.transitions[0].budget_limit = EXCHANGE_MAX_BUDGET_LIMIT + 1;
        discovery.active_graph.transitions[0].transition_id =
            discovery.active_graph.transitions[0].canonical_transition_id();
        discovery.active_graph.graph_id = discovery.active_graph.canonical_graph_id();
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_err());

        let mut discovery = ExchangeDiscoveryV2 {
            active_graph: graph_v2(),
            retained_graphs: vec![],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![],
        };
        discovery.active_graph.descriptors[0].valid_from = 0;
        discovery.active_graph.descriptors[0].descriptor_id = discovery.active_graph.descriptors[0]
            .canonical_descriptor_id()
            .unwrap();
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_err());

        let mut discovery = ExchangeDiscoveryV2 {
            active_graph: graph_v2(),
            retained_graphs: vec![],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![],
        };
        discovery.active_receipt_key.valid_from = 0;
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_err());
    }
}
