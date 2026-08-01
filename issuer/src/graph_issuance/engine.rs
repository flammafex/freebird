// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Graph issuance policy engine and public decisions.

use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::graph_issuance_api::{
    self, GraphIssuanceRequestV2, GraphIssuanceResultV2, ReplayAuthorityProbeV1,
    GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL, GRAPH_ISSUANCE_QUANTITY, GRAPH_ISSUANCE_VERSION_V2,
    MAX_BLINDED_MESSAGE,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use subtle::ConstantTimeEq;

use freebird_common::api::GraphIssuanceDiscoveryV2;

use super::{
    authorizer::GraphIssuanceAuthorizer,
    policy::{
        GraphIssuanceAdmissionState, GraphIssuancePolicy, GraphIssuancePolicyDocument,
        POLICY_DOCUMENT_VERSION,
    },
    store::{status_digest, GraphIssuanceStore, ReserveOutcome, StoredOperation},
};
use crate::exchange::{profiles::ExchangeProfileV2, source_v5::PinnedTargetSignersV2};

/// Use the same filtered signer loader as runtime startup without opening a
/// Redis connection or mutating durable state. The offline validator calls
/// this exact path so graph issuance cannot pass validation with a signer
/// file runtime would reject.
pub fn validate_runtime_graph_issuance_signers(
    active: &ExchangeProfileV2,
    retained: &[ExchangeProfileV2],
    document: &GraphIssuancePolicyDocument,
) -> Result<()> {
    let required = document
        .policies
        .iter()
        .filter(|policy| policy.admission_state == GraphIssuanceAdmissionState::AcceptingNew)
        .map(|policy| policy.descriptor_id.clone())
        .collect::<HashSet<_>>();
    if !required.is_empty() {
        let _ = PinnedTargetSignersV2::load_for_graph_issuance(active, retained, &required)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessDecision {
    Committed(Vec<u8>),
    Conflict,
    Rejected,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusDecision {
    Committed(Vec<u8>),
    Unknown,
    Unauthorized,
}

pub struct GraphIssuanceEngine {
    enabled: bool,
    active_graph_id: String,
    policies: HashMap<String, GraphIssuancePolicy>,
    policy_order: Vec<String>,
    signers: Option<PinnedTargetSignersV2>,
    store: GraphIssuanceStore,
    authorizer: Arc<dyn GraphIssuanceAuthorizer>,
}

impl GraphIssuanceEngine {
    pub fn new(
        active: &ExchangeProfileV2,
        retained: &[ExchangeProfileV2],
        document: GraphIssuancePolicyDocument,
        redis_url: &str,
        authorizer: Arc<dyn GraphIssuanceAuthorizer>,
    ) -> Result<Self> {
        Self::new_with_enabled(active, retained, document, redis_url, authorizer, true)
    }

    pub fn new_with_enabled(
        active: &ExchangeProfileV2,
        retained: &[ExchangeProfileV2],
        document: GraphIssuancePolicyDocument,
        redis_url: &str,
        authorizer: Arc<dyn GraphIssuanceAuthorizer>,
        enabled: bool,
    ) -> Result<Self> {
        document.validate(active, retained)?;
        for policy in &document.policies {
            if policy.admission_state == GraphIssuanceAdmissionState::AcceptingNew {
                authorizer.validate_policy_configuration(policy)?;
                let descriptor = active
                    .keysets
                    .iter()
                    .find(|keyset| keyset.id == policy.keyset_id)
                    .and_then(|keyset| {
                        keyset
                            .keys
                            .iter()
                            .find(|key| key.descriptor.id == policy.descriptor_id)
                    })
                    .context("graph issuance signer descriptor is unavailable")?;
                if descriptor.descriptor.valid_from <= 0
                    || descriptor.descriptor.valid_from >= descriptor.descriptor.valid_until
                    || descriptor.descriptor.valid_until
                        > freebird_common::api::EXCHANGE_MAX_VALID_UNTIL
                {
                    bail!("graph issuance signer validity window is invalid")
                }
            }
        }
        let needs_signers = document
            .policies
            .iter()
            .any(|policy| policy.admission_state == GraphIssuanceAdmissionState::AcceptingNew);
        let required_descriptors = document
            .policies
            .iter()
            .filter(|policy| policy.admission_state == GraphIssuanceAdmissionState::AcceptingNew)
            .map(|policy| policy.descriptor_id.clone())
            .collect::<HashSet<_>>();
        Ok(Self {
            enabled,
            active_graph_id: active.graph_id.clone(),
            policy_order: document
                .policies
                .iter()
                .map(|policy| policy.issuance_policy_id.clone())
                .collect(),
            policies: document
                .policies
                .into_iter()
                .map(|policy| (policy.issuance_policy_id.clone(), policy))
                .collect(),
            signers: if needs_signers {
                Some(PinnedTargetSignersV2::load_for_graph_issuance(
                    active,
                    retained,
                    &required_descriptors,
                )?)
            } else {
                None
            },
            store: GraphIssuanceStore::new(redis_url)?,
            authorizer,
        })
    }

    /// Complete durable authority initialization only after all policy and
    /// signer validation has succeeded. This ordering keeps a failed fresh
    /// configuration from leaving an authority identity behind.
    pub async fn initialize(&mut self) -> Result<GraphIssuanceDiscoveryV2> {
        self.store.redis_time().await?;
        let scopes = self
            .policies
            .values()
            .filter(|policy| policy.authorization_scheme == GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL)
            .filter_map(|policy| policy.v4_local.as_ref())
            .map(|v4| {
                freebird_crypto::build_scope_digest(&v4.verifier_id, &v4.audience)
                    .map_err(|_| anyhow::anyhow!("invalid graph issuance V4 scope"))
            })
            .collect::<Result<Vec<_>>>()?;
        self.store.initialize_replay_authority(&scopes).await?;
        self.discovery_from_durable().await
    }

    fn discovery_from_state(
        &self,
        authority: &[u8; 32],
        tombstones: &[[u8; 32]],
    ) -> GraphIssuanceDiscoveryV2 {
        let authority_id = Base64UrlUnpadded::encode_string(authority);
        let tombstones = tombstones
            .iter()
            .map(|scope| Base64UrlUnpadded::encode_string(scope))
            .collect::<Vec<_>>();
        let document = GraphIssuancePolicyDocument {
            version: POLICY_DOCUMENT_VERSION.into(),
            policies: self
                .policy_order
                .iter()
                .filter_map(|id| self.policies.get(id).cloned())
                .collect(),
        };
        document.discovery(&authority_id, &tombstones)
    }

    /// Build discovery from the complete durable Redis authority state. This
    /// is intentionally asynchronous so publication cannot use a startup
    /// snapshot after Redis has been edited, restored, or corrupted.
    pub async fn discovery_from_durable(&self) -> Result<GraphIssuanceDiscoveryV2> {
        let (authority, tombstones) = self.store.read_replay_authority_state().await?;
        Ok(self.discovery_from_state(&authority, &tombstones))
    }

    pub fn issuance_enabled(&self) -> bool {
        self.enabled
    }

    pub async fn replay_authority_probe(
        &self,
        probe: &ReplayAuthorityProbeV1,
        issuer_id: &str,
    ) -> Result<Option<[u8; 32]>> {
        probe
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        self.store.replay_authority_probe(probe, issuer_id).await
    }

    pub async fn readiness_check(&self) -> bool {
        let Ok((_authority, tombstones)) = self.store.read_replay_authority_state().await else {
            return false;
        };
        let required_scopes = self
            .policies
            .values()
            .filter(|policy| policy.authorization_scheme == GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL)
            .filter_map(|policy| policy.v4_local.as_ref())
            .filter_map(|v4| {
                freebird_crypto::build_scope_digest(&v4.verifier_id, &v4.audience).ok()
            })
            .collect::<Vec<_>>();
        if required_scopes
            .iter()
            .any(|scope| !tombstones.contains(scope))
        {
            return false;
        }
        let Ok(now) = self.store.redis_time().await else {
            return false;
        };
        self.policies.values().all(|policy| {
            if policy.admission_state != GraphIssuanceAdmissionState::AcceptingNew
                || policy.graph_id != self.active_graph_id
            {
                return true;
            }
            self.signers
                .as_ref()
                .and_then(|signers| signers.graph_issuance_validity(&policy.descriptor_id).ok())
                .is_some_and(|(first, last)| now >= first && now <= last)
        })
    }

    fn validate_stored_response(
        record: &StoredOperation,
        expected_operation_id: Option<&[u8; 16]>,
    ) -> Result<Vec<u8>> {
        let result: GraphIssuanceResultV2 = serde_json::from_slice(&record.response)
            .context("corrupt stored graph issuance response")?;
        result
            .validate()
            .map_err(|error| anyhow::anyhow!("corrupt stored graph issuance response: {error}"))?;
        let blind_signature = freebird_common::exchange_api::decode_base64url(
            &result.blind_signature,
            graph_issuance_api::MAX_BLIND_SIGNATURE,
        )
        .map_err(|error| anyhow::anyhow!("corrupt stored graph issuance response: {error}"))?;
        if blind_signature.is_empty() {
            bail!("corrupt stored graph issuance response signature")
        }
        if result.issuance_policy_id != record.issuance_policy_id
            || result.graph_id != record.graph_id
            || result.keyset_id != record.keyset_id
            || result.descriptor_id != record.descriptor_id
            || result.token_key_id != record.signer_key_id
            || result.quantity != GRAPH_ISSUANCE_QUANTITY
            || record.quantity != GRAPH_ISSUANCE_QUANTITY
        {
            bail!("corrupt stored graph issuance response selectors")
        }
        if let Some(operation_id) = expected_operation_id {
            if result.public_operation_id != Base64UrlUnpadded::encode_string(operation_id) {
                bail!("corrupt stored graph issuance operation selector")
            }
        }
        let digest = graph_issuance_api::decode_digest(&result.request_digest)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if !bool::from(digest.ct_eq(&record.request_digest)) {
            bail!("corrupt stored graph issuance request digest")
        }
        Ok(record.response.clone())
    }

    pub async fn process(
        &self,
        request: &GraphIssuanceRequestV2,
        status_capability: &[u8; 32],
    ) -> Result<ProcessDecision> {
        let operation_id = match request.operation_id() {
            Ok(value) => value,
            Err(_) => return Ok(ProcessDecision::Rejected),
        };
        let request_digest = match request.request_digest() {
            Ok(value) => value,
            Err(_) => return Ok(ProcessDecision::Rejected),
        };
        if let Some(existing) = self.store.get(&operation_id).await? {
            let response = Self::validate_stored_response(&existing, Some(&operation_id))?;
            return Ok(
                if existing.request_digest != request_digest
                    || !bool::from(
                        existing
                            .status_capability_digest
                            .ct_eq(&status_digest(status_capability)),
                    )
                {
                    ProcessDecision::Conflict
                } else {
                    let result: GraphIssuanceResultV2 = serde_json::from_slice(&response)?;
                    result
                        .validate_against(request, &existing.signer_key_id)
                        .map_err(|error| {
                            anyhow::anyhow!("corrupt stored graph issuance response: {error}")
                        })?;
                    ProcessDecision::Committed(response)
                },
            );
        }
        if !self.enabled {
            return Ok(ProcessDecision::Unavailable);
        }
        let Some(policy) = self.policies.get(&request.issuance_policy_id) else {
            return Ok(ProcessDecision::Rejected);
        };
        if policy.admission_state != GraphIssuanceAdmissionState::AcceptingNew
            || policy.graph_id != self.active_graph_id
            || request.graph_id != policy.graph_id
            || request.keyset_id != policy.keyset_id
            || request.descriptor_id != policy.descriptor_id
        {
            return Ok(ProcessDecision::Rejected);
        }
        let signers = self
            .signers
            .as_ref()
            .context("graph issuance signer set is unavailable")?;
        let (descriptor_valid_from, descriptor_valid_until) =
            signers.graph_issuance_validity(&policy.descriptor_id)?;
        let now = self.store.redis_time().await?;
        if now < descriptor_valid_from || now > descriptor_valid_until {
            return Ok(ProcessDecision::Rejected);
        }
        let blinded = match freebird_common::exchange_api::decode_base64url(
            &request.blinded_message,
            MAX_BLINDED_MESSAGE,
        ) {
            Ok(value) if !value.is_empty() => value,
            _ => return Ok(ProcessDecision::Rejected),
        };
        let authorization_claim = match self.authorizer.authorize(
            policy,
            &request
                .authorization_binding_digest()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            &request.authorization,
        ) {
            Ok(value) => value,
            Err(_) => return Ok(ProcessDecision::Rejected),
        };
        let (signer_key_id, blind_signature) = match signers
            .sign_graph_issuance(&policy.keyset_id, &policy.descriptor_id, &blinded)
            .await
        {
            Ok(value) => value,
            Err(_) => return Ok(ProcessDecision::Rejected),
        };
        let mut result = GraphIssuanceResultV2 {
            version: GRAPH_ISSUANCE_VERSION_V2,
            public_operation_id: request.public_operation_id.clone(),
            issuance_policy_id: policy.issuance_policy_id.clone(),
            graph_id: policy.graph_id.clone(),
            keyset_id: policy.keyset_id.clone(),
            descriptor_id: policy.descriptor_id.clone(),
            token_key_id: signer_key_id.clone(),
            quantity: policy.quantity,
            request_digest: Base64UrlUnpadded::encode_string(&request_digest),
            blind_signature: Base64UrlUnpadded::encode_string(&blind_signature),
            result_digest: String::new(),
        };
        if blind_signature.is_empty() {
            bail!("graph issuance signer returned an empty signature")
        }
        result.result_digest = Base64UrlUnpadded::encode_string(
            &result
                .calculated_result_digest()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        );
        result
            .validate_against(request, &signer_key_id)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let response = serde_json::to_vec(&result)?;
        Ok(
            match self
                .store
                .reserve(
                    &operation_id,
                    &request_digest,
                    status_capability,
                    policy,
                    &authorization_claim.nullifier_digest,
                    authorization_claim.global_spend_key.as_deref(),
                    &signer_key_id,
                    &blind_signature,
                    &response,
                    descriptor_valid_from,
                    descriptor_valid_until,
                )
                .await?
            {
                ReserveOutcome::Created => ProcessDecision::Committed(response),
                ReserveOutcome::Existing(existing) => {
                    let response = Self::validate_stored_response(&existing, Some(&operation_id))?;
                    if existing.request_digest != request_digest
                        || !bool::from(
                            existing
                                .status_capability_digest
                                .ct_eq(&status_digest(status_capability)),
                        )
                    {
                        ProcessDecision::Conflict
                    } else {
                        let stored: GraphIssuanceResultV2 = serde_json::from_slice(&response)?;
                        stored
                            .validate_against(request, &existing.signer_key_id)
                            .map_err(|error| {
                                anyhow::anyhow!("corrupt stored graph issuance response: {error}")
                            })?;
                        ProcessDecision::Committed(response)
                    }
                }
                ReserveOutcome::Conflict => ProcessDecision::Conflict,
                ReserveOutcome::AuthorizationUsed
                | ReserveOutcome::PolicyConflict
                | ReserveOutcome::BudgetExhausted
                | ReserveOutcome::DescriptorWindow => ProcessDecision::Rejected,
            },
        )
    }

    pub async fn status(
        &self,
        operation_id: &[u8; 16],
        status_capability: &[u8; 32],
    ) -> Result<StatusDecision> {
        Ok(match self.store.get(operation_id).await? {
            None => StatusDecision::Unknown,
            Some(record)
                if !bool::from(
                    record
                        .status_capability_digest
                        .ct_eq(&status_digest(status_capability)),
                ) =>
            {
                StatusDecision::Unauthorized
            }
            Some(record) => {
                let response = Self::validate_stored_response(&record, Some(operation_id))?;
                StatusDecision::Committed(response)
            }
        })
    }
}
