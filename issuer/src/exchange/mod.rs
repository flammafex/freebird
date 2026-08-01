// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(dead_code)]
//! Private Phase 2 exchange engine. No HTTP route is registered here.

pub mod history;
pub mod profiles;
pub mod receipt;
#[cfg(test)]
mod redis_harness;
#[cfg(test)]
mod redis_tests;
pub(crate) mod source_v5;
pub(crate) mod store;

use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::exchange_api::{
    decode_base64url, parse_operation_id, ExchangeReceiptV2, ExchangeRequestV2,
    ExchangeResultOutput, ExchangeResultV2, ExchangeSlot, EXCHANGE_VERSION_V2, MAX_ARTIFACT,
};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};
use store::{
    budget_policy_digest_v2, status_capability_digest_v2, ClaimOutcome, ExchangeStore, OutputWork,
    State, TransitionOutcome, V2OperationRecord, V2ReservationInput, V2ReserveOutcome,
    V2SourceSpend,
};
use subtle::ConstantTimeEq;

pub use profiles::ExchangeProfileV2;
pub use receipt::{load_or_generate_receipt_key, ReceiptKey, ReceiptKeyConfig, ReceiptKeyRing};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProcessDecision {
    Committed(Vec<u8>),
    Conflict,
    Retryable,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StatusDecision {
    Committed(Vec<u8>),
    Pending,
    Unknown,
    Unauthorized,
}

pub struct ExchangeEngine {
    store: ExchangeStore,
    v2: Option<Arc<V2Context>>,
    receipt_keys: Arc<ReceiptKeyRing>,
    issuer_id: String,
    receipt_lifetime_secs: u64,
}

#[derive(Serialize)]
struct ExchangeResponseV2<'a> {
    result: &'a ExchangeResultV2,
    receipt: &'a ExchangeReceiptV2,
}

struct V2Context {
    graphs: BTreeMap<String, ExchangeProfileV2>,
    signers: source_v5::PinnedTargetSignersV2,
    source_valid_until: BTreeMap<String, i64>,
}

impl ExchangeEngine {
    /// Build the graph-only V2 engine. Configuration/profile validation is
    /// performed by the configuration lane before this boundary; this loader
    /// additionally pins every signer and freezes the durable key registry.
    pub(crate) async fn new_v2(
        active: ExchangeProfileV2,
        retained: Vec<ExchangeProfileV2>,
        store: ExchangeStore,
        issuer_id: String,
        receipt_keys: ReceiptKeyRing,
        receipt_lifetime_secs: u64,
    ) -> Result<Self> {
        let mut source_valid_until = BTreeMap::new();
        for graph in std::iter::once(&active).chain(&retained) {
            for key in graph.keysets.iter().flat_map(|keyset| &keyset.keys) {
                source_valid_until
                    .entry(key.descriptor.kid.clone())
                    .and_modify(|until: &mut i64| *until = (*until).max(key.descriptor.valid_until))
                    .or_insert(key.descriptor.valid_until);
            }
        }
        Self::new_v2_with_source_validity(
            active,
            retained,
            store,
            issuer_id,
            receipt_keys,
            receipt_lifetime_secs,
            source_valid_until,
        )
        .await
    }

    pub(crate) async fn new_v2_with_source_validity(
        active: ExchangeProfileV2,
        retained: Vec<ExchangeProfileV2>,
        store: ExchangeStore,
        issuer_id: String,
        receipt_keys: ReceiptKeyRing,
        receipt_lifetime_secs: u64,
        source_valid_until: BTreeMap<String, i64>,
    ) -> Result<Self> {
        if receipt_lifetime_secs == 0 {
            bail!("receipt lifetime must be nonzero")
        }
        profiles::validate_exchange_profile_set_v2(&active, &retained, &issuer_id, None)?;
        let signers = source_v5::PinnedTargetSignersV2::load(&active, &retained)?;
        let mut graphs = BTreeMap::new();
        for graph in std::iter::once(active).chain(retained) {
            if graphs.insert(graph.graph_id.clone(), graph).is_some() {
                bail!("duplicate V2 graph id")
            }
        }
        let engine = Self {
            store,
            v2: Some(Arc::new(V2Context {
                graphs,
                signers,
                source_valid_until,
            })),
            receipt_keys: Arc::new(receipt_keys),
            issuer_id,
            receipt_lifetime_secs,
        };
        engine.validate_pending_signers_v2().await?;
        Ok(engine)
    }

    pub(crate) async fn process_or_recover_v2(
        &self,
        request: &ExchangeRequestV2,
        status_capability: &[u8; 32],
    ) -> Result<ProcessDecision> {
        let operation_id = match parse_operation_id(&request.public_operation_id) {
            Ok(id) => id,
            Err(_) => return Ok(ProcessDecision::Rejected),
        };
        let request_hash = match request.request_digest() {
            Ok(hash) => hash,
            Err(_) => return Ok(ProcessDecision::Rejected),
        };

        // Recovery is selected exclusively from persisted identities. Present-
        // day admission is consulted only after the work and signer references
        // have been loaded and authenticated.
        if let Some(record) = self.store.get_v2(&operation_id).await? {
            if record.request_hash != request_hash {
                return Ok(ProcessDecision::Conflict);
            }
            if !capability_authorized(&record, status_capability) {
                return Ok(ProcessDecision::Conflict);
            }
            return self.recover_v2(&operation_id, record).await;
        }

        let fresh = match self.validate_fresh_v2(request) {
            Ok(fresh) => fresh,
            Err(_) => return Ok(ProcessDecision::Rejected),
        };
        let receipt_key_id = self.receipt_keys.active_id().to_owned();
        let (receipt_valid_from, receipt_valid_until) = self.receipt_keys.active_validity()?;
        let receipt_ref = ExchangeStore::receipt_ref_key_v2(&receipt_key_id);
        let reservation = self
            .store
            .reserve_v2(V2ReservationInput {
                operation_id: &operation_id,
                public_operation_id: &request.public_operation_id,
                status_capability,
                request_hash: &request_hash,
                graph_id: &request.graph_id,
                transition_id: &request.transition_id,
                source_keyset_id: &request.source_keyset_id,
                target_keyset_id: &request.target_keyset_id,
                sources: &fresh.sources,
                outputs: &fresh.outputs,
                signer_ref_keys: &fresh.signer_refs,
                receipt_key_id: &receipt_key_id,
                receipt_ref_key: &receipt_ref,
                budget_id: &fresh.budget_id,
                budget_policy_digest: &fresh.budget_policy_digest,
                budget_limit: fresh.budget_limit,
                receipt_lifetime_secs: self.receipt_lifetime_secs,
                receipt_valid_from,
                receipt_valid_until,
            })
            .await?;
        match reservation {
            V2ReserveOutcome::Created(reservation) => {
                let record = self
                    .store
                    .get_v2(&operation_id)
                    .await?
                    .context("reserved V2 operation missing")?;
                self.execute_owned_v2(&operation_id, record, reservation.fence)
                    .await
            }
            V2ReserveOutcome::Existing(record) => {
                if record.request_hash != request_hash
                    || !capability_authorized(&record, status_capability)
                {
                    Ok(ProcessDecision::Conflict)
                } else {
                    self.recover_v2(&operation_id, *record).await
                }
            }
            V2ReserveOutcome::Conflict | V2ReserveOutcome::CapabilityMismatch => {
                Ok(ProcessDecision::Conflict)
            }
            V2ReserveOutcome::DuplicateSource
            | V2ReserveOutcome::Spent
            | V2ReserveOutcome::InvalidEntries
            | V2ReserveOutcome::BudgetPolicyConflict
            | V2ReserveOutcome::BudgetExhausted => Ok(ProcessDecision::Rejected),
        }
    }

    pub(crate) async fn status_v2(
        &self,
        operation_id: &[u8; 16],
        status_capability: &[u8; 32],
    ) -> Result<StatusDecision> {
        Ok(match self.store.get_v2(operation_id).await? {
            Some(record) if !capability_authorized(&record, status_capability) => {
                StatusDecision::Unauthorized
            }
            Some(record) if record.state == State::Committed => {
                StatusDecision::Committed(record.response.context("committed response missing")?)
            }
            Some(_) => StatusDecision::Pending,
            None => StatusDecision::Unknown,
        })
    }

    fn validate_fresh_v2(&self, request: &ExchangeRequestV2) -> Result<FreshWorkV2> {
        request
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let context = self.v2_context()?;
        let graph = context
            .graphs
            .get(&request.graph_id)
            .context("unknown exchange graph")?;
        let transition = graph
            .transitions
            .iter()
            .find(|transition| transition.id == request.transition_id)
            .context("unknown exchange transition")?;
        if transition.source_keyset_id != request.source_keyset_id
            || transition.target_keyset_id != request.target_keyset_id
            || !transition.admits_new()
        {
            bail!("selected transition does not admit fresh work")
        }
        if request.sources.len() != transition.sources.len() {
            bail!("source cardinality does not match selected transition")
        }
        let source_keyset = graph
            .keysets
            .iter()
            .find(|keyset| keyset.id == transition.source_keyset_id)
            .context("selected source keyset is unavailable")?;
        let mut sources = Vec::with_capacity(request.sources.len());
        for (source, expected) in request.sources.iter().zip(&transition.sources) {
            if source.slot.keyset_id != source_keyset.id
                || source.slot.descriptor_id != expected.descriptor_id
                || source.slot.slot_id != expected.slot_id
                || source.slot.quantity != expected.quantity
            {
                bail!("source does not satisfy selected transition")
            }
            let artifact = decode_base64url(&source.artifact, MAX_ARTIFACT)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let validated = source_v5::validate_source_v5_v2(
                source_keyset,
                &source.slot.descriptor_id,
                &artifact,
                &self.issuer_id,
            )?;
            let descriptor = source_keyset
                .keys
                .iter()
                .find(|key| key.descriptor.id == validated.descriptor_id)
                .map(|key| &key.descriptor)
                .context("selected source descriptor is unavailable")?;
            sources.push(V2SourceSpend {
                spend_key: validated.spend_key,
                valid_from: descriptor.valid_from,
                valid_until: *context
                    .source_valid_until
                    .get(&descriptor.kid)
                    .context("global V5 key validity is unavailable")?,
            });
        }
        let outputs = context.signers.validate_outputs(
            &transition.target_keyset_id,
            &transition.outputs,
            &request.outputs,
        )?;
        let signer_refs = context.signers.signer_ref_keys(&outputs)?;
        Ok(FreshWorkV2 {
            sources,
            outputs,
            signer_refs,
            budget_id: transition.budget_id.clone(),
            budget_policy_digest: budget_policy_digest_v2(&transition.stable_contract_bytes())?,
            budget_limit: transition.budget_limit,
        })
    }

    async fn recover_v2(
        &self,
        operation_id: &[u8; 16],
        mut record: V2OperationRecord,
    ) -> Result<ProcessDecision> {
        for _ in 0..8 {
            if record.state == State::Committed {
                return Ok(ProcessDecision::Committed(
                    record.response.context("committed V2 response missing")?,
                ));
            }
            if !self.record_signers_available_v2(&record) {
                return Ok(ProcessDecision::Retryable);
            }
            let transition = match self.transition_for_record_v2(&record) {
                Some(transition) => transition,
                None => return Ok(ProcessDecision::Retryable),
            };
            if !transition.allows_recovery() {
                return Ok(ProcessDecision::Rejected);
            }
            match self.store.claim_v2(operation_id).await? {
                ClaimOutcome::Claimed(reservation) => {
                    return self
                        .execute_owned_v2(operation_id, record, reservation.fence)
                        .await
                }
                ClaimOutcome::Live => return Ok(ProcessDecision::Retryable),
                ClaimOutcome::Committed | ClaimOutcome::InvalidState => {
                    record = self
                        .store
                        .get_v2(operation_id)
                        .await?
                        .context("V2 operation disappeared during recovery")?;
                }
                ClaimOutcome::Missing => return Ok(ProcessDecision::Retryable),
            }
        }
        Ok(ProcessDecision::Retryable)
    }

    async fn execute_owned_v2(
        &self,
        operation_id: &[u8; 16],
        mut record: V2OperationRecord,
        fence: Vec<u8>,
    ) -> Result<ProcessDecision> {
        let context = self.v2_context()?;
        if record.state == State::Reserved {
            let signatures = context
                .signers
                .sign_work(
                    &record.target_keyset_id,
                    &record.outputs,
                    &record.signer_refs,
                )
                .await?;
            let mut result = ExchangeResultV2 {
                version: EXCHANGE_VERSION_V2,
                public_operation_id: record.public_operation_id.clone(),
                graph_id: record.graph_id.clone(),
                transition_id: record.transition_id.clone(),
                source_keyset_id: record.source_keyset_id.clone(),
                target_keyset_id: record.target_keyset_id.clone(),
                outputs: record
                    .outputs
                    .iter()
                    .zip(signatures)
                    .map(|(output, signature)| ExchangeResultOutput {
                        slot: ExchangeSlot {
                            descriptor_id: output.descriptor_id.clone(),
                            keyset_id: output.keyset_id.clone(),
                            slot_id: output.slot_id.clone(),
                            quantity: output.quantity,
                        },
                        blinded_value: Base64UrlUnpadded::encode_string(&output.blinded_value),
                        blind_signature: Base64UrlUnpadded::encode_string(&signature),
                    })
                    .collect(),
                result_digest: String::new(),
            };
            let digest = result
                .result_digest()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            result.result_digest = Base64UrlUnpadded::encode_string(&digest);
            result
                .canonical_bytes()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let result_bytes = serde_json::to_vec(&result)?;
            match self
                .store
                .result_ready_v2(operation_id, &fence, &result_bytes, &digest)
                .await?
            {
                TransitionOutcome::Applied | TransitionOutcome::Repeated => {
                    record = self
                        .store
                        .get_v2(operation_id)
                        .await?
                        .context("V2 result operation missing")?;
                }
                TransitionOutcome::StaleFence
                | TransitionOutcome::InvalidState
                | TransitionOutcome::Conflict
                | TransitionOutcome::Underflow => {
                    return self.latest_v2_decision(operation_id).await;
                }
            }
        }
        if record.state != State::ResultReady {
            return Ok(ProcessDecision::Retryable);
        }
        let result: ExchangeResultV2 = serde_json::from_slice(
            record
                .result
                .as_deref()
                .context("persisted V2 result missing")?,
        )
        .context("invalid persisted V2 result")?;
        result
            .canonical_bytes()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        validate_result_record_binding_v2(&result, &record)?;
        let digest = record.result_digest.context("V2 result digest missing")?;
        if !bool::from(
            result
                .result_digest()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?
                .ct_eq(&digest),
        ) {
            bail!("persisted V2 result digest mismatch")
        }
        let mut receipt = ExchangeReceiptV2 {
            version: EXCHANGE_VERSION_V2,
            public_operation_id: record.public_operation_id.clone(),
            graph_id: record.graph_id.clone(),
            transition_id: record.transition_id.clone(),
            source_keyset_id: record.source_keyset_id.clone(),
            target_keyset_id: record.target_keyset_id.clone(),
            result_digest: Base64UrlUnpadded::encode_string(&digest),
            created_at: record.created_at,
            expires_at: record.receipt_expires_at,
            receipt_key_id: record.receipt_key_id.clone(),
            signature: String::new(),
        };
        let receipt_key = self.receipt_keys.recovery_signer(
            &record.receipt_key_id,
            record.created_at,
            record.receipt_expires_at,
        )?;
        receipt.signature =
            Base64UrlUnpadded::encode_string(&receipt_key.sign_receipt_v2(&receipt)?);
        receipt
            .validate_result(&result)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let receipt_bytes = serde_json::to_vec(&receipt)?;
        let response = serde_json::to_vec(&ExchangeResponseV2 {
            result: &result,
            receipt: &receipt,
        })?;
        match self
            .store
            .commit_v2(operation_id, &fence, &receipt_bytes, &response)
            .await?
        {
            TransitionOutcome::Applied | TransitionOutcome::Repeated => {
                Ok(ProcessDecision::Committed(response))
            }
            TransitionOutcome::StaleFence
            | TransitionOutcome::InvalidState
            | TransitionOutcome::Conflict
            | TransitionOutcome::Underflow => self.latest_v2_decision(operation_id).await,
        }
    }

    async fn latest_v2_decision(&self, operation_id: &[u8; 16]) -> Result<ProcessDecision> {
        let latest = self
            .store
            .get_v2(operation_id)
            .await?
            .context("V2 operation missing after transition race")?;
        if latest.state == State::Committed {
            Ok(ProcessDecision::Committed(
                latest.response.context("committed V2 response missing")?,
            ))
        } else {
            Ok(ProcessDecision::Retryable)
        }
    }

    fn transition_for_record_v2(
        &self,
        record: &V2OperationRecord,
    ) -> Option<&profiles::ExchangeTransitionV2> {
        let graph = self.v2.as_ref()?.graphs.get(&record.graph_id)?;
        let transition = graph
            .transitions
            .iter()
            .find(|transition| transition.id == record.transition_id)?;
        (transition.source_keyset_id == record.source_keyset_id
            && transition.target_keyset_id == record.target_keyset_id)
            .then_some(())
            .filter(|_| record.outputs.len() == transition.outputs.len())
            .filter(|_| {
                record
                    .outputs
                    .iter()
                    .zip(&transition.outputs)
                    .all(|(output, slot)| {
                        output.keyset_id == transition.target_keyset_id
                            && output.descriptor_id == slot.descriptor_id
                            && output.slot_id == slot.slot_id
                            && output.quantity == slot.quantity
                    })
            })
            .map(|_| transition)
    }

    fn record_signers_available_v2(&self, record: &V2OperationRecord) -> bool {
        match record.state {
            State::Reserved => {
                self.v2.as_ref().is_some_and(|context| {
                    context.signers.supports_work(
                        &record.target_keyset_id,
                        &record.outputs,
                        &record.signer_refs,
                    )
                }) && self
                    .receipt_keys
                    .recovery_signer(
                        &record.receipt_key_id,
                        record.created_at,
                        record.receipt_expires_at,
                    )
                    .is_ok()
            }
            State::ResultReady => self
                .receipt_keys
                .recovery_signer(
                    &record.receipt_key_id,
                    record.created_at,
                    record.receipt_expires_at,
                )
                .is_ok(),
            State::Committed => true,
        }
    }

    async fn validate_pending_signers_v2(&self) -> Result<()> {
        for record in self.store.pending_records_v2().await? {
            if !self.record_signers_available_v2(&record) {
                bail!("pending V2 exchange requires unavailable persisted signers")
            }
        }
        Ok(())
    }

    fn v2_context(&self) -> Result<&V2Context> {
        self.v2
            .as_deref()
            .context("V2 exchange engine is unavailable")
    }

    pub(crate) async fn readiness_check(&self) -> Result<()> {
        self.store.validate_durable_standalone().await?;
        self.validate_pending_signers_v2().await
    }
}

struct FreshWorkV2 {
    sources: Vec<V2SourceSpend>,
    outputs: Vec<OutputWork>,
    signer_refs: Vec<String>,
    budget_id: String,
    budget_policy_digest: [u8; 32],
    budget_limit: u64,
}

fn capability_authorized(record: &V2OperationRecord, capability: &[u8; 32]) -> bool {
    bool::from(
        record
            .status_capability_digest
            .ct_eq(&status_capability_digest_v2(capability)),
    )
}

fn validate_result_record_binding_v2(
    result: &ExchangeResultV2,
    record: &V2OperationRecord,
) -> Result<()> {
    if result.version != EXCHANGE_VERSION_V2
        || result.public_operation_id != record.public_operation_id
        || result.graph_id != record.graph_id
        || result.transition_id != record.transition_id
        || result.source_keyset_id != record.source_keyset_id
        || result.target_keyset_id != record.target_keyset_id
        || result.outputs.len() != record.outputs.len()
    {
        bail!("persisted V2 result selector binding mismatch")
    }
    for (result, output) in result.outputs.iter().zip(&record.outputs) {
        if result.slot.descriptor_id != output.descriptor_id
            || result.slot.keyset_id != output.keyset_id
            || result.slot.slot_id != output.slot_id
            || result.slot.quantity != output.quantity
            || result.blinded_value != Base64UrlUnpadded::encode_string(&output.blinded_value)
        {
            bail!("persisted V2 result output binding mismatch")
        }
    }
    Ok(())
}
