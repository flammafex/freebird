// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(dead_code)]
//! Private Phase 2 exchange engine. No HTTP route is registered here.

#[cfg(test)]
mod engine_tests;
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
    decode_base64url, ExchangeReceipt, ExchangeRequest, ExchangeResult, ExchangeResultOutput,
    ExchangeSlot, MAX_ARTIFACT,
};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};
use store::{
    capacity_key, receipt_ref_key, target_ref_key, CapacityEntry, ClaimOutcome, ExchangeStore,
    OperationRecord, OutputWork, ReservationInput, ReserveOutcome, State, TransitionOutcome,
};

pub use profiles::{ExchangeDescriptor, ExchangeKeyset, ExchangeProfile, ExchangeSourceAllowlist};
pub use receipt::{load_or_generate_receipt_key, ReceiptKey, ReceiptKeyRing};

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
}

pub struct ExchangeEngine {
    profile: Arc<ExchangeProfile>,
    store: ExchangeStore,
    signers: Arc<source_v5::PinnedTargetSigners>,
    receipt_keys: Arc<ReceiptKeyRing>,
    issuer_id: String,
    receipt_lifetime_secs: u64,
}

#[derive(Serialize)]
struct ExchangeResponse<'a> {
    result: &'a ExchangeResult,
    receipt: &'a ExchangeReceipt,
}

impl ExchangeEngine {
    pub(crate) async fn new(
        profile: ExchangeProfile,
        retained_profiles: Vec<ExchangeProfile>,
        store: ExchangeStore,
        issuer_id: String,
        receipt_keys: ReceiptKeyRing,
        receipt_lifetime_secs: u64,
    ) -> Result<Self> {
        if receipt_lifetime_secs == 0 {
            bail!("receipt lifetime must be nonzero")
        }
        profile.validate_issuer_id(&issuer_id)?;
        for retained in &retained_profiles {
            retained.validate_issuer_id(&issuer_id)?;
        }
        let signers = Arc::new(source_v5::PinnedTargetSigners::load(
            &profile,
            &retained_profiles,
        )?);
        let engine = Self {
            profile: Arc::new(profile),
            store,
            signers,
            receipt_keys: Arc::new(receipt_keys),
            issuer_id,
            receipt_lifetime_secs,
        };
        engine.validate_pending_signers().await?;
        Ok(engine)
    }

    /// The sole exchange orchestration boundary. The source artifacts are read
    /// only from `request`; exact existing operations are resolved before any
    /// present-day descriptor, source-signature, or signer validation.
    pub(crate) async fn process_or_recover(
        &self,
        operation_id: &[u8; 16],
        request: &ExchangeRequest,
    ) -> Result<ProcessDecision> {
        let request_hash = match request.canonical_hash(operation_id) {
            Ok(hash) => hash,
            Err(_) => return Ok(ProcessDecision::Rejected),
        };

        if let Some(record) = self.store.get(operation_id).await? {
            if record.request_hash != request_hash {
                return Ok(ProcessDecision::Conflict);
            }
            return self.recover(operation_id, record).await;
        }

        // Everything below is pure. No Redis mutation happens until all source
        // signatures and every RSA representative have passed validation.
        let fresh = match self.validate_fresh(request) {
            Ok(fresh) => fresh,
            Err(_) => return Ok(ProcessDecision::Rejected),
        };
        let receipt_key_id = self.receipt_keys.active_id().to_owned();
        let reservation = self
            .store
            .reserve(ReservationInput {
                operation_id,
                request_hash: &request_hash,
                profile_id: &request.profile,
                rule_id: &request.rule_id,
                target_keyset_id: &self.profile.target_keyset.id,
                receipt_key_id: &receipt_key_id,
                sources: &fresh.sources,
                outputs: &fresh.outputs,
                target_refs: &fresh.target_refs,
                receipt_ref_key: &receipt_ref_key(&receipt_key_id),
                capacities: &fresh.capacities,
                receipt_lifetime_secs: self.receipt_lifetime_secs,
            })
            .await?;
        match reservation {
            ReserveOutcome::Created(reservation) => {
                let record = self
                    .store
                    .get(operation_id)
                    .await?
                    .context("reserved operation missing")?;
                self.execute_owned(operation_id, record, reservation.fence)
                    .await
            }
            ReserveOutcome::Existing(record) => {
                if record.request_hash != request_hash {
                    Ok(ProcessDecision::Conflict)
                } else {
                    self.recover(operation_id, *record).await
                }
            }
            ReserveOutcome::Conflict => Ok(ProcessDecision::Conflict),
            ReserveOutcome::DuplicateSource
            | ReserveOutcome::Spent
            | ReserveOutcome::SourceWindow
            | ReserveOutcome::TargetWindow
            | ReserveOutcome::InvalidEntries
            | ReserveOutcome::Capacity => Ok(ProcessDecision::Rejected),
        }
    }

    pub(crate) async fn status(&self, operation_id: &[u8; 16]) -> Result<StatusDecision> {
        Ok(match self.store.get(operation_id).await? {
            Some(record) if record.state == State::Committed => {
                StatusDecision::Committed(record.response.context("committed response missing")?)
            }
            Some(_) => StatusDecision::Pending,
            None => StatusDecision::Unknown,
        })
    }

    pub(crate) async fn readiness_check(&self) -> Result<()> {
        self.store.validate_durable_standalone().await?;
        self.validate_pending_signers().await
    }

    fn validate_fresh(&self, request: &ExchangeRequest) -> Result<FreshWork> {
        self.profile
            .validate_request(request)
            .context("exchange profile validation")?;
        let mut sources = Vec::with_capacity(request.sources.len());
        for source in &request.sources {
            let artifact = decode_base64url(&source.artifact, MAX_ARTIFACT)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let validated = source_v5::validate_source_v5(
                &self.profile,
                &source.slot.descriptor_id,
                &artifact,
                &self.issuer_id,
            )?;
            let descriptor = self
                .profile
                .sources
                .descriptors
                .iter()
                .find(|d| d.id == source.slot.descriptor_id)
                .context("source descriptor")?;
            sources.push(store::SourceWork {
                descriptor_id: validated.descriptor_id,
                spend_key: validated.spend_key,
                valid_from: descriptor.valid_from,
                valid_until: descriptor.valid_until,
            });
        }
        let outputs = self
            .signers
            .validate_outputs(&self.profile.target_keyset.id, &request.outputs)?;
        let mut targets = BTreeMap::<String, (i64, i64)>::new();
        let mut capacity = BTreeMap::<String, (u64, u64)>::new();
        for output in &outputs {
            let descriptor = &self
                .profile
                .target_keyset
                .targets
                .iter()
                .find(|target| target.descriptor.id == output.descriptor_id)
                .context("target descriptor")?
                .descriptor;
            targets.insert(
                descriptor.id.clone(),
                (descriptor.valid_from, descriptor.valid_until),
            );
            let entry = capacity
                .entry(descriptor.id.clone())
                .or_insert((0, u64::from(descriptor.max_quantity)));
            entry.0 = entry
                .0
                .checked_add(u64::from(output.quantity))
                .context("capacity overflow")?;
        }
        let target_refs = targets
            .into_iter()
            .map(|(id, (first, last))| target_ref_key(&id, first, last))
            .collect();
        let capacities = capacity
            .into_iter()
            .map(|(id, (amount, limit))| CapacityEntry {
                key: capacity_key(&id),
                amount,
                limit,
            })
            .collect();
        Ok(FreshWork {
            sources,
            outputs,
            target_refs,
            capacities,
        })
    }

    async fn recover(
        &self,
        operation_id: &[u8; 16],
        mut record: OperationRecord,
    ) -> Result<ProcessDecision> {
        // All lease decisions are made by Redis TIME in `claim`; local wall time
        // is intentionally absent from this decision table.
        for _ in 0..8 {
            if record.state == State::Committed {
                return Ok(ProcessDecision::Committed(
                    record.response.context("committed response missing")?,
                ));
            }
            if !self.record_signers_available(&record) {
                return Ok(ProcessDecision::Retryable);
            }
            match self.store.claim(operation_id).await? {
                ClaimOutcome::Claimed(reservation) => {
                    return self
                        .execute_owned(operation_id, record, reservation.fence)
                        .await
                }
                ClaimOutcome::Live => return Ok(ProcessDecision::Retryable),
                ClaimOutcome::Committed => {
                    record = self
                        .store
                        .get(operation_id)
                        .await?
                        .context("committed operation missing")?;
                }
                ClaimOutcome::Missing => return Ok(ProcessDecision::Retryable),
                ClaimOutcome::InvalidState => {
                    record = self
                        .store
                        .get(operation_id)
                        .await?
                        .context("operation missing")?;
                }
            }
        }
        Ok(ProcessDecision::Retryable)
    }

    async fn execute_owned(
        &self,
        operation_id: &[u8; 16],
        mut record: OperationRecord,
        fence: Vec<u8>,
    ) -> Result<ProcessDecision> {
        if record.state == State::Reserved {
            let signatures = self
                .signers
                .sign_work(&record.target_keyset_id, &record.outputs)
                .await?;
            let mut result = ExchangeResult {
                operation_id: Base64UrlUnpadded::encode_string(operation_id),
                profile: record.profile_id.clone(),
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
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            result.result_digest = Base64UrlUnpadded::encode_string(&digest);
            result
                .canonical_bytes()
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let result_bytes = serde_json::to_vec(&result)?;
            match self
                .store
                .result_ready(operation_id, &fence, &result_bytes, &digest)
                .await?
            {
                TransitionOutcome::Applied | TransitionOutcome::Repeated => {
                    record = self
                        .store
                        .get(operation_id)
                        .await?
                        .context("result operation missing")?;
                }
                TransitionOutcome::StaleFence
                | TransitionOutcome::InvalidState
                | TransitionOutcome::Conflict
                | TransitionOutcome::Underflow => {
                    let latest = self
                        .store
                        .get(operation_id)
                        .await?
                        .context("operation missing after result race")?;
                    return if latest.state == State::Committed {
                        Ok(ProcessDecision::Committed(
                            latest.response.context("response missing")?,
                        ))
                    } else {
                        Ok(ProcessDecision::Retryable)
                    };
                }
            }
        }
        if record.state != State::ResultReady {
            return Ok(ProcessDecision::Retryable);
        }
        let result_bytes = record.result.as_deref().context("result bytes missing")?;
        let result: ExchangeResult =
            serde_json::from_slice(result_bytes).context("invalid persisted result")?;
        result
            .canonical_bytes()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let digest = record.result_digest.context("result digest missing")?;
        if result.result_digest != Base64UrlUnpadded::encode_string(&digest) {
            bail!("persisted result digest mismatch")
        }
        let mut receipt = ExchangeReceipt {
            operation_id: Base64UrlUnpadded::encode_string(operation_id),
            profile: record.profile_id.clone(),
            target_keyset_id: record.target_keyset_id.clone(),
            result_digest: Base64UrlUnpadded::encode_string(&digest),
            created_at: record.created_at,
            expires_at: record.receipt_expires_at,
            receipt_key_id: record.receipt_key_id.clone(),
            signature: String::new(),
        };
        let receipt_key = self
            .receipt_keys
            .resolve(&receipt.receipt_key_id)
            .context("pinned receipt signer unavailable")?;
        let signature = receipt_key.sign_receipt(&receipt)?;
        receipt.signature = Base64UrlUnpadded::encode_string(&signature);
        receipt
            .validate_signature()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let receipt_bytes = serde_json::to_vec(&receipt)?;
        let response = serde_json::to_vec(&ExchangeResponse {
            result: &result,
            receipt: &receipt,
        })?;
        match self
            .store
            .commit(operation_id, &fence, &receipt_bytes, &response)
            .await?
        {
            TransitionOutcome::Applied | TransitionOutcome::Repeated => {
                Ok(ProcessDecision::Committed(response))
            }
            TransitionOutcome::StaleFence
            | TransitionOutcome::InvalidState
            | TransitionOutcome::Conflict
            | TransitionOutcome::Underflow => {
                let latest = self
                    .store
                    .get(operation_id)
                    .await?
                    .context("operation missing after commit race")?;
                if latest.state == State::Committed {
                    Ok(ProcessDecision::Committed(
                        latest.response.context("response missing")?,
                    ))
                } else {
                    Ok(ProcessDecision::Retryable)
                }
            }
        }
    }

    fn record_signers_available(&self, record: &OperationRecord) -> bool {
        match record.state {
            State::Reserved => {
                self.signers
                    .supports_work(&record.target_keyset_id, &record.outputs)
                    && self.receipt_keys.contains(&record.receipt_key_id)
            }
            State::ResultReady => self.receipt_keys.contains(&record.receipt_key_id),
            State::Committed => true,
        }
    }

    async fn validate_pending_signers(&self) -> Result<()> {
        for record in self.store.pending_records().await? {
            if !self.record_signers_available(&record) {
                bail!("pending exchange operation requires unavailable target or receipt signer")
            }
        }
        Ok(())
    }
}

struct FreshWork {
    sources: Vec<store::SourceWork>,
    outputs: Vec<OutputWork>,
    target_refs: Vec<store::TargetRef>,
    capacities: Vec<CapacityEntry>,
}
