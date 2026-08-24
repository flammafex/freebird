// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Phase 3 native V7 exchange engine.
//!
//! This module is intentionally independent of the retained exchange engine.
//! It admits only the closed common V7 contract, uses V7 signer identities, and
//! persists work under V7-only Redis schemas and replay namespaces.

use super::{receipt::ReceiptKeyRing, v7_store::*};
use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{
    native_exchange_v3_ordered_root, native_exchange_v3_output_leaf,
    native_exchange_v3_source_leaf, NativeExchangeV3Descriptor, NativeExchangeV3Discovery,
    NativeExchangeV3Receipt, NativeExchangeV3Request, NativeExchangeV3Result,
    NativeExchangeV3ResultOutput, NATIVE_EXCHANGE_V3_PROFILE_ID,
    NATIVE_EXCHANGE_V3_RECEIPT_LIFETIME_SECS, NATIVE_EXCHANGE_V3_VERSION,
};
use freebird_common::v7_wire::{decode_base64url, parse_operation_id, MAX_ARTIFACT};
use freebird_crypto::{
    V7BlindMessage, V7BodyPolicy, V7KeyIdentity, V7PublicKeyBinding, V7TokenKeyId,
};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use crate::v7_signers::{V7Signer, V7SignerIdentity, V7SignerInventory};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V7ProcessDecision {
    Committed(Vec<u8>),
    Conflict,
    Retryable,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V7StatusDecision {
    Committed(Vec<u8>),
    Pending,
    Unknown,
    Unauthorized,
}

#[derive(Serialize)]
struct V7ExchangeResponse<'a> {
    result: &'a NativeExchangeV3Result,
    receipt: &'a NativeExchangeV3Receipt,
}

pub struct V7ExchangeEngine {
    store: V7ExchangeStore,
    descriptors: BTreeMap<String, NativeExchangeV3Descriptor>,
    transitions: BTreeMap<String, freebird_common::api::NativeExchangeV3Transition>,
    inventory: Arc<V7SignerInventory>,
    receipt_keys: Arc<ReceiptKeyRing>,
    issuer_or_federation_id: String,
    graph_id: String,
}

impl V7ExchangeEngine {
    pub async fn new(
        discovery: NativeExchangeV3Discovery,
        store: V7ExchangeStore,
        inventory: Arc<V7SignerInventory>,
        receipt_keys: ReceiptKeyRing,
        issuer_or_federation_id: String,
        graph_id: String,
    ) -> Result<Self> {
        discovery
            .validate()
            .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
        if issuer_or_federation_id.is_empty() {
            bail!("V7 exchange issuer/federation identity must not be empty")
        }
        if graph_id != discovery.profile.graph_id {
            bail!("V7 exchange graph identity does not match discovery profile")
        }
        let mut descriptors = BTreeMap::new();
        for descriptor in discovery
            .active_descriptors
            .into_iter()
            .chain(discovery.retained_descriptors)
        {
            if descriptors
                .insert(descriptor.descriptor_id.clone(), descriptor)
                .is_some()
            {
                bail!("duplicate V7 exchange descriptor")
            }
        }
        let mut transitions = BTreeMap::new();
        for transition in discovery.transitions {
            if transitions
                .insert(transition.transition_id.clone(), transition)
                .is_some()
            {
                bail!("duplicate V7 exchange transition")
            }
        }
        if descriptors.is_empty() || transitions.is_empty() {
            bail!("V7 exchange discovery must contain descriptors and transitions")
        }
        Ok(Self {
            store,
            descriptors,
            transitions,
            inventory,
            receipt_keys: Arc::new(receipt_keys),
            issuer_or_federation_id,
            graph_id,
        })
    }

    pub fn store(&self) -> &V7ExchangeStore {
        &self.store
    }

    /// Verify the backing store without changing exchange state.
    pub async fn readiness_check(&self) -> Result<()> {
        self.store.readiness_check().await
    }

    pub async fn process_or_recover(
        &self,
        request: &NativeExchangeV3Request,
        status_capability: &[u8; 32],
    ) -> Result<V7ProcessDecision> {
        let operation_id = match parse_operation_id(&request.public_operation_id) {
            Ok(operation_id) => operation_id,
            Err(_) => return Ok(V7ProcessDecision::Rejected),
        };
        let request_digest = match request.request_digest() {
            Ok(digest) => digest,
            Err(_) => return Ok(V7ProcessDecision::Rejected),
        };
        if let Some(record) = self.store.get(&operation_id).await? {
            if record.request_digest != request_digest
                || record.status_capability_digest
                    != V7ExchangeStore::status_capability_digest(status_capability)
            {
                return Ok(V7ProcessDecision::Conflict);
            }
            return self.recover(&operation_id, record).await;
        }

        let spent_keys = match self.validate_fresh(request).await {
            Ok(spent_keys) => spent_keys,
            Err(_) => return Ok(V7ProcessDecision::Rejected),
        };
        let created_at = unix_now()? as u64;
        self.receipt_keys.active_signer(
            created_at,
            created_at
                .checked_add(NATIVE_EXCHANGE_V3_RECEIPT_LIFETIME_SECS)
                .context("V7 receipt lifetime overflow")?,
        )?;
        let request_bytes = serde_json::to_vec(request)?;
        match self
            .store
            .reserve(
                &operation_id,
                &request_bytes,
                &request_digest,
                status_capability,
                &spent_keys,
                self.receipt_keys.active_id(),
            )
            .await?
        {
            V7ReserveOutcome::Created(reservation) => {
                let record = self
                    .store
                    .get(&operation_id)
                    .await?
                    .context("reserved V7 operation missing")?;
                self.execute_owned(&operation_id, record, reservation.fence)
                    .await
            }
            V7ReserveOutcome::Existing(record) => self.recover(&operation_id, *record).await,
            V7ReserveOutcome::Conflict
            | V7ReserveOutcome::CapabilityMismatch
            | V7ReserveOutcome::DuplicateSource
            | V7ReserveOutcome::Spent
            | V7ReserveOutcome::InvalidSchema => Ok(V7ProcessDecision::Rejected),
        }
    }

    pub async fn status(
        &self,
        operation_id: &[u8; 16],
        status_capability: &[u8; 32],
    ) -> Result<V7StatusDecision> {
        Ok(match self.store.get(operation_id).await? {
            Some(record)
                if record.status_capability_digest
                    != V7ExchangeStore::status_capability_digest(status_capability) =>
            {
                V7StatusDecision::Unauthorized
            }
            Some(record) if record.state == V7State::Committed => {
                V7StatusDecision::Committed(record.response.context("V7 response missing")?)
            }
            Some(_) => V7StatusDecision::Pending,
            None => V7StatusDecision::Unknown,
        })
    }

    async fn validate_fresh(&self, request: &NativeExchangeV3Request) -> Result<Vec<String>> {
        request
            .validate()
            .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
        if request.issuer_or_federation_id != self.issuer_or_federation_id {
            bail!("V7 exchange issuer/federation identity mismatch")
        }
        if request.graph_id != self.graph_id {
            bail!("V7 exchange graph identity mismatch")
        }
        let transition = self
            .transitions
            .get(&request.transition_id)
            .context("unknown V7 exchange transition")?;
        if transition.profile_id != NATIVE_EXCHANGE_V3_PROFILE_ID
            || transition.source_keyset_id != request.source_keyset_id
            || transition.target_keyset_id != request.target_keyset_id
            || request.sources.len() != transition.source_slots.len()
            || request.outputs.len() != transition.output_slots.len()
        {
            bail!("V7 exchange transition binding mismatch")
        }

        let mut spent_keys = Vec::with_capacity(request.sources.len());
        let mut source_leaves = Vec::with_capacity(request.sources.len());
        for (source, expected) in request.sources.iter().zip(&transition.source_slots) {
            if source.descriptor_id != expected.descriptor_id
                || source.keyset_id != expected.keyset_id
                || source.slot_id != expected.slot_id
            {
                bail!("V7 source slot does not match transition")
            }
            let descriptor = self.descriptor(&source.descriptor_id)?;
            let artifact = decode_base64url(&source.artifact, MAX_ARTIFACT)
                .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
            let token = freebird_crypto::parse_native_bearer_v7_token(&artifact)
                .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
            let binding = descriptor_binding(descriptor)?;
            let policy = descriptor_policy(descriptor)?;
            if token.body().issuer_id() != descriptor.issuer_id
                || token.body().token_key_id().as_bytes()
                    != hex::decode(&descriptor.token_key_id)?.as_slice()
                || !valid_now(descriptor.valid_from, descriptor.valid_until)?
            {
                bail!("V7 source identity or validity mismatch")
            }
            token
                .verify(&binding, &policy)
                .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
            let source_digest: [u8; 32] =
                hex::decode(&source.source_artifact_digest)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid V7 source artifact digest"))?;
            let descriptor_id: [u8; 32] = hex::decode(&source.descriptor_id)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid V7 source descriptor ID"))?;
            let keyset_id: [u8; 32] = hex::decode(&source.keyset_id)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid V7 source keyset ID"))?;
            source_leaves.push(native_exchange_v3_source_leaf(
                source_leaves.len() as u32,
                &artifact,
                &source_digest,
                &descriptor_id,
                &keyset_id,
                &source.slot_id,
            )?);
            spent_keys.push(V7ExchangeStore::spent_key(
                &request.issuer_or_federation_id,
                token.body().nullifier(),
            ));
        }
        let mut request_output_leaves = Vec::with_capacity(request.outputs.len());
        for (index, (output, expected)) in request
            .outputs
            .iter()
            .zip(&transition.output_slots)
            .enumerate()
        {
            if output.descriptor_id != expected.descriptor_id
                || output.keyset_id != expected.keyset_id
                || output.slot_id != expected.slot_id
            {
                bail!("V7 output slot does not match transition")
            }
            let (_, signer) = self.output_signer(output)?;
            let blind = decode_base64url(&output.blinded_message, 384)
                .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
            let message = V7BlindMessage::from_bytes(&blind)
                .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
            // The inventory's signing boundary performs the complete V7
            // representative validation: raw384, nonzero, and m < modulus.
            let _ = signer
                .sign(&message)
                .await
                .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
            let output_id: [u8; 16] = decode_base64url(&output.output_id, 16)
                .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid V7 output ID"))?;
            let commitment: [u8; 32] =
                hex::decode(&output.request_output_commitment)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid V7 request output commitment"))?;
            request_output_leaves.push(native_exchange_v3_output_leaf(
                false,
                index as u32,
                &output_id,
                &commitment,
            ));
        }
        let source_root = hex::encode(native_exchange_v3_ordered_root(&source_leaves)?);
        let request_output_root =
            hex::encode(native_exchange_v3_ordered_root(&request_output_leaves)?);
        if request.source_root != source_root || request.request_output_root != request_output_root
        {
            bail!("V7 exchange Merkle root mismatch")
        }
        Ok(spent_keys)
    }

    fn descriptor(&self, descriptor_id: &str) -> Result<&NativeExchangeV3Descriptor> {
        self.descriptors
            .get(descriptor_id)
            .context("unknown V7 exchange descriptor")
    }

    fn output_signer(
        &self,
        output: &freebird_common::api::NativeExchangeV3Output,
    ) -> Result<(&NativeExchangeV3Descriptor, &V7Signer)> {
        let descriptor = self.descriptor(&output.descriptor_id)?;
        let signer = self.lookup_signer(descriptor)?;
        let current = unix_now()?;
        if !valid_now(descriptor.valid_from, descriptor.valid_until)?
            || !signer.is_valid_at(current)
        {
            bail!("V7 output signer is outside its immutable validity window")
        }
        if output.asset_id != descriptor.asset_id
            || output.amount_minor != descriptor.amount_minor
            || signer.policy().asset_id() != descriptor.asset_id
            || signer.policy().amount_minor().to_string() != descriptor.amount_minor
        {
            bail!("V7 output policy mismatch")
        }
        let message = decode_base64url(&output.blinded_message, 384)
            .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
        V7BlindMessage::from_bytes(&message)
            .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
        Ok((descriptor, signer))
    }

    fn lookup_signer(&self, descriptor: &NativeExchangeV3Descriptor) -> Result<&V7Signer> {
        let token_key_id: [u8; 32] = hex::decode(&descriptor.token_key_id)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid V7 token key ID"))?;
        let identity = V7SignerIdentity::new(
            descriptor.issuer_id.clone(),
            descriptor.profile_id.clone(),
            descriptor.descriptor_id.clone(),
            V7TokenKeyId::new(token_key_id),
        )?;
        let signer = self.inventory.lookup(&identity)?;
        if signer.metadata().spki_fingerprint != descriptor.spki_fingerprint
            || signer.metadata().pubkey_spki_b64 != descriptor.pubkey_spki_b64
            || signer.metadata().profile_id != descriptor.profile_id
            || signer.metadata().descriptor_id != descriptor.descriptor_id
        {
            bail!("V7 output descriptor does not match immutable signer inventory")
        }
        Ok(signer)
    }

    async fn recover(
        &self,
        operation_id: &[u8; 16],
        mut record: V7OperationRecord,
    ) -> Result<V7ProcessDecision> {
        for _ in 0..8 {
            if record.state == V7State::Committed {
                return Ok(V7ProcessDecision::Committed(
                    record.response.context("V7 response missing")?,
                ));
            }
            match self.store.claim(operation_id).await? {
                V7ClaimOutcome::Claimed(reservation) => {
                    return self
                        .execute_owned(operation_id, record, reservation.fence)
                        .await
                }
                V7ClaimOutcome::Live => return Ok(V7ProcessDecision::Retryable),
                V7ClaimOutcome::Committed | V7ClaimOutcome::InvalidState => {
                    record = self
                        .store
                        .get(operation_id)
                        .await?
                        .context("V7 operation disappeared during recovery")?;
                }
                V7ClaimOutcome::Missing => return Ok(V7ProcessDecision::Retryable),
            }
        }
        Ok(V7ProcessDecision::Retryable)
    }

    async fn execute_owned(
        &self,
        operation_id: &[u8; 16],
        mut record: V7OperationRecord,
        fence: Vec<u8>,
    ) -> Result<V7ProcessDecision> {
        if record.state == V7State::Reserved {
            let request: NativeExchangeV3Request = serde_json::from_slice(&record.request)
                .context("invalid persisted V7 exchange request")?;
            request
                .validate()
                .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
            if request.graph_id != self.graph_id {
                bail!("persisted V7 exchange graph identity mismatch")
            }
            let mut outputs = Vec::with_capacity(request.outputs.len());
            for output in &request.outputs {
                let (_, signer) = self.output_signer(output)?;
                let blind = decode_base64url(&output.blinded_message, 384)
                    .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
                let message = V7BlindMessage::from_bytes(&blind)
                    .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
                let signature = self.inventory.sign(signer.identity(), &message).await?;
                outputs.push((
                    output,
                    Base64UrlUnpadded::encode_string(signature.as_bytes()),
                ));
            }
            let mut result = build_result(&request, outputs)?;
            let digest = result
                .result_digest()
                .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
            result.result_digest = hex::encode(digest);
            result
                .validate()
                .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
            let result_bytes = serde_json::to_vec(&result)?;
            match self
                .store
                .result_ready(operation_id, &fence, &result_bytes, &digest)
                .await?
            {
                V7TransitionOutcome::Applied | V7TransitionOutcome::Repeated => {
                    record = self
                        .store
                        .get(operation_id)
                        .await?
                        .context("V7 result operation missing")?;
                }
                V7TransitionOutcome::Conflict
                | V7TransitionOutcome::InvalidState
                | V7TransitionOutcome::StaleFence => return self.latest(operation_id).await,
            }
        }
        if record.state != V7State::ResultReady {
            return Ok(V7ProcessDecision::Retryable);
        }
        let request: NativeExchangeV3Request = serde_json::from_slice(&record.request)?;
        let result: NativeExchangeV3Result = serde_json::from_slice(
            record
                .result
                .as_deref()
                .context("persisted V7 result missing")?,
        )?;
        result
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let digest = record.result_digest.context("V7 result digest missing")?;
        if result
            .result_digest()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
            != digest
        {
            bail!("persisted V7 result digest mismatch")
        }
        let created_at = record.created_at;
        let expires_at = created_at
            .checked_add(NATIVE_EXCHANGE_V3_RECEIPT_LIFETIME_SECS)
            .context("V7 receipt lifetime overflow")?;
        let receipt_key =
            self.receipt_keys
                .recovery_signer(&record.receipt_key_id, created_at, expires_at)?;
        let mut receipt = NativeExchangeV3Receipt {
            version: NATIVE_EXCHANGE_V3_VERSION,
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            issuer_or_federation_id: request.issuer_or_federation_id.clone(),
            public_operation_id: request.public_operation_id.clone(),
            graph_id: request.graph_id.clone(),
            transition_id: request.transition_id.clone(),
            source_keyset_id: request.source_keyset_id.clone(),
            target_keyset_id: request.target_keyset_id.clone(),
            asset_id: request.asset_id.clone(),
            source_count: request.source_count,
            output_count: request.output_count,
            source_total_minor: request.source_total_minor.clone(),
            output_total_minor: request.output_total_minor.clone(),
            source_root: request.source_root.clone(),
            request_output_root: request.request_output_root.clone(),
            result_output_root: result.result_output_root.clone(),
            request_digest: hex::encode(
                request
                    .request_digest()
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?,
            ),
            result_digest: hex::encode(digest),
            created_at,
            expires_at,
            output_recovery_until: expires_at,
            receipt_key_id: receipt_key.key_id(),
            signature: Base64UrlUnpadded::encode_string(&[0; 64]),
        };
        receipt.signature =
            Base64UrlUnpadded::encode_string(&receipt_key.sign_receipt_v7(&receipt)?);
        receipt
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let receipt_bytes = serde_json::to_vec(&receipt)?;
        let response = serde_json::to_vec(&V7ExchangeResponse {
            result: &result,
            receipt: &receipt,
        })?;
        match self
            .store
            .commit(operation_id, &fence, &receipt_bytes, &response)
            .await?
        {
            V7TransitionOutcome::Applied | V7TransitionOutcome::Repeated => {
                Ok(V7ProcessDecision::Committed(response))
            }
            V7TransitionOutcome::Conflict
            | V7TransitionOutcome::InvalidState
            | V7TransitionOutcome::StaleFence => self.latest(operation_id).await,
        }
    }

    async fn latest(&self, operation_id: &[u8; 16]) -> Result<V7ProcessDecision> {
        let record = self
            .store
            .get(operation_id)
            .await?
            .context("V7 operation missing after transition race")?;
        if record.state == V7State::Committed {
            Ok(V7ProcessDecision::Committed(
                record.response.context("V7 response missing")?,
            ))
        } else {
            Ok(V7ProcessDecision::Retryable)
        }
    }
}

fn descriptor_binding(descriptor: &NativeExchangeV3Descriptor) -> Result<V7PublicKeyBinding> {
    let token_key_id: [u8; 32] = hex::decode(&descriptor.token_key_id)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid V7 descriptor token key ID"))?;
    let spki = decode_base64url(&descriptor.pubkey_spki_b64, 4096)
        .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?;
    V7PublicKeyBinding::new(
        V7KeyIdentity::new(
            descriptor.issuer_id.clone(),
            V7TokenKeyId::new(token_key_id),
        )
        .map_err(|error| anyhow::anyhow!(format!("{error:?}")))?,
        &spki,
    )
    .map_err(|error| anyhow::anyhow!(format!("{error:?}")))
}

fn descriptor_policy(descriptor: &NativeExchangeV3Descriptor) -> Result<V7BodyPolicy> {
    V7BodyPolicy::new(
        descriptor.asset_id.clone(),
        descriptor.amount_minor.parse()?,
    )
    .map_err(|error| anyhow::anyhow!(format!("{error:?}")))
}

fn valid_now(valid_from: u64, valid_until: u64) -> Result<bool> {
    let now = unix_now()? as u64;
    Ok(valid_from <= now && now <= valid_until)
}

fn unix_now() -> Result<i64> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    i64::try_from(now).context("system clock exceeds V7 timestamp range")
}

fn build_result<'a>(
    request: &'a NativeExchangeV3Request,
    signatures: Vec<(&'a freebird_common::api::NativeExchangeV3Output, String)>,
) -> Result<NativeExchangeV3Result> {
    let mut result_outputs = Vec::with_capacity(signatures.len());
    let mut leaves = Vec::with_capacity(signatures.len());
    for (index, (output, signature)) in signatures.into_iter().enumerate() {
        let output_id = decode_base64url(&output.output_id, 16)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let commitment = hex::decode(&output.request_output_commitment)?;
        let commitment: [u8; 32] = commitment
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid V7 output commitment"))?;
        leaves.push(native_exchange_v3_output_leaf(
            true,
            index as u32,
            &output_id
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid V7 output ID"))?,
            &commitment,
        ));
        result_outputs.push(NativeExchangeV3ResultOutput {
            output_id: output.output_id.clone(),
            descriptor_id: output.descriptor_id.clone(),
            keyset_id: output.keyset_id.clone(),
            slot_id: output.slot_id.clone(),
            asset_id: output.asset_id.clone(),
            amount_minor: output.amount_minor.clone(),
            blinded_message: output.blinded_message.clone(),
            handoff_commitment: output.handoff_commitment.clone(),
            request_output_commitment: output.request_output_commitment.clone(),
            request_output_proof: output.request_output_proof.clone(),
            result_output_commitment: output.request_output_commitment.clone(),
            result_output_proof: output.request_output_proof.clone(),
            blind_signature: signature,
        });
    }
    let result_output_root = hex::encode(native_exchange_v3_ordered_root(&leaves)?);
    Ok(NativeExchangeV3Result {
        version: request.version,
        profile_id: request.profile_id.clone(),
        issuer_or_federation_id: request.issuer_or_federation_id.clone(),
        public_operation_id: request.public_operation_id.clone(),
        graph_id: request.graph_id.clone(),
        transition_id: request.transition_id.clone(),
        source_keyset_id: request.source_keyset_id.clone(),
        target_keyset_id: request.target_keyset_id.clone(),
        asset_id: request.asset_id.clone(),
        source_count: request.source_count,
        output_count: request.output_count,
        source_total_minor: request.source_total_minor.clone(),
        output_total_minor: request.output_total_minor.clone(),
        source_root: request.source_root.clone(),
        request_output_root: request.request_output_root.clone(),
        result_output_root,
        request_digest: hex::encode(
            request
                .request_digest()
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
        ),
        outputs: result_outputs,
        result_digest: String::new(),
    })
}
