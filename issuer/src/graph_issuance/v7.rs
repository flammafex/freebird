// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Native V7 graph blind issuance.
//!
//! This lane is intentionally separate from the historical graph issuance
//! implementation.  It has its own wire profile, Redis namespace, result
//! schema, and signer selection path.

use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use blind_rsa_signatures::PublicKeySha384PSSRandomized;
use ed25519_dalek::{Signature, VerifyingKey};
use freebird_common::api::{
    NativeGraphIssuanceV7Discovery, NativeGraphIssuanceV7Policy, NativeGraphIssuanceV7Request,
    NativeGraphIssuanceV7Result, NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID,
    NATIVE_GRAPH_ISSUANCE_V7_QUANTITY, NATIVE_GRAPH_ISSUANCE_V7_VERSION,
};
use freebird_crypto::{V7BlindMessage, V7TokenKeyId};
use std::{collections::HashMap, sync::Arc};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use super::authorizer::{
    GraphIssuanceAuthorizer, V4LocalAuthorization, V4LocalGraphIssuanceAuthorizer,
};
use super::policy::GraphIssuancePolicy;
use crate::v7_signers::{V7Signer, V7SignerIdentity, V7SignerInventory};

#[path = "v7_store.rs"]
mod v7_store;
use self::v7_store::{
    StoredV7Operation, V7ClaimOutcome, V7GraphIssuanceStore, V7ReserveOutcome, V7State,
    V7TransitionOutcome,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V7ProcessDecision {
    Committed(Vec<u8>),
    Pending,
    Conflict,
    Rejected,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V7StatusDecision {
    Committed(Vec<u8>),
    Pending,
    Unknown,
}

/// Issuer-side engine for the closed native V7 graph-issuance contract.
pub struct V7GraphIssuanceEngine {
    enabled: bool,
    issuer_id: String,
    policies: HashMap<String, NativeGraphIssuanceV7Policy>,
    inventory: Arc<V7SignerInventory>,
    store: V7GraphIssuanceStore,
    authorization_policy: Option<GraphIssuancePolicy>,
    authorizer: Option<Arc<V4LocalGraphIssuanceAuthorizer>>,
}

impl V7GraphIssuanceEngine {
    /// Construct an enabled V7 engine after validating every immutable policy
    /// against the already-loaded V7 signer inventory.
    pub fn new(
        issuer_id: impl Into<String>,
        policies: Vec<NativeGraphIssuanceV7Policy>,
        inventory: Arc<V7SignerInventory>,
        redis_url: &str,
    ) -> Result<Self> {
        Self::new_internal(issuer_id, policies, inventory, redis_url, None, None, true)
    }

    /// Constructor variant used by startup and focused tests which need the
    /// recovery surface while fresh issuance is disabled.
    pub fn new_with_enabled(
        issuer_id: impl Into<String>,
        policies: Vec<NativeGraphIssuanceV7Policy>,
        inventory: Arc<V7SignerInventory>,
        redis_url: &str,
        enabled: bool,
    ) -> Result<Self> {
        Self::new_internal(
            issuer_id, policies, inventory, redis_url, None, None, enabled,
        )
    }

    /// Construct the V7 lane with the existing V4-local verifier and its
    /// unchanged policy/trust configuration. V7 never parses or authenticates
    /// the credential itself; it delegates that operation to the established
    /// authorizer before touching the V7 signer or durable issuance state.
    pub fn new_with_v4_local_authorization(
        issuer_id: impl Into<String>,
        policies: Vec<NativeGraphIssuanceV7Policy>,
        inventory: Arc<V7SignerInventory>,
        redis_url: &str,
        authorization_policy: GraphIssuancePolicy,
        authorizer: Arc<V4LocalGraphIssuanceAuthorizer>,
    ) -> Result<Self> {
        Self::new_internal(
            issuer_id,
            policies,
            inventory,
            redis_url,
            Some(authorization_policy),
            Some(authorizer),
            true,
        )
    }

    /// Alias with the generic authorization wording used by route wiring.
    pub fn new_with_authorization(
        issuer_id: impl Into<String>,
        policies: Vec<NativeGraphIssuanceV7Policy>,
        inventory: Arc<V7SignerInventory>,
        redis_url: &str,
        authorization_policy: GraphIssuancePolicy,
        authorizer: Arc<V4LocalGraphIssuanceAuthorizer>,
    ) -> Result<Self> {
        Self::new_with_v4_local_authorization(
            issuer_id,
            policies,
            inventory,
            redis_url,
            authorization_policy,
            authorizer,
        )
    }

    fn new_internal(
        issuer_id: impl Into<String>,
        policies: Vec<NativeGraphIssuanceV7Policy>,
        inventory: Arc<V7SignerInventory>,
        redis_url: &str,
        authorization_policy: Option<GraphIssuancePolicy>,
        authorizer: Option<Arc<V4LocalGraphIssuanceAuthorizer>>,
        enabled: bool,
    ) -> Result<Self> {
        let issuer_id = issuer_id.into();
        if issuer_id.is_empty() {
            bail!("V7 graph issuer identity must not be empty")
        }
        if let (Some(policy), Some(authorizer)) = (&authorization_policy, &authorizer) {
            if policy.authorization_scheme != "v4_local" || policy.v4_local.is_none() {
                bail!("V7 graph authorization policy must be v4_local")
            }
            authorizer.validate_policy_configuration(policy)?;
        } else if authorization_policy.is_some() || authorizer.is_some() {
            bail!("V7 graph authorization configuration is incomplete")
        }
        let mut indexed = HashMap::with_capacity(policies.len());
        for policy in policies {
            policy.validate().map_err(anyhow::Error::msg)?;
            if policy.issuer_id != issuer_id {
                bail!("V7 graph policy issuer identity mismatch")
            }
            let identity = identity_for_policy(&policy)?;
            let signer = inventory.lookup(&identity)?;
            validate_policy_binding(&policy, signer)?;
            if indexed.insert(policy.policy_id.clone(), policy).is_some() {
                bail!("duplicate V7 graph policy identity")
            }
        }
        Ok(Self {
            enabled,
            issuer_id,
            policies: indexed,
            inventory,
            store: V7GraphIssuanceStore::new(redis_url)?,
            authorization_policy,
            authorizer,
        })
    }

    pub fn issuance_enabled(&self) -> bool {
        self.enabled
    }

    /// Verify the backing store without changing graph issuance state.
    pub async fn readiness_check(&self) -> Result<()> {
        self.store.readiness_check().await
    }

    /// Project the configured policies into the V7 graph discovery contract.
    pub fn discovery(&self, now: i64) -> NativeGraphIssuanceV7Discovery {
        let mut active_policies = Vec::new();
        let mut retained_policies = Vec::new();
        for policy in self.policies.values().cloned() {
            if policy.valid_from <= now && now <= policy.valid_until {
                active_policies.push(policy);
            } else {
                retained_policies.push(policy);
            }
        }
        active_policies.sort_by(|left, right| left.policy_id.cmp(&right.policy_id));
        retained_policies.sort_by(|left, right| left.policy_id.cmp(&right.policy_id));
        NativeGraphIssuanceV7Discovery {
            version: NATIVE_GRAPH_ISSUANCE_V7_VERSION,
            profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
            active_policies,
            retained_policies,
        }
    }

    fn validate_stored_response(
        record: &StoredV7Operation,
        request: &NativeGraphIssuanceV7Request,
        policy: &NativeGraphIssuanceV7Policy,
        signer: &V7Signer,
        replay_identity: &str,
    ) -> Result<Vec<u8>> {
        let response = record
            .response
            .as_ref()
            .context("committed V7 graph result is missing")?;
        let result: NativeGraphIssuanceV7Result =
            serde_json::from_slice(response).context("corrupt stored V7 graph result")?;
        validate_result_against(&result, request, policy, signer, replay_identity)?;
        Ok(response.clone())
    }

    fn authorize(&self, request: &NativeGraphIssuanceV7Request) -> Result<V4LocalAuthorization> {
        let policy = self
            .authorization_policy
            .as_ref()
            .context("V7 graph authorization is not configured")?;
        let authorizer = self
            .authorizer
            .as_ref()
            .context("V7 graph authorization verifier is not configured")?;
        let binding = request
            .authorization_binding_digest()
            .map_err(anyhow::Error::msg)?;
        let verified = authorizer.verify_credential(policy, &binding, &request.authorization)?;
        let proof_bytes = request
            .authorization_proof_bytes()
            .map_err(anyhow::Error::msg)?;
        let proof_digest = request
            .authorization_proof_digest()
            .map_err(anyhow::Error::msg)?;
        let verifying_key = VerifyingKey::from_bytes(&verified.nonce)
            .map_err(|_| anyhow::anyhow!("V7 authorization nonce is not an Ed25519 key"))?;
        verifying_key
            .verify_strict(&proof_digest, &Signature::from_bytes(&proof_bytes))
            .map_err(|_| anyhow::anyhow!("invalid V7 authorization proof"))?;
        let expected_global_spend_key =
            freebird_common::spend_key::v4_spend_key(&verified.nullifier);
        let Some(global_spend_key) = verified.claim.global_spend_key.as_deref() else {
            bail!("V7 graph authorization did not produce a global replay key")
        };
        if global_spend_key
            .as_bytes()
            .ct_eq(expected_global_spend_key.as_bytes())
            .unwrap_u8()
            != 1
        {
            bail!("V7 graph authorization produced a noncanonical global replay key")
        }
        Ok(verified)
    }

    /// Process one V7 request. The durable reservation is never released:
    /// exact retries either recover a committed response or claim an expired
    /// lease and continue the same operation.
    pub async fn process(
        &self,
        request: &NativeGraphIssuanceV7Request,
    ) -> Result<V7ProcessDecision> {
        if request.validate().is_err() {
            return Ok(V7ProcessDecision::Rejected);
        }
        let operation_id = decode_operation_id(&request.public_operation_id)?;
        let request_digest = request.request_digest().map_err(anyhow::Error::msg)?;
        let canonical_request = request.canonical_bytes().map_err(anyhow::Error::msg)?;
        let request_bytes = serde_json::to_vec(request)?;
        let Some(policy) = self.policies.get(&request.policy_id) else {
            return Ok(V7ProcessDecision::Rejected);
        };
        let identity = identity_for_policy(policy)?;
        let signer = match self.inventory.lookup(&identity) {
            Ok(signer) => signer,
            Err(_) => return Ok(V7ProcessDecision::Rejected),
        };
        if validate_policy_binding(policy, signer).is_err()
            || !request_matches_policy(request, policy)
            || policy.issuer_id != self.issuer_id
        {
            return Ok(V7ProcessDecision::Rejected);
        }

        // Authenticate before looking at or mutating issuance state. This is
        // the unchanged V4-local verifier path and is intentionally before
        // any V7 signing operation.
        let verified = match self.authorize(request) {
            Ok(verified) => verified,
            Err(_) => return Ok(V7ProcessDecision::Rejected),
        };
        let claim = &verified.claim;
        let global_spend_key = claim
            .global_spend_key
            .as_deref()
            .context("missing authenticated V4 global spend key")?;
        let replay_identity =
            V7GraphIssuanceStore::replay_identity(global_spend_key, &claim.nullifier_digest);

        if let Some(existing) = self.store.get(&operation_id).await? {
            if !same_request(
                &existing,
                &request_bytes,
                &canonical_request,
                &request_digest,
                &replay_identity,
                global_spend_key,
            ) {
                return Ok(V7ProcessDecision::Conflict);
            }
            return self
                .recover(&operation_id, existing, policy, signer, &replay_identity)
                .await;
        }
        if !self.enabled {
            return Ok(V7ProcessDecision::Unavailable);
        }

        let now = OffsetDateTime::now_utc().unix_timestamp();
        if now < policy.valid_from || now > policy.valid_until || !signer.is_valid_at(now) {
            return Ok(V7ProcessDecision::Rejected);
        }
        if validate_blinded_message(policy, &request.blinded_message).is_err() {
            return Ok(V7ProcessDecision::Rejected);
        }
        match self
            .store
            .reserve_authorization(
                &operation_id,
                &request_bytes,
                &canonical_request,
                &request_digest,
                global_spend_key,
                &replay_identity,
            )
            .await?
        {
            V7ReserveOutcome::Created(reservation) => {
                self.execute_owned(
                    &operation_id,
                    request,
                    policy,
                    signer,
                    &replay_identity,
                    &request_digest,
                    &reservation.fence,
                )
                .await
            }
            V7ReserveOutcome::Existing(existing) => {
                if !same_request(
                    &existing,
                    &request_bytes,
                    &canonical_request,
                    &request_digest,
                    &replay_identity,
                    global_spend_key,
                ) {
                    return Ok(V7ProcessDecision::Conflict);
                }
                self.recover(&operation_id, *existing, policy, signer, &replay_identity)
                    .await
            }
            V7ReserveOutcome::Conflict => Ok(V7ProcessDecision::Conflict),
            V7ReserveOutcome::AuthorizationUsed => Ok(V7ProcessDecision::Rejected),
            V7ReserveOutcome::InProgress => Ok(V7ProcessDecision::Pending),
        }
    }

    async fn recover(
        &self,
        operation_id: &[u8; 16],
        record: StoredV7Operation,
        policy: &NativeGraphIssuanceV7Policy,
        signer: &V7Signer,
        replay_identity: &str,
    ) -> Result<V7ProcessDecision> {
        if record.state == V7State::Committed {
            let response = Self::validate_stored_response(
                &record,
                &serde_json::from_slice(&record.request)?,
                policy,
                signer,
                replay_identity,
            )?;
            return Ok(V7ProcessDecision::Committed(response));
        }
        match self.store.claim(operation_id).await? {
            V7ClaimOutcome::Claimed(reservation) => {
                let request: NativeGraphIssuanceV7Request = serde_json::from_slice(&record.request)
                    .context("invalid persisted V7 graph request")?;
                self.execute_owned(
                    operation_id,
                    &request,
                    policy,
                    signer,
                    replay_identity,
                    &record.request_digest,
                    &reservation.fence,
                )
                .await
            }
            V7ClaimOutcome::Live => Ok(V7ProcessDecision::Pending),
            V7ClaimOutcome::Committed => {
                self.committed_from_store(
                    operation_id,
                    &serde_json::from_slice(&record.request)?,
                    policy,
                    signer,
                    replay_identity,
                )
                .await
            }
            V7ClaimOutcome::Missing | V7ClaimOutcome::InvalidState => {
                Ok(V7ProcessDecision::Pending)
            }
        }
    }

    async fn execute_owned(
        &self,
        operation_id: &[u8; 16],
        request: &NativeGraphIssuanceV7Request,
        policy: &NativeGraphIssuanceV7Policy,
        signer: &V7Signer,
        replay_identity: &str,
        request_digest: &[u8; 32],
        fence: &[u8],
    ) -> Result<V7ProcessDecision> {
        request.validate().map_err(anyhow::Error::msg)?;
        if request.request_digest().map_err(anyhow::Error::msg)? != *request_digest {
            bail!("persisted V7 graph request digest mismatch")
        }
        let message = validate_blinded_message(policy, &request.blinded_message)?;
        // This is the only signing call in the V7 graph lane. A provider
        // failure leaves the durable reservation in place for a later claim.
        let signature = match self.inventory.sign(signer.identity(), &message).await {
            Ok(signature) => signature,
            Err(_) => return Ok(V7ProcessDecision::Pending),
        };
        let mut result = NativeGraphIssuanceV7Result {
            version: request.version,
            profile_id: request.profile_id.clone(),
            issuer_id: request.issuer_id.clone(),
            public_operation_id: request.public_operation_id.clone(),
            graph_id: request.graph_id.clone(),
            policy_id: request.policy_id.clone(),
            keyset_id: request.keyset_id.clone(),
            descriptor_id: request.descriptor_id.clone(),
            token_key_id: request.token_key_id.clone(),
            asset_id: request.asset_id.clone(),
            amount_minor: request.amount_minor.clone(),
            quantity: request.quantity,
            blinded_message: request.blinded_message.clone(),
            request_commitment: request.request_commitment.clone(),
            replay_identity: replay_identity.to_owned(),
            blind_signature: Base64UrlUnpadded::encode_string(signature.as_bytes()),
            result_digest: String::new(),
        };
        result.result_digest =
            hex::encode(result.result_digest_bytes().map_err(anyhow::Error::msg)?);
        validate_result_against(&result, request, policy, signer, &replay_identity)?;
        let response = serde_json::to_vec(&result)?;
        match self
            .store
            .commit(operation_id, request_digest, fence, &response)
            .await?
        {
            V7TransitionOutcome::Applied | V7TransitionOutcome::Repeated => {
                self.committed_from_store(operation_id, request, policy, signer, replay_identity)
                    .await
            }
            V7TransitionOutcome::Conflict
            | V7TransitionOutcome::InvalidState
            | V7TransitionOutcome::StaleFence => match self.store.get(operation_id).await? {
                Some(record) if record.state == V7State::Committed => {
                    let request = serde_json::from_slice(&record.request)?;
                    let response = Self::validate_stored_response(
                        &record,
                        &request,
                        policy,
                        signer,
                        replay_identity,
                    )?;
                    Ok(V7ProcessDecision::Committed(response))
                }
                _ => Ok(V7ProcessDecision::Pending),
            },
        }
    }

    async fn committed_from_store(
        &self,
        operation_id: &[u8; 16],
        request: &NativeGraphIssuanceV7Request,
        policy: &NativeGraphIssuanceV7Policy,
        signer: &V7Signer,
        replay_identity: &str,
    ) -> Result<V7ProcessDecision> {
        let record = self
            .store
            .get(operation_id)
            .await?
            .context("committed V7 graph operation disappeared")?;
        if record.state != V7State::Committed {
            return Ok(V7ProcessDecision::Pending);
        }
        Ok(V7ProcessDecision::Committed(
            Self::validate_stored_response(&record, request, policy, signer, replay_identity)?,
        ))
    }

    pub async fn status(&self, operation_id: &[u8; 16]) -> Result<V7StatusDecision> {
        Ok(match self.store.get(operation_id).await? {
            None => V7StatusDecision::Unknown,
            Some(record) => match record.state {
                V7State::Reserved => V7StatusDecision::Pending,
                V7State::Committed => {
                    let response = record
                        .response
                        .context("committed V7 graph operation response missing")?;
                    let result: NativeGraphIssuanceV7Result = serde_json::from_slice(&response)?;
                    result.validate().map_err(anyhow::Error::msg)?;
                    V7StatusDecision::Committed(response)
                }
            },
        })
    }
}

fn same_request(
    record: &StoredV7Operation,
    request: &[u8],
    canonical_request: &[u8],
    request_digest: &[u8; 32],
    replay_identity: &str,
    global_spend_key: &str,
) -> bool {
    record.request == request
        && record.canonical_request == canonical_request
        && record.request_digest == *request_digest
        && record.replay_identity == replay_identity
        && record.global_spend_key == global_spend_key
}

fn decode_operation_id(value: &str) -> Result<[u8; 16]> {
    let bytes = Base64UrlUnpadded::decode_vec(value)?;
    if bytes.len() != 16 || Base64UrlUnpadded::encode_string(&bytes) != value {
        bail!("invalid V7 operation id")
    }
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid V7 operation id"))
}

fn identity_for_policy(policy: &NativeGraphIssuanceV7Policy) -> Result<V7SignerIdentity> {
    let token_key_id = hex::decode(&policy.token_key_id)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid V7 token key identity"))?;
    V7SignerIdentity::new(
        policy.issuer_id.clone(),
        policy.profile_id.clone(),
        policy.descriptor_id.clone(),
        V7TokenKeyId::new(token_key_id),
    )
}

fn validate_policy_binding(policy: &NativeGraphIssuanceV7Policy, signer: &V7Signer) -> Result<()> {
    let metadata = signer.metadata();
    if metadata.profile_id != policy.profile_id
        || metadata.issuer_id != policy.issuer_id
        || metadata.descriptor_id != policy.descriptor_id
        || metadata.token_key_id != policy.token_key_id
        || metadata.asset_id != policy.asset_id
        || metadata.amount_minor.to_string() != policy.amount_minor
        || metadata.suite != policy.suite
        || metadata.modulus_bits != policy.modulus_bits
        || metadata.exponent != policy.exponent
        || metadata.pubkey_spki_b64 != policy.pubkey_spki_b64
        || metadata.spki_fingerprint != policy.spki_fingerprint
        || metadata.valid_from != policy.valid_from
        || metadata.valid_until != policy.valid_until
    {
        bail!("V7 graph policy does not match immutable signer identity")
    }
    signer.validate_policy(&policy.asset_id, policy.amount_minor.parse()?)
}

fn request_matches_policy(
    request: &NativeGraphIssuanceV7Request,
    policy: &NativeGraphIssuanceV7Policy,
) -> bool {
    request.version == NATIVE_GRAPH_ISSUANCE_V7_VERSION
        && request.profile_id == NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID
        && request.issuer_id == policy.issuer_id
        && request.graph_id == policy.graph_id
        && request.policy_id == policy.policy_id
        && request.keyset_id == policy.keyset_id
        && request.descriptor_id == policy.descriptor_id
        && request.token_key_id == policy.token_key_id
        && request.asset_id == policy.asset_id
        && request.amount_minor == policy.amount_minor
        && request.quantity == NATIVE_GRAPH_ISSUANCE_V7_QUANTITY
}

fn validate_blinded_message(
    policy: &NativeGraphIssuanceV7Policy,
    encoded: &str,
) -> Result<V7BlindMessage> {
    let bytes = Base64UrlUnpadded::decode_vec(encoded)?;
    if bytes.len() != 384 || Base64UrlUnpadded::encode_string(&bytes) != encoded {
        bail!("V7 blinded representative must be canonical raw384")
    }
    if bytes.iter().all(|byte| *byte == 0) {
        bail!("V7 blinded representative must be nonzero")
    }
    let spki = Base64UrlUnpadded::decode_vec(&policy.pubkey_spki_b64)?;
    let public_key = PublicKeySha384PSSRandomized::from_spki(&spki)
        .map_err(|error| anyhow::anyhow!("invalid V7 selected modulus: {error}"))?;
    if bytes.as_slice() >= public_key.components().n().as_slice() {
        bail!("V7 blinded representative must be below selected modulus")
    }
    V7BlindMessage::from_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid V7 blind message: {error:?}"))
}

fn validate_result_against(
    result: &NativeGraphIssuanceV7Result,
    request: &NativeGraphIssuanceV7Request,
    policy: &NativeGraphIssuanceV7Policy,
    signer: &V7Signer,
    replay_identity: &str,
) -> Result<()> {
    result.validate().map_err(anyhow::Error::msg)?;
    if result.version != NATIVE_GRAPH_ISSUANCE_V7_VERSION
        || result.profile_id != request.profile_id
        || result.issuer_id != request.issuer_id
        || result.public_operation_id != request.public_operation_id
        || result.graph_id != policy.graph_id
        || result.policy_id != policy.policy_id
        || result.keyset_id != policy.keyset_id
        || result.descriptor_id != signer.identity().descriptor_id()
        || result.token_key_id != hex::encode(signer.identity().token_key_id().as_bytes())
        || result.asset_id != policy.asset_id
        || result.amount_minor != policy.amount_minor
        || result.quantity != NATIVE_GRAPH_ISSUANCE_V7_QUANTITY
        || result.blinded_message != request.blinded_message
        || result.request_commitment != request.request_commitment
        || result.replay_identity != replay_identity
    {
        bail!("V7 graph result does not match request or immutable policy")
    }
    Ok(())
}
