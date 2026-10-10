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
    NativeExchangeV3Descriptor, NativeExchangeV3Discovery, NativeGraphIssuanceV7Discovery,
    NativeGraphIssuanceV7Policy, NativeGraphIssuanceV7Request, NativeGraphIssuanceV7Result,
    NATIVE_EXCHANGE_V3_PROFILE_ID, NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID,
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
    graph_discovery: NativeGraphIssuanceV7Discovery,
    exchange_discovery: Arc<NativeExchangeV3Discovery>,
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
        discovery: NativeGraphIssuanceV7Discovery,
        exchange_discovery: Arc<NativeExchangeV3Discovery>,
        inventory: Arc<V7SignerInventory>,
        redis_url: &str,
    ) -> Result<Self> {
        Self::new_internal(
            issuer_id,
            discovery,
            exchange_discovery,
            inventory,
            redis_url,
            None,
            None,
            true,
        )
    }

    /// Constructor variant used by startup and focused tests which need the
    /// recovery surface while fresh issuance is disabled.
    pub fn new_with_enabled(
        issuer_id: impl Into<String>,
        discovery: NativeGraphIssuanceV7Discovery,
        exchange_discovery: Arc<NativeExchangeV3Discovery>,
        inventory: Arc<V7SignerInventory>,
        redis_url: &str,
        enabled: bool,
    ) -> Result<Self> {
        Self::new_internal(
            issuer_id,
            discovery,
            exchange_discovery,
            inventory,
            redis_url,
            None,
            None,
            enabled,
        )
    }

    /// Construct the V7 lane with the existing V4-local verifier and its
    /// unchanged policy/trust configuration. V7 never parses or authenticates
    /// the credential itself; it delegates that operation to the established
    /// authorizer before touching the V7 signer or durable issuance state.
    pub fn new_with_v4_local_authorization(
        issuer_id: impl Into<String>,
        discovery: NativeGraphIssuanceV7Discovery,
        exchange_discovery: Arc<NativeExchangeV3Discovery>,
        inventory: Arc<V7SignerInventory>,
        redis_url: &str,
        authorization_policy: GraphIssuancePolicy,
        authorizer: Arc<V4LocalGraphIssuanceAuthorizer>,
    ) -> Result<Self> {
        Self::new_internal(
            issuer_id,
            discovery,
            exchange_discovery,
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
        discovery: NativeGraphIssuanceV7Discovery,
        exchange_discovery: Arc<NativeExchangeV3Discovery>,
        inventory: Arc<V7SignerInventory>,
        redis_url: &str,
        authorization_policy: GraphIssuancePolicy,
        authorizer: Arc<V4LocalGraphIssuanceAuthorizer>,
    ) -> Result<Self> {
        Self::new_with_v4_local_authorization(
            issuer_id,
            discovery,
            exchange_discovery,
            inventory,
            redis_url,
            authorization_policy,
            authorizer,
        )
    }

    // These independently validated constructor inputs mirror the public overloads;
    // grouping them would be an unrelated API refactor in this focused repair.
    #[allow(clippy::too_many_arguments)]
    fn new_internal(
        issuer_id: impl Into<String>,
        discovery: NativeGraphIssuanceV7Discovery,
        exchange_discovery: Arc<NativeExchangeV3Discovery>,
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
            policy.validate()?;
            authorizer.validate_policy_configuration(policy)?;
        } else if authorization_policy.is_some() || authorizer.is_some() {
            bail!("V7 graph authorization configuration is incomplete")
        }
        let indexed =
            validate_graph_configuration(&issuer_id, &discovery, &exchange_discovery, &inventory)?;
        Ok(Self {
            enabled,
            issuer_id,
            policies: indexed,
            graph_discovery: discovery,
            exchange_discovery,
            inventory,
            store: V7GraphIssuanceStore::new(redis_url)?,
            authorization_policy,
            authorizer,
        })
    }

    pub fn issuance_enabled(&self) -> bool {
        self.enabled
    }

    /// Revalidate the captured graph/exchange/signer binding used by startup and readiness.
    pub fn validate_bindings(&self) -> Result<()> {
        Self::validate_configuration(
            &self.issuer_id,
            &self.graph_discovery,
            &self.exchange_discovery,
            &self.inventory,
        )
        .map(|_| ())
    }

    /// Validate a graph discovery against complete exchange metadata and the private signer inventory.
    pub fn validate_configuration(
        issuer_id: &str,
        graph: &NativeGraphIssuanceV7Discovery,
        exchange: &NativeExchangeV3Discovery,
        inventory: &V7SignerInventory,
    ) -> Result<()> {
        validate_graph_configuration(issuer_id, graph, exchange, inventory).map(|_| ())
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
        let descriptor = match exchange_descriptor_for_policy(policy, &self.exchange_discovery) {
            Some(descriptor) => descriptor,
            None => return Ok(V7ProcessDecision::Rejected),
        };
        if validate_policy_binding(policy, descriptor, signer).is_err()
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

    // Keep this explicit transaction context together; splitting it into a
    // parameter object would obscure the fixed request/policy/signer binding.
    #[allow(clippy::too_many_arguments)]
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
        validate_result_against(&result, request, policy, signer, replay_identity)?;
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
        NATIVE_EXCHANGE_V3_PROFILE_ID,
        policy.descriptor_id.clone(),
        V7TokenKeyId::new(token_key_id),
    )
}

fn validate_policy_binding(
    policy: &NativeGraphIssuanceV7Policy,
    descriptor: &NativeExchangeV3Descriptor,
    signer: &V7Signer,
) -> Result<()> {
    let metadata = signer.metadata();
    if descriptor.profile_id != NATIVE_EXCHANGE_V3_PROFILE_ID
        || descriptor.issuer_id != policy.issuer_id
        || descriptor.descriptor_id != policy.descriptor_id
        || descriptor.token_key_id != policy.token_key_id
        || descriptor.asset_id != policy.asset_id
        || descriptor.amount_minor != policy.amount_minor
        || descriptor.suite != policy.suite
        || descriptor.modulus_bits != policy.modulus_bits
        || descriptor.exponent != policy.exponent
        || descriptor.pubkey_spki_b64 != policy.pubkey_spki_b64
        || descriptor.spki_fingerprint != policy.spki_fingerprint
        || u64::try_from(policy.valid_from).ok() != Some(descriptor.valid_from)
        || u64::try_from(policy.valid_until).ok() != Some(descriptor.valid_until)
        || metadata.profile_id != NATIVE_EXCHANGE_V3_PROFILE_ID
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

fn exchange_descriptor_for_policy<'a>(
    policy: &NativeGraphIssuanceV7Policy,
    exchange: &'a NativeExchangeV3Discovery,
) -> Option<&'a NativeExchangeV3Descriptor> {
    exchange
        .active_descriptors
        .iter()
        .chain(&exchange.retained_descriptors)
        .find(|descriptor| descriptor.descriptor_id == policy.descriptor_id)
}

/// Shared startup, constructor, and readiness validation for graph policy references.
pub fn validate_graph_configuration(
    issuer_id: &str,
    graph: &NativeGraphIssuanceV7Discovery,
    exchange: &NativeExchangeV3Discovery,
    inventory: &V7SignerInventory,
) -> Result<HashMap<String, NativeGraphIssuanceV7Policy>> {
    if graph.active_policies.is_empty() && graph.retained_policies.is_empty() {
        bail!("V7 graph policy list is empty")
    }
    freebird_common::api::validate_native_graph_issuance_v7_exchange_bindings(
        issuer_id, graph, exchange,
    )
    .map_err(anyhow::Error::msg)?;
    let mut indexed =
        HashMap::with_capacity(graph.active_policies.len() + graph.retained_policies.len());
    for policy in graph.active_policies.iter().chain(&graph.retained_policies) {
        let descriptor = exchange_descriptor_for_policy(policy, exchange)
            .context("V7 graph policy exchange descriptor is missing")?;
        let identity = identity_for_policy(policy)?;
        let signer = inventory.lookup(&identity).map_err(|_| {
            anyhow::anyhow!(
                "V7 graph exchange signer {} is missing from private signer inventory",
                policy.descriptor_id
            )
        })?;
        validate_policy_binding(policy, descriptor, signer)?;
        if indexed
            .insert(policy.policy_id.clone(), policy.clone())
            .is_some()
        {
            bail!("duplicate V7 graph policy identity")
        }
    }
    Ok(indexed)
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

#[cfg(test)]
mod exchange_reference_tests {
    use super::*;
    use crate::config::NativeBearerV7Config;
    use crate::v7_signers::{V7SignerInventory, V7SignerSpec};
    use base64ct::Encoding;
    use freebird_common::api::{
        NativeExchangeV3Keyset, NativeExchangeV3Profile, NATIVE_EXCHANGE_V3_SUITE,
    };
    use std::{path::Path, sync::Arc};
    use tempfile::{tempdir, TempDir};

    fn signer_config(root: &Path, profile_id: &str, byte: u8) -> NativeBearerV7Config {
        NativeBearerV7Config {
            sk_path: root.join(format!("{byte}.der")),
            metadata_path: root.join(format!("{byte}.json")),
            registry_path: root.join(format!("{byte}-registry.json")),
            profile_id: profile_id.into(),
            descriptor_id: String::new(),
            token_key_id: format!("{byte:02x}").repeat(32),
            asset_id: "USD".into(),
            amount_minor: 42,
            validity_secs: 86_400,
        }
    }

    struct Fixture {
        _directory: TempDir,
        inventory: Arc<V7SignerInventory>,
        direct_only_inventory: Arc<V7SignerInventory>,
        exchange: NativeExchangeV3Discovery,
        graph: NativeGraphIssuanceV7Discovery,
        direct_identity: V7SignerIdentity,
        graph_identity: V7SignerIdentity,
    }

    fn fixture() -> Fixture {
        let directory = tempdir().unwrap();
        let direct_config = signer_config(
            directory.path(),
            freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID,
            0x11,
        );
        let exchange_config = signer_config(directory.path(), NATIVE_EXCHANGE_V3_PROFILE_ID, 0x22);
        let direct_spec = V7SignerSpec::from_native_config(&direct_config, "issuer:test").unwrap();
        let exchange_spec =
            V7SignerSpec::from_native_config(&exchange_config, "issuer:test").unwrap();
        let direct_only_inventory = Arc::new(
            V7SignerInventory::load_or_generate(
                direct_spec.clone(),
                Vec::new(),
                &direct_config.registry_path,
            )
            .unwrap(),
        );
        let _exchange_generation = V7SignerInventory::load_or_generate(
            exchange_spec.clone(),
            Vec::new(),
            &exchange_config.registry_path,
        )
        .unwrap();
        let direct =
            Arc::new(crate::v7_signers::V7Signer::load_existing(&direct_spec, true).unwrap());
        let exchange_signer =
            Arc::new(crate::v7_signers::V7Signer::load_existing(&exchange_spec, true).unwrap());
        let inventory = Arc::new(
            V7SignerInventory::from_signers(
                direct.clone(),
                vec![direct.clone(), exchange_signer.clone()],
                None,
            )
            .unwrap(),
        );
        let metadata = exchange_signer.metadata();
        let descriptor = NativeExchangeV3Descriptor {
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
        };
        let keyset_id = canonical_keyset_id(std::slice::from_ref(&descriptor.descriptor_id));
        let exchange = NativeExchangeV3Discovery {
            version: 3,
            profile: NativeExchangeV3Profile {
                version: 3,
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                graph_id: String::new(),
                suite: NATIVE_EXCHANGE_V3_SUITE.into(),
                modulus_bits: 3072,
                exponent: 65_537,
            },
            active_descriptors: vec![descriptor.clone()],
            retained_descriptors: vec![],
            active_keysets: vec![NativeExchangeV3Keyset {
                keyset_id: keyset_id.clone(),
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                descriptor_ids: vec![descriptor.descriptor_id.clone()],
            }],
            retained_keysets: vec![],
            transitions: vec![],
        };
        let mut exchange = exchange;
        exchange.profile.graph_id = canonical_exchange_graph_id(&exchange);
        let graph_id = exchange.profile.graph_id.clone();
        let mut policy = NativeGraphIssuanceV7Policy {
            policy_id: String::new(),
            profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
            graph_id,
            keyset_id,
            descriptor_id: descriptor.descriptor_id.clone(),
            token_key_id: descriptor.token_key_id.clone(),
            issuer_id: descriptor.issuer_id.clone(),
            asset_id: descriptor.asset_id.clone(),
            amount_minor: descriptor.amount_minor.clone(),
            suite: descriptor.suite.clone(),
            modulus_bits: descriptor.modulus_bits,
            exponent: descriptor.exponent,
            quantity: 1,
            pubkey_spki_b64: descriptor.pubkey_spki_b64.clone(),
            spki_fingerprint: descriptor.spki_fingerprint.clone(),
            valid_from: descriptor.valid_from as i64,
            valid_until: descriptor.valid_until as i64,
        };
        policy.policy_id = canonical_policy_id(&policy);
        let graph = NativeGraphIssuanceV7Discovery {
            version: 7,
            profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
            active_policies: vec![policy.clone()],
            retained_policies: vec![],
        };
        let token_key_id = hex::decode(&policy.token_key_id)
            .unwrap()
            .try_into()
            .unwrap();
        let graph_identity = V7SignerIdentity::new(
            policy.issuer_id,
            NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID,
            policy.descriptor_id,
            freebird_crypto::V7TokenKeyId::new(token_key_id),
        )
        .unwrap();
        Fixture {
            _directory: directory,
            inventory,
            direct_only_inventory,
            exchange,
            graph,
            direct_identity: direct.identity().clone(),
            graph_identity,
        }
    }

    fn canonical_policy_id(policy: &NativeGraphIssuanceV7Policy) -> String {
        use sha2::Digest;
        let mut transcript = Vec::new();
        for value in [
            &policy.profile_id,
            &policy.graph_id,
            &policy.keyset_id,
            &policy.descriptor_id,
            &policy.token_key_id,
            &policy.issuer_id,
            &policy.asset_id,
            &policy.amount_minor,
            &policy.suite,
        ] {
            transcript.extend_from_slice(&(value.len() as u32).to_be_bytes());
            transcript.extend_from_slice(value.as_bytes());
        }
        transcript.extend_from_slice(&policy.modulus_bits.to_be_bytes());
        transcript.extend_from_slice(&policy.exponent.to_be_bytes());
        transcript.extend_from_slice(&policy.quantity.to_be_bytes());
        let spki = Base64UrlUnpadded::decode_vec(&policy.pubkey_spki_b64).unwrap();
        transcript.extend_from_slice(&(spki.len() as u32).to_be_bytes());
        transcript.extend_from_slice(&spki);
        transcript.extend_from_slice(&(policy.spki_fingerprint.len() as u32).to_be_bytes());
        transcript.extend_from_slice(policy.spki_fingerprint.as_bytes());
        transcript.extend_from_slice(&(policy.valid_from as u64).to_be_bytes());
        transcript.extend_from_slice(&(policy.valid_until as u64).to_be_bytes());
        hex::encode(sha2::Sha256::digest(
            [
                b"freebird native graph issuance policy v7\0".as_slice(),
                transcript.as_slice(),
            ]
            .concat(),
        ))
    }

    fn lp32(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    fn canonical_keyset_id(descriptor_ids: &[String]) -> String {
        use sha2::Digest;
        let mut transcript = Vec::new();
        for descriptor_id in descriptor_ids {
            lp32(&mut transcript, descriptor_id.as_bytes());
        }
        hex::encode(sha2::Sha256::digest(
            [
                b"freebird native exchange keyset v3\0".as_slice(),
                transcript.as_slice(),
            ]
            .concat(),
        ))
    }

    fn canonical_exchange_graph_id(exchange: &NativeExchangeV3Discovery) -> String {
        use sha2::Digest;
        let mut transcript = Vec::new();
        lp32(&mut transcript, exchange.profile.profile_id.as_bytes());
        for keyset in exchange
            .active_keysets
            .iter()
            .chain(&exchange.retained_keysets)
        {
            lp32(&mut transcript, keyset.keyset_id.as_bytes());
        }
        for transition in &exchange.transitions {
            lp32(&mut transcript, transition.transition_id.as_bytes());
        }
        hex::encode(sha2::Sha256::digest(
            [
                b"freebird native exchange graph v3\0".as_slice(),
                transcript.as_slice(),
            ]
            .concat(),
        ))
    }

    #[test]
    fn generated_identity_builders_match_the_pinned_public_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../common/test-fixtures/v7-graph-reference.json"
        ))
        .unwrap();
        let exchange: NativeExchangeV3Discovery =
            serde_json::from_value(fixture["native_exchange_v7"].clone()).unwrap();
        let graph: NativeGraphIssuanceV7Discovery =
            serde_json::from_value(fixture["native_graph_issuance_v7"].clone()).unwrap();
        assert_eq!(
            canonical_keyset_id(&exchange.active_keysets[0].descriptor_ids),
            "a264ac5743948feea6d3b6bfc08b34be606ffcb40b673fefc59b6c33fa7f867a"
        );
        assert_eq!(
            canonical_exchange_graph_id(&exchange),
            "ebd7be96c21cfeb624974b96569084de33bbcc7d3bc5576d2de242ade7156efe"
        );
        assert_eq!(
            canonical_policy_id(&graph.active_policies[0]),
            "04e122f20d6adbe7271a5d6917c1fb8755def65e176bb48437955940da032b8d"
        );
    }

    #[test]
    fn graph_role_resolves_the_exchange_profile_signer_and_retained_policies_remain_valid() {
        let fixture = fixture();
        assert_ne!(
            fixture.direct_identity.token_key_id(),
            fixture.graph_identity.token_key_id()
        );
        assert_eq!(
            fixture.graph_identity.profile_id(),
            NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID
        );
        let indexed = validate_graph_configuration(
            "issuer:test",
            &fixture.graph,
            &fixture.exchange,
            &fixture.inventory,
        )
        .unwrap();
        assert_eq!(indexed.len(), 1);
        let engine = V7GraphIssuanceEngine::new_with_enabled(
            "issuer:test",
            fixture.graph.clone(),
            Arc::new(fixture.exchange.clone()),
            fixture.inventory.clone(),
            "redis://127.0.0.1:1",
            false,
        )
        .unwrap();
        engine.validate_bindings().unwrap();

        let mut retained_graph = fixture.graph.clone();
        retained_graph.retained_policies = std::mem::take(&mut retained_graph.active_policies);
        let mut retained_exchange = fixture.exchange.clone();
        retained_exchange.retained_descriptors =
            std::mem::take(&mut retained_exchange.active_descriptors);
        retained_exchange.retained_keysets = std::mem::take(&mut retained_exchange.active_keysets);
        validate_graph_configuration(
            "issuer:test",
            &retained_graph,
            &retained_exchange,
            &fixture.inventory,
        )
        .unwrap();
    }

    #[test]
    fn direct_or_graph_profile_signers_cannot_substitute_for_exchange_signer() {
        let fixture = fixture();
        assert!(validate_graph_configuration(
            "issuer:test",
            &fixture.graph,
            &fixture.exchange,
            &fixture.direct_only_inventory,
        )
        .is_err());

        let mut graph_config = signer_config(
            fixture._directory.path(),
            NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID,
            0x23,
        );
        graph_config.token_key_id = fixture.graph.active_policies[0].token_key_id.clone();
        let graph_spec = V7SignerSpec::from_native_config(&graph_config, "issuer:test").unwrap();
        let graph_only = V7SignerInventory::load_or_generate(
            graph_spec,
            Vec::new(),
            &graph_config.registry_path,
        )
        .unwrap();
        assert!(validate_graph_configuration(
            "issuer:test",
            &fixture.graph,
            &fixture.exchange,
            &graph_only,
        )
        .is_err());
    }

    #[test]
    fn graph_configuration_rejects_each_reference_and_signer_metadata_mismatch() {
        let fixture = fixture();
        for mutation in 0..15 {
            let mut graph = fixture.graph.clone();
            let mut exchange = fixture.exchange.clone();
            let policy = &mut graph.active_policies[0];
            match mutation {
                0 => policy.descriptor_id = "55".repeat(32),
                1 => policy.keyset_id = "55".repeat(32),
                2 => exchange.active_keysets[0].descriptor_ids[0] = "55".repeat(32),
                3 => policy.graph_id = "55".repeat(32),
                4 => policy.issuer_id = "issuer:other".into(),
                5 => policy.token_key_id = "55".repeat(32),
                6 => {
                    let direct = fixture.direct_only_inventory.active().metadata();
                    policy.pubkey_spki_b64 = direct.pubkey_spki_b64.clone();
                    policy.spki_fingerprint = direct.spki_fingerprint.clone();
                }
                7 => policy.asset_id = "EUR".into(),
                8 => policy.amount_minor = "43".into(),
                9 => policy.suite = "other-suite".into(),
                10 => policy.modulus_bits = 2048,
                11 => policy.exponent = 3,
                12 => policy.valid_from += 1,
                13 => policy.valid_until -= 1,
                _ => policy.policy_id = "55".repeat(32),
            }
            if mutation != 14 {
                policy.policy_id = canonical_policy_id(policy);
            }
            assert!(
                validate_graph_configuration("issuer:test", &graph, &exchange, &fixture.inventory,)
                    .is_err(),
                "graph metadata mutation {mutation} was accepted"
            );
        }
    }

    #[test]
    fn incomplete_v4_local_graph_authorization_is_rejected() {
        let policy = GraphIssuancePolicy {
            issuance_policy_id: "policy".into(),
            graph_id: "graph".into(),
            keyset_id: "keyset".into(),
            descriptor_id: "descriptor".into(),
            budget_id: "budget".into(),
            budget_limit: 1,
            quantity: 1,
            admission_state: crate::graph_issuance::GraphIssuanceAdmissionState::AcceptingNew,
            authorization_scheme: "v4_local".into(),
            v4_local: None,
        };
        assert!(policy.validate().is_err());
        assert!(V4LocalGraphIssuanceAuthorizer::new(Vec::new()).is_err());
    }
}
