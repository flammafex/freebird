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
use self::v7_store::{StoredV7Operation, V7GraphIssuanceStore, V7ReserveOutcome};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V7ProcessDecision {
    Committed(Vec<u8>),
    Conflict,
    Rejected,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V7StatusDecision {
    Committed(Vec<u8>),
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
        let result: NativeGraphIssuanceV7Result =
            serde_json::from_slice(&record.response).context("corrupt stored V7 graph result")?;
        validate_result_against(&result, request, policy, signer, replay_identity)?;
        Ok(record.response.clone())
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

    /// Process one V7 request.  The Redis reservation is the finalization
    /// point, so exact retries recover the original signed result.
    pub async fn process(
        &self,
        request: &NativeGraphIssuanceV7Request,
    ) -> Result<V7ProcessDecision> {
        if request.validate().is_err() {
            return Ok(V7ProcessDecision::Rejected);
        }
        let operation_id = decode_operation_id(&request.public_operation_id)?;
        let request_digest = request.request_digest().map_err(anyhow::Error::msg)?;
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
            let response = Self::validate_stored_response(
                &existing,
                request,
                policy,
                signer,
                &replay_identity,
            )?;
            return Ok(
                if existing.request_digest == request_digest
                    && existing.replay_identity == replay_identity
                {
                    V7ProcessDecision::Committed(response)
                } else {
                    V7ProcessDecision::Conflict
                },
            );
        }
        if !self.enabled {
            return Ok(V7ProcessDecision::Unavailable);
        }

        let now = OffsetDateTime::now_utc().unix_timestamp();
        if now < policy.valid_from || now > policy.valid_until || !signer.is_valid_at(now) {
            return Ok(V7ProcessDecision::Rejected);
        }
        let message = match validate_blinded_message(policy, &request.blinded_message) {
            Ok(message) => message,
            Err(_) => return Ok(V7ProcessDecision::Rejected),
        };
        match self
            .store
            .reserve_authorization(
                &operation_id,
                &request_digest,
                global_spend_key,
                &replay_identity,
            )
            .await?
        {
            V7ReserveOutcome::Created => {}
            V7ReserveOutcome::Existing(existing) => {
                let response = Self::validate_stored_response(
                    &existing,
                    request,
                    policy,
                    signer,
                    &replay_identity,
                )?;
                return Ok(V7ProcessDecision::Committed(response));
            }
            V7ReserveOutcome::Conflict | V7ReserveOutcome::AuthorizationUsed => {
                return Ok(V7ProcessDecision::Rejected)
            }
            V7ReserveOutcome::InProgress => return Ok(V7ProcessDecision::Unavailable),
        }
        // This is the only signing call in the V7 graph lane.  The inventory
        // performs the same validity and representative checks immediately
        // before dispatching to the V7 provider.
        let signature = match self.inventory.sign(&identity, &message).await {
            Ok(signature) => signature,
            Err(_) => {
                self.store
                    .release_authorization(&operation_id, &request_digest, global_spend_key)
                    .await?;
                return Ok(V7ProcessDecision::Rejected);
            }
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
            replay_identity: replay_identity.clone(),
            blind_signature: Base64UrlUnpadded::encode_string(signature.as_bytes()),
            result_digest: String::new(),
        };
        result.result_digest =
            hex::encode(result.result_digest_bytes().map_err(anyhow::Error::msg)?);
        validate_result_against(&result, request, policy, signer, &replay_identity)?;
        let response = serde_json::to_vec(&result)?;
        self.store
            .commit(&operation_id, &request_digest, &response)
            .await?;
        Ok(V7ProcessDecision::Committed(response))
    }

    pub async fn status(&self, operation_id: &[u8; 16]) -> Result<V7StatusDecision> {
        Ok(match self.store.get(operation_id).await? {
            None => V7StatusDecision::Unknown,
            Some(record) => {
                let result: NativeGraphIssuanceV7Result = serde_json::from_slice(&record.response)?;
                result.validate().map_err(anyhow::Error::msg)?;
                V7StatusDecision::Committed(record.response)
            }
        })
    }
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
    Ok(V7BlindMessage::from_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid V7 blind message: {error:?}"))?)
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
mod tests {
    use super::*;
    use crate::{
        config::NativeBearerV7Config,
        exchange::profiles::{
            ExchangeDescriptorV2, ExchangeKeyV2, ExchangeKeysetV2, ExchangeProfileV2, PROFILE_ID_V2,
        },
        graph_issuance::{
            GraphIssuanceAdmissionState, GraphIssuanceEngine, GraphIssuancePolicyDocument,
            GraphIssuanceV4LocalPolicy, GraphIssuanceV4TrustedIssuer, ProcessDecision,
            V4LocalGraphIssuanceAuthorizer, POLICY_DOCUMENT_VERSION,
        },
        v7_signers::{V7SignerInventory, V7SignerSpec},
    };
    use base64ct::Base64UrlUnpadded;
    use ed25519_dalek::{Signer, SigningKey};
    use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};
    use redis::AsyncCommands;
    use std::{
        net::{TcpListener, TcpStream},
        process::{Child, Command, Stdio},
        thread,
        time::Duration,
    };
    use tempfile::{tempdir, TempDir};

    struct RedisHarness {
        child: Child,
        url: String,
        port: u16,
        dir: TempDir,
    }

    impl RedisHarness {
        fn start() -> Option<Self> {
            if !Command::new("redis-server")
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
            {
                return None;
            }
            let listener = TcpListener::bind("127.0.0.1:0").ok()?;
            let port = listener.local_addr().ok()?.port();
            drop(listener);
            let dir = tempdir().ok()?;
            let child = Command::new("redis-server")
                .args([
                    "--port",
                    &port.to_string(),
                    "--bind",
                    "127.0.0.1",
                    "--dir",
                    dir.path().to_str()?,
                    "--appendonly",
                    "yes",
                    "--appendfsync",
                    "always",
                    "--save",
                    "",
                    "--maxmemory-policy",
                    "noeviction",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok()?;
            for _ in 0..250 {
                if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return Some(Self {
                        child,
                        url: format!("redis://127.0.0.1:{port}/"),
                        port,
                        dir,
                    });
                }
                thread::sleep(Duration::from_millis(20));
            }
            None
        }
    }

    impl Drop for RedisHarness {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = self.port;
            let _ = &self.dir;
        }
    }

    fn fixture() -> (TempDir, Arc<V7SignerInventory>, NativeGraphIssuanceV7Policy) {
        let root = tempdir().unwrap();
        let config = NativeBearerV7Config {
            sk_path: root.path().join("graph.der"),
            metadata_path: root.path().join("graph.json"),
            registry_path: root.path().join("registry.json"),
            profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
            descriptor_id: "02".repeat(32),
            token_key_id: "01".repeat(32),
            asset_id: "USD".into(),
            amount_minor: 42,
            validity_secs: 3600,
        };
        let spec = V7SignerSpec::from_native_config(&config, "issuer:test").unwrap();
        let inventory = Arc::new(
            V7SignerInventory::load_or_generate(spec, Vec::new(), &config.registry_path).unwrap(),
        );
        let metadata = inventory.active().metadata();
        let policy = NativeGraphIssuanceV7Policy {
            policy_id: "04".repeat(32),
            profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
            graph_id: "03".repeat(32),
            keyset_id: "05".repeat(32),
            descriptor_id: metadata.descriptor_id.clone(),
            token_key_id: metadata.token_key_id.clone(),
            issuer_id: metadata.issuer_id.clone(),
            asset_id: metadata.asset_id.clone(),
            amount_minor: metadata.amount_minor.to_string(),
            suite: metadata.suite.clone(),
            modulus_bits: metadata.modulus_bits,
            exponent: metadata.exponent,
            quantity: NATIVE_GRAPH_ISSUANCE_V7_QUANTITY,
            pubkey_spki_b64: metadata.pubkey_spki_b64.clone(),
            spki_fingerprint: metadata.spki_fingerprint.clone(),
            valid_from: metadata.valid_from,
            valid_until: metadata.valid_until,
        };
        (root, inventory, policy)
    }

    fn request(
        policy: &NativeGraphIssuanceV7Policy,
        blind: Vec<u8>,
        authorization: String,
        authorization_proof: String,
    ) -> NativeGraphIssuanceV7Request {
        NativeGraphIssuanceV7Request {
            version: NATIVE_GRAPH_ISSUANCE_V7_VERSION,
            profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
            issuer_id: policy.issuer_id.clone(),
            public_operation_id: Base64UrlUnpadded::encode_string(&[7; 16]),
            graph_id: policy.graph_id.clone(),
            policy_id: policy.policy_id.clone(),
            keyset_id: policy.keyset_id.clone(),
            descriptor_id: policy.descriptor_id.clone(),
            token_key_id: policy.token_key_id.clone(),
            asset_id: policy.asset_id.clone(),
            amount_minor: policy.amount_minor.clone(),
            quantity: NATIVE_GRAPH_ISSUANCE_V7_QUANTITY,
            blinded_message: Base64UrlUnpadded::encode_string(&blind),
            request_commitment: "06".repeat(32),
            authorization,
            authorization_proof,
        }
    }

    fn v4_authorization_policy() -> (GraphIssuancePolicy, [u8; 32]) {
        let issuer_id = "issuer:test:v4";
        let kid = "kid-v4";
        let secret = [0x41; 32];
        (
            GraphIssuancePolicy {
                issuance_policy_id: "v4-authorization-policy".into(),
                graph_id: "11".repeat(32),
                keyset_id: "22".repeat(32),
                descriptor_id: "33".repeat(32),
                budget_id: "44".repeat(32),
                budget_limit: 100,
                quantity: 1,
                admission_state: GraphIssuanceAdmissionState::AcceptingNew,
                authorization_scheme: "v4_local".into(),
                v4_local: Some(GraphIssuanceV4LocalPolicy {
                    verifier_id: "verifier:test:v4".into(),
                    audience: "native-graph-v7".into(),
                    trusted_issuers: vec![GraphIssuanceV4TrustedIssuer {
                        issuer_id: issuer_id.into(),
                        key_ids: vec![kid.into()],
                    }],
                }),
            },
            secret,
        )
    }

    fn holder_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x52; 32])
    }

    fn v4_credential(secret: [u8; 32], wrong_scope: bool) -> String {
        let verifier_id = if wrong_scope {
            "verifier:wrong"
        } else {
            "verifier:test:v4"
        };
        let audience = "native-graph-v7";
        let scope = freebird_crypto::build_scope_digest(verifier_id, audience).unwrap();
        let input = freebird_crypto::build_private_token_input(
            "issuer:test:v4",
            "kid-v4",
            &holder_signing_key().verifying_key().to_bytes(),
            &scope,
        )
        .unwrap();
        let server =
            freebird_crypto::Server::from_secret_key(secret, freebird_crypto::VOPRF_CONTEXT_V4)
                .unwrap();
        let token = freebird_crypto::RedemptionToken {
            nonce: holder_signing_key().verifying_key().to_bytes(),
            scope_digest: scope,
            kid: "kid-v4".into(),
            issuer_id: "issuer:test:v4".into(),
            authenticator: server.evaluate_unblinded(&input).unwrap(),
        };
        Base64UrlUnpadded::encode_string(&freebird_crypto::build_redemption_token(&token).unwrap())
    }

    fn unsigned_proof() -> String {
        Base64UrlUnpadded::encode_string(&[0; 64])
    }

    fn holder_authorized_request(
        policy: &NativeGraphIssuanceV7Policy,
        authorization: String,
    ) -> NativeGraphIssuanceV7Request {
        let mut request = request(policy, vec![1; 384], authorization, unsigned_proof());
        resign_holder_proof(&mut request);
        request
    }

    fn resign_holder_proof(request: &mut NativeGraphIssuanceV7Request) {
        let digest = request.authorization_proof_digest().unwrap();
        request.authorization_proof =
            Base64UrlUnpadded::encode_string(&holder_signing_key().sign(&digest).to_bytes());
    }

    fn v4_authorizer(secret: [u8; 32]) -> Arc<V4LocalGraphIssuanceAuthorizer> {
        Arc::new(
            V4LocalGraphIssuanceAuthorizer::new(vec![
                crate::config::GraphIssuanceV4VerificationKey {
                    issuer_id: "issuer:test:v4".into(),
                    kid: "kid-v4".into(),
                    secret_key: secret,
                },
            ])
            .unwrap(),
        )
    }

    fn authorized_engine(
        inventory: Arc<V7SignerInventory>,
        policy: NativeGraphIssuanceV7Policy,
        redis_url: &str,
    ) -> V7GraphIssuanceEngine {
        let (authorization_policy, secret) = v4_authorization_policy();
        let authorizer = v4_authorizer(secret);
        V7GraphIssuanceEngine::new_with_v4_local_authorization(
            "issuer:test",
            vec![policy],
            inventory,
            redis_url,
            authorization_policy,
            authorizer,
        )
        .unwrap()
    }

    async fn legacy_engine_fixture(
        directory: &TempDir,
        redis_url: &str,
        authorization_policy: &GraphIssuancePolicy,
        secret: [u8; 32],
        authorization: String,
    ) -> (
        GraphIssuanceEngine,
        freebird_common::graph_issuance_api::GraphIssuanceRequestV2,
    ) {
        let provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let private_key_path = directory.path().join("legacy-graph-signer.der");
        std::fs::write(&private_key_path, provider.to_der().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let mut descriptor = ExchangeDescriptorV2 {
            id: String::new(),
            profile_id: PROFILE_ID_V2.into(),
            issuer_id: "issuer:legacy-graph".into(),
            kid: hex::encode(provider.token_key_id()),
            audience: None,
            spki_b64: Base64UrlUnpadded::encode_string(provider.public_key_spki()),
            suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
            valid_from: 1,
            valid_until: 4_102_444_800,
        };
        descriptor.id = descriptor.canonical_id().unwrap();
        let mut keyset = ExchangeKeysetV2 {
            id: String::new(),
            keys: vec![ExchangeKeyV2 {
                descriptor: descriptor.clone(),
                private_key_path: Some(private_key_path.display().to_string()),
            }],
        };
        keyset.id = keyset.canonical_id();
        let graph = ExchangeProfileV2 {
            profile_id: PROFILE_ID_V2.into(),
            graph_id: "a1".repeat(32),
            keysets: vec![keyset],
            transitions: Vec::new(),
        };
        let policy = GraphIssuancePolicy {
            issuance_policy_id: "legacy-cross-engine-policy".into(),
            graph_id: graph.graph_id.clone(),
            keyset_id: graph.keysets[0].id.clone(),
            descriptor_id: descriptor.id.clone(),
            budget_id: "legacy-cross-engine-budget".into(),
            budget_limit: 2,
            quantity: 1,
            admission_state: GraphIssuanceAdmissionState::AcceptingNew,
            authorization_scheme: "v4_local".into(),
            v4_local: authorization_policy.v4_local.clone(),
        };
        let authorizer = v4_authorizer(secret);
        let mut engine = GraphIssuanceEngine::new(
            &graph,
            &[],
            GraphIssuancePolicyDocument {
                version: POLICY_DOCUMENT_VERSION.into(),
                policies: vec![policy.clone()],
            },
            redis_url,
            authorizer,
        )
        .unwrap();
        engine.initialize().await.unwrap();
        let request = freebird_common::graph_issuance_api::GraphIssuanceRequestV2 {
            version: freebird_common::graph_issuance_api::GRAPH_ISSUANCE_VERSION_V2,
            public_operation_id: Base64UrlUnpadded::encode_string(&[0x91; 16]),
            issuance_policy_id: policy.issuance_policy_id,
            graph_id: policy.graph_id,
            keyset_id: policy.keyset_id,
            descriptor_id: policy.descriptor_id,
            blinded_message: Base64UrlUnpadded::encode_string(&[0x92; 256]),
            authorization,
        };
        (engine, request)
    }

    async fn canonical_v4_spend_key(
        authorization_policy: &GraphIssuancePolicy,
        secret: [u8; 32],
        authorization: &str,
    ) -> String {
        let verified = v4_authorizer(secret)
            .verify_credential(authorization_policy, &[0; 32], authorization)
            .unwrap();
        let key = verified.claim.global_spend_key.unwrap();
        assert_eq!(
            key,
            freebird_common::spend_key::v4_spend_key(&verified.nullifier)
        );
        key
    }

    #[test]
    fn v7_policy_resolves_the_complete_immutable_identity() {
        let (_root, inventory, policy) = fixture();
        let engine = V7GraphIssuanceEngine::new(
            "issuer:test",
            vec![policy.clone()],
            inventory.clone(),
            "redis://v7-graph-shape",
        )
        .unwrap();
        assert_eq!(engine.discovery(i64::MAX).retained_policies.len(), 1);

        let mut wrong = policy;
        wrong.descriptor_id = "08".repeat(32);
        assert!(V7GraphIssuanceEngine::new(
            "issuer:test",
            vec![wrong],
            inventory,
            "redis://v7-graph-shape-wrong",
        )
        .is_err());
    }

    #[test]
    fn v7_blinds_are_exact_raw384_nonzero_and_below_the_selected_modulus() {
        let (_root, _inventory, policy) = fixture();
        let encoded = |bytes: &[u8]| Base64UrlUnpadded::encode_string(bytes);
        assert!(validate_blinded_message(&policy, &encoded(&[1; 384])).is_ok());
        assert!(validate_blinded_message(&policy, &encoded(&[0; 383])).is_err());
        assert!(validate_blinded_message(&policy, &encoded(&[0; 385])).is_err());
        assert!(validate_blinded_message(&policy, &encoded(&[0; 384])).is_err());
        let modulus = PublicKeySha384PSSRandomized::from_spki(
            &Base64UrlUnpadded::decode_vec(&policy.pubkey_spki_b64).unwrap(),
        )
        .unwrap()
        .components()
        .n()
        .clone();
        assert!(validate_blinded_message(&policy, &encoded(&modulus)).is_err());
    }

    #[test]
    fn v7_contract_rejects_v5_v6_and_tampered_request_or_result_digests() {
        let (_root, _inventory, policy) = fixture();
        let mut request = request(
            &policy,
            vec![1; 384],
            Base64UrlUnpadded::encode_string(&[8; 64]),
            unsigned_proof(),
        );
        assert!(request.validate().is_ok());
        request.version = 6;
        assert!(request.validate().is_err());
        request.version = 5;
        assert!(request.validate().is_err());

        request.version = NATIVE_GRAPH_ISSUANCE_V7_VERSION;
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
            replay_identity: "09".repeat(32),
            blind_signature: Base64UrlUnpadded::encode_string(&[9; 384]),
            result_digest: String::new(),
        };
        result.result_digest = hex::encode(result.result_digest_bytes().unwrap());
        assert!(result.validate().is_ok());
        result.result_digest = "00".repeat(32);
        assert!(result.validate().is_err());
        request.request_commitment = "08".repeat(32);
        assert_ne!(request.request_digest().unwrap(), [0; 32]);
    }

    #[tokio::test]
    async fn valid_v4_authorization_is_verified_before_v7_signing() {
        let Some(redis) = RedisHarness::start() else {
            return;
        };
        let (_root, inventory, policy) = fixture();
        let engine = authorized_engine(inventory, policy.clone(), &redis.url);
        let (_authorization_policy, secret) = v4_authorization_policy();
        let request = holder_authorized_request(&policy, v4_credential(secret, false));
        let decision = engine.process(&request).await.unwrap();
        let V7ProcessDecision::Committed(bytes) = decision else {
            panic!("valid V4 authorization was rejected")
        };
        let result: NativeGraphIssuanceV7Result = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.descriptor_id, policy.descriptor_id);
        assert_eq!(result.token_key_id, policy.token_key_id);
        assert_eq!(result.replay_identity.len(), 64);
        assert_ne!(result.replay_identity, "07".repeat(32));
    }

    #[tokio::test]
    async fn malformed_tampered_and_wrong_scope_v4_authorizations_are_rejected_before_reservation()
    {
        let Some(redis) = RedisHarness::start() else {
            return;
        };
        let (_root, inventory, policy) = fixture();
        let engine = authorized_engine(inventory, policy.clone(), &redis.url);
        let (_authorization_policy, secret) = v4_authorization_policy();
        for (index, authorization) in ["not-base64".to_owned(), v4_credential(secret, true), {
            let mut bytes = Base64UrlUnpadded::decode_vec(&v4_credential(secret, false)).unwrap();
            bytes[0] ^= 1;
            Base64UrlUnpadded::encode_string(&bytes)
        }]
        .into_iter()
        .enumerate()
        {
            let mut request = request(&policy, vec![1; 384], authorization, unsigned_proof());
            request.public_operation_id = Base64UrlUnpadded::encode_string(&[20 + index as u8; 16]);
            assert!(matches!(
                engine.process(&request).await.unwrap(),
                V7ProcessDecision::Rejected
            ));
        }
    }

    #[tokio::test]
    async fn one_v4_credential_is_global_replay_once_across_operations_and_retries() {
        let Some(redis) = RedisHarness::start() else {
            return;
        };
        let (_root, inventory, policy) = fixture();
        let engine = Arc::new({
            let engine = authorized_engine(inventory, policy.clone(), &redis.url);
            engine
        });
        let (_authorization_policy, secret) = v4_authorization_policy();
        let authorization = v4_credential(secret, false);
        let first = holder_authorized_request(&policy, authorization.clone());
        assert!(matches!(
            engine.process(&first).await.unwrap(),
            V7ProcessDecision::Committed(_)
        ));
        let mut different_operation = first.clone();
        different_operation.public_operation_id = Base64UrlUnpadded::encode_string(&[8; 16]);
        resign_holder_proof(&mut different_operation);
        assert!(matches!(
            engine.process(&different_operation).await.unwrap(),
            V7ProcessDecision::Rejected
        ));
        assert!(matches!(
            engine.process(&first).await.unwrap(),
            V7ProcessDecision::Committed(_)
        ));
    }

    #[tokio::test]
    async fn concurrent_v4_replay_reservation_allows_one_sign_and_exact_retry_recovers() {
        let Some(redis) = RedisHarness::start() else {
            return;
        };
        let (_root, inventory, policy) = fixture();
        let engine = Arc::new(authorized_engine(inventory, policy.clone(), &redis.url));
        let (_authorization_policy, secret) = v4_authorization_policy();
        let request = holder_authorized_request(&policy, v4_credential(secret, false));
        let (left, right) = tokio::join!(engine.process(&request), engine.process(&request));
        let decisions = [left.unwrap(), right.unwrap()];
        let committed_count = decisions
            .iter()
            .filter(|decision| matches!(decision, V7ProcessDecision::Committed(_)))
            .count();
        assert!(committed_count >= 1);
        assert!(decisions.iter().any(|decision| matches!(
            decision,
            V7ProcessDecision::Unavailable | V7ProcessDecision::Committed(_)
        )));
        assert!(matches!(
            engine.process(&request).await.unwrap(),
            V7ProcessDecision::Committed(_)
        ));
    }

    #[tokio::test]
    async fn cross_engine_legacy_first_then_v7_rejects_on_the_canonical_marker() {
        let Some(redis) = RedisHarness::start() else {
            return;
        };
        let (authorization_policy, secret) = v4_authorization_policy();
        let authorization = v4_credential(secret, false);
        let global_key =
            canonical_v4_spend_key(&authorization_policy, secret, &authorization).await;
        let legacy_directory = tempdir().unwrap();
        let (legacy, legacy_request) = legacy_engine_fixture(
            &legacy_directory,
            &redis.url,
            &authorization_policy,
            secret,
            authorization.clone(),
        )
        .await;
        let (_root, inventory, policy) = fixture();
        let v7 = authorized_engine(inventory, policy.clone(), &redis.url);
        let v7_request = holder_authorized_request(&policy, authorization);

        assert!(matches!(
            legacy.process(&legacy_request, &[0xa1; 32]).await.unwrap(),
            ProcessDecision::Committed(_)
        ));
        assert!(matches!(
            v7.process(&v7_request).await.unwrap(),
            V7ProcessDecision::Rejected
        ));

        let mut connection = redis::Client::open(redis.url.clone())
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let marker: Option<Vec<u8>> = connection.get(&global_key).await.unwrap();
        assert_eq!(marker.as_deref(), Some(b"1".as_slice()));
    }

    #[tokio::test]
    async fn cross_engine_v7_first_then_legacy_rejects_on_the_canonical_marker() {
        let Some(redis) = RedisHarness::start() else {
            return;
        };
        let (authorization_policy, secret) = v4_authorization_policy();
        let authorization = v4_credential(secret, false);
        let global_key =
            canonical_v4_spend_key(&authorization_policy, secret, &authorization).await;
        let legacy_directory = tempdir().unwrap();
        let (legacy, legacy_request) = legacy_engine_fixture(
            &legacy_directory,
            &redis.url,
            &authorization_policy,
            secret,
            authorization.clone(),
        )
        .await;
        let (_root, inventory, policy) = fixture();
        let v7 = authorized_engine(inventory, policy.clone(), &redis.url);
        let v7_request = holder_authorized_request(&policy, authorization);

        assert!(matches!(
            v7.process(&v7_request).await.unwrap(),
            V7ProcessDecision::Committed(_)
        ));
        assert!(matches!(
            legacy.process(&legacy_request, &[0xa2; 32]).await.unwrap(),
            ProcessDecision::Rejected
        ));

        let mut connection = redis::Client::open(redis.url.clone())
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let marker: Option<Vec<u8>> = connection.get(&global_key).await.unwrap();
        assert_eq!(
            marker.as_deref(),
            Some(v7_request.request_digest().unwrap().as_slice())
        );
    }

    #[tokio::test]
    async fn cross_engine_concurrent_attempts_commit_once_and_reject_once() {
        let Some(redis) = RedisHarness::start() else {
            return;
        };
        let (authorization_policy, secret) = v4_authorization_policy();
        let authorization = v4_credential(secret, false);
        let global_key =
            canonical_v4_spend_key(&authorization_policy, secret, &authorization).await;
        let legacy_directory = tempdir().unwrap();
        let (legacy, legacy_request) = legacy_engine_fixture(
            &legacy_directory,
            &redis.url,
            &authorization_policy,
            secret,
            authorization.clone(),
        )
        .await;
        let (_root, inventory, policy) = fixture();
        let v7_request = holder_authorized_request(&policy, authorization);
        let legacy = Arc::new(legacy);
        let v7 = Arc::new(authorized_engine(inventory, policy, &redis.url));
        let (legacy_result, v7_result) = tokio::join!(
            legacy.process(&legacy_request, &[0xa3; 32]),
            v7.process(&v7_request),
        );
        let legacy_result = legacy_result.unwrap();
        let v7_result = v7_result.unwrap();
        let legacy_committed = matches!(legacy_result, ProcessDecision::Committed(_));
        let v7_committed = matches!(v7_result, V7ProcessDecision::Committed(_));
        assert_ne!(legacy_committed, v7_committed);
        assert_eq!(
            matches!(legacy_result, ProcessDecision::Rejected),
            !legacy_committed
        );
        assert_eq!(
            matches!(v7_result, V7ProcessDecision::Rejected),
            !v7_committed
        );

        let mut connection = redis::Client::open(redis.url.clone())
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let marker: Option<Vec<u8>> = connection.get(&global_key).await.unwrap();
        assert!(marker.is_some());
        if legacy_committed {
            assert_eq!(marker.as_deref(), Some(b"1".as_slice()));
        } else {
            assert_eq!(
                marker.as_deref(),
                Some(v7_request.request_digest().unwrap().as_slice())
            );
        }
    }
}
