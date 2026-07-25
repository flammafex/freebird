// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Policy-authorized blind initial issuance into V2 graph keysets.

use crate::exchange::{profiles::ExchangeProfileV2, source_v5::PinnedTargetSignersV2};
use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::{
    api::{
        ExchangeAdmissionStateV2 as DiscoveryAdmissionState, GraphIssuanceDiscoveryV1,
        GraphIssuancePolicyDiscoveryV1,
    },
    graph_issuance_api::{
        GraphIssuanceRequestV1, GraphIssuanceResultV1, GRAPH_ISSUANCE_VERSION_V1,
        MAX_BLINDED_MESSAGE,
    },
};
use hmac::{Hmac, Mac};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::Path, sync::Arc};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const PREFIX: &str = "freebird:graph-issuance:v1:";
const STATUS_DOMAIN: &[u8] = b"freebird graph issuance status capability v1\0";
const NULLIFIER_DOMAIN: &[u8] = b"freebird graph issuance authorization nullifier v1\0";
const POLICY_DOMAIN: &[u8] = b"freebird graph issuance policy v1\0";
const AUTH_TAG_DOMAIN: &[u8] = b"freebird graph issuance hmac authorization v1\0";
pub const POLICY_DOCUMENT_VERSION: &str = "freebird/graph-blind-issuance-policy/v1";

const RESERVE: &str = r#"
local op=KEYS[1]
if redis.call('EXISTS',op)==1 then
  if redis.call('HGET',op,'request_digest')~=ARGV[1] then return 2 end
  if redis.call('HGET',op,'status_capability_digest')~=ARGV[2] then return 3 end
  return 1
end
local auth=KEYS[2]; local budget=KEYS[3]; local global_spend=KEYS[4]
local uses_global_spend=ARGV[15]=='1'
if uses_global_spend then
  if redis.call('EXISTS',global_spend)==1 then return 4 end
elseif redis.call('EXISTS',auth)==1 then return 4 end
local budget_type=redis.call('TYPE',budget)['ok']
if budget_type~='none' and budget_type~='hash' then return 5 end
local charged=0
if budget_type=='hash' then
  if redis.call('HGET',budget,'policy_digest')~=ARGV[10] or
     redis.call('HGET',budget,'policy_id')~=ARGV[3] or
     redis.call('HGET',budget,'limit')~=ARGV[12] or
     redis.call('HGET',budget,'charge_kind')~='issuance_quantity' then return 5 end
  charged=tonumber(redis.call('HGET',budget,'charged'))
  if not charged then return 5 end
end
local quantity=tonumber(ARGV[11]); local limit=tonumber(ARGV[12])
if not quantity or not limit or quantity<1 or limit<1 or quantity>limit-charged then return 6 end
-- No mutation is permitted above this line.
if uses_global_spend then
  redis.call('SET',global_spend,'1')
else
  redis.call('HSET',auth,'policy_id',ARGV[3],'authorization_nullifier_digest',ARGV[9],
    'request_digest',ARGV[1],'claimed','1')
end
if budget_type=='none' then
  redis.call('HSET',budget,'policy_id',ARGV[3],'policy_digest',ARGV[10],
    'limit',ARGV[12],'charge_kind','issuance_quantity','charged','0')
end
redis.call('HINCRBY',budget,'charged',ARGV[11])
redis.call('HSET',op,
  'request_digest',ARGV[1],'status_capability_digest',ARGV[2],
  'issuance_policy_id',ARGV[3],'graph_id',ARGV[4],'keyset_id',ARGV[5],
  'descriptor_id',ARGV[6],'signer_key_id',ARGV[7],
  'authorization_nullifier_digest',ARGV[9],'policy_digest',ARGV[10],
  'quantity',ARGV[11],'budget_id',ARGV[13],'state','committed',
  'blind_signature',ARGV[8],'response',ARGV[14])
return 0
"#;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GraphIssuanceAdmissionState {
    AcceptingNew,
    RecoveryOnly,
    Disabled,
}

impl GraphIssuanceAdmissionState {
    fn discovery(self) -> DiscoveryAdmissionState {
        match self {
            Self::AcceptingNew => DiscoveryAdmissionState::AcceptingNew,
            Self::RecoveryOnly => DiscoveryAdmissionState::RecoveryOnly,
            Self::Disabled => DiscoveryAdmissionState::Disabled,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphIssuancePolicy {
    pub issuance_policy_id: String,
    pub graph_id: String,
    pub keyset_id: String,
    pub descriptor_id: String,
    pub budget_id: String,
    pub budget_limit: u64,
    pub quantity: u32,
    pub admission_state: GraphIssuanceAdmissionState,
    pub authorization_scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v4_local: Option<GraphIssuanceV4LocalPolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphIssuanceV4LocalPolicy {
    pub verifier_id: String,
    pub audience: String,
    pub trusted_issuers: Vec<GraphIssuanceV4TrustedIssuer>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphIssuanceV4TrustedIssuer {
    pub issuer_id: String,
    pub key_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphIssuancePolicyDocument {
    pub version: String,
    pub policies: Vec<GraphIssuancePolicy>,
}

impl GraphIssuancePolicyDocument {
    pub fn load(
        path: &Path,
        active: &ExchangeProfileV2,
        retained: &[ExchangeProfileV2],
    ) -> Result<Self> {
        let document: Self = serde_json::from_slice(
            &std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
        )?;
        document.validate(active, retained)?;
        Ok(document)
    }

    pub fn validate(
        &self,
        active: &ExchangeProfileV2,
        retained: &[ExchangeProfileV2],
    ) -> Result<()> {
        if self.version != POLICY_DOCUMENT_VERSION
            || self.policies.is_empty()
            || self.policies.len() > freebird_common::exchange_api::MAX_ITEMS
        {
            bail!("invalid graph issuance policy document bounds")
        }
        let mut ids = std::collections::HashSet::new();
        let mut budgets = std::collections::HashSet::new();
        for policy in &self.policies {
            let (graph, active_graph) = std::iter::once((active, true))
                .chain(retained.iter().map(|graph| (graph, false)))
                .find(|(graph, _)| graph.graph_id == policy.graph_id)
                .context("graph issuance policy references an unknown graph")?;
            let keyset = graph
                .keysets
                .iter()
                .find(|keyset| keyset.id == policy.keyset_id)
                .context("graph issuance policy references an unknown keyset")?;
            let key = keyset
                .keys
                .iter()
                .find(|key| key.descriptor.id == policy.descriptor_id)
                .context("graph issuance policy references an unknown descriptor")?;
            if !bounded_id(&policy.issuance_policy_id)
                || !bounded_id(&policy.budget_id)
                || !matches!(
                    policy.authorization_scheme.as_str(),
                    "hmac_sha256" | "v4_local" | "development_mock"
                )
                || policy.budget_limit == 0
                || policy.budget_limit > freebird_common::api::EXCHANGE_MAX_BUDGET_LIMIT
                || policy.quantity == 0
                || u64::from(policy.quantity) > policy.budget_limit
                || !ids.insert(policy.issuance_policy_id.as_str())
                || !budgets.insert(policy.budget_id.as_str())
                || (policy.admission_state == GraphIssuanceAdmissionState::AcceptingNew
                    && (!active_graph || key.private_key_path.is_none()))
            {
                bail!("invalid graph issuance policy")
            }
            match (policy.authorization_scheme.as_str(), &policy.v4_local) {
                ("v4_local", Some(v4)) => validate_v4_local_policy(v4)?,
                ("v4_local", None) => bail!("v4_local graph issuance policy is incomplete"),
                (_, Some(_)) => bail!("non-v4 graph issuance policy contains V4 configuration"),
                (_, None) => {}
            }
        }
        Ok(())
    }

    pub fn discovery(&self) -> GraphIssuanceDiscoveryV1 {
        GraphIssuanceDiscoveryV1 {
            version: GRAPH_ISSUANCE_VERSION_V1,
            policies: self
                .policies
                .iter()
                .map(|policy| GraphIssuancePolicyDiscoveryV1 {
                    issuance_policy_id: policy.issuance_policy_id.clone(),
                    graph_id: policy.graph_id.clone(),
                    keyset_id: policy.keyset_id.clone(),
                    descriptor_id: policy.descriptor_id.clone(),
                    budget_id: policy.budget_id.clone(),
                    budget_limit: policy.budget_limit,
                    quantity: policy.quantity,
                    admission_state: policy.admission_state.discovery(),
                    authorization_scheme: policy.authorization_scheme.clone(),
                })
                .collect(),
        }
    }
}

fn bounded_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.is_ascii()
}

fn validate_v4_local_policy(policy: &GraphIssuanceV4LocalPolicy) -> Result<()> {
    if policy.verifier_id.is_empty()
        || policy.verifier_id.len() > 255
        || policy.audience.is_empty()
        || policy.audience.len() > 255
        || policy.trusted_issuers.is_empty()
        || policy.trusted_issuers.len() > freebird_common::exchange_api::MAX_ITEMS
        || freebird_crypto::build_scope_digest(&policy.verifier_id, &policy.audience).is_err()
    {
        bail!("invalid v4_local graph issuance scope")
    }
    let mut issuers = std::collections::HashSet::new();
    let mut pairs = std::collections::HashSet::new();
    for issuer in &policy.trusted_issuers {
        if issuer.issuer_id.is_empty()
            || issuer.issuer_id.len() > 255
            || issuer.key_ids.is_empty()
            || issuer.key_ids.len() > freebird_common::exchange_api::MAX_ITEMS
            || !issuers.insert(issuer.issuer_id.as_str())
        {
            bail!("invalid v4_local trusted issuer")
        }
        for kid in &issuer.key_ids {
            if kid.is_empty()
                || kid.len() > 255
                || !pairs.insert((issuer.issuer_id.as_str(), kid.as_str()))
            {
                bail!("invalid v4_local trusted key id")
            }
        }
    }
    Ok(())
}

pub struct AuthorizationClaim {
    pub nullifier_digest: [u8; 32],
    pub global_spend_key: Option<String>,
}

pub trait GraphIssuanceAuthorizer: Send + Sync {
    fn validate_policy_configuration(&self, _policy: &GraphIssuancePolicy) -> Result<()> {
        Ok(())
    }

    /// Verify opaque authorization and return a stable one-use nullifier digest.
    fn authorize(
        &self,
        policy: &GraphIssuancePolicy,
        request_binding: &[u8; 32],
        authorization: &str,
    ) -> Result<AuthorizationClaim>;
}

pub struct HmacGraphIssuanceAuthorizer {
    secret: Zeroizing<Vec<u8>>,
}

impl HmacGraphIssuanceAuthorizer {
    pub fn new(secret: Vec<u8>) -> Result<Self> {
        if secret.len() < 32 {
            bail!("graph issuance HMAC secret must contain at least 32 bytes")
        }
        Ok(Self {
            secret: Zeroizing::new(secret),
        })
    }
}

impl GraphIssuanceAuthorizer for HmacGraphIssuanceAuthorizer {
    fn authorize(
        &self,
        policy: &GraphIssuancePolicy,
        request_binding: &[u8; 32],
        authorization: &str,
    ) -> Result<AuthorizationClaim> {
        if policy.authorization_scheme != "hmac_sha256" {
            bail!("unsupported graph issuance authorization scheme")
        }
        let bytes = Base64UrlUnpadded::decode_vec(authorization)
            .context("invalid graph issuance authorization")?;
        if bytes.len() != 64 || Base64UrlUnpadded::encode_string(&bytes) != authorization {
            bail!("invalid graph issuance authorization")
        }
        let (nonce, tag) = bytes.split_at(32);
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .expect("HMAC accepts arbitrary key lengths");
        mac.update(AUTH_TAG_DOMAIN);
        mac.update(&(policy.issuance_policy_id.len() as u32).to_be_bytes());
        mac.update(policy.issuance_policy_id.as_bytes());
        mac.update(request_binding);
        mac.verify_slice(tag)
            .map_err(|_| anyhow::anyhow!("invalid graph issuance authorization"))?;
        Ok(AuthorizationClaim {
            nullifier_digest: domain_digest(NULLIFIER_DOMAIN, nonce),
            global_spend_key: None,
        })
    }
}

/// Explicitly unsafe authorizer for development and tests only.
pub struct DevelopmentMockAuthorizer;

impl GraphIssuanceAuthorizer for DevelopmentMockAuthorizer {
    fn authorize(
        &self,
        policy: &GraphIssuancePolicy,
        _request_binding: &[u8; 32],
        authorization: &str,
    ) -> Result<AuthorizationClaim> {
        if policy.authorization_scheme != "development_mock" {
            bail!("unsupported graph issuance authorization scheme")
        }
        let nonce = Base64UrlUnpadded::decode_vec(authorization)?;
        if nonce.len() != 32 || Base64UrlUnpadded::encode_string(&nonce) != authorization {
            bail!("invalid development graph issuance authorization")
        }
        Ok(AuthorizationClaim {
            nullifier_digest: domain_digest(NULLIFIER_DOMAIN, &nonce),
            global_spend_key: None,
        })
    }
}

/// Validate that the configured verifier can serve every accepting policy.
/// Used by both runtime startup and the offline configuration validator.
pub fn validate_configured_authorizer(
    config: &crate::config::GraphIssuanceAuthorizationConfig,
    document: &GraphIssuancePolicyDocument,
) -> Result<()> {
    let (scheme, authorizer): (&str, Arc<dyn GraphIssuanceAuthorizer>) = match config {
        crate::config::GraphIssuanceAuthorizationConfig::HmacSha256(secret) => (
            "hmac_sha256",
            Arc::new(HmacGraphIssuanceAuthorizer::new(secret.clone())?),
        ),
        crate::config::GraphIssuanceAuthorizationConfig::V4Local { keys, .. } => (
            "v4_local",
            Arc::new(V4LocalGraphIssuanceAuthorizer::new(keys.clone())?),
        ),
        crate::config::GraphIssuanceAuthorizationConfig::DevelopmentMock => {
            ("development_mock", Arc::new(DevelopmentMockAuthorizer))
        }
        crate::config::GraphIssuanceAuthorizationConfig::Disabled => {
            bail!("graph issuance authorization verifier is disabled")
        }
    };
    for policy in &document.policies {
        if policy.admission_state == GraphIssuanceAdmissionState::AcceptingNew {
            if policy.authorization_scheme != scheme {
                bail!("accepting graph issuance policy authorization scheme mismatch")
            }
            authorizer.validate_policy_configuration(policy)?;
        }
    }
    Ok(())
}

pub struct V4LocalGraphIssuanceAuthorizer {
    keys: HashMap<(String, String), freebird_common::v4_admission::V4VerificationKey>,
}

impl V4LocalGraphIssuanceAuthorizer {
    pub fn new(keys: Vec<crate::config::GraphIssuanceV4VerificationKey>) -> Result<Self> {
        let mut trusted = HashMap::new();
        for key in keys {
            freebird_crypto::Server::from_secret_key(
                key.secret_key,
                freebird_crypto::VOPRF_CONTEXT_V4,
            )
            .map_err(|_| anyhow::anyhow!("invalid graph issuance V4 verification key"))?;
            if trusted
                .insert(
                    (key.issuer_id, key.kid),
                    freebird_common::v4_admission::V4VerificationKey {
                        secret_key: key.secret_key,
                        context: freebird_crypto::VOPRF_CONTEXT_V4.to_vec(),
                    },
                )
                .is_some()
            {
                bail!("duplicate graph issuance V4 verification key")
            }
        }
        if trusted.is_empty() {
            bail!("graph issuance V4 verification keyring is empty")
        }
        Ok(Self { keys: trusted })
    }
}

impl GraphIssuanceAuthorizer for V4LocalGraphIssuanceAuthorizer {
    fn validate_policy_configuration(&self, policy: &GraphIssuancePolicy) -> Result<()> {
        let v4 = policy
            .v4_local
            .as_ref()
            .context("v4_local graph issuance policy is incomplete")?;
        for issuer in &v4.trusted_issuers {
            for kid in &issuer.key_ids {
                if !self
                    .keys
                    .contains_key(&(issuer.issuer_id.clone(), kid.clone()))
                {
                    bail!("v4_local policy references unavailable private verification key")
                }
            }
        }
        Ok(())
    }

    fn authorize(
        &self,
        policy: &GraphIssuancePolicy,
        _request_binding: &[u8; 32],
        authorization: &str,
    ) -> Result<AuthorizationClaim> {
        if policy.authorization_scheme != "v4_local" {
            bail!("unsupported graph issuance authorization scheme")
        }
        let v4 = policy
            .v4_local
            .as_ref()
            .context("v4_local graph issuance policy is incomplete")?;
        let token_bytes = Base64UrlUnpadded::decode_vec(authorization)
            .context("invalid V4 graph issuance authorization")?;
        if token_bytes.is_empty() || Base64UrlUnpadded::encode_string(&token_bytes) != authorization
        {
            bail!("V4 graph issuance authorization is not canonical base64url")
        }
        let expected_scope = freebird_crypto::build_scope_digest(&v4.verifier_id, &v4.audience)
            .map_err(|_| anyhow::anyhow!("invalid V4 graph issuance scope"))?;
        let verified = freebird_common::v4_admission::verify_v4_credential(
            &token_bytes,
            &expected_scope,
            &v4.verifier_id,
            &v4.audience,
            |issuer_id, kid| {
                let selected = v4.trusted_issuers.iter().any(|issuer| {
                    issuer.issuer_id == issuer_id && issuer.key_ids.iter().any(|id| id == kid)
                });
                selected
                    .then(|| {
                        self.keys
                            .get(&(issuer_id.to_owned(), kid.to_owned()))
                            .cloned()
                    })
                    .flatten()
            },
        )
        .map_err(|_| anyhow::anyhow!("V4 graph issuance authorization rejected"))?;
        let nullifier_digest: [u8; 32] = Base64UrlUnpadded::decode_vec(&verified.nullifier)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid canonical V4 nullifier"))?;
        Ok(AuthorizationClaim {
            nullifier_digest,
            global_spend_key: Some(verified.spend_key),
        })
    }
}

fn domain_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(value);
    hash.finalize().into()
}

fn status_digest(capability: &[u8; 32]) -> [u8; 32] {
    domain_digest(STATUS_DOMAIN, capability)
}

fn policy_digest(policy: &GraphIssuancePolicy) -> [u8; 32] {
    let mut bytes = Vec::new();
    for value in [
        &policy.issuance_policy_id,
        &policy.graph_id,
        &policy.keyset_id,
        &policy.descriptor_id,
        &policy.budget_id,
        &policy.authorization_scheme,
    ] {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&policy.budget_limit.to_be_bytes());
    bytes.extend_from_slice(&policy.quantity.to_be_bytes());
    match &policy.v4_local {
        Some(v4) => {
            bytes.push(1);
            for value in [&v4.verifier_id, &v4.audience] {
                bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
                bytes.extend_from_slice(value.as_bytes());
            }
            bytes.extend_from_slice(&(v4.trusted_issuers.len() as u32).to_be_bytes());
            for issuer in &v4.trusted_issuers {
                bytes.extend_from_slice(&(issuer.issuer_id.len() as u32).to_be_bytes());
                bytes.extend_from_slice(issuer.issuer_id.as_bytes());
                bytes.extend_from_slice(&(issuer.key_ids.len() as u32).to_be_bytes());
                for kid in &issuer.key_ids {
                    bytes.extend_from_slice(&(kid.len() as u32).to_be_bytes());
                    bytes.extend_from_slice(kid.as_bytes());
                }
            }
        }
        None => bytes.push(0),
    }
    domain_digest(POLICY_DOMAIN, &bytes)
}

#[derive(Clone)]
struct GraphIssuanceStore {
    client: redis::Client,
}

#[derive(Debug)]
struct StoredOperation {
    request_digest: [u8; 32],
    status_capability_digest: [u8; 32],
    response: Vec<u8>,
}

enum ReserveOutcome {
    Created,
    Existing(StoredOperation),
    Conflict,
    AuthorizationUsed,
    PolicyConflict,
    BudgetExhausted,
}

impl GraphIssuanceStore {
    fn new(redis_url: &str) -> Result<Self> {
        Ok(Self {
            client: redis::Client::open(redis_url)?,
        })
    }

    fn operation_key(operation_id: &[u8; 16]) -> String {
        format!("{PREFIX}op:{}", hex::encode(operation_id))
    }

    async fn get(&self, operation_id: &[u8; 16]) -> Result<Option<StoredOperation>> {
        let mut connection = self.client.get_async_connection().await?;
        let values: HashMap<Vec<u8>, Vec<u8>> = connection
            .hgetall(Self::operation_key(operation_id))
            .await?;
        if values.is_empty() {
            return Ok(None);
        }
        let required = |name: &[u8]| {
            values
                .get(name)
                .cloned()
                .context("incomplete graph issuance operation")
        };
        Ok(Some(StoredOperation {
            request_digest: required(b"request_digest")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid graph issuance request digest"))?,
            status_capability_digest: required(b"status_capability_digest")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid graph issuance capability digest"))?,
            response: required(b"response")?,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn reserve(
        &self,
        operation_id: &[u8; 16],
        request_digest: &[u8; 32],
        status_capability: &[u8; 32],
        policy: &GraphIssuancePolicy,
        authorization_nullifier_digest: &[u8; 32],
        global_spend_key: Option<&str>,
        signer_key_id: &str,
        blind_signature: &[u8],
        response: &[u8],
    ) -> Result<ReserveOutcome> {
        let capability_digest = status_digest(status_capability);
        let policy_digest = policy_digest(policy);
        let authorization_key = format!(
            "{PREFIX}authorization:{}:{}",
            policy.issuance_policy_id,
            hex::encode(authorization_nullifier_digest)
        );
        let budget_key = format!("{PREFIX}budget:{}", policy.budget_id);
        let no_global_spend = format!("{PREFIX}no-global-spend:{}", hex::encode(operation_id));
        let mut connection = self.client.get_async_connection().await?;
        let code: i64 = redis::Script::new(RESERVE)
            .key(Self::operation_key(operation_id))
            .key(authorization_key)
            .key(budget_key)
            .key(global_spend_key.unwrap_or(&no_global_spend))
            .arg(request_digest.as_slice())
            .arg(capability_digest.as_slice())
            .arg(&policy.issuance_policy_id)
            .arg(&policy.graph_id)
            .arg(&policy.keyset_id)
            .arg(&policy.descriptor_id)
            .arg(signer_key_id)
            .arg(blind_signature)
            .arg(authorization_nullifier_digest.as_slice())
            .arg(policy_digest.as_slice())
            .arg(policy.quantity)
            .arg(policy.budget_limit)
            .arg(&policy.budget_id)
            .arg(response)
            .arg(global_spend_key.is_some())
            .invoke_async(&mut connection)
            .await?;
        Ok(match code {
            0 => ReserveOutcome::Created,
            1 => ReserveOutcome::Existing(
                self.get(operation_id)
                    .await?
                    .context("existing graph issuance operation disappeared")?,
            ),
            2 | 3 => ReserveOutcome::Conflict,
            4 => ReserveOutcome::AuthorizationUsed,
            5 => ReserveOutcome::PolicyConflict,
            6 => ReserveOutcome::BudgetExhausted,
            _ => bail!("invalid graph issuance reservation result"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessDecision {
    Committed(Vec<u8>),
    Conflict,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusDecision {
    Committed(Vec<u8>),
    Unknown,
    Unauthorized,
}

pub struct GraphIssuanceEngine {
    active_graph_id: String,
    policies: HashMap<String, GraphIssuancePolicy>,
    signers: PinnedTargetSignersV2,
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
        document.validate(active, retained)?;
        for policy in &document.policies {
            if policy.admission_state == GraphIssuanceAdmissionState::AcceptingNew {
                authorizer.validate_policy_configuration(policy)?;
            }
        }
        Ok(Self {
            active_graph_id: active.graph_id.clone(),
            policies: document
                .policies
                .into_iter()
                .map(|policy| (policy.issuance_policy_id.clone(), policy))
                .collect(),
            signers: PinnedTargetSignersV2::load(active, retained)?,
            store: GraphIssuanceStore::new(redis_url)?,
            authorizer,
        })
    }

    pub async fn process(
        &self,
        request: &GraphIssuanceRequestV1,
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
                    ProcessDecision::Committed(existing.response)
                },
            );
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
        let blinded = match freebird_common::exchange_api::decode_base64url(
            &request.blinded_message,
            MAX_BLINDED_MESSAGE,
        ) {
            Ok(value) => value,
            Err(_) => return Ok(ProcessDecision::Rejected),
        };
        let (signer_key_id, blind_signature) = match self
            .signers
            .sign_graph_issuance(&policy.keyset_id, &policy.descriptor_id, &blinded)
            .await
        {
            Ok(value) => value,
            Err(_) => return Ok(ProcessDecision::Rejected),
        };
        let mut result = GraphIssuanceResultV1 {
            version: GRAPH_ISSUANCE_VERSION_V1,
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
        result.result_digest = Base64UrlUnpadded::encode_string(
            &result
                .calculated_result_digest()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        );
        result
            .validate()
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
                )
                .await?
            {
                ReserveOutcome::Created => ProcessDecision::Committed(response),
                ReserveOutcome::Existing(existing)
                    if existing.request_digest == request_digest
                        && bool::from(
                            existing
                                .status_capability_digest
                                .ct_eq(&status_digest(status_capability)),
                        ) =>
                {
                    ProcessDecision::Committed(existing.response)
                }
                ReserveOutcome::Existing(_) | ReserveOutcome::Conflict => ProcessDecision::Conflict,
                ReserveOutcome::AuthorizationUsed
                | ReserveOutcome::PolicyConflict
                | ReserveOutcome::BudgetExhausted => ProcessDecision::Rejected,
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
            Some(record) => StatusDecision::Committed(record.response),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{bail, Context};
    use std::{
        collections::HashMap,
        io::Write,
        net::{TcpListener, TcpStream},
        process::{Child, Command, Stdio},
        sync::Mutex,
        thread,
        time::Duration,
    };

    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    struct LogWriter(LogCapture);

    impl Write for LogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 .0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for LogCapture {
        type Writer = LogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            LogWriter(self.clone())
        }
    }

    struct RedisHarness {
        child: Option<Child>,
        url: String,
        port: u16,
        dir: tempfile::TempDir,
    }

    impl RedisHarness {
        fn start_if_available() -> anyhow::Result<Option<Self>> {
            if !Command::new("redis-server")
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
            {
                return Ok(None);
            }
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port();
            drop(listener);
            let dir = tempfile::tempdir()?;
            let mut harness = Self {
                child: None,
                url: format!("redis://127.0.0.1:{port}/"),
                port,
                dir,
            };
            harness.spawn()?;
            Ok(Some(harness))
        }

        fn spawn(&mut self) -> anyhow::Result<()> {
            self.child = Some(
                Command::new("redis-server")
                    .args([
                        "--port",
                        &self.port.to_string(),
                        "--bind",
                        "127.0.0.1",
                        "--dir",
                        self.dir.path().to_str().context("non-UTF8 Redis path")?,
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
                    .spawn()?,
            );
            for _ in 0..250 {
                if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                    return Ok(());
                }
                if self
                    .child
                    .as_mut()
                    .is_some_and(|child| child.try_wait().ok().flatten().is_some())
                {
                    bail!("Redis exited during graph issuance test startup")
                }
                thread::sleep(Duration::from_millis(20));
            }
            bail!("Redis did not become reachable")
        }

        fn restart(&mut self) -> anyhow::Result<()> {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            self.spawn()
        }
    }

    impl Drop for RedisHarness {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn redis_policy(budget_id: &str, budget_limit: u64) -> GraphIssuancePolicy {
        GraphIssuancePolicy {
            issuance_policy_id: "redis-v4-policy".into(),
            graph_id: "1".repeat(64),
            keyset_id: "2".repeat(64),
            descriptor_id: "3".repeat(64),
            budget_id: budget_id.into(),
            budget_limit,
            quantity: 1,
            admission_state: GraphIssuanceAdmissionState::AcceptingNew,
            authorization_scheme: "v4_local".into(),
            v4_local: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn reserve_for_test(
        store: &GraphIssuanceStore,
        operation: [u8; 16],
        request: [u8; 32],
        capability: [u8; 32],
        policy: &GraphIssuancePolicy,
        marker: &str,
    ) -> anyhow::Result<ReserveOutcome> {
        store
            .reserve(
                &operation,
                &request,
                &capability,
                policy,
                &[operation[0]; 32],
                Some(marker),
                "target-key",
                b"blind-signature",
                b"durable-response",
            )
            .await
    }

    #[tokio::test]
    async fn graph_issuance_redis_reservation_is_atomic_idempotent_and_aof_recoverable() {
        let Some(mut harness) = RedisHarness::start_if_available().unwrap() else {
            return;
        };
        let policy = redis_policy("redis-v4-budget", 2);
        let store = GraphIssuanceStore::new(&harness.url).unwrap();
        let marker = "freebird:spent:v4:redis-v4-marker";
        assert!(matches!(
            reserve_for_test(&store, [1; 16], [1; 32], [2; 32], &policy, marker,)
                .await
                .unwrap(),
            ReserveOutcome::Created
        ));

        let mut connection = redis::Client::open(harness.url.clone())
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let budget_key = "freebird:graph-issuance:v1:budget:redis-v4-budget";
        let budget: HashMap<Vec<u8>, Vec<u8>> = redis::cmd("HGETALL")
            .arg(budget_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(
            budget.get(b"charged".as_slice()).map(Vec::as_slice),
            Some(b"1".as_slice())
        );
        assert_eq!(
            redis::cmd("GET")
                .arg(marker)
                .query_async::<_, Option<Vec<u8>>>(&mut connection)
                .await
                .unwrap()
                .as_deref(),
            Some(b"1".as_slice())
        );
        drop(connection);

        // Exact retries recover the stored response and do not re-charge the
        // budget or attempt to consume the global V4 marker again.
        assert!(matches!(
            reserve_for_test(&store, [1; 16], [1; 32], [2; 32], &policy, marker,)
                .await
                .unwrap(),
            ReserveOutcome::Existing(_)
        ));
        assert!(matches!(
            reserve_for_test(&store, [1; 16], [9; 32], [2; 32], &policy, marker,)
                .await
                .unwrap(),
            ReserveOutcome::Conflict
        ));
        assert!(matches!(
            reserve_for_test(&store, [1; 16], [1; 32], [9; 32], &policy, marker,)
                .await
                .unwrap(),
            ReserveOutcome::Conflict
        ));

        // A duplicate V4 marker is rejected even under a different policy and
        // operation, while a concurrent race has exactly one winner.
        let other_policy = GraphIssuancePolicy {
            issuance_policy_id: "redis-v4-policy-two".into(),
            budget_id: "redis-v4-budget-two".into(),
            ..policy.clone()
        };
        assert!(matches!(
            reserve_for_test(&store, [3; 16], [3; 32], [4; 32], &other_policy, marker,)
                .await
                .unwrap(),
            ReserveOutcome::AuthorizationUsed
        ));

        let race_marker = "freebird:spent:v4:redis-v4-race";
        let (race_a, race_b) = tokio::join!(
            reserve_for_test(&store, [4; 16], [4; 32], [5; 32], &policy, race_marker,),
            reserve_for_test(&store, [5; 16], [5; 32], [6; 32], &policy, race_marker,),
        );
        let race_outcomes = [race_a.unwrap(), race_b.unwrap()];
        assert_eq!(
            race_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ReserveOutcome::Created))
                .count(),
            1
        );

        // The first reservation plus the race winner consume the entire
        // independent issuance budget; the losing request never charges it.
        assert!(matches!(
            reserve_for_test(
                &store,
                [6; 16],
                [6; 32],
                [7; 32],
                &policy,
                "freebird:spent:v4:redis-v4-exhausted",
            )
            .await
            .unwrap(),
            ReserveOutcome::BudgetExhausted
        ));

        harness.restart().unwrap();
        let recovered = GraphIssuanceStore::new(&harness.url).unwrap();
        assert!(matches!(
            reserve_for_test(&recovered, [1; 16], [1; 32], [2; 32], &policy, marker,)
                .await
                .unwrap(),
            ReserveOutcome::Existing(_)
        ));
        let mut connection = redis::Client::open(harness.url.clone())
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let budget: HashMap<Vec<u8>, Vec<u8>> = redis::cmd("HGETALL")
            .arg(budget_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(
            budget.get(b"charged".as_slice()).map(Vec::as_slice),
            Some(b"2".as_slice())
        );
        assert!(redis::cmd("GET")
            .arg("freebird:spent:v4:redis-v4-exhausted")
            .query_async::<_, Option<Vec<u8>>>(&mut connection)
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn hmac_authorization_is_bound_and_nullified_without_persisting_secret() {
        let policy = GraphIssuancePolicy {
            issuance_policy_id: "bootstrap".into(),
            graph_id: "1".repeat(64),
            keyset_id: "2".repeat(64),
            descriptor_id: "3".repeat(64),
            budget_id: "budget".into(),
            budget_limit: 10,
            quantity: 1,
            admission_state: GraphIssuanceAdmissionState::AcceptingNew,
            authorization_scheme: "hmac_sha256".into(),
            v4_local: None,
        };
        let secret = vec![7; 32];
        let authorizer = HmacGraphIssuanceAuthorizer::new(secret.clone()).unwrap();
        let binding = [8; 32];
        let nonce = [9; 32];
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
        mac.update(AUTH_TAG_DOMAIN);
        mac.update(&(policy.issuance_policy_id.len() as u32).to_be_bytes());
        mac.update(policy.issuance_policy_id.as_bytes());
        mac.update(&binding);
        let mut authorization = nonce.to_vec();
        authorization.extend_from_slice(&mac.finalize().into_bytes());
        let authorization = Base64UrlUnpadded::encode_string(&authorization);
        let claim = authorizer
            .authorize(&policy, &binding, &authorization)
            .unwrap();
        assert_eq!(
            claim.nullifier_digest,
            domain_digest(NULLIFIER_DOMAIN, &nonce)
        );
        assert!(claim.global_spend_key.is_none());
        assert!(authorizer
            .authorize(&policy, &[0; 32], &authorization)
            .is_err());
    }

    #[test]
    fn v4_local_uses_shared_verification_and_never_logs_the_raw_credential() {
        let secret = [0x41; 32];
        let verifier_id = "verifier:test:v4-local";
        let audience = "graph";
        let issuer_id = "issuer:test:v4-local";
        let kid = "kid-v4-local";
        let scope = freebird_crypto::build_scope_digest(verifier_id, audience).unwrap();
        let input =
            freebird_crypto::build_private_token_input(issuer_id, kid, &[9; 32], &scope).unwrap();
        let server =
            freebird_crypto::Server::from_secret_key(secret, freebird_crypto::VOPRF_CONTEXT_V4)
                .unwrap();
        let token = freebird_crypto::RedemptionToken {
            nonce: [9; 32],
            scope_digest: scope,
            kid: kid.into(),
            issuer_id: issuer_id.into(),
            authenticator: server.evaluate_unblinded(&input).unwrap(),
        };
        let authorization = Base64UrlUnpadded::encode_string(
            &freebird_crypto::build_redemption_token(&token).unwrap(),
        );
        let policy = GraphIssuancePolicy {
            issuance_policy_id: "v4-policy".into(),
            graph_id: "1".repeat(64),
            keyset_id: "2".repeat(64),
            descriptor_id: "3".repeat(64),
            budget_id: "v4-budget".into(),
            budget_limit: 10,
            quantity: 1,
            admission_state: GraphIssuanceAdmissionState::AcceptingNew,
            authorization_scheme: "v4_local".into(),
            v4_local: Some(GraphIssuanceV4LocalPolicy {
                verifier_id: verifier_id.into(),
                audience: audience.into(),
                trusted_issuers: vec![GraphIssuanceV4TrustedIssuer {
                    issuer_id: issuer_id.into(),
                    key_ids: vec![kid.into()],
                }],
            }),
        };
        let authorizer = V4LocalGraphIssuanceAuthorizer::new(vec![
            crate::config::GraphIssuanceV4VerificationKey {
                issuer_id: issuer_id.into(),
                kid: kid.into(),
                secret_key: secret,
            },
        ])
        .unwrap();
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let claim = tracing::subscriber::with_default(subscriber, || {
            authorizer.authorize(&policy, &[0; 32], &authorization)
        })
        .unwrap();
        assert_eq!(
            claim.global_spend_key,
            Some(v4_spend_key_for_test(&token, verifier_id, audience))
        );
        let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(!logs.contains(&authorization));
    }

    fn v4_spend_key_for_test(
        token: &freebird_crypto::RedemptionToken,
        verifier_id: &str,
        audience: &str,
    ) -> String {
        let nullifier = freebird_crypto::nullifier_key_v4(token, verifier_id, audience).unwrap();
        freebird_common::spend_key::v4_spend_key(&nullifier)
    }
}
