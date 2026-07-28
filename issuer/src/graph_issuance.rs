// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Policy-authorized blind initial issuance into V2 graph keysets.

use crate::exchange::{profiles::ExchangeProfileV2, source_v5::PinnedTargetSignersV2};
use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::{
    api::{
        ExchangeAdmissionStateV2 as DiscoveryAdmissionState, GraphIssuanceDiscoveryV2,
        GraphIssuancePolicyDiscoveryV2, GraphIssuanceReplayAuthorityDiscoveryV1,
    },
    graph_issuance_api::{
        self, GraphIssuanceRequestV2, GraphIssuanceResultV2, ReplayAuthorityProbeV1,
        GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL, GRAPH_ISSUANCE_QUANTITY, GRAPH_ISSUANCE_VERSION_V2,
        MAX_BLINDED_MESSAGE,
    },
};
use rand::RngCore;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const PREFIX: &str = "freebird:graph-issuance:v2:";
const STATUS_DOMAIN: &[u8] = b"freebird graph issuance status capability v2\0";
const NULLIFIER_DOMAIN: &[u8] = b"freebird graph issuance authorization nullifier v1\0";
const POLICY_DOMAIN: &[u8] = b"freebird graph issuance policy v2\0";
pub const POLICY_DOCUMENT_VERSION: &str = "freebird/graph-blind-issuance-policy/v2";

pub const REPLAY_AUTHORITY_ID_KEY: &str = "freebird:v4-replay-authority:v1:id";
const REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY: &str =
    "freebird:v4-replay-authority:v1:scope-tombstones";
const REPLAY_AUTHORITY_PROBE_PREFIX: &str = "freebird:v4-replay-authority:v1:probe:";
const REPLAY_AUTHORITY_ACK_PREFIX: &str = "freebird:v4-replay-authority:v1:ack:";
const REPLAY_AUTHORITY_PROBE_TTL_SECS: u64 = 30;

const RESERVE: &str = r#"
local op=KEYS[1]
if redis.call('EXISTS',op)==1 then
  if redis.call('HGET',op,'request_digest')~=ARGV[1] then return 2 end
  if redis.call('HGET',op,'status_capability_digest')~=ARGV[2] then return 3 end
  return 1
end
local time_reply=redis.call('TIME')
if type(time_reply)~='table' or not time_reply[1] or not tonumber(time_reply[1]) then return 7 end
local now=tonumber(time_reply[1])
local descriptor_first=tonumber(ARGV[16]); local descriptor_last=tonumber(ARGV[17])
if not descriptor_first or not descriptor_last or descriptor_first>descriptor_last or
   now<descriptor_first or now>descriptor_last then return 7 end
local auth=KEYS[2]; local budget=KEYS[3]; local global_spend=KEYS[4]
local uses_global_spend=ARGV[15]=='1'
if uses_global_spend then
  if redis.call('EXISTS',global_spend)==1 then return 4 end
elseif redis.call('EXISTS',auth)==1 then return 4 end
if not string.match(ARGV[11],'^[0-9]+$') or not string.match(ARGV[12],'^[0-9]+$') then return 6 end
local quantity=tonumber(ARGV[11]); local limit=tonumber(ARGV[12])
if not quantity or not limit or quantity~=1 or limit<1 then return 6 end
local budget_type=redis.call('TYPE',budget)['ok']
if budget_type~='none' and budget_type~='hash' then return 5 end
local charged=0
if budget_type=='hash' then
  if redis.call('HGET',budget,'policy_digest')~=ARGV[10] or
     redis.call('HGET',budget,'policy_id')~=ARGV[3] or
     redis.call('HGET',budget,'limit')~=ARGV[12] or
     redis.call('HGET',budget,'charge_kind')~='issuance_quantity' then return 5 end
  local charged_raw=redis.call('HGET',budget,'charged')
  if not charged_raw or not string.match(charged_raw,'^[0-9]+$') then return 5 end
  charged=tonumber(charged_raw)
  if not charged or charged<0 or charged>limit then return 5 end
end
if quantity>limit-charged then return 6 end
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

// The authority identity check and challenge consumption are one Redis
// operation. A changed/deleted authority can therefore never consume a
// probe challenge.
const REPLAY_AUTHORITY_PROBE: &str = r#"
local authority=redis.call('GET',KEYS[1])
if redis.call('TTL',KEYS[1])~=-1 or not authority or string.len(authority)~=32 or authority~=ARGV[1] then
  return {1,''}
end
local challenge=redis.call('GETDEL',KEYS[2])
if not challenge then return {2,''} end
return {0,challenge}
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
                || policy.quantity != GRAPH_ISSUANCE_QUANTITY
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

    pub fn discovery(
        &self,
        authority_id: &str,
        v4_scope_digest_tombstones: &[String],
    ) -> GraphIssuanceDiscoveryV2 {
        GraphIssuanceDiscoveryV2 {
            version: GRAPH_ISSUANCE_VERSION_V2,
            policies: self
                .policies
                .iter()
                .map(|policy| GraphIssuancePolicyDiscoveryV2 {
                    issuance_policy_id: policy.issuance_policy_id.clone(),
                    graph_id: policy.graph_id.clone(),
                    keyset_id: policy.keyset_id.clone(),
                    descriptor_id: policy.descriptor_id.clone(),
                    budget_id: policy.budget_id.clone(),
                    budget_limit: policy.budget_limit,
                    quantity: policy.quantity,
                    admission_state: policy.admission_state.discovery(),
                    authorization_scheme: policy.authorization_scheme.clone(),
                    authorization_scope_digest_b64: policy
                        .v4_local
                        .as_ref()
                        .and_then(|v4| {
                            freebird_crypto::build_scope_digest(&v4.verifier_id, &v4.audience).ok()
                        })
                        .map(|scope| Base64UrlUnpadded::encode_string(&scope)),
                })
                .collect(),
            replay_authority: GraphIssuanceReplayAuthorityDiscoveryV1 {
                authority_id: authority_id.into(),
                v4_scope_digest_tombstones: v4_scope_digest_tombstones.to_vec(),
            },
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
        let nonce = graph_issuance_api::verify_hmac_authorization_v2(
            &self.secret,
            &policy.issuance_policy_id,
            request_binding,
            authorization,
        )
        .map_err(|_| anyhow::anyhow!("invalid graph issuance authorization"))?;
        Ok(AuthorizationClaim {
            nullifier_digest: domain_digest(NULLIFIER_DOMAIN, &nonce),
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

/// Keeps the durable authority and recovery/probe surface available while
/// fresh graph issuance is disabled by configuration.
pub struct DisabledGraphIssuanceAuthorizer;

impl GraphIssuanceAuthorizer for DisabledGraphIssuanceAuthorizer {
    fn authorize(
        &self,
        _policy: &GraphIssuancePolicy,
        _request_binding: &[u8; 32],
        _authorization: &str,
    ) -> Result<AuthorizationClaim> {
        bail!("graph issuance authorization is disabled")
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
        crate::config::GraphIssuanceAuthorizationConfig::V4Local { keys } => (
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
pub struct GraphIssuanceStore {
    client: redis::Client,
}

#[derive(Debug)]
struct StoredOperation {
    request_digest: [u8; 32],
    status_capability_digest: [u8; 32],
    issuance_policy_id: String,
    graph_id: String,
    keyset_id: String,
    descriptor_id: String,
    signer_key_id: String,
    quantity: u32,
    response: Vec<u8>,
}

enum ReserveOutcome {
    Created,
    Existing(Box<StoredOperation>),
    Conflict,
    AuthorizationUsed,
    PolicyConflict,
    BudgetExhausted,
    DescriptorWindow,
}

impl GraphIssuanceStore {
    pub fn new(redis_url: &str) -> Result<Self> {
        Ok(Self {
            client: redis::Client::open(redis_url)?,
        })
    }

    async fn connection(&self) -> Result<redis::aio::Connection> {
        Ok(self.client.get_async_connection().await?)
    }

    pub async fn redis_time(&self) -> Result<i64> {
        let mut connection = self.connection().await?;
        let reply: Vec<String> = redis::cmd("TIME")
            .query_async(&mut connection)
            .await
            .context("invalid Redis TIME reply")?;
        let seconds = reply
            .first()
            .context("Redis TIME omitted seconds")?
            .parse::<i64>()
            .context("Redis TIME seconds are invalid")?;
        let micros = reply
            .get(1)
            .context("Redis TIME omitted microseconds")?
            .parse::<u32>()
            .context("Redis TIME microseconds are invalid")?;
        if reply.len() != 2 || micros >= 1_000_000 || seconds < 0 {
            bail!("Redis TIME descriptor validity reply is invalid")
        }
        Ok(seconds)
    }

    pub async fn initialize_replay_authority(
        &self,
        scopes: &[[u8; 32]],
    ) -> Result<([u8; 32], Vec<[u8; 32]>)> {
        let mut connection = self.connection().await?;
        let authority_type: String = redis::cmd("TYPE")
            .arg(REPLAY_AUTHORITY_ID_KEY)
            .query_async(&mut connection)
            .await?;
        if authority_type != "none" && authority_type != "string" {
            bail!("replay authority identity has an invalid Redis type")
        }
        if authority_type == "string" {
            let ttl: i64 = redis::cmd("TTL")
                .arg(REPLAY_AUTHORITY_ID_KEY)
                .query_async(&mut connection)
                .await?;
            if ttl != -1 {
                bail!("replay authority identity must not expire")
            }
        }
        let _authority = if authority_type == "none" {
            let mut generated = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut generated);
            let created: Option<String> = redis::cmd("SET")
                .arg(REPLAY_AUTHORITY_ID_KEY)
                .arg(generated.as_slice())
                .arg("NX")
                .query_async(&mut connection)
                .await?;
            if created.is_some() {
                generated
            } else {
                let value: Vec<u8> = redis::cmd("GET")
                    .arg(REPLAY_AUTHORITY_ID_KEY)
                    .query_async(&mut connection)
                    .await?;
                value
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("replay authority identity is not 32 bytes"))?
            }
        } else {
            let value: Vec<u8> = redis::cmd("GET")
                .arg(REPLAY_AUTHORITY_ID_KEY)
                .query_async(&mut connection)
                .await?;
            value
                .try_into()
                .map_err(|_| anyhow::anyhow!("replay authority identity is not 32 bytes"))?
        };

        let tombstone_type: String = redis::cmd("TYPE")
            .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
            .query_async(&mut connection)
            .await?;
        if tombstone_type != "none" && tombstone_type != "hash" {
            bail!("replay authority scope tombstones have an invalid Redis type")
        }
        if tombstone_type == "hash" {
            let ttl: i64 = redis::cmd("TTL")
                .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
                .query_async(&mut connection)
                .await?;
            if ttl != -1 {
                bail!("replay authority scope tombstones must not expire")
            }
        }
        let existing: HashMap<Vec<u8>, Vec<u8>> = if tombstone_type == "hash" {
            redis::cmd("HGETALL")
                .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
                .query_async(&mut connection)
                .await?
        } else {
            HashMap::new()
        };
        let mut retained = Vec::with_capacity(existing.len() + scopes.len());
        for (field, value) in existing {
            let field_text = String::from_utf8(field).context("invalid scope tombstone field")?;
            let raw: [u8; 32] = hex::decode(&field_text)
                .context("invalid scope tombstone encoding")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("scope tombstone is not 32 bytes"))?;
            if hex::encode(raw) != field_text {
                bail!("scope tombstone encoding is not canonical")
            }
            if value.as_slice() != raw.as_slice() {
                bail!("scope tombstone value does not match its identity")
            }
            retained.push(raw);
        }
        for scope in scopes {
            if !retained.contains(scope) {
                retained.push(*scope);
            }
        }
        retained.sort_unstable();
        retained.dedup();
        if retained.len() > freebird_common::exchange_api::MAX_ITEMS {
            bail!("too many replay authority scope tombstones")
        }
        for scope in &retained {
            redis::cmd("HSET")
                .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
                .arg(hex::encode(scope))
                .arg(scope.as_slice())
                .query_async::<_, i64>(&mut connection)
                .await?;
        }
        drop(connection);
        self.read_replay_authority_state().await
    }

    /// Read and validate the complete durable replay-authority container.
    /// Callers must use this rather than a startup snapshot when publishing
    /// discovery or determining readiness.
    pub async fn read_replay_authority_state(&self) -> Result<([u8; 32], Vec<[u8; 32]>)> {
        let mut connection = self.connection().await?;
        let authority_type: String = redis::cmd("TYPE")
            .arg(REPLAY_AUTHORITY_ID_KEY)
            .query_async(&mut connection)
            .await?;
        if authority_type != "string" {
            bail!("replay authority identity is missing or has an invalid Redis type")
        }
        let authority_ttl: i64 = redis::cmd("TTL")
            .arg(REPLAY_AUTHORITY_ID_KEY)
            .query_async(&mut connection)
            .await?;
        if authority_ttl != -1 {
            bail!("replay authority identity must not expire")
        }
        let authority: [u8; 32] = {
            let value: Vec<u8> = redis::cmd("GET")
                .arg(REPLAY_AUTHORITY_ID_KEY)
                .query_async(&mut connection)
                .await?;
            value
                .try_into()
                .map_err(|_| anyhow::anyhow!("replay authority identity is not 32 bytes"))?
        };
        let tombstone_type: String = redis::cmd("TYPE")
            .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
            .query_async(&mut connection)
            .await?;
        if tombstone_type != "none" && tombstone_type != "hash" {
            bail!("replay authority scope tombstones have an invalid Redis type")
        }
        if tombstone_type == "hash" {
            let tombstone_ttl: i64 = redis::cmd("TTL")
                .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
                .query_async(&mut connection)
                .await?;
            if tombstone_ttl != -1 {
                bail!("replay authority scope tombstones must not expire")
            }
        }
        let existing: HashMap<Vec<u8>, Vec<u8>> = if tombstone_type == "hash" {
            redis::cmd("HGETALL")
                .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
                .query_async(&mut connection)
                .await?
        } else {
            HashMap::new()
        };
        if existing.len() > freebird_common::exchange_api::MAX_ITEMS {
            bail!("too many replay authority scope tombstones")
        }
        let mut tombstones = Vec::with_capacity(existing.len());
        for (field, value) in existing {
            let field_text = String::from_utf8(field).context("invalid scope tombstone field")?;
            let scope: [u8; 32] = hex::decode(&field_text)
                .context("invalid scope tombstone encoding")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("scope tombstone is not 32 bytes"))?;
            if hex::encode(scope) != field_text || value.as_slice() != scope.as_slice() {
                bail!("invalid replay authority scope tombstone")
            }
            tombstones.push(scope);
        }
        tombstones.sort_unstable();
        Ok((authority, tombstones))
    }

    pub fn probe_key(probe_id: &[u8; 32]) -> String {
        format!("{REPLAY_AUTHORITY_PROBE_PREFIX}{}", hex::encode(probe_id))
    }

    pub fn ack_key(probe_id: &[u8; 32]) -> String {
        format!("{REPLAY_AUTHORITY_ACK_PREFIX}{}", hex::encode(probe_id))
    }

    pub async fn replay_authority_probe(
        &self,
        probe: &ReplayAuthorityProbeV1,
        issuer_id: &str,
    ) -> Result<Option<[u8; 32]>> {
        let authority = probe.authority_id()?;
        let probe_id = probe.probe_id()?;
        let mut connection = self.connection().await?;
        let (code, challenge): (i64, Vec<u8>) = redis::Script::new(REPLAY_AUTHORITY_PROBE)
            .key(REPLAY_AUTHORITY_ID_KEY)
            .key(Self::probe_key(&probe_id))
            .arg(authority.as_slice())
            .invoke_async(&mut connection)
            .await?;
        if code == 1 {
            bail!("replay authority selector mismatch")
        }
        if code == 2 {
            return Ok(None);
        }
        if code != 0 {
            bail!("invalid replay authority probe result")
        }
        let challenge: [u8; 32] = challenge
            .try_into()
            .map_err(|_| anyhow::anyhow!("replay authority challenge is not 32 bytes"))?;
        let proof = graph_issuance_api::replay_authority_proof_v1(
            &challenge, &authority, &probe_id, issuer_id,
        )?;
        let ack: Option<String> = redis::cmd("SET")
            .arg(Self::ack_key(&probe_id))
            .arg(proof.as_slice())
            .arg("NX")
            .arg("EX")
            .arg(REPLAY_AUTHORITY_PROBE_TTL_SECS)
            .query_async(&mut connection)
            .await?;
        if ack.is_none() {
            bail!("replay authority acknowledgement already exists")
        }
        Ok(Some(proof))
    }

    fn operation_key(operation_id: &[u8; 16]) -> String {
        format!("{PREFIX}op:{}", hex::encode(operation_id))
    }

    async fn get(&self, operation_id: &[u8; 16]) -> Result<Option<StoredOperation>> {
        let mut connection = self.connection().await?;
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
            issuance_policy_id: String::from_utf8(required(b"issuance_policy_id")?)?,
            graph_id: String::from_utf8(required(b"graph_id")?)?,
            keyset_id: String::from_utf8(required(b"keyset_id")?)?,
            descriptor_id: String::from_utf8(required(b"descriptor_id")?)?,
            signer_key_id: String::from_utf8(required(b"signer_key_id")?)?,
            quantity: String::from_utf8(required(b"quantity")?)?.parse()?,
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
        descriptor_valid_from: i64,
        descriptor_valid_until: i64,
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
        let mut connection = self.connection().await?;
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
            .arg(descriptor_valid_from)
            .arg(descriptor_valid_until)
            .invoke_async(&mut connection)
            .await?;
        Ok(match code {
            0 => ReserveOutcome::Created,
            1 => ReserveOutcome::Existing(Box::new(
                self.get(operation_id)
                    .await?
                    .context("existing graph issuance operation disappeared")?,
            )),
            2 | 3 => ReserveOutcome::Conflict,
            4 => ReserveOutcome::AuthorizationUsed,
            5 => ReserveOutcome::PolicyConflict,
            6 => ReserveOutcome::BudgetExhausted,
            7 => ReserveOutcome::DescriptorWindow,
            _ => bail!("invalid graph issuance reservation result"),
        })
    }
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

    #[tokio::test]
    async fn replay_authority_identity_probe_and_tombstones_are_durable() {
        let Some(harness) = RedisHarness::start_if_available().unwrap() else {
            return;
        };
        let store = GraphIssuanceStore::new(&harness.url).unwrap();
        let first_scope = [7u8; 32];
        let (authority, tombstones) = store
            .initialize_replay_authority(&[first_scope])
            .await
            .unwrap();
        assert_eq!(authority.len(), 32);
        assert_eq!(tombstones, vec![first_scope]);
        let (same_authority, tombstones) = store
            .initialize_replay_authority(&[[8u8; 32]])
            .await
            .unwrap();
        assert_eq!(same_authority, authority);
        assert_eq!(tombstones.len(), 2);
        let (durable_authority, durable_tombstones) =
            store.read_replay_authority_state().await.unwrap();
        assert_eq!(durable_authority, authority);
        assert_eq!(durable_tombstones.len(), 2);

        let probe_id = [9u8; 32];
        let challenge = [10u8; 32];
        let mut connection = redis::Client::open(harness.url.clone())
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let _: String = redis::cmd("SET")
            .arg(GraphIssuanceStore::probe_key(&probe_id))
            .arg(challenge.as_slice())
            .arg("NX")
            .arg("EX")
            .arg(REPLAY_AUTHORITY_PROBE_TTL_SECS)
            .query_async(&mut connection)
            .await
            .unwrap();
        drop(connection);

        let probe = ReplayAuthorityProbeV1 {
            version: freebird_common::graph_issuance_api::REPLAY_AUTHORITY_VERSION_V1,
            authority_id: Base64UrlUnpadded::encode_string(&authority),
            probe_id: Base64UrlUnpadded::encode_string(&probe_id),
        };
        let proof = store
            .replay_authority_probe(&probe, "issuer:test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            proof,
            graph_issuance_api::replay_authority_proof_v1(
                &challenge,
                &authority,
                &probe_id,
                "issuer:test"
            )
            .unwrap()
        );
        assert!(store
            .replay_authority_probe(&probe, "issuer:test")
            .await
            .unwrap()
            .is_none());
        let mut connection = redis::Client::open(harness.url.clone())
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let _: i64 = redis::cmd("DEL")
            .arg(REPLAY_AUTHORITY_ID_KEY)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(store.read_replay_authority_state().await.is_err());
        let _: String = redis::cmd("SET")
            .arg(REPLAY_AUTHORITY_ID_KEY)
            .arg(authority.as_slice())
            .query_async(&mut connection)
            .await
            .unwrap();
        let ack: Vec<u8> = redis::cmd("GETDEL")
            .arg(GraphIssuanceStore::ack_key(&probe_id))
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(ack, proof);

        let replacement_challenge = [12u8; 32];
        let _: String = redis::cmd("SET")
            .arg(REPLAY_AUTHORITY_ID_KEY)
            .arg([11u8; 32].as_slice())
            .query_async(&mut connection)
            .await
            .unwrap();
        let _: String = redis::cmd("SET")
            .arg(GraphIssuanceStore::probe_key(&probe_id))
            .arg(replacement_challenge.as_slice())
            .arg("EX")
            .arg(REPLAY_AUTHORITY_PROBE_TTL_SECS)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(store
            .replay_authority_probe(&probe, "issuer:test")
            .await
            .is_err());
        let retained_challenge: Vec<u8> = redis::cmd("GET")
            .arg(GraphIssuanceStore::probe_key(&probe_id))
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(retained_challenge, replacement_challenge);
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
                1,
                i64::MAX,
            )
            .await
    }

    #[tokio::test]
    async fn malformed_budget_charge_is_rejected_without_any_mutation() {
        let Some(harness) = RedisHarness::start_if_available().unwrap() else {
            return;
        };
        let store = GraphIssuanceStore::new(&harness.url).unwrap();
        let policy = redis_policy("malformed-budget", 10);
        let budget_key = format!("{PREFIX}budget:{}", policy.budget_id);
        let digest = policy_digest(&policy);
        let mut connection = redis::Client::open(harness.url.clone())
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let _: i64 = redis::cmd("HSET")
            .arg(&budget_key)
            .arg("policy_id")
            .arg(&policy.issuance_policy_id)
            .arg("policy_digest")
            .arg(digest.as_slice())
            .arg("limit")
            .arg(policy.budget_limit)
            .arg("charge_kind")
            .arg("issuance_quantity")
            .arg("charged")
            .arg("0")
            .query_async(&mut connection)
            .await
            .unwrap();
        drop(connection);

        for (index, malformed) in ["1.5", "-1"].into_iter().enumerate() {
            let mut connection = redis::Client::open(harness.url.clone())
                .unwrap()
                .get_async_connection()
                .await
                .unwrap();
            let _: i64 = redis::cmd("HSET")
                .arg(&budget_key)
                .arg("charged")
                .arg(malformed)
                .query_async(&mut connection)
                .await
                .unwrap();
            drop(connection);

            let operation = [20 + index as u8; 16];
            let marker = format!("{PREFIX}malformed-marker-{index}");
            assert!(matches!(
                reserve_for_test(
                    &store,
                    operation,
                    [30 + index as u8; 32],
                    [40 + index as u8; 32],
                    &policy,
                    &marker,
                )
                .await
                .unwrap(),
                ReserveOutcome::PolicyConflict
            ));
            let mut connection = redis::Client::open(harness.url.clone())
                .unwrap()
                .get_async_connection()
                .await
                .unwrap();
            let operation_value: i64 = redis::cmd("EXISTS")
                .arg(GraphIssuanceStore::operation_key(&operation))
                .query_async(&mut connection)
                .await
                .unwrap();
            assert_eq!(operation_value, 0);
            let marker_value: Option<Vec<u8>> = redis::cmd("GET")
                .arg(&marker)
                .query_async(&mut connection)
                .await
                .unwrap();
            assert!(marker_value.is_none());
            let stored: Vec<u8> = redis::cmd("HGET")
                .arg(&budget_key)
                .arg("charged")
                .query_async(&mut connection)
                .await
                .unwrap();
            assert_eq!(stored, malformed.as_bytes());
        }
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
        let budget_key = "freebird:graph-issuance:v2:budget:redis-v4-budget";
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
        let authorization = graph_issuance_api::build_hmac_authorization_v2(
            &secret,
            &nonce,
            &policy.issuance_policy_id,
            &binding,
        )
        .unwrap();
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
        let mut tampered = Base64UrlUnpadded::decode_vec(&authorization).unwrap();
        tampered[0] ^= 1;
        assert!(authorizer
            .authorize(
                &policy,
                &binding,
                &Base64UrlUnpadded::encode_string(&tampered)
            )
            .is_err());
    }

    #[test]
    fn issuer_rejects_quantity_and_digest_mutations_in_v2_results() {
        let request = graph_issuance_api::GraphIssuanceRequestV2 {
            version: GRAPH_ISSUANCE_VERSION_V2,
            public_operation_id: Base64UrlUnpadded::encode_string(&[1; 16]),
            issuance_policy_id: "policy".into(),
            graph_id: "1".repeat(64),
            keyset_id: "2".repeat(64),
            descriptor_id: "3".repeat(64),
            blinded_message: Base64UrlUnpadded::encode_string(&[4; 32]),
            authorization: Base64UrlUnpadded::encode_string(&[5; 32]),
        };
        let mut result = GraphIssuanceResultV2 {
            version: GRAPH_ISSUANCE_VERSION_V2,
            public_operation_id: request.public_operation_id.clone(),
            issuance_policy_id: request.issuance_policy_id.clone(),
            graph_id: request.graph_id.clone(),
            keyset_id: request.keyset_id.clone(),
            descriptor_id: request.descriptor_id.clone(),
            token_key_id: "a".repeat(64),
            quantity: 1,
            request_digest: Base64UrlUnpadded::encode_string(&request.request_digest().unwrap()),
            blind_signature: Base64UrlUnpadded::encode_string(&[6; 32]),
            result_digest: String::new(),
        };
        result.result_digest =
            Base64UrlUnpadded::encode_string(&result.calculated_result_digest().unwrap());
        assert!(result.validate_against(&request, &"a".repeat(64)).is_ok());
        result.quantity = 2;
        assert!(result.validate_against(&request, &"a".repeat(64)).is_err());
        result.quantity = 1;
        result.result_digest = Base64UrlUnpadded::encode_string(&[0; 32]);
        assert!(result.validate_against(&request, &"a".repeat(64)).is_err());
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
