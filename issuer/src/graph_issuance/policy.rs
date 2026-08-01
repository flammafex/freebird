// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Graph issuance policy documents and canonical policy digests.

use crate::exchange::profiles::ExchangeProfileV2;
use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::{
    api::{
        ExchangeAdmissionStateV2 as DiscoveryAdmissionState, GraphIssuanceDiscoveryV2,
        GraphIssuancePolicyDiscoveryV2, GraphIssuanceReplayAuthorityDiscoveryV1,
    },
    graph_issuance_api::{GRAPH_ISSUANCE_QUANTITY, GRAPH_ISSUANCE_VERSION_V2},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

const POLICY_DOMAIN: &[u8] = b"freebird graph issuance policy v2\0";
pub const POLICY_DOCUMENT_VERSION: &str = "freebird/graph-blind-issuance-policy/v2";

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

pub(super) fn validate_v4_local_policy(policy: &GraphIssuanceV4LocalPolicy) -> Result<()> {
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

pub(super) fn policy_digest(policy: &GraphIssuancePolicy) -> [u8; 32] {
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
    let mut hash = Sha256::new();
    hash.update(POLICY_DOMAIN);
    hash.update(&bytes);
    hash.finalize().into()
}
