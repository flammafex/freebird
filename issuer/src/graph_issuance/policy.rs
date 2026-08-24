// SPDX-License-Identifier: Apache-2.0 OR MIT
//! V7 graph-issuance authorization policy structures.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GraphIssuanceAdmissionState {
    AcceptingNew,
    RecoveryOnly,
    Disabled,
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

impl GraphIssuancePolicy {
    pub fn validate(&self) -> Result<()> {
        if !bounded(&self.issuance_policy_id)
            || !bounded(&self.graph_id)
            || !bounded(&self.keyset_id)
            || !bounded(&self.descriptor_id)
            || !bounded(&self.budget_id)
            || self.budget_limit == 0
            || self.budget_limit > freebird_common::api::EXCHANGE_MAX_BUDGET_LIMIT
            || self.quantity != 1
            || u64::from(self.quantity) > self.budget_limit
            || self.authorization_scheme != "v4_local"
        {
            bail!("invalid native V7 graph issuance policy")
        }
        match (&self.authorization_scheme[..], &self.v4_local) {
            ("v4_local", Some(policy)) => validate_v4_local_policy(policy),
            ("v4_local", None) => bail!("V4-local graph policy is incomplete"),
            (_, Some(_)) => bail!("non-V4 graph policy contains V4 configuration"),
            (_, None) => Ok(()),
        }
    }
}

fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.is_ascii()
}

pub(super) fn validate_v4_local_policy(policy: &GraphIssuanceV4LocalPolicy) -> Result<()> {
    if policy.verifier_id.is_empty()
        || policy.verifier_id.len() > 255
        || policy.audience.is_empty()
        || policy.audience.len() > 255
        || policy.trusted_issuers.is_empty()
        || policy.trusted_issuers.len() > 64
        || freebird_crypto::build_scope_digest(&policy.verifier_id, &policy.audience).is_err()
    {
        bail!("invalid V4-local graph issuance scope")
    }
    for issuer in &policy.trusted_issuers {
        if issuer.issuer_id.is_empty()
            || issuer.issuer_id.len() > 255
            || issuer.key_ids.is_empty()
            || issuer.key_ids.len() > 64
        {
            bail!("invalid V4-local trusted issuer")
        }
    }
    Ok(())
}
