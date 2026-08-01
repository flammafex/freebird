// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Policy-authorized blind initial issuance into V2 graph keysets.

mod authorizer;
mod engine;
mod policy;
mod store;

pub use authorizer::{
    validate_configured_authorizer, AuthorizationClaim, DevelopmentMockAuthorizer,
    DisabledGraphIssuanceAuthorizer, GraphIssuanceAuthorizer, HmacGraphIssuanceAuthorizer,
    V4LocalGraphIssuanceAuthorizer,
};
pub use engine::{
    validate_runtime_graph_issuance_signers, GraphIssuanceEngine, ProcessDecision, StatusDecision,
};
pub use policy::{
    GraphIssuanceAdmissionState, GraphIssuancePolicy, GraphIssuancePolicyDocument,
    GraphIssuanceV4LocalPolicy, GraphIssuanceV4TrustedIssuer, POLICY_DOCUMENT_VERSION,
};
pub use store::{GraphIssuanceStore, REPLAY_AUTHORITY_ID_KEY};

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) const REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY: &str =
        super::store::REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY;

    pub(crate) fn status_digest(capability: &[u8; 32]) -> [u8; 32] {
        super::store::status_digest(capability)
    }

    pub(crate) fn policy_digest(policy: &super::policy::GraphIssuancePolicy) -> [u8; 32] {
        super::policy::policy_digest(policy)
    }

    pub(crate) fn operation_key(operation_id: &[u8; 16]) -> String {
        super::store::GraphIssuanceStore::operation_key(operation_id)
    }

    pub(crate) fn no_global_spend_key(operation_id: &[u8; 16]) -> String {
        super::store::GraphIssuanceStore::no_global_spend_key(operation_id)
    }
}

#[cfg(test)]
#[path = "graph_issuance/tests.rs"]
mod tests;
