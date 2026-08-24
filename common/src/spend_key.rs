// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Shared Redis spend-key construction.
//!
//! Keep this deliberately boring: changing the returned bytes changes the
//! replay namespace shared by issuers and verifiers.

/// Redis namespace for native V7 source-artifact spends.
pub const V7_SPEND_KEY_PREFIX: &str = "freebird:spent:v7:";
/// Redis namespace for non-expiring V4 private-token spends.
pub const V4_SPEND_KEY_PREFIX: &str = "freebird:spent:v4:";

/// Construct the canonical global V4 replay marker used by all verifiers and
/// local graph issuance. It is deliberately not policy-namespaced.
pub fn v4_spend_key(nullifier: &str) -> String {
    let mut key = String::with_capacity(V4_SPEND_KEY_PREFIX.len() + nullifier.len());
    key.push_str(V4_SPEND_KEY_PREFIX);
    key.push_str(nullifier);
    key
}

/// Construct the canonical global V7 replay marker from the issuer/federation
/// namespace and body nullifier.
///
/// The tuple is the complete V7 spend identity. Policy, keyset, graph,
/// profile, and artifact-digest identifiers must never be included in this key.
pub fn v7_spend_key(issuer_or_federation_id: &str, body_nullifier: &str) -> String {
    let mut key = String::with_capacity(
        V7_SPEND_KEY_PREFIX.len() + issuer_or_federation_id.len() + 1 + body_nullifier.len(),
    );
    key.push_str(V7_SPEND_KEY_PREFIX);
    key.push_str(issuer_or_federation_id);
    key.push(':');
    key.push_str(body_nullifier);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_marker_is_global_and_non_policy_scoped() {
        assert_eq!(v4_spend_key("abc"), "freebird:spent:v4:abc");
    }

    #[test]
    fn v7_marker_uses_only_the_issuer_and_body_nullifier() {
        assert_eq!(
            v7_spend_key("issuer:test", "abc"),
            "freebird:spent:v7:issuer:test:abc"
        );
    }
}
