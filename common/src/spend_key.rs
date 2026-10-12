// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Shared Redis spend-key construction.
//!
//! Keep this deliberately boring: changing the returned bytes changes the
//! replay namespace shared by issuers and verifiers.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_marker_is_global_and_non_policy_scoped() {
        assert_eq!(v4_spend_key("abc"), "freebird:spent:v4:abc");
    }
}
