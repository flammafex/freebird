// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use crate::config::Config;
use anyhow::bail;
use tracing::warn;

pub(super) fn run(config: &mut Config) -> anyhow::Result<String> {
    if config.key_config.hsm.is_some() {
        bail!(crate::config::HSM_ENABLE_UNSUPPORTED_MESSAGE);
    }
    if config.sybil_config.progressive_trust_salt == "default-salt-change-in-production" {
        bail!("Insecure default salt detected for SYBIL_PROGRESSIVE_TRUST_SALT");
    }
    if config.sybil_config.proof_of_diversity_fingerprint_salt
        == "default-salt-change-in-production"
    {
        bail!("Insecure default salt detected for SYBIL_PROOF_OF_DIVERSITY_SALT");
    }
    if config.sybil_config.multi_party_vouching_salt == "default-salt-change-in-production" {
        bail!("Insecure default salt detected for SYBIL_MULTI_PARTY_VOUCHING_SALT");
    }
    if config.allow_unsafe_v4_rotation {
        warn!(
            target: "freebird_issuer::startup",
            "UNSAFE V4 admin key rotation is enabled; development only"
        );
    } else {
        warn!(
            target: "freebird_issuer::startup",
            "V4 admin key rotation is disabled (development override required)"
        );
    }

    take_admin_api_key(&mut config.admin_api_key)
}

fn take_admin_api_key(admin_api_key: &mut Option<String>) -> anyhow::Result<String> {
    match admin_api_key.take() {
        Some(key) if key.len() >= 32 => Ok(key),
        Some(key) => bail!(
            "ADMIN_API_KEY must be at least 32 characters, got {}",
            key.len()
        ),
        None => bail!("ADMIN_API_KEY must be set (minimum 32 characters)"),
    }
}

#[cfg(test)]
mod tests {
    use super::take_admin_api_key;

    #[test]
    fn valid_take_clears_source() {
        let mut source = Some("a".repeat(32));

        let key = take_admin_api_key(&mut source).expect("valid key should be taken");

        assert_eq!(key, "a".repeat(32));
        assert!(source.is_none());
    }

    #[test]
    fn second_take_yields_missing_key_error() {
        let mut source = Some("a".repeat(32));

        take_admin_api_key(&mut source).expect("first take should succeed");
        let error = take_admin_api_key(&mut source).expect_err("second take should fail");

        assert_eq!(
            error.to_string(),
            "ADMIN_API_KEY must be set (minimum 32 characters)"
        );
    }

    #[test]
    fn short_key_is_consumed_and_error_only_includes_byte_length() {
        let secret = "short-secret-sentinel";
        let mut source = Some(secret.to_owned());

        let error = take_admin_api_key(&mut source).expect_err("short key should fail");

        assert!(source.is_none());
        assert_eq!(
            error.to_string(),
            "ADMIN_API_KEY must be at least 32 characters, got 21"
        );
        assert!(!error.to_string().contains(secret));
    }
}
