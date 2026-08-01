// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Graph issuance authorization verifiers.

use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::graph_issuance_api;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use zeroize::Zeroizing;

use super::policy::{
    GraphIssuanceAdmissionState, GraphIssuancePolicy, GraphIssuancePolicyDocument,
};

pub(super) const NULLIFIER_DOMAIN: &[u8] = b"freebird graph issuance authorization nullifier v1\0";

pub(super) fn domain_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(value);
    hash.finalize().into()
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
