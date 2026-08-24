// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Graph issuance authorization verifiers.

use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::collections::HashMap;

use super::policy::GraphIssuancePolicy;

pub struct AuthorizationClaim {
    pub nullifier_digest: [u8; 32],
    pub global_spend_key: Option<String>,
}

/// Authenticated V4-local material needed by the V7 holder-proof lane. The
/// V4 credential parsing, scope, trust, authenticator, nullifier, and spend
/// key derivation are still performed by the existing shared path.
pub struct V4LocalAuthorization {
    pub claim: AuthorizationClaim,
    pub nonce: [u8; 32],
    pub nullifier: String,
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

    /// Verify one V4-local credential without changing the legacy verifier
    /// behavior. V7 uses the returned authenticated nonce solely as an
    /// Ed25519 public key for its additional holder proof.
    pub fn verify_credential(
        &self,
        policy: &GraphIssuancePolicy,
        _request_binding: &[u8; 32],
        authorization: &str,
    ) -> Result<V4LocalAuthorization> {
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
        Ok(V4LocalAuthorization {
            claim: AuthorizationClaim {
                nullifier_digest,
                global_spend_key: Some(verified.spend_key),
            },
            nonce: verified.token.nonce,
            nullifier: verified.nullifier,
        })
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
        request_binding: &[u8; 32],
        authorization: &str,
    ) -> Result<AuthorizationClaim> {
        Ok(self
            .verify_credential(policy, request_binding, authorization)?
            .claim)
    }
}
