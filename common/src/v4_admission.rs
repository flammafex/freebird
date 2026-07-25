// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared local V4 admission verification used by ordinary verifiers and
//! atomic graph issuance. Parsing and authenticator validation remain in the
//! crypto crate; this module only composes the approved primitives.

use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct V4VerificationKey {
    pub secret_key: [u8; 32],
    pub context: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedV4Credential {
    pub token: freebird_crypto::RedemptionToken,
    pub nullifier: String,
    pub spend_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V4AdmissionError {
    InvalidToken(String),
    Rejected,
}

impl std::fmt::Display for V4AdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken(detail) => write!(formatter, "invalid V4 token: {detail}"),
            Self::Rejected => formatter.write_str("V4 admission verification failed"),
        }
    }
}

impl std::error::Error for V4AdmissionError {}

/// Parse, scope-check, authenticate, and derive the canonical global spend
/// handle for one V4 credential. The resolver is the caller's explicit trust
/// policy and returns private verification material only for allowed issuer/kid
/// pairs.
pub fn verify_v4_credential<F>(
    token_bytes: &[u8],
    expected_scope_digest: &[u8; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
    verifier_id: &str,
    audience: &str,
    mut resolve_key: F,
) -> Result<VerifiedV4Credential, V4AdmissionError>
where
    F: FnMut(&str, &str) -> Option<V4VerificationKey>,
{
    let canonical_scope = freebird_crypto::build_scope_digest(verifier_id, audience)
        .map_err(|_| V4AdmissionError::Rejected)?;
    if !bool::from(canonical_scope.ct_eq(expected_scope_digest)) {
        return Err(V4AdmissionError::Rejected);
    }
    let token = authenticate_v4_credential(token_bytes, expected_scope_digest, &mut resolve_key)?;
    let nullifier = freebird_crypto::nullifier_key_v4(&token, verifier_id, audience)
        .map_err(|_| V4AdmissionError::Rejected)?;
    let spend_key = crate::spend_key::v4_spend_key(&nullifier);
    Ok(VerifiedV4Credential {
        token,
        nullifier,
        spend_key,
    })
}

/// Shared parser/scope/authenticator path for ordinary V4 verification. Replay
/// handling is intentionally left to the caller.
pub fn authenticate_v4_credential<F>(
    token_bytes: &[u8],
    expected_scope_digest: &[u8; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
    mut resolve_key: F,
) -> Result<freebird_crypto::RedemptionToken, V4AdmissionError>
where
    F: FnMut(&str, &str) -> Option<V4VerificationKey>,
{
    let token = freebird_crypto::parse_redemption_token(token_bytes)
        .map_err(|error| V4AdmissionError::InvalidToken(format!("{error:?}")))?;
    if !bool::from(token.scope_digest.ct_eq(expected_scope_digest)) {
        return Err(V4AdmissionError::Rejected);
    }
    let key = resolve_key(&token.issuer_id, &token.kid).ok_or(V4AdmissionError::Rejected)?;
    freebird_crypto::verify_private_token_authenticator(key.secret_key, &key.context, &token)
        .map_err(|_| V4AdmissionError::Rejected)?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_scope_and_trust_mismatches_without_reimplementing_crypto() {
        let secret = [7; 32];
        let scope = freebird_crypto::build_scope_digest("verifier:test", "audience").unwrap();
        let server =
            freebird_crypto::Server::from_secret_key(secret, freebird_crypto::VOPRF_CONTEXT_V4)
                .unwrap();
        let input =
            freebird_crypto::build_private_token_input("issuer:test", "kid", &[8; 32], &scope)
                .unwrap();
        let authenticator = server.evaluate_unblinded(&input).unwrap();
        let token = freebird_crypto::RedemptionToken {
            nonce: [8; 32],
            scope_digest: scope,
            kid: "kid".into(),
            issuer_id: "issuer:test".into(),
            authenticator,
        };
        let bytes = freebird_crypto::build_redemption_token(&token).unwrap();
        let verified = verify_v4_credential(
            &bytes,
            &scope,
            "verifier:test",
            "audience",
            |issuer, kid| {
                (issuer == "issuer:test" && kid == "kid").then(|| V4VerificationKey {
                    secret_key: secret,
                    context: freebird_crypto::VOPRF_CONTEXT_V4.to_vec(),
                })
            },
        )
        .unwrap();
        assert_eq!(
            verified.spend_key,
            crate::spend_key::v4_spend_key(&verified.nullifier)
        );
        assert!(
            verify_v4_credential(&bytes, &scope, "verifier:wrong", "audience", |_, _| None,)
                .is_err()
        );
    }
}
