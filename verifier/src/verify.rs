// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! V4 private-verification token core.
//!
//! Lives in the library so integration tests exercise the same function the
//! binary calls.

use crate::metadata::IssuerInfo;
use crate::state::{V7IssuerTrustEntry, V7TrustRegistry};
use axum::http::StatusCode;
use base64ct::{Base64UrlUnpadded, Encoding};
use std::collections::HashMap;
use tracing::{debug, error};

/// Parse a V4 redemption token from base64url, find the issuer-trusted private
/// verification key, and recompute the token authenticator locally.
///
/// Returns `(parsed_token, issuer_info)` on success.
pub fn verify_v4_token(
    token_b64: &str,
    issuers: &HashMap<String, IssuerInfo>,
    expected_scope_digest: &[u8; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
) -> Result<(freebird_crypto::RedemptionToken, IssuerInfo), (StatusCode, String)> {
    let token_bytes = Base64UrlUnpadded::decode_vec(token_b64).map_err(|e| {
        error!("Failed to decode token: {:?}", e);
        (
            StatusCode::BAD_REQUEST,
            "invalid token encoding".to_string(),
        )
    })?;

    let parsed = freebird_common::v4_admission::authenticate_v4_credential(
        &token_bytes,
        expected_scope_digest,
        |issuer_id, kid| {
            let issuer = issuers.get(issuer_id)?;
            Some(freebird_common::v4_admission::V4VerificationKey {
                secret_key: issuer.verification_key_for(kid)?,
                context: issuer.ctx.clone(),
            })
        },
    )
    .map_err(|error| {
        error!("V4 token parsing, scope, trust, or authenticator verification failed");
        match error {
            freebird_common::v4_admission::V4AdmissionError::InvalidToken(detail) => (
                StatusCode::BAD_REQUEST,
                format!("invalid token format: {detail}"),
            ),
            freebird_common::v4_admission::V4AdmissionError::Rejected => {
                (StatusCode::UNAUTHORIZED, "verification failed".to_string())
            }
        }
    })?;
    let issuer = issuers
        .get(&parsed.issuer_id)
        .expect("shared V4 verification resolved this issuer");

    debug!("V4 private token authenticator verified");

    Ok((parsed, issuer.clone()))
}

pub fn decode_token_version(token_b64: &str) -> Result<u8, (StatusCode, String)> {
    let token_bytes = Base64UrlUnpadded::decode_vec(token_b64).map_err(|e| {
        error!("Failed to decode token: {:?}", e);
        (
            StatusCode::BAD_REQUEST,
            "invalid token encoding".to_string(),
        )
    })?;
    token_bytes.first().copied().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "invalid token format: empty token".to_string(),
        )
    })
}

/// Parse and publicly verify a nominal V7 native bearer artifact.
///
/// V7 trust is resolved by the issuer ID carried by the body and then by the
/// body's typed token-key ID.  The descriptor metadata retained in the trust
/// entry is intentionally not part of this decision: only the key binding,
/// fixed body policy, and inclusive validity window authorize the artifact.
///
/// Parsing failures are public format errors.  Missing or expired trust and
/// every identity, policy, randomizer, or signature failure use the same
/// generic public verification error.
pub fn verify_v7_public_token(
    token_b64: &str,
    trust: &V7TrustRegistry,
) -> Result<(freebird_crypto::NativeBearerV7Token, V7IssuerTrustEntry), (StatusCode, String)> {
    let token_bytes = decode_canonical_v7(token_b64)?;
    let parsed = freebird_crypto::parse_native_bearer_v7_token(&token_bytes).map_err(|e| {
        error!(error = ?e, "Failed to parse V7 token");
        (StatusCode::BAD_REQUEST, "invalid token format".to_string())
    })?;

    let body = parsed.body();
    let entry = trust
        .get(body.issuer_id())
        .and_then(|snapshot| snapshot.get(body.token_key_id()))
        .cloned()
        .ok_or_else(|| {
            error!(
                issuer_id = %body.issuer_id(),
                token_key_id = %hex::encode(body.token_key_id().as_bytes()),
                "V7 token trust is unavailable"
            );
            (StatusCode::UNAUTHORIZED, "verification failed".to_string())
        })?;

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    verify_v7_with_entry(parsed, entry, now)
}

fn decode_canonical_v7(token_b64: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let token_bytes = Base64UrlUnpadded::decode_vec(token_b64).map_err(|e| {
        error!(error = ?e, "Failed to decode V7 token");
        (
            StatusCode::BAD_REQUEST,
            "invalid token encoding".to_string(),
        )
    })?;
    if Base64UrlUnpadded::encode_string(&token_bytes) != token_b64 {
        error!("V7 token encoding is not canonical unpadded base64url");
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid token encoding".to_string(),
        ));
    }
    Ok(token_bytes)
}

fn verify_v7_with_entry(
    parsed: freebird_crypto::NativeBearerV7Token,
    entry: V7IssuerTrustEntry,
    now: i64,
) -> Result<(freebird_crypto::NativeBearerV7Token, V7IssuerTrustEntry), (StatusCode, String)> {
    let body = parsed.body();
    if now < entry.valid_from || now > entry.valid_until {
        error!("V7 token trust is outside its validity window");
        return Err((StatusCode::UNAUTHORIZED, "verification failed".to_string()));
    }

    parsed.verify(&entry.binding, &entry.policy).map_err(|e| {
        error!(error = ?e, "V7 native bearer verification failed");
        (StatusCode::UNAUTHORIZED, "verification failed".to_string())
    })?;

    debug!(
        issuer_id = %body.issuer_id(),
        token_key_id = %hex::encode(body.token_key_id().as_bytes()),
        "V7 native bearer verification succeeded"
    );
    Ok((parsed, entry))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{V7DescriptorIdentity, V7IssuerTrustSnapshot};
    use base64ct::Base64UrlUnpadded;
    use freebird_crypto::{
        blind_v7, finalize_v7, provider::software::SoftwareV7BlindRsaProvider, PublicBearerV7Body,
        V7KeyIdentity, V7MessageRandomizer, V7Signature, V7TokenKeyId,
    };
    use std::collections::HashMap;

    const ISSUER: &str = "issuer:v7:verifier-test";

    struct Fixture {
        token_b64: String,
        trust: V7TrustRegistry,
        token: freebird_crypto::NativeBearerV7Token,
        valid_from: i64,
        valid_until: i64,
    }

    async fn fixture() -> Fixture {
        let token_key_id = V7TokenKeyId::new([0x17; 32]);
        let identity = V7KeyIdentity::new(ISSUER, token_key_id).unwrap();
        let provider = SoftwareV7BlindRsaProvider::generate(identity).unwrap();
        let body = PublicBearerV7Body::new_derived(
            "USD",
            42,
            ISSUER,
            token_key_id,
            [0x21; 32],
            [0x31; 32],
        )
        .unwrap();
        let (blind_message, randomizer, state) = blind_v7(provider.binding(), &body).unwrap();
        let blind_signature = provider
            .blind_sign(provider.binding().identity(), &blind_message)
            .await
            .unwrap();
        let signature = finalize_v7(provider.binding(), state, &blind_signature).unwrap();
        let token = freebird_crypto::NativeBearerV7Token::new(body, randomizer, signature);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let entry = V7IssuerTrustEntry {
            binding: provider.binding().clone(),
            policy: freebird_crypto::V7BodyPolicy::new("USD", 42).unwrap(),
            identity: V7DescriptorIdentity {
                profile_id: "ignored-profile".into(),
                descriptor_id: "ignored-descriptor".into(),
            },
            valid_from: now - 60,
            valid_until: now + 60,
        };
        let mut snapshot = V7IssuerTrustSnapshot::default();
        snapshot.by_token_key_id.insert(token_key_id, entry);
        let trust = HashMap::from([(ISSUER.to_owned(), snapshot)]);
        let token_b64 = Base64UrlUnpadded::encode_string(&token.serialize().unwrap());
        Fixture {
            token_b64,
            trust,
            token,
            valid_from: now - 60,
            valid_until: now + 60,
        }
    }

    #[tokio::test]
    async fn verifies_nominal_v7_artifact_and_rejects_noncanonical_encoding() {
        let fixture = fixture().await;
        let (parsed, _) = verify_v7_public_token(&fixture.token_b64, &fixture.trust).unwrap();
        assert_eq!(parsed, fixture.token);

        let padded = format!("{}=", fixture.token_b64);
        assert!(verify_v7_public_token(&padded, &fixture.trust).is_err());
    }

    #[tokio::test]
    async fn v7_validity_endpoint_is_inclusive() {
        let fixture = fixture().await;
        let entry = fixture
            .trust
            .get(ISSUER)
            .unwrap()
            .get(fixture.token.body().token_key_id())
            .unwrap()
            .clone();
        verify_v7_with_entry(fixture.token.clone(), entry, fixture.valid_from).unwrap();
        verify_v7_with_entry(
            fixture.token.clone(),
            fixture_entry(&fixture),
            fixture.valid_until,
        )
        .unwrap();
        assert!(verify_v7_with_entry(
            fixture.token.clone(),
            fixture_entry(&fixture),
            fixture.valid_from - 1
        )
        .is_err());
        assert!(verify_v7_with_entry(
            fixture.token.clone(),
            fixture_entry(&fixture),
            fixture.valid_until + 1
        )
        .is_err());
    }

    fn fixture_entry(fixture: &Fixture) -> V7IssuerTrustEntry {
        fixture
            .trust
            .get(ISSUER)
            .unwrap()
            .get(fixture.token.body().token_key_id())
            .unwrap()
            .clone()
    }

    #[tokio::test]
    async fn v7_wrong_trust_is_generic() {
        let fixture = fixture().await;
        let mut trust = fixture.trust.clone();
        trust.get_mut(ISSUER).unwrap().by_token_key_id.clear();
        let error = verify_v7_public_token(&fixture.token_b64, &trust).unwrap_err();
        assert_eq!(
            error,
            (StatusCode::UNAUTHORIZED, "verification failed".into())
        );
    }

    #[tokio::test]
    async fn malformed_v7_artifact_error_is_generic() {
        let fixture = fixture().await;
        let mut bytes = Base64UrlUnpadded::decode_vec(&fixture.token_b64).unwrap();
        bytes.pop();
        let malformed = Base64UrlUnpadded::encode_string(&bytes);

        assert_eq!(
            verify_v7_public_token(&malformed, &fixture.trust).unwrap_err(),
            (StatusCode::BAD_REQUEST, "invalid token format".into())
        );
    }

    #[test]
    fn malformed_v7_randomizer_and_signature_are_format_or_generic_errors() {
        let body = PublicBearerV7Body::new_derived(
            "USD",
            42,
            ISSUER,
            V7TokenKeyId::new([1; 32]),
            [2; 32],
            [3; 32],
        )
        .unwrap();
        let token = freebird_crypto::NativeBearerV7Token::new(
            body,
            V7MessageRandomizer::new([0; 32]),
            V7Signature::new([0; 384]),
        );
        let bytes = token.serialize().unwrap();
        assert!(freebird_crypto::parse_native_bearer_v7_token(&bytes[..bytes.len() - 1]).is_err());
    }
}
