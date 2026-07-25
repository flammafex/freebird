// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! V4 private-verification token core.
//!
//! Lives in the library so integration tests exercise the same function the
//! binary calls.

use crate::routes::admin::{IssuerInfo, PublicIssuerKey};
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

/// Parse and publicly verify a V5 bearer pass.
pub fn verify_v5_public_token(
    token_b64: &str,
    issuers: &HashMap<String, IssuerInfo>,
    verifier_audience: &str,
) -> Result<(freebird_crypto::PublicBearerPass, PublicIssuerKey), (StatusCode, String)> {
    let token_bytes = Base64UrlUnpadded::decode_vec(token_b64).map_err(|e| {
        error!("Failed to decode token: {:?}", e);
        (
            StatusCode::BAD_REQUEST,
            "invalid token encoding".to_string(),
        )
    })?;

    let parsed = freebird_crypto::parse_public_bearer_pass(&token_bytes).map_err(|e| {
        error!("Failed to parse V5 token: {:?}", e);
        (
            StatusCode::BAD_REQUEST,
            format!("invalid token format: {:?}", e),
        )
    })?;

    let issuer = issuers.get(&parsed.issuer_id).ok_or_else(|| {
        error!("token issuer is not trusted");
        (StatusCode::UNAUTHORIZED, "verification failed".to_string())
    })?;
    let key = issuer
        .public_keys
        .get(&parsed.token_key_id)
        .ok_or_else(|| {
            error!("V5 public token key is not trusted");
            (StatusCode::UNAUTHORIZED, "verification failed".to_string())
        })?;

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if now < key.valid_from || now > key.valid_until {
        error!("V5 public token key is outside its validity window");
        return Err((StatusCode::UNAUTHORIZED, "verification failed".to_string()));
    }

    if let Some(audience) = &key.audience {
        if audience != verifier_audience {
            error!("V5 public token audience does not match verifier");
            return Err((StatusCode::UNAUTHORIZED, "verification failed".to_string()));
        }
    }

    freebird_crypto::verify_public_bearer_signature(&key.pubkey_spki, &parsed).map_err(|e| {
        error!(error = ?e, "V5 public bearer signature verification failed");
        (StatusCode::UNAUTHORIZED, "verification failed".to_string())
    })?;

    debug!("V5 public bearer signature verified");
    Ok((parsed, key.clone()))
}
