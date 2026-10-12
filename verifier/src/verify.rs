// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! V4 private-verification token core.
//!
//! Lives in the library so integration tests exercise the same function the
//! binary calls.

use crate::metadata::IssuerInfo;
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
