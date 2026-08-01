// SPDX-License-Identifier: Apache-2.0 OR MIT
use serde::{Deserialize, Serialize};

// Verification Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyReq {
    /// Base64url-encoded V4 private-verification redemption token.
    pub token_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResp {
    pub ok: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    #[serde(default)]
    pub verified_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifierMetadataResp {
    pub verifier_id: String,
    pub audience: String,
    /// Base64url-encoded SHA-256 scope digest clients must bind into V4 token input.
    pub scope_digest_b64: String,
    /// Token families accepted by this verifier (for example `v4`, `v5`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_token_versions: Option<Vec<String>>,
}

// ============================================================================
// Batch Verification Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchVerifyReq {
    pub tokens: Vec<TokenToVerify>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenToVerify {
    pub token_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchVerifyResp {
    pub results: Vec<VerifyResult>,
    pub successful: usize,
    pub failed: usize,
    pub processing_time_ms: u64,
    pub throughput: f64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum VerifyResult {
    Success { verified_at: i64 },
    Error { message: String, code: String },
}

// ============================================================================
