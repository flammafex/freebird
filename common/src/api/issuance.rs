// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::sybil::SybilProof;
use serde::{Deserialize, Serialize};

// VOPRF Issuance Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueReq {
    /// Blinded element for VOPRF (base64url encoded)
    #[serde(alias = "blinded")]
    pub blinded_element_b64: String,

    /// Optional context (currently unused but reserved)
    #[serde(default)]
    pub ctx_b64: Option<String>,

    /// Optional Sybil resistance proof
    #[serde(default)]
    pub sybil_proof: Option<SybilProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueResp {
    /// Base64url-encoded VOPRF evaluation [VERSION|A|B|DLEQ_proof] (131 bytes)
    pub token: String,
    /// Key identifier used for issuance
    pub kid: String,
    /// Issuer identifier
    pub issuer_id: String,
    /// Optional Sybil resistance verification info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SybilInfo {
    pub required: bool,
    pub passed: bool,
    pub cost: u64,
}

/// Stable JSON error body used by public issuance endpoints.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResp {
    pub error: String,
}

// ============================================================================
// Batch Issuance Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchIssueReq {
    pub blinded_elements: Vec<String>,

    #[serde(default)]
    pub ctx_b64: Option<String>,

    #[serde(default)]
    pub sybil_proof: Option<SybilProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchIssueResp {
    pub results: Vec<TokenResult>,
    pub successful: usize,
    pub failed: usize,
    pub processing_time_ms: u64,
    pub throughput: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum TokenResult {
    Success {
        token: String,
        kid: String,
        issuer_id: String,
    },
    Error {
        message: String,
        code: String,
    },
}

// ============================================================================
// V5 Public Bearer Pass Issuance Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIssueReq {
    /// RFC 9474 blinded message for a V5 public bearer pass.
    pub blinded_msg_b64: String,

    /// Optional active token key requested by the client.
    #[serde(default)]
    pub token_key_id: Option<String>,

    /// Optional Sybil resistance proof.
    #[serde(default)]
    pub sybil_proof: Option<SybilProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicIssueResp {
    /// Base64url-encoded RFC 9474 blind signature.
    pub blind_signature_b64: String,
    /// Strict lowercase hex SHA-256 digest of the V5 SPKI public key.
    pub token_key_id: String,
    /// Issuer identifier embedded in the client-finalized V5 token.
    pub issuer_id: String,
    /// Optional Sybil resistance verification info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicBatchIssueReq {
    pub blinded_msgs: Vec<String>,

    #[serde(default)]
    pub token_key_id: Option<String>,

    #[serde(default)]
    pub sybil_proof: Option<SybilProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicBatchIssueResp {
    pub blind_signatures: Vec<String>,
    pub token_key_id: String,
    pub issuer_id: String,
    pub successful: usize,
    pub failed: usize,
    pub processing_time_ms: u64,
    pub throughput: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}

// ============================================================================
