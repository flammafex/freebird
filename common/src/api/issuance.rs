// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::sybil::SybilProof;
use base64ct::{Base64UrlUnpadded, Encoding};
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
// V7 Native Bearer Issuance Types
// ============================================================================

/// Direct V7 issuance request.
///
/// `blinded_msg_b64` is exactly one canonical, unpadded base64url encoding of
/// the 384-byte raw RFC 9474 blinded message.  The key ID is mandatory and is
/// never inferred from an untyped request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBearerV7IssueReq {
    #[serde(deserialize_with = "deserialize_v7_token_key_id")]
    pub token_key_id: String,
    #[serde(deserialize_with = "deserialize_v7_raw384_b64")]
    pub blinded_msg_b64: String,
    #[serde(default)]
    pub sybil_proof: Option<SybilProof>,
}

impl NativeBearerV7IssueReq {
    pub fn validate(&self) -> Result<(), String> {
        validate_v7_token_key_id(&self.token_key_id)?;
        validate_v7_raw384_b64(&self.blinded_msg_b64, "blinded_msg_b64")
    }
}

/// Direct V7 issuance response containing one raw384 blind signature.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBearerV7IssueResp {
    #[serde(deserialize_with = "deserialize_v7_raw384_b64")]
    pub blind_signature_b64: String,
    #[serde(deserialize_with = "deserialize_v7_token_key_id")]
    pub token_key_id: String,
    pub issuer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}

impl NativeBearerV7IssueResp {
    pub fn validate(&self) -> Result<(), String> {
        validate_v7_token_key_id(&self.token_key_id)?;
        validate_v7_raw384_b64(&self.blind_signature_b64, "blind_signature_b64")?;
        if self.issuer_id.is_empty() {
            return Err("issuer_id must be nonempty".into());
        }
        Ok(())
    }
}

/// Batch V7 issuance request. Every element is a fixed-size raw384 blinded
/// message and all elements explicitly select the same V7 key ID.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBearerV7BatchIssueReq {
    #[serde(deserialize_with = "deserialize_v7_token_key_id")]
    pub token_key_id: String,
    #[serde(deserialize_with = "deserialize_v7_raw384_vec")]
    pub blinded_msgs_b64: Vec<String>,
    #[serde(default)]
    pub sybil_proof: Option<SybilProof>,
}

impl NativeBearerV7BatchIssueReq {
    pub fn validate(&self) -> Result<(), String> {
        validate_v7_token_key_id(&self.token_key_id)?;
        if self.blinded_msgs_b64.is_empty() {
            return Err("blinded_msgs_b64 must be nonempty".into());
        }
        for message in &self.blinded_msgs_b64 {
            validate_v7_raw384_b64(message, "blinded_msgs_b64")?;
        }
        Ok(())
    }
}

/// Batch V7 issuance response containing one raw384 signature per request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBearerV7BatchIssueResp {
    #[serde(deserialize_with = "deserialize_v7_raw384_vec")]
    pub blind_signatures_b64: Vec<String>,
    #[serde(deserialize_with = "deserialize_v7_token_key_id")]
    pub token_key_id: String,
    pub issuer_id: String,
    pub successful: usize,
    pub failed: usize,
    pub processing_time_ms: u64,
    pub throughput: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}

impl NativeBearerV7BatchIssueResp {
    pub fn validate(&self) -> Result<(), String> {
        validate_v7_token_key_id(&self.token_key_id)?;
        if self.issuer_id.is_empty() {
            return Err("issuer_id must be nonempty".into());
        }
        if self.successful != self.blind_signatures_b64.len() {
            return Err("successful must equal blind_signatures_b64 length".into());
        }
        if self.successful + self.failed == 0 {
            return Err("V7 batch response must contain a result".into());
        }
        for signature in &self.blind_signatures_b64 {
            validate_v7_raw384_b64(signature, "blind_signatures_b64")?;
        }
        Ok(())
    }
}

fn validate_v7_token_key_id(value: &str) -> Result<(), String> {
    let bytes = hex::decode(value).map_err(|_| "token_key_id must be lowercase hex".to_string())?;
    if value.len() != 64
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || freebird_crypto::V7TokenKeyId::from_bytes(&bytes).is_err()
    {
        return Err("token_key_id must be exactly 64 lowercase hexadecimal characters".into());
    }
    Ok(())
}

fn validate_v7_raw384_b64(value: &str, field: &str) -> Result<(), String> {
    let decoded = Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| format!("{field} must be unpadded base64url"))?;
    if decoded.len() != freebird_crypto::public_bearer_v7::V7_SIGNATURE_LEN
        || Base64UrlUnpadded::encode_string(&decoded) != value
    {
        return Err(format!(
            "{field} must be canonical unpadded base64url for exactly 384 bytes"
        ));
    }
    Ok(())
}

fn deserialize_v7_token_key_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_v7_token_key_id(&value).map_err(serde::de::Error::custom)?;
    Ok(value)
}

fn deserialize_v7_raw384_b64<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_v7_raw384_b64(&value, "V7 raw384 message").map_err(serde::de::Error::custom)?;
    Ok(value)
}

fn deserialize_v7_raw384_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    for value in &values {
        validate_v7_raw384_b64(value, "V7 raw384 message").map_err(serde::de::Error::custom)?;
    }
    Ok(values)
}

// ============================================================================
