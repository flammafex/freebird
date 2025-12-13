// common/src/api.rs
use serde::{Deserialize, Serialize};

// ============================================================================
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
    /// Base64url-encoded evaluation token
    pub token: String,

    /// DLEQ proof
    #[serde(default)]
    pub proof: String,

    /// Key identifier used for issuance
    pub kid: String,

    /// Expiration timestamp (Unix seconds)
    pub exp: i64,

    /// Epoch used for MAC key derivation
    pub epoch: u32,

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
        proof: String,
        kid: String,
        exp: i64,
        epoch: u32,
    },
    Error {
        message: String,
        code: String,
    },
}

// ============================================================================
// Verification Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyReq {
    pub token_b64: String,
    pub issuer_id: String,

    /// Optional: Token expiration time (Unix timestamp)
    /// If provided, verifier checks clock skew against this.
    #[serde(default)]
    pub exp: Option<i64>,

    /// Epoch used for MAC key derivation
    pub epoch: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResp {
    pub ok: bool,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    
    #[serde(default)]
    pub verified_at: i64,
}

// ============================================================================
// Batch Verification Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchVerifyReq {
    pub tokens: Vec<TokenToVerify>,
    pub issuer_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenToVerify {
    pub token_b64: String,

    /// Optional: Token expiration time (Unix timestamp)
    /// If provided, verifier checks clock skew against this.
    #[serde(default)]
    pub exp: Option<i64>,

    /// Epoch used for MAC key derivation
    pub epoch: u32,
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
    Success {
        verified_at: i64,
    },
    Error {
        message: String,
        code: String,
    },
}

// ============================================================================
// Sybil Proof Types
// ============================================================================

/// A single vouch proof for Multi-Party Vouching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VouchProof {
    pub voucher_id: String,
    pub vouchee_id: String,
    pub timestamp: i64,
    pub signature: String,
    /// Voucher's public key (SEC1 uncompressed, base64url encoded)
    /// Required for signature verification
    pub voucher_pubkey_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SybilProof {
    ProofOfWork {
        nonce: u64,
        input: String,
        timestamp: u64,
    },
    RateLimit {
        client_id: String,
        timestamp: u64,
    },
    Invitation {
        code: String,
        signature: String,
    },
    /// Registered user proof - for users already in the system (e.g., instance owner)
    /// This bypasses invitation requirement for users who exist in the users table
    RegisteredUser {
        user_id: String,
    },
    // Note: WebAuthn fields are strings/integers, so they verify
    // fine even if the backend doesn't have the webauthn crate enabled.
    WebAuthn {
        username: String,
        auth_proof: String,
        timestamp: i64,
    },
    ProgressiveTrust {
        user_id_hash: String,   // Blake3(username + salt) - privacy preserving
        first_seen: i64,        // Unix timestamp of first issuance
        tokens_issued: u32,     // Lifetime token count
        last_issuance: i64,     // Unix timestamp of last issuance
        hmac_proof: String,     // HMAC(secret, all fields) - prevents forgery
    },
    ProofOfDiversity {
        user_id_hash: String,   // Blake3(username + salt)
        diversity_score: u8,    // 0-100 score
        unique_networks: u32,   // Count of unique networks observed
        unique_devices: u32,    // Count of unique devices observed
        first_seen: i64,        // Unix timestamp of first observation
        hmac_proof: String,     // HMAC(secret, all fields)
    },
    MultiPartyVouching {
        vouchee_id_hash: String,  // Blake3(username + salt)
        vouches: Vec<VouchProof>, // List of vouch proofs
        hmac_proof: String,       // HMAC(secret, all fields)
        timestamp: i64,           // Unix timestamp of proof generation
    },
    FederatedTrust {
        source_issuer_id: String,  // ID of the issuer that issued the source token
        source_token_b64: String,  // Base64url-encoded token from source issuer
        token_exp: i64,            // Expiration timestamp of source token
        token_issued_at: Option<i64>, // When the source token was issued (for age validation)
        trust_path: Vec<String>,   // Trust path from source to us (optional)
    },
    /// Multiple proofs for AND/threshold combination modes
    Multi {
        proofs: Vec<SybilProof>,
    },
    None,
}

// ============================================================================
// Key Management Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyDiscoveryResp {
    pub issuer_id: String,
    pub current_epoch: u32,
    pub valid_epochs: Vec<u32>,
    pub epoch_duration_sec: u64,
    pub voprf: VoprfKeyInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VoprfKeyInfo {
    pub suite: String,
    pub kid: String,
    pub pubkey: String,
    pub exp_sec: u64,
}