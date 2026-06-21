// SPDX-License-Identifier: Apache-2.0 OR MIT

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEdge {
    pub truster: String,
    pub trustee: String,
    pub weight: f64,
    pub timestamp: u64,
    pub revoked: bool,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestRequest {
    pub holder_commitment: String,
    pub subject: String,
    pub evidence: Vec<TrustEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttestResponse {
    Success {
        attestation: Box<SocialGraphAttestation>,
    },
    Failure {
        reasons: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct AttesterConfig {
    pub bind_addr: String,
    pub private_key_path: String,
    pub kid: String,
    pub attester_id: String,
    pub policy_id: String,
    pub ttl_secs: u64,
    pub trusted_roots: Vec<String>,
    pub scoring: crate::scoring::ScoringConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialGraphAttestation {
    pub contract_version: String,
    pub artifact_type: String,
    pub version: String,
    pub attester_id: String,
    pub kid: String,
    pub policy_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub eligibility_level: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_nullifier: Option<String>,
    pub jti: String,
    pub holder_commitment: String,
    pub signature: String,
}
