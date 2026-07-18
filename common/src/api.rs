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
// Sybil Proof Types
// ============================================================================

/// A single vouch proof for Multi-Party Vouching
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
        subject_hash: String,
        auth_proof: String,
        timestamp: i64,
    },
    ProgressiveTrust {
        user_id_hash: String, // Blake3(username + salt) - privacy preserving
        first_seen: i64,      // Unix timestamp of first issuance
        tokens_issued: u32,   // Lifetime token count
        last_issuance: i64,   // Unix timestamp of last issuance
        hmac_proof: String,   // HMAC(secret, all fields) - prevents forgery
    },
    ProofOfDiversity {
        user_id_hash: String, // Blake3(username + salt)
        diversity_score: u8,  // 0-100 score
        unique_networks: u32, // Count of unique networks observed
        unique_devices: u32,  // Count of unique devices observed
        first_seen: i64,      // Unix timestamp of first observation
        hmac_proof: String,   // HMAC(secret, all fields)
    },
    MultiPartyVouching {
        vouchee_id_hash: String,  // Blake3(username + salt)
        vouches: Vec<VouchProof>, // List of vouch proofs
        hmac_proof: String,       // HMAC(secret, all fields)
        timestamp: i64,           // Unix timestamp of proof generation
    },
    SocialGraph {
        /// The complete cred.presentation artifact as JSON string
        attestation: String,
        /// The presentation_signature field as hex string
        presentation: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDiscoveryResp {
    pub issuer_id: String,
    pub current_epoch: u32,
    pub valid_epochs: Vec<u32>,
    pub epoch_duration_sec: u64,
    pub voprf: VoprfKeyInfo,
    #[serde(default)]
    pub public: Vec<PublicKeyInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exchange: Option<ExchangeDiscoveryInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeDiscoveryInfo {
    pub profile_id: String,
    pub target_keysets: Vec<ExchangeTargetKeysetInfo>,
    pub descriptors: Vec<ExchangeDescriptorInfo>,
    pub receipt_keys: Vec<ExchangeReceiptKeyInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeTargetKeysetInfo {
    pub keyset_id: String,
    /// Canonical ordered descriptor membership.
    pub descriptor_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeReceiptKeyInfo {
    pub key_id: String,
    pub algorithm: String,
    pub purpose: String,
    pub public_key_b64: String,
    pub valid_from: u64,
    pub valid_until: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeDescriptorInfo {
    pub descriptor_id: String,
    pub keyset_id: String,
    pub purpose: String,
    pub profile_id: String,
    pub role: String,
    pub issuer_id: String,
    pub class: String,
    pub token_key_id: String,
    pub pubkey_spki_b64: String,
    pub suite: String,
    pub valid_from: i64,
    pub valid_until: i64,
    pub max_quantity: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangePublicHistory {
    #[serde(default)]
    pub target_keysets: Vec<ExchangeTargetKeysetInfo>,
    #[serde(default)]
    pub target_descriptors: Vec<ExchangeDescriptorInfo>,
    #[serde(default)]
    pub receipt_keys: Vec<ExchangeReceiptKeyInfo>,
}

impl ExchangeDescriptorInfo {
    pub fn canonical_descriptor_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        for value in [
            &self.profile_id,
            &self.role,
            &self.class,
            &self.issuer_id,
            &self.token_key_id,
            &self.suite,
        ] {
            bytes.extend_from_slice(
                &u32::try_from(value.len())
                    .map_err(|_| "descriptor field too large")?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(value.as_bytes());
        }
        if let Some(audience) = &self.audience {
            bytes.push(1);
            bytes.extend_from_slice(
                &u32::try_from(audience.len())
                    .map_err(|_| "audience too large")?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(audience.as_bytes());
        } else {
            bytes.push(0);
            bytes.extend_from_slice(&0u32.to_be_bytes());
        }
        let spki = crate::exchange_api::decode_base64url(&self.pubkey_spki_b64, 4096)
            .map_err(|error| error.to_string())?;
        bytes.extend_from_slice(&spki);
        bytes.extend_from_slice(&self.max_quantity.to_be_bytes());
        bytes.extend_from_slice(&self.valid_from.to_be_bytes());
        bytes.extend_from_slice(&self.valid_until.to_be_bytes());
        Ok(bytes)
    }

    pub fn canonical_descriptor_id(&self) -> Result<String, String> {
        Ok(crate::exchange_api::descriptor_id(
            &self.canonical_descriptor_bytes()?,
        ))
    }
}

impl ExchangeTargetKeysetInfo {
    pub fn canonical_keyset_id(&self) -> String {
        crate::exchange_api::keyset_id(&self.descriptor_ids)
    }
}

/// Validate the complete immutable target descriptor/keyset graph shared by
/// issuer history publication and verifier trust ingestion.
pub fn validate_exchange_target_metadata(
    profile_id: &str,
    issuer_id: &str,
    keysets: &[ExchangeTargetKeysetInfo],
    descriptors: &[ExchangeDescriptorInfo],
) -> Result<(), String> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, HashSet};

    if profile_id != crate::exchange_api::EXCHANGE_PROFILE_V1 || keysets.is_empty() {
        return Err("invalid exchange profile or keyset bounds".into());
    }
    let mut descriptor_map = HashMap::new();
    let mut spkis = HashSet::new();
    for descriptor in descriptors
        .iter()
        .filter(|descriptor| descriptor.purpose == "exchange_target")
    {
        crate::exchange_api::validate_descriptor_id(&descriptor.descriptor_id)
            .map_err(|error| error.to_string())?;
        crate::exchange_api::validate_keyset_id(&descriptor.keyset_id)
            .map_err(|error| error.to_string())?;
        if descriptor.profile_id != profile_id
            || descriptor.role != "target"
            || descriptor.issuer_id != issuer_id
            || descriptor.suite != "RSABSSA-SHA384-PSS-Deterministic"
            || descriptor.class.is_empty()
            || descriptor.class.len() > 128
            || !descriptor.class.is_ascii()
            || descriptor.max_quantity == 0
            || descriptor.max_quantity > 64
            || descriptor.valid_from >= descriptor.valid_until
            || descriptor.audience.as_ref().is_some_and(|audience| {
                audience.is_empty() || audience.len() > 128 || !audience.is_ascii()
            })
            || descriptor.canonical_descriptor_id()? != descriptor.descriptor_id
        {
            return Err("invalid immutable exchange target descriptor".into());
        }
        let spki = crate::exchange_api::decode_base64url(&descriptor.pubkey_spki_b64, 4096)
            .map_err(|error| error.to_string())?;
        if Base64UrlUnpadded::encode_string(&spki) != descriptor.pubkey_spki_b64
            || hex::encode(Sha256::digest(&spki)) != descriptor.token_key_id
            || freebird_crypto::validate_public_bearer_spki(&spki).is_err()
            || !spkis.insert(spki)
            || descriptor_map
                .insert(descriptor.descriptor_id.clone(), descriptor)
                .is_some()
        {
            return Err("exchange target identity collision".into());
        }
    }
    if descriptor_map.is_empty() {
        return Err("exchange target descriptors are empty".into());
    }
    let mut keyset_ids = HashSet::new();
    let mut memberships = HashSet::new();
    for keyset in keysets {
        crate::exchange_api::validate_keyset_id(&keyset.keyset_id)
            .map_err(|error| error.to_string())?;
        if keyset.descriptor_ids.is_empty()
            || keyset.canonical_keyset_id() != keyset.keyset_id
            || !keyset_ids.insert(&keyset.keyset_id)
        {
            return Err("invalid canonical exchange target keyset".into());
        }
        for descriptor_id in &keyset.descriptor_ids {
            let descriptor = descriptor_map
                .get(descriptor_id)
                .ok_or_else(|| "keyset references unknown descriptor".to_string())?;
            if descriptor.keyset_id != keyset.keyset_id
                || !memberships.insert(descriptor_id.clone())
            {
                return Err("descriptor keyset membership mismatch".into());
            }
        }
    }
    if memberships.len() != descriptor_map.len() {
        return Err("unpublished target keyset membership".into());
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoprfKeyInfo {
    pub suite: String,
    pub kid: String,
    pub pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    pub token_key_id: String,
    pub token_type: String,
    pub rfc9474_variant: String,
    pub modulus_bits: u16,
    pub pubkey_spki_b64: String,
    pub issuer_id: String,
    pub valid_from: i64,
    pub valid_until: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    pub spend_policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
}

#[cfg(test)]
mod exchange_metadata_tests {
    use super::*;

    #[test]
    fn receipt_metadata_round_trips_and_legacy_discovery_remains_compatible() {
        let key = ExchangeReceiptKeyInfo {
            key_id: "a".repeat(64),
            algorithm: "Ed25519".into(),
            purpose: "exchange_receipt_active".into(),
            public_key_b64: "AQ".into(),
            valid_from: 0,
            valid_until: u64::MAX,
        };
        assert_eq!(
            serde_json::from_value::<ExchangeReceiptKeyInfo>(serde_json::to_value(&key).unwrap())
                .unwrap(),
            key
        );
        let legacy = serde_json::json!({
            "issuer_id":"issuer:test",
            "current_epoch":1,
            "valid_epochs":[1],
            "epoch_duration_sec":86400,
            "voprf":{"suite":"suite","kid":"kid","pubkey":"key"},
            "public":[]
        });
        assert!(serde_json::from_value::<KeyDiscoveryResp>(legacy)
            .unwrap()
            .exchange
            .is_none());
    }
}
