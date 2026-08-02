// SPDX-License-Identifier: Apache-2.0 OR MIT
use serde::{Deserialize, Serialize};

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
    // WebAuthn proof fields are plain strings/integers; the issuer
    // verifies them against its WebAuthn gate when WebAuthn is configured.
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

#[cfg(test)]
mod sybil_fixture_tests {
    use super::SybilProof;
    use serde_json::Value;
    use std::{fs, path::Path};

    #[test]
    fn shared_sybil_fixture_round_trips_every_variant() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-fixtures/sybil-proofs.json");
        assert!(
            path.is_file(),
            "Sybil fixture missing at {}",
            path.display()
        );
        let fixture_text = fs::read_to_string(path).expect("Sybil fixture must be readable");
        assert_eq!(
            fixture_text,
            include_str!("../../test-fixtures/sybil-proofs.json")
        );
        let fixture: Value =
            serde_json::from_str(&fixture_text).expect("Sybil fixture must be valid JSON");
        let variants = fixture
            .get("variants")
            .and_then(Value::as_array)
            .expect("Sybil fixture must contain a variants array");
        let expected_types = [
            "proof_of_work",
            "rate_limit",
            "invitation",
            "registered_user",
            "web_authn",
            "progressive_trust",
            "proof_of_diversity",
            "multi_party_vouching",
            "social_graph",
            "multi",
            "none",
        ];

        assert_eq!(variants.len(), expected_types.len());
        for (variant, expected_type) in variants.iter().zip(expected_types) {
            assert_eq!(
                variant.get("type").and_then(Value::as_str),
                Some(expected_type)
            );
            let proof: SybilProof = serde_json::from_value(variant.clone())
                .expect("fixture variant must match SybilProof");
            assert_eq!(serde_json::to_value(proof).unwrap(), *variant);
        }
    }
}

// ============================================================================
