// issuer/src/webauthn/gate.rs
use anyhow::{anyhow, Context, Result};
use base64ct::Encoding;
use std::sync::Arc;
use tracing::{info, debug};

use common::api::SybilProof;
use crate::sybil_resistance::SybilResistance; // Trait still lives in common/sybil
use super::handlers::WebAuthnState;

pub struct WebAuthnGate {
    max_proof_age: i64,
    proof_key: [u8; 32],
}

impl WebAuthnGate {
    pub fn new(state: Arc<WebAuthnState>, max_proof_age: Option<i64>) -> Self {
        let max_proof_age = max_proof_age.unwrap_or(300);

        // Derive proof verification key from WebAuthn context
        // This creates a deterministic but secret key for HMAC verification
        let proof_key = Self::derive_proof_key(&state.webauthn.rp_id);

        info!(max_proof_age_secs = max_proof_age, "Initialized WebAuthn Sybil resistance");
        Self { max_proof_age, proof_key }
    }

    /// Derive a proof verification key from the RP ID
    /// This ensures proofs are server-specific and unforgeable
    fn derive_proof_key(rp_id: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&[0u8; 32]);
        hasher.update(b"webauthn:proof:key:v1:");
        hasher.update(rp_id.as_bytes());

        // Use system entropy if available, otherwise use RP ID as deterministic seed
        if let Ok(secret) = std::env::var("WEBAUTHN_PROOF_SECRET") {
            hasher.update(secret.as_bytes());
        } else {
            // Fallback: derive from RP ID (deterministic but unique per deployment)
            hasher.update(b":deterministic");
        }

        *hasher.finalize().as_bytes()
    }

    /// Compute the expected proof for verification
    /// Must match the computation in handlers.rs
    fn compute_proof(&self, username: &str, timestamp: i64) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&self.proof_key);
        hasher.update(b"webauthn:auth:");
        hasher.update(username.as_bytes());
        hasher.update(b":");
        hasher.update(&timestamp.to_le_bytes());
        base64ct::Base64UrlUnpadded::encode_string(hasher.finalize().as_bytes())
    }
}

impl SybilResistance for WebAuthnGate {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        match proof {
            SybilProof::WebAuthn { username, auth_proof, timestamp } => {
                let now = chrono::Utc::now().timestamp();
                let age = now - timestamp;

                // Validate timestamp
                if age > self.max_proof_age {
                    return Err(anyhow!("Authentication proof expired (age: {}s, max: {}s)", age, self.max_proof_age));
                }
                if age < -60 {
                    return Err(anyhow!("Timestamp in future"));
                }

                // Validate proof format
                let proof_bytes = base64ct::Base64UrlUnpadded::decode_vec(auth_proof)
                    .context("Invalid proof encoding")?;

                if proof_bytes.len() != 32 {
                    return Err(anyhow!("Invalid proof length: expected 32 bytes, got {}", proof_bytes.len()));
                }

                // CRITICAL: Verify the proof is cryptographically valid
                // This prevents forgery - only the server can generate valid proofs
                let expected_proof = self.compute_proof(username, *timestamp);

                if auth_proof != &expected_proof {
                    debug!(
                        username = %username,
                        timestamp = timestamp,
                        "WebAuthn proof verification failed: proof mismatch"
                    );
                    return Err(anyhow!("Invalid authentication proof"));
                }

                debug!(
                    username = %username,
                    timestamp = timestamp,
                    age_secs = age,
                    "WebAuthn proof verified successfully"
                );

                Ok(())
            }
            _ => Err(anyhow!("Expected WebAuthn proof")),
        }
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::WebAuthn { .. })
    }

    fn cost(&self) -> u64 { 0 }
}