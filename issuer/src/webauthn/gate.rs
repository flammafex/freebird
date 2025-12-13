// issuer/src/webauthn/gate.rs
use anyhow::{anyhow, Context, Result};
use base64ct::Encoding;
use std::sync::Arc;
use tracing::{info, debug, warn};

use freebird_common::api::SybilProof;
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

    /// Derive a proof verification key from the RP ID and server secret
    ///
    /// Security: This function derives a key for HMAC-based proof verification.
    /// - When WEBAUTHN_PROOF_SECRET is set, uses it as entropy (RECOMMENDED)
    /// - Without secret, falls back to deterministic derivation (INSECURE for production)
    ///
    /// The derived key ensures proofs are:
    /// - Server-specific (bound to RP ID)
    /// - Unforgeable (requires server secret)
    fn derive_proof_key(rp_id: &str) -> [u8; 32] {
        // Check for configured secret
        let (secret_bytes, has_secret) = if let Ok(secret) = std::env::var("WEBAUTHN_PROOF_SECRET") {
            if secret.len() < 32 {
                warn!(
                    "⚠️  WEBAUTHN_PROOF_SECRET is set but too short ({} chars). \
                     Recommend at least 32 characters for security.",
                    secret.len()
                );
            }
            // Derive initial key from secret
            let mut key_hasher = blake3::Hasher::new();
            key_hasher.update(b"webauthn:secret:key:v1:");
            key_hasher.update(secret.as_bytes());
            (*key_hasher.finalize().as_bytes(), true)
        } else {
            warn!(
                "⚠️  WEBAUTHN_PROOF_SECRET not set. Using deterministic key derivation. \
                 This is INSECURE for production! Set WEBAUTHN_PROOF_SECRET to a secure random value."
            );
            // Derive a deterministic but unique-per-deployment key from RP ID
            // This is NOT secure but provides some isolation between deployments
            let mut key_hasher = blake3::Hasher::new();
            key_hasher.update(b"webauthn:deterministic:key:v1:");
            key_hasher.update(rp_id.as_bytes());
            key_hasher.update(b":insecure-fallback");
            (*key_hasher.finalize().as_bytes(), false)
        };

        // Now use the derived key for the final proof key derivation
        let mut hasher = blake3::Hasher::new_keyed(&secret_bytes);
        hasher.update(b"webauthn:proof:key:v1:");
        hasher.update(rp_id.as_bytes());
        if !has_secret {
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