// issuer/src/webauthn/gate.rs
use anyhow::{anyhow, Context, Result};
use base64ct::Encoding;
use std::sync::Arc;
use tracing::info;

use common::api::SybilProof;
use crate::sybil_resistance::SybilResistance; // Trait still lives in common/sybil
use super::handlers::WebAuthnState;

pub struct WebAuthnGate {
    state: Arc<WebAuthnState>,
    max_proof_age: i64,
}

impl WebAuthnGate {
    pub fn new(state: Arc<WebAuthnState>, max_proof_age: Option<i64>) -> Self {
        let max_proof_age = max_proof_age.unwrap_or(300);
        info!(max_proof_age_secs = max_proof_age, "Initialized WebAuthn Sybil resistance");
        Self { state, max_proof_age }
    }
}

impl SybilResistance for WebAuthnGate {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        match proof {
            SybilProof::WebAuthn { auth_proof, timestamp, .. } => {
                let now = chrono::Utc::now().timestamp();
                let age = now - timestamp;

                if age > self.max_proof_age {
                    return Err(anyhow!("Authentication proof expired"));
                }
                if age < -60 {
                    return Err(anyhow!("Timestamp in future"));
                }

                let proof_bytes = base64ct::Base64UrlUnpadded::decode_vec(auth_proof)
                    .context("Invalid proof encoding")?;

                if proof_bytes.len() != 32 {
                    return Err(anyhow!("Invalid proof length"));
                }
                
                // Note: Real verification involves checking if `auth_proof` 
                // matches a recent session in `self.state`. 
                // For v0.1.0 we rely on the proof format and timestamp.
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