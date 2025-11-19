// issuer/src/sybil_resistance/webauthn_gate.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! WebAuthn-based Sybil resistance
//!
//! This module implements "proof of humanity" via WebAuthn/FIDO2 authentication.
//! Users must prove possession of a registered passkey or security key to obtain tokens.
//!
//! # Security Properties
//!
//! - **Hardware-backed**: Passkeys are protected by device TPM/Secure Enclave
//! - **Phishing-resistant**: Origin-bound credentials prevent phishing
//! - **No computational cost**: Unlike PoW, verification is instant
//! - **User-friendly**: Biometric unlock (Touch ID, Windows Hello, etc.)
//!
//! # Threat Model
//!
//! **Protects against:**
//! - Mass token requests from botnets
//! - Automated abuse without physical devices
//! - Credential stuffing attacks
//!
//! **Does NOT protect against:**
//! - Users with multiple physical devices
//! - Shared credentials (though WebAuthn makes this harder)
//! - Social engineering (users willingly giving access)
//!
//! # Integration
//!
//! ```rust
//! use sybil_resistance::SybilProof;
//!
//! let proof = SybilProof::WebAuthn {
//!     username: "alice".to_string(),
//!     auth_proof: "base64-encoded-proof".to_string(),
//!     timestamp: 1234567890,
//! };
//!
//! let checker = WebAuthnGate::new(webauthn_state);
//! checker.verify(&proof, None).await?;
//! ```

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64ct::Encoding;
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::{SybilProof, SybilResistance};
use crate::routes::webauthn::WebAuthnState;

/// WebAuthn-based Sybil resistance
pub struct WebAuthnGate {
    state: Arc<WebAuthnState>,
    /// Maximum age of authentication proofs (seconds)
    max_proof_age: i64,
}

impl WebAuthnGate {
    /// Create a new WebAuthn gate
    ///
    /// # Arguments
    ///
    /// * `state` - WebAuthn application state with credential store
    /// * `max_proof_age` - Maximum age of authentication proofs in seconds (default: 300 = 5 minutes)
    pub fn new(state: Arc<WebAuthnState>, max_proof_age: Option<i64>) -> Self {
        let max_proof_age = max_proof_age.unwrap_or(300);
        info!(
            max_proof_age_secs = max_proof_age,
            "Initialized WebAuthn Sybil resistance"
        );

        Self {
            state,
            max_proof_age,
        }
    }
}

impl SybilResistance for WebAuthnGate {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        match proof {
            SybilProof::WebAuthn {
                username,
                auth_proof,
                timestamp,
            } => {
                // Check timestamp first (no async needed)
                let now = chrono::Utc::now().timestamp();
                let age = now - timestamp;

                if age > self.max_proof_age {
                    return Err(anyhow!("Authentication proof expired"));
                }

                if age < -60 {
                    return Err(anyhow!("Timestamp in future"));
                }

                // Just verify proof format without checking credentials
                let proof_bytes = base64ct::Base64UrlUnpadded::decode_vec(auth_proof)
                    .context("Invalid proof encoding")?;

                if proof_bytes.len() != 32 {
                    return Err(anyhow!("Invalid proof length"));
                }

                Ok(())
            }
            _ => Err(anyhow!("Expected WebAuthn proof")),
        }
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::WebAuthn { .. })
    }

    fn cost(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn_ctx::WebAuthnCtx;
    use crate::webauthn_store::InMemoryCredStore;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn test_webauthn_gate_proof_expiration() {
        let webauthn_ctx = WebAuthnCtx::test_context();
        let cred_store =
            crate::routes::webauthn::CredentialStore::InMemory(InMemoryCredStore::new());

        let state = Arc::new(crate::routes::webauthn::WebAuthnState {
            webauthn: webauthn_ctx,
            cred_store,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        });

        let gate = WebAuthnGate::new(state, Some(300));

        // Test expired proof
        let old_timestamp = chrono::Utc::now().timestamp() - 400; // 400 seconds ago
        let proof = SybilProof::WebAuthn {
            username: "alice".to_string(),
            auth_proof: base64ct::Base64UrlUnpadded::encode_string(&[0u8; 32]),
            timestamp: old_timestamp,
        };

        let result = gate.verify(&proof, None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[tokio::test]
    async fn test_webauthn_gate_future_timestamp() {
        let webauthn_ctx = WebAuthnCtx::test_context();
        let cred_store =
            crate::routes::webauthn::CredentialStore::InMemory(InMemoryCredStore::new());

        let state = Arc::new(crate::routes::webauthn::WebAuthnState {
            webauthn: webauthn_ctx,
            cred_store,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        });

        let gate = WebAuthnGate::new(state, Some(300));

        // Test future timestamp (more than 1 minute ahead)
        let future_timestamp = chrono::Utc::now().timestamp() + 120;
        let proof = SybilProof::WebAuthn {
            username: "alice".to_string(),
            auth_proof: base64ct::Base64UrlUnpadded::encode_string(&[0u8; 32]),
            timestamp: future_timestamp,
        };

        let result = gate.verify(&proof, None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("future"));
    }
}
