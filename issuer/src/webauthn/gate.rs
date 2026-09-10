// issuer/src/webauthn/gate.rs
use anyhow::{anyhow, Context, Result};
use base64ct::Encoding;
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::handlers::WebAuthnState;
use crate::sybil_resistance::{
    memory_replay_store, replay_ttl, verify_timestamp_at, ReplayStore, SybilResistance,
    WEBAUTHN_FUTURE_SKEW_SECS,
};
use freebird_common::api::SybilProof;

pub struct WebAuthnGate {
    max_proof_age: i64,
    proof_key: [u8; 32],
    replay_store: Arc<dyn ReplayStore>,
}

impl WebAuthnGate {
    pub fn new(state: Arc<WebAuthnState>, max_proof_age: Option<i64>) -> Self {
        let max_proof_age = max_proof_age.unwrap_or(300);

        // Derive proof verification key from WebAuthn context
        // This creates a deterministic but secret key for HMAC verification
        let proof_key = Self::derive_proof_key(&state.webauthn.rp_id);

        info!(
            max_proof_age_secs = max_proof_age,
            "Initialized WebAuthn Sybil resistance"
        );
        Self {
            max_proof_age,
            proof_key,
            replay_store: memory_replay_store(),
        }
    }

    pub fn with_replay_store(
        state: Arc<WebAuthnState>,
        max_proof_age: Option<i64>,
        replay_store: Arc<dyn ReplayStore>,
    ) -> Self {
        let mut gate = Self::new(state, max_proof_age);
        gate.replay_store = replay_store;
        gate
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
        let (secret_bytes, has_secret) = if let Ok(secret) = std::env::var("WEBAUTHN_PROOF_SECRET")
        {
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
    fn compute_proof(&self, subject_hash: &str, timestamp: i64) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&self.proof_key);
        hasher.update(b"webauthn:auth:");
        hasher.update(subject_hash.as_bytes());
        hasher.update(b":");
        hasher.update(&timestamp.to_le_bytes());
        base64ct::Base64UrlUnpadded::encode_string(hasher.finalize().as_bytes())
    }

    fn reject_replay_or_record(&self, proof: &str) -> Result<()> {
        self.replay_store.mark_once(
            "webauthn",
            proof,
            replay_ttl(
                u64::try_from(self.max_proof_age).context("invalid maximum proof age")?,
                WEBAUTHN_FUTURE_SKEW_SECS,
            )?,
        )
    }
}

impl WebAuthnGate {
    fn verify_at(&self, proof: &SybilProof, now: i64) -> Result<()> {
        match proof {
            SybilProof::WebAuthn {
                subject_hash,
                auth_proof,
                timestamp,
            } => {
                let age = i128::from(now) - i128::from(*timestamp);
                verify_timestamp_at(
                    (*timestamp).into(),
                    now.into(),
                    u64::try_from(self.max_proof_age).context("invalid maximum proof age")?,
                    WEBAUTHN_FUTURE_SKEW_SECS,
                )?;

                // Validate proof format
                let proof_bytes = base64ct::Base64UrlUnpadded::decode_vec(auth_proof)
                    .context("Invalid proof encoding")?;

                if proof_bytes.len() != 32 {
                    return Err(anyhow!(
                        "Invalid proof length: expected 32 bytes, got {}",
                        proof_bytes.len()
                    ));
                }

                // CRITICAL: Verify the proof is cryptographically valid
                // This prevents forgery - only the server can generate valid proofs
                let expected_proof = self.compute_proof(subject_hash, *timestamp);

                if auth_proof != &expected_proof {
                    debug!(
                        subject_hash = %subject_hash,
                        timestamp = timestamp,
                        "WebAuthn proof verification failed: proof mismatch"
                    );
                    return Err(anyhow!("Invalid authentication proof"));
                }

                self.reject_replay_or_record(auth_proof)?;

                debug!(
                    subject_hash = %subject_hash,
                    timestamp = timestamp,
                    age_secs = %age,
                    "WebAuthn proof verified successfully"
                );

                Ok(())
            }
            _ => Err(anyhow!("Expected WebAuthn proof")),
        }
    }
}

impl SybilResistance for WebAuthnGate {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        self.verify_at(proof, chrono::Utc::now().timestamp())
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
    use crate::sybil_resistance::replay_retention_tests::ClockStore;

    #[test]
    fn replay_retention_covers_future_skew_and_inclusive_endpoint() {
        for max_age in [0, 300] {
            let store = Arc::new(ClockStore::default());
            let gate = WebAuthnGate {
                max_proof_age: max_age,
                proof_key: [7; 32],
                replay_store: store.clone(),
            };
            let now = 10_000;
            let timestamp = now + WEBAUTHN_FUTURE_SKEW_SECS as i64;
            let proof = SybilProof::WebAuthn {
                subject_hash: "subject".into(),
                auth_proof: gate.compute_proof("subject", timestamp),
                timestamp,
            };
            assert!(gate.verify_at(&proof, now - 1).is_err());
            gate.verify_at(&proof, now).unwrap();
            let last = max_age as u64 + WEBAUTHN_FUTURE_SKEW_SECS;
            assert_eq!(store.ttls()[0].as_secs(), last + 1);
            store.advance_to(last);
            assert!(gate
                .verify_at(&proof, now + last as i64)
                .unwrap_err()
                .to_string()
                .contains("already used"));
            store.advance_to(last + 1);
            assert!(gate
                .verify_at(&proof, now + last as i64 + 1)
                .unwrap_err()
                .to_string()
                .contains("too old"));
        }
    }

    #[test]
    fn invalid_retention_and_extreme_timestamps_return_errors() {
        for max_proof_age in [-1, i64::MAX] {
            let store = Arc::new(ClockStore::default());
            let gate = WebAuthnGate {
                max_proof_age,
                proof_key: [7; 32],
                replay_store: store.clone(),
            };
            let proof = SybilProof::WebAuthn {
                subject_hash: "s".into(),
                auth_proof: gate.compute_proof("s", 1000),
                timestamp: 1000,
            };
            assert!(gate.verify_at(&proof, 1000).is_err());
            assert!(store.ttls().is_empty());
        }
        let gate = WebAuthnGate {
            max_proof_age: 300,
            proof_key: [7; 32],
            replay_store: memory_replay_store(),
        };
        for timestamp in [i64::MIN, i64::MAX] {
            let proof = SybilProof::WebAuthn {
                subject_hash: "s".into(),
                auth_proof: gate.compute_proof("s", timestamp),
                timestamp,
            };
            assert!(gate.verify_at(&proof, 1000).is_err());
        }
    }
}
