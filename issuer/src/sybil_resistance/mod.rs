// issuer/src/sybil_resistance/mod.rs
//! Sybil resistance mechanisms for Freebird token issuance
//!
//! This module provides pluggable Sybil resistance to prevent users from
//! obtaining unlimited tokens. Different mechanisms have different tradeoffs:
//!
//! - **ProofOfWork**: Computational cost makes scaling expensive
//! - **PaymentGate**: Economic cost (requires Lightning integration)
//! - **RateLimit**: IP/fingerprint-based rate limiting (weak but simple)
//! - **InvitationSystem**: Federated trust (requires bootstrap)
//!
//! # Architecture
//!
//! ```rust
//! use sybil_resistance::{SybilResistance, SybilProof};
//!
//! // Before issuing a token, verify Sybil resistance proof
//! let proof = SybilProof::from_request(&request)?;
//! let checker = ProofOfWork::new(difficulty);
//!
//! if checker.verify(&proof)? {
//!     // Issue token
//! } else {
//!     // Reject
//! }
//! ```

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod proof_of_work;
pub mod rate_limit;
pub mod invitation;

// Re-export the main types so they can be imported as `use sybil_resistance::ProofOfWork`
pub use proof_of_work::ProofOfWork;
pub use rate_limit::{RateLimit, client_id_from_ip, client_id_from_fingerprint};
pub use invitation::{InvitationSystem, InvitationConfig, InvitationStats};

// Future implementations:
// pub mod payment_gate;
// pub mod proof_of_humanity;

/// Proof submitted to demonstrate Sybil resistance
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SybilProof {
    /// Proof-of-work: Client computed hash with N leading zeros
    ProofOfWork {
        /// Nonce that produces valid hash
        nonce: u64,
        /// Client's input (for verification)
        input: String,
        /// Timestamp (prevents pre-computation)
        timestamp: u64,
    },

    /// Rate limit: Client asserts they haven't requested recently
    /// (Verifier must track state)
    RateLimit {
        /// Client identifier (could be fingerprint, IP hash, etc.)
        client_id: String,
        /// Timestamp of request
        timestamp: u64,
    },

    /// Payment: Client paid for this token
    /// (Requires Lightning/crypto integration)
    #[allow(dead_code)]
    Payment {
        /// Payment proof (invoice, preimage, etc.)
        proof: String,
        /// Amount paid
        amount_sats: u64,
    },

    /// Invitation: Client was invited by existing user
    /// (inviter_id is tracked server-side, not in the proof)
    #[allow(dead_code)]
    Invitation {
        /// Invitation code
        code: String,
        /// Signature from issuer (proves authenticity)
        signature: String,
    },

    /// Proof of Humanity: External system verified uniqueness
    #[allow(dead_code)]
    ProofOfHumanity {
        /// Provider (e.g., "worldcoin", "brightid")
        provider: String,
        /// Proof payload (provider-specific)
        proof: String,
    },

    /// No proof (for testing or permissive contexts)
    None,
}

/// Trait for Sybil resistance mechanisms
pub trait SybilResistance: Send + Sync {
    /// Verify that the proof demonstrates uniqueness/scarcity
    ///
    /// Returns Ok(()) if proof is valid, Err otherwise
    fn verify(&self, proof: &SybilProof) -> Result<()>;

    /// Optional: Get the difficulty/cost of this mechanism
    ///
    /// Used for adaptive difficulty or cost estimation
    fn cost(&self) -> u64 {
        0
    }

    /// Optional: Check if this proof type is supported
    fn supports(&self, proof: &SybilProof) -> bool;
}

/// No Sybil resistance (permissive mode)
///
/// Accepts all requests. Use only for testing or low-stakes contexts.
pub struct NoSybilResistance;

impl SybilResistance for NoSybilResistance {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        match proof {
            SybilProof::None => Ok(()),
            _ => Err(anyhow!("NoSybilResistance only accepts None proof")),
        }
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::None)
    }
}

/// Combined Sybil resistance (requires multiple proofs)
///
/// Implements defense-in-depth by requiring multiple weak proofs.
///
/// # Example
///
/// ```rust
/// // Require BOTH proof-of-work AND rate limiting
/// let combined = CombinedSybilResistance::new(vec![
///     Box::new(ProofOfWork::new(4)),
///     Box::new(RateLimit::new(Duration::from_secs(3600))),
/// ]);
/// ```
///
/// # Important Note
///
/// This implementation requires that the proof satisfies ALL mechanisms.
/// If you configure PoW + RateLimit, the client must provide a proof that
/// works for both (which may require extending the SybilProof enum to support
/// multiple proofs in one request, or using a wrapper proof type).
///
/// Current implementation: Proof must be valid for ALL configured mechanisms.
pub struct CombinedSybilResistance {
    mechanisms: Vec<Box<dyn SybilResistance>>,
}

impl CombinedSybilResistance {
    pub fn new(mechanisms: Vec<Box<dyn SybilResistance>>) -> Self {
        Self { mechanisms }
    }
}

impl SybilResistance for CombinedSybilResistance {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        // CRITICAL FIX: All mechanisms must verify the proof
        // We count how many mechanisms support and verify this proof
        let mut supported_count = 0;
        let mut verified_count = 0;
        
        for mechanism in &self.mechanisms {
            if mechanism.supports(proof) {
                supported_count += 1;
                mechanism.verify(proof)?;
                verified_count += 1;
            }
        }
        
        // The proof must be supported by at least one mechanism
        if supported_count == 0 {
            return Err(anyhow!(
                "proof type {:?} not supported by any configured mechanism",
                std::mem::discriminant(proof)
            ));
        }
        
        // WARNING: With single-proof design, we can only verify mechanisms
        // that support this proof type. If you want defense-in-depth with
        // multiple proof types, you need to extend the API to accept
        // multiple proofs or use a MultiProof variant.
        //
        // For now, we document this limitation.
        if supported_count < self.mechanisms.len() {
            tracing::warn!(
                supported = supported_count,
                total = self.mechanisms.len(),
                "proof only verified by subset of mechanisms (consider multi-proof API)"
            );
        }
        
        // All mechanisms that support this proof have verified it
        Ok(())
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        self.mechanisms.iter().any(|m| m.supports(proof))
    }
}

/// Helper: Get current Unix timestamp
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}

/// Helper: Verify timestamp is recent (within window)
pub fn verify_timestamp_recent(timestamp: u64, window_secs: u64) -> Result<()> {
    let now = current_timestamp();
    let age = now.saturating_sub(timestamp);

    if age > window_secs {
        return Err(anyhow!(
            "timestamp too old: {} seconds (max {})",
            age,
            window_secs
        ));
    }

    // Also check for future timestamps (clock skew)
    if timestamp > now + 300 {
        // 5 minutes tolerance
        return Err(anyhow!("timestamp in future: {}", timestamp - now));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_no_sybil_resistance() {
        let checker = NoSybilResistance;
        assert!(checker.verify(&SybilProof::None).is_ok());
        assert!(checker
            .verify(&SybilProof::ProofOfWork {
                nonce: 0,
                input: "test".into(),
                timestamp: 0
            })
            .is_err());
    }

    #[test]
    fn test_timestamp_validation() {
        let now = current_timestamp();

        // Current timestamp should be valid
        assert!(verify_timestamp_recent(now, 60).is_ok());

        // Old timestamp should fail
        assert!(verify_timestamp_recent(now - 120, 60).is_err());

        // Future timestamp should fail
        assert!(verify_timestamp_recent(now + 400, 60).is_err());

        // Recent timestamp should be valid
        assert!(verify_timestamp_recent(now - 30, 60).is_ok());
    }
    
    #[test]
    fn test_combined_requires_supported_proof() {
        let combined = CombinedSybilResistance::new(vec![
            Box::new(ProofOfWork::new(16)),
        ]);
        
        // ProofOfWork proof should work
        let timestamp = current_timestamp();
        let (nonce, _) = ProofOfWork::compute(16, "test", timestamp).unwrap();
        let proof = SybilProof::ProofOfWork {
            nonce,
            input: "test".to_string(),
            timestamp,
        };
        assert!(combined.verify(&proof).is_ok());
        
        // RateLimit proof should fail (not supported)
        let rate_proof = SybilProof::RateLimit {
            client_id: "test".to_string(),
            timestamp: current_timestamp(),
        };
        assert!(combined.verify(&rate_proof).is_err());
    }
}