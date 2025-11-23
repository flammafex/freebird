// issuer/src/sybil_resistance/mod.rs
//! Sybil resistance mechanisms for Freebird token issuance
//!
//! ...
//!
//! # Architecture
//!
//! ```rust,ignore
//! // FIX: Added 'ignore' because this is pseudo-code (SybilProof::from_request doesn't exist)
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
use std::time::{SystemTime, UNIX_EPOCH};
use common::api::SybilProof;

pub mod invitation;
pub mod proof_of_work;
pub mod rate_limit;
pub mod progressive_trust;

// Re-export the main types so they can be imported as `use sybil_resistance::ProofOfWork`
pub use invitation::ClientData;
pub use proof_of_work::ProofOfWork;
pub use rate_limit::RateLimit;
pub use progressive_trust::{ProgressiveTrustSystem, ProgressiveTrustConfig, TrustLevel};
#[cfg(feature = "human-gate-webauthn")]
pub use crate::webauthn::gate::WebAuthnGate;

pub trait SybilResistance: Send + Sync {
    fn verify(&self, proof: &SybilProof) -> Result<()>; // Keep as fn, not async fn
    fn supports(&self, proof: &SybilProof) -> bool;
    fn cost(&self) -> u64; // Add back the cost method
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
    fn supports(&self, proof: &SybilProof) -> bool { matches!(proof, SybilProof::None) }
    fn cost(&self) -> u64 { 0 }
}

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
        let mut supported_count = 0;
        for mechanism in &self.mechanisms {
            if mechanism.supports(proof) {
                supported_count += 1;
                mechanism.verify(proof)?;
            }
        }
        if supported_count == 0 {
            return Err(anyhow!("proof type not supported by any configured mechanism"));
        }
        Ok(())
    }
    fn supports(&self, proof: &SybilProof) -> bool {
        self.mechanisms.iter().any(|m| m.supports(proof))
    }
    fn cost(&self) -> u64 { 0 }
}

pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

pub fn verify_timestamp_recent(timestamp: u64, window_secs: u64) -> Result<()> {
    let now = current_timestamp();
    let age = now.saturating_sub(timestamp);
    if age > window_secs { return Err(anyhow!("timestamp too old")); }
    if timestamp > now + 300 { return Err(anyhow!("timestamp in future")); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let combined = CombinedSybilResistance::new(vec![Box::new(ProofOfWork::new(16))]);

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
