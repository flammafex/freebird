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
use std::sync::Arc;
use freebird_common::api::SybilProof;

pub mod invitation;
pub mod proof_of_work;
pub mod rate_limit;
pub mod progressive_trust;
pub mod proof_of_diversity;
pub mod multi_party_vouching;
pub mod federated_trust;

// Re-export the main types so they can be imported as `use sybil_resistance::ProofOfWork`
pub use invitation::ClientData;
pub use proof_of_work::ProofOfWork;
pub use rate_limit::RateLimit;
pub use progressive_trust::{ProgressiveTrustSystem, ProgressiveTrustConfig, TrustLevel};
pub use proof_of_diversity::{ProofOfDiversitySystem, ProofOfDiversityConfig};
pub use multi_party_vouching::{MultiPartyVouchingSystem, MultiPartyVouchingConfig};
pub use federated_trust::{FederatedTrustSystem, FederatedTrustConfig};
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

/// Combined OR: Client provides ONE proof, at least one mechanism must support it
/// This is the same as CombinedSybilResistance but with an explicit name
pub struct CombinedOr {
    mechanisms: Vec<Arc<dyn SybilResistance>>,
}

impl CombinedOr {
    pub fn new(mechanisms: Vec<Arc<dyn SybilResistance>>) -> Self {
        Self { mechanisms }
    }
}

impl SybilResistance for CombinedOr {
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
    fn cost(&self) -> u64 {
        // Return average cost of all mechanisms
        if self.mechanisms.is_empty() {
            return 0;
        }
        self.mechanisms.iter().map(|m| m.cost()).sum::<u64>() / self.mechanisms.len() as u64
    }
}

/// Combined AND: Client provides MULTIPLE proofs, ALL mechanisms must pass
pub struct CombinedAnd {
    mechanisms: Vec<Arc<dyn SybilResistance>>,
}

impl CombinedAnd {
    pub fn new(mechanisms: Vec<Arc<dyn SybilResistance>>) -> Self {
        Self { mechanisms }
    }
}

impl SybilResistance for CombinedAnd {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        match proof {
            SybilProof::Multi { proofs } => {
                if proofs.len() != self.mechanisms.len() {
                    return Err(anyhow!(
                        "expected {} proofs for AND combination, got {}",
                        self.mechanisms.len(),
                        proofs.len()
                    ));
                }

                // Each mechanism must find and verify its corresponding proof
                for mechanism in &self.mechanisms {
                    let mut verified = false;
                    for proof in proofs {
                        if mechanism.supports(proof) {
                            mechanism.verify(proof)?;
                            verified = true;
                            break;
                        }
                    }
                    if !verified {
                        return Err(anyhow!("missing proof for one or more required mechanisms"));
                    }
                }
                Ok(())
            }
            _ => Err(anyhow!("AND combination requires Multi proof with all mechanisms")),
        }
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::Multi { .. })
    }

    fn cost(&self) -> u64 {
        // Return sum of all mechanism costs
        self.mechanisms.iter().map(|m| m.cost()).sum()
    }
}

/// Combined Threshold: Client provides MULTIPLE proofs, at least N must pass
pub struct CombinedThreshold {
    mechanisms: Vec<Arc<dyn SybilResistance>>,
    threshold: usize,
}

impl CombinedThreshold {
    pub fn new(mechanisms: Vec<Arc<dyn SybilResistance>>, threshold: usize) -> Result<Self> {
        if threshold == 0 {
            return Err(anyhow!("threshold must be at least 1"));
        }
        if threshold > mechanisms.len() {
            return Err(anyhow!(
                "threshold ({}) cannot exceed number of mechanisms ({})",
                threshold,
                mechanisms.len()
            ));
        }
        Ok(Self { mechanisms, threshold })
    }
}

impl SybilResistance for CombinedThreshold {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        match proof {
            SybilProof::Multi { proofs } => {
                let mut passed = 0;
                let mut errors = Vec::new();

                // Try to verify each proof with its corresponding mechanism
                for proof in proofs {
                    for mechanism in &self.mechanisms {
                        if mechanism.supports(proof) {
                            match mechanism.verify(proof) {
                                Ok(()) => {
                                    passed += 1;
                                    break;
                                }
                                Err(e) => {
                                    errors.push(format!("{}", e));
                                }
                            }
                        }
                    }
                }

                if passed >= self.threshold {
                    Ok(())
                } else {
                    Err(anyhow!(
                        "threshold not met: passed {}/{}, need {} (errors: {})",
                        passed,
                        proofs.len(),
                        self.threshold,
                        errors.join("; ")
                    ))
                }
            }
            _ => Err(anyhow!("threshold combination requires Multi proof")),
        }
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::Multi { .. })
    }

    fn cost(&self) -> u64 {
        // Return average cost weighted by threshold
        if self.mechanisms.is_empty() {
            return 0;
        }
        let total_cost: u64 = self.mechanisms.iter().map(|m| m.cost()).sum();
        (total_cost * self.threshold as u64) / self.mechanisms.len() as u64
    }
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
