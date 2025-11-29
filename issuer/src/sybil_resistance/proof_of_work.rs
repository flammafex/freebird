// issuer/src/sybil_resistance/proof_of_work.rs
//! Proof-of-Work Sybil resistance
//!
//! ...
//!
//! # Example
//!
//! ```rust
//! use freebird_issuer::sybil_resistance::{ProofOfWork, SybilResistance};
//! use freebird_common::api::SybilProof;
//!
//! # fn main() -> anyhow::Result<()> {
//! let difficulty = 1; // Low difficulty for test
//! let input = "test_input";
//! let timestamp = freebird_issuer::sybil_resistance::current_timestamp();
//!
//! // Client side: compute proof
//! let (nonce, hash) = ProofOfWork::compute(difficulty, &input, timestamp)?;
//! let proof = SybilProof::ProofOfWork { nonce, input: input.to_string(), timestamp };
//!
//! // Server side: verify
//! let checker = ProofOfWork::new(difficulty);
//! checker.verify(&proof)?;
//! # Ok(())
//! # }
//! ```

use super::{verify_timestamp_recent, SybilResistance};
use freebird_common::api::SybilProof; // Use shared type
use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

/// Proof-of-Work Sybil resistance mechanism
///
/// Requires clients to find a nonce such that:
/// `SHA256(input || nonce || timestamp)` has `difficulty` leading zero bits
pub struct ProofOfWork {
    /// Number of leading zero bits required (1-256)
    ///
    /// Recommended values:
    /// - 16 bits: ~65k hashes (~instant on modern CPU)
    /// - 20 bits: ~1M hashes (~1 second)
    /// - 24 bits: ~16M hashes (~10-30 seconds)
    /// - 28 bits: ~268M hashes (~5-10 minutes)
    difficulty: u32,

    /// Maximum age of timestamp (prevents pre-computation)
    max_timestamp_age_secs: u64,
}

impl ProofOfWork {
    /// Create new Proof-of-Work checker
    ///
    /// # Arguments
    ///
    /// * `difficulty` - Number of leading zero bits (1-256)
    ///
    /// # Panics
    ///
    /// Panics if difficulty is 0 or > 256
    pub fn new(difficulty: u32) -> Self {
        assert!(difficulty > 0 && difficulty <= 256, "invalid difficulty");
        Self {
            difficulty,
            max_timestamp_age_secs: 300, // 5 minutes
        }
    }

    /// Create with custom timestamp window
    pub fn with_timestamp_window(mut self, secs: u64) -> Self {
        self.max_timestamp_age_secs = secs;
        self
    }

    /// Compute proof-of-work (client-side helper)
    ///
    /// Searches for a nonce that produces a hash with required leading zeros.
    /// Returns (nonce, resulting_hash).
    ///
    /// # Warning
    ///
    /// This can take a long time for high difficulty values.
    /// Difficulty 24 takes ~10-30 seconds on modern hardware.
    pub fn compute(difficulty: u32, input: &str, timestamp: u64) -> Result<(u64, Vec<u8>)> {
        if difficulty > 32 {
            return Err(anyhow!(
                "difficulty too high for compute(): {} (max 32)",
                difficulty
            ));
        }

        let required_zeros = difficulty / 8; // Full zero bytes
        let remaining_bits = difficulty % 8;

        for nonce in 0..u64::MAX {
            let hash = Self::hash_pow(input, nonce, timestamp);

            // Check full zero bytes
            if !hash[..required_zeros as usize].iter().all(|&b| b == 0) {
                continue;
            }

            // Check remaining bits in next byte (if any)
            if remaining_bits > 0 {
                let next_byte = hash[required_zeros as usize];
                let mask = 0xFF << (8 - remaining_bits);
                if next_byte & mask != 0 {
                    continue;
                }
            }

            return Ok((nonce, hash));
        }

        Err(anyhow!("exhausted nonce space (extremely unlikely)"))
    }

    /// Hash function for proof-of-work
    fn hash_pow(input: &str, nonce: u64, timestamp: u64) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hasher.update(nonce.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.finalize().to_vec()
    }

    /// Verify proof-of-work has required leading zeros
    fn verify_hash(&self, hash: &[u8]) -> Result<()> {
        let required_zeros = self.difficulty / 8;
        let remaining_bits = self.difficulty % 8;

        // Check full zero bytes
        for i in 0..required_zeros {
            if hash[i as usize] != 0 {
                return Err(anyhow!("insufficient leading zeros at byte {}", i));
            }
        }

        // Check remaining bits
        if remaining_bits > 0 {
            let next_byte = hash[required_zeros as usize];
            let mask = 0xFF << (8 - remaining_bits);
            if next_byte & mask != 0 {
                return Err(anyhow!(
                    "insufficient leading zeros in partial byte (need {} more bits)",
                    remaining_bits
                ));
            }
        }

        Ok(())
    }
}

impl SybilResistance for ProofOfWork {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        let (nonce, input, timestamp) = match proof {
            SybilProof::ProofOfWork {
                nonce,
                input,
                timestamp,
            } => (*nonce, input.as_str(), *timestamp),
            _ => return Err(anyhow!("expected ProofOfWork proof")),
        };

        // Check timestamp is recent (prevents pre-computation)
        verify_timestamp_recent(timestamp, self.max_timestamp_age_secs)?;

        // Recompute hash
        let hash = Self::hash_pow(input, nonce, timestamp);

        // Verify leading zeros
        self.verify_hash(&hash)?;

        Ok(())
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::ProofOfWork { .. })
    }

    fn cost(&self) -> u64 {
        // Approximate number of hashes required
        2u64.pow(self.difficulty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sybil_resistance::current_timestamp;
    #[test]
    fn test_pow_difficulty_16() {
        let difficulty = 16; // ~65k hashes
        let checker = ProofOfWork::new(difficulty);
        let input = "test_input";
        let timestamp = current_timestamp();

        let (nonce, hash) =
            ProofOfWork::compute(difficulty, input, timestamp).expect("should find nonce");

        println!(
            "Found nonce {} with hash {:02x?} (difficulty {})",
            nonce,
            &hash[..4],
            difficulty
        );

        // Create proof
        let proof = SybilProof::ProofOfWork {
            nonce,
            input: input.to_string(),
            timestamp,
        };

        // Verify
        assert!(checker.verify(&proof).is_ok());
    }

    #[test]
    fn test_pow_invalid_nonce() {
        let difficulty = 16;
        let checker = ProofOfWork::new(difficulty);
        let timestamp = current_timestamp();

        // Use wrong nonce
        let proof = SybilProof::ProofOfWork {
            nonce: 12345,
            input: "test".to_string(),
            timestamp,
        };

        // Should fail
        assert!(checker.verify(&proof).is_err());
    }

    #[test]
    fn test_pow_old_timestamp() {
        let difficulty = 16;
        let checker = ProofOfWork::new(difficulty);
        let old_timestamp = current_timestamp() - 600; // 10 minutes ago

        let (nonce, _) = ProofOfWork::compute(difficulty, "test", old_timestamp).expect("compute");

        let proof = SybilProof::ProofOfWork {
            nonce,
            input: "test".to_string(),
            timestamp: old_timestamp,
        };

        // Should fail due to old timestamp
        assert!(checker.verify(&proof).is_err());
    }

    #[test]
    fn test_pow_cost_scaling() {
        let pow16 = ProofOfWork::new(16);
        let pow20 = ProofOfWork::new(20);
        let pow24 = ProofOfWork::new(24);

        assert_eq!(pow16.cost(), 65536);
        assert_eq!(pow20.cost(), 1048576);
        assert_eq!(pow24.cost(), 16777216);

        // Cost increases exponentially
        assert!(pow20.cost() == pow16.cost() * 16);
        assert!(pow24.cost() == pow20.cost() * 16);
    }
}
