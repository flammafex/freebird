// issuer/src/sybil_resistance/rate_limit.rs
//! Rate-limiting Sybil resistance
//!
//! Limits token issuance by client identifier (IP hash, fingerprint, etc.).
//! This is weak Sybil resistance (bypassable with VPNs) but simple to implement.
//!
//! # Properties
//!
//! - ✓ Simple to implement
//! - ✓ No computation required
//! - ✗ Bypassable (VPNs, Tor, residential proxies)
//! - ✗ Can block legitimate users (shared IPs, NAT)
//! - ✗ Requires state storage
//!
//! # Example
//!
//! ```rust
//! use freebird_issuer::sybil_resistance::{RateLimit, SybilResistance}; // FIX: Correct import path
//! use freebird_common::api::SybilProof;
//! use std::time::Duration;
//! use freebird_issuer::sybil_resistance::current_timestamp; // FIX: Import helper
//!
//! # fn main() -> anyhow::Result<()> { // FIX: Wrap in main for Error handling
//! // Allow one token per client per hour
//! let limiter = RateLimit::new(Duration::from_secs(3600));
//!
//! let proof = SybilProof::RateLimit {
//!     client_id: "hash_of_ip_or_fingerprint".to_string(),
//!     timestamp: current_timestamp(),
//! };
//!
//! limiter.verify(&proof)?;
//! # Ok(())
//! # }
//! ```

use super::{current_timestamp, verify_timestamp_recent, SybilResistance}; // Remove SybilProof from here if unused in module logic
use freebird_common::api::SybilProof; // Use shared type
use anyhow::{anyhow, Result};
use base64ct::Encoding;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Rate-limiting Sybil resistance
///
/// Tracks last issuance time per client_id and enforces minimum interval.
/// Client IDs should be derived from IP address, browser fingerprint, or both.
pub struct RateLimit {
    /// Minimum time between token requests from same client
    min_interval: Duration,

    /// Maximum timestamp age (prevents replay)
    max_timestamp_age_secs: u64,

    /// Storage for last issuance times
    /// Maps client_id -> last_timestamp
    state: Arc<RwLock<HashMap<String, u64>>>,

    /// Cleanup interval (remove old entries)
    cleanup_after_secs: u64,
}

impl RateLimit {
    /// Create new rate limiter
    ///
    /// # Arguments
    ///
    /// * `min_interval` - Minimum time between requests from same client
    pub fn new(min_interval: Duration) -> Self {
        Self {
            min_interval,
            max_timestamp_age_secs: 60, // 1 minute
            state: Arc::new(RwLock::new(HashMap::new())),
            cleanup_after_secs: min_interval.as_secs() * 2,
        }
    }

    /// Check if client has requested recently
    fn check_rate_limit(&self, client_id: &str, timestamp: u64) -> Result<()> {
        let mut state = self.state.write().unwrap();

        // Cleanup old entries (simple approach)
        let now = current_timestamp();
        state.retain(|_, &mut last_time| now - last_time < self.cleanup_after_secs);

        // Check if client exists
        if let Some(&last_time) = state.get(client_id) {
            let elapsed = timestamp.saturating_sub(last_time);

            if elapsed < self.min_interval.as_secs() {
                let remaining = self.min_interval.as_secs() - elapsed;
                return Err(anyhow!(
                    "rate limit exceeded: please wait {} more seconds",
                    remaining
                ));
            }
        }

        // Update last issuance time
        state.insert(client_id.to_string(), timestamp);
        Ok(())
    }

    /// Get number of tracked clients
    #[allow(dead_code)]
    pub fn tracked_clients(&self) -> usize {
        self.state.read().unwrap().len()
    }

    /// Clear all tracked clients (for testing)
    #[cfg(test)]
    pub fn clear(&self) {
        self.state.write().unwrap().clear();
    }
}

impl SybilResistance for RateLimit {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        let (client_id, timestamp) = match proof {
            SybilProof::RateLimit {
                client_id,
                timestamp,
            } => (client_id.as_str(), *timestamp),
            _ => return Err(anyhow!("expected RateLimit proof")),
        };

        // Validate timestamp is recent
        verify_timestamp_recent(timestamp, self.max_timestamp_age_secs)?;

        // Check rate limit
        self.check_rate_limit(client_id, timestamp)?;

        Ok(())
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::RateLimit { .. })
    }

    fn cost(&self) -> u64 {
        // No computational cost, but time cost
        self.min_interval.as_secs()
    }
}

/// Helper: Derive client ID from IP address (hashed)
///
/// Use this to avoid storing raw IP addresses.
pub fn client_id_from_ip(ip: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"freebird-client-id:");
    hasher.update(ip.as_bytes());
    let hash = hasher.finalize();

    base64ct::Base64UrlUnpadded::encode_string(&hash[..16]) // First 128 bits
}

/// Helper: Derive client ID from fingerprint + IP
pub fn client_id_from_fingerprint(ip: &str, fingerprint: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"freebird-client-id:");
    hasher.update(ip.as_bytes());
    hasher.update(b":");
    hasher.update(fingerprint.as_bytes());
    let hash = hasher.finalize();

    base64ct::Base64UrlUnpadded::encode_string(&hash[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_rate_limit_allows_first_request() {
        let limiter = RateLimit::new(Duration::from_secs(60));
        let timestamp = current_timestamp();

        let proof = SybilProof::RateLimit {
            client_id: "client1".to_string(),
            timestamp,
        };

        // First request should succeed
        assert!(limiter.verify(&proof).is_ok());
    }

    #[test]
    fn test_rate_limit_blocks_rapid_requests() {
        let limiter = RateLimit::new(Duration::from_secs(60));
        let timestamp = current_timestamp();

        let proof1 = SybilProof::RateLimit {
            client_id: "client1".to_string(),
            timestamp,
        };

        // First request succeeds
        assert!(limiter.verify(&proof1).is_ok());

        // Immediate second request fails
        let proof2 = SybilProof::RateLimit {
            client_id: "client1".to_string(),
            timestamp: timestamp + 5, // 5 seconds later
        };

        assert!(limiter.verify(&proof2).is_err());
    }

    #[test]
    fn test_rate_limit_allows_after_interval() {
        let limiter = RateLimit::new(Duration::from_secs(2));
        let timestamp = current_timestamp();

        let proof1 = SybilProof::RateLimit {
            client_id: "client1".to_string(),
            timestamp,
        };

        assert!(limiter.verify(&proof1).is_ok());

        // Wait for interval
        thread::sleep(Duration::from_millis(2100));

        let proof2 = SybilProof::RateLimit {
            client_id: "client1".to_string(),
            timestamp: current_timestamp(),
        };

        // Should succeed after waiting
        assert!(limiter.verify(&proof2).is_ok());
    }

    #[test]
    fn test_rate_limit_separate_clients() {
        let limiter = RateLimit::new(Duration::from_secs(60));
        let timestamp = current_timestamp();

        // Two different clients
        let proof1 = SybilProof::RateLimit {
            client_id: "client1".to_string(),
            timestamp,
        };
        let proof2 = SybilProof::RateLimit {
            client_id: "client2".to_string(),
            timestamp,
        };

        // Both should succeed (different clients)
        assert!(limiter.verify(&proof1).is_ok());
        assert!(limiter.verify(&proof2).is_ok());
    }

    #[test]
    fn test_client_id_derivation() {
        let id1 = client_id_from_ip("192.168.1.1");
        let id2 = client_id_from_ip("192.168.1.1");
        let id3 = client_id_from_ip("192.168.1.2");

        // Same IP produces same ID
        assert_eq!(id1, id2);

        // Different IP produces different ID
        assert_ne!(id1, id3);

        // IDs are base64url encoded (no raw IP)
        assert!(!id1.contains("192"));
    }

    #[test]
    fn test_client_id_with_fingerprint() {
        let id1 = client_id_from_fingerprint("192.168.1.1", "firefox_linux");
        let id2 = client_id_from_fingerprint("192.168.1.1", "chrome_windows");

        // Same IP, different fingerprint = different ID
        assert_ne!(id1, id2);
    }
}
