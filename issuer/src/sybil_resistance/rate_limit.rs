// issuer/src/sybil_resistance/rate_limit.rs
//! Rate-limiting Sybil resistance
//!
//! Context-aware issuance always shares a primary budget per validated IP.
//! This is weak Sybil resistance (bypassable with VPNs) but simple to implement.
//! Clients behind the same NAT share this budget, even with different browsers
//! or User-Agent values; fingerprints cannot grant additional allowances.
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

use super::{current_timestamp, SybilRequestContext, SybilResistance};
use anyhow::{anyhow, Result};
use base64ct::Encoding;
use freebird_common::api::SybilProof; // Use shared type
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Rate-limiting Sybil resistance
///
/// Tracks last issuance time per client_id and enforces minimum interval.
/// Context-aware verification anchors the budget to the server-observed IP;
/// fingerprint-derived proof IDs are accepted for compatibility only.
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

    /// Validate the client timestamp and return the server timestamp to use for
    /// rate-limit accounting.
    fn server_timestamp_for(&self, client_timestamp: u64) -> Result<u64> {
        let server_timestamp = current_timestamp();
        if client_timestamp.abs_diff(server_timestamp) > self.max_timestamp_age_secs {
            return Err(anyhow!("timestamp outside allowed clock-skew window"));
        }

        Ok(server_timestamp)
    }

    /// Check if client has requested recently, using only server time.
    fn check_rate_limit(&self, client_id: &str, server_timestamp: u64) -> Result<()> {
        let mut state = self.state.write().unwrap();

        // Cleanup old entries (simple approach)
        state.retain(|_, &mut last_time| {
            server_timestamp.saturating_sub(last_time) < self.cleanup_after_secs
        });

        // Check if client exists
        if let Some(&last_time) = state.get(client_id) {
            let elapsed = server_timestamp.saturating_sub(last_time);

            if elapsed < self.min_interval.as_secs() {
                let remaining = self.min_interval.as_secs() - elapsed;
                return Err(anyhow!(
                    "rate limit exceeded: please wait {} more seconds",
                    remaining
                ));
            }
        }

        // Update last issuance time
        state.insert(client_id.to_string(), server_timestamp);
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

        let server_timestamp = self.server_timestamp_for(timestamp)?;

        // Check rate limit
        self.check_rate_limit(client_id, server_timestamp)?;

        Ok(())
    }

    fn verify_with_context(&self, proof: &SybilProof, ctx: &SybilRequestContext) -> Result<()> {
        let (client_id, timestamp) = match proof {
            SybilProof::RateLimit {
                client_id,
                timestamp,
            } => (client_id.as_str(), *timestamp),
            _ => return Err(anyhow!("expected RateLimit proof")),
        };

        let server_timestamp = self.server_timestamp_for(timestamp)?;

        let observed = ctx
            .client_data
            .as_ref()
            .ok_or_else(|| anyhow!("server-observed client data required for rate limiting"))?;
        let ip = observed
            .ip_addr
            .as_deref()
            .ok_or_else(|| anyhow!("server-observed IP required for rate limiting"))?;
        let primary_client_id = client_id_from_ip(ip);
        // Preserve existing proof IDs, but never use a client-controlled
        // fingerprint to partition the mandatory IP budget.
        let expected_client_id = match &observed.fingerprint {
            Some(fingerprint) => client_id_from_fingerprint(ip, fingerprint),
            None => primary_client_id.clone(),
        };

        if !client_id.is_empty() && client_id != expected_client_id {
            return Err(anyhow!(
                "rate limit client_id does not match observed request"
            ));
        }

        self.check_rate_limit(&primary_client_id, server_timestamp)?;
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
    fn test_rate_limit_rejects_stale_and_future_timestamps() {
        let limiter = RateLimit::new(Duration::from_secs(60));
        let now = current_timestamp();
        let outside_window = limiter.max_timestamp_age_secs + 2;

        let stale = SybilProof::RateLimit {
            client_id: "stale-client".to_string(),
            timestamp: now.saturating_sub(outside_window),
        };
        assert!(limiter.verify(&stale).is_err());

        let future = SybilProof::RateLimit {
            client_id: "future-client".to_string(),
            timestamp: now.saturating_add(outside_window),
        };
        assert!(limiter.verify(&future).is_err());
    }

    #[test]
    fn test_rate_limit_interval_uses_server_time_not_proof_timestamp() {
        let limiter = RateLimit::new(Duration::from_secs(60));
        let timestamp = current_timestamp();

        let first = SybilProof::RateLimit {
            client_id: "client1".to_string(),
            timestamp,
        };
        assert!(limiter.verify(&first).is_ok());

        // A client-controlled timestamp that claims the full interval has
        // elapsed must not bypass the server-side interval check.
        let forged_elapsed = SybilProof::RateLimit {
            client_id: "client1".to_string(),
            timestamp: timestamp + limiter.min_interval.as_secs(),
        };
        assert!(limiter.verify(&forged_elapsed).is_err());
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
    fn test_rate_limit_cleanup_handles_stale_and_future_entries() {
        let limiter = RateLimit::new(Duration::from_secs(60));
        let now = current_timestamp();
        let stale_timestamp = now.saturating_sub(limiter.cleanup_after_secs + 1);
        let future_timestamp = now.saturating_add(1);

        {
            let mut state = limiter.state.write().unwrap();
            state.insert("stale-client".to_string(), stale_timestamp);
            state.insert("future-client".to_string(), future_timestamp);
        }

        // Cleanup must not underflow when an entry is ahead of server time.
        limiter.check_rate_limit("new-client", now).unwrap();

        let state = limiter.state.read().unwrap();
        assert!(!state.contains_key("stale-client"));
        assert!(state.contains_key("future-client"));
        assert_eq!(state.get("new-client"), Some(&now));
    }

    #[test]
    fn test_rate_limit_context_uses_observed_client_id() {
        let limiter = RateLimit::new(Duration::from_secs(60));
        let timestamp = current_timestamp();
        let ctx = SybilRequestContext {
            client_data: Some(
                crate::sybil_resistance::ClientData::from_ip_and_fingerprint(
                    "203.0.113.10",
                    "ua-hash",
                ),
            ),
            ..Default::default()
        };
        let expected = client_id_from_fingerprint("203.0.113.10", "ua-hash");

        let proof = SybilProof::RateLimit {
            client_id: expected,
            timestamp,
        };
        assert!(limiter.verify_with_context(&proof, &ctx).is_ok());

        let forged = SybilProof::RateLimit {
            client_id: "attacker-chosen-id".to_string(),
            timestamp: timestamp + 61,
        };
        assert!(limiter.verify_with_context(&forged, &ctx).is_err());
    }

    #[test]
    fn test_rate_limit_user_agent_rotation_shares_validated_ip_budget() {
        use axum::{http::HeaderMap, Extension};
        use freebird_common::tls_enforcement::ValidatedClientIp;

        let limiter = RateLimit::new(Duration::from_secs(60));
        // Exercise both server-derived (empty) and legacy fingerprint proof IDs.
        for explicit_id in [false, true] {
            limiter.clear();
            for (index, user_agent) in [Some("browser-a"), Some("browser-b"), None, Some("")]
                .into_iter()
                .enumerate()
            {
                let mut headers = HeaderMap::new();
                if let Some(user_agent) = user_agent {
                    headers.insert("user-agent", user_agent.parse().unwrap());
                }
                for ip in ["203.0.113.10", "203.0.113.11"] {
                    let observed = crate::routes::issue::extract_client_data(
                        None,
                        false,
                        &headers,
                        Some(Extension(ValidatedClientIp(ip.parse().unwrap()))),
                    );
                    let client_id = if explicit_id {
                        match &observed.fingerprint {
                            Some(fp) => client_id_from_fingerprint(ip, fp),
                            None => client_id_from_ip(ip),
                        }
                    } else {
                        String::new()
                    };
                    let proof = SybilProof::RateLimit {
                        client_id,
                        timestamp: current_timestamp(),
                    };
                    let ctx = SybilRequestContext {
                        client_data: Some(observed),
                        ..Default::default()
                    };
                    let result = limiter.verify_with_context(&proof, &ctx);
                    if index == 0 {
                        result.unwrap();
                    } else {
                        assert!(result
                            .unwrap_err()
                            .to_string()
                            .contains("rate limit exceeded"));
                    }
                }
            }
            assert_eq!(limiter.tracked_clients(), 2);
        }
    }

    #[test]
    fn test_rate_limit_requires_ip_even_with_user_agent() {
        use axum::http::HeaderMap;

        let limiter = RateLimit::new(Duration::from_secs(60));
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "browser-a".parse().unwrap());
        let ctx = SybilRequestContext {
            client_data: Some(crate::routes::issue::extract_client_data(
                None, false, &headers, None,
            )),
            ..Default::default()
        };
        let proof = SybilProof::RateLimit {
            client_id: String::new(),
            timestamp: current_timestamp(),
        };
        assert!(limiter
            .verify_with_context(&proof, &ctx)
            .unwrap_err()
            .to_string()
            .contains("server-observed IP required"));
        assert_eq!(limiter.tracked_clients(), 0);
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
