// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Rate limiting for admin API authentication attempts
//!
//! This module provides protection against brute-force attacks on the admin API key
//! by tracking failed authentication attempts per IP address and temporarily blocking
//! IPs that exceed the allowed failure threshold.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::warn;

/// Configuration for admin authentication rate limiting
#[derive(Debug, Clone)]
pub struct AdminRateLimitConfig {
    /// Maximum number of failed attempts before blocking
    pub max_failures: u32,
    /// Time window for tracking failures (resets after this duration)
    pub window_duration: Duration,
    /// How long to block an IP after exceeding max_failures
    pub block_duration: Duration,
}

impl Default for AdminRateLimitConfig {
    fn default() -> Self {
        Self {
            max_failures: 5,
            window_duration: Duration::from_secs(5 * 60),  // 5 minutes
            block_duration: Duration::from_secs(15 * 60), // 15 minutes
        }
    }
}

/// Tracks authentication attempts for a single IP
#[derive(Debug, Clone)]
struct IpAttemptRecord {
    /// Number of failed attempts in the current window
    failure_count: u32,
    /// When the tracking window started
    window_start: Instant,
    /// If blocked, when the block expires (None if not blocked)
    blocked_until: Option<Instant>,
}

impl IpAttemptRecord {
    fn new() -> Self {
        Self {
            failure_count: 0,
            window_start: Instant::now(),
            blocked_until: None,
        }
    }

    /// Check if this IP is currently blocked
    fn is_blocked(&self) -> bool {
        if let Some(blocked_until) = self.blocked_until {
            Instant::now() < blocked_until
        } else {
            false
        }
    }

    /// Reset the tracking window if it has expired
    fn maybe_reset_window(&mut self, window_duration: Duration) {
        if self.window_start.elapsed() > window_duration {
            self.failure_count = 0;
            self.window_start = Instant::now();
        }
    }
}

/// Rate limiter for admin API authentication
#[derive(Clone)]
pub struct AdminRateLimiter {
    config: AdminRateLimitConfig,
    attempts: Arc<RwLock<HashMap<IpAddr, IpAttemptRecord>>>,
}

impl AdminRateLimiter {
    /// Create a new rate limiter with default configuration
    pub fn new() -> Self {
        Self::with_config(AdminRateLimitConfig::default())
    }

    /// Create a new rate limiter with custom configuration
    pub fn with_config(config: AdminRateLimitConfig) -> Self {
        Self {
            config,
            attempts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if an IP is allowed to attempt authentication
    /// Returns Ok(()) if allowed, Err with seconds until unblock if blocked
    pub async fn check_allowed(&self, ip: IpAddr) -> Result<(), u64> {
        let attempts = self.attempts.read().await;

        if let Some(record) = attempts.get(&ip) {
            if let Some(blocked_until) = record.blocked_until {
                let now = Instant::now();
                if now < blocked_until {
                    let remaining = blocked_until.duration_since(now);
                    return Err(remaining.as_secs());
                }
            }
        }

        Ok(())
    }

    /// Record a failed authentication attempt
    /// Returns true if the IP is now blocked
    pub async fn record_failure(&self, ip: IpAddr) -> bool {
        let mut attempts = self.attempts.write().await;

        let record = attempts.entry(ip).or_insert_with(IpAttemptRecord::new);

        // Reset window if expired
        record.maybe_reset_window(self.config.window_duration);

        // Increment failure count
        record.failure_count += 1;

        // Check if we should block
        if record.failure_count >= self.config.max_failures {
            record.blocked_until = Some(Instant::now() + self.config.block_duration);
            warn!(
                ip = %ip,
                failures = record.failure_count,
                block_minutes = self.config.block_duration.as_secs() / 60,
                "Admin API: IP blocked due to too many failed authentication attempts"
            );
            true
        } else {
            warn!(
                ip = %ip,
                failures = record.failure_count,
                max = self.config.max_failures,
                "Admin API: failed authentication attempt"
            );
            false
        }
    }

    /// Record a successful authentication (resets failure count)
    pub async fn record_success(&self, ip: IpAddr) {
        let mut attempts = self.attempts.write().await;
        attempts.remove(&ip);
    }

    /// Clean up expired records (should be called periodically)
    pub async fn cleanup_expired(&self) {
        let mut attempts = self.attempts.write().await;
        let now = Instant::now();

        attempts.retain(|_, record| {
            // Keep if blocked and block hasn't expired
            if let Some(blocked_until) = record.blocked_until {
                if now < blocked_until {
                    return true;
                }
            }
            // Keep if window hasn't expired
            record.window_start.elapsed() < self.config.window_duration
        });
    }

    /// Get the number of currently tracked IPs (for monitoring)
    pub async fn tracked_ip_count(&self) -> usize {
        self.attempts.read().await.len()
    }

    /// Get the number of currently blocked IPs (for monitoring)
    pub async fn blocked_ip_count(&self) -> usize {
        let attempts = self.attempts.read().await;
        attempts.values().filter(|r| r.is_blocked()).count()
    }
}

impl Default for AdminRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_allows_initial_attempt() {
        let limiter = AdminRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        assert!(limiter.check_allowed(ip).await.is_ok());
    }

    #[tokio::test]
    async fn test_blocks_after_max_failures() {
        let config = AdminRateLimitConfig {
            max_failures: 3,
            window_duration: Duration::from_secs(60),
            block_duration: Duration::from_secs(60),
        };
        let limiter = AdminRateLimiter::with_config(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Record failures
        assert!(!limiter.record_failure(ip).await); // 1
        assert!(!limiter.record_failure(ip).await); // 2
        assert!(limiter.record_failure(ip).await);  // 3 - should block

        // Should be blocked now
        assert!(limiter.check_allowed(ip).await.is_err());
    }

    #[tokio::test]
    async fn test_success_resets_count() {
        let config = AdminRateLimitConfig {
            max_failures: 3,
            window_duration: Duration::from_secs(60),
            block_duration: Duration::from_secs(60),
        };
        let limiter = AdminRateLimiter::with_config(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Record some failures
        limiter.record_failure(ip).await;
        limiter.record_failure(ip).await;

        // Success resets
        limiter.record_success(ip).await;

        // Should need 3 more failures to block
        assert!(!limiter.record_failure(ip).await);
        assert!(!limiter.record_failure(ip).await);
        assert!(limiter.record_failure(ip).await);
    }

    #[tokio::test]
    async fn test_different_ips_tracked_separately() {
        let config = AdminRateLimitConfig {
            max_failures: 2,
            window_duration: Duration::from_secs(60),
            block_duration: Duration::from_secs(60),
        };
        let limiter = AdminRateLimiter::with_config(config);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Block ip1
        limiter.record_failure(ip1).await;
        limiter.record_failure(ip1).await;

        // ip1 blocked, ip2 should be fine
        assert!(limiter.check_allowed(ip1).await.is_err());
        assert!(limiter.check_allowed(ip2).await.is_ok());
    }
}
