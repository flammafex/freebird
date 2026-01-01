// issuer/src/webauthn/rate_limit.rs
//! Rate limiting for WebAuthn operations to prevent abuse
//!
//! Provides per-IP rate limiting for:
//! - Registration attempts (prevent account enumeration/DoS)
//! - Authentication attempts (prevent brute force)
//! - Session creation (prevent memory exhaustion)

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Configuration for WebAuthn rate limiting
#[derive(Clone, Debug)]
pub struct WebAuthnRateLimitConfig {
    /// Maximum registration attempts per IP per window
    pub max_registration_attempts: u32,
    /// Maximum authentication attempts per IP per window
    pub max_auth_attempts: u32,
    /// Time window for rate limiting (seconds)
    pub window_secs: u64,
    /// How long to block after exceeding limit (seconds)
    pub block_duration_secs: u64,
    /// Maximum total active sessions (memory protection)
    pub max_total_sessions: usize,
    /// Maximum sessions per IP
    pub max_sessions_per_ip: usize,
}

impl Default for WebAuthnRateLimitConfig {
    fn default() -> Self {
        Self {
            max_registration_attempts: 10,  // 10 registration attempts per window
            max_auth_attempts: 20,          // 20 auth attempts per window
            window_secs: 300,               // 5 minute window
            block_duration_secs: 900,       // 15 minute block
            max_total_sessions: 10000,      // Max 10k active sessions
            max_sessions_per_ip: 50,        // Max 50 sessions per IP
        }
    }
}

/// Tracks rate limit state for a single IP
#[derive(Debug, Clone)]
struct IpRateLimitState {
    /// Registration attempts in current window
    registration_attempts: u32,
    /// Authentication attempts in current window
    auth_attempts: u32,
    /// Active sessions from this IP
    active_sessions: u32,
    /// Window start time
    window_start: Instant,
    /// If blocked, when the block expires
    blocked_until: Option<Instant>,
}

impl IpRateLimitState {
    fn new() -> Self {
        Self {
            registration_attempts: 0,
            auth_attempts: 0,
            active_sessions: 0,
            window_start: Instant::now(),
            blocked_until: None,
        }
    }

    fn reset_if_window_expired(&mut self, window_duration: Duration) {
        if self.window_start.elapsed() > window_duration {
            self.registration_attempts = 0;
            self.auth_attempts = 0;
            self.window_start = Instant::now();
        }
    }

    fn is_blocked(&self) -> bool {
        self.blocked_until
            .map(|until| Instant::now() < until)
            .unwrap_or(false)
    }

    fn seconds_until_unblock(&self) -> u64 {
        self.blocked_until
            .map(|until| {
                let now = Instant::now();
                if now < until {
                    (until - now).as_secs()
                } else {
                    0
                }
            })
            .unwrap_or(0)
    }
}

/// WebAuthn rate limiter
#[derive(Clone)]
pub struct WebAuthnRateLimiter {
    config: WebAuthnRateLimitConfig,
    state: Arc<RwLock<HashMap<IpAddr, IpRateLimitState>>>,
    total_sessions: Arc<RwLock<usize>>,
}

impl WebAuthnRateLimiter {
    pub fn new() -> Self {
        Self::with_config(WebAuthnRateLimitConfig::default())
    }

    pub fn with_config(config: WebAuthnRateLimitConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(HashMap::new())),
            total_sessions: Arc::new(RwLock::new(0)),
        }
    }

    /// Check if a registration attempt is allowed for this IP
    pub async fn check_registration_allowed(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        let mut state = self.state.write().await;
        let ip_state = state.entry(ip).or_insert_with(IpRateLimitState::new);

        // Reset window if expired
        ip_state.reset_if_window_expired(Duration::from_secs(self.config.window_secs));

        // Check if blocked
        if ip_state.is_blocked() {
            return Err(RateLimitError::Blocked(ip_state.seconds_until_unblock()));
        }

        // Check registration rate
        if ip_state.registration_attempts >= self.config.max_registration_attempts {
            ip_state.blocked_until = Some(Instant::now() + Duration::from_secs(self.config.block_duration_secs));
            return Err(RateLimitError::TooManyRegistrations(self.config.block_duration_secs));
        }

        // Check session limits
        if ip_state.active_sessions >= self.config.max_sessions_per_ip as u32 {
            return Err(RateLimitError::TooManySessions);
        }

        let total = *self.total_sessions.read().await;
        if total >= self.config.max_total_sessions {
            return Err(RateLimitError::SystemOverloaded);
        }

        Ok(())
    }

    /// Check if an authentication attempt is allowed for this IP
    pub async fn check_auth_allowed(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        let mut state = self.state.write().await;
        let ip_state = state.entry(ip).or_insert_with(IpRateLimitState::new);

        // Reset window if expired
        ip_state.reset_if_window_expired(Duration::from_secs(self.config.window_secs));

        // Check if blocked
        if ip_state.is_blocked() {
            return Err(RateLimitError::Blocked(ip_state.seconds_until_unblock()));
        }

        // Check auth rate
        if ip_state.auth_attempts >= self.config.max_auth_attempts {
            ip_state.blocked_until = Some(Instant::now() + Duration::from_secs(self.config.block_duration_secs));
            return Err(RateLimitError::TooManyAuthAttempts(self.config.block_duration_secs));
        }

        // Check session limits
        if ip_state.active_sessions >= self.config.max_sessions_per_ip as u32 {
            return Err(RateLimitError::TooManySessions);
        }

        let total = *self.total_sessions.read().await;
        if total >= self.config.max_total_sessions {
            return Err(RateLimitError::SystemOverloaded);
        }

        Ok(())
    }

    /// Record a registration attempt
    pub async fn record_registration_attempt(&self, ip: IpAddr) {
        let mut state = self.state.write().await;
        let ip_state = state.entry(ip).or_insert_with(IpRateLimitState::new);
        ip_state.registration_attempts += 1;
    }

    /// Record an authentication attempt
    pub async fn record_auth_attempt(&self, ip: IpAddr) {
        let mut state = self.state.write().await;
        let ip_state = state.entry(ip).or_insert_with(IpRateLimitState::new);
        ip_state.auth_attempts += 1;
    }

    /// Record a new session
    pub async fn record_session_created(&self, ip: IpAddr) {
        let mut state = self.state.write().await;
        let ip_state = state.entry(ip).or_insert_with(IpRateLimitState::new);
        ip_state.active_sessions += 1;

        let mut total = self.total_sessions.write().await;
        *total += 1;
    }

    /// Record a session ended (consumed or expired)
    pub async fn record_session_ended(&self, ip: IpAddr) {
        let mut state = self.state.write().await;
        if let Some(ip_state) = state.get_mut(&ip) {
            ip_state.active_sessions = ip_state.active_sessions.saturating_sub(1);
        }

        let mut total = self.total_sessions.write().await;
        *total = total.saturating_sub(1);
    }

    /// Clean up expired entries to prevent memory growth
    pub async fn cleanup_expired(&self) {
        let mut state = self.state.write().await;
        let window_duration = Duration::from_secs(self.config.window_secs * 2);

        state.retain(|_, ip_state| {
            // Keep if has active sessions or window hasn't expired
            ip_state.active_sessions > 0 || ip_state.window_start.elapsed() < window_duration
        });
    }

    /// Get current total session count
    pub async fn total_sessions(&self) -> usize {
        *self.total_sessions.read().await
    }
}

impl Default for WebAuthnRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limit errors
#[derive(Debug)]
pub enum RateLimitError {
    /// IP is blocked, includes seconds until unblock
    Blocked(u64),
    /// Too many registration attempts
    TooManyRegistrations(u64),
    /// Too many authentication attempts
    TooManyAuthAttempts(u64),
    /// Too many active sessions from this IP
    TooManySessions,
    /// System is overloaded (too many total sessions)
    SystemOverloaded,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitError::Blocked(secs) => {
                write!(f, "Rate limited. Try again in {} seconds", secs)
            }
            RateLimitError::TooManyRegistrations(secs) => {
                write!(f, "Too many registration attempts. Try again in {} seconds", secs)
            }
            RateLimitError::TooManyAuthAttempts(secs) => {
                write!(f, "Too many authentication attempts. Try again in {} seconds", secs)
            }
            RateLimitError::TooManySessions => {
                write!(f, "Too many active sessions")
            }
            RateLimitError::SystemOverloaded => {
                write!(f, "Service temporarily unavailable")
            }
        }
    }
}

impl RateLimitError {
    pub fn status_code(&self) -> axum::http::StatusCode {
        match self {
            RateLimitError::Blocked(_) |
            RateLimitError::TooManyRegistrations(_) |
            RateLimitError::TooManyAuthAttempts(_) |
            RateLimitError::TooManySessions => axum::http::StatusCode::TOO_MANY_REQUESTS,
            RateLimitError::SystemOverloaded => axum::http::StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_registration_rate_limit() {
        let config = WebAuthnRateLimitConfig {
            max_registration_attempts: 3,
            window_secs: 60,
            block_duration_secs: 60,
            ..Default::default()
        };
        let limiter = WebAuthnRateLimiter::with_config(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 3 attempts should succeed
        for _ in 0..3 {
            assert!(limiter.check_registration_allowed(ip).await.is_ok());
            limiter.record_registration_attempt(ip).await;
        }

        // 4th attempt should fail
        assert!(matches!(
            limiter.check_registration_allowed(ip).await,
            Err(RateLimitError::TooManyRegistrations(_))
        ));
    }

    #[tokio::test]
    async fn test_session_limits() {
        let config = WebAuthnRateLimitConfig {
            max_sessions_per_ip: 2,
            max_total_sessions: 5,
            ..Default::default()
        };
        let limiter = WebAuthnRateLimiter::with_config(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Create 2 sessions
        limiter.record_session_created(ip).await;
        limiter.record_session_created(ip).await;

        // 3rd session should fail per-IP limit
        assert!(matches!(
            limiter.check_registration_allowed(ip).await,
            Err(RateLimitError::TooManySessions)
        ));

        // End one session
        limiter.record_session_ended(ip).await;

        // Now should succeed
        assert!(limiter.check_registration_allowed(ip).await.is_ok());
    }
}
