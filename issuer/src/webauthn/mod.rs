// issuer/src/webauthn/mod.rs

#[cfg(feature = "human-gate-webauthn")]
pub mod ctx;
#[cfg(feature = "human-gate-webauthn")]
pub mod store;
#[cfg(feature = "human-gate-webauthn")]
pub mod handlers;
#[cfg(feature = "human-gate-webauthn")]
pub mod gate;
#[cfg(feature = "human-gate-webauthn")]
pub mod rate_limit;

// Re-exports for cleaner access
#[cfg(feature = "human-gate-webauthn")]
pub use ctx::WebAuthnCtx;
#[cfg(feature = "human-gate-webauthn")]
pub use store::{CredentialStore, RedisCredStore, InMemoryCredStore};
#[cfg(feature = "human-gate-webauthn")]
pub use handlers::{WebAuthnState, router};
#[cfg(feature = "human-gate-webauthn")]
pub use gate::WebAuthnGate;
#[cfg(feature = "human-gate-webauthn")]
pub use rate_limit::{WebAuthnRateLimiter, RateLimitError};