// issuer/src/webauthn/mod.rs

#[cfg(feature = "human-gate-webauthn")]
pub mod attestation;
#[cfg(feature = "human-gate-webauthn")]
pub mod ctx;
#[cfg(feature = "human-gate-webauthn")]
pub mod discoverable;
#[cfg(feature = "human-gate-webauthn")]
pub mod gate;
#[cfg(feature = "human-gate-webauthn")]
pub mod handlers;
#[cfg(feature = "human-gate-webauthn")]
pub mod rate_limit;
#[cfg(feature = "human-gate-webauthn")]
pub mod store;

// Re-exports for cleaner access
#[cfg(feature = "human-gate-webauthn")]
pub use attestation::{AttestationConfig, AttestationInfo, AttestationPolicy};
#[cfg(feature = "human-gate-webauthn")]
pub use ctx::WebAuthnCtx;
#[cfg(feature = "human-gate-webauthn")]
pub use discoverable::{admin_router, discoverable_router};
#[cfg(feature = "human-gate-webauthn")]
pub use gate::WebAuthnGate;
#[cfg(feature = "human-gate-webauthn")]
pub use handlers::{router, WebAuthnState};
#[cfg(feature = "human-gate-webauthn")]
pub use rate_limit::{RateLimitError, WebAuthnRateLimiter};
#[cfg(feature = "human-gate-webauthn")]
pub use store::{
    AuthenticatorTransport, CredentialCreateOptions, CredentialStore, CredentialSummary,
    DeviceType, InMemoryCredStore, RedisCredStore, StoredCredential,
};
