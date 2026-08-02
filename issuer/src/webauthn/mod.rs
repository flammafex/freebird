// issuer/src/webauthn/mod.rs

pub mod attestation;
pub mod ctx;
pub mod discoverable;
pub mod gate;
pub mod handlers;
pub mod rate_limit;
pub mod store;

// Re-exports for cleaner access
pub use attestation::{AttestationConfig, AttestationInfo, AttestationPolicy};
pub use ctx::WebAuthnCtx;
pub use discoverable::{admin_router, discoverable_router};
pub use gate::WebAuthnGate;
pub use handlers::{router, WebAuthnState};
pub use rate_limit::{RateLimitError, WebAuthnRateLimiter};
pub use store::{
    AuthenticatorTransport, CredentialCreateOptions, CredentialStore, CredentialSummary,
    DeviceType, InMemoryCredStore, RedisCredStore, StoredCredential,
};
