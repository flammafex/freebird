// issuer/src/routes/mod.rs
pub mod admin;
pub mod batch_issue;
pub mod issue;
#[cfg(feature = "human-gate-webauthn")]
pub mod webauthn;
#[cfg(feature = "human-gate-webauthn")]
pub mod webauthn_attestation; // Add this line

// Re-export types
pub use batch_issue::{BatchIssueReq, BatchIssueResp};
pub use issue::{IssueReq, IssueResp};

// Re-export handlers (for use in main.rs)
pub use admin::admin_router;
pub use batch_issue::handle_batch;
pub use issue::handle;
