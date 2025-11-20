// issuer/src/routes/mod.rs
pub mod admin;
pub mod batch_issue;
pub mod issue;
pub mod metadata;

#[cfg(feature = "human-gate-webauthn")]
pub mod webauthn;
#[cfg(feature = "human-gate-webauthn")]
pub mod webauthn_attestation;

// Re-export types from common directly
pub use common::api::{BatchIssueReq, BatchIssueResp, IssueReq, IssueResp};

pub use admin::admin_router;
pub use batch_issue::handle_batch;
pub use issue::handle;