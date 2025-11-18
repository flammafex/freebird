// issuer/src/routes/mod.rs
pub mod issue;
pub mod batch_issue;
pub mod admin;

// Re-export types
pub use issue::{IssueReq, IssueResp};
pub use batch_issue::{BatchIssueReq, BatchIssueResp};

// Re-export handlers (for use in main.rs)
pub use issue::handle;
pub use batch_issue::handle_batch;
pub use admin::admin_router;