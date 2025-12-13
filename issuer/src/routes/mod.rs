// issuer/src/routes/mod.rs
pub mod admin;
pub mod admin_rate_limit;
pub mod batch_issue;
pub mod issue;
pub mod metadata;

// Re-export types from common directly
pub use freebird_common::api::{BatchIssueReq, BatchIssueResp, IssueReq, IssueResp};

pub use admin::admin_router;
pub use batch_issue::handle_batch;
pub use issue::handle;