// issuer/src/routes/mod.rs
//! HTTP route handlers for the issuer service
//!
//! This module contains the unified token issuance handler that supports
//! both protected (with Sybil resistance) and unprotected modes.

pub mod issue;

// Re-export the main types for convenience
pub use issue::{handle, IssueReq, IssueResp, SybilInfo};