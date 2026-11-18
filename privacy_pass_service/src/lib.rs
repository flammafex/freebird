//! This experimental service issues and redeems RFC 9578 tokens of type 2.
//! Use it for testing the protocol.

// Use this lock to keep a child from inheriting a store's file lock while another test reopens the store.
// A child can hold the descriptor until `exec` even with `CLOEXEC` set. Take a read guard
// from initialization through reopening, and a write guard around process spawning.
// Tokio's lock supports guards in async tests.
#[cfg(test)]
pub(crate) static SPAWN_LOCK: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

pub mod admission;
pub mod app_admission;
pub mod control;
pub mod issuer;
pub mod key_store;
pub mod origin;
pub mod pow;
