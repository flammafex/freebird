//! Experimental RFC 9578 type-2 service path. Not a production release.

// Spawning can briefly retain even CLOEXEC flock descriptors before exec.
// Store tests hold a read guard across initialize/open/drop/reopen; process
// spawners take a write guard. Tokio's lock also supports async test lifetimes.
#[cfg(test)]
pub(crate) static SPAWN_LOCK: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

pub mod admission;
pub mod app_admission;
pub mod control;
pub mod issuer;
pub mod key_store;
pub mod origin;
pub mod pow;
