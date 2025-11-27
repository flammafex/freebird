// issuer/src/ledger.rs
use async_trait::async_trait;
use anyhow::Result;
pub mod sidecar;
#[async_trait]
pub trait BurnLedger: Send + Sync {
    /// Check if a nullifier has already been used
    async fn is_spent(&self, nullifier: &str) -> Result<bool>;

    /// Mark a nullifier as used (burn the token)
    /// This operation must be atomic.
    async fn mark_spent(&self, nullifier: &str) -> Result<()>;
}