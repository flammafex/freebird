//! Bounded bridge for synchronous stateful admission and replay health work.
use super::{SybilRequestContext, SybilResistance};
use anyhow::{Context, Result};
use freebird_common::api::SybilProof;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Copy)]
pub struct AdmissionUnavailable;
impl std::fmt::Display for AdmissionUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("admission temporarily unavailable")
    }
}
impl std::error::Error for AdmissionUnavailable {}

#[derive(Clone)]
pub struct AdmissionExecutor {
    permits: Arc<Semaphore>,
}
impl Default for AdmissionExecutor {
    fn default() -> Self {
        Self::new(16)
    }
}
impl AdmissionExecutor {
    pub fn new(capacity: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(capacity)),
        }
    }
    pub async fn run<T, F>(&self, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .context(AdmissionUnavailable)?;
        tokio::task::spawn_blocking(move || {
            // Actual work owns capacity even if its awaiting request is cancelled.
            let _permit = permit;
            work()
        })
        .await
        .context(AdmissionUnavailable)?
    }
    pub async fn verify(
        &self,
        checker: Arc<dyn SybilResistance>,
        proof: SybilProof,
        ctx: SybilRequestContext,
    ) -> Result<()> {
        self.run(move || checker.verify_with_context(&proof, &ctx))
            .await
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;
