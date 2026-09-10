//! Bounded bridge for synchronous stateful admission and replay health work.
use super::{SybilRequestContext, SybilResistance};
use anyhow::{Context, Result};
use freebird_common::api::SybilProof;
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify, Semaphore};

#[derive(Default)]
struct Lifecycle {
    closed: bool,
    active: usize,
    failed: bool,
}

#[derive(Default)]
struct Jobs {
    state: Mutex<Lifecycle>,
    changed: Notify,
}

struct Job(Arc<Jobs>);
impl Drop for Job {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.failed |= std::thread::panicking();
        state.active -= 1;
        self.0.changed.notify_waiters();
    }
}

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
    jobs: Arc<Jobs>,
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
            jobs: Arc::new(Jobs::default()),
        }
    }

    /// Atomically stop accepting both admission and readiness work.
    pub fn close(&self) {
        self.jobs.state.lock().unwrap().closed = true;
        self.permits.close();
    }

    /// Includes blocking jobs whose callers have already been cancelled.
    pub async fn drain(&self) -> Result<()> {
        self.close();
        loop {
            let changed = self.jobs.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.jobs.state.lock().unwrap();
                if state.active == 0 {
                    anyhow::ensure!(!state.failed, "admission blocking job panicked");
                    return Ok(());
                }
            }
            changed.await;
        }
    }
    pub async fn run<T, F>(&self, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let (permit, job) = {
            let mut state = self.jobs.state.lock().unwrap();
            if state.closed {
                return Err(AdmissionUnavailable.into());
            }
            let permit = self
                .permits
                .clone()
                .try_acquire_owned()
                .context(AdmissionUnavailable)?;
            state.active += 1;
            (permit, Job(self.jobs.clone()))
        };
        tokio::task::spawn_blocking(move || {
            // Actual work owns capacity even if its awaiting request is cancelled.
            let _permit = permit;
            let _job = job;
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
