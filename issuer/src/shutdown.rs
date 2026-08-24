// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shutdown coordination for the issuer's mutable, file-backed state.

use anyhow::{anyhow, Result};
use std::{
    future::Future,
    path::Path,
    pin::Pin,
    time::{Duration, Instant},
};
use tracing::{error, info};

type Flush = Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

pub(crate) fn persistence_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Runs required persistence operations in registration order.  Keeping the
/// operations here (rather than spawning one task per store) prevents a second
/// writer from racing an existing store's autosave task.
#[derive(Default)]
pub struct ShutdownCoordinator {
    flushes: Vec<(&'static str, Flush)>,
}

impl ShutdownCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add<F, Fut>(&mut self, name: &'static str, flush: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        self.flushes
            .push((name, Box::new(move || Box::pin(flush()))));
    }

    pub async fn flush_until(self, deadline: Instant) -> Result<()> {
        let mut errors = Vec::new();
        for (name, flush) in self.flushes {
            info!(store = name, "flushing issuer state");
            let result = tokio::time::timeout_at(deadline.into(), flush())
                .await
                .map_err(|_| anyhow!("timed out"))
                .and_then(|result| result.map_err(|e| anyhow!("{e:#}")));
            if let Err(error) = result {
                errors.push(format!("{name}: {error:#}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow!("{}", errors.join("; ")))
        }
    }

    pub async fn flush(self, timeout: Duration) -> Result<()> {
        self.flush_until(Instant::now() + timeout).await
    }
}

pub async fn wait_for_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.expect("failed to install CTRL+C handler"),
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C handler");
}

pub async fn flush_or_report(coordinator: ShutdownCoordinator, deadline: Instant) -> Result<()> {
    match coordinator.flush_until(deadline).await {
        Ok(()) => {
            info!("issuer shutdown persistence completed");
            Ok(())
        }
        Err(error) => {
            error!(critical_state = %error, "CRITICAL: issuer shutdown persistence failed");
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn flushes_in_order() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut c = ShutdownCoordinator::new();
        for name in ["audit", "invitations", "rotation"] {
            let order = Arc::clone(&order);
            c.add(name, move || {
                let order = Arc::clone(&order);
                async move {
                    order.lock().unwrap().push(name);
                    Ok(())
                }
            });
        }
        c.flush(Duration::from_secs(1)).await.unwrap();
        assert_eq!(*order.lock().unwrap(), ["audit", "invitations", "rotation"]);
    }

    #[tokio::test]
    async fn failure_and_timeout_are_errors() {
        let mut failed = ShutdownCoordinator::new();
        failed.add("broken", || async { Err(anyhow!("disk full")) });
        assert!(failed.flush(Duration::from_secs(1)).await.is_err());

        let mut timed_out = ShutdownCoordinator::new();
        timed_out.add("slow", || async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        });
        assert!(timed_out.flush(Duration::from_millis(1)).await.is_err());
    }

    #[tokio::test]
    async fn attempts_later_stores_and_uses_one_deadline() {
        let attempted = Arc::new(Mutex::new(Vec::new()));
        let mut coordinator = ShutdownCoordinator::new();
        let first = Arc::clone(&attempted);
        coordinator.add("first", move || {
            let first = Arc::clone(&first);
            async move {
                first.lock().unwrap().push("first");
                Err(anyhow!("write failed"))
            }
        });
        let later = Arc::clone(&attempted);
        coordinator.add("later", move || {
            let later = Arc::clone(&later);
            async move {
                later.lock().unwrap().push("later");
                Ok(())
            }
        });
        let result = coordinator.flush(Duration::from_secs(1)).await;
        assert!(result.unwrap_err().to_string().contains("first"));
        assert_eq!(*attempted.lock().unwrap(), ["first", "later"]);

        let mut multiple = ShutdownCoordinator::new();
        multiple.add("audit", || async { Err(anyhow!("audit failed")) });
        multiple.add("invitations", || async {
            Err(anyhow!("invitations failed"))
        });
        let error = multiple.flush(Duration::from_secs(1)).await.unwrap_err();
        assert!(error.to_string().contains("audit"));
        assert!(error.to_string().contains("invitations"));

        let attempted = Arc::new(Mutex::new(Vec::new()));
        let mut bounded = ShutdownCoordinator::new();
        bounded.add("slow", || async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(())
        });
        let later = Arc::clone(&attempted);
        bounded.add("after_timeout", move || {
            let later = Arc::clone(&later);
            async move {
                later.lock().unwrap().push("after_timeout");
                Ok(())
            }
        });
        assert!(bounded
            .flush_until(Instant::now() + Duration::from_millis(10))
            .await
            .is_err());
        assert_eq!(*attempted.lock().unwrap(), ["after_timeout"]);
    }

    #[test]
    fn relative_persistence_paths_sync_the_current_directory() {
        assert_eq!(persistence_parent(Path::new("state.json")), Path::new("."));
        assert_eq!(persistence_parent(Path::new("")), Path::new("."));
        assert_eq!(
            persistence_parent(Path::new("nested/state.json")),
            Path::new("nested")
        );
    }
}
