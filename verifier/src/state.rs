// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use crate::metadata::IssuerInfo;
use crate::readiness::{MetadataStatus, StoreHealth};
use crate::store::{SpendOutcome, SpendStore};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub(crate) issuers: Arc<RwLock<HashMap<String, IssuerInfo>>>,
    pub(crate) store: Arc<dyn SpendStore>,
    pub(crate) verifier_id: String,
    pub(crate) audience: String,
    pub(crate) scope_digest: [u8; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
    /// Epoch configuration kept for admin display / operator observability.
    /// V4 token lifetime is controlled by verifier key acceptance policy.
    #[allow(dead_code)]
    pub(crate) epoch_duration_sec: u64,
    #[allow(dead_code)]
    pub(crate) epoch_retention: u32,
    pub(crate) issuer_urls: Vec<String>,
    pub(crate) metadata: Arc<RwLock<HashMap<String, MetadataStatus>>>,
    pub(crate) refresh_interval: Duration,
    pub(crate) store_health: StoreHealth,
}

pub(crate) async fn record_spend(
    store: &dyn SpendStore,
    spend_key: &str,
) -> anyhow::Result<SpendOutcome> {
    Ok(if store.mark_spent(spend_key, None).await? {
        SpendOutcome::Fresh
    } else {
        SpendOutcome::Replay
    })
}

pub(crate) fn compute_throughput(successful: usize, total_time_ms: u64) -> f64 {
    if total_time_ms == 0 {
        0.0
    } else {
        (successful as f64 / total_time_ms as f64) * 1000.0
    }
}

#[cfg(test)]
mod tests {
    use super::{compute_throughput, record_spend};
    use crate::store::{SpendOutcome, SpendStore};
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingStore {
        calls: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl SpendStore for RecordingStore {
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn mark_spent(
            &self,
            key: &str,
            ttl: Option<std::time::Duration>,
        ) -> anyhow::Result<bool> {
            assert!(ttl.is_none(), "V4 replay markers must remain non-expiring");
            self.calls.lock().unwrap().push(key.to_string());
            Ok(true)
        }
    }

    #[test]
    fn throughput_handles_zero_and_normal_durations() {
        assert_eq!(compute_throughput(100, 0), 0.0);
        assert_eq!(compute_throughput(500, 250), 2000.0);
    }

    #[tokio::test]
    async fn spend_recording_preserves_v4_non_expiring_replay_markers() {
        let store = RecordingStore::default();
        assert_eq!(
            record_spend(&store, "v4").await.unwrap(),
            SpendOutcome::Fresh
        );
        assert_eq!(*store.calls.lock().unwrap(), vec!["v4".to_string()]);
    }
}
