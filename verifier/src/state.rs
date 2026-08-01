// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use crate::metadata::IssuerInfo;
use crate::readiness::{MetadataStatus, StoreHealth, TokenFamily};
use crate::replay_authority::ReplayAuthorityHealth;
use crate::store::SpendStore;
use axum::http::StatusCode;
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
    /// V4 token lifetime is controlled by verifier key acceptance policy,
    /// but operators still configure these env vars and expect them surfaced.
    #[allow(dead_code)]
    pub(crate) epoch_duration_sec: u64,
    #[allow(dead_code)]
    pub(crate) epoch_retention: u32,
    pub(crate) issuer_urls: Vec<String>,
    pub(crate) metadata: Arc<RwLock<HashMap<String, MetadataStatus>>>,
    pub(crate) accepted_token_families: Vec<TokenFamily>,
    pub(crate) refresh_interval: Duration,
    pub(crate) store_health: StoreHealth,
    pub(crate) replay_authority: Arc<ReplayAuthorityHealth>,
    pub(crate) store_is_memory: bool,
}

pub(crate) fn ensure_token_family_enabled(
    version: u8,
    accepted: &[TokenFamily],
) -> Result<(), (StatusCode, String)> {
    let enabled = match version {
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 => accepted.contains(&TokenFamily::V4),
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V5 => accepted.contains(&TokenFamily::V5),
        _ => true,
    };
    if enabled {
        Ok(())
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            "token family is not accepted by this verifier".into(),
        ))
    }
}

pub(crate) fn family_enabled(accepted: &[TokenFamily], family: TokenFamily) -> bool {
    accepted.contains(&family)
}

pub(crate) async fn record_spend(
    store: &dyn SpendStore,
    spend_key: &str,
    valid_until: Option<i64>,
) -> anyhow::Result<bool> {
    match valid_until {
        Some(valid_until) => store.mark_spent_through(spend_key, valid_until).await,
        None => store.mark_spent(spend_key, None).await,
    }
}

pub(crate) fn compute_throughput(successful: usize, total_time_ms: u64) -> f64 {
    if total_time_ms == 0 {
        0.0
    } else {
        (successful as f64 / total_time_ms as f64) * 1000.0
    }
}

pub(crate) async fn ensure_v4_replay_authority_ready(
    state: &AppState,
) -> Result<(), (StatusCode, String)> {
    if !state
        .replay_authority
        .allows_v4_replay(state.store_is_memory)
        .await
    {
        tracing::error!("V4 replay authority attestation is unavailable");
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "replay authority unavailable".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        compute_throughput, ensure_token_family_enabled, ensure_v4_replay_authority_ready,
        family_enabled, record_spend, AppState,
    };
    use crate::readiness::TokenFamily;
    use crate::replay_authority::{ReplayAuthorityConfig, ReplayAuthorityHealth};
    use crate::store::SpendStore;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::sync::RwLock;

    #[derive(Default)]
    struct RecordingStore {
        calls: Mutex<Vec<(String, Option<i64>)>>,
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
            self.calls.lock().unwrap().push((key.to_string(), None));
            Ok(true)
        }

        async fn mark_spent_through(&self, key: &str, valid_until: i64) -> anyhow::Result<bool> {
            self.calls
                .lock()
                .unwrap()
                .push((key.to_string(), Some(valid_until)));
            Ok(true)
        }
    }

    #[test]
    fn test_compute_throughput_zero_time() {
        assert_eq!(compute_throughput(100, 0), 0.0);
    }

    #[test]
    fn test_compute_throughput_normal() {
        assert_eq!(compute_throughput(500, 250), 2000.0);
    }

    #[test]
    fn token_family_enforcement_is_explicit_and_refresh_uses_enabled_families() {
        let accepted = [TokenFamily::V4];
        assert!(ensure_token_family_enabled(
            freebird_crypto::REDEMPTION_TOKEN_VERSION_V4,
            &accepted
        )
        .is_ok());
        assert!(ensure_token_family_enabled(
            freebird_crypto::REDEMPTION_TOKEN_VERSION_V5,
            &accepted
        )
        .is_err());
        assert!(family_enabled(&[TokenFamily::V4], TokenFamily::V4));
        assert!(!family_enabled(&[TokenFamily::V4], TokenFamily::V5));
        assert!(family_enabled(&[TokenFamily::V5], TokenFamily::V5));
        assert!(!family_enabled(&[TokenFamily::V5], TokenFamily::V4));
    }

    #[tokio::test]
    async fn single_and_batch_writes_share_v5_absolute_expiry_and_preserve_v4() {
        let store = RecordingStore::default();

        assert!(record_spend(&store, "single-v5", Some(123)).await.unwrap());
        assert!(record_spend(&store, "batch-v5", Some(123)).await.unwrap());
        assert!(record_spend(&store, "v4", None).await.unwrap());

        assert_eq!(
            *store.calls.lock().unwrap(),
            vec![
                ("single-v5".to_string(), Some(123)),
                ("batch-v5".to_string(), Some(123)),
                ("v4".to_string(), None),
            ]
        );
    }

    #[tokio::test]
    async fn nonparticipating_memory_v4_does_not_gate_spend_mutation() {
        let store = Arc::new(RecordingStore::default());
        let authority = Arc::new(
            ReplayAuthorityHealth::new(
                store.clone(),
                ReplayAuthorityConfig {
                    graph_issuer_urls: vec![],
                    probe_interval: Duration::from_secs(30),
                    max_staleness: Duration::from_secs(60),
                },
                [0; 32],
            )
            .unwrap(),
        );
        let state = AppState {
            issuers: Arc::new(RwLock::new(HashMap::new())),
            store: store.clone(),
            verifier_id: "verifier:test".into(),
            audience: "test".into(),
            scope_digest: [0; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
            epoch_duration_sec: 86_400,
            epoch_retention: 2,
            issuer_urls: vec![],
            metadata: Arc::new(RwLock::new(HashMap::new())),
            accepted_token_families: vec![TokenFamily::V4],
            refresh_interval: Duration::from_secs(60),
            store_health: crate::readiness::StoreHealth::new(store.clone()),
            replay_authority: authority,
            store_is_memory: true,
        };
        assert!(ensure_v4_replay_authority_ready(&state).await.is_ok());
        assert!(store.calls.lock().unwrap().is_empty());
    }
}
