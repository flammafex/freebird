// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::multi_key_voprf::MultiKeyVoprfCore;
use crate::sybil_resistance::ReplayStore;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::{atomic::AtomicBool, atomic::Ordering};
use std::time::Duration;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ReadinessReport {
    pub ready: bool,
    pub redis: bool,
    pub storage: bool,
    pub issuance_key: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_issuance: Option<bool>,
    pub stores: BTreeMap<String, bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub development_unsafe: Option<bool>,
}

#[derive(Clone)]
pub struct ReadinessState {
    report: Arc<RwLock<ReadinessReport>>,
}

#[derive(Clone)]
pub(crate) struct ExchangeReadinessState {
    engine: Arc<crate::exchange::ExchangeEngine>,
    store: crate::exchange::store::ExchangeStore,
    registry: Vec<crate::exchange::store::KeyRegistryEntry>,
    issuer_id: String,
    discovery: freebird_common::api::ExchangeDiscoveryV2,
    disabled_publication_ack_paths: Vec<PathBuf>,
    registry_failed_closed: Arc<AtomicBool>,
}

#[derive(Clone)]
pub(crate) struct GraphIssuanceReadinessState {
    engine: Arc<crate::graph_issuance::GraphIssuanceEngine>,
}

impl GraphIssuanceReadinessState {
    pub(crate) fn new(engine: Arc<crate::graph_issuance::GraphIssuanceEngine>) -> Self {
        Self { engine }
    }

    async fn check(&self) -> bool {
        self.engine.readiness_check().await
    }
}

impl ExchangeReadinessState {
    pub(crate) fn new(
        engine: Arc<crate::exchange::ExchangeEngine>,
        store: crate::exchange::store::ExchangeStore,
        registry: Vec<crate::exchange::store::KeyRegistryEntry>,
        issuer_id: String,
        discovery: freebird_common::api::ExchangeDiscoveryV2,
        disabled_publication_ack_paths: Vec<PathBuf>,
    ) -> Self {
        Self {
            engine,
            store,
            registry,
            issuer_id,
            discovery,
            disabled_publication_ack_paths,
            registry_failed_closed: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn check(&self) -> bool {
        use crate::exchange::store::KeyRegistryOutcome;

        let acknowledgements = match crate::config::load_disabled_publication_acknowledgements(
            &self.disabled_publication_ack_paths,
        ) {
            Ok(acknowledgements) => acknowledgements,
            Err(_) => return false,
        };
        if self.engine.readiness_check().await.is_err()
            || freebird_common::api::validate_exchange_discovery_v2(
                &self.issuer_id,
                &self.discovery,
            )
            .is_err()
            || !self.pending_references_are_recoverable().await
            || crate::startup::validate_disabled_publication_acknowledgements_v2(
                &self.issuer_id,
                &self.discovery,
                &acknowledgements,
            )
            .is_err()
        {
            return false;
        }
        if self.registry_failed_closed.load(Ordering::Acquire) {
            return false;
        }
        let registry_equal = matches!(
            self.store.initialize_key_registry_v2(&self.registry).await,
            Ok(KeyRegistryOutcome::Equal)
        );
        if !registry_equal {
            self.registry_failed_closed.store(true, Ordering::Release);
        }
        registry_equal
    }

    async fn pending_references_are_recoverable(&self) -> bool {
        let records = match self.store.pending_records_v2().await {
            Ok(records) => records,
            Err(_) => return false,
        };
        records.into_iter().all(|record| {
            std::iter::once(&self.discovery.active_graph)
                .chain(&self.discovery.retained_graphs)
                .find(|graph| graph.graph_id == record.graph_id)
                .and_then(|graph| {
                    graph.transitions.iter().find(|transition| {
                        transition.transition_id == record.transition_id
                            && transition.source_keyset_id == record.source_keyset_id
                            && transition.target_keyset_id == record.target_keyset_id
                    })
                })
                .is_some_and(|transition| {
                    transition.admission_state
                        != freebird_common::api::ExchangeAdmissionStateV2::Disabled
                })
        })
    }
}

impl ReadinessState {
    pub fn new(development_unsafe: bool) -> Self {
        Self {
            report: Arc::new(RwLock::new(ReadinessReport {
                development_unsafe: Some(development_unsafe),
                ..Default::default()
            })),
        }
    }

    pub fn report(&self) -> ReadinessReport {
        self.report.read().expect("readiness lock poisoned").clone()
    }

    fn update(&self, report: ReadinessReport) {
        let unsafe_mode = self
            .report
            .read()
            .expect("readiness lock poisoned")
            .development_unsafe;
        *self.report.write().expect("readiness lock poisoned") = ReadinessReport {
            development_unsafe: unsafe_mode,
            ..report
        };
    }

    pub(crate) fn spawn_checks(
        &self,
        replay_store: Arc<dyn ReplayStore>,
        storage_paths: Vec<(String, PathBuf)>,
        voprf: Arc<MultiKeyVoprfCore>,
        exchange: Option<ExchangeReadinessState>,
        graph_issuance: Option<GraphIssuanceReadinessState>,
    ) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                let mut report = check_once(&replay_store, &storage_paths, &voprf).await;
                if let Some(exchange) = &exchange {
                    let ready = tokio::time::timeout(Duration::from_secs(2), exchange.check())
                        .await
                        .is_ok_and(|ready| ready);
                    report.exchange = Some(ready);
                    report.ready &= ready;
                }
                if let Some(graph_issuance) = &graph_issuance {
                    let ready =
                        tokio::time::timeout(Duration::from_secs(2), graph_issuance.check())
                            .await
                            .is_ok_and(|ready| ready);
                    report.graph_issuance = Some(ready);
                    report.ready &= ready;
                }
                state.update(report);
            }
        });
    }
}

pub async fn check_once(
    replay_store: &Arc<dyn ReplayStore>,
    storage_paths: &[(String, PathBuf)],
    voprf: &Arc<MultiKeyVoprfCore>,
) -> ReadinessReport {
    let store = Arc::clone(replay_store);
    let redis = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || store.health_check()),
    )
    .await
    .is_ok_and(|result| result.is_ok_and(|result| result.is_ok()));
    let paths = storage_paths.to_vec();
    let storage = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || {
            paths
                .iter()
                .map(|(name, path)| (name.clone(), writable_probe(path)))
                .collect::<BTreeMap<_, _>>()
        }),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or_default();
    let storage_ready = !storage.is_empty() && storage.values().all(|ready| *ready);
    let issuance_key =
        !voprf.active_kid().await.is_empty() && !voprf.active_pubkey_b64().await.is_empty();
    ReadinessReport {
        ready: redis && storage_ready && issuance_key,
        redis,
        storage: storage_ready,
        issuance_key,
        exchange: None,
        graph_issuance: None,
        stores: storage,
        development_unsafe: None,
    }
}

fn writable_probe(path: &Path) -> bool {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return false;
    }
    let suffix = format!(
        ".freebird-readiness-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    );
    let probe = parent.join(&suffix);
    let replacement = parent.join(format!("{suffix}-replacement"));
    let result = (|| -> std::io::Result<()> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)?;
        file.sync_all()?;
        std::fs::rename(&probe, &replacement)?;
        let _ = std::fs::remove_file(&replacement);
        #[cfg(unix)]
        if let Ok(directory) = std::fs::File::open(parent) {
            directory.sync_all()?;
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&probe);
    let _ = std::fs::remove_file(&replacement);
    result.is_ok()
}

pub async fn public_readiness(state: ReadinessState) -> impl axum::response::IntoResponse {
    let report = state.report();
    if report.ready {
        (
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({"status":"ready"})),
        )
    } else {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"status":"not_ready"})),
        )
    }
}

pub async fn liveness() -> impl axum::response::IntoResponse {
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({"status":"alive"})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sybil_resistance::memory_replay_store;
    use tempfile::tempdir;

    async fn core() -> Arc<MultiKeyVoprfCore> {
        Arc::new(
            MultiKeyVoprfCore::new([7; 32], "pubkey".into(), "active".into(), b"test").unwrap(),
        )
    }

    #[tokio::test]
    async fn in_memory_replay_never_reports_ready() {
        let dir = tempdir().unwrap();
        let report = check_once(
            &memory_replay_store(),
            &[
                ("audit".into(), dir.path().join("audit.json")),
                ("rotation".into(), dir.path().join("keys.json")),
            ],
            &core().await,
        )
        .await;
        assert!(!report.ready);
        assert!(!report.redis);
        assert!(report.storage);
        assert!(report.issuance_key);
    }

    #[tokio::test]
    async fn unavailable_storage_is_not_ready_and_recovers() {
        let dir = tempdir().unwrap();
        let missing_parent = dir.path().join("new");
        let missing = missing_parent.join("audit.json");
        let store = memory_replay_store();
        let report = check_once(&store, &[("audit".into(), missing)], &core().await).await;
        assert!(!report.ready);
        assert!(!report.storage);
        std::fs::create_dir(&missing_parent).unwrap();
        let report = check_once(
            &store,
            &[("audit".into(), missing_parent.join("audit.json"))],
            &core().await,
        )
        .await;
        assert!(report.storage);
    }

    #[tokio::test]
    async fn every_configured_store_is_reported() {
        let dir = tempdir().unwrap();
        let stores = [
            "audit",
            "rotation",
            "invitation",
            "progressive_trust",
            "proof_of_diversity",
            "vouching",
        ]
        .into_iter()
        .map(|name| (name.to_string(), dir.path().join(format!("{name}.json"))))
        .collect::<Vec<_>>();
        let report = check_once(&memory_replay_store(), &stores, &core().await).await;
        assert_eq!(report.stores.len(), 6);
        assert!(report.stores.values().all(|ready| *ready));
    }

    #[cfg(unix)]
    #[test]
    fn existing_file_does_not_hide_non_writable_parent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("existing.json");
        std::fs::write(&path, b"state").unwrap();
        let original = std::fs::metadata(dir.path()).unwrap().permissions();
        let mut read_only = original.clone();
        use std::os::unix::fs::PermissionsExt;
        read_only.set_mode(0o500);
        std::fs::set_permissions(dir.path(), read_only).unwrap();
        let result = writable_probe(&path);
        std::fs::set_permissions(dir.path(), original).unwrap();
        assert!(!result);
    }
}
