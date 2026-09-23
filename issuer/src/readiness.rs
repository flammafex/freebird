// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::multi_key_voprf::MultiKeyVoprfCore;
use crate::sybil_resistance::{admission::AdmissionExecutor, ReplayStore};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_authority: Option<bool>,
    pub stores: BTreeMap<String, bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub development_unsafe: Option<bool>,
}

#[derive(Clone)]
pub struct ReadinessState {
    report: Arc<RwLock<ReadinessReport>>,
}

#[derive(Clone)]
pub(crate) struct V7ExchangeReadinessState {
    engine: Arc<crate::exchange::v7::V7ExchangeEngine>,
    inventory: Arc<crate::v7_signers::V7SignerInventory>,
    discovery: freebird_common::api::NativeExchangeV3Discovery,
}

#[derive(Clone)]
pub(crate) struct V7GraphIssuanceReadinessState {
    engine: Arc<crate::graph_issuance::V7GraphIssuanceEngine>,
    inventory: Arc<crate::v7_signers::V7SignerInventory>,
    discovery: freebird_common::api::NativeGraphIssuanceV7Discovery,
    v4_local_authorization: bool,
}

impl V7ExchangeReadinessState {
    pub(crate) fn new(
        engine: Arc<crate::exchange::v7::V7ExchangeEngine>,
        inventory: Arc<crate::v7_signers::V7SignerInventory>,
        discovery: freebird_common::api::NativeExchangeV3Discovery,
    ) -> Self {
        Self {
            engine,
            inventory,
            discovery,
        }
    }

    async fn check(&self) -> bool {
        if self.discovery.validate().is_err() {
            return false;
        }
        if crate::startup::validate_v7_exchange_inventory(&self.discovery, &self.inventory).is_err()
        {
            return false;
        }
        self.engine.readiness_check().await.is_ok()
    }
}

impl V7GraphIssuanceReadinessState {
    pub(crate) fn new(
        engine: Arc<crate::graph_issuance::V7GraphIssuanceEngine>,
        inventory: Arc<crate::v7_signers::V7SignerInventory>,
        discovery: freebird_common::api::NativeGraphIssuanceV7Discovery,
        v4_local_authorization: bool,
    ) -> Self {
        Self {
            engine,
            inventory,
            discovery,
            v4_local_authorization,
        }
    }

    async fn check(&self) -> bool {
        if self.discovery.validate().is_err() {
            return false;
        }
        if !self.engine.issuance_enabled()
            || !self.v4_local_authorization
            || validate_v7_graph_inventory(&self.discovery, &self.inventory).is_err()
        {
            return false;
        }
        self.engine.readiness_check().await.is_ok()
    }
}

fn validate_v7_graph_inventory(
    discovery: &freebird_common::api::NativeGraphIssuanceV7Discovery,
    inventory: &crate::v7_signers::V7SignerInventory,
) -> anyhow::Result<()> {
    for policy in discovery
        .active_policies
        .iter()
        .chain(discovery.retained_policies.iter())
    {
        let token_key_id: [u8; 32] = hex::decode(&policy.token_key_id)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid V7 graph token key ID"))?;
        let identity = crate::v7_signers::V7SignerIdentity::new(
            policy.issuer_id.clone(),
            policy.profile_id.clone(),
            policy.descriptor_id.clone(),
            freebird_crypto::V7TokenKeyId::new(token_key_id),
        )?;
        let signer = inventory.lookup(&identity)?;
        if signer.metadata().pubkey_spki_b64 != policy.pubkey_spki_b64
            || signer.metadata().spki_fingerprint != policy.spki_fingerprint
            || signer.metadata().asset_id != policy.asset_id
            || signer.metadata().amount_minor.to_string() != policy.amount_minor
        {
            anyhow::bail!("V7 graph policy does not match shared signer inventory")
        }
    }
    Ok(())
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

    // Startup passes the readiness dependencies as separate, stable inputs;
    // retain that signature rather than adding a one-use configuration object.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn_checks(
        &self,
        admission: AdmissionExecutor,
        replay_store: Arc<dyn ReplayStore>,
        storage_paths: Vec<(String, PathBuf)>,
        voprf: Arc<MultiKeyVoprfCore>,
        v7_exchange: Option<V7ExchangeReadinessState>,
        v7_graph_issuance: Option<V7GraphIssuanceReadinessState>,
        replay_authority: Option<Arc<crate::replay_authority::ReplayAuthority>>,
    ) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                let mut report = check_once_with_replay_authority(
                    &admission,
                    &replay_store,
                    &storage_paths,
                    &voprf,
                    replay_authority.as_ref(),
                )
                .await;
                if let Some(exchange) = &v7_exchange {
                    let ready = tokio::time::timeout(Duration::from_secs(2), exchange.check())
                        .await
                        .is_ok_and(|ready| ready);
                    report.exchange = Some(ready);
                    report.ready &= ready;
                }
                if let Some(graph_issuance) = &v7_graph_issuance {
                    let ready =
                        tokio::time::timeout(Duration::from_secs(2), graph_issuance.check())
                            .await
                            .is_ok_and(|ready| ready);
                    report.graph_issuance = Some(report.graph_issuance.unwrap_or(true) && ready);
                    report.ready &= ready;
                }
                state.update(report);
            }
        });
    }
}

pub async fn check_once(
    admission: &AdmissionExecutor,
    replay_store: &Arc<dyn ReplayStore>,
    storage_paths: &[(String, PathBuf)],
    voprf: &Arc<MultiKeyVoprfCore>,
) -> ReadinessReport {
    check_once_with_replay_authority(admission, replay_store, storage_paths, voprf, None).await
}

pub(crate) async fn check_once_with_replay_authority(
    admission: &AdmissionExecutor,
    replay_store: &Arc<dyn ReplayStore>,
    storage_paths: &[(String, PathBuf)],
    voprf: &Arc<MultiKeyVoprfCore>,
    replay_authority: Option<&Arc<crate::replay_authority::ReplayAuthority>>,
) -> ReadinessReport {
    let store = Arc::clone(replay_store);
    // The shared admission executor owns the blocking job and its permit.
    // Redis health_check bounds its own connection/command lifetime; abandoning
    // this caller cannot release capacity before the actual job completes.
    let redis = admission.run(move || store.health_check()).await.is_ok();
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
    let replay_authority_ready = match replay_authority {
        Some(authority) => Some(
            tokio::time::timeout(Duration::from_secs(2), authority.health_check())
                .await
                .is_ok_and(|result| result.is_ok()),
        ),
        None => None,
    };
    let authority_ready = replay_authority_ready.unwrap_or(true);
    ReadinessReport {
        ready: redis && storage_ready && issuance_key && authority_ready,
        redis,
        storage: storage_ready,
        issuance_key,
        exchange: None,
        graph_issuance: None,
        replay_authority: replay_authority_ready,
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
    use crate::replay_authority::ReplayAuthority;
    use crate::sybil_resistance::memory_replay_store;
    use tempfile::tempdir;

    async fn core() -> Arc<MultiKeyVoprfCore> {
        Arc::new(
            MultiKeyVoprfCore::new([7; 32], "pubkey".into(), "active".into(), b"test").unwrap(),
        )
    }

    #[derive(Default)]
    struct BlockingReplayStore {
        calls: std::sync::atomic::AtomicUsize,
        started: tokio::sync::Notify,
        released: std::sync::Mutex<bool>,
        wake: std::sync::Condvar,
    }

    impl BlockingReplayStore {
        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.wake.notify_all();
        }
    }

    impl ReplayStore for BlockingReplayStore {
        fn mark_once(&self, _: &str, _: &str, _: Duration) -> anyhow::Result<()> {
            unreachable!("readiness must only check health")
        }
        fn health_check(&self) -> anyhow::Result<()> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.started.notify_one();
            let released = self.released.lock().unwrap();
            drop(
                self.wake
                    .wait_while(released, |released| !*released)
                    .unwrap(),
            );
            Ok(())
        }
    }

    // Always unblock the fake, including when an assertion fails, so runtime
    // shutdown cannot hang waiting for a deliberately blocked test closure.
    struct ReleaseOnDrop(Arc<BlockingReplayStore>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    #[tokio::test]
    async fn abandoned_readiness_holds_shared_capacity_and_recovers() {
        use std::sync::atomic::Ordering;
        let admission = AdmissionExecutor::new(1);
        let fake = Arc::new(BlockingReplayStore::default());
        let release = ReleaseOnDrop(fake.clone());
        let store: Arc<dyn ReplayStore> = fake.clone();
        let core = core().await;
        let dir = tempdir().unwrap();
        let paths = vec![("audit".into(), dir.path().join("audit.json"))];
        let caller = {
            let (admission, store, core, paths) = (
                admission.clone(),
                store.clone(),
                core.clone(),
                paths.clone(),
            );
            tokio::spawn(async move { check_once(&admission, &store, &paths, &core).await })
        };
        tokio::time::timeout(Duration::from_secs(2), fake.started.notified())
            .await
            .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());

        for _ in 0..5 {
            let report = tokio::time::timeout(
                Duration::from_secs(2),
                check_once(&admission, &store, &paths, &core),
            )
            .await
            .unwrap();
            assert!(!report.redis && !report.ready);
            assert!(report.storage && report.issuance_key);
            assert_eq!(
                fake.calls.load(Ordering::SeqCst),
                1,
                "no queued health jobs"
            );
        }
        // Issuance shares that exact cap, not a separate readiness semaphore.
        assert!(admission
            .run::<(), _>(|| panic!("must not queue admission"))
            .await
            .unwrap_err()
            .is::<crate::sybil_resistance::admission::AdmissionUnavailable>());

        drop(release);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let report = check_once(&admission, &store, &paths, &core).await;
                if report.ready {
                    assert!(report.redis);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed work must restore capacity");
        assert!(fake.calls.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn admission_saturation_prevents_readiness_health_work() {
        let admission = AdmissionExecutor::new(1);
        let fake = Arc::new(BlockingReplayStore::default());
        let release = ReleaseOnDrop(fake.clone());
        let task = {
            let (admission, fake) = (admission.clone(), fake.clone());
            tokio::spawn(async move { admission.run(move || fake.health_check()).await })
        };
        tokio::time::timeout(Duration::from_secs(2), fake.started.notified())
            .await
            .unwrap();
        let store: Arc<dyn ReplayStore> = fake.clone();
        for _ in 0..5 {
            let report = check_once(&admission, &store, &[], &core().await).await;
            assert!(!report.redis && !report.ready);
        }
        assert_eq!(fake.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(release);
        task.await.unwrap().unwrap();
        assert!(
            check_once(&admission, &store, &[], &core().await)
                .await
                .redis
        );
    }

    #[tokio::test]
    async fn replay_health_task_failure_is_not_ready() {
        struct PanickingStore;
        impl ReplayStore for PanickingStore {
            fn mark_once(&self, _: &str, _: &str, _: Duration) -> anyhow::Result<()> {
                unreachable!()
            }
            fn health_check(&self) -> anyhow::Result<()> {
                panic!("private backend details")
            }
        }
        let store: Arc<dyn ReplayStore> = Arc::new(PanickingStore);
        let admission = AdmissionExecutor::new(1);
        let report = check_once(&admission, &store, &[], &core().await).await;
        assert!(!report.redis && !report.ready);
        admission.run(|| Ok(())).await.unwrap();
    }

    #[tokio::test]
    async fn in_memory_replay_never_reports_ready() {
        let dir = tempdir().unwrap();
        let report = check_once(
            &AdmissionExecutor::default(),
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
    async fn replay_authority_failure_is_not_ready() {
        let dir = tempdir().unwrap();
        let authority = Arc::new(ReplayAuthority::new("redis://127.0.0.1:1").unwrap());
        let report = tokio::time::timeout(
            Duration::from_secs(3),
            check_once_with_replay_authority(
                &AdmissionExecutor::default(),
                &memory_replay_store(),
                &[("audit".into(), dir.path().join("audit.json"))],
                &core().await,
                Some(&authority),
            ),
        )
        .await
        .unwrap();
        assert!(!report.ready);
        assert_eq!(report.replay_authority, Some(false));
    }

    #[tokio::test]
    async fn unavailable_storage_is_not_ready_and_recovers() {
        let dir = tempdir().unwrap();
        let missing_parent = dir.path().join("new");
        let missing = missing_parent.join("audit.json");
        let store = memory_replay_store();
        let admission = AdmissionExecutor::default();
        let report = check_once(
            &admission,
            &store,
            &[("audit".into(), missing)],
            &core().await,
        )
        .await;
        assert!(!report.ready);
        assert!(!report.storage);
        std::fs::create_dir(&missing_parent).unwrap();
        let report = check_once(
            &admission,
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
        let report = check_once(
            &AdmissionExecutor::default(),
            &memory_replay_store(),
            &stores,
            &core().await,
        )
        .await;
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
