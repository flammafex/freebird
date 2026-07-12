// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{routes::admin::IssuerInfo, store::SpendStore};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenFamily {
    V4,
    V5,
}

#[derive(Clone, Debug)]
pub struct MetadataStatus {
    pub issuer_id: Option<String>,
    pub last_refresh: Option<Instant>,
}

#[derive(Clone, Debug)]
pub struct ReadinessReport {
    pub failures: Vec<String>,
}

/// Bounded, short-lived store health cache.  This prevents every probe from
/// opening a Redis connection while still allowing recovery to be observed.
#[derive(Clone)]
pub struct StoreHealth {
    store: Arc<dyn SpendStore>,
    cached: Arc<Mutex<Option<(Instant, bool)>>>,
    cache_ttl: Duration,
    timeout: Duration,
}

impl StoreHealth {
    pub fn new(store: Arc<dyn SpendStore>) -> Self {
        Self {
            store,
            cached: Arc::new(Mutex::new(None)),
            cache_ttl: Duration::from_secs(5),
            timeout: Duration::from_secs(2),
        }
    }

    pub async fn healthy(&self) -> bool {
        {
            let cached = self.cached.lock().await;
            if let Some((at, value)) = *cached {
                let ttl = if value {
                    self.cache_ttl
                } else {
                    Duration::from_secs(1)
                };
                if at.elapsed() < ttl {
                    return value;
                }
            }
        }
        let value = tokio::time::timeout(self.timeout, self.store.health_check())
            .await
            .is_ok_and(|r| r.is_ok());
        *self.cached.lock().await = Some((Instant::now(), value));
        value
    }
}

impl ReadinessReport {
    pub fn ready(&self) -> bool {
        self.failures.is_empty()
    }
}

pub async fn evaluate(
    store_health: &StoreHealth,
    issuers: &HashMap<String, IssuerInfo>,
    metadata: &HashMap<String, MetadataStatus>,
    issuer_urls: &[String],
    accepted: &[TokenFamily],
    refresh_interval: Duration,
) -> ReadinessReport {
    let mut failures = Vec::new();
    if !store_health.healthy().await {
        failures.push("replay store is unreachable".into());
    }
    let max_age = refresh_interval.saturating_mul(2);
    let now = Instant::now();
    for url in issuer_urls {
        let Some(status) = metadata.get(url) else {
            failures.push(format!("metadata unavailable for issuer {url}"));
            continue;
        };
        if status
            .last_refresh
            .map(|t| now.duration_since(t) > max_age)
            .unwrap_or(true)
        {
            failures.push(format!("metadata is stale for issuer {url}"));
            continue;
        }
        let Some(issuer_id) = status.issuer_id.as_deref() else {
            failures.push(format!("metadata unavailable for issuer {url}"));
            continue;
        };
        let Some(info) = issuers.get(issuer_id) else {
            failures.push(format!("issuer {issuer_id} is not loaded"));
            continue;
        };
        for family in accepted {
            match family {
                TokenFamily::V4 if info.verification_key.is_none() => {
                    failures.push(format!("V4 private key unavailable for issuer {issuer_id}"))
                }
                TokenFamily::V5
                    if !info.public_keys.values().any(|key| {
                        key.valid_from <= time::OffsetDateTime::now_utc().unix_timestamp()
                            && key.valid_until > time::OffsetDateTime::now_utc().unix_timestamp()
                    }) =>
                {
                    failures.push(format!(
                        "V5 public key unavailable or expired for issuer {issuer_id}"
                    ))
                }
                _ => {}
            }
        }
    }
    ReadinessReport { failures }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SpendStore;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::collections::HashMap;

    struct HealthyStore;
    #[async_trait]
    impl SpendStore for HealthyStore {
        async fn health_check(&self) -> Result<()> {
            Ok(())
        }
        async fn mark_spent(&self, _: &str, _: Option<Duration>) -> Result<bool> {
            Ok(true)
        }
    }

    struct RecoveringStore(std::sync::atomic::AtomicBool);
    #[async_trait]
    impl SpendStore for RecoveringStore {
        async fn health_check(&self) -> Result<()> {
            if self.0.load(std::sync::atomic::Ordering::Relaxed) {
                Ok(())
            } else {
                anyhow::bail!("down")
            }
        }
        async fn mark_spent(&self, _: &str, _: Option<Duration>) -> Result<bool> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn store_health_is_bounded_cached_and_recovers() {
        let store = Arc::new(RecoveringStore(std::sync::atomic::AtomicBool::new(false)));
        let health = StoreHealth::new(store.clone());
        assert!(!health.healthy().await);
        store.0.store(true, std::sync::atomic::Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert!(health.healthy().await);
    }

    fn issuer(v4: bool, v5: bool) -> IssuerInfo {
        let mut public_keys = HashMap::new();
        if v5 {
            public_keys.insert(
                [1; 32],
                crate::routes::admin::PublicIssuerKey {
                    token_key_id: [1; 32],
                    token_key_id_hex: "01".into(),
                    pubkey_spki: vec![],
                    issuer_id: "issuer".into(),
                    valid_from: 0,
                    valid_until: i64::MAX,
                    audience: None,
                },
            );
        }
        IssuerInfo {
            pubkey_bytes: vec![],
            kid: "kid".into(),
            ctx: vec![],
            verification_key: v4.then_some([2; 32]),
            deprecated_verification_keys: HashMap::new(),
            public_keys,
            last_refreshed: Some(Instant::now()),
        }
    }

    #[tokio::test]
    async fn each_enabled_family_and_issuer_is_independent() {
        let store: Arc<dyn SpendStore> = Arc::new(HealthyStore);
        let health = StoreHealth::new(store);
        let urls: Vec<String> = vec!["one".into(), "two".into()];
        let metadata = urls
            .iter()
            .map(|url| {
                (
                    url.clone(),
                    MetadataStatus {
                        issuer_id: Some(if url == "one" {
                            "one".into()
                        } else {
                            "two".into()
                        }),
                        last_refresh: Some(Instant::now()),
                    },
                )
            })
            .collect();
        let mut issuers = HashMap::new();
        issuers.insert("one".into(), issuer(true, true));
        issuers.insert("two".into(), issuer(false, true));
        let report = evaluate(
            &health,
            &issuers,
            &metadata,
            &urls,
            &[TokenFamily::V4, TokenFamily::V5],
            Duration::from_secs(60),
        )
        .await;
        assert!(!report.ready());
        assert!(report
            .failures
            .iter()
            .any(|f| f.contains("V4") && f.contains("two")));
        issuers.insert("two".into(), issuer(true, false));
        let report = evaluate(
            &health,
            &issuers,
            &metadata,
            &urls,
            &[TokenFamily::V4, TokenFamily::V5],
            Duration::from_secs(60),
        )
        .await;
        assert!(!report.ready());
        assert!(report
            .failures
            .iter()
            .any(|f| f.contains("V5") && f.contains("two")));
    }

    #[tokio::test]
    async fn stale_metadata_is_not_ready() {
        let store: Arc<dyn SpendStore> = Arc::new(HealthyStore);
        let health = StoreHealth::new(store);
        let mut issuers = HashMap::new();
        issuers.insert("one".into(), issuer(true, true));
        let mut metadata = HashMap::new();
        metadata.insert(
            "one".into(),
            MetadataStatus {
                issuer_id: Some("one".into()),
                last_refresh: Some(Instant::now() - Duration::from_secs(121)),
            },
        );
        let report = evaluate(
            &health,
            &issuers,
            &metadata,
            &["one".into()],
            &[TokenFamily::V4],
            Duration::from_secs(60),
        )
        .await;
        assert!(!report.ready());
        assert!(report.failures[0].contains("stale"));
    }
}
