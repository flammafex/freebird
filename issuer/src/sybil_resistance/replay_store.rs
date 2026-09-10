use super::admission::AdmissionUnavailable;
use anyhow::{anyhow, Context, Result};
use redis::{AsyncCommands, ConnectionAddr, ExistenceCheck, SetExpiry, SetOptions};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

const REDIS_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);

pub trait ReplayStore: Send + Sync {
    fn mark_once(&self, namespace: &str, key: &str, ttl: Duration) -> Result<()>;
    fn health_check(&self) -> Result<()>;
}

#[derive(Default)]
pub struct InMemoryReplayStore {
    entries: Mutex<HashMap<String, Instant>>,
}

impl InMemoryReplayStore {
    fn scoped_key(namespace: &str, key: &str) -> String {
        format!("{namespace}:{key}")
    }
}

impl ReplayStore for InMemoryReplayStore {
    fn mark_once(&self, namespace: &str, key: &str, ttl: Duration) -> Result<()> {
        let now = Instant::now();
        let expires_at = now + ttl;
        let scoped_key = Self::scoped_key(namespace, key);

        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("replay store lock poisoned"))?;
        entries.retain(|_, expires| *expires > now);

        if entries.contains_key(&scoped_key) {
            return Err(anyhow!("Sybil proof already used"));
        }

        entries.insert(scoped_key, expires_at);
        Ok(())
    }

    fn health_check(&self) -> Result<()> {
        Err(anyhow!("in-memory replay store is not persistent"))
    }
}

pub struct RedisReplayStore {
    client: redis::Client,
    key_prefix: String,
    operation_timeout: Duration,
}

impl RedisReplayStore {
    pub fn new(redis_url: &str, key_prefix: impl Into<String>) -> Result<Self> {
        // Client::open only parses configuration; it performs no network I/O.
        let client =
            redis::Client::open(redis_url).context("invalid Redis replay configuration")?;
        match &client.get_connection_info().addr {
            ConnectionAddr::Tcp(host, _) | ConnectionAddr::TcpTls { host, .. } => {
                // Parse the crate's normalized host (including unbracketed IPv6),
                // not the URL. Numeric addresses bypass Tokio's DNS resolver.
                host.parse::<std::net::IpAddr>().map_err(|_| anyhow!(
                    "Redis replay endpoint must be a numeric IPv4/IPv6 address or Unix socket; hostnames are not supported"
                ))?;
            }
            ConnectionAddr::Unix(_) => {}
        }
        Ok(Self {
            client,
            key_prefix: key_prefix.into(),
            operation_timeout: REDIS_OPERATION_TIMEOUT,
        })
    }

    fn redis_key(&self, namespace: &str, key: &str) -> String {
        format!("{}:{}:{}", self.key_prefix, namespace, key)
    }

    // Called only from blocking admission/readiness work. The one-shot connection
    // is dropped on timeout, including during AUTH/SELECT/CLIENT initialization.
    // No multiplexed driver or retry survives this operation.
    fn with_deadline<T>(
        &self,
        operation: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        let deadline = tokio::time::Instant::now() + self.operation_timeout;
        let runtime = tokio::runtime::Handle::try_current().context(AdmissionUnavailable)?;
        runtime.block_on(async {
            tokio::time::timeout_at(deadline, operation)
                .await
                .context(AdmissionUnavailable)?
        })
    }

    async fn mark_once_async(&self, namespace: &str, key: &str, ttl: Duration) -> Result<()> {
        let redis_key = self.redis_key(namespace, key);
        let ttl_secs = usize::try_from(ttl.as_secs().max(1)).context(AdmissionUnavailable)?;
        let mut conn = self
            .client
            .get_tokio_connection()
            .await
            .context(AdmissionUnavailable)?;
        let options = SetOptions::default()
            .conditional_set(ExistenceCheck::NX)
            .with_expiration(SetExpiry::EX(ttl_secs));
        let result: Option<String> = conn
            .set_options(&redis_key, "1", options)
            .await
            .context(AdmissionUnavailable)?;

        if result.is_some() {
            Ok(())
        } else {
            Err(anyhow!("Sybil proof already used"))
        }
    }

    async fn health_check_async(&self) -> Result<()> {
        let mut conn = self
            .client
            .get_tokio_connection()
            .await
            .context(AdmissionUnavailable)?;
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .context(AdmissionUnavailable)?;
        Ok(())
    }
}

impl ReplayStore for RedisReplayStore {
    fn mark_once(&self, namespace: &str, key: &str, ttl: Duration) -> Result<()> {
        self.with_deadline(self.mark_once_async(namespace, key, ttl))
    }
    fn health_check(&self) -> Result<()> {
        self.with_deadline(self.health_check_async())
    }
}

pub fn memory_replay_store() -> Arc<dyn ReplayStore> {
    Arc::new(InMemoryReplayStore::default())
}

pub fn replay_store_from_env() -> Result<Arc<dyn ReplayStore>> {
    let backend = std::env::var("SYBIL_REPLAY_STORE").unwrap_or_else(|_| "memory".to_string());
    match backend.to_ascii_lowercase().as_str() {
        "memory" | "in_memory" => {
            info!("using in-memory Sybil replay store");
            Ok(memory_replay_store())
        }
        "redis" => {
            let redis_url = std::env::var("SYBIL_REPLAY_REDIS_URL")
                .or_else(|_| std::env::var("REDIS_URL"))
                .context("SYBIL_REPLAY_STORE=redis requires SYBIL_REPLAY_REDIS_URL or REDIS_URL")?;
            let key_prefix = std::env::var("SYBIL_REPLAY_KEY_PREFIX")
                .unwrap_or_else(|_| "freebird:sybil:replay".to_string());
            info!(key_prefix = %key_prefix, "using Redis Sybil replay store");
            Ok(Arc::new(RedisReplayStore::new(&redis_url, key_prefix)?))
        }
        other => {
            warn!(backend = %other, "unknown Sybil replay store backend");
            Err(anyhow!(
                "unknown SYBIL_REPLAY_STORE '{}'; expected memory or redis",
                other
            ))
        }
    }
}

#[cfg(test)]
#[path = "redis_deadline_tests.rs"]
mod redis_deadline_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_configuration_rejects_hostnames_without_network_io() {
        for url in [
            "redis://localhost/",
            "redis://redis.example.invalid/",
            "rediss://user:private-password@redis.example.invalid:6380/4",
            "redis://127.0.0.1.example.invalid/",
        ] {
            let error = RedisReplayStore::new(url, "test")
                .err()
                .expect("hostname rejected");
            assert_eq!(error.to_string(), "Redis replay endpoint must be a numeric IPv4/IPv6 address or Unix socket; hostnames are not supported");
            assert!(!format!("{error:#}").contains("private-password"));
        }
    }

    #[test]
    fn replay_configuration_preserves_numeric_auth_db_and_tls_without_connecting() {
        // No runtime or server: construction is configuration parsing only.
        for scheme in ["redis", "rediss"] {
            for (host, expected) in [("192.0.2.1", "192.0.2.1"), ("[2001:db8::1]", "2001:db8::1")] {
                let store =
                    RedisReplayStore::new(&format!("{scheme}://user:p%40ss@{host}:6380/4"), "test")
                        .unwrap();
                let info = store.client.get_connection_info();
                assert_eq!(info.redis.db, 4);
                assert_eq!(info.redis.username.as_deref(), Some("user"));
                assert_eq!(info.redis.password.as_deref(), Some("p@ss"));
                match &info.addr {
                    ConnectionAddr::Tcp(host, port) => {
                        assert_eq!(scheme, "redis");
                        assert_eq!(host, expected);
                        assert_eq!(*port, 6380);
                    }
                    ConnectionAddr::TcpTls {
                        host,
                        port,
                        insecure,
                        ..
                    } => {
                        assert_eq!(scheme, "rediss");
                        assert_eq!(host, expected);
                        assert_eq!(*port, 6380);
                        assert!(!insecure);
                    }
                    _ => panic!("expected TCP endpoint"),
                }
            }
        }
        let store = RedisReplayStore::new("rediss://[::1]/0#insecure", "test").unwrap();
        assert!(matches!(
            store.client.get_connection_info().addr,
            ConnectionAddr::TcpTls { insecure: true, .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn replay_configuration_preserves_unix_auth_and_db_without_connecting() {
        for scheme in ["unix", "redis+unix"] {
            let store = RedisReplayStore::new(
                &format!("{scheme}:///nonexistent/replay.sock?db=4&user=user&pass=p%40ss"),
                "test",
            )
            .unwrap();
            let info = store.client.get_connection_info();
            assert!(
                matches!(&info.addr, ConnectionAddr::Unix(path) if path == std::path::Path::new("/nonexistent/replay.sock"))
            );
            assert_eq!(info.redis.db, 4);
            assert_eq!(info.redis.username.as_deref(), Some("user"));
            assert_eq!(info.redis.password.as_deref(), Some("p@ss"));
        }
    }

    #[test]
    fn memory_store_rejects_replay_until_ttl_expires() {
        let store = InMemoryReplayStore::default();
        store
            .mark_once("test", "proof", Duration::from_secs(60))
            .unwrap();
        assert!(store
            .mark_once("test", "proof", Duration::from_secs(60))
            .is_err());

        // Expire explicitly rather than racing a one-millisecond wall-clock TTL.
        store.entries.lock().unwrap().insert(
            InMemoryReplayStore::scoped_key("test", "proof"),
            Instant::now(),
        );
        assert!(store
            .mark_once("test", "proof", Duration::from_secs(60))
            .is_ok());
    }

    #[test]
    fn memory_store_scopes_namespaces() {
        let store = InMemoryReplayStore::default();
        store
            .mark_once("one", "proof", Duration::from_secs(60))
            .unwrap();
        assert!(store
            .mark_once("two", "proof", Duration::from_secs(60))
            .is_ok());
    }
}
