use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

pub trait ReplayStore: Send + Sync {
    fn mark_once(&self, namespace: &str, key: &str, ttl: Duration) -> Result<()>;
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
}

pub struct RedisReplayStore {
    client: redis::Client,
    key_prefix: String,
}

impl RedisReplayStore {
    pub fn new(redis_url: &str, key_prefix: impl Into<String>) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .with_context(|| format!("create Redis replay client at {redis_url}"))?;
        Ok(Self {
            client,
            key_prefix: key_prefix.into(),
        })
    }

    fn redis_key(&self, namespace: &str, key: &str) -> String {
        format!("{}:{}:{}", self.key_prefix, namespace, key)
    }

    fn mark_once_blocking(&self, namespace: &str, key: &str, ttl: Duration) -> Result<()> {
        let redis_key = self.redis_key(namespace, key);
        let ttl_secs = ttl.as_secs().max(1) as usize;
        let mut conn = self.client.get_connection().context("connect to Redis")?;

        let result: Option<String> = redis::cmd("SET")
            .arg(&redis_key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query(&mut conn)
            .context("record Sybil replay key in Redis")?;

        if result.is_some() {
            Ok(())
        } else {
            Err(anyhow!("Sybil proof already used"))
        }
    }
}

impl ReplayStore for RedisReplayStore {
    fn mark_once(&self, namespace: &str, key: &str, ttl: Duration) -> Result<()> {
        self.mark_once_blocking(namespace, key, ttl)
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
mod tests {
    use super::*;

    #[test]
    fn memory_store_rejects_replay_until_ttl_expires() {
        let store = InMemoryReplayStore::default();
        store
            .mark_once("test", "proof", Duration::from_millis(1))
            .unwrap();
        assert!(store
            .mark_once("test", "proof", Duration::from_secs(60))
            .is_err());

        std::thread::sleep(Duration::from_millis(5));
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
