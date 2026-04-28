// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.
use anyhow::{Context, Result};
use async_trait::async_trait;
use redis::{aio::ConnectionLike, AsyncCommands, Script};
use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Error types for store operations.
#[derive(Debug)]
pub enum StoreError {
    Connection(String),
    Configuration(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Connection(msg) => write!(f, "Store connection error: {msg}"),
            StoreError::Configuration(msg) => write!(f, "Store configuration error: {msg}"),
        }
    }
}

impl std::error::Error for StoreError {}

//
// ─── REDIS LUA SCRIPT ────────────────────────────────────────────────
//   Atomic set-if-absent with optional expiry
//
const LUA_MARK_SPENT: &str = r#"
  -- KEYS[1] = token_key, ARGV[1] = ttl (seconds)
  if redis.call('SETNX', KEYS[1], '1') == 1 then
    local ttl = tonumber(ARGV[1])
    if ttl and ttl > 0 then
      redis.call('EXPIRE', KEYS[1], ttl)
    end
    return 1
  else
    return 0
  end
"#;

//
// ─── LOW-LEVEL REDIS UTILITIES ───────────────────────────────────────
//
pub async fn has_been_spent<C: ConnectionLike + Send>(
    conn: &mut C,
    token_key: &str,
) -> Result<bool> {
    let v: Option<String> = conn.get(token_key).await?;
    Ok(v.is_some())
}

pub async fn mark_spent_atomic<C: ConnectionLike + Send>(
    conn: &mut C,
    token_key: &str,
    ttl_seconds: Option<usize>,
) -> Result<bool> {
    let script = Script::new(LUA_MARK_SPENT);
    let res: i32 = script
        .key(token_key)
        .arg(ttl_seconds.unwrap_or(0))
        .invoke_async(conn)
        .await
        .context("invoke redis lua")?;
    Ok(res == 1)
}

//
// ─── GENERIC SPEND STORE TRAIT ──────────────────────────────────────
//
#[async_trait]
pub trait SpendStore: Send + Sync {
    /// Attempts to mark a spend handle as used.
    /// Returns true if this is the first time (fresh),
    /// false if it was already present (replay).
    ///
    /// `ttl = None` keeps the replay record for the store's lifetime. The V4
    /// verifier uses non-expiring records because V4 tokens do not carry an
    /// issuer-enforced expiration timestamp.
    async fn mark_spent(&self, key: &str, ttl: Option<Duration>) -> Result<bool>;
}

//
// ─── IN-MEMORY BACKEND ───────────────────────────────────────────────
//
#[derive(Default)]
pub struct InMemoryStore {
    map: Arc<RwLock<HashMap<String, Option<Instant>>>>,
}

#[async_trait]
impl SpendStore for InMemoryStore {
    async fn mark_spent(&self, key: &str, ttl: Option<Duration>) -> Result<bool> {
        let mut map = self.map.write().await;
        let now = Instant::now();

        // purge expired
        map.retain(|_, exp| match exp {
            Some(exp) => *exp > now,
            None => true,
        });

        // Nullifier keys are SHA-256 hashes — standard HashMap lookup is safe
        // (timing attacks on hash lookups are not meaningful for random-looking keys)
        if map.contains_key(key) {
            debug!("replay detected (in-memory)");
            Ok(false)
        } else {
            map.insert(key.to_owned(), ttl.map(|ttl| now + ttl));
            debug!(ttl=?ttl, "marked spent (in-memory)");
            Ok(true)
        }
    }
}

//
// ─── REDIS BACKEND ──────────────────────────────────────────────────
//
pub struct RedisStore {
    pool: deadpool_redis::Pool,
}

impl RedisStore {
    pub fn new(url: &str) -> Result<Self> {
        let cfg = deadpool_redis::Config::from_url(url);
        let pool = cfg
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .with_context(|| format!("create redis pool @ {}", url))?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl SpendStore for RedisStore {
    async fn mark_spent(&self, key: &str, ttl: Option<Duration>) -> Result<bool> {
        let ttl_secs = ttl.map(|ttl| ttl.as_secs().max(1) as usize);
        let mut conn = self.pool.get().await?;
        let fresh = mark_spent_atomic(&mut *conn, key, ttl_secs).await?;

        if fresh {
            info!(ttl = ?ttl_secs, "marked spent (redis)");
        } else {
            warn!("replay detected (redis)");
        }
        Ok(fresh)
    }
}

//
// ─── FACTORY FUNCTION ────────────────────────────────────────────────
//
pub enum StoreBackend {
    InMemory,
    Redis(String),
}

impl StoreBackend {
    pub async fn build(self) -> Result<Arc<dyn SpendStore>, StoreError> {
        match self {
            StoreBackend::InMemory => {
                info!("using InMemory spend store");
                Ok(Arc::new(InMemoryStore::default()))
            }
            StoreBackend::Redis(url) => {
                info!(%url, "using Redis spend store");
                let store = RedisStore::new(&url).map_err(|e| {
                    StoreError::Connection(format!("Failed to connect to Redis: {e}"))
                })?;
                Ok(Arc::new(store))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_first_mark_returns_true() {
        let store = InMemoryStore::default();
        let result = store
            .mark_spent("key-1", Some(Duration::from_secs(60)))
            .await
            .unwrap();
        assert!(result, "first mark_spent should return true (fresh)");
    }

    #[tokio::test]
    async fn test_replay_returns_false() {
        let store = InMemoryStore::default();
        let ttl = Some(Duration::from_secs(60));
        store.mark_spent("key-1", ttl).await.unwrap();
        let result = store.mark_spent("key-1", ttl).await.unwrap();
        assert!(!result, "second mark_spent should return false (replay)");
    }

    #[tokio::test]
    async fn test_different_keys_independent() {
        let store = InMemoryStore::default();
        let ttl = Some(Duration::from_secs(60));
        let a = store.mark_spent("key-a", ttl).await.unwrap();
        let b = store.mark_spent("key-b", ttl).await.unwrap();
        assert!(a, "key-a should be fresh");
        assert!(b, "key-b should be fresh");
    }

    #[tokio::test]
    async fn test_expired_entry_allows_reuse() {
        let store = InMemoryStore::default();
        let ttl = Some(Duration::from_millis(1));
        let first = store.mark_spent("key-exp", ttl).await.unwrap();
        assert!(first);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let second = store.mark_spent("key-exp", ttl).await.unwrap();
        assert!(second, "expired entry should allow reuse");
    }

    #[tokio::test]
    async fn test_two_stores_independent() {
        let store_a = InMemoryStore::default();
        let store_b = InMemoryStore::default();
        let ttl = Some(Duration::from_secs(60));
        store_a.mark_spent("shared-key", ttl).await.unwrap();
        let result = store_b.mark_spent("shared-key", ttl).await.unwrap();
        assert!(result, "separate stores should not share state");
    }

    #[tokio::test]
    async fn test_non_expiring_entry_rejects_reuse() {
        let store = InMemoryStore::default();
        let first = store.mark_spent("key-persistent", None).await.unwrap();
        let second = store.mark_spent("key-persistent", None).await.unwrap();
        assert!(first);
        assert!(!second, "non-expiring entry should reject reuse");
    }
}
