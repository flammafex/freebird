// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.
use anyhow::{Context, Result};
use async_trait::async_trait;
use freebird_common::api::EXCHANGE_MAX_VALID_UNTIL;
use redis::{aio::ConnectionLike, AsyncCommands, Script};
use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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

/// Convert an inclusive V5 validity endpoint to Redis's exclusive absolute
/// expiry. The upper bound is shared with exchange V2, whose Lua paths must
/// represent validity timestamps exactly.
pub fn v5_replay_expires_at(valid_until: i64) -> Result<u64> {
    if !(1..=EXCHANGE_MAX_VALID_UNTIL).contains(&valid_until) {
        anyhow::bail!("V5 replay validity endpoint is out of range");
    }
    u64::try_from(valid_until)?
        .checked_add(1)
        .context("V5 replay expiry overflow")
}

pub async fn mark_spent_exat_atomic<C: ConnectionLike + Send>(
    conn: &mut C,
    token_key: &str,
    expires_at: u64,
) -> Result<bool> {
    let result: Option<String> = redis::cmd("SET")
        .arg(token_key)
        .arg("1")
        .arg("NX")
        .arg("EXAT")
        .arg(expires_at)
        .query_async(conn)
        .await
        .context("invoke redis SET NX EXAT")?;
    Ok(result.is_some())
}

//
// ─── GENERIC SPEND STORE TRAIT ──────────────────────────────────────
//
#[async_trait]
pub trait SpendStore: Send + Sync {
    /// Check that the backing store is reachable.  Readiness must not infer
    /// this from successful construction of a connection pool.
    async fn health_check(&self) -> Result<()>;
    /// Attempts to mark a spend handle as used.
    /// Returns true if this is the first time (fresh),
    /// false if it was already present (replay).
    ///
    /// `ttl = None` keeps the replay record for the store's lifetime. The V4
    /// verifier uses non-expiring records because V4 tokens do not carry an
    /// issuer-enforced expiration timestamp.
    async fn mark_spent(&self, key: &str, ttl: Option<Duration>) -> Result<bool>;

    /// Mark a V5 spend through the inclusive `valid_until` second. Persistent
    /// implementations must use the absolute expiry `valid_until + 1` rather
    /// than deriving a relative TTL from the verifier's local clock.
    async fn mark_spent_through(&self, _key: &str, valid_until: i64) -> Result<bool> {
        v5_replay_expires_at(valid_until)?;
        anyhow::bail!("absolute replay expiry is unsupported by this store")
    }
}

//
// ─── IN-MEMORY BACKEND ───────────────────────────────────────────────
//
#[derive(Clone, Copy)]
enum MemoryExpiry {
    Relative(Instant),
    Absolute(u64),
}

#[derive(Clone, Copy)]
struct ReplayNow {
    monotonic: Instant,
    unix_seconds: u64,
}

pub struct InMemoryStore {
    map: Arc<RwLock<HashMap<String, Option<MemoryExpiry>>>>,
    clock: Arc<dyn Fn() -> ReplayNow + Send + Sync>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self {
            map: Arc::new(RwLock::new(HashMap::new())),
            clock: Arc::new(|| ReplayNow {
                monotonic: Instant::now(),
                unix_seconds: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            }),
        }
    }
}

impl InMemoryStore {
    async fn mark_spent_with_expiry(
        &self,
        key: &str,
        expiry: Option<MemoryExpiry>,
    ) -> Result<bool> {
        let mut map = self.map.write().await;
        let now = (self.clock)();

        map.retain(|_, expiry| match expiry {
            Some(MemoryExpiry::Relative(expires_at)) => *expires_at > now.monotonic,
            Some(MemoryExpiry::Absolute(expires_at)) => *expires_at > now.unix_seconds,
            None => true,
        });

        if matches!(expiry, Some(MemoryExpiry::Absolute(expires_at)) if expires_at <= now.unix_seconds)
        {
            anyhow::bail!("V5 replay expiry has elapsed");
        }

        // Nullifier keys are SHA-256 hashes — standard HashMap lookup is safe
        // (timing attacks on hash lookups are not meaningful for random-looking keys)
        if map.contains_key(key) {
            debug!("replay detected (in-memory)");
            Ok(false)
        } else {
            map.insert(key.to_owned(), expiry);
            debug!("marked spent (in-memory)");
            Ok(true)
        }
    }
}

#[async_trait]
impl SpendStore for InMemoryStore {
    async fn health_check(&self) -> Result<()> {
        anyhow::bail!("in-memory replay store is not persistent")
    }

    async fn mark_spent(&self, key: &str, ttl: Option<Duration>) -> Result<bool> {
        let now = (self.clock)();
        self.mark_spent_with_expiry(
            key,
            ttl.map(|ttl| MemoryExpiry::Relative(now.monotonic + ttl)),
        )
        .await
    }

    async fn mark_spent_through(&self, key: &str, valid_until: i64) -> Result<bool> {
        let expires_at = v5_replay_expires_at(valid_until)?;
        self.mark_spent_with_expiry(key, Some(MemoryExpiry::Absolute(expires_at)))
            .await
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
    async fn health_check(&self) -> Result<()> {
        let mut conn = self.pool.get().await.context("get redis connection")?;
        let _: String = redis::cmd("PING").query_async(&mut *conn).await?;
        Ok(())
    }

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

    async fn mark_spent_through(&self, key: &str, valid_until: i64) -> Result<bool> {
        let expires_at = v5_replay_expires_at(valid_until)?;
        let mut conn = self.pool.get().await?;
        let fresh = mark_spent_exat_atomic(&mut *conn, key, expires_at).await?;

        if fresh {
            info!(expires_at, "marked V5 spend with absolute expiry (redis)");
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
    use freebird_common::spend_key::v5_spend_key;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    fn store_at(unix_seconds: Arc<AtomicU64>) -> InMemoryStore {
        let monotonic = Instant::now();
        InMemoryStore {
            map: Arc::new(RwLock::new(HashMap::new())),
            clock: Arc::new(move || ReplayNow {
                monotonic,
                unix_seconds: unix_seconds.load(Ordering::Relaxed),
            }),
        }
    }

    async fn emulate_exchange_reservation(
        store: &InMemoryStore,
        key: &str,
        valid_until: i64,
    ) -> Result<bool> {
        let expires_at = v5_replay_expires_at(valid_until)?;
        store
            .mark_spent_with_expiry(key, Some(MemoryExpiry::Absolute(expires_at)))
            .await
    }

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

    #[tokio::test]
    async fn v5_marker_remains_through_inclusive_valid_until() {
        let now = Arc::new(AtomicU64::new(100));
        let store = store_at(now.clone());

        assert!(store.mark_spent_through("v5-inclusive", 100).await.unwrap());
        assert!(!store.mark_spent_through("v5-inclusive", 100).await.unwrap());

        now.store(101, Ordering::Relaxed);
        assert!(store.mark_spent_through("v5-inclusive", 101).await.unwrap());
    }

    #[tokio::test]
    async fn verifier_first_marker_survives_direct_window_through_graph_horizon() {
        let now = Arc::new(AtomicU64::new(100));
        let key = v5_spend_key("shared-nullifier");
        let direct_valid_until = 120;
        let graph_valid_until = 200;

        let verifier_first = store_at(now.clone());
        assert!(verifier_first
            .mark_spent_through(&key, graph_valid_until)
            .await
            .unwrap());
        now.store(direct_valid_until as u64 + 1, Ordering::Relaxed);
        assert!(now.load(Ordering::Relaxed) < graph_valid_until as u64);
        assert!(
            !emulate_exchange_reservation(&verifier_first, &key, graph_valid_until)
                .await
                .unwrap(),
            "exchange must reject a verifier-first spend after the shorter direct window"
        );

        let exchange_first = store_at(now);
        assert!(
            emulate_exchange_reservation(&exchange_first, &key, graph_valid_until)
                .await
                .unwrap()
        );
        assert!(!exchange_first
            .mark_spent_through(&key, graph_valid_until)
            .await
            .unwrap());
    }

    #[test]
    fn v5_absolute_expiry_rejects_malformed_and_overflowing_endpoints() {
        assert_eq!(v5_replay_expires_at(1).unwrap(), 2);
        assert_eq!(
            v5_replay_expires_at(EXCHANGE_MAX_VALID_UNTIL).unwrap(),
            EXCHANGE_MAX_VALID_UNTIL as u64 + 1
        );
        assert!(v5_replay_expires_at(0).is_err());
        assert!(v5_replay_expires_at(-1).is_err());
        assert!(v5_replay_expires_at(EXCHANGE_MAX_VALID_UNTIL + 1).is_err());
        assert!(v5_replay_expires_at(i64::MAX).is_err());
    }
}
