// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.
use anyhow::{Context, Result};
use async_trait::async_trait;
use redis::{aio::ConnectionLike, AsyncCommands, Script};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use subtle::ConstantTimeEq;

//
// ─── REDIS LUA SCRIPT ────────────────────────────────────────────────
//   Atomic set-if-absent with expiry
//
const LUA_MARK_SPENT: &str = r#"
  -- KEYS[1] = token_key, ARGV[1] = ttl (seconds)
  if redis.call('SETNX', KEYS[1], '1') == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
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
    ttl_seconds: usize,
) -> Result<bool> {
    let script = Script::new(LUA_MARK_SPENT);
    let res: i32 = script
        .key(token_key)
        .arg(ttl_seconds)
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
    async fn mark_spent(&self, key: &str, ttl: Duration) -> Result<bool>;
}

//
// ─── CONSTANT-TIME STRING COMPARISON ────────────────────────────────
//
/// Constant-time comparison for nullifier keys to prevent timing attacks
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

//
// ─── IN-MEMORY BACKEND ───────────────────────────────────────────────
//
#[derive(Default)]
pub struct InMemoryStore {
    map: Arc<RwLock<HashMap<String, Instant>>>,
}

#[async_trait]
impl SpendStore for InMemoryStore {
    async fn mark_spent(&self, key: &str, ttl: Duration) -> Result<bool> {
        let mut map = self.map.write().await;
        let now = Instant::now();

        // purge expired
        map.retain(|_, &mut exp| exp > now);

        // Use constant-time comparison to check for key existence
        // This prevents timing attacks on nullifier lookup
        let mut found = false;
        for stored_key in map.keys() {
            if constant_time_eq(stored_key, key) {
                found = true;
                break;
            }
        }

        if found {
            debug!(%key, "replay detected (in-memory)");
            Ok(false)
        } else {
            map.insert(key.to_owned(), now + ttl);
            debug!(%key, ttl=?ttl, "marked spent (in-memory)");
            Ok(true)
        }
    }
}

//
// ─── REDIS BACKEND ──────────────────────────────────────────────────
//
pub struct RedisStore {
    client: redis::Client,
}

impl RedisStore {
    pub fn new(url: &str) -> Result<Self> {
        let client =
            redis::Client::open(url).with_context(|| format!("connect redis @ {}", url))?;
        Ok(Self { client })
    }

    async fn get_conn(&self) -> Result<redis::aio::Connection> {
        let mut backoff_ms = 200u64;
        for attempt in 1..=3 {
            match self.client.get_async_connection().await {
                Ok(conn) => return Ok(conn),
                Err(e) if attempt < 3 => {
                    warn!(
                        attempt,
                        "redis connect failed: {e}; retrying in {backoff_ms}ms"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms *= 2;
                }
                Err(e) => return Err(e.into()),
            }
        }
        unreachable!()
    }
}

#[async_trait]
impl SpendStore for RedisStore {
    async fn mark_spent(&self, key: &str, ttl: Duration) -> Result<bool> {
        let ttl_secs = ttl.as_secs().max(1) as usize;
        let mut conn = self.get_conn().await?;
        let fresh = mark_spent_atomic(&mut conn, key, ttl_secs).await?;

        if fresh {
            info!(%key, ttl = %ttl_secs, "marked spent (redis)");
        } else {
            warn!(%key, "replay detected (redis)");
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
    pub async fn build(self) -> Arc<dyn SpendStore> {
        match self {
            StoreBackend::InMemory => {
                info!("using InMemory spend store");
                Arc::new(InMemoryStore::default())
            }
            StoreBackend::Redis(url) => {
                info!(%url, "using Redis spend store");
                Arc::new(RedisStore::new(&url).expect("connect redis"))
            }
        }
    }
}
