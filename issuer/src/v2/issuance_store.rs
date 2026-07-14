//! Durable, isolated Freebird V2 mint issuance state. This module is not wired
//! into routes, startup, admission, or signing providers.

use anyhow::{anyhow, Result};
use redis::{aio::Connection, AsyncCommands, Client, Script};
use std::time::Duration;

const PREFIX: &str = "freebird:v2:issuance:";
const RESERVE: &str = r#"
local state = redis.call('HGET', KEYS[1], 'state')
if not state then
  redis.call('HSET', KEYS[1], 'state', 'RESERVED', 'digest', ARGV[1], 'fence', ARGV[2])
  redis.call('PEXPIRE', KEYS[1], ARGV[3])
  return {1, ''}
end
local digest = redis.call('HGET', KEYS[1], 'digest')
if state == 'ISSUED' then
  if digest == ARGV[1] then return {3, redis.call('HGET', KEYS[1], 'response')} else return {4, ''} end
end
if state == 'RESERVED' then
  if redis.call('PTTL', KEYS[1]) <= 0 then
    redis.call('HSET', KEYS[1], 'state', 'RESERVED', 'digest', ARGV[1], 'fence', ARGV[2])
    redis.call('PEXPIRE', KEYS[1], ARGV[3])
    return {1, ''}
  end
  if digest == ARGV[1] then return {2, ''} else return {4, ''} end
end
return {4, ''}
"#;
const COMMIT: &str = r#"
local state = redis.call('HGET', KEYS[1], 'state')
local digest = redis.call('HGET', KEYS[1], 'digest')
local fence = redis.call('HGET', KEYS[1], 'fence')
if state == 'ISSUED' then
  if digest == ARGV[1] then return {3, redis.call('HGET', KEYS[1], 'response')} else return {4, ''} end
end
if state ~= 'RESERVED' or digest ~= ARGV[1] or fence ~= ARGV[2] or redis.call('PTTL', KEYS[1]) <= 0 then return {4, ''} end
redis.call('HSET', KEYS[1], 'state', 'ISSUED', 'response', ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return {1, ''}
"#;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReserveResult {
    Reserved { fence: u64 },
    InProgress,
    Replay(Vec<u8>),
    Conflict,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitResult {
    Committed,
    Replay(Vec<u8>),
    Conflict,
}

pub struct IssuanceStore {
    client: Client,
    reservation_ttl: Duration,
    issued_ttl: Duration,
}

impl IssuanceStore {
    pub fn new(redis_url: &str, reservation_ttl: Duration, issued_ttl: Duration) -> Result<Self> {
        Ok(Self {
            client: Client::open(redis_url)?,
            reservation_ttl,
            issued_ttl,
        })
    }
    async fn connection(&self) -> Result<Connection> {
        Ok(self.client.get_async_connection().await?)
    }
    fn key(request_id: &[u8]) -> String {
        format!("{PREFIX}request:{}", hex::encode(request_id))
    }
    async fn next_fence(&self, conn: &mut Connection) -> Result<u64> {
        Ok(conn.incr(format!("{PREFIX}fence"), 1u64).await?)
    }

    pub async fn reserve(&self, request_id: &[u8], request_digest: &[u8]) -> Result<ReserveResult> {
        let mut conn = self.connection().await?;
        let fence = self.next_fence(&mut conn).await?;
        let result: redis::Value = Script::new(RESERVE)
            .key(Self::key(request_id))
            .arg(hex::encode(request_digest))
            .arg(fence)
            .arg(self.reservation_ttl.as_millis() as u64)
            .invoke_async(&mut conn)
            .await?;
        let redis::Value::Bulk(mut values) = result else {
            return Err(anyhow!("invalid V2 reservation result"));
        };
        if values.len() != 2 {
            return Err(anyhow!("invalid V2 reservation result length"));
        }
        let redis::Value::Int(code) = values.remove(0) else {
            return Err(anyhow!("invalid V2 reservation status"));
        };
        match code {
            1 => Ok(ReserveResult::Reserved { fence }),
            2 => Ok(ReserveResult::InProgress),
            3 => match values.remove(0) {
                redis::Value::Data(response) => Ok(ReserveResult::Replay(response)),
                _ => Err(anyhow!("missing V2 replay response")),
            },
            4 => Ok(ReserveResult::Conflict),
            _ => Err(anyhow!("unknown V2 reservation result")),
        }
    }

    pub async fn commit(
        &self,
        request_id: &[u8],
        request_digest: &[u8],
        fence: u64,
        response: &[u8],
    ) -> Result<CommitResult> {
        let mut conn = self.connection().await?;
        let result: redis::Value = Script::new(COMMIT)
            .key(Self::key(request_id))
            .arg(hex::encode(request_digest))
            .arg(fence)
            .arg(response)
            .arg(self.issued_ttl.as_millis() as u64)
            .invoke_async(&mut conn)
            .await?;
        let redis::Value::Bulk(mut values) = result else {
            return Err(anyhow!("invalid V2 commit result"));
        };
        if values.len() != 2 {
            return Err(anyhow!("invalid V2 commit result length"));
        }
        let redis::Value::Int(code) = values.remove(0) else {
            return Err(anyhow!("invalid V2 commit status"));
        };
        match code {
            1 => Ok(CommitResult::Committed),
            3 => match values.remove(0) {
                redis::Value::Data(response) => Ok(CommitResult::Replay(response)),
                _ => Err(anyhow!("missing V2 committed response")),
            },
            4 => Ok(CommitResult::Conflict),
            _ => Err(anyhow!("unknown V2 commit result")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    async fn store() -> Option<IssuanceStore> {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let result = IssuanceStore::new(&url, Duration::from_millis(100), Duration::from_secs(60));
        let store = result.ok()?;
        let mut conn = store.connection().await.ok()?;
        if redis::cmd("PING")
            .query_async::<_, String>(&mut conn)
            .await
            .is_err()
        {
            return None;
        }
        Some(store)
    }
    async fn cleanup(store: &IssuanceStore, id: &[u8]) {
        if let Ok(mut c) = store.connection().await {
            let _: Result<(), _> = c.del(IssuanceStore::key(id)).await;
        }
    }
    #[tokio::test]
    async fn v2_redis_state_transitions_and_fencing() {
        let Some(store) = store().await else {
            eprintln!("skipping V2 Redis store test: Redis unavailable");
            return;
        };
        let id = b"v2-transition";
        let digest = b"digest-a";
        let reserved = store.reserve(id, digest).await.unwrap();
        let fence = match reserved {
            ReserveResult::Reserved { fence } => fence,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            store.reserve(id, digest).await.unwrap(),
            ReserveResult::InProgress
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        let reclaimed = store.reserve(id, b"digest-b").await.unwrap();
        let new_fence = match reclaimed {
            ReserveResult::Reserved { fence } => fence,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            store
                .commit(id, digest, fence, b"stale-response")
                .await
                .unwrap(),
            CommitResult::Conflict
        );
        assert_eq!(
            store
                .commit(id, b"digest-c", new_fence, b"conflicting-response")
                .await
                .unwrap(),
            CommitResult::Conflict
        );
        assert_eq!(
            store
                .commit(id, b"digest-b", new_fence, b"response")
                .await
                .unwrap(),
            CommitResult::Committed
        );
        assert_eq!(
            store.reserve(id, b"digest-b").await.unwrap(),
            ReserveResult::Replay(b"response".to_vec())
        );
        assert_eq!(
            store.reserve(id, b"digest-c").await.unwrap(),
            ReserveResult::Conflict
        );
        cleanup(&store, id).await;
    }
    #[tokio::test]
    async fn v2_redis_expiry_reclaim_and_concurrent_reserve() {
        let Some(store) = store().await else {
            eprintln!("skipping V2 Redis store test: Redis unavailable");
            return;
        };
        let id = b"v2-expiry";
        let first = store.reserve(id, b"digest-a").await.unwrap();
        assert!(matches!(first, ReserveResult::Reserved { .. }));
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(matches!(
            store.reserve(id, b"digest-b").await.unwrap(),
            ReserveResult::Reserved { .. }
        ));
        cleanup(&store, id).await;
        let store = Arc::new(store);
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let store = Arc::clone(&store);
            tasks.push(tokio::spawn(async move {
                store.reserve(b"v2-concurrent", b"digest-c").await.unwrap()
            }));
        }
        let mut reserved = 0;
        for task in tasks {
            if matches!(task.await.unwrap(), ReserveResult::Reserved { .. }) {
                reserved += 1;
            }
        }
        assert_eq!(reserved, 1);
        cleanup(&store, b"v2-concurrent").await;
    }
}
