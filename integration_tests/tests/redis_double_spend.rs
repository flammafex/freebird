use anyhow::Result;
use async_trait::async_trait;
use freebird_verifier::store::{RedisStore, SpendStore};
use futures::future::join_all;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::{Barrier, Mutex};

const CONCURRENCY: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyCode {
    Success,
    ReplayDetected,
    StoreError,
}

async fn verify_once(store: &dyn SpendStore, key: &str, ttl: Duration) -> VerifyCode {
    match store.mark_spent(key, Some(ttl)).await {
        Ok(true) => VerifyCode::Success,
        Ok(false) => VerifyCode::ReplayDetected,
        Err(_) => VerifyCode::StoreError,
    }
}

async fn verify_batch_codes(
    store: &dyn SpendStore,
    keys: &[String],
    ttl: Duration,
) -> Vec<VerifyCode> {
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        out.push(verify_once(store, key, ttl).await);
    }
    out
}

struct FlakyRedisStore {
    inner: Arc<RedisStore>,
    failures_remaining: Mutex<usize>,
}

impl FlakyRedisStore {
    fn new(inner: Arc<RedisStore>, fail_first_n: usize) -> Self {
        Self {
            inner,
            failures_remaining: Mutex::new(fail_first_n),
        }
    }
}

#[async_trait]
impl SpendStore for FlakyRedisStore {
    async fn mark_spent(&self, key: &str, ttl: Option<Duration>) -> anyhow::Result<bool> {
        let mut guard = self.failures_remaining.lock().await;
        if *guard > 0 {
            *guard -= 1;
            anyhow::bail!("injected transient redis failure");
        }
        drop(guard);
        self.inner.mark_spent(key, ttl).await
    }
}

async fn redis_store_or_skip() -> Option<Arc<RedisStore>> {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let store = match RedisStore::new(&redis_url) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!(
                "Skipping Redis test: could not create client for {}: {}",
                redis_url, e
            );
            return None;
        }
    };

    let probe_key = format!("test:redis_probe:{}", uuid::Uuid::new_v4());
    if let Err(e) = store
        .mark_spent(&probe_key, Some(Duration::from_secs(1)))
        .await
    {
        eprintln!(
            "Skipping Redis test: Redis command probe failed for {}: {}",
            redis_url, e
        );
        return None;
    }

    Some(store)
}

#[tokio::test]
async fn test_redis_atomic_double_spend_protection() -> Result<()> {
    let Some(store) = redis_store_or_skip().await else {
        return Ok(());
    };

    // 2. Prepare the attack
    // A random nullifier that hasn't been seen before
    let nullifier = uuid::Uuid::new_v4().to_string();
    let spend_key = format!("test:double_spend:{}", nullifier);
    let ttl = Duration::from_secs(60);

    println!(
        "🚀 Launching {} concurrent spend requests for key: {}",
        CONCURRENCY, spend_key
    );

    // 3. Launch concurrent tasks
    // We use a Barrier (conceptually) or just spawn them all at once.
    // Tokio handles spawn execution effectively in parallel.
    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for _ in 0..CONCURRENCY {
        let store_clone = store.clone();
        let key_clone = spend_key.clone();
        let counter = success_count.clone();

        handles.push(tokio::spawn(async move {
            // Try to mark as spent
            match store_clone.mark_spent(&key_clone, Some(ttl)).await {
                Ok(true) => {
                    // Success: We were the first!
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                Ok(false) => {
                    // Failed: It was already spent (Replay detected)
                }
                Err(e) => {
                    eprintln!("Store error: {}", e);
                }
            }
        }));
    }

    // 4. Await all results
    join_all(handles).await;

    // 5. Assertions
    let successes = success_count.load(Ordering::SeqCst);
    println!(
        "📊 Results: {} successes out of {} attempts",
        successes, CONCURRENCY
    );

    assert_eq!(
        successes, 1,
        "CRITICAL: Double spend detected! More than one request succeeded."
    );

    // Verify the key is actually in Redis (ttl check)
    // We can't easily verify TTL without raw redis client, but mark_spent returning true implies it was set.

    Ok(())
}

#[tokio::test]
async fn test_redis_n_way_race_duplicate_submissions() -> Result<()> {
    const N_WAY: usize = 200;
    let Some(store) = redis_store_or_skip().await else {
        return Ok(());
    };

    let key = format!("test:n_way_race:{}", uuid::Uuid::new_v4());
    let ttl = Duration::from_secs(60);
    let barrier = Arc::new(Barrier::new(N_WAY));
    let success_count = Arc::new(AtomicUsize::new(0));
    let replay_count = Arc::new(AtomicUsize::new(0));
    let error_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(N_WAY);
    for _ in 0..N_WAY {
        let store = store.clone();
        let key = key.clone();
        let ttl = ttl;
        let barrier = barrier.clone();
        let success_count = success_count.clone();
        let replay_count = replay_count.clone();
        let error_count = error_count.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            match verify_once(store.as_ref(), &key, ttl).await {
                VerifyCode::Success => {
                    success_count.fetch_add(1, Ordering::SeqCst);
                }
                VerifyCode::ReplayDetected => {
                    replay_count.fetch_add(1, Ordering::SeqCst);
                }
                VerifyCode::StoreError => {
                    error_count.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }

    join_all(handles).await;

    assert_eq!(success_count.load(Ordering::SeqCst), 1);
    assert_eq!(replay_count.load(Ordering::SeqCst), N_WAY - 1);
    assert_eq!(error_count.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn test_redis_transient_failure_handling_path() -> Result<()> {
    let Some(base) = redis_store_or_skip().await else {
        return Ok(());
    };

    let flaky = FlakyRedisStore::new(base, 1);
    let key = format!("test:transient:{}", uuid::Uuid::new_v4());
    let ttl = Duration::from_secs(60);

    let first = verify_once(&flaky, &key, ttl).await;
    let second = verify_once(&flaky, &key, ttl).await;
    let third = verify_once(&flaky, &key, ttl).await;

    assert_eq!(first, VerifyCode::StoreError);
    assert_eq!(second, VerifyCode::Success);
    assert_eq!(third, VerifyCode::ReplayDetected);
    Ok(())
}

#[tokio::test]
async fn test_redis_batch_duplicate_error_code_stability() -> Result<()> {
    let Some(store) = redis_store_or_skip().await else {
        return Ok(());
    };

    let ttl = Duration::from_secs(60);
    let a = format!("test:batch:a:{}", uuid::Uuid::new_v4());
    let b = format!("test:batch:b:{}", uuid::Uuid::new_v4());
    let keys = vec![a.clone(), b.clone(), a.clone(), a.clone(), b.clone()];
    let codes = verify_batch_codes(store.as_ref(), &keys, ttl).await;

    assert_eq!(
        codes,
        vec![
            VerifyCode::Success,
            VerifyCode::Success,
            VerifyCode::ReplayDetected,
            VerifyCode::ReplayDetected,
            VerifyCode::ReplayDetected,
        ]
    );
    Ok(())
}
