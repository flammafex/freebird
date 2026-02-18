// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: In-Memory Double-Spend Protection
//
// This test validates that the InMemoryStore correctly rejects replay attempts
// under high concurrency, mirroring the Redis double-spend test but for the
// in-memory backend.

use anyhow::Result;
use async_trait::async_trait;
use futures::future::join_all;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::{Barrier, Mutex};
use std::time::Duration;

use freebird_verifier::store::{InMemoryStore, SpendStore};

const CONCURRENCY: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyCode {
    Success,
    ReplayDetected,
    StoreError,
}

async fn verify_once(store: &dyn SpendStore, key: &str, ttl: Duration) -> VerifyCode {
    match store.mark_spent(key, ttl).await {
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

struct FlakyInMemoryStore {
    inner: Arc<InMemoryStore>,
    failures_remaining: Mutex<usize>,
}

impl FlakyInMemoryStore {
    fn new(inner: Arc<InMemoryStore>, fail_first_n: usize) -> Self {
        Self {
            inner,
            failures_remaining: Mutex::new(fail_first_n),
        }
    }
}

#[async_trait]
impl SpendStore for FlakyInMemoryStore {
    async fn mark_spent(&self, key: &str, ttl: Duration) -> anyhow::Result<bool> {
        let mut guard = self.failures_remaining.lock().await;
        if *guard > 0 {
            *guard -= 1;
            anyhow::bail!("injected transient store failure");
        }
        drop(guard);
        self.inner.mark_spent(key, ttl).await
    }
}

#[tokio::test]
async fn test_memory_atomic_double_spend_protection() -> Result<()> {
    // 1. Setup InMemory Store
    let store = Arc::new(InMemoryStore::default());

    // 2. Prepare the attack
    // A unique nullifier for this test run
    let nullifier = uuid::Uuid::new_v4().to_string();
    let spend_key = format!("test:double_spend:{}", nullifier);
    let ttl = Duration::from_secs(60);

    println!(
        "🚀 Launching {} concurrent spend requests for key: {}",
        CONCURRENCY, spend_key
    );

    // 3. Launch concurrent tasks
    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for _ in 0..CONCURRENCY {
        let store_clone = store.clone();
        let key_clone = spend_key.clone();
        let counter = success_count.clone();

        handles.push(tokio::spawn(async move {
            // Try to mark as spent
            match store_clone.mark_spent(&key_clone, ttl).await {
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

    Ok(())
}

#[tokio::test]
async fn test_memory_ttl_expiration() -> Result<()> {
    // Test that expired entries are correctly cleaned up
    let store = Arc::new(InMemoryStore::default());
    let key = format!("test:ttl:{}", uuid::Uuid::new_v4());

    // Mark as spent with very short TTL
    let ttl = Duration::from_millis(100);
    let first = store.mark_spent(&key, ttl).await?;
    assert!(first, "First spend should succeed");

    // Immediately try again - should fail
    let second = store.mark_spent(&key, ttl).await?;
    assert!(!second, "Immediate replay should fail");

    // Wait for TTL to expire
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Try again after expiration - should succeed (entry expired)
    let after_ttl = store.mark_spent(&key, ttl).await?;
    assert!(after_ttl, "Spend after TTL expiration should succeed");

    println!("✅ TTL expiration works correctly");
    Ok(())
}

#[tokio::test]
async fn test_memory_different_keys_independent() -> Result<()> {
    // Test that different keys are tracked independently
    let store = Arc::new(InMemoryStore::default());
    let ttl = Duration::from_secs(60);

    let key1 = format!("test:key1:{}", uuid::Uuid::new_v4());
    let key2 = format!("test:key2:{}", uuid::Uuid::new_v4());
    let key3 = format!("test:key3:{}", uuid::Uuid::new_v4());

    // All first spends should succeed
    assert!(store.mark_spent(&key1, ttl).await?, "key1 first spend");
    assert!(store.mark_spent(&key2, ttl).await?, "key2 first spend");
    assert!(store.mark_spent(&key3, ttl).await?, "key3 first spend");

    // All replays should fail
    assert!(!store.mark_spent(&key1, ttl).await?, "key1 replay");
    assert!(!store.mark_spent(&key2, ttl).await?, "key2 replay");
    assert!(!store.mark_spent(&key3, ttl).await?, "key3 replay");

    println!("✅ Independent key tracking works correctly");
    Ok(())
}

#[tokio::test]
async fn test_memory_n_way_race_duplicate_submissions() -> Result<()> {
    // Stronger N-way race than the baseline test.
    const N_WAY: usize = 200;
    let store = Arc::new(InMemoryStore::default());
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
async fn test_memory_transient_failure_handling_path() -> Result<()> {
    let base = Arc::new(InMemoryStore::default());
    let flaky = FlakyInMemoryStore::new(base, 1);
    let key = format!("test:transient:{}", uuid::Uuid::new_v4());
    let ttl = Duration::from_secs(60);

    let first = verify_once(&flaky, &key, ttl).await;
    let second = verify_once(&flaky, &key, ttl).await;
    let third = verify_once(&flaky, &key, ttl).await;

    assert_eq!(first, VerifyCode::StoreError, "first call should surface transient store error");
    assert_eq!(second, VerifyCode::Success, "retry should succeed");
    assert_eq!(third, VerifyCode::ReplayDetected, "subsequent duplicate should be replay");
    Ok(())
}

#[tokio::test]
async fn test_memory_batch_duplicate_error_code_stability() -> Result<()> {
    let store = Arc::new(InMemoryStore::default());
    let ttl = Duration::from_secs(60);
    let a = format!("test:batch:a:{}", uuid::Uuid::new_v4());
    let b = format!("test:batch:b:{}", uuid::Uuid::new_v4());

    // Pattern: A, B, A, A, B
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
