// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: In-Memory Double-Spend Protection
//
// This test validates that the InMemoryStore correctly rejects replay attempts
// under high concurrency, mirroring the Redis double-spend test but for the
// in-memory backend.

use anyhow::Result;
use futures::future::join_all;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use freebird_verifier::store::{InMemoryStore, SpendStore};

const CONCURRENCY: usize = 50;

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
