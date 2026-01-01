use anyhow::Result;
use futures::future::join_all;
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};
use std::time::Duration;
use freebird_verifier::store::{RedisStore, SpendStore};

const CONCURRENCY: usize = 50;

#[tokio::test]
async fn test_redis_atomic_double_spend_protection() -> Result<()> {
    // 1. Setup Redis Store
    // We use a distinct prefix or DB in real apps, but for this test
    // we'll just generate a random nullifier key to avoid collisions.
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    
    let store = match RedisStore::new(&redis_url) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("⚠️ Skipping Redis test: could not connect to {}: {}", redis_url, e);
            return Ok(());
        }
    };

    // 2. Prepare the attack
    // A random nullifier that hasn't been seen before
    let nullifier = uuid::Uuid::new_v4().to_string();
    let spend_key = format!("test:double_spend:{}", nullifier);
    let ttl = Duration::from_secs(60);

    println!("🚀 Launching {} concurrent spend requests for key: {}", CONCURRENCY, spend_key);

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
    println!("📊 Results: {} successes out of {} attempts", successes, CONCURRENCY);

    assert_eq!(successes, 1, "CRITICAL: Double spend detected! More than one request succeeded.");
    
    // Verify the key is actually in Redis (ttl check)
    // We can't easily verify TTL without raw redis client, but mark_spent returning true implies it was set.

    Ok(())
}