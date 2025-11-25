// issuer/src/webauthn_store.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Redis-backed credential storage for WebAuthn
//!
//! This module provides persistent storage for WebAuthn credentials using Redis.
//! Credentials are stored with the following structure:
//! - Key: `webauthn:cred:{cred_id_base64}`
//! - Value: JSON-serialized credential data
//! - TTL: Optional expiration for credential lifecycle management
//!
//! # Security Considerations
//!
//! - Credentials contain public keys only (no secrets stored)
//! - User handles are hashed to prevent enumeration
//! - Redis should be configured with authentication and encryption in transit
//! - Consider using Redis ACLs to restrict access to webauthn:* keys

use anyhow::{Context, Result};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use webauthn_rs::prelude::Passkey;

// --- Types ---
/// Serializable credential data for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Credential ID (raw bytes)
    pub cred_id: Vec<u8>,
    /// Full PasskeyRegistration data from webauthn-rs
    pub credential: Passkey,
    /// User handle (hashed for privacy)
    pub user_id_hash: String,
    /// Registration timestamp (Unix seconds)
    pub registered_at: i64,
    /// Last used timestamp (Unix seconds, optional)
    pub last_used_at: Option<i64>,
}

// --- Abstraction ---

/// Unified wrapper for storage backends
#[derive(Clone)]
pub enum CredentialStore {
    Redis(RedisCredStore),
    InMemory(InMemoryCredStore),
}

impl CredentialStore {
    pub async fn save(&self, cred_id: Vec<u8>, credential: Passkey, user_id_hash: String) -> Result<()> {
        match self {
            Self::Redis(s) => s.save(cred_id, credential, user_id_hash).await,
            Self::InMemory(s) => s.save(cred_id, credential, user_id_hash).await,
        }
    }

    pub async fn load(&self, cred_id: &[u8]) -> Result<Option<StoredCredential>> {
        match self {
            Self::Redis(s) => s.load(cred_id).await,
            Self::InMemory(s) => s.load(cred_id).await,
        }
    }

    pub async fn load_user_credentials(&self, user_id_hash: &str) -> Result<Vec<StoredCredential>> {
        match self {
            Self::Redis(s) => s.load_user_credentials(user_id_hash).await,
            Self::InMemory(s) => s.load_user_credentials(user_id_hash).await,
        }
    }

    pub async fn update_last_used(&self, cred_id: &[u8]) -> Result<()> {
        match self {
            Self::Redis(s) => s.update_last_used(cred_id).await,
            Self::InMemory(s) => s.update_last_used(cred_id).await,
        }
    }

    pub async fn delete(&self, cred_id: &[u8]) -> Result<bool> {
        match self {
            Self::Redis(s) => s.delete(cred_id).await,
            Self::InMemory(s) => s.delete(cred_id).await,
        }
    }

    pub async fn list_all_credentials(&self) -> Result<Vec<StoredCredential>> {
        match self {
            Self::Redis(s) => s.list_all_credentials().await,
            Self::InMemory(s) => s.list_all_credentials().await,
        }
    }
}

// --- Redis Backend ---

#[derive(Clone)]
pub struct RedisCredStore {
    client: redis::Client,
    credential_ttl: Option<u64>,
}


impl RedisCredStore {
    pub fn new(redis_url: &str, credential_ttl: Option<u64>) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .with_context(|| format!("Failed to connect to Redis at {}", redis_url))?;
        Ok(Self { client, credential_ttl })
    }

    /// Get async connection with retry logic
    async fn get_connection(&self) -> Result<redis::aio::Connection> {
        let mut backoff_ms = 100u64;
        for attempt in 1..=3 {
            match self.client.get_async_connection().await {
                Ok(conn) => return Ok(conn),
                Err(e) if attempt < 3 => {
                    warn!(
                        attempt,
                        backoff_ms, "Redis connection failed, retrying: {}", e
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms *= 2;
                }
                Err(e) => return Err(e.into()),
            }
        }
        unreachable!()
    }

    /// Generate Redis key for credential
    fn credential_key(cred_id: &[u8]) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding};
        format!(
            "webauthn:cred:{}",
            Base64UrlUnpadded::encode_string(cred_id)
        )
    }

    /// Generate Redis key for user's credential list
    fn user_creds_key(user_id_hash: &str) -> String {
        format!("webauthn:user:{}", user_id_hash)
    }

    /// Save a credential to Redis
    ///
    /// This stores:
    /// 1. The credential itself at `webauthn:cred:{cred_id}`
    /// 2. A reference in the user's credential set at `webauthn:user:{user_id_hash}`
    pub async fn save(
        &self,
        cred_id: Vec<u8>,
        credential: Passkey,
        user_id_hash: String,
    ) -> Result<()> {
        let mut conn = self.get_connection().await?;

        let stored = StoredCredential {
            cred_id: cred_id.clone(),
            credential,
            user_id_hash: user_id_hash.clone(),
            registered_at: chrono::Utc::now().timestamp(),
            last_used_at: None,
        };

        let cred_json = serde_json::to_string(&stored).context("Failed to serialize credential")?;

        let cred_key = Self::credential_key(&cred_id);
        let user_key = Self::user_creds_key(&user_id_hash);

        // Store credential
        if let Some(ttl) = self.credential_ttl {
            conn.set_ex::<_, _, ()>(&cred_key, cred_json, ttl).await?;
        } else {
            conn.set::<_, _, ()>(&cred_key, cred_json).await?;
        }

        // Add to user's credential set
        conn.sadd::<_, _, ()>(&user_key, &cred_key).await?;

        // Optionally set TTL on user set as well
        if let Some(ttl) = self.credential_ttl {
            conn.expire::<_, ()>(&user_key, ttl as i64).await?;
        }

        info!(
            cred_key = %cred_key,
            user_key = %user_key,
            "Saved WebAuthn credential"
        );

        Ok(())
    }

    /// Load a credential by credential ID
    pub async fn load(&self, cred_id: &[u8]) -> Result<Option<StoredCredential>> {
        let mut conn = self.get_connection().await?;
        let cred_key = Self::credential_key(cred_id);

        let cred_json: Option<String> = conn.get(&cred_key).await?;

        match cred_json {
            Some(json) => {
                let stored: StoredCredential =
                    serde_json::from_str(&json).context("Failed to deserialize credential")?;
                debug!(cred_key = %cred_key, "Loaded WebAuthn credential");
                Ok(Some(stored))
            }
            None => {
                debug!(cred_key = %cred_key, "Credential not found");
                Ok(None)
            }
        }
    }

    /// Load all credentials for a user
    pub async fn load_user_credentials(&self, user_id_hash: &str) -> Result<Vec<StoredCredential>> {
        let mut conn = self.get_connection().await?;
        let user_key = Self::user_creds_key(user_id_hash);

        // Get all credential keys for this user
        let cred_keys: Vec<String> = conn.smembers(&user_key).await?;

        if cred_keys.is_empty() {
            debug!(user_key = %user_key, "No credentials found for user");
            return Ok(Vec::new());
        }

        // Load all credentials
        let mut credentials = Vec::new();
        for cred_key in cred_keys {
            let cred_json: Option<String> = conn.get(&cred_key).await?;
            if let Some(json) = cred_json {
                match serde_json::from_str::<StoredCredential>(&json) {
                    Ok(stored) => credentials.push(stored),
                    Err(e) => warn!(
                        cred_key = %cred_key,
                        error = %e,
                        "Failed to deserialize credential, skipping"
                    ),
                }
            }
        }

        debug!(
            user_key = %user_key,
            count = credentials.len(),
            "Loaded user credentials"
        );

        Ok(credentials)
    }

    /// Update last_used_at timestamp for a credential
    pub async fn update_last_used(&self, cred_id: &[u8]) -> Result<()> {
        let mut stored = match self.load(cred_id).await? {
            Some(s) => s,
            None => return Ok(()), // Credential doesn't exist, nothing to update
        };

        stored.last_used_at = Some(chrono::Utc::now().timestamp());

        let cred_json = serde_json::to_string(&stored)?;
        let cred_key = Self::credential_key(cred_id);

        let mut conn = self.get_connection().await?;
        if let Some(ttl) = self.credential_ttl {
            conn.set_ex::<_, _, ()>(&cred_key, cred_json, ttl).await?;
        } else {
            conn.set::<_, _, ()>(&cred_key, cred_json).await?;
        }

        debug!(cred_key = %cred_key, "Updated credential last_used_at");
        Ok(())
    }

    /// Delete a credential
    pub async fn delete(&self, cred_id: &[u8]) -> Result<bool> {
        let mut conn = self.get_connection().await?;
        let cred_key = Self::credential_key(cred_id);

        // Load credential to get user_id_hash before deleting
        if let Some(stored) = self.load(cred_id).await? {
            let user_key = Self::user_creds_key(&stored.user_id_hash);

            // Remove from user's set
            conn.srem::<_, _, ()>(&user_key, &cred_key).await?;

            // Delete credential
            let deleted: bool = conn.del(&cred_key).await?;

            info!(
                cred_key = %cred_key,
                user_key = %user_key,
                "Deleted WebAuthn credential"
            );

            Ok(deleted)
        } else {
            debug!(cred_key = %cred_key, "Credential not found for deletion");
            Ok(false)
        }
    }

    /// Count total credentials in system
    pub async fn count_credentials(&self) -> Result<usize> {
        let mut conn = self.get_connection().await?;
        let keys: Vec<String> = conn.keys("webauthn:cred:*").await?;
        Ok(keys.len())
    }

    /// List all credentials in the system
    pub async fn list_all_credentials(&self) -> Result<Vec<StoredCredential>> {
        let mut conn = self.get_connection().await?;
        let keys: Vec<String> = conn.keys("webauthn:cred:*").await?;

        let mut credentials = Vec::new();
        for key in keys {
            let cred_json: Option<String> = conn.get(&key).await?;
            if let Some(json) = cred_json {
                match serde_json::from_str::<StoredCredential>(&json) {
                    Ok(stored) => {
                        credentials.push(StoredCredential {
                            cred_id: stored.cred_id,
                            credential: stored.credential,
                            user_id_hash: stored.user_id_hash,
                            registered_at: stored.registered_at,
                            last_used_at: stored.last_used_at,
                        });
                    }
                    Err(e) => warn!(
                        key = %key,
                        error = %e,
                        "Failed to deserialize credential, skipping"
                    ),
                }
            }
        }

        debug!(count = credentials.len(), "Listed all credentials");
        Ok(credentials)
    }
}

/// In-memory credential store (for development/testing)
#[derive(Default, Clone)]
pub struct InMemoryCredStore {
    credentials: Arc<RwLock<std::collections::HashMap<Vec<u8>, StoredCredential>>>,
}

impl InMemoryCredStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn save(
        &self,
        cred_id: Vec<u8>,
        credential: Passkey,
        user_id_hash: String,
    ) -> Result<()> {
        let stored = StoredCredential {
            cred_id: cred_id.clone(),
            credential,
            user_id_hash,
            registered_at: chrono::Utc::now().timestamp(),
            last_used_at: None,
        };

        self.credentials.write().await.insert(cred_id, stored);
        Ok(())
    }

    pub async fn load(&self, cred_id: &[u8]) -> Result<Option<StoredCredential>> {
        Ok(self.credentials.read().await.get(cred_id).cloned())
    }

    pub async fn load_user_credentials(&self, user_id_hash: &str) -> Result<Vec<StoredCredential>> {
        let creds = self.credentials.read().await;
        Ok(creds
            .values()
            .filter(|c| c.user_id_hash == user_id_hash)
            .cloned()
            .collect())
    }

    pub async fn update_last_used(&self, cred_id: &[u8]) -> Result<()> {
        if let Some(stored) = self.credentials.write().await.get_mut(cred_id) {
            stored.last_used_at = Some(chrono::Utc::now().timestamp());
        }
        Ok(())
    }

    pub async fn delete(&self, cred_id: &[u8]) -> Result<bool> {
        Ok(self.credentials.write().await.remove(cred_id).is_some())
    }

    pub async fn count_credentials(&self) -> Result<usize> {
        Ok(self.credentials.read().await.len())
    }

    pub async fn list_all_credentials(&self) -> Result<Vec<StoredCredential>> {
        Ok(self.credentials.read().await.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_store() {
        let store = InMemoryCredStore::new();

        // Create a mock credential
        let cred_id = vec![1, 2, 3, 4];
        let user_id_hash = "user123".to_string();

        // Note: Creating a real Passkey requires complex setup, so this is just a structure test
        // In real tests, you'd use webauthn-rs test utilities
        assert_eq!(store.count_credentials().await.unwrap(), 0);
    }
}
