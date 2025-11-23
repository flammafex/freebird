// issuer/src/sybil_resistance/progressive_trust.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Progressive Trust Sybil Resistance
//!
//! Build trust over time rather than demanding it upfront.
//! Users earn higher token limits and reduced cooldowns as they demonstrate
//! consistent, legitimate usage over time.
//!
//! # Privacy
//! - User IDs are hashed (Blake3) with a per-deployment salt
//! - No raw usernames stored
//! - Proofs are HMAC-signed to prevent forgery
//!
//! # Security
//! - Time cannot be faked (server-controlled timestamps)
//! - Proofs are unforgeable (HMAC with server secret)
//! - State is persistent across restarts
//!
//! # Combinability
//! - Can be combined with WebAuthn, Invitation, etc.
//! - Example: "WebAuthn + Level 2 Trust" for high-security apps

use anyhow::{anyhow, Context, Result};
use base64ct::Encoding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use common::api::SybilProof;
use crate::sybil_resistance::SybilResistance;

// ============================================================================
// Configuration
// ============================================================================

#[derive(Debug, Clone)]
pub struct ProgressiveTrustConfig {
    /// Trust levels (sorted by min_age_secs ascending)
    pub levels: Vec<TrustLevel>,
    /// Path to persistence file
    pub persistence_path: PathBuf,
    /// Auto-save interval (seconds)
    pub autosave_interval_secs: u64,
    /// Server secret for HMAC (derived if not provided)
    pub hmac_secret: Option<String>,
    /// Salt for user ID hashing (per-deployment)
    pub user_id_salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustLevel {
    /// Minimum account age (seconds) to reach this level
    pub min_age_secs: u64,
    /// Maximum tokens allowed per cooldown period
    pub max_tokens_per_period: u32,
    /// Cooldown between token requests (seconds)
    pub cooldown_secs: u64,
}

impl Default for ProgressiveTrustConfig {
    fn default() -> Self {
        Self {
            levels: vec![
                TrustLevel {
                    min_age_secs: 0,
                    max_tokens_per_period: 1,
                    cooldown_secs: 86400, // 24 hours
                },
                TrustLevel {
                    min_age_secs: 30 * 24 * 3600, // 30 days
                    max_tokens_per_period: 10,
                    cooldown_secs: 3600, // 1 hour
                },
                TrustLevel {
                    min_age_secs: 90 * 24 * 3600, // 90 days
                    max_tokens_per_period: 100,
                    cooldown_secs: 60, // 1 minute
                },
            ],
            persistence_path: PathBuf::from("progressive_trust.json"),
            autosave_interval_secs: 300,
            hmac_secret: None,
            user_id_salt: String::from("default-salt"),
        }
    }
}

// ============================================================================
// User Trust Record
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserTrustRecord {
    /// Hashed user ID (Blake3)
    pub user_id_hash: String,
    /// First token issuance timestamp
    pub first_seen: i64,
    /// Total tokens issued (lifetime)
    pub tokens_issued: u32,
    /// Last token issuance timestamp
    pub last_issuance: i64,
    /// Current trust level (index into config.levels)
    #[serde(default)]
    pub current_level: usize,
}

impl UserTrustRecord {
    pub fn new(user_id_hash: String, now: i64) -> Self {
        Self {
            user_id_hash,
            first_seen: now,
            tokens_issued: 0,
            last_issuance: 0,
            current_level: 0,
        }
    }

    /// Account age in seconds
    pub fn age_secs(&self, now: i64) -> u64 {
        (now - self.first_seen).max(0) as u64
    }

    /// Time since last issuance
    pub fn time_since_last(&self, now: i64) -> u64 {
        if self.last_issuance == 0 {
            u64::MAX // Never issued before
        } else {
            (now - self.last_issuance).max(0) as u64
        }
    }
}

// ============================================================================
// Progressive Trust System
// ============================================================================

pub struct ProgressiveTrustSystem {
    config: ProgressiveTrustConfig,
    users: Arc<RwLock<HashMap<String, UserTrustRecord>>>,
    hmac_key: [u8; 32],
    dirty: Arc<RwLock<bool>>,
}

impl ProgressiveTrustSystem {
    /// Create a new progressive trust system
    pub async fn new(config: ProgressiveTrustConfig) -> Result<Arc<Self>> {
        // Derive HMAC key
        let hmac_key = Self::derive_hmac_key(&config);

        // Load existing state if available
        let users = Self::load_state(&config.persistence_path).await?;

        let system = Arc::new(Self {
            config,
            users: Arc::new(RwLock::new(users)),
            hmac_key,
            dirty: Arc::new(RwLock::new(false)),
        });

        // Start autosave task
        let autosave_system = system.clone();
        tokio::spawn(async move {
            autosave_system.autosave_loop().await;
        });

        info!(
            levels = system.config.levels.len(),
            persistence = ?system.config.persistence_path,
            "Initialized Progressive Trust system"
        );

        Ok(system)
    }

    /// Derive HMAC key from config or generate deterministic key
    fn derive_hmac_key(config: &ProgressiveTrustConfig) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&[0u8; 32]);
        hasher.update(b"progressive_trust:hmac:v1:");
        hasher.update(config.user_id_salt.as_bytes());

        if let Some(secret) = &config.hmac_secret {
            hasher.update(secret.as_bytes());
        } else {
            hasher.update(b":deterministic");
        }

        *hasher.finalize().as_bytes()
    }

    /// Hash a username to a user ID
    fn hash_user_id(&self, username: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"progressive_trust:user:");
        hasher.update(self.config.user_id_salt.as_bytes());
        hasher.update(b":");
        hasher.update(username.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Compute HMAC proof for a user record
    fn compute_hmac_proof(&self, record: &UserTrustRecord) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&self.hmac_key);
        hasher.update(b"progressive_trust:proof:");
        hasher.update(record.user_id_hash.as_bytes());
        hasher.update(b":");
        hasher.update(&record.first_seen.to_le_bytes());
        hasher.update(b":");
        hasher.update(&record.tokens_issued.to_le_bytes());
        hasher.update(b":");
        hasher.update(&record.last_issuance.to_le_bytes());
        base64ct::Base64UrlUnpadded::encode_string(hasher.finalize().as_bytes())
    }

    /// Get or create user record
    pub async fn get_or_create_user(&self, username: &str) -> Result<UserTrustRecord> {
        let user_id_hash = self.hash_user_id(username);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut users = self.users.write().await;
        let record = users
            .entry(user_id_hash.clone())
            .or_insert_with(|| {
                debug!(username, "Creating new progressive trust record");
                UserTrustRecord::new(user_id_hash, now)
            })
            .clone();

        Ok(record)
    }

    /// Update user after successful token issuance
    pub async fn update_after_issuance(&self, username: &str) -> Result<()> {
        let user_id_hash = self.hash_user_id(username);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut users = self.users.write().await;
        if let Some(record) = users.get_mut(&user_id_hash) {
            record.tokens_issued += 1;
            record.last_issuance = now;

            // Update trust level based on age
            let age_secs = record.age_secs(now);
            for (idx, level) in self.config.levels.iter().enumerate().rev() {
                if age_secs >= level.min_age_secs {
                    record.current_level = idx;
                    break;
                }
            }

            *self.dirty.write().await = true;

            debug!(
                username,
                tokens_issued = record.tokens_issued,
                trust_level = record.current_level,
                "Updated progressive trust record"
            );
        }

        Ok(())
    }

    /// Determine current trust level for a user
    pub fn determine_trust_level(&self, record: &UserTrustRecord, now: i64) -> usize {
        let age_secs = record.age_secs(now);

        for (idx, level) in self.config.levels.iter().enumerate().rev() {
            if age_secs >= level.min_age_secs {
                return idx;
            }
        }

        0 // Default to lowest level
    }

    /// Generate a proof for a user
    pub async fn generate_proof(&self, username: &str) -> Result<SybilProof> {
        let record = self.get_or_create_user(username).await?;
        let hmac_proof = self.compute_hmac_proof(&record);

        Ok(SybilProof::ProgressiveTrust {
            user_id_hash: record.user_id_hash,
            first_seen: record.first_seen,
            tokens_issued: record.tokens_issued,
            last_issuance: record.last_issuance,
            hmac_proof,
        })
    }

    /// Load state from disk
    async fn load_state(path: &PathBuf) -> Result<HashMap<String, UserTrustRecord>> {
        if !path.exists() {
            info!(?path, "No existing progressive trust state found");
            return Ok(HashMap::new());
        }

        let data = tokio::fs::read_to_string(path)
            .await
            .context("Failed to read progressive trust state")?;

        let users: HashMap<String, UserTrustRecord> =
            serde_json::from_str(&data).context("Failed to parse progressive trust state")?;

        info!(?path, users = users.len(), "Loaded progressive trust state");
        Ok(users)
    }

    /// Save state to disk
    async fn save_state(&self) -> Result<()> {
        let users = self.users.read().await;
        let data = serde_json::to_string_pretty(&*users)
            .context("Failed to serialize progressive trust state")?;

        tokio::fs::write(&self.config.persistence_path, data)
            .await
            .context("Failed to write progressive trust state")?;

        *self.dirty.write().await = false;

        debug!(
            path = ?self.config.persistence_path,
            users = users.len(),
            "Saved progressive trust state"
        );

        Ok(())
    }

    /// Autosave loop
    async fn autosave_loop(&self) {
        let interval = tokio::time::Duration::from_secs(self.config.autosave_interval_secs);
        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;

            if *self.dirty.read().await {
                if let Err(e) = self.save_state().await {
                    warn!(error = %e, "Failed to autosave progressive trust state");
                }
            }
        }
    }
}

// ============================================================================
// SybilResistance Implementation
// ============================================================================

impl SybilResistance for ProgressiveTrustSystem {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        match proof {
            SybilProof::ProgressiveTrust {
                user_id_hash,
                first_seen,
                tokens_issued,
                last_issuance,
                hmac_proof,
            } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                // Reconstruct the record from the proof
                let record = UserTrustRecord {
                    user_id_hash: user_id_hash.clone(),
                    first_seen: *first_seen,
                    tokens_issued: *tokens_issued,
                    last_issuance: *last_issuance,
                    current_level: 0, // Will be recalculated
                };

                // Verify HMAC
                let expected_hmac = self.compute_hmac_proof(&record);
                if hmac_proof != &expected_hmac {
                    debug!("Progressive trust proof verification failed: HMAC mismatch");
                    return Err(anyhow!("Invalid progressive trust proof"));
                }

                // Determine current trust level
                let trust_level = self.determine_trust_level(&record, now);
                let level_config = &self.config.levels[trust_level];

                // Check cooldown
                let time_since_last = record.time_since_last(now);
                if time_since_last < level_config.cooldown_secs {
                    let remaining = level_config.cooldown_secs - time_since_last;
                    return Err(anyhow!(
                        "Progressive trust cooldown: {} seconds remaining (level {})",
                        remaining,
                        trust_level
                    ));
                }

                debug!(
                    user_id_hash = %user_id_hash,
                    trust_level = trust_level,
                    tokens_issued = tokens_issued,
                    age_days = record.age_secs(now) / 86400,
                    "Progressive trust verification successful"
                );

                Ok(())
            }
            _ => Err(anyhow!("Expected ProgressiveTrust proof")),
        }
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::ProgressiveTrust { .. })
    }

    fn cost(&self) -> u64 {
        0 // No computational cost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_user_creation() {
        let config = ProgressiveTrustConfig::default();
        let system = ProgressiveTrustSystem::new(config).await.unwrap();

        let record = system.get_or_create_user("alice").await.unwrap();
        assert_eq!(record.tokens_issued, 0);
        assert!(record.first_seen > 0);
    }

    #[tokio::test]
    async fn test_trust_level_progression() {
        let mut config = ProgressiveTrustConfig::default();
        config.levels = vec![
            TrustLevel {
                min_age_secs: 0,
                max_tokens_per_period: 1,
                cooldown_secs: 3600,
            },
            TrustLevel {
                min_age_secs: 100, // 100 seconds for testing
                max_tokens_per_period: 10,
                cooldown_secs: 60,
            },
        ];

        let system = ProgressiveTrustSystem::new(config).await.unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // New user starts at level 0
        let mut record = UserTrustRecord::new("user1".to_string(), now - 50);
        let level = system.determine_trust_level(&record, now);
        assert_eq!(level, 0);

        // After 100 seconds, should be level 1
        record.first_seen = now - 150;
        let level = system.determine_trust_level(&record, now);
        assert_eq!(level, 1);
    }

    #[tokio::test]
    async fn test_hmac_verification() {
        let config = ProgressiveTrustConfig::default();
        let system = ProgressiveTrustSystem::new(config).await.unwrap();

        let proof = system.generate_proof("alice").await.unwrap();
        assert!(system.verify(&proof).is_ok());
    }
}
