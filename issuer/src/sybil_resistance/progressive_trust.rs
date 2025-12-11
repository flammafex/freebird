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
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use freebird_common::api::SybilProof;
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
    /// Server secret for HMAC (loaded from file or provided directly)
    /// If not provided, a random secret will be generated and persisted
    pub hmac_secret: Option<String>,
    /// Path to persist the generated HMAC secret (if hmac_secret is not provided)
    /// Defaults to "progressive_trust_secret.bin"
    pub hmac_secret_path: PathBuf,
    /// Salt for user ID hashing (per-deployment)
    pub user_id_salt: String,
    /// Allow deterministic key derivation without a secret (INSECURE - for testing only)
    /// When false (default), the system will generate and persist a random secret
    pub allow_insecure_deterministic: bool,
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
            hmac_secret_path: PathBuf::from("progressive_trust_secret.bin"),
            user_id_salt: String::from("default-salt"),
            allow_insecure_deterministic: false,
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
        // Load or generate HMAC secret (ensures unique key per deployment)
        let secret = Self::load_or_generate_secret(&config)?;

        // Derive HMAC key from secret
        let hmac_key = Self::derive_hmac_key(&secret, &config);

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

    /// Load or generate the HMAC secret
    ///
    /// Security: This function ensures each deployment has a unique HMAC secret.
    /// The secret is either:
    /// 1. Provided directly in config (hmac_secret)
    /// 2. Loaded from a persisted file (hmac_secret_path)
    /// 3. Generated randomly and persisted for future use
    ///
    /// If allow_insecure_deterministic is true and no secret can be loaded/generated,
    /// falls back to deterministic derivation (INSECURE - for testing only).
    fn load_or_generate_secret(config: &ProgressiveTrustConfig) -> Result<[u8; 32]> {
        // Priority 1: Use provided secret directly
        if let Some(secret) = &config.hmac_secret {
            info!("Using provided HMAC secret for progressive trust");
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"progressive_trust:secret:v1:");
            hasher.update(secret.as_bytes());
            return Ok(*hasher.finalize().as_bytes());
        }

        // Priority 2: Try to load from persisted file
        if config.hmac_secret_path.exists() {
            match fs::read(&config.hmac_secret_path) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(&bytes);
                    info!(
                        path = ?config.hmac_secret_path,
                        "Loaded HMAC secret from file"
                    );
                    return Ok(secret);
                }
                Ok(bytes) => {
                    error!(
                        path = ?config.hmac_secret_path,
                        len = bytes.len(),
                        "Invalid HMAC secret file (expected 32 bytes)"
                    );
                    // Fall through to generate new secret
                }
                Err(e) => {
                    warn!(
                        path = ?config.hmac_secret_path,
                        error = %e,
                        "Failed to read HMAC secret file"
                    );
                    // Fall through to generate new secret
                }
            }
        }

        // Priority 3: Generate new random secret and persist it
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);

        match Self::atomic_write_secure(&config.hmac_secret_path, &secret) {
            Ok(()) => {
                info!(
                    path = ?config.hmac_secret_path,
                    "Generated and persisted new HMAC secret"
                );
                return Ok(secret);
            }
            Err(e) => {
                error!(
                    path = ?config.hmac_secret_path,
                    error = %e,
                    "Failed to persist HMAC secret"
                );

                // Check if insecure fallback is allowed
                if config.allow_insecure_deterministic {
                    warn!(
                        "SECURITY WARNING: Using deterministic HMAC key derivation. \
                         This is INSECURE and should only be used for testing. \
                         All deployments with the same user_id_salt will share the same HMAC key, \
                         enabling cross-deployment proof forgery."
                    );
                    // Return the generated secret even if not persisted
                    return Ok(secret);
                } else {
                    return Err(anyhow!(
                        "Failed to persist HMAC secret and insecure deterministic mode is disabled. \
                         Either provide hmac_secret in config, ensure hmac_secret_path is writable, \
                         or set allow_insecure_deterministic=true for testing."
                    ));
                }
            }
        }
    }

    /// Atomic write with restrictive permissions (mode 0600 on Unix)
    fn atomic_write_secure(path: &Path, data: &[u8]) -> Result<()> {
        let tmp = path.with_extension("tmp");

        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .context("Failed to create temp file for secret")?;
            f.write_all(data).context("Failed to write secret to temp file")?;
            f.sync_all().context("Failed to sync secret file")?;
        }

        #[cfg(not(unix))]
        {
            let mut f = fs::File::create(&tmp).context("Failed to create temp file for secret")?;
            f.write_all(data).context("Failed to write secret to temp file")?;
            f.sync_all().context("Failed to sync secret file")?;
        }

        fs::rename(&tmp, path).context("Failed to rename temp file to final path")?;
        Ok(())
    }

    /// Derive HMAC key from the loaded/generated secret
    ///
    /// Security: The HMAC key is derived using BLAKE3 with proper domain separation.
    /// The secret MUST be unique per deployment to prevent cross-deployment proof forgery.
    fn derive_hmac_key(secret: &[u8; 32], config: &ProgressiveTrustConfig) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(secret);
        hasher.update(b"progressive_trust:hmac:v1:");
        hasher.update(config.user_id_salt.as_bytes());
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

                // Verify HMAC (constant-time comparison to prevent timing attacks)
                let expected_hmac = self.compute_hmac_proof(&record);
                if !bool::from(hmac_proof.as_bytes().ct_eq(expected_hmac.as_bytes())) {
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
    use std::sync::atomic::{AtomicU64, Ordering};

    // Atomic counter to ensure unique test paths
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Create a test config with unique paths to avoid test interference
    fn test_config() -> ProgressiveTrustConfig {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        ProgressiveTrustConfig {
            persistence_path: PathBuf::from(format!("/tmp/progressive_trust_test_{}.json", id)),
            hmac_secret_path: PathBuf::from(format!("/tmp/progressive_trust_secret_test_{}.bin", id)),
            ..Default::default()
        }
    }

    /// Cleanup test files
    fn cleanup_test_files(config: &ProgressiveTrustConfig) {
        let _ = std::fs::remove_file(&config.persistence_path);
        let _ = std::fs::remove_file(&config.hmac_secret_path);
    }

    #[tokio::test]
    async fn test_user_creation() {
        let config = test_config();
        let system = ProgressiveTrustSystem::new(config.clone()).await.unwrap();

        let record = system.get_or_create_user("alice").await.unwrap();
        assert_eq!(record.tokens_issued, 0);
        assert!(record.first_seen > 0);

        cleanup_test_files(&config);
    }

    #[tokio::test]
    async fn test_trust_level_progression() {
        let mut config = test_config();
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

        let system = ProgressiveTrustSystem::new(config.clone()).await.unwrap();
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

        cleanup_test_files(&config);
    }

    #[tokio::test]
    async fn test_hmac_verification() {
        let config = test_config();
        let system = ProgressiveTrustSystem::new(config.clone()).await.unwrap();

        let proof = system.generate_proof("alice").await.unwrap();
        assert!(system.verify(&proof).is_ok());

        cleanup_test_files(&config);
    }

    #[tokio::test]
    async fn test_secret_persistence() {
        let config = test_config();

        // Create system - should generate and persist secret
        let system1 = ProgressiveTrustSystem::new(config.clone()).await.unwrap();
        let proof1 = system1.generate_proof("bob").await.unwrap();

        // Verify secret file was created
        assert!(config.hmac_secret_path.exists(), "Secret file should be created");

        // Create second system with same config - should load same secret
        let system2 = ProgressiveTrustSystem::new(config.clone()).await.unwrap();

        // Proofs should be verifiable by both systems (same HMAC key)
        assert!(system2.verify(&proof1).is_ok(), "Proof from system1 should verify on system2");

        cleanup_test_files(&config);
    }

    #[tokio::test]
    async fn test_different_secrets_produce_different_proofs() {
        let config1 = test_config();
        let config2 = test_config();

        let system1 = ProgressiveTrustSystem::new(config1.clone()).await.unwrap();
        let system2 = ProgressiveTrustSystem::new(config2.clone()).await.unwrap();

        // Create user records with identical data
        let proof1 = system1.generate_proof("testuser").await.unwrap();

        // Proof from system1 should NOT verify on system2 (different secrets)
        assert!(system2.verify(&proof1).is_err(), "Proof should not verify with different secret");

        cleanup_test_files(&config1);
        cleanup_test_files(&config2);
    }

    #[tokio::test]
    async fn test_provided_secret_used() {
        let mut config = test_config();
        config.hmac_secret = Some("my-custom-secret".to_string());

        let system = ProgressiveTrustSystem::new(config.clone()).await.unwrap();
        let proof = system.generate_proof("alice").await.unwrap();
        assert!(system.verify(&proof).is_ok());

        // Secret file should NOT be created when secret is provided directly
        assert!(!config.hmac_secret_path.exists(), "Secret file should not be created when secret is provided");

        cleanup_test_files(&config);
    }
}
