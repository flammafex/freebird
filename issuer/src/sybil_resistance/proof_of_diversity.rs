// issuer/src/sybil_resistance/proof_of_diversity.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Proof of Diversity Sybil Resistance
//!
//! Detect botnet behavior by analyzing network and device diversity.
//! Real users access from multiple networks (home, work, mobile, coffee shops).
//! Botnets typically originate from uniform datacenter IPs with identical fingerprints.
//!
//! # Privacy
//! - Network IDs are hashed (per-user salt)
//! - Device fingerprints are hashed (per-user salt)
//! - No raw IPs or User-Agents stored
//! - No cross-user correlation possible
//!
//! # Scoring
//! ```text
//! diversity_score = (unique_networks × 30) + (unique_devices × 20) + min(time_span_days, 50)
//!
//! Max score: ~100
//! - 3 networks = 90 points
//! - 3 devices = 60 points
//! - 50+ days = 50 points
//! ```
//!
//! # Anti-Botnet Logic
//! - Datacenter IPs (same ASN) = low network diversity
//! - Identical User-Agents = low device diversity
//! - Recent creation = low time span
//!
//! Botnets fail on all three dimensions.

use anyhow::{anyhow, Result};
use base64ct::Encoding;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use freebird_common::api::SybilProof;
use crate::sybil_resistance::SybilResistance;

// ============================================================================
// Configuration
// ============================================================================

#[derive(Debug, Clone)]
pub struct ProofOfDiversityConfig {
    /// Minimum diversity score required
    pub min_score: u8,
    /// Path to persistence file
    pub persistence_path: PathBuf,
    /// Auto-save interval (seconds)
    pub autosave_interval_secs: u64,
    /// Server secret for HMAC
    pub hmac_secret: Option<String>,
    /// Salt for fingerprint hashing
    pub fingerprint_salt: String,
}

impl Default for ProofOfDiversityConfig {
    fn default() -> Self {
        Self {
            min_score: 40,
            persistence_path: PathBuf::from("proof_of_diversity.json"),
            autosave_interval_secs: 300,
            hmac_secret: None,
            fingerprint_salt: String::from("default-salt-change-in-production"),
        }
    }
}

// ============================================================================
// Diversity Record
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiversityRecord {
    /// Hashed user ID
    pub user_id_hash: String,
    /// First observation timestamp
    pub first_seen: i64,
    /// Last observation timestamp
    pub last_seen: i64,
    /// Set of unique network hashes (ASN-based)
    pub unique_networks: HashSet<String>,
    /// Set of unique device hashes (User-Agent-based)
    pub unique_devices: HashSet<String>,
    /// Current diversity score
    #[serde(default)]
    pub score: u8,
}

impl DiversityRecord {
    pub fn new(user_id_hash: String, now: i64) -> Self {
        Self {
            user_id_hash,
            first_seen: now,
            last_seen: now,
            unique_networks: HashSet::new(),
            unique_devices: HashSet::new(),
            score: 0,
        }
    }

    /// Time span in days
    pub fn time_span_days(&self, now: i64) -> u32 {
        let secs = (now - self.first_seen).max(0) as u64;
        (secs / 86400) as u32
    }

    /// Calculate diversity score
    pub fn calculate_score(&self, now: i64) -> u8 {
        let network_score = (self.unique_networks.len() as u32 * 30).min(90);
        let device_score = (self.unique_devices.len() as u32 * 20).min(60);
        let time_score = self.time_span_days(now).min(50);

        (network_score + device_score + time_score).min(255) as u8
    }
}

// ============================================================================
// Proof of Diversity System
// ============================================================================

pub struct ProofOfDiversitySystem {
    config: ProofOfDiversityConfig,
    records: Arc<RwLock<HashMap<String, DiversityRecord>>>,
    hmac_key: [u8; 32],
    dirty: Arc<RwLock<bool>>,
}

impl ProofOfDiversitySystem {
    /// Create a new proof of diversity system
    pub async fn new(config: ProofOfDiversityConfig) -> Result<Arc<Self>> {
        // Derive HMAC key
        let hmac_key = Self::derive_hmac_key(&config);

        // Load existing state
        let records = Self::load_state(&config.persistence_path).await?;

        let system = Arc::new(Self {
            config,
            records: Arc::new(RwLock::new(records)),
            hmac_key,
            dirty: Arc::new(RwLock::new(false)),
        });

        // Start autosave task
        let autosave_system = system.clone();
        tokio::spawn(async move {
            autosave_system.autosave_loop().await;
        });

        info!(
            min_score = system.config.min_score,
            persistence = ?system.config.persistence_path,
            "Initialized Proof of Diversity system"
        );

        Ok(system)
    }

    /// Derive HMAC key
    fn derive_hmac_key(config: &ProofOfDiversityConfig) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&[0u8; 32]);
        hasher.update(b"proof_of_diversity:hmac:v1:");
        hasher.update(config.fingerprint_salt.as_bytes());

        if let Some(secret) = &config.hmac_secret {
            hasher.update(secret.as_bytes());
        } else {
            hasher.update(b":deterministic");
        }

        *hasher.finalize().as_bytes()
    }

    /// Hash a username to user ID
    fn hash_user_id(&self, username: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"proof_of_diversity:user:");
        hasher.update(self.config.fingerprint_salt.as_bytes());
        hasher.update(b":");
        hasher.update(username.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Hash a network identifier (ASN or IP)
    fn hash_network(&self, user_id_hash: &str, network_info: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"proof_of_diversity:network:");
        hasher.update(user_id_hash.as_bytes()); // Per-user salt
        hasher.update(b":");
        hasher.update(network_info.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Hash a device fingerprint
    fn hash_device(&self, user_id_hash: &str, device_info: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"proof_of_diversity:device:");
        hasher.update(user_id_hash.as_bytes()); // Per-user salt
        hasher.update(b":");
        hasher.update(device_info.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Compute HMAC proof for a record
    fn compute_hmac_proof(&self, record: &DiversityRecord) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&self.hmac_key);
        hasher.update(b"proof_of_diversity:proof:");
        hasher.update(record.user_id_hash.as_bytes());
        hasher.update(b":");
        hasher.update(&record.first_seen.to_le_bytes());
        hasher.update(b":");
        hasher.update(&(record.unique_networks.len() as u32).to_le_bytes());
        hasher.update(b":");
        hasher.update(&(record.unique_devices.len() as u32).to_le_bytes());
        hasher.update(b":");
        hasher.update(&record.score.to_le_bytes());
        base64ct::Base64UrlUnpadded::encode_string(hasher.finalize().as_bytes())
    }

    /// Observe a user access (update diversity)
    pub async fn observe_access(
        &self,
        username: &str,
        network_info: &str,
        device_info: &str,
    ) -> Result<DiversityRecord> {
        let user_id_hash = self.hash_user_id(username);
        let network_hash = self.hash_network(&user_id_hash, network_info);
        let device_hash = self.hash_device(&user_id_hash, device_info);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut records = self.records.write().await;
        let record = records
            .entry(user_id_hash.clone())
            .or_insert_with(|| {
                debug!(username, "Creating new diversity record");
                DiversityRecord::new(user_id_hash, now)
            });

        // Update observations
        let network_is_new = record.unique_networks.insert(network_hash);
        let device_is_new = record.unique_devices.insert(device_hash);
        record.last_seen = now;
        record.score = record.calculate_score(now);

        if network_is_new || device_is_new {
            *self.dirty.write().await = true;
            debug!(
                username,
                networks = record.unique_networks.len(),
                devices = record.unique_devices.len(),
                score = record.score,
                "Updated diversity record"
            );
        }

        Ok(record.clone())
    }

    /// Generate a proof for a user
    pub async fn generate_proof(&self, username: &str) -> Result<SybilProof> {
        let user_id_hash = self.hash_user_id(username);
        let records = self.records.read().await;

        let record = records.get(&user_id_hash).ok_or_else(|| {
            anyhow!("No diversity record found for user (needs initial observation)")
        })?;

        let hmac_proof = self.compute_hmac_proof(record);

        Ok(SybilProof::ProofOfDiversity {
            user_id_hash: record.user_id_hash.clone(),
            diversity_score: record.score,
            unique_networks: record.unique_networks.len() as u32,
            unique_devices: record.unique_devices.len() as u32,
            first_seen: record.first_seen,
            hmac_proof,
        })
    }

    /// Load state from disk
    async fn load_state(path: &PathBuf) -> Result<HashMap<String, DiversityRecord>> {
        if !path.exists() {
            info!(?path, "No existing diversity state found");
            return Ok(HashMap::new());
        }

        let data = tokio::fs::read_to_string(path)
            .await
            .context("Failed to read diversity state")?;

        let records: HashMap<String, DiversityRecord> =
            serde_json::from_str(&data).context("Failed to parse diversity state")?;

        info!(?path, records = records.len(), "Loaded diversity state");
        Ok(records)
    }

    /// Save state to disk
    async fn save_state(&self) -> Result<()> {
        let records = self.records.read().await;
        let data = serde_json::to_string_pretty(&*records)
            .context("Failed to serialize diversity state")?;

        tokio::fs::write(&self.config.persistence_path, data)
            .await
            .context("Failed to write diversity state")?;

        *self.dirty.write().await = false;

        debug!(
            path = ?self.config.persistence_path,
            records = records.len(),
            "Saved diversity state"
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
                    warn!(error = %e, "Failed to autosave diversity state");
                }
            }
        }
    }
}

// ============================================================================
// SybilResistance Implementation
// ============================================================================

impl SybilResistance for ProofOfDiversitySystem {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        match proof {
            SybilProof::ProofOfDiversity {
                user_id_hash,
                diversity_score,
                unique_networks,
                unique_devices,
                first_seen,
                hmac_proof,
            } => {
                let _now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                // Reconstruct record for HMAC verification
                let mut record = DiversityRecord::new(user_id_hash.clone(), *first_seen);
                // We can't reconstruct the actual sets, but we can verify the counts and score
                record.score = *diversity_score;

                // Verify HMAC
                // Note: We're verifying the score and counts, not the actual network/device sets
                let mut hasher = blake3::Hasher::new_keyed(&self.hmac_key);
                hasher.update(b"proof_of_diversity:proof:");
                hasher.update(user_id_hash.as_bytes());
                hasher.update(b":");
                hasher.update(&first_seen.to_le_bytes());
                hasher.update(b":");
                hasher.update(&unique_networks.to_le_bytes());
                hasher.update(b":");
                hasher.update(&unique_devices.to_le_bytes());
                hasher.update(b":");
                hasher.update(&diversity_score.to_le_bytes());
                let expected_hmac = base64ct::Base64UrlUnpadded::encode_string(hasher.finalize().as_bytes());

                // Constant-time comparison to prevent timing attacks
                if !bool::from(hmac_proof.as_bytes().ct_eq(expected_hmac.as_bytes())) {
                    debug!("Diversity proof verification failed: HMAC mismatch");
                    return Err(anyhow!("Invalid proof of diversity"));
                }

                // Check minimum score
                if diversity_score < &self.config.min_score {
                    return Err(anyhow!(
                        "Insufficient diversity score: {} < {} (networks: {}, devices: {})",
                        diversity_score,
                        self.config.min_score,
                        unique_networks,
                        unique_devices
                    ));
                }

                debug!(
                    user_id_hash = %user_id_hash,
                    score = diversity_score,
                    networks = unique_networks,
                    devices = unique_devices,
                    "Diversity verification successful"
                );

                Ok(())
            }
            _ => Err(anyhow!("Expected ProofOfDiversity proof")),
        }
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::ProofOfDiversity { .. })
    }

    fn cost(&self) -> u64 {
        0
    }
}

use anyhow::Context;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_diversity_scoring() {
        let config = ProofOfDiversityConfig::default();
        let system = ProofOfDiversitySystem::new(config).await.unwrap();

        // Single network, single device
        let record1 = system
            .observe_access("alice", "192.168.1.1", "Mozilla/5.0")
            .await
            .unwrap();
        assert_eq!(record1.unique_networks.len(), 1);
        assert_eq!(record1.unique_devices.len(), 1);
        assert_eq!(record1.score, 50); // 30 + 20 + 0 (time)

        // Different network, same device
        let record2 = system
            .observe_access("alice", "10.0.0.1", "Mozilla/5.0")
            .await
            .unwrap();
        assert_eq!(record2.unique_networks.len(), 2);
        assert_eq!(record2.unique_devices.len(), 1);
        assert_eq!(record2.score, 80); // 60 + 20 + 0

        // Same networks, different device
        let record3 = system
            .observe_access("alice", "192.168.1.1", "Chrome/100")
            .await
            .unwrap();
        assert_eq!(record3.unique_networks.len(), 2);
        assert_eq!(record3.unique_devices.len(), 2);
        assert_eq!(record3.score, 100); // 60 + 40 + 0
    }

    #[tokio::test]
    async fn test_hmac_verification() {
        let config = ProofOfDiversityConfig::default();
        let system = ProofOfDiversitySystem::new(config).await.unwrap();

        system
            .observe_access("bob", "192.168.1.1", "Safari/16")
            .await
            .unwrap();

        let proof = system.generate_proof("bob").await.unwrap();
        assert!(system.verify(&proof).is_ok());
    }

    #[tokio::test]
    async fn test_min_score_enforcement() {
        let mut config = ProofOfDiversityConfig::default();
        config.min_score = 80; // High requirement
        let system = ProofOfDiversitySystem::new(config).await.unwrap();

        // Single network/device = score 50, fails
        system
            .observe_access("charlie", "192.168.1.1", "Firefox/100")
            .await
            .unwrap();

        let proof = system.generate_proof("charlie").await.unwrap();
        assert!(system.verify(&proof).is_err());
    }
}
