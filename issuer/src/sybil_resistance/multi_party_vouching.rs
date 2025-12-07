// issuer/src/sybil_resistance/multi_party_vouching.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Multi-Party Vouching Sybil Resistance
//!
//! Requires multiple existing users to vouch for a new user, providing
//! social consensus-based Sybil resistance through collective accountability.

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{SybilProof, VouchProof};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::fs;
use tokio::sync::RwLock;

use super::SybilResistance;

/// Configuration for Multi-Party Vouching system
#[derive(Debug, Clone)]
pub struct MultiPartyVouchingConfig {
    /// Number of vouchers required for a new user
    pub required_vouchers: u32,
    /// Cooldown between vouches from the same voucher
    pub voucher_cooldown_secs: u64,
    /// How long a vouch remains valid
    pub vouch_expires_secs: u64,
    /// Waiting period before new users can vouch for others
    pub new_user_can_vouch_after_secs: u64,
    /// Path to persistence file
    pub persistence_path: PathBuf,
    /// Autosave interval in seconds
    pub autosave_interval_secs: u64,
    /// HMAC secret for proof verification (optional)
    pub hmac_secret: Option<String>,
    /// Salt for hashing user IDs
    pub user_id_salt: String,
}

/// Record of a voucher's activity and reputation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherRecord {
    /// Hashed user ID
    pub voucher_id: String,
    /// Set of users this voucher has vouched for
    pub vouched_for: HashSet<String>,
    /// Timestamp of last vouch
    pub last_vouch_time: i64,
    /// Number of successful vouches (vouched users are still in good standing)
    pub successful_vouches: u32,
    /// Number of problematic vouches (vouched users were banned/flagged)
    pub problematic_vouches: u32,
    /// When this voucher first appeared
    pub first_seen: i64,
    /// Public key for signature verification
    pub public_key_b64: String,
}

/// Multi-Party Vouching System
pub struct MultiPartyVouchingSystem {
    config: MultiPartyVouchingConfig,
    vouchers: Arc<RwLock<HashMap<String, VoucherRecord>>>,
    pending_vouches: Arc<RwLock<HashMap<String, Vec<VouchProof>>>>,
    hmac_key: [u8; 32],
    dirty: Arc<RwLock<bool>>,
}

impl MultiPartyVouchingSystem {
    /// Create a new Multi-Party Vouching system
    pub async fn new(config: MultiPartyVouchingConfig) -> Result<Arc<Self>> {
        // Derive HMAC key for proof verification
        let hmac_key = Self::derive_hmac_key(&config);

        let system = Arc::new(Self {
            config: config.clone(),
            vouchers: Arc::new(RwLock::new(HashMap::new())),
            pending_vouches: Arc::new(RwLock::new(HashMap::new())),
            hmac_key,
            dirty: Arc::new(RwLock::new(false)),
        });

        // Load existing state if available
        if config.persistence_path.exists() {
            system.load_state().await?;
        }

        // Start autosave task
        let save_system = Arc::clone(&system);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(
                    save_system.config.autosave_interval_secs,
                ))
                .await;

                let is_dirty = *save_system.dirty.read().await;
                if is_dirty {
                    if let Err(e) = save_system.save_state().await {
                        tracing::warn!("Multi-Party Vouching autosave failed: {}", e);
                    } else {
                        *save_system.dirty.write().await = false;
                    }
                }
            }
        });

        Ok(system)
    }

    /// Derive HMAC key from configuration
    fn derive_hmac_key(config: &MultiPartyVouchingConfig) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&[0u8; 32]);
        hasher.update(b"multi_party_vouching:hmac_key:v1:");
        if let Some(secret) = &config.hmac_secret {
            hasher.update(secret.as_bytes());
        } else {
            hasher.update(b":deterministic");
        }
        *hasher.finalize().as_bytes()
    }

    /// Hash a user ID with salt
    fn hash_user_id(&self, user_id: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"multi_party_vouching:user:");
        hasher.update(self.config.user_id_salt.as_bytes());
        hasher.update(b":");
        hasher.update(user_id.as_bytes());
        base64ct::Base64UrlUnpadded::encode_string(hasher.finalize().as_bytes())
    }

    /// Add a new voucher (bootstrap or newly vouched user)
    pub async fn add_voucher(
        &self,
        user_id: String,
        public_key: VerifyingKey,
    ) -> Result<()> {
        let user_id_hash = self.hash_user_id(&user_id);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let public_key_b64 = base64ct::Base64UrlUnpadded::encode_string(
            &public_key.to_encoded_point(false).as_bytes(),
        );

        let record = VoucherRecord {
            voucher_id: user_id_hash.clone(),
            vouched_for: HashSet::new(),
            last_vouch_time: 0,
            successful_vouches: 0,
            problematic_vouches: 0,
            first_seen: now,
            public_key_b64,
        };

        self.vouchers.write().await.insert(user_id_hash, record);
        *self.dirty.write().await = true;
        Ok(())
    }

    /// Submit a vouch for a new user
    pub async fn submit_vouch(
        &self,
        voucher_id: &str,
        vouchee_id: &str,
        signature: Signature,
        timestamp: i64,
    ) -> Result<VouchProof> {
        let voucher_id_hash = self.hash_user_id(voucher_id);
        let vouchee_id_hash = self.hash_user_id(vouchee_id);
        let now = timestamp;

        // Check if voucher exists
        let mut vouchers = self.vouchers.write().await;
        let voucher = vouchers
            .get_mut(&voucher_id_hash)
            .ok_or_else(|| anyhow!("Voucher not found"))?;

        // Check if voucher is eligible to vouch
        let age = now - voucher.first_seen;
        if age < self.config.new_user_can_vouch_after_secs as i64 {
            return Err(anyhow!("Voucher must wait before vouching for others"));
        }

        // Check cooldown
        let time_since_last_vouch = now - voucher.last_vouch_time;
        if time_since_last_vouch < self.config.voucher_cooldown_secs as i64 {
            return Err(anyhow!("Voucher cooldown not expired"));
        }

        // Check if already vouched for this user
        if voucher.vouched_for.contains(&vouchee_id_hash) {
            return Err(anyhow!("Already vouched for this user"));
        }

        // Verify signature
        let public_key_bytes = base64ct::Base64UrlUnpadded::decode_vec(&voucher.public_key_b64)
            .map_err(|_| anyhow!("Invalid public key encoding"))?;
        let public_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
            .map_err(|_| anyhow!("Invalid public key"))?;

        let message = format!("vouch:{}:{}", vouchee_id_hash, now);
        public_key
            .verify(message.as_bytes(), &signature)
            .map_err(|_| anyhow!("Invalid signature"))?;

        // Update voucher record
        voucher.vouched_for.insert(vouchee_id_hash.clone());
        voucher.last_vouch_time = now;

        // Create vouch proof (including public key for verification)
        let proof = VouchProof {
            voucher_id: voucher_id_hash.clone(),
            vouchee_id: vouchee_id_hash.clone(),
            timestamp: now,
            signature: base64ct::Base64UrlUnpadded::encode_string(&signature.to_bytes()),
            voucher_pubkey_b64: voucher.public_key_b64.clone(),
        };

        // Add to pending vouches
        drop(vouchers);
        let mut pending = self.pending_vouches.write().await;
        pending
            .entry(vouchee_id_hash)
            .or_insert_with(Vec::new)
            .push(proof.clone());

        *self.dirty.write().await = true;
        Ok(proof)
    }

    /// Check if a user has enough vouches
    pub async fn check_vouches(&self, vouchee_id: &str) -> Result<Vec<VouchProof>> {
        let vouchee_id_hash = self.hash_user_id(vouchee_id);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let pending = self.pending_vouches.read().await;
        let vouches = pending
            .get(&vouchee_id_hash)
            .ok_or_else(|| anyhow!("No vouches found"))?;

        // Filter expired vouches
        let valid_vouches: Vec<VouchProof> = vouches
            .iter()
            .filter(|v| {
                let age = now - v.timestamp;
                age < self.config.vouch_expires_secs as i64
            })
            .cloned()
            .collect();

        if valid_vouches.len() < self.config.required_vouchers as usize {
            return Err(anyhow!(
                "Insufficient vouches: {} of {} required",
                valid_vouches.len(),
                self.config.required_vouchers
            ));
        }

        Ok(valid_vouches)
    }

    /// Generate proof for token issuance
    pub async fn generate_proof(
        &self,
        vouchee_id: &str,
    ) -> Result<(String, Vec<VouchProof>, String)> {
        let vouchee_id_hash = self.hash_user_id(vouchee_id);
        let vouches = self.check_vouches(vouchee_id).await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Compute HMAC proof
        let hmac_proof = self.compute_hmac_proof(&vouchee_id_hash, &vouches, now);

        Ok((vouchee_id_hash, vouches, hmac_proof))
    }

    /// Compute HMAC proof
    fn compute_hmac_proof(
        &self,
        vouchee_id_hash: &str,
        vouches: &[VouchProof],
        timestamp: i64,
    ) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&self.hmac_key);
        hasher.update(b"multi_party_vouching:proof:");
        hasher.update(vouchee_id_hash.as_bytes());
        hasher.update(b":");
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(b":");
        for vouch in vouches {
            hasher.update(vouch.voucher_id.as_bytes());
            hasher.update(b":");
        }
        base64ct::Base64UrlUnpadded::encode_string(hasher.finalize().as_bytes())
    }

    /// Mark a vouched user as problematic (for reputation tracking)
    pub async fn mark_problematic(&self, vouchee_id: &str) -> Result<()> {
        let vouchee_id_hash = self.hash_user_id(vouchee_id);
        let pending = self.pending_vouches.read().await;
        let vouches = pending
            .get(&vouchee_id_hash)
            .ok_or_else(|| anyhow!("No vouches found"))?;

        let mut vouchers = self.vouchers.write().await;
        for vouch in vouches {
            if let Some(voucher) = vouchers.get_mut(&vouch.voucher_id) {
                voucher.problematic_vouches += 1;
            }
        }

        *self.dirty.write().await = true;
        Ok(())
    }

    /// Mark a vouched user as successful (for reputation tracking)
    pub async fn mark_successful(&self, vouchee_id: &str) -> Result<()> {
        let vouchee_id_hash = self.hash_user_id(vouchee_id);
        let pending = self.pending_vouches.read().await;
        let vouches = pending
            .get(&vouchee_id_hash)
            .ok_or_else(|| anyhow!("No vouches found"))?;

        let mut vouchers = self.vouchers.write().await;
        for vouch in vouches {
            if let Some(voucher) = vouchers.get_mut(&vouch.voucher_id) {
                voucher.successful_vouches += 1;
            }
        }

        *self.dirty.write().await = true;
        Ok(())
    }

    /// Save state to disk
    async fn save_state(&self) -> Result<()> {
        let vouchers = self.vouchers.read().await.clone();
        let pending = self.pending_vouches.read().await.clone();

        let state = MultiPartyVouchingState { vouchers, pending };

        let json = serde_json::to_string_pretty(&state)?;
        fs::write(&self.config.persistence_path, json).await?;
        Ok(())
    }

    /// Load state from disk
    async fn load_state(&self) -> Result<()> {
        let json = fs::read_to_string(&self.config.persistence_path).await?;
        let state: MultiPartyVouchingState = serde_json::from_str(&json)?;

        *self.vouchers.write().await = state.vouchers;
        *self.pending_vouches.write().await = state.pending;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MultiPartyVouchingState {
    vouchers: HashMap<String, VoucherRecord>,
    pending: HashMap<String, Vec<VouchProof>>,
}

impl SybilResistance for MultiPartyVouchingSystem {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        match proof {
            SybilProof::MultiPartyVouching {
                vouchee_id_hash,
                vouches,
                hmac_proof,
                timestamp,
            } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                // Check proof age
                let age = now - timestamp;
                if age > 300 {
                    // 5 minute proof validity
                    return Err(anyhow!("Proof too old"));
                }

                // Verify we have enough vouches
                if vouches.len() < self.config.required_vouchers as usize {
                    return Err(anyhow!("Insufficient vouches"));
                }

                // Verify each vouch signature using the embedded public key
                for vouch in vouches {
                    // Decode and parse the signature
                    let signature_bytes = Base64UrlUnpadded::decode_vec(&vouch.signature)
                        .map_err(|_| anyhow!("Invalid signature encoding"))?;
                    let signature_array: [u8; 64] = signature_bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow!("Invalid signature length"))?;
                    let signature = Signature::from_bytes((&signature_array).into())
                        .map_err(|_| anyhow!("Invalid signature format"))?;

                    // Decode and parse the voucher's public key
                    let pubkey_bytes = Base64UrlUnpadded::decode_vec(&vouch.voucher_pubkey_b64)
                        .map_err(|_| anyhow!("Invalid voucher public key encoding"))?;
                    let public_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes)
                        .map_err(|_| anyhow!("Invalid voucher public key format"))?;

                    // Reconstruct the signed message and VERIFY THE SIGNATURE
                    let message = format!("vouch:{}:{}", vouch.vouchee_id, vouch.timestamp);
                    public_key
                        .verify(message.as_bytes(), &signature)
                        .map_err(|_| anyhow!("Vouch signature verification failed for voucher {}", vouch.voucher_id))?;

                    // Check vouch expiration
                    let vouch_age = now - vouch.timestamp;
                    if vouch_age > self.config.vouch_expires_secs as i64 {
                        return Err(anyhow!("Vouch expired"));
                    }

                    // Verify vouchee_id matches
                    if vouch.vouchee_id != *vouchee_id_hash {
                        return Err(anyhow!("Vouch vouchee_id mismatch"));
                    }
                }

                // Verify HMAC proof (constant-time comparison to prevent timing attacks)
                let expected_hmac = self.compute_hmac_proof(vouchee_id_hash, vouches, *timestamp);
                if !bool::from(hmac_proof.as_bytes().ct_eq(expected_hmac.as_bytes())) {
                    return Err(anyhow!("Invalid HMAC proof"));
                }

                Ok(())
            }
            _ => Err(anyhow!("Expected MultiPartyVouching proof")),
        }
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::MultiPartyVouching { .. })
    }

    fn cost(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn test_multi_party_vouching_basic() {
        let config = MultiPartyVouchingConfig {
            required_vouchers: 2,
            voucher_cooldown_secs: 10,
            vouch_expires_secs: 86400,
            new_user_can_vouch_after_secs: 0,
            persistence_path: PathBuf::from("/tmp/test_mpv.json"),
            autosave_interval_secs: 3600,
            hmac_secret: Some("test-secret".to_string()),
            user_id_salt: "test-salt".to_string(),
        };

        let system = MultiPartyVouchingSystem::new(config).await.unwrap();

        // Create vouchers
        let voucher1_sk = SigningKey::random(&mut OsRng);
        let voucher1_pk = VerifyingKey::from(&voucher1_sk);
        let voucher2_sk = SigningKey::random(&mut OsRng);
        let voucher2_pk = VerifyingKey::from(&voucher2_sk);

        system
            .add_voucher("alice".to_string(), voucher1_pk)
            .await
            .unwrap();
        system
            .add_voucher("bob".to_string(), voucher2_pk)
            .await
            .unwrap();

        // Create vouches for new user "charlie"
        let timestamp1 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let message1 = format!(
            "vouch:{}:{}",
            system.hash_user_id("charlie"),
            timestamp1
        );
        let sig1: Signature = voucher1_sk.sign(message1.as_bytes());

        tokio::time::sleep(Duration::from_secs(1)).await;

        let timestamp2 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let message2 = format!(
            "vouch:{}:{}",
            system.hash_user_id("charlie"),
            timestamp2
        );
        let sig2: Signature = voucher2_sk.sign(message2.as_bytes());

        // Submit vouches
        system
            .submit_vouch("alice", "charlie", sig1, timestamp1)
            .await
            .unwrap();
        system.submit_vouch("bob", "charlie", sig2, timestamp2).await.unwrap();

        // Check vouches
        let vouches = system.check_vouches("charlie").await.unwrap();
        assert_eq!(vouches.len(), 2);

        // Generate proof
        let (_id, _vouches, _hmac) = system.generate_proof("charlie").await.unwrap();

        // Cleanup
        let _ = std::fs::remove_file("/tmp/test_mpv.json");
    }
}
