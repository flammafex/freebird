// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Persistent storage for federation data (vouches and revocations)
//!
//! This module provides simple file-based storage for managing vouches
//! and revocations. Data is stored as JSON files for easy inspection
//! and manual editing if needed.

use anyhow::{Context, Result};
use freebird_common::federation::{Revocation, Vouch};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Federation storage manager
#[derive(Clone)]
pub struct FederationStore {
    /// Path to the data directory
    data_dir: PathBuf,

    /// In-memory cache of vouches
    vouches: std::sync::Arc<RwLock<Vec<Vouch>>>,

    /// In-memory cache of revocations
    revocations: std::sync::Arc<RwLock<Vec<Revocation>>>,
}

/// Container for serializing vouches to disk
#[derive(Debug, Serialize, Deserialize)]
struct VouchesFile {
    vouches: Vec<Vouch>,
}

/// Container for serializing revocations to disk
#[derive(Debug, Serialize, Deserialize)]
struct RevocationsFile {
    revocations: Vec<Revocation>,
}

impl FederationStore {
    /// Create a new federation store
    ///
    /// Creates the data directory if it doesn't exist and loads
    /// existing vouches and revocations from disk.
    pub async fn new<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        fs::create_dir_all(&data_dir).await
            .context("Failed to create federation data directory")?;

        let store = Self {
            data_dir,
            vouches: std::sync::Arc::new(RwLock::new(Vec::new())),
            revocations: std::sync::Arc::new(RwLock::new(Vec::new())),
        };

        // Load existing data
        store.load().await?;

        Ok(store)
    }

    /// Add a vouch to storage
    pub async fn add_vouch(&self, vouch: Vouch) -> Result<()> {
        let mut vouches = self.vouches.write().await;

        // Check if vouch already exists (by vouched_issuer_id)
        if vouches.iter().any(|v| v.vouched_issuer_id == vouch.vouched_issuer_id) {
            return Err(anyhow::anyhow!(
                "Vouch for {} already exists",
                vouch.vouched_issuer_id
            ));
        }

        vouches.push(vouch);
        drop(vouches); // Release lock before saving

        self.save_vouches().await?;
        info!("Added vouch to storage");

        Ok(())
    }

    /// Remove a vouch from storage
    pub async fn remove_vouch(&self, vouched_issuer_id: &str) -> Result<()> {
        let mut vouches = self.vouches.write().await;

        let initial_len = vouches.len();
        vouches.retain(|v| v.vouched_issuer_id != vouched_issuer_id);

        if vouches.len() == initial_len {
            return Err(anyhow::anyhow!(
                "No vouch found for {}",
                vouched_issuer_id
            ));
        }

        drop(vouches);
        self.save_vouches().await?;
        info!("Removed vouch for {}", vouched_issuer_id);

        Ok(())
    }

    /// Add a revocation to storage
    pub async fn add_revocation(&self, revocation: Revocation) -> Result<()> {
        let mut revocations = self.revocations.write().await;

        // Check if revocation already exists
        if revocations
            .iter()
            .any(|r| r.revoked_issuer_id == revocation.revoked_issuer_id)
        {
            return Err(anyhow::anyhow!(
                "Revocation for {} already exists",
                revocation.revoked_issuer_id
            ));
        }

        revocations.push(revocation);
        drop(revocations);

        self.save_revocations().await?;
        info!("Added revocation to storage");

        Ok(())
    }

    /// Remove a revocation from storage
    pub async fn remove_revocation(&self, revoked_issuer_id: &str) -> Result<()> {
        let mut revocations = self.revocations.write().await;

        let initial_len = revocations.len();
        revocations.retain(|r| r.revoked_issuer_id != revoked_issuer_id);

        if revocations.len() == initial_len {
            return Err(anyhow::anyhow!(
                "No revocation found for {}",
                revoked_issuer_id
            ));
        }

        drop(revocations);
        self.save_revocations().await?;
        info!("Removed revocation for {}", revoked_issuer_id);

        Ok(())
    }

    /// Get all vouches
    pub async fn get_vouches(&self) -> Vec<Vouch> {
        let vouches = self.vouches.read().await;
        vouches.clone()
    }

    /// Get all revocations
    pub async fn get_revocations(&self) -> Vec<Revocation> {
        let revocations = self.revocations.read().await;
        revocations.clone()
    }

    /// Load vouches and revocations from disk
    async fn load(&self) -> Result<()> {
        // Load vouches
        let vouches_path = self.data_dir.join("vouches.json");
        if vouches_path.exists() {
            let content = fs::read_to_string(&vouches_path).await
                .context("Failed to read vouches file")?;

            let vouches_file: VouchesFile = serde_json::from_str(&content)
                .context("Failed to parse vouches JSON")?;

            let mut vouches = self.vouches.write().await;
            *vouches = vouches_file.vouches;

            debug!("Loaded {} vouches from disk", vouches.len());
        } else {
            debug!("No vouches file found, starting with empty vouches");
        }

        // Load revocations
        let revocations_path = self.data_dir.join("revocations.json");
        if revocations_path.exists() {
            let content = fs::read_to_string(&revocations_path).await
                .context("Failed to read revocations file")?;

            let revocations_file: RevocationsFile = serde_json::from_str(&content)
                .context("Failed to parse revocations JSON")?;

            let mut revocations = self.revocations.write().await;
            *revocations = revocations_file.revocations;

            debug!("Loaded {} revocations from disk", revocations.len());
        } else {
            debug!("No revocations file found, starting with empty revocations");
        }

        Ok(())
    }

    /// Save vouches to disk
    async fn save_vouches(&self) -> Result<()> {
        let vouches = self.vouches.read().await;
        let vouches_file = VouchesFile {
            vouches: vouches.clone(),
        };

        let json = serde_json::to_string_pretty(&vouches_file)
            .context("Failed to serialize vouches")?;

        let vouches_path = self.data_dir.join("vouches.json");
        fs::write(&vouches_path, json).await
            .context("Failed to write vouches file")?;

        debug!("Saved {} vouches to disk", vouches.len());
        Ok(())
    }

    /// Save revocations to disk
    async fn save_revocations(&self) -> Result<()> {
        let revocations = self.revocations.read().await;
        let revocations_file = RevocationsFile {
            revocations: revocations.clone(),
        };

        let json = serde_json::to_string_pretty(&revocations_file)
            .context("Failed to serialize revocations")?;

        let revocations_path = self.data_dir.join("revocations.json");
        fs::write(&revocations_path, json).await
            .context("Failed to write revocations file")?;

        debug!("Saved {} revocations to disk", revocations.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_federation_store_new() {
        let dir = tempdir().unwrap();
        let store = FederationStore::new(dir.path()).await.unwrap();

        let vouches = store.get_vouches().await;
        let revocations = store.get_revocations().await;

        assert_eq!(vouches.len(), 0);
        assert_eq!(revocations.len(), 0);
    }

    #[tokio::test]
    async fn test_add_and_get_vouch() {
        let dir = tempdir().unwrap();
        let store = FederationStore::new(dir.path()).await.unwrap();

        let vouch = Vouch {
            voucher_issuer_id: "issuer:a:v1".to_string(),
            vouched_issuer_id: "issuer:b:v1".to_string(),
            vouched_pubkey: vec![1, 2, 3],
            expires_at: 9999999999,
            created_at: 1234567890,
            trust_level: Some(80),
            signature: [0u8; 64],
        };

        store.add_vouch(vouch.clone()).await.unwrap();

        let vouches = store.get_vouches().await;
        assert_eq!(vouches.len(), 1);
        assert_eq!(vouches[0].vouched_issuer_id, "issuer:b:v1");
    }

    #[tokio::test]
    async fn test_persistence() {
        let dir = tempdir().unwrap();

        // Create store and add vouch
        {
            let store = FederationStore::new(dir.path()).await.unwrap();

            let vouch = Vouch {
                voucher_issuer_id: "issuer:a:v1".to_string(),
                vouched_issuer_id: "issuer:b:v1".to_string(),
                vouched_pubkey: vec![1, 2, 3],
                expires_at: 9999999999,
                created_at: 1234567890,
                trust_level: Some(80),
                signature: [0u8; 64],
            };

            store.add_vouch(vouch).await.unwrap();
        }

        // Create new store instance and verify data persisted
        {
            let store = FederationStore::new(dir.path()).await.unwrap();
            let vouches = store.get_vouches().await;

            assert_eq!(vouches.len(), 1);
            assert_eq!(vouches[0].vouched_issuer_id, "issuer:b:v1");
        }
    }

    #[tokio::test]
    async fn test_remove_vouch() {
        let dir = tempdir().unwrap();
        let store = FederationStore::new(dir.path()).await.unwrap();

        let vouch = Vouch {
            voucher_issuer_id: "issuer:a:v1".to_string(),
            vouched_issuer_id: "issuer:b:v1".to_string(),
            vouched_pubkey: vec![1, 2, 3],
            expires_at: 9999999999,
            created_at: 1234567890,
            trust_level: Some(80),
            signature: [0u8; 64],
        };

        store.add_vouch(vouch).await.unwrap();
        assert_eq!(store.get_vouches().await.len(), 1);

        store.remove_vouch("issuer:b:v1").await.unwrap();
        assert_eq!(store.get_vouches().await.len(), 0);
    }
}
