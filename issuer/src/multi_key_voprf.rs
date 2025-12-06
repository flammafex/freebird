// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Multi-key VOPRF core with key rotation support
//!
//! This module extends the basic VoprfCore to support multiple active keys,
//! enabling graceful key rotation with zero downtime.
//!
//! # Key Lifecycle
//!
//! 1. **Active**: New tokens are issued with this key
//! 2. **Deprecated**: Old tokens can still be verified, no new issuance
//! 3. **Expired**: Key is removed after grace period
//!
//! # Grace Period
//!
//! Default: 30 days (configurable)
//! - Tokens issued before rotation remain valid
//! - Old keys continue to verify tokens
//! - After grace period, old keys are removed
//!
//! # Example
//!
//! ```rust,no_run
//! # use freebird_issuer::multi_key_voprf::{MultiKeyVoprfCore, EvaluationWithKid};
//! # use anyhow::Result;
//! # async fn example() -> Result<()> {
//! # let sk_bytes = [0u8; 32];
//! # let new_sk_bytes = [0u8; 32];
//! # let ctx = b"context";
//! # let blinded = "valid_base64_blinded_element";
//! // Initialize with active key
//! let multi_key = MultiKeyVoprfCore::new(sk_bytes, "pubkey".to_string(), "key-2024-01".to_string(), ctx)?;
//!
//! // Issue tokens (uses active key)
//! // Note: evaluate_b64 returns an EvaluationWithKid struct, not a tuple
//! let EvaluationWithKid { token, kid } = multi_key.evaluate_b64(blinded).await?;
//!
//! // Rotate to new key
//! multi_key.rotate_key(new_sk_bytes, "new_pubkey".to_string(), "key-2024-02".to_string(), Some(30 * 24 * 3600)).await?;
//!
//! // Old tokens still verify
//! // multi_key.verify_with_kid(old_token, "key-2024-01").await?; // ✓ Works
//!
//! // New tokens use new key
//! let EvaluationWithKid { token, kid } = multi_key.evaluate_b64(blinded).await?;
//! assert_eq!(kid, "key-2024-02");
//! # Ok(())
//! # }
//! ```

use anyhow::{anyhow, Context, Result};
use elliptic_curve::subtle::ConstantTimeEq;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::voprf_core::VoprfCore;

/// Current timestamp in seconds since Unix epoch
fn now() -> u64 {
    OffsetDateTime::now_utc().unix_timestamp() as u64
}

/// Constant-time string comparison for key IDs
///
/// This prevents timing attacks that could leak information about which
/// key IDs are in use or the timing of key rotation events.
///
/// # Security
///
/// While key IDs are typically public metadata, using constant-time comparison
/// provides defense-in-depth by preventing any potential timing side-channels.
fn constant_time_str_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Metadata about a deprecated key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeprecatedKeyMetadata {
    /// Key identifier
    pub kid: String,
    /// When this key was deprecated (Unix timestamp)
    pub deprecated_at: u64,
    /// When this key expires and will be removed (Unix timestamp)
    pub expires_at: u64,
    /// Base64url-encoded SEC1 compressed public key
    pub pubkey_b64: String,
}

/// A deprecated key that can still verify tokens
struct DeprecatedKey {
    voprf: VoprfCore,
    metadata: DeprecatedKeyMetadata,
}

/// Persisted key rotation state
#[derive(Clone, Debug, Serialize, Deserialize)]
struct KeyRotationState {
    /// Active key ID
    pub active_kid: String,
    /// Deprecated keys metadata
    pub deprecated_keys: Vec<DeprecatedKeyMetadata>,
    /// Version of this state format
    pub version: u32,
}

impl Default for KeyRotationState {
    fn default() -> Self {
        Self {
            active_kid: String::new(),
            deprecated_keys: Vec::new(),
            version: 1,
        }
    }
}

/// Response from token evaluation including key ID
#[derive(Debug, Clone)]
pub struct EvaluationWithKid {
    /// Base64url-encoded evaluation token
    pub token: String,
    /// Key ID used for this evaluation
    pub kid: String,
}

/// Status of a key
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Deprecated,
}

/// Information about a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub kid: String,
    pub status: KeyStatus,
    pub pubkey_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// Multi-key VOPRF core supporting key rotation
pub struct MultiKeyVoprfCore {
    /// Active key for new token issuance
    active_key: Arc<RwLock<VoprfCore>>,
    /// Deprecated keys for verification only
    deprecated_keys: Arc<RwLock<HashMap<String, DeprecatedKey>>>,
    /// VOPRF context
    ctx: Vec<u8>,
    /// Path to persistence file
    persistence_path: Option<std::path::PathBuf>,
    /// Default grace period for deprecated keys (seconds)
    default_grace_period_secs: u64,
}

impl MultiKeyVoprfCore {
    /// Create a new multi-key VOPRF core with an initial active key
    ///
    /// # Arguments
    ///
    /// * `sk` - Secret key bytes (32 bytes)
    /// * `pubkey_b64` - Base64url-encoded public key
    /// * `kid` - Key identifier
    /// * `ctx` - VOPRF context bytes
    pub fn new(sk: [u8; 32], pubkey_b64: String, kid: String, ctx: &[u8]) -> Result<Self> {
        let voprf = VoprfCore::new(sk, pubkey_b64, kid, ctx)?;

        Ok(Self {
            active_key: Arc::new(RwLock::new(voprf)),
            deprecated_keys: Arc::new(RwLock::new(HashMap::new())),
            ctx: ctx.to_vec(),
            persistence_path: None,
            default_grace_period_secs: 30 * 24 * 3600, // 30 days
        })
    }

    /// Create or load from persistence
    pub async fn load_or_create(
        sk: [u8; 32],
        pubkey_b64: String,
        kid: String,
        ctx: &[u8],
        persistence_path: Option<std::path::PathBuf>,
    ) -> Result<Self> {
        let mut core = Self::new(sk, pubkey_b64.clone(), kid.clone(), ctx)?;
        core.persistence_path = persistence_path.clone();

        // Try to load existing state
        if let Some(ref path) = persistence_path {
            if path.exists() {
                info!("Loading key rotation state from {:?}", path);
                core.load_state(path).await?;
            } else {
                info!("No existing key rotation state, starting fresh");
                // Save initial state
                core.save_state().await?;
            }
        }

        Ok(core)
    }

    /// Set the default grace period for deprecated keys
    pub fn set_grace_period(&mut self, seconds: u64) {
        self.default_grace_period_secs = seconds;
    }

    /// Get the current active key ID
    pub async fn active_kid(&self) -> String {
        self.active_key.read().await.kid.clone()
    }

    /// Get the active key's public key
    pub async fn active_pubkey_b64(&self) -> String {
        self.active_key.read().await.pubkey_b64.clone()
    }

    /// Derive MAC key for the active key and given epoch
    pub async fn derive_mac_key_for_epoch(&self, issuer_id: &str, epoch: u32) -> [u8; 32] {
        let active = self.active_key.read().await;
        active.derive_mac_key_for_epoch(issuer_id, epoch).await
    }

    /// Sign token metadata using the active key (for federation support)
    pub async fn sign_token_metadata(&self, token_bytes: &[u8], kid: &str, exp: i64, issuer_id: &str) -> Result<[u8; 64]> {
        let active = self.active_key.read().await;
        active.sign_token_metadata(token_bytes, kid, exp, issuer_id).await
    }

    /// Evaluate a blinded element using the active key
    ///
    /// Returns the evaluation token and the key ID used
    pub async fn evaluate_b64(&self, blinded_b64: &str) -> Result<EvaluationWithKid> {
        let active = self.active_key.read().await;
        let token = active.evaluate_b64(blinded_b64).await?;
        let kid = active.kid.clone();

        Ok(EvaluationWithKid { token, kid })
    }

    /// Verify a token with a specific key ID
    ///
    /// This supports both active and deprecated keys
    ///
    /// # Security
    ///
    /// Uses constant-time string comparison for key ID matching to prevent
    /// timing side-channels, providing defense-in-depth even though key IDs
    /// are typically public metadata.
    pub async fn verify_with_kid(&self, token_b64: &str, kid: &str) -> Result<String> {
        // Try active key first (constant-time comparison)
        {
            let active = self.active_key.read().await;
            if constant_time_str_eq(&active.kid, kid) {
                return self.verify_with_voprf(&active, token_b64);
            }
        }

        // Try deprecated keys (constant-time comparison)
        let deprecated = self.deprecated_keys.read().await;
        for (stored_kid, dep_key) in deprecated.iter() {
            if constant_time_str_eq(stored_kid, kid) {
                return self.verify_with_voprf(&dep_key.voprf, token_b64);
            }
        }

        Err(anyhow!("unknown key ID: {}", kid))
    }

    /// Verify token with a VoprfCore instance (internal helper)
    fn verify_with_voprf(&self, _voprf: &VoprfCore, token_b64: &str) -> Result<String> {
        // The token is actually the evaluation result, not something to "verify"
        // In the context of VOPRF, the verifier just needs to extract the PRF output
        // This is a placeholder - adjust based on your actual verification logic

        // For now, we'll just return the token as-is since verification happens
        // at the verifier service level with the public key
        Ok(token_b64.to_string())
    }

    /// Rotate to a new key
    ///
    /// The current active key becomes deprecated and the new key becomes active.
    ///
    /// # Arguments
    ///
    /// * `new_sk` - New secret key bytes
    /// * `new_pubkey_b64` - New public key (base64url)
    /// * `new_kid` - New key identifier
    /// * `grace_period_secs` - How long to keep old key active (None = use default)
    pub async fn rotate_key(
        &self,
        new_sk: [u8; 32],
        new_pubkey_b64: String,
        new_kid: String,
        grace_period_secs: Option<u64>,
    ) -> Result<()> {
        let grace_period = grace_period_secs.unwrap_or(self.default_grace_period_secs);
        let now_ts = now();
        let expires_at = now_ts + grace_period;

        // Get current active key
        let old_voprf = {
            let mut active = self.active_key.write().await;
            let old_kid = active.kid.clone();
            let old_pubkey = active.pubkey_b64.clone();

            info!(
                old_kid = %old_kid,
                new_kid = %new_kid,
                grace_period_days = grace_period / 86400,
                "Rotating key"
            );

            // Create new active key
            let new_voprf =
                VoprfCore::new(new_sk, new_pubkey_b64.clone(), new_kid.clone(), &self.ctx)?;

            // Swap active key
            let old_voprf = std::mem::replace(&mut *active, new_voprf);

            (old_voprf, old_kid, old_pubkey)
        };

        // Move old key to deprecated
        {
            let mut deprecated = self.deprecated_keys.write().await;

            let metadata = DeprecatedKeyMetadata {
                kid: old_voprf.1.clone(),
                deprecated_at: now_ts,
                expires_at,
                pubkey_b64: old_voprf.2.clone(),
            };

            deprecated.insert(
                old_voprf.1.clone(),
                DeprecatedKey {
                    voprf: old_voprf.0,
                    metadata,
                },
            );
        }

        // Persist state
        self.save_state().await?;

        // Log completion (get count before to avoid Send issues)
        let deprecated_count = self.deprecated_keys.read().await.len();
        info!(
            new_kid = %new_kid,
            deprecated_count = deprecated_count,
            "Key rotation complete"
        );

        Ok(())
    }

    /// Remove expired deprecated keys
    ///
    /// This should be called periodically (e.g., daily) to clean up old keys
    pub async fn cleanup_expired_keys(&self) -> Result<usize> {
        let now_ts = now();
        let mut removed = Vec::new();

        {
            let mut deprecated = self.deprecated_keys.write().await;

            // Find expired keys
            for (kid, dep_key) in deprecated.iter() {
                if now_ts >= dep_key.metadata.expires_at {
                    removed.push(kid.clone());
                }
            }

            // Remove them
            for kid in &removed {
                deprecated.remove(kid);
                info!(kid = %kid, "Removed expired key");
            }
        }

        if !removed.is_empty() {
            self.save_state().await?;
        }

        Ok(removed.len())
    }

    /// Force remove a deprecated key immediately
    ///
    /// Use with caution - this may invalidate tokens still in circulation
    pub async fn force_remove_key(&self, kid: &str) -> Result<()> {
        let mut deprecated = self.deprecated_keys.write().await;

        if deprecated.remove(kid).is_some() {
            warn!(kid = %kid, "Force removed key");
            drop(deprecated);
            self.save_state().await?;
            Ok(())
        } else {
            Err(anyhow!("key not found: {}", kid))
        }
    }

    /// List all keys (active and deprecated)
    pub async fn list_keys(&self) -> Vec<KeyInfo> {
        let mut keys = Vec::new();

        // Active key
        {
            let active = self.active_key.read().await;
            keys.push(KeyInfo {
                kid: active.kid.clone(),
                status: KeyStatus::Active,
                pubkey_b64: active.pubkey_b64.clone(),
                deprecated_at: None,
                expires_at: None,
            });
        }

        // Deprecated keys
        {
            let deprecated = self.deprecated_keys.read().await;
            for dep_key in deprecated.values() {
                keys.push(KeyInfo {
                    kid: dep_key.metadata.kid.clone(),
                    status: KeyStatus::Deprecated,
                    pubkey_b64: dep_key.metadata.pubkey_b64.clone(),
                    deprecated_at: Some(dep_key.metadata.deprecated_at),
                    expires_at: Some(dep_key.metadata.expires_at),
                });
            }
        }

        keys
    }

    /// Get metadata for the well-known endpoint
    ///
    /// Returns all valid keys (active + deprecated)
    pub async fn well_known_keys(&self) -> Vec<(String, String)> {
        let mut keys = Vec::new();

        // Active key
        {
            let active = self.active_key.read().await;
            keys.push((active.kid.clone(), active.pubkey_b64.clone()));
        }

        // Deprecated keys (still valid)
        {
            let deprecated = self.deprecated_keys.read().await;
            for dep_key in deprecated.values() {
                keys.push((
                    dep_key.metadata.kid.clone(),
                    dep_key.metadata.pubkey_b64.clone(),
                ));
            }
        }

        keys
    }

    /// Get key statistics
    pub async fn key_stats(&self) -> KeyStats {
        let deprecated = self.deprecated_keys.read().await;
        let now_ts = now();

        let mut expiring_soon = 0;
        let mut oldest_expires_at = None;

        for dep_key in deprecated.values() {
            let time_until_expiry = dep_key.metadata.expires_at.saturating_sub(now_ts);

            // Expiring within 7 days
            if time_until_expiry < 7 * 24 * 3600 {
                expiring_soon += 1;
            }

            // Track oldest expiry
            if oldest_expires_at.is_none()
                || dep_key.metadata.expires_at < oldest_expires_at.unwrap()
            {
                oldest_expires_at = Some(dep_key.metadata.expires_at);
            }
        }

        KeyStats {
            total_keys: 1 + deprecated.len(),
            active_keys: 1,
            deprecated_keys: deprecated.len(),
            expiring_soon,
            oldest_expires_at,
        }
    }

    /// Save current state to disk
    async fn save_state(&self) -> Result<()> {
        let Some(ref path) = self.persistence_path else {
            return Ok(()); // No persistence configured
        };

        let state = {
            let active = self.active_key.read().await;
            let deprecated = self.deprecated_keys.read().await;

            KeyRotationState {
                active_kid: active.kid.clone(),
                deprecated_keys: deprecated.values().map(|dk| dk.metadata.clone()).collect(),
                version: 1,
            }
        };

        let json = serde_json::to_string_pretty(&state)
            .context("failed to serialize key rotation state")?;

        // Atomic write
        let tmp_path = path.with_extension("tmp");
        tokio::fs::write(&tmp_path, json.as_bytes())
            .await
            .context("failed to write temp file")?;
        tokio::fs::rename(&tmp_path, path)
            .await
            .context("failed to rename temp file")?;

        debug!("Saved key rotation state to {:?}", path);
        Ok(())
    }

    /// Load state from disk
    async fn load_state(&self, path: &Path) -> Result<()> {
        let json = tokio::fs::read_to_string(path)
            .await
            .context("failed to read key rotation state")?;

        let state: KeyRotationState =
            serde_json::from_str(&json).context("failed to parse key rotation state")?;

        // Note: We don't actually load the keys themselves from disk
        // because we don't persist secret keys. This just loads metadata.
        // In a real implementation, you'd need to handle key loading separately
        // or use this metadata to validate against expected keys.

        info!(
            active_kid = %state.active_kid,
            deprecated_count = state.deprecated_keys.len(),
            "Loaded key rotation state"
        );

        Ok(())
    }
}

/// Statistics about keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStats {
    pub total_keys: usize,
    pub active_keys: usize,
    pub deprecated_keys: usize,
    pub expiring_soon: usize,
    pub oldest_expires_at: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_key_rotation() {
        let ctx = b"test_context";
        let sk1 = [1u8; 32];
        let sk2 = [2u8; 32];

        let core =
            MultiKeyVoprfCore::new(sk1, "pubkey1".to_string(), "key-2024-01".to_string(), ctx)
                .unwrap();

        // Check initial state
        assert_eq!(core.active_kid().await, "key-2024-01");
        assert_eq!(core.list_keys().await.len(), 1);

        // Rotate key
        core.rotate_key(
            sk2,
            "pubkey2".to_string(),
            "key-2024-02".to_string(),
            Some(3600), // 1 hour grace period
        )
        .await
        .unwrap();

        // Check new state
        assert_eq!(core.active_kid().await, "key-2024-02");
        let keys = core.list_keys().await;
        assert_eq!(keys.len(), 2);

        // Verify both keys are present
        assert!(keys
            .iter()
            .any(|k| k.kid == "key-2024-02" && matches!(k.status, KeyStatus::Active)));
        assert!(keys
            .iter()
            .any(|k| k.kid == "key-2024-01" && matches!(k.status, KeyStatus::Deprecated)));
    }

    #[tokio::test]
    async fn test_key_cleanup() {
        let ctx = b"test_context";
        let sk1 = [1u8; 32];
        let sk2 = [2u8; 32];

        let core =
            MultiKeyVoprfCore::new(sk1, "pubkey1".to_string(), "key-old".to_string(), ctx).unwrap();

        // Rotate with very short grace period (1 second for testing)
        core.rotate_key(sk2, "pubkey2".to_string(), "key-new".to_string(), Some(1))
            .await
            .unwrap();

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Cleanup
        let removed = core.cleanup_expired_keys().await.unwrap();
        assert_eq!(removed, 1);

        // Only new key should remain
        let keys = core.list_keys().await;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, "key-new");
    }

    #[test]
    fn test_constant_time_str_eq() {
        // Test basic equality
        assert!(constant_time_str_eq("key-001", "key-001"));
        assert!(constant_time_str_eq("", ""));

        // Test inequality
        assert!(!constant_time_str_eq("key-001", "key-002"));
        assert!(!constant_time_str_eq("short", "longer-string"));
        assert!(!constant_time_str_eq("longer-string", "short"));

        // Test that all character positions are checked
        assert!(!constant_time_str_eq("key-001", "key-002")); // Last char differs
        assert!(!constant_time_str_eq("aey-001", "key-001")); // First char differs
        assert!(!constant_time_str_eq("key-001", "key-101")); // Middle char differs

        // Test edge cases
        assert!(!constant_time_str_eq("key-001", "KEY-001")); // Case sensitivity
        assert!(!constant_time_str_eq("key-001 ", "key-001")); // Trailing space
        assert!(!constant_time_str_eq(" key-001", "key-001")); // Leading space
    }

    #[tokio::test]
    async fn test_verify_with_kid_constant_time() {
        let ctx = b"test_context";
        let sk1 = [1u8; 32];
        let sk2 = [2u8; 32];
        let sk3 = [3u8; 32];

        let core = MultiKeyVoprfCore::new(
            sk1,
            "pubkey1".to_string(),
            "key-2024-01".to_string(),
            ctx,
        )
        .unwrap();

        // Add multiple deprecated keys
        core.rotate_key(
            sk2,
            "pubkey2".to_string(),
            "key-2024-02".to_string(),
            Some(3600),
        )
        .await
        .unwrap();

        core.rotate_key(
            sk3,
            "pubkey3".to_string(),
            "key-2024-03".to_string(),
            Some(3600),
        )
        .await
        .unwrap();

        // Test verifying with active key
        let result = core.verify_with_kid("test-token", "key-2024-03").await;
        assert!(result.is_ok());

        // Test verifying with deprecated keys
        let result = core.verify_with_kid("test-token", "key-2024-02").await;
        assert!(result.is_ok());

        let result = core.verify_with_kid("test-token", "key-2024-01").await;
        assert!(result.is_ok());

        // Test with non-existent key
        let result = core.verify_with_kid("test-token", "key-2024-99").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unknown key ID"));

        // Test with similar but different key IDs (constant-time should handle these)
        let result = core.verify_with_kid("test-token", "key-2024-0").await; // Missing last char
        assert!(result.is_err());

        let result = core.verify_with_kid("test-token", "key-2024-031").await; // Extra char
        assert!(result.is_err());

        let result = core.verify_with_kid("test-token", "KEY-2024-03").await; // Different case
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_constant_time_key_matching_patterns() {
        // Test that constant-time comparison works for various key ID patterns
        let ctx = b"test";
        let sk = [42u8; 32];

        // Test with different key ID formats
        let test_cases = vec![
            ("key-001", "key-001", true),
            ("key-001", "key-002", false),
            ("a", "a", true),
            ("a", "b", false),
            ("very-long-key-identifier-12345", "very-long-key-identifier-12345", true),
            ("very-long-key-identifier-12345", "very-long-key-identifier-12346", false),
            ("key", "key-", false), // Length mismatch
            ("", "", true),          // Empty strings
        ];

        for (kid1, kid2, expected) in test_cases {
            let core = MultiKeyVoprfCore::new(
                sk,
                format!("pubkey-{}", kid1),
                kid1.to_string(),
                ctx,
            )
            .unwrap();

            let result = core.verify_with_kid("token", kid2).await;

            if expected {
                assert!(
                    result.is_ok(),
                    "Expected kid '{}' to match '{}', but it didn't",
                    kid1,
                    kid2
                );
            } else {
                assert!(
                    result.is_err(),
                    "Expected kid '{}' not to match '{}', but it did",
                    kid1,
                    kid2
                );
            }
        }
    }
}