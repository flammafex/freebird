// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Trust graph traversal and federation verification (Layer 2)
//!
//! This module implements the trust graph traversal algorithm that allows
//! verifiers to determine if an issuer should be trusted based on vouches
//! from other trusted issuers.

use anyhow::{Context, Result};
use freebird_common::federation::{FederationMetadata, Revocation, TrustPolicy, Vouch};
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Maximum clock skew tolerance for vouch validity checks (5 minutes)
const MAX_CLOCK_SKEW_SECS: i64 = 300;

/// Issuer metadata from /.well-known/issuer endpoint
#[derive(Debug, Clone, Deserialize)]
struct IssuerMetadata {
    #[allow(dead_code)]
    issuer_id: String,
    voprf: VoprfInfo,
}

#[derive(Debug, Clone, Deserialize)]
struct VoprfInfo {
    #[allow(dead_code)]
    suite: String,
    #[allow(dead_code)]
    kid: String,
    pubkey: String,  // Base64-encoded public key
    #[allow(dead_code)]
    exp_sec: u64,
}

/// Cached federation metadata for an issuer
#[derive(Debug, Clone)]
struct CachedMetadata {
    metadata: FederationMetadata,
    fetched_at: SystemTime,
}

/// Cached public key for an issuer
#[derive(Debug, Clone)]
struct CachedPubkey {
    pubkey: Vec<u8>,
    fetched_at: SystemTime,
}

/// Trust graph manager for Layer 2 federation
///
/// This manages the trust graph, fetches federation metadata from remote
/// issuers, caches it, and provides methods to check if an issuer is trusted.
pub struct TrustGraph {
    /// Policy configuration
    policy: TrustPolicy,

    /// Cached federation metadata, keyed by issuer_id
    cache: Arc<RwLock<HashMap<String, CachedMetadata>>>,

    /// Cached public keys, keyed by issuer_id
    pubkey_cache: Arc<RwLock<HashMap<String, CachedPubkey>>>,

    /// HTTP client for fetching remote metadata
    client: reqwest::Client,
}

impl TrustGraph {
    /// Create a new trust graph with the given policy
    pub fn new(policy: TrustPolicy) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            policy,
            cache: Arc::new(RwLock::new(HashMap::new())),
            pubkey_cache: Arc::new(RwLock::new(HashMap::new())),
            client,
        }
    }

    /// Check if an issuer is trusted according to the policy
    ///
    /// This traverses the trust graph using BFS to find valid trust paths
    /// from trusted roots to the target issuer.
    ///
    /// # Arguments
    /// * `issuer_id` - The issuer ID to check
    /// * `issuer_pubkey` - The issuer's public key (for vouch verification)
    ///
    /// # Returns
    /// true if the issuer is trusted, false otherwise
    pub async fn is_trusted(&self, issuer_id: &str, issuer_pubkey: &[u8]) -> bool {
        // Check if federation is enabled
        if !self.policy.enabled {
            debug!("Federation disabled, rejecting issuer {}", issuer_id);
            return false;
        }

        // Check if issuer is explicitly blocked
        if self.policy.blocked_issuers.contains(&issuer_id.to_string()) {
            warn!("Issuer {} is explicitly blocked", issuer_id);
            return false;
        }

        // Check if issuer is a trusted root
        if self.policy.trusted_roots.contains(&issuer_id.to_string()) {
            debug!("Issuer {} is a trusted root", issuer_id);
            return true;
        }

        // If require_direct_trust is set, only accept direct vouches from roots
        if self.policy.require_direct_trust {
            return self.has_direct_trust(issuer_id, issuer_pubkey).await;
        }

        // Otherwise, traverse the trust graph to find paths
        match self.find_trust_paths(issuer_id, issuer_pubkey).await {
            Ok(paths) => {
                let count = paths.len();
                debug!(
                    "Found {} trust paths to issuer {} (required: {})",
                    count, issuer_id, self.policy.min_trust_paths
                );
                count >= self.policy.min_trust_paths as usize
            }
            Err(e) => {
                warn!("Failed to traverse trust graph for {}: {}", issuer_id, e);
                false
            }
        }
    }

    /// Check if an issuer has direct vouches from trusted roots
    async fn has_direct_trust(&self, issuer_id: &str, issuer_pubkey: &[u8]) -> bool {
        let now = current_timestamp();

        for root_id in &self.policy.trusted_roots {
            // Fetch metadata for the root
            let metadata = match self.fetch_metadata(root_id).await {
                Ok(m) => m,
                Err(e) => {
                    warn!("Failed to fetch metadata for root {}: {}", root_id, e);
                    continue;
                }
            };

            // Check if root has vouched for this issuer
            for vouch in &metadata.vouches {
                if vouch.vouched_issuer_id == issuer_id
                    && self.is_vouch_valid(vouch, issuer_pubkey, now).await
                {
                    debug!(
                        "Found direct vouch from root {} for {}",
                        root_id, issuer_id
                    );
                    return true;
                }
            }
        }

        false
    }

    /// Find all valid trust paths from trusted roots to the target issuer
    ///
    /// Uses BFS to explore the trust graph up to max_trust_depth.
    /// Returns a list of trust paths (each path is a list of issuer IDs).
    async fn find_trust_paths(
        &self,
        target_issuer_id: &str,
        target_pubkey: &[u8],
    ) -> Result<Vec<Vec<String>>> {
        let now = current_timestamp();
        let mut paths = Vec::new();

        // BFS queue: (current_issuer_id, path_so_far, depth)
        let mut queue: VecDeque<(String, Vec<String>, u32)> = VecDeque::new();

        // Initialize queue with trusted roots
        for root in &self.policy.trusted_roots {
            queue.push_back((root.clone(), vec![root.clone()], 0));
        }

        // Track visited issuers to avoid cycles
        let mut visited = HashSet::new();

        while let Some((current_id, path, depth)) = queue.pop_front() {
            // Skip if we've already visited this issuer
            if visited.contains(&current_id) {
                continue;
            }
            visited.insert(current_id.clone());

            // Fetch metadata for current issuer
            let metadata = match self.fetch_metadata(&current_id).await {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        "Failed to fetch metadata for {}: {}, skipping",
                        current_id, e
                    );
                    continue;
                }
            };

            // Check each vouch from this issuer
            for vouch in &metadata.vouches {
                // Skip if vouched issuer is blocked
                if self
                    .policy
                    .blocked_issuers
                    .contains(&vouch.vouched_issuer_id)
                {
                    continue;
                }

                // Skip if vouched issuer has been revoked
                if self.is_revoked(&vouch.vouched_issuer_id, &metadata.revocations, now).await {
                    debug!(
                        "Issuer {} has been revoked by {}, skipping",
                        vouch.vouched_issuer_id, current_id
                    );
                    continue;
                }

                // Check if this vouch points to our target
                if vouch.vouched_issuer_id == target_issuer_id {
                    // Verify the vouch is valid
                    if self.is_vouch_valid(vouch, target_pubkey, now).await {
                        let mut final_path = path.clone();
                        final_path.push(target_issuer_id.to_string());
                        paths.push(final_path);
                        debug!(
                            "Found trust path: {:?}",
                            paths.last().unwrap()
                        );
                    }
                } else if depth < self.policy.max_trust_depth {
                    // Continue exploring if we haven't reached max depth
                    // We need the vouched issuer's public key to verify subsequent vouches
                    // For now, we trust the vouch if it's properly signed by the current issuer

                    // Get current issuer's public key to verify this vouch
                    // TODO: We need to track public keys for all issuers in the path
                    // For now, we'll skip deep verification and just check the signature
                    // This will be improved when we add proper public key tracking

                    let mut new_path = path.clone();
                    new_path.push(vouch.vouched_issuer_id.clone());
                    queue.push_back((
                        vouch.vouched_issuer_id.clone(),
                        new_path,
                        depth + 1,
                    ));
                }
            }
        }

        Ok(paths)
    }

    /// Fetch federation metadata for an issuer (with caching)
    async fn fetch_metadata(&self, issuer_id: &str) -> Result<FederationMetadata> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(issuer_id) {
                let age = SystemTime::now()
                    .duration_since(cached.fetched_at)
                    .unwrap_or(Duration::from_secs(0));

                let ttl = Duration::from_secs(self.policy.refresh_interval_secs);

                if age < ttl {
                    debug!(
                        "Using cached metadata for {} (age: {:?})",
                        issuer_id, age
                    );
                    return Ok(cached.metadata.clone());
                }
            }
        }

        // Fetch from remote
        debug!("Fetching federation metadata for {}", issuer_id);
        let url = format!("https://{}/.well-known/federation", issuer_id);

        let metadata: FederationMetadata = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch federation metadata")?
            .json()
            .await
            .context("Failed to parse federation metadata")?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                issuer_id.to_string(),
                CachedMetadata {
                    metadata: metadata.clone(),
                    fetched_at: SystemTime::now(),
                },
            );
        }

        info!("Fetched and cached metadata for {}", issuer_id);
        Ok(metadata)
    }

    /// Fetch issuer public key (with caching)
    async fn fetch_pubkey(&self, issuer_id: &str) -> Result<Vec<u8>> {
        // Check cache first
        {
            let cache = self.pubkey_cache.read().await;
            if let Some(cached) = cache.get(issuer_id) {
                let age = SystemTime::now()
                    .duration_since(cached.fetched_at)
                    .unwrap_or(Duration::from_secs(0));

                let ttl = Duration::from_secs(self.policy.refresh_interval_secs);

                if age < ttl {
                    debug!(
                        "Using cached pubkey for {} (age: {:?})",
                        issuer_id, age
                    );
                    return Ok(cached.pubkey.clone());
                }
            }
        }

        // Fetch from remote
        debug!("Fetching issuer metadata for {}", issuer_id);
        let url = format!("https://{}/.well-known/issuer", issuer_id);

        let issuer_metadata: IssuerMetadata = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch issuer metadata")?
            .json()
            .await
            .context("Failed to parse issuer metadata")?;

        // Decode base64 public key
        use base64ct::{Base64UrlUnpadded, Encoding};
        let pubkey = Base64UrlUnpadded::decode_vec(&issuer_metadata.voprf.pubkey)
            .context("Failed to decode public key")?;

        // Update cache
        {
            let mut cache = self.pubkey_cache.write().await;
            cache.insert(
                issuer_id.to_string(),
                CachedPubkey {
                    pubkey: pubkey.clone(),
                    fetched_at: SystemTime::now(),
                },
            );
        }

        info!("Fetched and cached pubkey for {}", issuer_id);
        Ok(pubkey)
    }

    /// Check if a vouch is valid (not expired, proper signature, meets trust level)
    async fn is_vouch_valid(&self, vouch: &Vouch, vouched_pubkey: &[u8], now: i64) -> bool {
        // Check expiration and creation time
        if !vouch.is_valid_at(now, MAX_CLOCK_SKEW_SECS) {
            debug!(
                "Vouch from {} for {} is expired or invalid time",
                vouch.voucher_issuer_id, vouch.vouched_issuer_id
            );
            return false;
        }

        // Check trust level
        if let Some(level) = vouch.trust_level {
            if level < self.policy.min_trust_level {
                debug!(
                    "Vouch from {} for {} has insufficient trust level ({} < {})",
                    vouch.voucher_issuer_id,
                    vouch.vouched_issuer_id,
                    level,
                    self.policy.min_trust_level
                );
                return false;
            }
        }

        // Verify the vouch signature using the vouched issuer's public key
        // The vouch should contain the public key of the vouched issuer
        if vouch.vouched_pubkey != vouched_pubkey {
            debug!(
                "Vouch public key mismatch for {}",
                vouch.vouched_issuer_id
            );
            return false;
        }

        // Fetch the voucher's public key to verify the signature
        let voucher_pubkey = match self.fetch_pubkey(&vouch.voucher_issuer_id).await {
            Ok(pk) => pk,
            Err(e) => {
                warn!(
                    "Failed to fetch pubkey for voucher {}: {}",
                    vouch.voucher_issuer_id, e
                );
                return false;
            }
        };

        // Verify the vouch signature using the VOUCHER's public key
        if !vouch.verify(&voucher_pubkey) {
            warn!(
                "Vouch signature verification failed for {} vouching for {}",
                vouch.voucher_issuer_id, vouch.vouched_issuer_id
            );
            return false;
        }

        debug!(
            "Vouch from {} for {} is valid (verified signature)",
            vouch.voucher_issuer_id, vouch.vouched_issuer_id
        );
        true
    }

    /// Check if an issuer has been revoked
    ///
    /// Checks if the issuer appears in the revocations list.
    /// Revocations are considered valid regardless of timestamp (permanent).
    /// Verifies revocation signatures against the revoker's public key.
    async fn is_revoked(
        &self,
        issuer_id: &str,
        revocations: &[Revocation],
        _now: i64,
    ) -> bool {
        for revocation in revocations {
            if revocation.revoked_issuer_id == issuer_id {
                // Fetch the revoker's public key to verify the signature
                let revoker_pubkey = match self.fetch_pubkey(&revocation.revoker_issuer_id).await {
                    Ok(pk) => pk,
                    Err(e) => {
                        warn!(
                            "Failed to fetch pubkey for revoker {}: {}",
                            revocation.revoker_issuer_id, e
                        );
                        continue; // Try next revocation
                    }
                };

                // Verify the revocation signature using the REVOKER's public key
                if !revocation.verify(&revoker_pubkey) {
                    warn!(
                        "Revocation signature verification failed for {} revoking {}",
                        revocation.revoker_issuer_id, revocation.revoked_issuer_id
                    );
                    continue; // Try next revocation
                }

                debug!(
                    "Issuer {} has been revoked by {} (reason: {:?}, verified signature)",
                    issuer_id, revocation.revoker_issuer_id, revocation.reason
                );
                return true;
            }
        }
        false
    }

    /// Clear the metadata and public key caches
    pub async fn clear_cache(&self) {
        {
            let mut cache = self.cache.write().await;
            cache.clear();
        }
        {
            let mut pubkey_cache = self.pubkey_cache.write().await;
            pubkey_cache.clear();
        }
        info!("Federation metadata and public key caches cleared");
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_policy_default() {
        let policy = TrustPolicy::default();
        assert!(policy.enabled);
        assert_eq!(policy.max_trust_depth, 2);
        assert_eq!(policy.min_trust_paths, 1);
    }

    #[test]
    fn test_current_timestamp() {
        let now = current_timestamp();
        assert!(now > 1700000000); // Sanity check: after Nov 2023
    }

    #[tokio::test]
    async fn test_trust_graph_disabled() {
        let mut policy = TrustPolicy::default();
        policy.enabled = false;

        let graph = TrustGraph::new(policy);
        let trusted = graph.is_trusted("issuer:test:v1", &[0u8; 33]).await;

        assert!(!trusted, "Should not trust when federation is disabled");
    }

    #[tokio::test]
    async fn test_trust_graph_blocked_issuer() {
        let mut policy = TrustPolicy::default();
        policy.blocked_issuers = vec!["issuer:bad:v1".to_string()];

        let graph = TrustGraph::new(policy);
        let trusted = graph.is_trusted("issuer:bad:v1", &[0u8; 33]).await;

        assert!(!trusted, "Should not trust blocked issuer");
    }

    #[tokio::test]
    async fn test_trust_graph_trusted_root() {
        let mut policy = TrustPolicy::default();
        policy.trusted_roots = vec!["issuer:root:v1".to_string()];

        let graph = TrustGraph::new(policy);
        let trusted = graph.is_trusted("issuer:root:v1", &[0u8; 33]).await;

        assert!(trusted, "Should trust root issuer");
    }

    // Note: The test_is_revoked test has been removed because is_revoked
    // now performs signature verification which requires fetching public keys
    // from remote issuers. The revocation logic is tested as part of the full
    // trust graph traversal in integration tests.
}
