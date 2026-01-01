// issuer/src/sybil_resistance/federated_trust.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Federated Trust Sybil Resistance
//!
//! Accepts users who have valid tokens from federated issuers that we trust.
//! Leverages the existing issuer-to-issuer federation infrastructure to
//! provide cross-issuer user interoperability.

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{KeyDiscoveryResp, SybilProof};
use freebird_common::federation::{TrustPolicy, Vouch};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::federation_store::FederationStore;
use super::SybilResistance;

/// Validate that the returned issuer_id matches the expected domain
///
/// This prevents a malicious server from claiming to be a different issuer.
/// The issuer_id can be:
/// - Simple hostname (e.g., "issuer.example.com")
/// - Prefixed format (e.g., "issuer:example.com:v1")
fn validate_issuer_domain(expected_domain: &str, returned_issuer_id: &str) -> bool {
    // Case 1: Exact match
    if expected_domain == returned_issuer_id {
        return true;
    }

    // Case 2: Extract hostname from prefixed issuer_id format
    // Format: "prefix:hostname:suffix" or "prefix:hostname"
    let returned_hostname = if returned_issuer_id.contains(':') {
        let parts: Vec<&str> = returned_issuer_id.split(':').collect();
        if parts.len() >= 2 {
            parts[1]
        } else {
            returned_issuer_id
        }
    } else {
        returned_issuer_id
    };

    // Compare expected domain with extracted hostname
    expected_domain == returned_hostname
}

/// Configuration for Federated Trust system
#[derive(Clone)]
pub struct FederatedTrustConfig {
    /// Trust policy for determining which issuers to trust
    pub trust_policy: TrustPolicy,
    /// Federation store containing our vouches
    pub federation_store: Arc<FederationStore>,
    /// Our issuer ID
    pub our_issuer_id: String,
    /// Cache TTL for remote federation metadata (seconds)
    pub cache_ttl_secs: u64,
    /// Maximum token age to accept (seconds)
    pub max_token_age_secs: i64,
}

/// Cached remote issuer public key
#[derive(Debug, Clone)]
struct CachedIssuerKey {
    /// SEC1 compressed public key (33 bytes)
    pubkey: Vec<u8>,
    /// When this was fetched (Unix timestamp)
    fetched_at: i64,
}

/// Federated Trust System
pub struct FederatedTrustSystem {
    config: FederatedTrustConfig,
    /// Cache of remote issuer public keys
    pubkey_cache: Arc<RwLock<HashMap<String, CachedIssuerKey>>>,
}

impl FederatedTrustSystem {
    /// Create a new Federated Trust system
    pub async fn new(config: FederatedTrustConfig) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            config,
            pubkey_cache: Arc::new(RwLock::new(HashMap::new())),
        }))
    }

    /// Get our current vouches from the federation store
    async fn get_our_vouches(&self) -> Vec<Vouch> {
        self.config.federation_store.get_vouches().await
    }

    /// Check if we directly trust an issuer
    async fn is_directly_trusted(&self, issuer_id: &str) -> Result<bool> {
        // Check if in trusted roots
        if self.config.trust_policy.trusted_roots.contains(&issuer_id.to_string()) {
            return Ok(true);
        }

        // Check if we have a vouch for this issuer
        let vouches = self.get_our_vouches().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        for vouch in vouches {
            if vouch.vouched_issuer_id == issuer_id {
                // Check if vouch is still valid
                if !vouch.is_valid_at(now, 300) {
                    continue;
                }

                // Check trust level if configured
                if let Some(min_level) = Some(self.config.trust_policy.min_trust_level) {
                    if let Some(level) = vouch.trust_level {
                        if level < min_level {
                            continue;
                        }
                    } else if min_level > 0 {
                        continue; // No trust level specified, but minimum required
                    }
                }

                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if we trust an issuer through a trust path
    async fn is_trusted(&self, issuer_id: &str, max_depth: u32) -> Result<bool> {
        // Check if explicitly blocked
        if self.config.trust_policy.blocked_issuers.contains(&issuer_id.to_string()) {
            return Ok(false);
        }

        // Check direct trust
        if self.is_directly_trusted(issuer_id).await? {
            return Ok(true);
        }

        // If require_direct_trust is set, don't traverse
        if self.config.trust_policy.require_direct_trust || max_depth == 0 {
            return Ok(false);
        }

        // TODO: Implement trust graph traversal for indirect trust
        // For now, only support direct trust
        Ok(false)
    }

    /// Fetch issuer public key from their /.well-known/issuer endpoint
    async fn fetch_issuer_pubkey(&self, issuer_id: &str) -> Result<Vec<u8>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Check cache first
        {
            let cache = self.pubkey_cache.read().await;
            if let Some(cached) = cache.get(issuer_id) {
                if now - cached.fetched_at < self.config.cache_ttl_secs as i64 {
                    return Ok(cached.pubkey.clone());
                }
            }
        }

        // Construct the issuer's metadata URL
        // issuer_id format is typically "issuer:hostname:version" or just a hostname
        let url = if issuer_id.starts_with("http://") || issuer_id.starts_with("https://") {
            format!("{}/.well-known/issuer", issuer_id)
        } else {
            // Extract hostname from issuer_id (e.g., "issuer:example.com:v1" -> "example.com")
            let parts: Vec<&str> = issuer_id.split(':').collect();
            let hostname = if parts.len() >= 2 { parts[1] } else { issuer_id };
            format!("https://{}/.well-known/issuer", hostname)
        };

        // Fetch metadata
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

        let resp_text = client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch issuer metadata from {}: {}", url, e))?
            .text()
            .await
            .map_err(|e| anyhow!("Failed to read issuer metadata: {}", e))?;

        let resp: KeyDiscoveryResp = serde_json::from_str(&resp_text)
            .map_err(|e| anyhow!("Failed to parse issuer metadata: {}", e))?;

        // Validate that the returned issuer_id matches the expected domain
        // This prevents a malicious server from claiming to be a different issuer
        if !validate_issuer_domain(issuer_id, &resp.issuer_id) {
            return Err(anyhow!(
                "Issuer metadata issuer_id mismatch: requested '{}', got '{}'",
                issuer_id,
                resp.issuer_id
            ));
        }

        // Decode the public key
        let pubkey = Base64UrlUnpadded::decode_vec(&resp.voprf.pubkey)
            .map_err(|_| anyhow!("Invalid pubkey encoding in issuer metadata"))?;

        // Update cache
        {
            let mut cache = self.pubkey_cache.write().await;
            cache.insert(
                issuer_id.to_string(),
                CachedIssuerKey {
                    pubkey: pubkey.clone(),
                    fetched_at: now,
                },
            );
        }

        Ok(pubkey)
    }

    /// Cryptographically verify a federated token against the source issuer's public key
    async fn verify_token_crypto(
        &self,
        token_b64: &str,
        source_issuer_id: &str,
    ) -> Result<()> {
        // Decode the token
        let token_bytes = Base64UrlUnpadded::decode_vec(token_b64)
            .map_err(|_| anyhow!("Invalid base64 token"))?;

        // Check minimum token length (VOPRF token is 131 bytes)
        if token_bytes.len() < 131 {
            return Err(anyhow!(
                "Token too short: {} bytes, minimum 131 for VOPRF",
                token_bytes.len()
            ));
        }

        // Fetch the source issuer's public key
        let pubkey = self.fetch_issuer_pubkey(source_issuer_id).await?;

        // The token may be:
        // - 131 bytes: just VOPRF (no auth, unusual)
        // - 163 bytes: VOPRF + MAC (V1 format, we can't verify without their secret key)
        // - 195 bytes: VOPRF + signature (V2 format, we CAN verify with public key)
        //
        // For VOPRF-only portion, we can verify the DLEQ proof against the public key.
        // This proves the token was correctly evaluated by someone with the corresponding
        // secret key.

        // Extract just the VOPRF portion (first 131 bytes)
        let voprf_token = &token_bytes[..131];
        let voprf_b64 = Base64UrlUnpadded::encode_string(voprf_token);

        // Verify the VOPRF proof against the issuer's public key
        let ctx = b"freebird-v1";
        let verifier = freebird_crypto::Verifier::new(ctx);

        // The public key should be SEC1 compressed (33 bytes)
        if pubkey.len() != 33 {
            return Err(anyhow!(
                "Invalid public key length: {} bytes, expected 33",
                pubkey.len()
            ));
        }

        verifier
            .verify(&voprf_b64, &pubkey)
            .map_err(|_| anyhow!(
                "VOPRF token verification failed - token was not issued by {}",
                source_issuer_id
            ))?;

        Ok(())
    }
}

impl SybilResistance for FederatedTrustSystem {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        match proof {
            SybilProof::FederatedTrust {
                source_issuer_id,
                source_token_b64,
                token_exp,
                token_issued_at,
                trust_path,
            } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                // Verify token hasn't expired
                if *token_exp < now {
                    return Err(anyhow!("Source token has expired"));
                }

                // Verify token age (anti-replay protection)
                // Priority 1: Use explicit issued_at timestamp if provided
                // Priority 2: Fall back to checking remaining validity
                if let Some(issued_at) = token_issued_at {
                    // Validate issued_at is sane (not in the future)
                    if *issued_at > now {
                        return Err(anyhow!("Token issued_at is in the future"));
                    }

                    // Validate issued_at is before expiration
                    if *issued_at >= *token_exp {
                        return Err(anyhow!("Token issued_at must be before expiration"));
                    }

                    // Check actual token age
                    let token_age = now - *issued_at;
                    if token_age > self.config.max_token_age_secs {
                        return Err(anyhow!(
                            "Token is too old: {} seconds (max: {})",
                            token_age,
                            self.config.max_token_age_secs
                        ));
                    }
                } else {
                    // Backward compatibility: if no issued_at, check remaining validity
                    // This is less secure but maintains compatibility with old clients.
                    // We limit the remaining validity window to prevent accepting tokens
                    // with excessively long lifetimes from federated issuers.
                    if *token_exp > now + self.config.max_token_age_secs {
                        return Err(anyhow!(
                            "Source token expiration is too far in the future (provide token_issued_at for better validation)"
                        ));
                    }
                }

                // Cryptographically verify the token against the source issuer's public key
                // This fetches their public key and verifies the VOPRF DLEQ proof
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        self.verify_token_crypto(source_token_b64, source_issuer_id).await
                    })
                })?;

                // Verify we trust the source issuer
                let max_depth = self.config.trust_policy.max_trust_depth;
                let is_trusted = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        self.is_trusted(source_issuer_id, max_depth).await
                    })
                })?;

                if !is_trusted {
                    return Err(anyhow!(
                        "Source issuer '{}' is not in our trust graph",
                        source_issuer_id
                    ));
                }

                // Verify trust path if provided
                if !trust_path.is_empty() {
                    // First element should be the source issuer
                    if trust_path.first() != Some(source_issuer_id) {
                        return Err(anyhow!("Trust path doesn't start with source issuer"));
                    }

                    // Last element should be us
                    if trust_path.last() != Some(&self.config.our_issuer_id) {
                        return Err(anyhow!("Trust path doesn't end with our issuer"));
                    }

                    // Verify path length doesn't exceed max depth
                    if trust_path.len() > (max_depth as usize + 1) {
                        return Err(anyhow!("Trust path exceeds maximum depth"));
                    }
                }

                Ok(())
            }
            _ => Err(anyhow!("Expected FederatedTrust proof")),
        }
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::FederatedTrust { .. })
    }

    fn cost(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_federation_store() -> Arc<FederationStore> {
        let store = FederationStore::new("/tmp/federated_trust_test")
            .await
            .unwrap();
        Arc::new(store)
    }

    #[tokio::test]
    async fn test_federated_trust_basic() {
        let store = create_test_federation_store().await;

        let config = FederatedTrustConfig {
            trust_policy: TrustPolicy {
                enabled: true,
                max_trust_depth: 2,
                min_trust_paths: 1,
                require_direct_trust: false,
                trusted_roots: vec!["issuer:root:v1".to_string()],
                blocked_issuers: vec![],
                refresh_interval_secs: 3600,
                min_trust_level: 50,
            },
            federation_store: store,
            our_issuer_id: "issuer:b:v1".to_string(),
            cache_ttl_secs: 3600,
            max_token_age_secs: 600,
        };

        let system = FederatedTrustSystem::new(config).await.unwrap();

        // Test that trusted root is recognized
        assert!(system.is_trusted("issuer:root:v1", 2).await.unwrap());

        // Test that unknown issuer is not trusted
        assert!(!system.is_trusted("issuer:unknown:v1", 2).await.unwrap());

        // Cleanup
        let _ = std::fs::remove_dir_all("/tmp/federated_trust_test");
    }

    // Note: verify_token_crypto requires network access to fetch issuer pubkeys,
    // so it cannot be unit tested without mocking. Integration tests should
    // cover the full token verification flow.
}
