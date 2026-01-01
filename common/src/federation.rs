// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Layer 2 Federation: Trust graph and issuer discovery
//!
//! This module implements ActivityPub-style federation for Freebird,
//! allowing issuers to vouch for each other and verifiers to traverse
//! trust graphs to make authorization decisions.

use serde::{Deserialize, Serialize};

/// A cryptographic vouch from one issuer for another
///
/// Vouches are signed statements that allow trust to be delegated
/// through a network of issuers. They form the edges of the trust graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vouch {
    /// The issuer making this vouch (voucher)
    pub voucher_issuer_id: String,

    /// The issuer being vouched for (vouchee)
    pub vouched_issuer_id: String,

    /// Public key of the vouched issuer (for verification)
    #[serde(with = "base64_bytes")]
    pub vouched_pubkey: Vec<u8>,

    /// When this vouch expires (Unix timestamp)
    pub expires_at: i64,

    /// When this vouch was created (Unix timestamp)
    pub created_at: i64,

    /// Optional trust level (0-100, where 100 is full trust)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<u8>,

    /// ECDSA signature over the vouch data by the voucher
    /// Signature covers: voucher_issuer_id || vouched_issuer_id || vouched_pubkey || expires_at || created_at
    #[serde(with = "base64_signature")]
    pub signature: [u8; 64],
}

impl Vouch {
    /// Create the message bytes that should be signed for this vouch
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.voucher_issuer_id.as_bytes());
        msg.extend_from_slice(b"|");
        msg.extend_from_slice(self.vouched_issuer_id.as_bytes());
        msg.extend_from_slice(b"|");
        msg.extend_from_slice(&self.vouched_pubkey);
        msg.extend_from_slice(b"|");
        msg.extend_from_slice(&self.expires_at.to_be_bytes());
        msg.extend_from_slice(b"|");
        msg.extend_from_slice(&self.created_at.to_be_bytes());
        msg
    }

    /// Check if this vouch has expired
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at <= now
    }

    /// Check if this vouch is currently valid (not expired, not future-dated)
    pub fn is_valid_at(&self, now: i64, max_clock_skew_secs: i64) -> bool {
        let max_future = now + max_clock_skew_secs;
        let min_past = now - max_clock_skew_secs;

        // Created time should not be too far in the future
        if self.created_at > max_future {
            return false;
        }

        // Should not be expired (with some clock skew tolerance)
        if self.expires_at < min_past {
            return false;
        }

        true
    }

    /// Sign this vouch with the voucher's secret key
    ///
    /// Creates an ECDSA signature over the vouch data using the voucher's
    /// secret key. The signature is deterministic (RFC 6979).
    ///
    /// # Arguments
    /// * `secret_key` - The voucher's 32-byte secret key
    ///
    /// # Returns
    /// 64-byte ECDSA signature (r || s)
    pub fn sign(&self, secret_key: &[u8; 32]) -> Result<[u8; 64], String> {
        let msg = self.signing_message();
        freebird_crypto::sign_message(secret_key, &msg)
            .map_err(|e| format!("Failed to sign vouch: {:?}", e))
    }

    /// Verify this vouch's signature using the voucher's public key
    ///
    /// Verifies the ECDSA signature over the vouch data.
    ///
    /// # Arguments
    /// * `public_key` - The voucher's public key (SEC1 compressed, 33 bytes)
    ///
    /// # Returns
    /// true if signature is valid, false otherwise
    pub fn verify(&self, public_key: &[u8]) -> bool {
        let msg = self.signing_message();
        freebird_crypto::verify_message_signature(public_key, &msg, &self.signature)
    }
}

/// A revocation statement removing trust from an issuer
///
/// Revocations allow issuers to explicitly remove vouches or
/// signal that another issuer should no longer be trusted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Revocation {
    /// The issuer making this revocation
    pub revoker_issuer_id: String,

    /// The issuer being revoked
    pub revoked_issuer_id: String,

    /// When this revocation was issued (Unix timestamp)
    pub revoked_at: i64,

    /// Reason for revocation (optional, for transparency)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// ECDSA signature over the revocation data
    /// Signature covers: revoker_issuer_id || revoked_issuer_id || revoked_at
    #[serde(with = "base64_signature")]
    pub signature: [u8; 64],
}

impl Revocation {
    /// Create the message bytes that should be signed for this revocation
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.revoker_issuer_id.as_bytes());
        msg.extend_from_slice(b"|");
        msg.extend_from_slice(self.revoked_issuer_id.as_bytes());
        msg.extend_from_slice(b"|");
        msg.extend_from_slice(&self.revoked_at.to_be_bytes());
        msg
    }

    /// Sign this revocation with the revoker's secret key
    ///
    /// Creates an ECDSA signature over the revocation data using the revoker's
    /// secret key. The signature is deterministic (RFC 6979).
    ///
    /// # Arguments
    /// * `secret_key` - The revoker's 32-byte secret key
    ///
    /// # Returns
    /// 64-byte ECDSA signature (r || s)
    pub fn sign(&self, secret_key: &[u8; 32]) -> Result<[u8; 64], String> {
        let msg = self.signing_message();
        freebird_crypto::sign_message(secret_key, &msg)
            .map_err(|e| format!("Failed to sign revocation: {:?}", e))
    }

    /// Verify this revocation's signature using the revoker's public key
    ///
    /// Verifies the ECDSA signature over the revocation data.
    ///
    /// # Arguments
    /// * `public_key` - The revoker's public key (SEC1 compressed, 33 bytes)
    ///
    /// # Returns
    /// true if signature is valid, false otherwise
    pub fn verify(&self, public_key: &[u8]) -> bool {
        let msg = self.signing_message();
        freebird_crypto::verify_message_signature(public_key, &msg, &self.signature)
    }
}

/// Federation metadata exposed at /.well-known/federation
///
/// This endpoint allows other issuers and verifiers to discover
/// which issuers this issuer trusts or has revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationMetadata {
    /// The issuer publishing this metadata
    pub issuer_id: String,

    /// List of active vouches issued by this issuer
    pub vouches: Vec<Vouch>,

    /// List of revocations issued by this issuer
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revocations: Vec<Revocation>,

    /// When this metadata was last updated (Unix timestamp)
    pub updated_at: i64,

    /// Optional: Recommended cache TTL in seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_secs: Option<u64>,
}

/// Trust policy configuration for verifiers
///
/// Determines how verifiers make trust decisions based on the federation graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPolicy {
    /// Whether federation is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum depth to traverse in the trust graph (0 = direct vouches only)
    #[serde(default = "default_max_trust_depth")]
    pub max_trust_depth: u32,

    /// Minimum number of independent trust paths required
    #[serde(default = "default_min_trust_paths")]
    pub min_trust_paths: u32,

    /// Only accept issuers with direct vouches from trusted roots
    #[serde(default)]
    pub require_direct_trust: bool,

    /// List of explicitly trusted root issuers (always trusted, regardless of vouches)
    #[serde(default)]
    pub trusted_roots: Vec<String>,

    /// List of explicitly blocked issuers (never trusted, even with vouches)
    #[serde(default)]
    pub blocked_issuers: Vec<String>,

    /// How often to refresh federation metadata (in seconds)
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_secs: u64,

    /// Minimum trust level required for vouches (0-100)
    #[serde(default = "default_min_trust_level")]
    pub min_trust_level: u8,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_trust_depth: 2,
            min_trust_paths: 1,
            require_direct_trust: false,
            trusted_roots: Vec::new(),
            blocked_issuers: Vec::new(),
            refresh_interval_secs: 3600, // 1 hour
            min_trust_level: 50,
        }
    }
}

impl TrustPolicy {
    /// Create a TrustPolicy from environment variables.
    ///
    /// This allows operators to configure federation trust policies without
    /// code changes. All values have sensible defaults.
    ///
    /// # Environment Variables
    ///
    /// - `TRUST_POLICY_ENABLED` - Enable federation (default: true)
    /// - `TRUST_POLICY_MAX_DEPTH` - Maximum trust graph depth (default: 2)
    /// - `TRUST_POLICY_MIN_PATHS` - Minimum independent trust paths (default: 1)
    /// - `TRUST_POLICY_REQUIRE_DIRECT` - Only accept direct vouches (default: false)
    /// - `TRUST_POLICY_TRUSTED_ROOTS` - Comma-separated list of trusted root issuer IDs
    /// - `TRUST_POLICY_BLOCKED_ISSUERS` - Comma-separated list of blocked issuer IDs
    /// - `TRUST_POLICY_REFRESH_INTERVAL` - Metadata refresh interval (default: "1h")
    ///   Supports human-readable durations: "30m", "1h", "1d"
    /// - `TRUST_POLICY_MIN_TRUST_LEVEL` - Minimum vouch trust level 0-100 (default: 50)
    ///
    /// # Examples
    ///
    /// ```bash
    /// # Enable federation with custom roots
    /// TRUST_POLICY_ENABLED=true
    /// TRUST_POLICY_TRUSTED_ROOTS=issuer:mozilla:v1,issuer:eff:v1
    /// TRUST_POLICY_MAX_DEPTH=3
    /// TRUST_POLICY_REFRESH_INTERVAL=30m
    /// ```
    pub fn from_env() -> Self {
        use crate::duration::env_duration;
        use std::env;

        let enabled = env::var("TRUST_POLICY_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(true);

        let max_trust_depth = env::var("TRUST_POLICY_MAX_DEPTH")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2);

        let min_trust_paths = env::var("TRUST_POLICY_MIN_PATHS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let require_direct_trust = env::var("TRUST_POLICY_REQUIRE_DIRECT")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let trusted_roots = env::var("TRUST_POLICY_TRUSTED_ROOTS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let blocked_issuers = env::var("TRUST_POLICY_BLOCKED_ISSUERS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        // Supports human-readable durations: "30m", "1h", "1d"
        let refresh_interval_secs = env_duration("TRUST_POLICY_REFRESH_INTERVAL", 3600);

        let min_trust_level = env::var("TRUST_POLICY_MIN_TRUST_LEVEL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50);

        Self {
            enabled,
            max_trust_depth,
            min_trust_paths,
            require_direct_trust,
            trusted_roots,
            blocked_issuers,
            refresh_interval_secs,
            min_trust_level,
        }
    }

    /// Check if this policy has any trusted roots configured
    pub fn has_trusted_roots(&self) -> bool {
        !self.trusted_roots.is_empty()
    }

    /// Check if a specific issuer is blocked
    pub fn is_blocked(&self, issuer_id: &str) -> bool {
        self.blocked_issuers.contains(&issuer_id.to_string())
    }

    /// Check if a specific issuer is a trusted root
    pub fn is_trusted_root(&self, issuer_id: &str) -> bool {
        self.trusted_roots.contains(&issuer_id.to_string())
    }
}

// Default value functions for serde
fn default_true() -> bool { true }
fn default_max_trust_depth() -> u32 { 2 }
fn default_min_trust_paths() -> u32 { 1 }
fn default_refresh_interval() -> u64 { 3600 }
fn default_min_trust_level() -> u8 { 50 }

/// Helper module for base64 encoding of byte slices
mod base64_bytes {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = Base64UrlUnpadded::encode_string(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Base64UrlUnpadded::decode_vec(&s).map_err(serde::de::Error::custom)
    }
}

/// Helper module for base64 encoding of 64-byte signatures
mod base64_signature {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(sig: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = Base64UrlUnpadded::encode_string(sig);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = Base64UrlUnpadded::decode_vec(&s).map_err(serde::de::Error::custom)?;
        let len = bytes.len();
        bytes.try_into().map_err(|_| {
            serde::de::Error::custom(format!("expected 64 bytes, got {}", len))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_vouch_signing_message() {
        let vouch = Vouch {
            voucher_issuer_id: "issuer:a:v1".to_string(),
            vouched_issuer_id: "issuer:b:v1".to_string(),
            vouched_pubkey: vec![1, 2, 3, 4],
            expires_at: 1234567890,
            created_at: 1234567800,
            trust_level: Some(80),
            signature: [0u8; 64],
        };

        let msg = vouch.signing_message();
        assert!(!msg.is_empty());

        // Should be deterministic
        let msg2 = vouch.signing_message();
        assert_eq!(msg, msg2);
    }

    #[test]
    fn test_vouch_expiration() {
        let vouch = Vouch {
            voucher_issuer_id: "issuer:a:v1".to_string(),
            vouched_issuer_id: "issuer:b:v1".to_string(),
            vouched_pubkey: vec![1, 2, 3],
            expires_at: 1000,
            created_at: 500,
            trust_level: None,
            signature: [0u8; 64],
        };

        assert!(!vouch.is_expired(999)); // Not expired
        assert!(vouch.is_expired(1000));  // Expired at exact time
        assert!(vouch.is_expired(1001));  // Expired after
    }

    #[test]
    fn test_vouch_validity_with_clock_skew() {
        let vouch = Vouch {
            voucher_issuer_id: "issuer:a:v1".to_string(),
            vouched_issuer_id: "issuer:b:v1".to_string(),
            vouched_pubkey: vec![1, 2, 3],
            expires_at: 2000,
            created_at: 1000,
            trust_level: None,
            signature: [0u8; 64],
        };

        let max_clock_skew = 300; // 5 minutes

        // Valid in the middle
        assert!(vouch.is_valid_at(1500, max_clock_skew));

        // Valid near creation with skew
        assert!(vouch.is_valid_at(800, max_clock_skew));

        // Valid near expiration with skew
        assert!(vouch.is_valid_at(2200, max_clock_skew));

        // Invalid: created too far in future
        assert!(!vouch.is_valid_at(500, max_clock_skew));

        // Invalid: expired too long ago
        assert!(!vouch.is_valid_at(2600, max_clock_skew));
    }

    #[test]
    fn test_revocation_signing_message() {
        let revocation = Revocation {
            revoker_issuer_id: "issuer:a:v1".to_string(),
            revoked_issuer_id: "issuer:bad:v1".to_string(),
            revoked_at: 1234567890,
            reason: Some("compromised".to_string()),
            signature: [0u8; 64],
        };

        let msg = revocation.signing_message();
        assert!(!msg.is_empty());

        // Should be deterministic
        let msg2 = revocation.signing_message();
        assert_eq!(msg, msg2);
    }

    #[test]
    fn test_trust_policy_defaults() {
        let policy = TrustPolicy::default();

        assert!(policy.enabled);
        assert_eq!(policy.max_trust_depth, 2);
        assert_eq!(policy.min_trust_paths, 1);
        assert!(!policy.require_direct_trust);
        assert!(policy.trusted_roots.is_empty());
        assert!(policy.blocked_issuers.is_empty());
        assert_eq!(policy.refresh_interval_secs, 3600);
        assert_eq!(policy.min_trust_level, 50);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let vouch = Vouch {
            voucher_issuer_id: "issuer:a:v1".to_string(),
            vouched_issuer_id: "issuer:b:v1".to_string(),
            vouched_pubkey: vec![1, 2, 3, 4, 5],
            expires_at: 1234567890,
            created_at: 1234567800,
            trust_level: Some(75),
            signature: [42u8; 64],
        };

        let json = serde_json::to_string(&vouch).expect("serialize");
        let decoded: Vouch = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(vouch, decoded);
    }

    #[test]
    fn test_vouch_sign_and_verify() {
        // Setup: Create issuer keypair
        let sk = [0x42u8; 32];
        let ctx = b"freebird:v1";
        let server = freebird_crypto::Server::from_secret_key(sk, ctx).expect("server");
        let pk = server.public_key_sec1_compressed();

        // Create vouch (without signature yet)
        let mut vouch = Vouch {
            voucher_issuer_id: "issuer:a:v1".to_string(),
            vouched_issuer_id: "issuer:b:v1".to_string(),
            vouched_pubkey: vec![1, 2, 3, 4, 5],
            expires_at: 9999999999,
            created_at: 1234567890,
            trust_level: Some(80),
            signature: [0u8; 64], // Placeholder
        };

        // Sign the vouch
        let signature = vouch.sign(&sk).expect("sign vouch");
        vouch.signature = signature;

        // Verify the vouch with correct public key
        assert!(vouch.verify(&pk), "Vouch should verify with correct public key");
    }

    #[test]
    fn test_vouch_verify_wrong_key() {
        // Setup: Create two different keypairs
        let sk_a = [0x11u8; 32];
        let sk_b = [0x22u8; 32];
        let ctx = b"freebird:v1";

        let server_a = freebird_crypto::Server::from_secret_key(sk_a, ctx).expect("server A");
        let pk_a = server_a.public_key_sec1_compressed();

        let server_b = freebird_crypto::Server::from_secret_key(sk_b, ctx).expect("server B");
        let pk_b = server_b.public_key_sec1_compressed();

        // Create and sign vouch with key A
        let mut vouch = Vouch {
            voucher_issuer_id: "issuer:a:v1".to_string(),
            vouched_issuer_id: "issuer:b:v1".to_string(),
            vouched_pubkey: vec![1, 2, 3],
            expires_at: 9999999999,
            created_at: 1234567890,
            trust_level: Some(80),
            signature: [0u8; 64],
        };

        let signature = vouch.sign(&sk_a).expect("sign vouch");
        vouch.signature = signature;

        // Should verify with correct key
        assert!(vouch.verify(&pk_a), "Should verify with correct key");

        // Should NOT verify with different key
        assert!(!vouch.verify(&pk_b), "Should not verify with wrong key");
    }

    #[test]
    fn test_vouch_verify_tampered() {
        // Setup: Create issuer keypair
        let sk = [0x42u8; 32];
        let ctx = b"freebird:v1";
        let server = freebird_crypto::Server::from_secret_key(sk, ctx).expect("server");
        let pk = server.public_key_sec1_compressed();

        // Create and sign vouch
        let mut vouch = Vouch {
            voucher_issuer_id: "issuer:a:v1".to_string(),
            vouched_issuer_id: "issuer:b:v1".to_string(),
            vouched_pubkey: vec![1, 2, 3],
            expires_at: 9999999999,
            created_at: 1234567890,
            trust_level: Some(80),
            signature: [0u8; 64],
        };

        let signature = vouch.sign(&sk).expect("sign vouch");
        vouch.signature = signature;

        // Verify original vouch works
        assert!(vouch.verify(&pk), "Original vouch should verify");

        // Tamper with vouch data
        vouch.expires_at = 8888888888;

        // Should NOT verify after tampering
        assert!(!vouch.verify(&pk), "Tampered vouch should not verify");
    }

    #[test]
    fn test_revocation_sign_and_verify() {
        // Setup: Create issuer keypair
        let sk = [0x42u8; 32];
        let ctx = b"freebird:v1";
        let server = freebird_crypto::Server::from_secret_key(sk, ctx).expect("server");
        let pk = server.public_key_sec1_compressed();

        // Create revocation (without signature yet)
        let mut revocation = Revocation {
            revoker_issuer_id: "issuer:a:v1".to_string(),
            revoked_issuer_id: "issuer:bad:v1".to_string(),
            revoked_at: 1234567890,
            reason: Some("compromised".to_string()),
            signature: [0u8; 64], // Placeholder
        };

        // Sign the revocation
        let signature = revocation.sign(&sk).expect("sign revocation");
        revocation.signature = signature;

        // Verify the revocation with correct public key
        assert!(
            revocation.verify(&pk),
            "Revocation should verify with correct public key"
        );
    }

    #[test]
    fn test_revocation_verify_wrong_key() {
        // Setup: Create two different keypairs
        let sk_a = [0x11u8; 32];
        let sk_b = [0x22u8; 32];
        let ctx = b"freebird:v1";

        let server_a = freebird_crypto::Server::from_secret_key(sk_a, ctx).expect("server A");
        let pk_a = server_a.public_key_sec1_compressed();

        let server_b = freebird_crypto::Server::from_secret_key(sk_b, ctx).expect("server B");
        let pk_b = server_b.public_key_sec1_compressed();

        // Create and sign revocation with key A
        let mut revocation = Revocation {
            revoker_issuer_id: "issuer:a:v1".to_string(),
            revoked_issuer_id: "issuer:bad:v1".to_string(),
            revoked_at: 1234567890,
            reason: None,
            signature: [0u8; 64],
        };

        let signature = revocation.sign(&sk_a).expect("sign revocation");
        revocation.signature = signature;

        // Should verify with correct key
        assert!(revocation.verify(&pk_a), "Should verify with correct key");

        // Should NOT verify with different key
        assert!(!revocation.verify(&pk_b), "Should not verify with wrong key");
    }

    #[test]
    #[serial]
    fn test_trust_policy_from_env_defaults() {
        // Clear all trust policy env vars
        std::env::remove_var("TRUST_POLICY_ENABLED");
        std::env::remove_var("TRUST_POLICY_MAX_DEPTH");
        std::env::remove_var("TRUST_POLICY_MIN_PATHS");
        std::env::remove_var("TRUST_POLICY_REQUIRE_DIRECT");
        std::env::remove_var("TRUST_POLICY_TRUSTED_ROOTS");
        std::env::remove_var("TRUST_POLICY_BLOCKED_ISSUERS");
        std::env::remove_var("TRUST_POLICY_REFRESH_INTERVAL");
        std::env::remove_var("TRUST_POLICY_MIN_TRUST_LEVEL");

        let policy = TrustPolicy::from_env();

        // Should match defaults
        assert!(policy.enabled);
        assert_eq!(policy.max_trust_depth, 2);
        assert_eq!(policy.min_trust_paths, 1);
        assert!(!policy.require_direct_trust);
        assert!(policy.trusted_roots.is_empty());
        assert!(policy.blocked_issuers.is_empty());
        assert_eq!(policy.refresh_interval_secs, 3600);
        assert_eq!(policy.min_trust_level, 50);
    }

    #[test]
    #[serial]
    fn test_trust_policy_from_env_custom() {
        // Set custom values
        std::env::set_var("TRUST_POLICY_ENABLED", "false");
        std::env::set_var("TRUST_POLICY_MAX_DEPTH", "5");
        std::env::set_var("TRUST_POLICY_MIN_PATHS", "3");
        std::env::set_var("TRUST_POLICY_REQUIRE_DIRECT", "true");
        std::env::set_var("TRUST_POLICY_TRUSTED_ROOTS", "issuer:a:v1, issuer:b:v1");
        std::env::set_var("TRUST_POLICY_BLOCKED_ISSUERS", "issuer:bad:v1");
        std::env::set_var("TRUST_POLICY_REFRESH_INTERVAL", "30m");
        std::env::set_var("TRUST_POLICY_MIN_TRUST_LEVEL", "75");

        let policy = TrustPolicy::from_env();

        assert!(!policy.enabled);
        assert_eq!(policy.max_trust_depth, 5);
        assert_eq!(policy.min_trust_paths, 3);
        assert!(policy.require_direct_trust);
        assert_eq!(policy.trusted_roots, vec!["issuer:a:v1", "issuer:b:v1"]);
        assert_eq!(policy.blocked_issuers, vec!["issuer:bad:v1"]);
        assert_eq!(policy.refresh_interval_secs, 1800); // 30 minutes
        assert_eq!(policy.min_trust_level, 75);

        // Cleanup
        std::env::remove_var("TRUST_POLICY_ENABLED");
        std::env::remove_var("TRUST_POLICY_MAX_DEPTH");
        std::env::remove_var("TRUST_POLICY_MIN_PATHS");
        std::env::remove_var("TRUST_POLICY_REQUIRE_DIRECT");
        std::env::remove_var("TRUST_POLICY_TRUSTED_ROOTS");
        std::env::remove_var("TRUST_POLICY_BLOCKED_ISSUERS");
        std::env::remove_var("TRUST_POLICY_REFRESH_INTERVAL");
        std::env::remove_var("TRUST_POLICY_MIN_TRUST_LEVEL");
    }

    #[test]
    fn test_trust_policy_helper_methods() {
        let policy = TrustPolicy {
            enabled: true,
            max_trust_depth: 2,
            min_trust_paths: 1,
            require_direct_trust: false,
            trusted_roots: vec!["issuer:root:v1".to_string()],
            blocked_issuers: vec!["issuer:bad:v1".to_string()],
            refresh_interval_secs: 3600,
            min_trust_level: 50,
        };

        assert!(policy.has_trusted_roots());
        assert!(policy.is_trusted_root("issuer:root:v1"));
        assert!(!policy.is_trusted_root("issuer:other:v1"));
        assert!(policy.is_blocked("issuer:bad:v1"));
        assert!(!policy.is_blocked("issuer:good:v1"));
    }
}
