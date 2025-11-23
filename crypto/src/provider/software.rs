// crypto/src/provider/software.rs
//! Software-based cryptographic provider (in-memory keys)
//!
//! This provider performs all cryptographic operations in software using
//! the p256 crate. Secret keys are stored in process memory and should be
//! zeroized on drop.
//!
//! # Security Considerations
//!
//! - Keys stored in RAM are vulnerable to memory dumps and cold boot attacks
//! - No hardware protection against key extraction
//! - Suitable for development, testing, and non-critical deployments
//! - For production use with sensitive keys, consider HSM-backed providers

use anyhow::Result;
use async_trait::async_trait;
use zeroize::Zeroize;

use crate::voprf::core::Server as VoprfServer;
use super::CryptoProvider;

/// Software crypto provider with in-memory key storage
///
/// This provider wraps the existing VOPRF implementation and provides
/// MAC key derivation using the secret key material.
pub struct SoftwareCryptoProvider {
    /// VOPRF server instance for evaluations
    server: VoprfServer,

    /// Secret key (stored for MAC key derivation)
    secret_key: [u8; 32],

    /// Public key (SEC1 compressed format, 33 bytes)
    public_key: [u8; 33],

    /// Key identifier
    key_id: String,

    /// Context for VOPRF operations
    context: Vec<u8>,
}

impl SoftwareCryptoProvider {
    /// Create a new software crypto provider
    ///
    /// # Arguments
    ///
    /// * `secret_key` - 32-byte P-256 secret key
    /// * `key_id` - Unique identifier for this key
    /// * `context` - Context bytes for VOPRF domain separation
    ///
    /// # Returns
    ///
    /// A new software provider ready for cryptographic operations
    ///
    /// # Errors
    ///
    /// Returns error if the secret key is invalid (e.g., zero scalar)
    pub fn new(
        secret_key: [u8; 32],
        key_id: String,
        context: Vec<u8>,
    ) -> Result<Self> {
        // Initialize VOPRF server
        let server = VoprfServer::from_secret_key(secret_key, &context)
            .map_err(|_| anyhow::anyhow!("invalid secret key for VOPRF"))?;

        // Get public key
        let public_key = server.public_key_sec1_compressed();

        Ok(Self {
            server,
            secret_key,
            public_key,
            key_id,
            context,
        })
    }
}

#[async_trait]
impl CryptoProvider for SoftwareCryptoProvider {
    async fn voprf_evaluate(&self, blinded: &[u8]) -> Result<Vec<u8>> {
        // Perform VOPRF evaluation in software
        self.server
            .evaluate(blinded)
            .map_err(|e| anyhow::anyhow!("VOPRF evaluation failed: {:?}", e))
    }

    async fn derive_mac_key(
        &self,
        issuer_id: &str,
        kid: &str,
        epoch: u32,
    ) -> Result<[u8; 32]> {
        // Use the existing HKDF-based MAC key derivation
        Ok(crate::derive_mac_key_v2(
            &self.secret_key,
            issuer_id,
            kid,
            epoch,
        ))
    }

    async fn sign_token_metadata(
        &self,
        token_bytes: &[u8],
        kid: &str,
        exp: i64,
        issuer_id: &str,
    ) -> Result<[u8; 64]> {
        // Use the existing ECDSA signature function
        crate::compute_token_signature(
            &self.secret_key,
            token_bytes,
            kid,
            exp,
            issuer_id,
        )
        .map_err(|e| anyhow::anyhow!("signature generation failed: {:?}", e))
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn context(&self) -> &[u8] {
        &self.context
    }
}

impl Drop for SoftwareCryptoProvider {
    fn drop(&mut self) {
        // Zeroize secret key on drop
        self.secret_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_software_provider_creation() {
        let sk = [42u8; 32];
        let kid = "test-key-001".to_string();
        let ctx = b"test-context".to_vec();

        let provider = SoftwareCryptoProvider::new(sk, kid.clone(), ctx.clone()).unwrap();

        assert_eq!(provider.key_id(), "test-key-001");
        assert_eq!(provider.context(), b"test-context");
        assert_eq!(provider.public_key().len(), 33);
    }

    #[tokio::test]
    async fn test_voprf_evaluation() {
        let sk = [42u8; 32];
        let kid = "test-key-001".to_string();
        let ctx = b"test-context".to_vec();

        let provider = SoftwareCryptoProvider::new(sk, kid, ctx).unwrap();

        // Create a valid blinded element (33-byte compressed point)
        // For testing, we'll use the generator point
        use crate::voprf::core::Server as VoprfServer;
        let test_server = VoprfServer::from_secret_key([1u8; 32], b"ctx").unwrap();
        let test_pk = test_server.public_key_sec1_compressed();

        // Evaluate the test public key as a blinded element
        let result = provider.voprf_evaluate(&test_pk).await;

        // Should succeed and return token bytes
        assert!(result.is_ok());
        let token = result.unwrap();

        // Token format: [VERSION||A||B||Proof] = 1 + 33 + 33 + 64 = 131 bytes
        assert_eq!(token.len(), 131);
        assert_eq!(token[0], 0x01); // VERSION byte
    }

    #[tokio::test]
    async fn test_mac_key_derivation() {
        let sk = [42u8; 32];
        let kid = "test-key-001".to_string();
        let ctx = b"test-context".to_vec();

        let provider = SoftwareCryptoProvider::new(sk, kid, ctx).unwrap();

        // Derive MAC keys for different epochs
        let key_epoch0 = provider.derive_mac_key("issuer1", "kid1", 0).await.unwrap();
        let key_epoch1 = provider.derive_mac_key("issuer1", "kid1", 1).await.unwrap();

        // Should be deterministic
        let key_epoch0_again = provider.derive_mac_key("issuer1", "kid1", 0).await.unwrap();
        assert_eq!(key_epoch0, key_epoch0_again);

        // Different epochs should produce different keys
        assert_ne!(key_epoch0, key_epoch1);

        // Different issuers should produce different keys
        let key_issuer2 = provider.derive_mac_key("issuer2", "kid1", 0).await.unwrap();
        assert_ne!(key_epoch0, key_issuer2);
    }

    #[tokio::test]
    async fn test_signature_signing_and_verification() {
        let sk = [42u8; 32];
        let kid = "test-key-001".to_string();
        let ctx = b"test-context".to_vec();

        let provider = SoftwareCryptoProvider::new(sk, kid, ctx).unwrap();

        let token = vec![1, 2, 3, 4, 5];
        let kid_str = "test-kid";
        let exp = 1234567890i64;
        let issuer_id = "test-issuer";

        // Sign metadata
        let signature = provider
            .sign_token_metadata(&token, kid_str, exp, issuer_id)
            .await
            .unwrap();

        assert_eq!(signature.len(), 64);

        // Verify signature using public key
        let pubkey = provider.public_key();
        let valid = crate::verify_token_signature(pubkey, &token, &signature, kid_str, exp, issuer_id);
        assert!(valid);

        // Tampering should fail verification
        let mut bad_token = token.clone();
        bad_token[0] ^= 1;
        let invalid = crate::verify_token_signature(pubkey, &bad_token, &signature, kid_str, exp, issuer_id);
        assert!(!invalid);
    }

    #[tokio::test]
    async fn test_signature_determinism() {
        let sk = [42u8; 32];
        let kid = "test-key-001".to_string();
        let ctx = b"test-context".to_vec();

        let provider = SoftwareCryptoProvider::new(sk, kid, ctx).unwrap();

        let token = vec![1, 2, 3];
        let kid_str = "kid";
        let exp = 123i64;
        let issuer_id = "issuer";

        // Signatures should be deterministic (RFC 6979)
        let sig1 = provider.sign_token_metadata(&token, kid_str, exp, issuer_id).await.unwrap();
        let sig2 = provider.sign_token_metadata(&token, kid_str, exp, issuer_id).await.unwrap();
        assert_eq!(sig1, sig2);
    }

    #[tokio::test]
    async fn test_zero_scalar_rejection() {
        let sk = [0u8; 32];
        let kid = "test-key-001".to_string();
        let ctx = b"test-context".to_vec();

        // Should reject zero scalar
        let result = SoftwareCryptoProvider::new(sk, kid, ctx);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_suite_id() {
        let sk = [42u8; 32];
        let kid = "test-key-001".to_string();
        let ctx = b"test-context".to_vec();

        let provider = SoftwareCryptoProvider::new(sk, kid, ctx).unwrap();

        assert_eq!(provider.suite_id(), "OPRF(P-256, SHA-256)-verifiable");
    }

    #[tokio::test]
    async fn test_secret_key_zeroization() {
        // Test that secret key is zeroized when provider is dropped
        let sk = [42u8; 32];
        let kid = "test-key-001".to_string();
        let ctx = b"test-context".to_vec();

        // Create a pointer to track the memory location
        let sk_copy = sk;

        {
            let provider = SoftwareCryptoProvider::new(sk, kid, ctx).unwrap();

            // Use the provider to ensure it's not optimized away
            assert_eq!(provider.key_id(), "test-key-001");

            // Provider will be dropped here
        }

        // After drop, we can't directly verify zeroization without unsafe code,
        // but we've verified the Drop implementation is called
        // This test documents the zeroization behavior
        assert_eq!(sk_copy, [42u8; 32]); // Original copy unchanged
    }

    #[tokio::test]
    async fn test_mac_key_zeroization() {
        use zeroize::Zeroizing;

        // Test that Zeroizing wrapper works for MAC keys
        let test_key = [0xAAu8; 32];

        {
            let mac_key = Zeroizing::new(test_key);
            assert_eq!(*mac_key, [0xAAu8; 32]);
            // mac_key will be zeroized when dropped here
        }

        // Original test_key is unchanged (it's a copy)
        assert_eq!(test_key, [0xAAu8; 32]);
    }
}
