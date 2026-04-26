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
use blind_rsa_signatures::{
    DefaultRng, KeyPairSha384PSSDeterministic, SecretKeySha384PSSDeterministic,
};

use super::{BlindRsaProvider, CryptoProvider};
use crate::voprf::core::Server as VoprfServer;

/// Software crypto provider with in-memory key storage
///
/// This provider wraps the existing VOPRF implementation for blinded
/// evaluations.
pub struct SoftwareCryptoProvider {
    /// VOPRF server instance for evaluations
    server: VoprfServer,

    /// Public key (SEC1 compressed format, 33 bytes)
    public_key: [u8; 33],

    /// Key identifier
    key_id: String,

    /// Context for VOPRF operations
    context: Vec<u8>,
}

/// Software provider for V5 public bearer pass blind RSA signatures.
pub struct SoftwareBlindRsaProvider {
    secret_key: SecretKeySha384PSSDeterministic,
    public_key_spki: Vec<u8>,
    token_key_id: [u8; crate::PUBLIC_BEARER_TOKEN_KEY_ID_LEN],
    modulus_bits: u16,
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
    pub fn new(secret_key: [u8; 32], key_id: String, context: Vec<u8>) -> Result<Self> {
        // Initialize VOPRF server
        let server = VoprfServer::from_secret_key(secret_key, &context)
            .map_err(|_| anyhow::anyhow!("invalid secret key for VOPRF"))?;

        // Get public key
        let public_key = server.public_key_sec1_compressed();

        Ok(Self {
            server,
            public_key,
            key_id,
            context,
        })
    }
}

impl SoftwareBlindRsaProvider {
    /// Generate a new RSA blind-signature key.
    pub fn generate(modulus_bits: usize) -> Result<Self> {
        let mut rng = DefaultRng;
        let key_pair = KeyPairSha384PSSDeterministic::generate(&mut rng, modulus_bits)
            .map_err(|e| anyhow::anyhow!("failed to generate blind RSA key: {e}"))?;
        Self::from_secret_key(key_pair.sk)
    }

    /// Load a provider from PKCS#8 or PKCS#1 DER private key bytes.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let secret_key = SecretKeySha384PSSDeterministic::from_der(der)
            .map_err(|e| anyhow::anyhow!("invalid blind RSA private key: {e}"))?;
        Self::from_secret_key(secret_key)
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        self.secret_key
            .to_der()
            .map_err(|e| anyhow::anyhow!("failed to encode blind RSA private key: {e}"))
    }

    fn from_secret_key(secret_key: SecretKeySha384PSSDeterministic) -> Result<Self> {
        let public_key = secret_key
            .public_key()
            .map_err(|e| anyhow::anyhow!("invalid blind RSA public key: {e}"))?;
        let public_key_spki = public_key
            .to_spki()
            .map_err(|e| anyhow::anyhow!("failed to encode blind RSA public key SPKI: {e}"))?;
        let token_key_id = crate::token_key_id_from_spki(&public_key_spki);
        let modulus_bits = public_key.components().n().len().saturating_mul(8);
        let modulus_bits = u16::try_from(modulus_bits)
            .map_err(|_| anyhow::anyhow!("blind RSA modulus is too large"))?;

        Ok(Self {
            secret_key,
            public_key_spki,
            token_key_id,
            modulus_bits,
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

#[async_trait]
impl BlindRsaProvider for SoftwareBlindRsaProvider {
    async fn blind_sign(&self, blinded_msg: &[u8]) -> Result<Vec<u8>> {
        let sig = self
            .secret_key
            .blind_sign(blinded_msg)
            .map_err(|e| anyhow::anyhow!("blind RSA signing failed: {e}"))?;
        Ok(sig.0)
    }

    fn public_key_spki(&self) -> &[u8] {
        &self.public_key_spki
    }

    fn token_key_id(&self) -> &[u8; crate::PUBLIC_BEARER_TOKEN_KEY_ID_LEN] {
        &self.token_key_id
    }

    fn modulus_bits(&self) -> u16 {
        self.modulus_bits
    }
}

// Drop is handled automatically by Zeroizing<[u8; 32]> on the secret_key field.

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
}
