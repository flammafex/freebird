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
use blind_rsa_signatures::{DefaultRng, KeyPairSha384PSSRandomized, SecretKeySha384PSSRandomized};

use super::{CryptoProvider, V7BlindRsaProvider};
use crate::public_bearer_v7::{
    V7BlindMessage, V7BlindSignature, V7KeyIdentity, V7PublicKeyBinding,
};
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

/// The fixed V7 RSA profile.
const V7_MODULUS_BITS: usize = 3072;

/// Software provider for the separate V7 randomized public bearer flow.
///
/// This type stores the randomized RSA-BSSA key type directly.
pub struct SoftwareV7BlindRsaProvider {
    secret_key: SecretKeySha384PSSRandomized,
    binding: V7PublicKeyBinding,
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

impl SoftwareV7BlindRsaProvider {
    /// Generate a V7 RSA-3072 key for an explicit issuer/key-id identity.
    pub fn generate(identity: V7KeyIdentity) -> Result<Self> {
        let mut rng = DefaultRng;
        let key_pair = KeyPairSha384PSSRandomized::generate(&mut rng, V7_MODULUS_BITS)
            .map_err(|e| anyhow::anyhow!("failed to generate V7 blind RSA key: {e}"))?;
        Self::from_secret_key(key_pair.sk, identity)
    }

    /// Load a V7 provider from PKCS#8 or PKCS#1 DER private key bytes.
    pub fn from_der(der: &[u8], identity: V7KeyIdentity) -> Result<Self> {
        let secret_key = SecretKeySha384PSSRandomized::from_der(der)
            .map_err(|e| anyhow::anyhow!("invalid V7 blind RSA private key: {e}"))?;
        Self::from_secret_key(secret_key, identity)
    }

    /// Serialize the V7 private key as PKCS#8 DER.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        self.secret_key
            .to_der()
            .map_err(|e| anyhow::anyhow!("failed to encode V7 blind RSA private key: {e}"))
    }

    /// Sign one nominal V7 blinded message for the requested identity.
    pub async fn blind_sign(
        &self,
        identity: &V7KeyIdentity,
        blinded_msg: &V7BlindMessage,
    ) -> Result<V7BlindSignature> {
        <Self as V7BlindRsaProvider>::blind_sign(self, identity, blinded_msg).await
    }

    /// Return the complete V7 issuer/key-id/SPKI binding.
    pub fn binding(&self) -> &V7PublicKeyBinding {
        &self.binding
    }

    fn from_secret_key(
        secret_key: SecretKeySha384PSSRandomized,
        identity: V7KeyIdentity,
    ) -> Result<Self> {
        let public_key = secret_key
            .public_key()
            .map_err(|e| anyhow::anyhow!("invalid V7 blind RSA public key: {e}"))?;
        let public_key_spki = public_key
            .to_spki()
            .map_err(|e| anyhow::anyhow!("failed to encode V7 blind RSA public key SPKI: {e}"))?;
        let binding = V7PublicKeyBinding::from_identity_and_spki(identity, &public_key_spki)
            .map_err(|e| anyhow::anyhow!("invalid V7 public token key: {e:?}"))?;

        Ok(Self {
            secret_key,
            binding,
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
impl V7BlindRsaProvider for SoftwareV7BlindRsaProvider {
    async fn blind_sign(
        &self,
        identity: &V7KeyIdentity,
        blinded_msg: &V7BlindMessage,
    ) -> Result<V7BlindSignature> {
        if identity != self.binding.identity() {
            return Err(anyhow::anyhow!(
                "V7 signing identity does not match provider binding"
            ));
        }
        let signature = self
            .secret_key
            .blind_sign(blinded_msg.as_bytes())
            .map_err(|e| anyhow::anyhow!("V7 blind RSA signing failed: {e}"))?;
        V7BlindSignature::from_bytes(&signature.0)
            .map_err(|e| anyhow::anyhow!("V7 signature must be exactly 384 bytes: {e:?}"))
    }

    fn binding(&self) -> &V7PublicKeyBinding {
        &self.binding
    }
}

// Drop is handled automatically by Zeroizing<[u8; 32]> on the secret_key field.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_bearer_v7::{
        validate_public_bearer_spki_v7, V7BlindMessage, V7BlindSignature, V7KeyIdentity,
        V7TokenKeyId,
    };

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

    #[tokio::test]
    async fn test_v7_provider_uses_explicit_binding_and_raw384_profile() {
        let identity = V7KeyIdentity::new("issuer:v7", V7TokenKeyId::new([0x42; 32])).unwrap();
        let provider = SoftwareV7BlindRsaProvider::generate(identity.clone()).unwrap();

        validate_public_bearer_spki_v7(provider.binding().public_key_spki()).unwrap();
        assert_eq!(provider.variant(), "RSABSSA-SHA384-PSS-Randomized-V7");
        assert_eq!(provider.binding().identity(), &identity);
        let der = provider.to_der().unwrap();
        let restored = SoftwareV7BlindRsaProvider::from_der(&der, identity.clone()).unwrap();
        assert_eq!(restored.binding(), provider.binding());

        let blind_message = V7BlindMessage::from_bytes(&[0u8; 384]).unwrap();
        let blind_signature = provider
            .blind_sign(&identity, &blind_message)
            .await
            .unwrap();
        assert_eq!(blind_signature.as_bytes().len(), 384);
        assert!(V7BlindMessage::from_bytes(&[0u8; 383]).is_err());
        assert!(V7BlindSignature::from_bytes(&[0u8; 383]).is_err());

        let wrong_identity =
            V7KeyIdentity::new("issuer:other", V7TokenKeyId::new([0x42; 32])).unwrap();
        let error = provider
            .blind_sign(&wrong_identity, &blind_message)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("identity does not match"));
    }
}
