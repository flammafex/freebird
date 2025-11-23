// crypto/src/provider/mod.rs
//! Cryptographic provider abstraction for software and HSM backends
//!
//! This module provides a pluggable architecture for cryptographic operations,
//! allowing the same VOPRF protocol to be executed either in software or using
//! hardware security modules (HSMs) via PKCS#11.

use anyhow::Result;
use async_trait::async_trait;

pub mod software;

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

/// Cryptographic provider for VOPRF operations and key derivation
///
/// This trait abstracts the cryptographic backend, allowing operations to be
/// performed either in software or using hardware security modules (HSMs).
///
/// # Security Considerations
///
/// - HSM implementations MUST ensure secret keys never leave the device
/// - All operations MUST be constant-time where applicable
/// - Implementations MUST properly zeroize sensitive intermediate values
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    /// Evaluate a VOPRF blinded element using the secret key
    ///
    /// This performs the core VOPRF evaluation: `sk * blinded_element`
    /// where sk is the secret scalar and blinded_element is a P-256 point.
    ///
    /// # Arguments
    ///
    /// * `blinded` - The blinded element (33-byte SEC1 compressed P-256 point)
    ///
    /// # Returns
    ///
    /// The evaluated token (131 bytes: VERSION || A || B || DLEQ_proof)
    ///
    /// # Security
    ///
    /// - For HSM implementations, this operation MUST occur entirely within the HSM
    /// - The secret key MUST NOT be exposed during this operation
    async fn voprf_evaluate(&self, blinded: &[u8]) -> Result<Vec<u8>>;

    /// Derive an epoch-specific MAC key using HKDF
    ///
    /// Derives a MAC key for token metadata binding using:
    /// `HKDF(secret_key, salt="freebird-mac-salt", info=issuer_id||kid||epoch)`
    ///
    /// # Arguments
    ///
    /// * `issuer_id` - Issuer identifier for domain separation
    /// * `kid` - Key identifier for domain separation
    /// * `epoch` - Time-based epoch number for key rotation
    ///
    /// # Returns
    ///
    /// A 32-byte MAC key derived from the secret key
    ///
    /// # Security
    ///
    /// - HSM implementations MAY perform HKDF in hardware if supported
    /// - Otherwise, use HSM for base key material and derive in software
    /// - Keys MUST be cryptographically independent across epochs
    async fn derive_mac_key(
        &self,
        issuer_id: &str,
        kid: &str,
        epoch: u32,
    ) -> Result<[u8; 32]>;

    /// Sign token metadata using ECDSA (for federation support)
    ///
    /// Signs the token metadata with the issuer's secret key using ECDSA.
    /// This enables multi-issuer federation because verifiers only need
    /// the public key to verify signatures (unlike MAC which requires secret key).
    ///
    /// Signs: `SHA256(token_bytes || kid || exp || issuer_id)`
    ///
    /// # Arguments
    ///
    /// * `token_bytes` - The VOPRF token bytes [VERSION||A||B||Proof] (131 bytes)
    /// * `kid` - Key identifier
    /// * `exp` - Expiration timestamp (Unix seconds)
    /// * `issuer_id` - Issuer identifier
    ///
    /// # Returns
    ///
    /// A 64-byte ECDSA signature (r || s, each 32 bytes)
    ///
    /// # Security
    ///
    /// - HSM implementations MUST perform signing entirely within the HSM
    /// - Uses deterministic ECDSA (RFC 6979) for reproducibility
    /// - Signature is over SHA256 hash of metadata
    async fn sign_token_metadata(
        &self,
        token_bytes: &[u8],
        kid: &str,
        exp: i64,
        issuer_id: &str,
    ) -> Result<[u8; 64]>;

    /// Get the public key corresponding to the secret key
    ///
    /// Returns the P-256 public key in SEC1 compressed format (33 bytes)
    ///
    /// # Returns
    ///
    /// SEC1 compressed P-256 public key (33 bytes)
    fn public_key(&self) -> &[u8];

    /// Get the key identifier
    ///
    /// Returns the unique identifier for this key
    fn key_id(&self) -> &str;

    /// Get the VOPRF suite identifier
    ///
    /// Returns the suite identifier string (e.g., "OPRF(P-256, SHA-256)-verifiable")
    fn suite_id(&self) -> &str {
        "OPRF(P-256, SHA-256)-verifiable"
    }

    /// Get the context string used for this VOPRF instance
    ///
    /// Returns the context bytes used for domain separation
    fn context(&self) -> &[u8];
}

/// Configuration for creating a crypto provider
#[derive(Debug, Clone)]
pub enum ProviderConfig {
    /// Software implementation (keys in memory)
    Software {
        secret_key: [u8; 32],
        key_id: String,
        context: Vec<u8>,
    },

    #[cfg(feature = "pkcs11")]
    /// PKCS#11 HSM implementation
    Pkcs11 {
        /// Path to PKCS#11 module (e.g., /usr/lib/libykcs11.so for YubiHSM)
        module_path: String,
        /// Slot number or token label
        slot: u64,
        /// User PIN for authentication
        pin: String,
        /// Key label in HSM
        key_label: String,
        /// Key identifier
        key_id: String,
        /// Context for VOPRF
        context: Vec<u8>,
    },
}

/// Create a crypto provider from configuration
///
/// # Arguments
///
/// * `config` - Provider configuration (Software or PKCS#11)
///
/// # Returns
///
/// A boxed crypto provider ready for use
///
/// # Errors
///
/// Returns error if:
/// - HSM connection fails
/// - Key not found in HSM
/// - Authentication fails
/// - Invalid key material
pub async fn create_provider(config: ProviderConfig) -> Result<Box<dyn CryptoProvider>> {
    match config {
        ProviderConfig::Software { secret_key, key_id, context } => {
            Ok(Box::new(software::SoftwareCryptoProvider::new(
                secret_key,
                key_id,
                context,
            )?))
        }

        #[cfg(feature = "pkcs11")]
        ProviderConfig::Pkcs11 { module_path, slot, pin, key_label, key_id, context } => {
            Ok(Box::new(pkcs11::Pkcs11CryptoProvider::new(
                &module_path,
                slot,
                &pin,
                &key_label,
                key_id,
                context,
            ).await?))
        }
    }
}
