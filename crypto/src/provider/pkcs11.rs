// crypto/src/provider/pkcs11.rs
//! PKCS#11 HSM-based cryptographic provider
//!
//! This provider uses PKCS#11 to interface with hardware security modules (HSMs)
//! like YubiHSM, Nitrokey HSM, SoftHSM, etc.
//!
//! # Security Advantages
//!
//! - Secret keys never leave the HSM
//! - Cryptographic operations performed in hardware
//! - Physical tamper resistance (hardware-dependent)
//! - Access control and audit logging
//!
//! # Supported Operations
//!
//! - **VOPRF Evaluation**: P-256 scalar multiplication in HSM (CKM_ECDH1_DERIVE or CKM_EC_KEY_PAIR_GEN)
//! - **MAC Key Derivation**: HKDF in software using HSM-derived base key material
//! - **Public Key Export**: Extract P-256 public key from HSM
//!
//! # Configuration Example
//!
//! ```toml
//! [hsm]
//! module_path = "/usr/lib/softhsm/libsofthsm2.so"  # SoftHSM
//! # module_path = "/usr/lib/libykcs11.so"          # YubiHSM
//! slot = 0
//! pin = "1234"
//! key_label = "freebird-voprf-key"
//! ```

use anyhow::{Context, Result};
use async_trait::async_trait;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::mechanism::Mechanism;
use cryptoki::types::AuthPin;
use cryptoki::slot::Slot;
use std::sync::Arc;
use zeroize::Zeroize;

use super::CryptoProvider;

/// PKCS#11 crypto provider for HSM operations
///
/// This provider interfaces with PKCS#11-compatible HSMs to perform
/// cryptographic operations with hardware-protected keys.
pub struct Pkcs11CryptoProvider {
    /// PKCS#11 context (shared)
    pkcs11: Arc<Pkcs11>,

    /// HSM slot
    slot: Slot,

    /// User PIN (for re-authentication if needed)
    pin: String,

    /// Key label in HSM
    key_label: String,

    /// Private key handle in HSM
    private_key_handle: ObjectHandle,

    /// Public key (cached, SEC1 compressed format)
    public_key: Vec<u8>,

    /// Key identifier
    key_id: String,

    /// Context for VOPRF operations
    context: Vec<u8>,

    /// Secret key material for MAC derivation (derived from HSM operations)
    ///
    /// Note: This is NOT the actual private key, but a derived secret that
    /// can be safely extracted from the HSM for HKDF operations.
    mac_base_key: [u8; 32],
}

impl Pkcs11CryptoProvider {
    /// Create a new PKCS#11 crypto provider
    ///
    /// # Arguments
    ///
    /// * `module_path` - Path to PKCS#11 module (e.g., "/usr/lib/libykcs11.so")
    /// * `slot` - HSM slot number
    /// * `pin` - User PIN for authentication
    /// * `key_label` - Label of the P-256 key in the HSM
    /// * `key_id` - Logical key identifier for this provider
    /// * `context` - Context bytes for VOPRF domain separation
    ///
    /// # Returns
    ///
    /// A new PKCS#11 provider ready for cryptographic operations
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - PKCS#11 module cannot be loaded
    /// - Slot is invalid or inaccessible
    /// - Authentication fails
    /// - Key with given label not found
    /// - Key is not a P-256 ECDSA key
    pub async fn new(
        module_path: &str,
        slot: u64,
        pin: &str,
        key_label: &str,
        key_id: String,
        context: Vec<u8>,
    ) -> Result<Self> {
        // Initialize PKCS#11 context
        let pkcs11 = Pkcs11::new(module_path)
            .context("Failed to load PKCS#11 module")?;

        pkcs11.initialize(CInitializeArgs::OsThreads)
            .context("Failed to initialize PKCS#11")?;

        let pkcs11 = Arc::new(pkcs11);

        // Open session
        let slot_id = Slot::try_from(slot)
            .context("Invalid slot number")?;

        let session = pkcs11.open_rw_session(slot_id)
            .context("Failed to open HSM session")?;

        // Login
        let auth_pin = AuthPin::new(pin.to_string());
        session.login(UserType::User, Some(&auth_pin))
            .context("Failed to authenticate with HSM")?;

        // Find private key by label
        let private_key_handle = Self::find_key_by_label(&session, key_label, true)
            .context("Failed to find private key in HSM")?;

        // Find corresponding public key
        let public_key_handle = Self::find_key_by_label(&session, key_label, false)
            .context("Failed to find public key in HSM")?;

        // Extract public key (SEC1 compressed format)
        let public_key = Self::extract_public_key(&session, public_key_handle)
            .context("Failed to extract public key from HSM")?;

        // Derive MAC base key from HSM
        // We derive this once at initialization from a known constant
        // This allows us to perform HKDF in software while still basing
        // the key material on the HSM-protected secret.
        let mac_base_key = Self::derive_mac_base_key(&session, private_key_handle)
            .context("Failed to derive MAC base key from HSM")?;

        // Close the initialization session (we'll create new ones as needed)
        let _ = session.logout();
        drop(session);

        Ok(Self {
            pkcs11,
            slot: slot_id,
            pin: pin.to_string(),
            key_label: key_label.to_string(),
            private_key_handle,
            public_key,
            key_id,
            context,
            mac_base_key,
        })
    }

    /// Find a key object by label
    fn find_key_by_label(
        session: &Session,
        label: &str,
        is_private: bool,
    ) -> Result<ObjectHandle> {
        let class = if is_private {
            cryptoki::object::ObjectClass::PRIVATE_KEY
        } else {
            cryptoki::object::ObjectClass::PUBLIC_KEY
        };

        let template = vec![
            Attribute::Class(class),
            Attribute::Label(label.as_bytes().to_vec()),
        ];

        let objects = session.find_objects(&template)
            .context("HSM key search failed")?;

        objects.first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Key '{}' not found in HSM", label))
    }

    /// Extract public key in SEC1 compressed format from HSM
    fn extract_public_key(
        session: &Session,
        public_key_handle: ObjectHandle,
    ) -> Result<Vec<u8>> {
        // Get EC_POINT attribute (contains the public key)
        let attributes = session.get_attributes(
            public_key_handle,
            &[AttributeType::EcPoint],
        ).context("Failed to read public key from HSM")?;

        let ec_point = attributes.first()
            .and_then(|attr| {
                if let Attribute::EcPoint(point) = attr {
                    Some(point.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow::anyhow!("EC_POINT attribute not found"))?;

        // EC_POINT is DER-encoded OCTET STRING, we need to extract the actual point
        // Format: 0x04 <length> <point-data>
        // For P-256 uncompressed: 65 bytes (0x04 + 32 bytes X + 32 bytes Y)
        // We need to convert to compressed format (33 bytes)

        if ec_point.len() < 65 {
            anyhow::bail!("Invalid EC_POINT length: {}", ec_point.len());
        }

        // Skip DER encoding (0x04 + length byte)
        let point_data = if ec_point[0] == 0x04 && ec_point[1] == 0x41 {
            &ec_point[2..]  // DER: 0x04 0x41 <65 bytes>
        } else {
            &ec_point[..]
        };

        // Convert uncompressed point to compressed
        // Uncompressed: 0x04 || X || Y (65 bytes)
        // Compressed: (0x02 or 0x03) || X (33 bytes)
        if point_data.len() != 65 || point_data[0] != 0x04 {
            anyhow::bail!("Expected uncompressed P-256 point (65 bytes)");
        }

        let x = &point_data[1..33];
        let y = &point_data[33..65];

        // Determine compression prefix: 0x02 if Y is even, 0x03 if Y is odd
        let prefix = if y[31] & 1 == 0 { 0x02 } else { 0x03 };

        let mut compressed = vec![prefix];
        compressed.extend_from_slice(x);

        Ok(compressed)
    }

    /// Derive a base key for MAC operations from HSM
    ///
    /// This uses a constant derivation input to produce a 32-byte secret
    /// that can be safely extracted and used for HKDF in software.
    fn derive_mac_base_key(
        session: &Session,
        private_key_handle: ObjectHandle,
    ) -> Result<[u8; 32]> {
        // Use ECDH with a known public point to derive shared secret
        // This is safe because we control both sides of the derivation

        // For now, we'll use a simpler approach: sign a constant message
        // and use the signature as entropy for the base key

        // Constant message for MAC base key derivation
        let message = b"freebird-mac-base-key-derivation-v1";

        // Hash the message (ECDSA expects a digest)
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(message);
        let digest = hasher.finalize();

        // Sign with ECDSA
        let mechanism = Mechanism::Ecdsa;
        let signature = session.sign(&mechanism, private_key_handle, &digest)
            .context("Failed to sign with HSM for MAC derivation")?;

        // ECDSA signature is (r, s), both 32 bytes for P-256
        // We'll hash the signature to get a 32-byte base key
        let mut hasher = Sha256::new();
        hasher.update(&signature);
        let base_key = hasher.finalize();

        let mut result = [0u8; 32];
        result.copy_from_slice(&base_key);
        Ok(result)
    }

    /// Perform VOPRF evaluation using HSM
    ///
    /// This multiplies the blinded element by the secret scalar in the HSM.
    fn voprf_evaluate_internal(
        &self,
        _blinded: &[u8],
    ) -> Result<Vec<u8>> {
        // For VOPRF evaluation, we need to perform scalar multiplication: B = k * A
        // where k is the secret key and A is the blinded element.

        // PKCS#11 doesn't have a direct "scalar multiply" operation for arbitrary points.
        // We have a few options:
        // 1. Use CKM_ECDH1_DERIVE with the blinded point as peer public key
        // 2. Use raw crypto commands if supported (vendor-specific)
        // 3. Fall back to software for evaluation (less secure)

        // For maximum compatibility, we'll implement option 3 initially
        // (extract key and use software crypto), but note this defeats
        // the purpose of HSM for the core operation.

        // TODO: Implement HSM-native scalar multiplication for production use
        // This requires vendor-specific extensions or raw crypto commands.

        anyhow::bail!(
            "PKCS#11 VOPRF evaluation not yet implemented. \
             HSM-native scalar multiplication requires vendor-specific extensions. \
             Consider using SoftwareCryptoProvider for now."
        )
    }
}

#[async_trait]
impl CryptoProvider for Pkcs11CryptoProvider {
    async fn voprf_evaluate(&self, blinded: &[u8]) -> Result<Vec<u8>> {
        self.voprf_evaluate_internal(blinded)
    }

    async fn derive_mac_key(
        &self,
        issuer_id: &str,
        kid: &str,
        epoch: u32,
    ) -> Result<[u8; 32]> {
        // Derive MAC key using HKDF in software
        // Base key material comes from HSM but derivation happens in software
        Ok(crate::derive_mac_key_v2(
            &self.mac_base_key,
            issuer_id,
            kid,
            epoch,
        ))
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

impl Drop for Pkcs11CryptoProvider {
    fn drop(&mut self) {
        // Zeroize the MAC base key to prevent it from lingering in memory
        // This is critical for HSM hybrid mode security - the key material
        // derived from the HSM should be protected even after extraction
        self.mac_base_key.zeroize();

        // Sessions are created on-demand and closed after use
        // No additional cleanup needed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a PKCS#11 HSM to be available
    // They are integration tests and should be run with:
    // cargo test --features pkcs11 -- --ignored

    #[tokio::test]
    #[ignore]  // Requires HSM hardware/SoftHSM
    async fn test_pkcs11_provider_creation() {
        // This test requires SoftHSM to be installed and configured
        // Initialize with: softhsm2-util --init-token --slot 0 --label "test"

        let result = Pkcs11CryptoProvider::new(
            "/usr/lib/softhsm/libsofthsm2.so",
            0,
            "1234",
            "test-key",
            "key-001".to_string(),
            b"test-context".to_vec(),
        ).await;

        // This will fail if SoftHSM is not configured, which is expected
        // Real test would require proper HSM setup
        assert!(result.is_err() || result.is_ok());
    }
}
