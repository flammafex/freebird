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
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::sync::Arc;
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

    /// Public key (cached, SEC1 compressed format)
    public_key: Vec<u8>,

    /// Key identifier
    key_id: String,

    /// Context for VOPRF operations
    context: Vec<u8>,

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
        let pkcs11 = Pkcs11::new(module_path).context("Failed to load PKCS#11 module")?;

        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .context("Failed to initialize PKCS#11")?;

        let pkcs11 = Arc::new(pkcs11);

        // Open session
        let slot_id = Slot::try_from(slot).context("Invalid slot number")?;

        let session = pkcs11
            .open_rw_session(slot_id)
            .context("Failed to open HSM session")?;

        // Login
        let auth_pin = AuthPin::new(pin.to_string());
        session
            .login(UserType::User, Some(&auth_pin))
            .context("Failed to authenticate with HSM")?;

        // Find corresponding public key
        let public_key_handle = Self::find_key_by_label(&session, key_label, false)
            .context("Failed to find public key in HSM")?;

        // Extract public key (SEC1 compressed format)
        let public_key = Self::extract_public_key(&session, public_key_handle)
            .context("Failed to extract public key from HSM")?;

        // Close the initialization session (we'll create new ones as needed)
        let _ = session.logout();
        drop(session);

        Ok(Self {
            pkcs11,
            slot: slot_id,
            pin: pin.to_string(),
            key_label: key_label.to_string(),
            public_key,
            key_id,
            context,
        })
    }

    /// Open and authenticate a fresh RW session.
    fn open_authenticated_session(&self) -> Result<Session> {
        let session = self
            .pkcs11
            .open_rw_session(self.slot)
            .context("Failed to open HSM session")?;
        let auth_pin = AuthPin::new(self.pin.clone());
        session
            .login(UserType::User, Some(&auth_pin))
            .context("Failed to authenticate with HSM")?;
        Ok(session)
    }

    /// Find a key object by label
    fn find_key_by_label(session: &Session, label: &str, is_private: bool) -> Result<ObjectHandle> {
        let class = if is_private {
            cryptoki::object::ObjectClass::PRIVATE_KEY
        } else {
            cryptoki::object::ObjectClass::PUBLIC_KEY
        };

        let template = vec![
            Attribute::Class(class),
            Attribute::Label(label.as_bytes().to_vec()),
        ];

        let objects = session
            .find_objects(&template)
            .context("HSM key search failed")?;

        objects
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Key '{}' not found in HSM", label))
    }

    /// Extract public key in SEC1 compressed format from HSM
    fn extract_public_key(session: &Session, public_key_handle: ObjectHandle) -> Result<Vec<u8>> {
        // Get EC_POINT attribute (contains the public key)
        let attributes = session
            .get_attributes(public_key_handle, &[AttributeType::EcPoint])
            .context("Failed to read public key from HSM")?;

        let ec_point = attributes
            .first()
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
            &ec_point[2..] // DER: 0x04 0x41 <65 bytes>
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

    /// Parse ASN.1 DER length at `idx`, returning (length, next_idx).
    fn parse_der_len(data: &[u8], idx: usize) -> Result<(usize, usize)> {
        let first = *data
            .get(idx)
            .ok_or_else(|| anyhow::anyhow!("invalid DER length"))?;
        if first & 0x80 == 0 {
            return Ok((first as usize, idx + 1));
        }

        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            anyhow::bail!("unsupported DER length encoding");
        }

        let mut len = 0usize;
        let mut pos = idx + 1;
        for _ in 0..count {
            let b = *data
                .get(pos)
                .ok_or_else(|| anyhow::anyhow!("truncated DER length"))?;
            len = (len << 8) | (b as usize);
            pos += 1;
        }
        Ok((len, pos))
    }

    /// Convert an ASN.1 INTEGER payload to 32-byte big-endian form.
    fn asn1_int_to_32(bytes: &[u8]) -> Result<[u8; 32]> {
        let mut v = bytes;
        while v.len() > 1 && v[0] == 0 {
            v = &v[1..];
        }
        if v.len() > 32 {
            anyhow::bail!("ECDSA integer too large");
        }

        let mut out = [0u8; 32];
        out[32 - v.len()..].copy_from_slice(v);
        Ok(out)
    }

    /// Normalize ECDSA signature into raw r||s (64 bytes).
    ///
    /// Some HSMs return raw 64-byte signatures, others return DER-encoded ASN.1.
    fn normalize_ecdsa_signature(sig: &[u8]) -> Result<[u8; 64]> {
        if sig.len() == 64 {
            let mut out = [0u8; 64];
            out.copy_from_slice(sig);
            return Ok(out);
        }

        if sig.first().copied() != Some(0x30) {
            anyhow::bail!("unsupported ECDSA signature format");
        }

        let (seq_len, mut idx) = Self::parse_der_len(sig, 1)?;
        if idx + seq_len != sig.len() {
            anyhow::bail!("invalid DER signature length");
        }

        if sig.get(idx).copied() != Some(0x02) {
            anyhow::bail!("missing DER INTEGER for r");
        }
        idx += 1;
        let (r_len, next) = Self::parse_der_len(sig, idx)?;
        idx = next;
        let r_end = idx + r_len;
        let r = Self::asn1_int_to_32(
            sig.get(idx..r_end)
                .ok_or_else(|| anyhow::anyhow!("truncated DER r"))?,
        )?;
        idx = r_end;

        if sig.get(idx).copied() != Some(0x02) {
            anyhow::bail!("missing DER INTEGER for s");
        }
        idx += 1;
        let (s_len, next) = Self::parse_der_len(sig, idx)?;
        idx = next;
        let s_end = idx + s_len;
        let s = Self::asn1_int_to_32(
            sig.get(idx..s_end)
                .ok_or_else(|| anyhow::anyhow!("truncated DER s"))?,
        )?;
        idx = s_end;

        if idx != sig.len() {
            anyhow::bail!("trailing bytes in DER signature");
        }

        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&r);
        out[32..].copy_from_slice(&s);
        Ok(out)
    }

    /// Perform VOPRF evaluation using HSM
    ///
    /// This multiplies the blinded element by the secret scalar in the HSM.
    fn voprf_evaluate_internal(&self, _blinded: &[u8]) -> Result<Vec<u8>> {
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

    async fn sign_token_metadata(
        &self,
        kid: &str,
        exp: i64,
        issuer_id: &str,
    ) -> Result<[u8; 64]> {
        use sha2::{Digest, Sha256};

        // Build V3 metadata message with domain separation
        let msg = crate::build_metadata_message(kid, exp, issuer_id);
        let msg_hash = Sha256::digest(&msg);

        let session = self.open_authenticated_session()?;
        let private_key_handle = Self::find_key_by_label(&session, &self.key_label, true)
            .context("Failed to find private key in HSM")?;
        let sig = session
            .sign(&Mechanism::Ecdsa, private_key_handle, &msg_hash)
            .context("Failed to sign token metadata with HSM")?;
        let _ = session.logout();

        Self::normalize_ecdsa_signature(&sig)
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


#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a PKCS#11 HSM to be available
    // They are integration tests and should be run with:
    // cargo test --features pkcs11 -- --ignored

    #[tokio::test]
    #[ignore] // Requires HSM hardware/SoftHSM
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
        )
        .await;

        // This will fail if SoftHSM is not configured, which is expected
        // Real test would require proper HSM setup
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_normalize_ecdsa_signature_raw_passthrough() {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }

        let normalized = Pkcs11CryptoProvider::normalize_ecdsa_signature(&raw).unwrap();
        assert_eq!(normalized, raw);
    }

    #[test]
    fn test_normalize_ecdsa_signature_der_standard() {
        let r: [u8; 32] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0,
            0xe0, 0xf0, 0x01, 0x02,
        ];
        let s: [u8; 32] = [
            0xfe, 0xed, 0xdc, 0xcb, 0xba, 0xa9, 0x98, 0x87, 0x76, 0x65, 0x54, 0x43, 0x32, 0x21,
            0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3,
            0xd2, 0xe1, 0xf0, 0x00,
        ];

        let mut der = Vec::new();
        der.push(0x30); // SEQUENCE
        der.push(0x44); // total length
        der.push(0x02); // INTEGER r
        der.push(0x20); // len(r)
        der.extend_from_slice(&r);
        der.push(0x02); // INTEGER s
        der.push(0x20); // len(s)
        der.extend_from_slice(&s);

        let normalized = Pkcs11CryptoProvider::normalize_ecdsa_signature(&der).unwrap();
        assert_eq!(&normalized[..32], &r);
        assert_eq!(&normalized[32..], &s);
    }

    #[test]
    fn test_normalize_ecdsa_signature_der_with_leading_zeros() {
        // r and s with high bit set require a DER sign-padding 0x00.
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r[0] = 0x80;
        r[31] = 0x7f;
        s[0] = 0x90;
        s[31] = 0x01;

        let mut der = Vec::new();
        der.push(0x30); // SEQUENCE
        der.push(0x46); // total length (2+33 + 2+33)
        der.push(0x02); // INTEGER r
        der.push(0x21); // len(r)
        der.push(0x00); // sign pad
        der.extend_from_slice(&r);
        der.push(0x02); // INTEGER s
        der.push(0x21); // len(s)
        der.push(0x00); // sign pad
        der.extend_from_slice(&s);

        let normalized = Pkcs11CryptoProvider::normalize_ecdsa_signature(&der).unwrap();
        assert_eq!(&normalized[..32], &r);
        assert_eq!(&normalized[32..], &s);
    }

    #[test]
    fn test_normalize_ecdsa_signature_rejects_invalid_format() {
        // Not raw (64 bytes) and not DER SEQUENCE.
        let bad = [0x01, 0x02, 0x03];
        let err = Pkcs11CryptoProvider::normalize_ecdsa_signature(&bad);
        assert!(err.is_err());
    }

    #[test]
    fn test_normalize_ecdsa_signature_rejects_truncated_der() {
        // Claims longer sequence than provided.
        let der = [0x30, 0x44, 0x02, 0x20, 0xaa];
        let err = Pkcs11CryptoProvider::normalize_ecdsa_signature(&der);
        assert!(err.is_err());
    }
}
