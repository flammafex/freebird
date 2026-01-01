// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Cryptographic primitives for Freebird
//!
//! This module provides high-level APIs for VOPRF operations using the
//! internal P-256 implementation in voprf/.
//!
//! # Memory Zeroization Security
//!
//! Freebird implements comprehensive memory zeroization to protect cryptographic
//! key material from memory dumps, cold boot attacks, and other extraction methods.
//!
//! ## Automatic Zeroization
//!
//! - **Scalar values (blinding factors, secret keys)**: The `Scalar` type from
//!   RustCrypto's `elliptic-curve` crate implements `DefaultIsZeroes`, ensuring
//!   automatic memory zeroization when dropped. This applies to:
//!   - VOPRF blinding factors (`r` in `BlindState`)
//!   - DLEQ proof ephemeral scalars (`r` in `prove()`)
//!   - Secret keys in VOPRF operations
//!
//! - **Software provider secret keys**: The `SoftwareCryptoProvider` explicitly
//!   zeroizes its secret key in the `Drop` implementation.
//!
//! - **PKCS11 provider MAC keys**: The `Pkcs11CryptoProvider` zeroizes the
//!   `mac_base_key` derived from the HSM in its `Drop` implementation.
//!
//! ## Explicit Zeroization (via Zeroizing wrapper)
//!
//! - **MAC keys**: All MAC keys derived for token authentication are wrapped in
//!   `Zeroizing<[u8; 32]>` to ensure they are erased immediately after use:
//!   - Issuer token MAC computation
//!   - Verifier token MAC verification
//!   - Batch issuance MAC operations
//!
//! ## Non-Secret Values (No Zeroization)
//!
//! - **Elliptic curve points** (`ProjectivePoint`, `AffinePoint`): These are
//!   public values that do not require zeroization.
//! - **Token data**: Tokens are meant to be shared and do not contain secrets.
//! - **Public keys**: Public keys are intentionally shareable.
//!
//! ## Verification
//!
//! To verify zeroization is working correctly, use memory analysis tools or
//! run the zeroization tests in the test suite.

use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

// Internal VOPRF implementation (was vendor/voprf_p256)
pub mod voprf;
use voprf as v;

// Cryptographic provider abstraction for software and HSM backends
pub mod provider;

#[derive(Debug)]
pub enum Error {
    Decode,
    Verify,
    Internal,
}

pub struct Client(v::Client);
pub struct Server(v::Server);
pub struct Verifier(v::Verifier);

pub struct BlindState {
    inner: v::BlindState,
}

/// Deterministic nullifier seed for anti-double-spend.
pub fn nullifier_key(issuer_id: &str, token_output_b64: &str) -> String {
    let mut h = Sha256::new();
    h.update(issuer_id.as_bytes());
    h.update(token_output_b64.as_bytes());
    Base64UrlUnpadded::encode_string(&h.finalize())
}

impl Client {
    pub fn new(ctx: &[u8]) -> Self {
        Self(v::Client::new(ctx))
    }

    /// Blind caller-provided input bytes. Returns (blinded_b64, state).
    pub fn blind(&mut self, input: &[u8]) -> Result<(String, BlindState), Error> {
        let (blinded_raw, st) = self.0.blind(input).map_err(|_| Error::Internal)?;
        Ok((
            Base64UrlUnpadded::encode_string(&blinded_raw),
            BlindState { inner: st },
        ))
    }

    /// Finalize with issuer evaluation token (base64url) and issuer pubkey (SEC1 compressed).
    /// Returns (token_b64, token_output_b64).
    pub fn finalize(
        self,
        state: BlindState,
        evaluation_b64: &str,
        issuer_pubkey_sec1_compressed: &[u8],
    ) -> Result<(String, String), Error> {
        let eval_raw = Base64UrlUnpadded::decode_vec(evaluation_b64).map_err(|_| Error::Decode)?;
        let (token_raw, out_raw) = self
            .0
            .finalize(state.inner, &eval_raw, issuer_pubkey_sec1_compressed)
            .map_err(|_| Error::Verify)?;
        Ok((
            Base64UrlUnpadded::encode_string(&token_raw),
            Base64UrlUnpadded::encode_string(&out_raw),
        ))
    }
}

impl Server {
    pub fn from_secret_key(sk_bytes: [u8; 32], ctx: &[u8]) -> Result<Self, Error> {
        v::Server::from_secret_key(sk_bytes, ctx)
            .map(Self)
            .map_err(|_| Error::Internal)
    }

    pub fn public_key_sec1_compressed(&self) -> [u8; 33] {
        self.0.public_key_sec1_compressed()
    }

    /// Evaluate a single blinded element (base64url), return evaluation/token bytes (base64url).
    pub fn evaluate_with_proof(&self, blinded_b64: &str) -> Result<String, Error> {
        let blinded_raw = Base64UrlUnpadded::decode_vec(blinded_b64).map_err(|_| Error::Decode)?;
        let eval_raw = self.0.evaluate(&blinded_raw).map_err(|_| Error::Internal)?;
        Ok(Base64UrlUnpadded::encode_string(&eval_raw))
    }
}

impl Verifier {
    pub fn new(ctx: &[u8]) -> Self {
        Self(v::Verifier::new(ctx))
    }

    /// Verify opaque token locally and derive token_output used for nullifier.
    pub fn verify(
        &self,
        token_b64: &str,
        issuer_pubkey_sec1_compressed: &[u8],
    ) -> Result<String, Error> {
        let tok_raw = Base64UrlUnpadded::decode_vec(token_b64).map_err(|_| Error::Decode)?;
        let out_raw = self
            .0
            .verify(&tok_raw, issuer_pubkey_sec1_compressed)
            .map_err(|_| Error::Verify)?;
        Ok(Base64UrlUnpadded::encode_string(&out_raw))
    }
}

/// Token MAC constants
pub const TOKEN_MAC_LEN: usize = 32; // HMAC-SHA256 output size

/// Token signature constants (for public-key metadata authentication)
pub const TOKEN_SIGNATURE_LEN: usize = 64; // ECDSA signature (r: 32 bytes, s: 32 bytes)

/// Token format versions
///
/// These distinguish between different token authentication schemes to enable
/// backward-compatible migration from MAC-based to signature-based auth.
pub const TOKEN_FORMAT_V1_MAC: u8 = 0x01;       // VOPRF (131) + MAC (32) = 163 bytes
pub const TOKEN_FORMAT_V2_SIGNATURE: u8 = 0x02; // VOPRF (131) + ECDSA (64) = 195 bytes

/// Total token lengths including authentication
pub const TOKEN_LEN_V1: usize = 131 + TOKEN_MAC_LEN;       // 163 bytes
pub const TOKEN_LEN_V2: usize = 131 + TOKEN_SIGNATURE_LEN; // 195 bytes

/// Compute HMAC-SHA256 over token and metadata to prevent tampering
///
/// MAC = HMAC-SHA256(mac_key, token_bytes || kid || exp || issuer_id)
///
/// # Arguments
/// * `mac_key` - 32-byte MAC key (should be derived from server secret key)
/// * `token_bytes` - The VOPRF token bytes [VERSION||A||B||Proof]
/// * `kid` - Key identifier
/// * `exp` - Expiration timestamp (Unix seconds)
/// * `issuer_id` - Issuer identifier
///
/// # Returns
/// 32-byte HMAC tag
pub fn compute_token_mac(
    mac_key: &[u8; 32],
    token_bytes: &[u8],
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(mac_key)
        .expect("HMAC can take key of any size");

    // MAC over: token || kid || exp || issuer_id
    mac.update(token_bytes);
    mac.update(kid.as_bytes());
    mac.update(&exp.to_be_bytes());
    mac.update(issuer_id.as_bytes());

    mac.finalize().into_bytes().into()
}

/// Verify HMAC-SHA256 over token and metadata (constant-time)
///
/// # Arguments
/// * `mac_key` - 32-byte MAC key
/// * `token_bytes` - The VOPRF token bytes [VERSION||A||B||Proof]
/// * `received_mac` - The MAC tag to verify
/// * `kid` - Key identifier
/// * `exp` - Expiration timestamp
/// * `issuer_id` - Issuer identifier
///
/// # Returns
/// true if MAC is valid, false otherwise (constant-time comparison)
pub fn verify_token_mac(
    mac_key: &[u8; 32],
    token_bytes: &[u8],
    received_mac: &[u8; 32],
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> bool {
    let computed = compute_token_mac(mac_key, token_bytes, kid, exp, issuer_id);

    // Constant-time comparison using subtle
    use subtle::ConstantTimeEq;
    bool::from(computed.ct_eq(received_mac))
}

// ============================================================================
// ECDSA Signature-based Metadata Authentication (Federation-Ready)
// ============================================================================
//
// This provides an alternative to HMAC-based MAC that enables multi-issuer
// federation. Instead of requiring verifiers to possess issuer secret keys,
// verifiers only need public keys to verify token metadata signatures.
//
// This is the cryptographic foundation for Layer 1 of multi-issuer federation.

/// Compute ECDSA signature over token metadata to prevent tampering
///
/// This replaces the HMAC-based MAC scheme with public-key signatures,
/// enabling verifiers to authenticate tokens using only the issuer's public key.
///
/// Signature = ECDSA_Sign(issuer_sk, SHA256(token_bytes || kid || exp || issuer_id))
///
/// # Arguments
/// * `issuer_sk` - Issuer's ECDSA secret key (32 bytes)
/// * `token_bytes` - The VOPRF token bytes [VERSION||A||B||Proof] (131 bytes)
/// * `kid` - Key identifier
/// * `exp` - Expiration timestamp (Unix seconds)
/// * `issuer_id` - Issuer identifier
///
/// # Returns
/// 64-byte ECDSA signature (r || s, each 32 bytes)
///
/// # Security
/// - Uses deterministic ECDSA (RFC 6979) for reproducibility
/// - Signs over SHA256 hash of metadata (standard ECDSA message preparation)
/// - Same P-256 curve as VOPRF operations
pub fn compute_token_signature(
    issuer_sk: &[u8; 32],
    token_bytes: &[u8],
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> Result<[u8; 64], Error> {
    use p256::ecdsa::{SigningKey, signature::Signer};

    // Construct message to sign (same as MAC scheme)
    let mut msg = Vec::new();
    msg.extend_from_slice(token_bytes);
    msg.extend_from_slice(kid.as_bytes());
    msg.extend_from_slice(&exp.to_be_bytes());
    msg.extend_from_slice(issuer_id.as_bytes());

    // Hash the message (ECDSA signs the hash, not raw message)
    let msg_hash = Sha256::digest(&msg);

    // Create signing key from secret key bytes
    let signing_key = SigningKey::from_bytes(issuer_sk.into())
        .map_err(|_| Error::Internal)?;

    // Sign (uses deterministic ECDSA by default in p256 crate)
    let signature: p256::ecdsa::Signature = signing_key.sign(&msg_hash);

    // Convert to raw 64-byte format (r || s)
    Ok(signature.to_bytes().into())
}

/// Verify ECDSA signature over token metadata (constant-time)
///
/// Verifies that the token metadata signature is valid using the issuer's
/// public key. This enables federation because verifiers don't need secret keys.
///
/// # Arguments
/// * `issuer_pubkey` - Issuer's public key (33 bytes, SEC1 compressed)
/// * `token_bytes` - The VOPRF token bytes [VERSION||A||B||Proof] (131 bytes)
/// * `received_signature` - The signature to verify (64 bytes, r || s)
/// * `kid` - Key identifier
/// * `exp` - Expiration timestamp (Unix seconds)
/// * `issuer_id` - Issuer identifier
///
/// # Returns
/// true if signature is valid, false otherwise (constant-time comparison)
pub fn verify_token_signature(
    issuer_pubkey: &[u8],
    token_bytes: &[u8],
    received_signature: &[u8; 64],
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> bool {
    use p256::ecdsa::{VerifyingKey, signature::Verifier};

    // Construct message (same as signing)
    let mut msg = Vec::new();
    msg.extend_from_slice(token_bytes);
    msg.extend_from_slice(kid.as_bytes());
    msg.extend_from_slice(&exp.to_be_bytes());
    msg.extend_from_slice(issuer_id.as_bytes());

    // Hash the message
    let msg_hash = Sha256::digest(&msg);

    // Parse public key (SEC1 compressed format)
    let verifying_key = match VerifyingKey::from_sec1_bytes(issuer_pubkey) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // Parse signature
    let signature = match p256::ecdsa::Signature::from_bytes(received_signature.into()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Verify signature (constant-time in the underlying implementation)
    verifying_key.verify(&msg_hash, &signature).is_ok()
}

/// Derive MAC key from server secret key using HKDF with domain separation
///
/// This ensures the MAC key is cryptographically independent from the
/// VOPRF secret key, following the principle of key separation.
///
/// # Arguments
/// * `server_sk` - Server's secret key (32 bytes)
/// * `issuer_id` - Issuer identifier for domain separation
/// * `key_id` - Key identifier (kid)
/// * `epoch` - Epoch number for key rotation (0 for initial deployment)
///
/// # Returns
/// Derived 32-byte MAC key
///
/// # Security
/// - Uses HKDF-SHA256 for cryptographic key derivation
/// - Domain-separated by issuer_id, key_id, and epoch
/// - Enables forward secrecy through epoch rotation
pub fn derive_mac_key_v2(
    server_sk: &[u8; 32],
    issuer_id: &str,
    key_id: &str,
    epoch: u32,
) -> [u8; 32] {
    use hkdf::Hkdf;

    // Domain-separated info string
    let info = format!("freebird-mac-v1|{}|{}|{}", issuer_id, key_id, epoch);

    let hkdf = Hkdf::<Sha256>::new(
        Some(b"freebird-mac-salt"), // Salt for additional entropy
        server_sk,
    );

    let mut mac_key = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut mac_key)
        .expect("32 bytes is a valid HKDF output length");

    mac_key
}

// ============================================================================
// Generic Message Signatures (for Layer 2 Federation)
// ============================================================================
//
// These functions provide generic ECDSA signing/verification for any message,
// used by Layer 2 federation for vouches, revocations, and other trust signals.

/// Sign an arbitrary message with an issuer's secret key
///
/// This is a generic signing function used for federation messages like
/// vouches and revocations. Uses deterministic ECDSA (RFC 6979).
///
/// # Arguments
/// * `secret_key` - Issuer's 32-byte secret key
/// * `message` - The message bytes to sign
///
/// # Returns
/// 64-byte ECDSA signature (r || s) or error
pub fn sign_message(
    secret_key: &[u8; 32],
    message: &[u8],
) -> Result<[u8; 64], Error> {
    use p256::ecdsa::{SigningKey, signature::Signer};

    // Hash the message first
    let msg_hash = Sha256::digest(message);

    // Create signing key from secret
    let signing_key = SigningKey::from_bytes(secret_key.into())
        .map_err(|_| Error::Internal)?;

    // Sign (deterministic, using RFC 6979)
    let signature: p256::ecdsa::Signature = signing_key.sign(&msg_hash);

    Ok(signature.to_bytes().into())
}

/// Verify an arbitrary message signature with an issuer's public key
///
/// This is a generic verification function used for federation messages.
///
/// # Arguments
/// * `public_key` - Issuer's public key (SEC1 compressed, 33 bytes)
/// * `message` - The message bytes that were signed
/// * `signature` - The 64-byte ECDSA signature to verify
///
/// # Returns
/// true if signature is valid, false otherwise
pub fn verify_message_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8; 64],
) -> bool {
    use p256::ecdsa::{VerifyingKey, signature::Verifier};

    // Hash the message
    let msg_hash = Sha256::digest(message);

    // Parse public key
    let verifying_key = match VerifyingKey::from_sec1_bytes(public_key) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // Parse signature
    let sig = match p256::ecdsa::Signature::from_bytes(signature.into()) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Verify signature
    verifying_key.verify(&msg_hash, &sig).is_ok()
}

/// Derive MAC key from server secret key using HKDF (legacy, simple version)
///
/// This ensures the MAC key is cryptographically independent from the
/// VOPRF secret key, following the principle of key separation.
///
/// # Arguments
/// * `server_sk` - Server's secret key (32 bytes)
/// * `info` - Optional context/domain separation (e.g., "freebird:mac:v1")
///
/// # Returns
/// Derived 32-byte MAC key
pub fn derive_mac_key(server_sk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;

    let hkdf = Hkdf::<Sha256>::new(None, server_sk);
    let mut mac_key = [0u8; 32];
    hkdf.expand(info, &mut mac_key)
        .expect("32 bytes is a valid HKDF output length");
    mac_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end() {
        let ctx = b"freebird-v1";
        let sk = [7u8; 32];

        let server = Server::from_secret_key(sk, ctx).unwrap();
        let pk = server.public_key_sec1_compressed();

        // client blinds input
        let mut client = Client::new(ctx);
        let (blinded_b64, st) = client.blind(b"hello world").unwrap();

        // server evaluates
        let eval_b64 = server.evaluate_with_proof(&blinded_b64).unwrap();

        // client finalizes
        let (token_b64, out_cli_b64) = client.finalize(st, &eval_b64, &pk).unwrap();

        // verifier derives same output
        let verifier = Verifier::new(ctx);
        let out_ver_b64 = verifier.verify(&token_b64, &pk).unwrap();

        assert_eq!(out_cli_b64, out_ver_b64);

        // nullifier determinism
        let n1 = nullifier_key("issuer:freebird:v1", &out_ver_b64);
        let n2 = nullifier_key("issuer:freebird:v1", &out_ver_b64);
        assert_eq!(n1, n2);
        assert!(!n1.is_empty());
    }

    #[test]
    fn test_mac_computation_and_verification() {
        let mac_key = [42u8; 32];
        let token = vec![1, 2, 3, 4, 5];
        let kid = "test-kid-001";
        let exp = 1234567890i64;
        let issuer_id = "test-issuer";

        // Compute MAC
        let mac = compute_token_mac(&mac_key, &token, kid, exp, issuer_id);
        assert_eq!(mac.len(), 32);

        // Verify MAC succeeds
        assert!(verify_token_mac(&mac_key, &token, &mac, kid, exp, issuer_id));

        // Tampered token fails
        let mut bad_token = token.clone();
        bad_token[0] ^= 1;
        assert!(!verify_token_mac(&mac_key, &bad_token, &mac, kid, exp, issuer_id));

        // Tampered kid fails
        assert!(!verify_token_mac(&mac_key, &token, &mac, "wrong-kid", exp, issuer_id));

        // Tampered exp fails
        assert!(!verify_token_mac(&mac_key, &token, &mac, kid, exp + 1, issuer_id));

        // Tampered issuer_id fails
        assert!(!verify_token_mac(&mac_key, &token, &mac, kid, exp, "wrong-issuer"));

        // Wrong MAC fails
        let wrong_mac = [0u8; 32];
        assert!(!verify_token_mac(&mac_key, &token, &wrong_mac, kid, exp, issuer_id));
    }

    #[test]
    fn test_mac_key_derivation() {
        let sk = [7u8; 32];
        let info1 = b"freebird:mac:v1";
        let info2 = b"freebird:mac:v2";

        let key1a = derive_mac_key(&sk, info1);
        let key1b = derive_mac_key(&sk, info1);
        let key2 = derive_mac_key(&sk, info2);

        // Deterministic derivation
        assert_eq!(key1a, key1b);

        // Different contexts produce different keys
        assert_ne!(key1a, key2);

        // Keys should not be all zeros
        assert_ne!(key1a, [0u8; 32]);
    }

    #[test]
    fn test_mac_key_derivation_v2() {
        let sk = [7u8; 32];
        let issuer = "test-issuer";
        let kid = "key-001";

        // Same parameters produce same key (deterministic)
        let key1 = derive_mac_key_v2(&sk, issuer, kid, 0);
        let key2 = derive_mac_key_v2(&sk, issuer, kid, 0);
        assert_eq!(key1, key2);

        // Different epoch produces different key
        let key_epoch1 = derive_mac_key_v2(&sk, issuer, kid, 1);
        assert_ne!(key1, key_epoch1);

        // Different issuer produces different key
        let key_issuer2 = derive_mac_key_v2(&sk, "other-issuer", kid, 0);
        assert_ne!(key1, key_issuer2);

        // Different kid produces different key
        let key_kid2 = derive_mac_key_v2(&sk, issuer, "key-002", 0);
        assert_ne!(key1, key_kid2);

        // Keys should not be all zeros
        assert_ne!(key1, [0u8; 32]);
    }

    #[test]
    fn test_mac_constant_time() {
        // This test doesn't prove constant-time behavior but verifies
        // that the comparison works correctly for all bit patterns
        let mac_key = [42u8; 32];
        let token = vec![1, 2, 3];
        let kid = "kid";
        let exp = 123i64;
        let issuer = "issuer";

        let correct_mac = compute_token_mac(&mac_key, &token, kid, exp, issuer);

        // Test all single-bit flips
        for byte_idx in 0..32 {
            for bit_idx in 0..8 {
                let mut wrong_mac = correct_mac;
                wrong_mac[byte_idx] ^= 1 << bit_idx;
                assert!(!verify_token_mac(&mac_key, &token, &wrong_mac, kid, exp, issuer));
            }
        }
    }

    // ========================================================================
    // Signature-based Authentication Tests
    // ========================================================================

    #[test]
    fn test_signature_computation_and_verification() {
        let sk = [7u8; 32];
        let ctx = b"freebird-v1";

        // Create server to get public key
        let server = Server::from_secret_key(sk, ctx).unwrap();
        let pubkey = server.public_key_sec1_compressed();

        let token = vec![1, 2, 3, 4, 5];
        let kid = "test-kid-001";
        let exp = 1234567890i64;
        let issuer_id = "test-issuer";

        // Compute signature
        let signature = compute_token_signature(&sk, &token, kid, exp, issuer_id).unwrap();
        assert_eq!(signature.len(), 64);

        // Verify signature succeeds
        assert!(verify_token_signature(&pubkey, &token, &signature, kid, exp, issuer_id));

        // Tampered token fails
        let mut bad_token = token.clone();
        bad_token[0] ^= 1;
        assert!(!verify_token_signature(&pubkey, &bad_token, &signature, kid, exp, issuer_id));

        // Tampered kid fails
        assert!(!verify_token_signature(&pubkey, &token, &signature, "wrong-kid", exp, issuer_id));

        // Tampered exp fails
        assert!(!verify_token_signature(&pubkey, &token, &signature, kid, exp + 1, issuer_id));

        // Tampered issuer_id fails
        assert!(!verify_token_signature(&pubkey, &token, &signature, kid, exp, "wrong-issuer"));

        // Wrong signature fails
        let wrong_signature = [0u8; 64];
        assert!(!verify_token_signature(&pubkey, &token, &wrong_signature, kid, exp, issuer_id));

        // Tampered signature fails
        let mut bad_signature = signature;
        bad_signature[0] ^= 1;
        assert!(!verify_token_signature(&pubkey, &token, &bad_signature, kid, exp, issuer_id));
    }

    #[test]
    fn test_signature_determinism() {
        let sk = [7u8; 32];
        let ctx = b"freebird-v1";
        let server = Server::from_secret_key(sk, ctx).unwrap();
        let pubkey = server.public_key_sec1_compressed();

        let token = vec![1, 2, 3, 4, 5];
        let kid = "test-kid-001";
        let exp = 1234567890i64;
        let issuer_id = "test-issuer";

        // Signatures should be deterministic (RFC 6979)
        let sig1 = compute_token_signature(&sk, &token, kid, exp, issuer_id).unwrap();
        let sig2 = compute_token_signature(&sk, &token, kid, exp, issuer_id).unwrap();
        assert_eq!(sig1, sig2);

        // Both should verify
        assert!(verify_token_signature(&pubkey, &token, &sig1, kid, exp, issuer_id));
        assert!(verify_token_signature(&pubkey, &token, &sig2, kid, exp, issuer_id));
    }

    #[test]
    fn test_signature_different_keys() {
        let sk1 = [7u8; 32];
        let sk2 = [8u8; 32];
        let ctx = b"freebird-v1";

        let server1 = Server::from_secret_key(sk1, ctx).unwrap();
        let server2 = Server::from_secret_key(sk2, ctx).unwrap();
        let pubkey1 = server1.public_key_sec1_compressed();
        let pubkey2 = server2.public_key_sec1_compressed();

        let token = vec![1, 2, 3, 4, 5];
        let kid = "test-kid-001";
        let exp = 1234567890i64;
        let issuer_id = "test-issuer";

        // Sign with key 1
        let sig1 = compute_token_signature(&sk1, &token, kid, exp, issuer_id).unwrap();

        // Verify with key 1's public key succeeds
        assert!(verify_token_signature(&pubkey1, &token, &sig1, kid, exp, issuer_id));

        // Verify with key 2's public key fails
        assert!(!verify_token_signature(&pubkey2, &token, &sig1, kid, exp, issuer_id));
    }

    #[test]
    fn test_signature_invalid_pubkey() {
        let sk = [7u8; 32];
        let token = vec![1, 2, 3, 4, 5];
        let kid = "test-kid-001";
        let exp = 1234567890i64;
        let issuer_id = "test-issuer";

        let signature = compute_token_signature(&sk, &token, kid, exp, issuer_id).unwrap();

        // Invalid public key (not a valid SEC1 compressed point)
        let bad_pubkey = [0xFFu8; 33];
        assert!(!verify_token_signature(&bad_pubkey, &token, &signature, kid, exp, issuer_id));

        // Wrong length public key
        let short_pubkey = [0x02u8; 32];
        assert!(!verify_token_signature(&short_pubkey, &token, &signature, kid, exp, issuer_id));
    }

    #[test]
    fn test_signature_with_real_voprf_token() {
        // End-to-end test with actual VOPRF token
        let sk = [7u8; 32];
        let ctx = b"freebird-v1";

        let server = Server::from_secret_key(sk, ctx).unwrap();
        let pk = server.public_key_sec1_compressed();

        // Generate a real VOPRF token
        let mut client = Client::new(ctx);
        let (blinded_b64, st) = client.blind(b"hello world").unwrap();
        let eval_b64 = server.evaluate_with_proof(&blinded_b64).unwrap();
        let (token_b64, _) = client.finalize(st, &eval_b64, &pk).unwrap();

        // Decode token to bytes
        let token_bytes = base64ct::Base64UrlUnpadded::decode_vec(&token_b64).unwrap();
        assert_eq!(token_bytes.len(), 131); // VOPRF token is 131 bytes

        let kid = "test-kid-001";
        let exp = 1234567890i64;
        let issuer_id = "issuer:freebird:v1";

        // Sign the real token
        let signature = compute_token_signature(&sk, &token_bytes, kid, exp, issuer_id).unwrap();

        // Verify signature
        assert!(verify_token_signature(&pk, &token_bytes, &signature, kid, exp, issuer_id));

        // Tampered token should fail
        let mut bad_token = token_bytes.clone();
        bad_token[0] ^= 1;
        assert!(!verify_token_signature(&pk, &bad_token, &signature, kid, exp, issuer_id));
    }

    // Generic message signing tests (for Layer 2 Federation)

    #[test]
    fn test_generic_message_signing() {
        let sk = [42u8; 32];
        let ctx = b"freebird-v1";
        let server = Server::from_secret_key(sk, ctx).unwrap();
        let pubkey = server.public_key_sec1_compressed();

        let message = b"Hello, Federation!";

        // Sign message
        let signature = sign_message(&sk, message).unwrap();
        assert_eq!(signature.len(), 64);

        // Verify signature
        assert!(verify_message_signature(&pubkey, message, &signature));

        // Wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(!verify_message_signature(&pubkey, wrong_message, &signature));

        // Wrong public key should fail
        let sk2 = [43u8; 32];
        let server2 = Server::from_secret_key(sk2, ctx).unwrap();
        let pubkey2 = server2.public_key_sec1_compressed();
        assert!(!verify_message_signature(&pubkey2, message, &signature));
    }

    #[test]
    fn test_generic_message_determinism() {
        let sk = [42u8; 32];
        let message = b"Deterministic test message";

        // Same inputs should produce same signature (RFC 6979)
        let sig1 = sign_message(&sk, message).unwrap();
        let sig2 = sign_message(&sk, message).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_generic_message_different_lengths() {
        let sk = [42u8; 32];
        let ctx = b"freebird-v1";
        let server = Server::from_secret_key(sk, ctx).unwrap();
        let pubkey = server.public_key_sec1_compressed();

        // Test with messages of different lengths
        let short_msg = b"Hi";
        let long_msg = b"This is a much longer message that tests whether the signing function handles variable-length inputs correctly.";

        let sig_short = sign_message(&sk, short_msg).unwrap();
        let sig_long = sign_message(&sk, long_msg).unwrap();

        assert!(verify_message_signature(&pubkey, short_msg, &sig_short));
        assert!(verify_message_signature(&pubkey, long_msg, &sig_long));

        // Cross-verification should fail
        assert!(!verify_message_signature(&pubkey, short_msg, &sig_long));
        assert!(!verify_message_signature(&pubkey, long_msg, &sig_short));
    }

    #[test]
    fn test_generic_message_empty() {
        let sk = [42u8; 32];
        let ctx = b"freebird-v1";
        let server = Server::from_secret_key(sk, ctx).unwrap();
        let pubkey = server.public_key_sec1_compressed();

        // Empty message should still work
        let empty_msg = b"";
        let sig = sign_message(&sk, empty_msg).unwrap();
        assert!(verify_message_signature(&pubkey, empty_msg, &sig));
    }

    #[test]
    fn test_generic_message_invalid_signature_bytes() {
        let sk = [42u8; 32];
        let ctx = b"freebird-v1";
        let server = Server::from_secret_key(sk, ctx).unwrap();
        let pubkey = server.public_key_sec1_compressed();

        let message = b"Test message";

        // Invalid signature (all zeros)
        let bad_sig = [0u8; 64];
        assert!(!verify_message_signature(&pubkey, message, &bad_sig));

        // Invalid signature (all 0xFF)
        let bad_sig2 = [0xFFu8; 64];
        assert!(!verify_message_signature(&pubkey, message, &bad_sig2));
    }
}