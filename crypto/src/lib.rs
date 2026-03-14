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
use sha2::{Digest, Sha256};

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
    InvalidInput(String),
}

pub struct Client(v::Client);
pub struct Server(v::Server);
pub struct Verifier(v::Verifier);

pub struct BlindState {
    inner: v::BlindState,
}

impl Verifier {
    pub fn new(ctx: &[u8]) -> Self {
        Self(v::Verifier::new(ctx))
    }
}

/// Deterministic nullifier seed for anti-double-spend.
pub fn nullifier_key(issuer_id: &str, token_output_b64: &str) -> String {
    let mut h = Sha256::new();
    h.update(issuer_id.as_bytes());
    h.update(b"|"); // domain separator to prevent preimage confusion
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

    /// Finalize with issuer evaluation token (base64url) and issuer pubkey (base64url SEC1 compressed).
    /// Returns the unblinded PRF output as base64url.
    pub fn finalize(
        self,
        st: BlindState,
        evaluation_b64: &str,
        issuer_pubkey_b64: &str,
    ) -> Result<String, Error> {
        let eval_bytes = Base64UrlUnpadded::decode_vec(evaluation_b64)
            .map_err(|_| Error::InvalidInput("bad base64 evaluation".into()))?;
        let pk_bytes = Base64UrlUnpadded::decode_vec(issuer_pubkey_b64)
            .map_err(|_| Error::InvalidInput("bad base64 pubkey".into()))?;
        let output = self.0.finalize(st.inner, &eval_bytes, &pk_bytes)
            .map_err(|_| Error::Verify)?;
        Ok(Base64UrlUnpadded::encode_string(&output))
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


/// Token signature constants (for public-key metadata authentication)
pub const TOKEN_SIGNATURE_LEN: usize = 64; // ECDSA signature (r: 32 bytes, s: 32 bytes)

// V3 redemption token constants
const REDEMPTION_TOKEN_VERSION_V3: u8 = 0x03;
const REDEMPTION_TOKEN_MIN_LEN: usize = 1 + 32 + 1 + 1 + 8 + 1 + 1 + 64; // 109
const REDEMPTION_TOKEN_MAX_LEN: usize = 512;

/// Total token length for V2 format (kept for backward compat references)
pub const TOKEN_LEN_V2: usize = 131 + TOKEN_SIGNATURE_LEN; // 195 bytes

/// V3 redemption token: the wire format clients send to verifiers.
///
/// Wire format: `[VERSION(1) | output(32) | kid_len(1) | kid(N) | exp(8) | issuer_id_len(1) | issuer_id(M) | ECDSA_sig(64)]`
pub struct RedemptionToken {
    pub output: [u8; 32],
    pub kid: String,
    pub exp: i64,
    pub issuer_id: String,
    pub sig: [u8; 64],
}

/// Serialize a `RedemptionToken` into V3 wire format bytes.
pub fn build_redemption_token(token: &RedemptionToken) -> Result<Vec<u8>, Error> {
    if token.kid.is_empty() || token.kid.len() > 255 {
        return Err(Error::InvalidInput("kid must be 1-255 bytes".to_string()));
    }
    if token.issuer_id.is_empty() || token.issuer_id.len() > 255 {
        return Err(Error::InvalidInput("issuer_id must be 1-255 bytes".to_string()));
    }
    let total_len = 1 + 32 + 1 + token.kid.len() + 8 + 1 + token.issuer_id.len() + 64;
    let mut buf = Vec::with_capacity(total_len);
    buf.push(REDEMPTION_TOKEN_VERSION_V3);
    buf.extend_from_slice(&token.output);
    buf.push(token.kid.len() as u8);
    buf.extend_from_slice(token.kid.as_bytes());
    buf.extend_from_slice(&token.exp.to_be_bytes());
    buf.push(token.issuer_id.len() as u8);
    buf.extend_from_slice(token.issuer_id.as_bytes());
    buf.extend_from_slice(&token.sig);
    Ok(buf)
}

/// Parse V3 wire format bytes into a `RedemptionToken`.
pub fn parse_redemption_token(bytes: &[u8]) -> Result<RedemptionToken, Error> {
    if bytes.len() < REDEMPTION_TOKEN_MIN_LEN {
        return Err(Error::InvalidInput("token too short".to_string()));
    }
    if bytes.len() > REDEMPTION_TOKEN_MAX_LEN {
        return Err(Error::InvalidInput("token too large".to_string()));
    }
    if bytes[0] != REDEMPTION_TOKEN_VERSION_V3 {
        return Err(Error::InvalidInput("unsupported token version".to_string()));
    }
    let mut pos = 1;
    let output: [u8; 32] = bytes[pos..pos + 32].try_into()
        .map_err(|_| Error::InvalidInput("bad output".to_string()))?;
    pos += 32;
    let kid_len = bytes[pos] as usize;
    pos += 1;
    if kid_len == 0 || pos + kid_len > bytes.len() {
        return Err(Error::InvalidInput("bad kid_len".to_string()));
    }
    let kid = String::from_utf8(bytes[pos..pos + kid_len].to_vec())
        .map_err(|_| Error::InvalidInput("kid not utf8".to_string()))?;
    pos += kid_len;
    if pos + 8 > bytes.len() {
        return Err(Error::InvalidInput("truncated exp".to_string()));
    }
    let exp = i64::from_be_bytes(bytes[pos..pos + 8].try_into()
        .map_err(|_| Error::InvalidInput("bad exp".to_string()))?);
    pos += 8;
    if pos >= bytes.len() {
        return Err(Error::InvalidInput("truncated issuer_id_len".to_string()));
    }
    let issuer_id_len = bytes[pos] as usize;
    pos += 1;
    if issuer_id_len == 0 || pos + issuer_id_len > bytes.len() {
        return Err(Error::InvalidInput("bad issuer_id_len".to_string()));
    }
    let issuer_id = String::from_utf8(bytes[pos..pos + issuer_id_len].to_vec())
        .map_err(|_| Error::InvalidInput("issuer_id not utf8".to_string()))?;
    pos += issuer_id_len;
    if bytes.len() - pos != 64 {
        return Err(Error::InvalidInput("bad sig length".to_string()));
    }
    let sig: [u8; 64] = bytes[pos..pos + 64].try_into()
        .map_err(|_| Error::InvalidInput("bad sig".to_string()))?;
    Ok(RedemptionToken { output, kid, exp, issuer_id, sig })
}

// ============================================================================
// ECDSA Signature-based Metadata Authentication (V3)
// ============================================================================
//
// V3 signatures cover metadata only (kid, exp, issuer_id) with domain
// separation and length-prefixed fields. The PRF output is self-authenticating
// via the discrete log assumption — the issuer cannot sign it because it
// doesn't know the blinding factor `r`.

/// Build the canonical metadata message for V3 ECDSA signing.
///
/// Format: `"freebird:token-metadata:v3" || kid_len(1) || kid || exp(8, i64 BE) || issuer_id_len(1) || issuer_id`
pub(crate) fn build_metadata_message(kid: &str, exp: i64, issuer_id: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"freebird:token-metadata:v3");
    msg.push(kid.len() as u8);
    msg.extend_from_slice(kid.as_bytes());
    msg.extend_from_slice(&exp.to_be_bytes());
    msg.push(issuer_id.len() as u8);
    msg.extend_from_slice(issuer_id.as_bytes());
    msg
}

/// Compute ECDSA signature over token metadata using V3 message format.
///
/// Signs metadata only (kid, exp, issuer_id) with domain separation.
/// Enables multi-issuer federation: verifiers only need public keys.
///
/// Signature = ECDSA_Sign(issuer_sk, SHA256(build_metadata_message(kid, exp, issuer_id)))
///
/// # Arguments
/// * `issuer_sk` - Issuer's ECDSA secret key (32 bytes)
/// * `kid` - Key identifier
/// * `exp` - Expiration timestamp (Unix seconds)
/// * `issuer_id` - Issuer identifier
///
/// # Returns
/// 64-byte ECDSA signature (r || s, each 32 bytes)
///
/// # Security
/// - Uses deterministic ECDSA (RFC 6979) for reproducibility
/// - Domain-separated message with length-prefixed fields
/// - Same P-256 curve as VOPRF operations
pub fn compute_token_signature(
    issuer_sk: &[u8; 32],
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> Result<[u8; 64], Error> {
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

    // Build the canonical V3 metadata message
    let msg = build_metadata_message(kid, exp, issuer_id);

    // Hash the message (we use sign_prehash to avoid double-hashing)
    let msg_hash = Sha256::digest(&msg);

    // Create signing key from secret key bytes
    let signing_key = SigningKey::from_bytes(issuer_sk.into()).map_err(|_| Error::Internal)?;

    // Sign the prehashed message (deterministic ECDSA, RFC 6979)
    let signature: p256::ecdsa::Signature = signing_key
        .sign_prehash(&msg_hash)
        .map_err(|_| Error::Internal)?;

    // Convert to raw 64-byte format (r || s)
    Ok(signature.to_bytes().into())
}

/// Verify ECDSA signature over token metadata using V3 message format.
///
/// Verifies that the token metadata signature is valid using the issuer's
/// public key. This enables federation because verifiers don't need secret keys.
///
/// # Arguments
/// * `issuer_pubkey` - Issuer's public key (33 bytes, SEC1 compressed)
/// * `received_signature` - The signature to verify (64 bytes, r || s)
/// * `kid` - Key identifier
/// * `exp` - Expiration timestamp (Unix seconds)
/// * `issuer_id` - Issuer identifier
///
/// # Returns
/// true if signature is valid, false otherwise
pub fn verify_token_signature(
    issuer_pubkey: &[u8],
    received_signature: &[u8; 64],
    kid: &str,
    exp: i64,
    issuer_id: &str,
) -> bool {
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};

    // Build the canonical V3 metadata message
    let msg = build_metadata_message(kid, exp, issuer_id);

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

    // Verify prehashed signature (constant-time in the underlying implementation)
    verifying_key.verify_prehash(&msg_hash, &signature).is_ok()
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
pub fn sign_message(secret_key: &[u8; 32], message: &[u8]) -> Result<[u8; 64], Error> {
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

    // Hash the message first
    let msg_hash = Sha256::digest(message);

    // Create signing key from secret
    let signing_key = SigningKey::from_bytes(secret_key.into()).map_err(|_| Error::Internal)?;

    // Sign prehashed message (deterministic, using RFC 6979)
    let signature: p256::ecdsa::Signature = signing_key
        .sign_prehash(&msg_hash)
        .map_err(|_| Error::Internal)?;

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
pub fn verify_message_signature(public_key: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};

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

    // Verify prehashed signature
    verifying_key.verify_prehash(&msg_hash, &sig).is_ok()
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
        let pk_b64 = Base64UrlUnpadded::encode_string(&pk);

        // client blinds input
        let mut client = Client::new(ctx);
        let (blinded_b64, st) = client.blind(b"hello world").unwrap();

        // server evaluates
        let eval_b64 = server.evaluate_with_proof(&blinded_b64).unwrap();

        // client finalizes — now returns unblinded PRF output only
        let out_cli_b64 = client.finalize(st, &eval_b64, &pk_b64).unwrap();

        // Verify output decodes to exactly 32 bytes (PRF output length)
        let out_raw = Base64UrlUnpadded::decode_vec(&out_cli_b64).unwrap();
        assert_eq!(out_raw.len(), 32);

        // nullifier determinism
        let n1 = nullifier_key("issuer:freebird:v1", &out_cli_b64);
        let n2 = nullifier_key("issuer:freebird:v1", &out_cli_b64);
        assert_eq!(n1, n2);
        assert!(!n1.is_empty());
    }

    // ========================================================================
    // V3 Metadata Signature Tests
    // ========================================================================

    #[test]
    fn test_v3_metadata_signature_roundtrip() {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let sk = SigningKey::random(&mut OsRng);
        let sk_bytes: [u8; 32] = sk.to_bytes().into();
        let pk_bytes = sk.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();

        let kid = "test-key-01";
        let exp = 1700000000i64;
        let issuer_id = "issuer-abc";

        let sig = compute_token_signature(&sk_bytes, kid, exp, issuer_id).unwrap();
        assert!(verify_token_signature(&pk_bytes, &sig, kid, exp, issuer_id));
    }

    #[test]
    fn test_v3_metadata_signature_rejects_wrong_kid() {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let sk = SigningKey::random(&mut OsRng);
        let sk_bytes: [u8; 32] = sk.to_bytes().into();
        let pk_bytes = sk.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();

        let sig = compute_token_signature(&sk_bytes, "key-1", 100i64, "issuer").unwrap();
        assert!(!verify_token_signature(&pk_bytes, &sig, "key-2", 100i64, "issuer"));
    }

    #[test]
    fn test_v3_metadata_signature_rejects_wrong_exp() {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let sk = SigningKey::random(&mut OsRng);
        let sk_bytes: [u8; 32] = sk.to_bytes().into();
        let pk_bytes = sk.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();

        let sig = compute_token_signature(&sk_bytes, "key-1", 100i64, "issuer").unwrap();
        assert!(!verify_token_signature(&pk_bytes, &sig, "key-1", 101i64, "issuer"));
    }

    #[test]
    fn test_v3_metadata_signature_rejects_wrong_issuer() {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let sk = SigningKey::random(&mut OsRng);
        let sk_bytes: [u8; 32] = sk.to_bytes().into();
        let pk_bytes = sk.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();

        let sig = compute_token_signature(&sk_bytes, "key-1", 100i64, "issuer-a").unwrap();
        assert!(!verify_token_signature(&pk_bytes, &sig, "key-1", 100i64, "issuer-b"));
    }

    #[test]
    fn test_signature_computation_and_verification() {
        let sk = [7u8; 32];
        let ctx = b"freebird-v1";

        // Create server to get public key
        let server = Server::from_secret_key(sk, ctx).unwrap();
        let pubkey = server.public_key_sec1_compressed();

        let kid = "test-kid-001";
        let exp = 1234567890i64;
        let issuer_id = "test-issuer";

        // Compute signature
        let signature = compute_token_signature(&sk, kid, exp, issuer_id).unwrap();
        assert_eq!(signature.len(), 64);

        // Verify signature succeeds
        assert!(verify_token_signature(
            &pubkey, &signature, kid, exp, issuer_id
        ));

        // Tampered kid fails
        assert!(!verify_token_signature(
            &pubkey,
            &signature,
            "wrong-kid",
            exp,
            issuer_id
        ));

        // Tampered exp fails
        assert!(!verify_token_signature(
            &pubkey,
            &signature,
            kid,
            exp + 1,
            issuer_id
        ));

        // Tampered issuer_id fails
        assert!(!verify_token_signature(
            &pubkey,
            &signature,
            kid,
            exp,
            "wrong-issuer"
        ));

        // Wrong signature fails
        let wrong_signature = [0u8; 64];
        assert!(!verify_token_signature(
            &pubkey,
            &wrong_signature,
            kid,
            exp,
            issuer_id
        ));

        // Tampered signature fails
        let mut bad_signature = signature;
        bad_signature[0] ^= 1;
        assert!(!verify_token_signature(
            &pubkey,
            &bad_signature,
            kid,
            exp,
            issuer_id
        ));
    }

    #[test]
    fn test_signature_determinism() {
        let sk = [7u8; 32];
        let ctx = b"freebird-v1";
        let server = Server::from_secret_key(sk, ctx).unwrap();
        let pubkey = server.public_key_sec1_compressed();

        let kid = "test-kid-001";
        let exp = 1234567890i64;
        let issuer_id = "test-issuer";

        // Signatures should be deterministic (RFC 6979)
        let sig1 = compute_token_signature(&sk, kid, exp, issuer_id).unwrap();
        let sig2 = compute_token_signature(&sk, kid, exp, issuer_id).unwrap();
        assert_eq!(sig1, sig2);

        // Both should verify
        assert!(verify_token_signature(
            &pubkey, &sig1, kid, exp, issuer_id
        ));
        assert!(verify_token_signature(
            &pubkey, &sig2, kid, exp, issuer_id
        ));
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

        let kid = "test-kid-001";
        let exp = 1234567890i64;
        let issuer_id = "test-issuer";

        // Sign with key 1
        let sig1 = compute_token_signature(&sk1, kid, exp, issuer_id).unwrap();

        // Verify with key 1's public key succeeds
        assert!(verify_token_signature(
            &pubkey1, &sig1, kid, exp, issuer_id
        ));

        // Verify with key 2's public key fails
        assert!(!verify_token_signature(
            &pubkey2, &sig1, kid, exp, issuer_id
        ));
    }

    #[test]
    fn test_signature_invalid_pubkey() {
        let sk = [7u8; 32];
        let kid = "test-kid-001";
        let exp = 1234567890i64;
        let issuer_id = "test-issuer";

        let signature = compute_token_signature(&sk, kid, exp, issuer_id).unwrap();

        // Invalid public key (not a valid SEC1 compressed point)
        let bad_pubkey = [0xFFu8; 33];
        assert!(!verify_token_signature(
            &bad_pubkey,
            &signature,
            kid,
            exp,
            issuer_id
        ));

        // Wrong length public key
        let short_pubkey = [0x02u8; 32];
        assert!(!verify_token_signature(
            &short_pubkey,
            &signature,
            kid,
            exp,
            issuer_id
        ));
    }

    #[test]
    fn test_build_metadata_message_format() {
        let kid = "k1";
        let exp = 0x0102030405060708i64;
        let issuer_id = "iss";

        let msg = build_metadata_message(kid, exp, issuer_id);

        // Verify the message format
        let mut expected = Vec::new();
        expected.extend_from_slice(b"freebird:token-metadata:v3");
        expected.push(2); // kid_len
        expected.extend_from_slice(b"k1");
        expected.extend_from_slice(&exp.to_be_bytes());
        expected.push(3); // issuer_id_len
        expected.extend_from_slice(b"iss");

        assert_eq!(msg, expected);
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
        assert!(!verify_message_signature(
            &pubkey,
            wrong_message,
            &signature
        ));

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

    // ========================================================================
    // V3 Redemption Token Tests
    // ========================================================================

    #[test]
    fn test_v3_redemption_token_roundtrip() {
        let token = RedemptionToken {
            output: [0xAA; 32],
            kid: "test-key-01".to_string(),
            exp: 1700000000i64,
            issuer_id: "issuer-abc".to_string(),
            sig: [0xBB; 64],
        };
        let bytes = build_redemption_token(&token).unwrap();
        assert_eq!(bytes[0], 0x03); // version byte
        let parsed = parse_redemption_token(&bytes).unwrap();
        assert_eq!(parsed.output, token.output);
        assert_eq!(parsed.kid, token.kid);
        assert_eq!(parsed.exp, token.exp);
        assert_eq!(parsed.issuer_id, token.issuer_id);
        assert_eq!(parsed.sig, token.sig);
    }

    #[test]
    fn test_v3_redemption_token_rejects_bad_version() {
        let token = RedemptionToken {
            output: [0xAA; 32],
            kid: "k".to_string(),
            exp: 1i64,
            issuer_id: "i".to_string(),
            sig: [0xBB; 64],
        };
        let mut bytes = build_redemption_token(&token).unwrap();
        bytes[0] = 0x01; // wrong version
        assert!(parse_redemption_token(&bytes).is_err());
    }

    #[test]
    fn test_v3_redemption_token_rejects_truncated() {
        let bytes = vec![0x03; 50]; // too short (min 109)
        assert!(parse_redemption_token(&bytes).is_err());
    }
}
