// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Cryptographic primitives for Freebird
//!
//! This module provides high-level APIs for VOPRF operations using the
//! internal P-256 implementation in voprf/.

use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

// Internal VOPRF implementation (was vendor/voprf_p256)
pub mod voprf;
use voprf as v;

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

/// Derive MAC key from server secret key using HKDF
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
}