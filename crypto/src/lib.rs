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
use subtle::ConstantTimeEq;

// Internal VOPRF implementation (was vendor/voprf_p256)
pub mod voprf;
use voprf as v;

// Native amount-bearing V7 body.
pub mod public_bearer_v7;
pub use public_bearer_v7::{
    blind_v7, build_native_bearer_v7_token, finalize_v7, parse_native_bearer_v7_token,
    serialize_native_bearer_v7_token, v7_artifact_digest, validate_public_bearer_spki_v7,
    verify_native_bearer_v7_token, verify_v7, NativeBearerV7Token, PublicBearerV7Body,
    V7ApplicationMessage, V7BlindMessage, V7BlindSignature, V7BlindState, V7BodyPolicy,
    V7KeyIdentity, V7MessageRandomizer, V7PublicKeyBinding, V7Signature, V7TokenKeyId,
    V7_ARTIFACT_DOMAIN, V7_ENVELOPE_VERSION, V7_RESERVED_ENVELOPE_VERSION,
    V7_RETIRED_ENVELOPE_VERSION, V7_RFC9474_VARIANT,
};

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

    /// Verify a VOPRF token's DLEQ proof against the issuer public key.
    ///
    /// Returns `Ok(())` if the proof is valid; `Err` if the token is malformed or the
    /// proof fails. Does NOT return a PRF output — use `Client::finalize()` for that,
    /// as computing the correct output requires the client's blinding factor.
    pub fn verify(&self, token_b64: &str, issuer_pubkey: &[u8]) -> Result<(), Error> {
        let token_bytes = Base64UrlUnpadded::decode_vec(token_b64)
            .map_err(|_| Error::InvalidInput("bad base64 token".into()))?;
        self.0
            .verify(&token_bytes, issuer_pubkey)
            .map_err(|_| Error::Verify)
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
        let output = self
            .0
            .finalize(st.inner, &eval_bytes, &pk_bytes)
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

    /// Evaluate a private-verification token input without blinding.
    ///
    /// Verifiers use this with the issuer-approved VOPRF secret to recompute a
    /// V4 token authenticator locally at redemption time.
    pub fn evaluate_unblinded(&self, input: &[u8]) -> Result<[u8; 32], Error> {
        self.0
            .evaluate_unblinded(input)
            .map_err(|_| Error::Internal)
    }
}

// V4 private-verification redemption token constants.
pub const VOPRF_CONTEXT_V4: &[u8] = b"freebird:v4";
pub const REDEMPTION_TOKEN_VERSION_V4: u8 = 0x04;
pub const PRIVATE_TOKEN_NONCE_LEN: usize = 32;
pub const PRIVATE_TOKEN_SCOPE_DIGEST_LEN: usize = 32;
pub const PRIVATE_TOKEN_AUTHENTICATOR_LEN: usize = 32;
const REDEMPTION_TOKEN_MIN_LEN: usize = 1
    + PRIVATE_TOKEN_NONCE_LEN
    + PRIVATE_TOKEN_SCOPE_DIGEST_LEN
    + 1
    + 1
    + 1
    + 1
    + PRIVATE_TOKEN_AUTHENTICATOR_LEN;
const REDEMPTION_TOKEN_MAX_LEN: usize = 512;

/// V4 redemption token: the wire format clients send to verifiers.
///
/// Wire format:
/// `[VERSION(1) | nonce(32) | scope_digest(32) | kid_len(1) | kid(N) | issuer_id_len(1) | issuer_id(M) | authenticator(32)]`
///
/// The authenticator is the unblinded VOPRF output over
/// `build_private_token_input(issuer_id, kid, nonce, scope_digest)`.
/// Verifiers recompute it privately with a VOPRF secret authorized by the
/// issuer-trust policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedemptionToken {
    pub nonce: [u8; PRIVATE_TOKEN_NONCE_LEN],
    pub scope_digest: [u8; PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
    pub kid: String,
    pub issuer_id: String,
    pub authenticator: [u8; PRIVATE_TOKEN_AUTHENTICATOR_LEN],
}

/// Build the verifier/audience scope digest that a V4 token is bound to.
///
/// The verifier publishes `(verifier_id, audience)` and clients include the
/// resulting digest in the blinded token input before issuance. Verifiers reject
/// tokens whose digest does not match their configured scope.
pub fn build_scope_digest(
    verifier_id: &str,
    audience: &str,
) -> Result<[u8; PRIVATE_TOKEN_SCOPE_DIGEST_LEN], Error> {
    validate_token_field("verifier_id", verifier_id)?;
    validate_token_field("audience", audience)?;

    let mut h = Sha256::new();
    h.update(b"freebird:scope:v4");
    h.update([verifier_id.len() as u8]);
    h.update(verifier_id.as_bytes());
    h.update([audience.len() as u8]);
    h.update(audience.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; PRIVATE_TOKEN_SCOPE_DIGEST_LEN];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn validate_token_field(name: &str, value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > 255 {
        return Err(Error::InvalidInput(format!("{name} must be 1-255 bytes")));
    }
    Ok(())
}

/// Build the public input that is blindly issued and privately re-evaluated.
pub fn build_private_token_input(
    issuer_id: &str,
    kid: &str,
    nonce: &[u8; PRIVATE_TOKEN_NONCE_LEN],
    scope_digest: &[u8; PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
) -> Result<Vec<u8>, Error> {
    validate_token_field("kid", kid)?;
    validate_token_field("issuer_id", issuer_id)?;

    let mut input = Vec::with_capacity(
        b"freebird:private-token-input:v4".len()
            + 1
            + issuer_id.len()
            + 1
            + kid.len()
            + PRIVATE_TOKEN_NONCE_LEN
            + PRIVATE_TOKEN_SCOPE_DIGEST_LEN,
    );
    input.extend_from_slice(b"freebird:private-token-input:v4");
    input.push(issuer_id.len() as u8);
    input.extend_from_slice(issuer_id.as_bytes());
    input.push(kid.len() as u8);
    input.extend_from_slice(kid.as_bytes());
    input.extend_from_slice(nonce);
    input.extend_from_slice(scope_digest);
    Ok(input)
}

/// Serialize a `RedemptionToken` into V4 wire format bytes.
pub fn build_redemption_token(token: &RedemptionToken) -> Result<Vec<u8>, Error> {
    validate_token_field("kid", &token.kid)?;
    validate_token_field("issuer_id", &token.issuer_id)?;

    let total_len = 1
        + PRIVATE_TOKEN_NONCE_LEN
        + PRIVATE_TOKEN_SCOPE_DIGEST_LEN
        + 1
        + token.kid.len()
        + 1
        + token.issuer_id.len()
        + PRIVATE_TOKEN_AUTHENTICATOR_LEN;
    let mut buf = Vec::with_capacity(total_len);
    buf.push(REDEMPTION_TOKEN_VERSION_V4);
    buf.extend_from_slice(&token.nonce);
    buf.extend_from_slice(&token.scope_digest);
    buf.push(token.kid.len() as u8);
    buf.extend_from_slice(token.kid.as_bytes());
    buf.push(token.issuer_id.len() as u8);
    buf.extend_from_slice(token.issuer_id.as_bytes());
    buf.extend_from_slice(&token.authenticator);
    Ok(buf)
}

/// Parse V4 wire format bytes into a `RedemptionToken`.
pub fn parse_redemption_token(bytes: &[u8]) -> Result<RedemptionToken, Error> {
    if bytes.len() < REDEMPTION_TOKEN_MIN_LEN {
        return Err(Error::InvalidInput("token too short".to_string()));
    }
    if bytes.len() > REDEMPTION_TOKEN_MAX_LEN {
        return Err(Error::InvalidInput("token too large".to_string()));
    }
    if bytes[0] != REDEMPTION_TOKEN_VERSION_V4 {
        return Err(Error::InvalidInput("unsupported token version".to_string()));
    }
    let mut pos = 1;
    let nonce: [u8; PRIVATE_TOKEN_NONCE_LEN] = bytes[pos..pos + PRIVATE_TOKEN_NONCE_LEN]
        .try_into()
        .map_err(|_| Error::InvalidInput("bad nonce".to_string()))?;
    pos += PRIVATE_TOKEN_NONCE_LEN;
    let scope_digest: [u8; PRIVATE_TOKEN_SCOPE_DIGEST_LEN] = bytes
        [pos..pos + PRIVATE_TOKEN_SCOPE_DIGEST_LEN]
        .try_into()
        .map_err(|_| Error::InvalidInput("bad scope_digest".to_string()))?;
    pos += PRIVATE_TOKEN_SCOPE_DIGEST_LEN;
    let kid_len = bytes[pos] as usize;
    pos += 1;
    if kid_len == 0 || pos + kid_len > bytes.len() {
        return Err(Error::InvalidInput("bad kid_len".to_string()));
    }
    let kid = String::from_utf8(bytes[pos..pos + kid_len].to_vec())
        .map_err(|_| Error::InvalidInput("kid not utf8".to_string()))?;
    pos += kid_len;
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
    if bytes.len() - pos != PRIVATE_TOKEN_AUTHENTICATOR_LEN {
        return Err(Error::InvalidInput("bad authenticator length".to_string()));
    }
    let authenticator: [u8; PRIVATE_TOKEN_AUTHENTICATOR_LEN] = bytes
        [pos..pos + PRIVATE_TOKEN_AUTHENTICATOR_LEN]
        .try_into()
        .map_err(|_| Error::InvalidInput("bad authenticator".to_string()))?;
    Ok(RedemptionToken {
        nonce,
        scope_digest,
        kid,
        issuer_id,
        authenticator,
    })
}

/// Recompute and verify a V4 token authenticator using a private VOPRF key.
pub fn verify_private_token_authenticator(
    issuer_sk: [u8; 32],
    ctx: &[u8],
    token: &RedemptionToken,
) -> Result<(), Error> {
    let input = build_private_token_input(
        &token.issuer_id,
        &token.kid,
        &token.nonce,
        &token.scope_digest,
    )?;
    let server = Server::from_secret_key(issuer_sk, ctx)?;
    let expected = server.evaluate_unblinded(&input)?;
    if bool::from(expected.ct_eq(&token.authenticator)) {
        Ok(())
    } else {
        Err(Error::Verify)
    }
}

/// Deterministic replay key for V4 private-verification tokens.
///
/// The verifier scope is included explicitly so shared replay stores cannot
/// correlate unrelated verifier audiences that happen to process structurally
/// similar tokens.
pub fn nullifier_key_v4(
    token: &RedemptionToken,
    verifier_id: &str,
    audience: &str,
) -> Result<String, Error> {
    validate_token_field("verifier_id", verifier_id)?;
    validate_token_field("audience", audience)?;

    let mut h = Sha256::new();
    h.update(b"freebird:nullifier:v4");
    h.update([verifier_id.len() as u8]);
    h.update(verifier_id.as_bytes());
    h.update([audience.len() as u8]);
    h.update(audience.as_bytes());
    h.update([token.issuer_id.len() as u8]);
    h.update(token.issuer_id.as_bytes());
    h.update([token.kid.len() as u8]);
    h.update(token.kid.as_bytes());
    h.update(token.nonce);
    h.update(token.scope_digest);
    h.update(token.authenticator);
    Ok(Base64UrlUnpadded::encode_string(&h.finalize()))
}

// ============================================================================
// Generic Message Signatures
// ============================================================================

/// Sign an arbitrary message with an issuer's secret key
///
/// This is a generic signing function for deterministic ECDSA (RFC 6979).
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
        let ctx = VOPRF_CONTEXT_V4;
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
        let n1 = nullifier_key("issuer:freebird:v4", &out_cli_b64);
        let n2 = nullifier_key("issuer:freebird:v4", &out_cli_b64);
        assert_eq!(n1, n2);
        assert!(!n1.is_empty());
    }

    // Generic message signing tests

    #[test]
    fn test_generic_message_signing() {
        let sk = [42u8; 32];
        let ctx = VOPRF_CONTEXT_V4;
        let server = Server::from_secret_key(sk, ctx).unwrap();
        let pubkey = server.public_key_sec1_compressed();

        let message = b"Hello, signed message!";

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
        let ctx = VOPRF_CONTEXT_V4;
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
        let ctx = VOPRF_CONTEXT_V4;
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
        let ctx = VOPRF_CONTEXT_V4;
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
    // V4 Redemption Token Tests
    // ========================================================================

    #[test]
    fn v4_wire_scope_and_nullifier_fixture() {
        // Provenance: independently assembled from the documented V4 wire layout
        // and SHA-256 domain separators. Do not regenerate these expectations with
        // the functions exercised below.
        const RAW: &[u8] = b"\x04\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x60\x8e\x97\xcd\x19\x7b\x62\x0c\xf3\x19\xe1\xa3\xd0\x78\x93\xe4\x07\x40\xb4\x63\x89\x6b\x2c\xca\xc9\xfc\x56\x3f\x8d\xc2\x45\xb1\x0e\x6b\x69\x64\x2d\x66\x69\x78\x74\x75\x72\x65\x2d\x30\x31\x11\x69\x73\x73\x75\x65\x72\x3a\x66\x69\x78\x74\x75\x72\x65\x3a\x76\x34\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f";
        const B64: &str = "BAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fYI6XzRl7YgzzGeGj0HiT5AdAtGOJayzKyfxWP43CRbEOa2lkLWZpeHR1cmUtMDERaXNzdWVyOmZpeHR1cmU6djSAgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2enw";
        const SCOPE: [u8; 32] = [
            0x60, 0x8e, 0x97, 0xcd, 0x19, 0x7b, 0x62, 0x0c, 0xf3, 0x19, 0xe1, 0xa3, 0xd0, 0x78,
            0x93, 0xe4, 0x07, 0x40, 0xb4, 0x63, 0x89, 0x6b, 0x2c, 0xca, 0xc9, 0xfc, 0x56, 0x3f,
            0x8d, 0xc2, 0x45, 0xb1,
        ];
        const NULLIFIER: &str = "FQr18I1vyV8goQLiPEZdxbKYPGNby28kDkvRx__UGoM";

        assert_eq!(
            build_scope_digest("verifier:fixture", "api/v1").unwrap(),
            SCOPE
        );
        assert_eq!(Base64UrlUnpadded::encode_string(RAW), B64);

        let parsed = parse_redemption_token(RAW).unwrap();
        assert_eq!(parsed.nonce, core::array::from_fn(|i| i as u8));
        assert_eq!(parsed.scope_digest, SCOPE);
        assert_eq!(parsed.kid, "kid-fixture-01");
        assert_eq!(parsed.issuer_id, "issuer:fixture:v4");
        assert_eq!(
            parsed.authenticator,
            core::array::from_fn(|i| 0x80 + i as u8)
        );
        assert_eq!(build_redemption_token(&parsed).unwrap(), RAW);
        assert_eq!(
            nullifier_key_v4(&parsed, "verifier:fixture", "api/v1").unwrap(),
            NULLIFIER
        );
    }

    #[test]
    fn test_v4_redemption_token_rejects_bad_version() {
        let token = RedemptionToken {
            nonce: [0xAA; 32],
            scope_digest: [0xCC; 32],
            kid: "k".to_string(),
            issuer_id: "i".to_string(),
            authenticator: [0xBB; 32],
        };
        let mut bytes = build_redemption_token(&token).unwrap();
        bytes[0] = 0x01; // wrong version
        assert!(parse_redemption_token(&bytes).is_err());
    }

    #[test]
    fn test_v4_redemption_token_rejects_truncated() {
        let bytes = vec![REDEMPTION_TOKEN_VERSION_V4; 50];
        assert!(parse_redemption_token(&bytes).is_err());
    }

    #[test]
    fn test_build_token_rejects_empty_kid() {
        let token = RedemptionToken {
            kid: "".to_string(),
            nonce: [0u8; 32],
            scope_digest: [0u8; 32],
            issuer_id: "x".to_string(),
            authenticator: [0u8; 32],
        };
        assert!(build_redemption_token(&token).is_err());
    }

    #[test]
    fn test_build_token_rejects_256_byte_kid() {
        let token = RedemptionToken {
            kid: "k".repeat(256),
            nonce: [0u8; 32],
            scope_digest: [0u8; 32],
            issuer_id: "x".to_string(),
            authenticator: [0u8; 32],
        };
        assert!(build_redemption_token(&token).is_err());
    }

    #[test]
    fn test_build_token_rejects_empty_issuer_id() {
        let token = RedemptionToken {
            kid: "k".to_string(),
            nonce: [0u8; 32],
            scope_digest: [0u8; 32],
            issuer_id: "".to_string(),
            authenticator: [0u8; 32],
        };
        assert!(build_redemption_token(&token).is_err());
    }

    #[test]
    fn test_build_token_rejects_256_byte_issuer_id() {
        let token = RedemptionToken {
            kid: "k".to_string(),
            nonce: [0u8; 32],
            scope_digest: [0u8; 32],
            issuer_id: "i".repeat(256),
            authenticator: [0u8; 32],
        };
        assert!(build_redemption_token(&token).is_err());
    }

    #[test]
    fn test_parse_token_rejects_too_large() {
        let bytes = vec![REDEMPTION_TOKEN_VERSION_V4; 513];
        assert!(parse_redemption_token(&bytes).is_err());
    }

    #[test]
    fn test_nullifier_different_issuers() {
        let n1 = nullifier_key("issuer-a", "out");
        let n2 = nullifier_key("issuer-b", "out");
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_nullifier_different_outputs() {
        let n1 = nullifier_key("issuer", "out1");
        let n2 = nullifier_key("issuer", "out2");
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_scope_digest_differs_by_verifier_and_audience() {
        let a = build_scope_digest("verifier-a", "api").unwrap();
        let b = build_scope_digest("verifier-b", "api").unwrap();
        let c = build_scope_digest("verifier-a", "admin").unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_nullifier_v4_differs_by_verifier_scope() {
        let token = RedemptionToken {
            nonce: [0xAA; 32],
            scope_digest: build_scope_digest("verifier-a", "api").unwrap(),
            kid: "kid".to_string(),
            issuer_id: "issuer".to_string(),
            authenticator: [0xBB; 32],
        };
        let n1 = nullifier_key_v4(&token, "verifier-a", "api").unwrap();
        let n2 = nullifier_key_v4(&token, "verifier-b", "api").unwrap();
        let n3 = nullifier_key_v4(&token, "verifier-a", "admin").unwrap();
        assert_ne!(n1, n2);
        assert_ne!(n1, n3);
    }

    #[test]
    fn test_v4_full_roundtrip_with_private_authenticator() {
        let sk = [7u8; 32];
        let ctx = VOPRF_CONTEXT_V4;

        let kid = "roundtrip-kid";
        let issuer_id = "roundtrip-issuer";
        let nonce = [0xCC; 32];
        let scope_digest = build_scope_digest("verifier:roundtrip", "default").unwrap();

        let input = build_private_token_input(issuer_id, kid, &nonce, &scope_digest).unwrap();
        let server = Server::from_secret_key(sk, ctx).unwrap();
        let authenticator = server.evaluate_unblinded(&input).unwrap();

        // Build the token
        let token = RedemptionToken {
            nonce,
            scope_digest,
            kid: kid.to_string(),
            issuer_id: issuer_id.to_string(),
            authenticator,
        };
        let bytes = build_redemption_token(&token).unwrap();

        // Parse it back
        let parsed = parse_redemption_token(&bytes).unwrap();
        assert_eq!(parsed.kid, kid);
        assert_eq!(parsed.issuer_id, issuer_id);
        assert_eq!(parsed.nonce, nonce);

        verify_private_token_authenticator(sk, ctx, &parsed)
            .expect("parsed token authenticator should verify against issuer secret");
    }
}
