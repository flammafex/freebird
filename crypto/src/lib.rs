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
use blind_rsa_signatures::{PublicKeySha384PSSDeterministic, Signature as BlindRsaSignature};
use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;

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
pub const REDEMPTION_TOKEN_VERSION_V5: u8 = 0x05;
pub const PRIVATE_TOKEN_NONCE_LEN: usize = 32;
pub const PRIVATE_TOKEN_SCOPE_DIGEST_LEN: usize = 32;
pub const PRIVATE_TOKEN_AUTHENTICATOR_LEN: usize = 32;
pub const PUBLIC_BEARER_NONCE_LEN: usize = 32;
pub const PUBLIC_BEARER_TOKEN_KEY_ID_LEN: usize = 32;
pub const PUBLIC_BEARER_MESSAGE_DIGEST_LEN: usize = 48;
pub const PUBLIC_BEARER_MAX_SIGNATURE_LEN: usize = 512;
pub const PUBLIC_BEARER_TOKEN_TYPE: &str = "public_bearer_pass";
pub const PUBLIC_BEARER_RFC9474_VARIANT: &str = "RSABSSA-SHA384-PSS-Deterministic";
pub const PUBLIC_BEARER_SPEND_POLICY_SINGLE_USE: &str = "single_use";
const REDEMPTION_TOKEN_MIN_LEN: usize = 1
    + PRIVATE_TOKEN_NONCE_LEN
    + PRIVATE_TOKEN_SCOPE_DIGEST_LEN
    + 1
    + 1
    + 1
    + 1
    + PRIVATE_TOKEN_AUTHENTICATOR_LEN;
const REDEMPTION_TOKEN_MAX_LEN: usize = 512;
const PUBLIC_BEARER_MIN_LEN: usize =
    1 + PUBLIC_BEARER_NONCE_LEN + PUBLIC_BEARER_TOKEN_KEY_ID_LEN + 1 + 1 + 2 + 1;
const PUBLIC_BEARER_MAX_LEN: usize = 1
    + PUBLIC_BEARER_NONCE_LEN
    + PUBLIC_BEARER_TOKEN_KEY_ID_LEN
    + 1
    + 255
    + 2
    + PUBLIC_BEARER_MAX_SIGNATURE_LEN;

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

/// V5 public bearer pass.
///
/// Wire format:
/// `[VERSION=0x05][nonce(32)][token_key_id(32)][issuer_id_len(1)|issuer_id][sig_len(2,BE)|signature]`
///
/// The signature is a finalized RFC 9474 blind RSA signature over
/// `build_public_bearer_message_from_parts(nonce, token_key_id, issuer_id)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicBearerPass {
    pub nonce: [u8; PUBLIC_BEARER_NONCE_LEN],
    pub token_key_id: [u8; PUBLIC_BEARER_TOKEN_KEY_ID_LEN],
    pub issuer_id: String,
    pub signature: Vec<u8>,
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

/// Compute the V5 public token key identifier from the RFC 9474 SPKI bytes.
pub fn token_key_id_from_spki(spki: &[u8]) -> [u8; PUBLIC_BEARER_TOKEN_KEY_ID_LEN] {
    let digest = Sha256::digest(spki);
    let mut out = [0u8; PUBLIC_BEARER_TOKEN_KEY_ID_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Strict lowercase hex encoding for V5 token key identifiers.
pub fn encode_token_key_id_hex(token_key_id: &[u8; PUBLIC_BEARER_TOKEN_KEY_ID_LEN]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(PUBLIC_BEARER_TOKEN_KEY_ID_LEN * 2);
    for byte in token_key_id {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decode a strict 64-character lowercase hex V5 token key identifier.
pub fn decode_token_key_id_hex(value: &str) -> Result<[u8; PUBLIC_BEARER_TOKEN_KEY_ID_LEN], Error> {
    if value.len() != PUBLIC_BEARER_TOKEN_KEY_ID_LEN * 2 {
        return Err(Error::InvalidInput(
            "token_key_id must be 64 lowercase hex characters".to_string(),
        ));
    }

    let mut out = [0u8; PUBLIC_BEARER_TOKEN_KEY_ID_LEN];
    let bytes = value.as_bytes();
    for (idx, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = strict_lower_hex_nibble(chunk[0])
            .ok_or_else(|| Error::InvalidInput("token_key_id must be lowercase hex".to_string()))?;
        let lo = strict_lower_hex_nibble(chunk[1])
            .ok_or_else(|| Error::InvalidInput("token_key_id must be lowercase hex".to_string()))?;
        out[idx] = (hi << 4) | lo;
    }
    Ok(out)
}

fn strict_lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Build the canonical 48-byte V5 message digest that clients blind-sign.
///
/// The blind-rsa-signatures crate hashes this digest again as its message
/// input while applying RFC 9474 PSS. That matches Freebird's V5 design: this
/// function is the protocol message, not hand-rolled padding.
pub fn build_public_bearer_message_from_parts(
    nonce: &[u8; PUBLIC_BEARER_NONCE_LEN],
    token_key_id: &[u8; PUBLIC_BEARER_TOKEN_KEY_ID_LEN],
    issuer_id: &str,
) -> Result<[u8; PUBLIC_BEARER_MESSAGE_DIGEST_LEN], Error> {
    validate_token_field("issuer_id", issuer_id)?;

    let mut h = Sha384::new();
    h.update(b"freebird:public-bearer-pass:v5");
    h.update([0x00]);
    h.update([REDEMPTION_TOKEN_VERSION_V5]);
    h.update(nonce);
    h.update(token_key_id);
    h.update([issuer_id.len() as u8]);
    h.update(issuer_id.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; PUBLIC_BEARER_MESSAGE_DIGEST_LEN];
    out.copy_from_slice(&digest);
    Ok(out)
}

pub fn build_public_bearer_message(
    token: &PublicBearerPass,
) -> Result<[u8; PUBLIC_BEARER_MESSAGE_DIGEST_LEN], Error> {
    build_public_bearer_message_from_parts(&token.nonce, &token.token_key_id, &token.issuer_id)
}

/// Serialize a V5 public bearer pass into wire format bytes.
pub fn build_public_bearer_pass(token: &PublicBearerPass) -> Result<Vec<u8>, Error> {
    validate_token_field("issuer_id", &token.issuer_id)?;
    if token.signature.is_empty() || token.signature.len() > PUBLIC_BEARER_MAX_SIGNATURE_LEN {
        return Err(Error::InvalidInput("bad signature length".to_string()));
    }

    let sig_len = u16::try_from(token.signature.len())
        .map_err(|_| Error::InvalidInput("signature too large".to_string()))?;
    let total_len = 1
        + PUBLIC_BEARER_NONCE_LEN
        + PUBLIC_BEARER_TOKEN_KEY_ID_LEN
        + 1
        + token.issuer_id.len()
        + 2
        + token.signature.len();
    let mut buf = Vec::with_capacity(total_len);
    buf.push(REDEMPTION_TOKEN_VERSION_V5);
    buf.extend_from_slice(&token.nonce);
    buf.extend_from_slice(&token.token_key_id);
    buf.push(token.issuer_id.len() as u8);
    buf.extend_from_slice(token.issuer_id.as_bytes());
    buf.extend_from_slice(&sig_len.to_be_bytes());
    buf.extend_from_slice(&token.signature);
    Ok(buf)
}

/// Parse V5 wire format bytes into a `PublicBearerPass`.
pub fn parse_public_bearer_pass(bytes: &[u8]) -> Result<PublicBearerPass, Error> {
    if bytes.len() < PUBLIC_BEARER_MIN_LEN {
        return Err(Error::InvalidInput("token too short".to_string()));
    }
    if bytes.len() > PUBLIC_BEARER_MAX_LEN {
        return Err(Error::InvalidInput("token too large".to_string()));
    }
    if bytes[0] != REDEMPTION_TOKEN_VERSION_V5 {
        return Err(Error::InvalidInput("unsupported token version".to_string()));
    }

    let mut pos = 1;
    let nonce: [u8; PUBLIC_BEARER_NONCE_LEN] = bytes[pos..pos + PUBLIC_BEARER_NONCE_LEN]
        .try_into()
        .map_err(|_| Error::InvalidInput("bad nonce".to_string()))?;
    pos += PUBLIC_BEARER_NONCE_LEN;

    let token_key_id: [u8; PUBLIC_BEARER_TOKEN_KEY_ID_LEN] = bytes
        [pos..pos + PUBLIC_BEARER_TOKEN_KEY_ID_LEN]
        .try_into()
        .map_err(|_| Error::InvalidInput("bad token_key_id".to_string()))?;
    pos += PUBLIC_BEARER_TOKEN_KEY_ID_LEN;

    let issuer_id_len = bytes[pos] as usize;
    pos += 1;
    if issuer_id_len == 0 || pos + issuer_id_len > bytes.len() {
        return Err(Error::InvalidInput("bad issuer_id_len".to_string()));
    }
    let issuer_id = String::from_utf8(bytes[pos..pos + issuer_id_len].to_vec())
        .map_err(|_| Error::InvalidInput("issuer_id not utf8".to_string()))?;
    pos += issuer_id_len;

    if pos + 2 > bytes.len() {
        return Err(Error::InvalidInput(
            "truncated signature length".to_string(),
        ));
    }
    let sig_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;
    if sig_len == 0 || sig_len > PUBLIC_BEARER_MAX_SIGNATURE_LEN || pos + sig_len != bytes.len() {
        return Err(Error::InvalidInput("bad signature length".to_string()));
    }

    Ok(PublicBearerPass {
        nonce,
        token_key_id,
        issuer_id,
        signature: bytes[pos..pos + sig_len].to_vec(),
    })
}

/// Verify a V5 public bearer pass signature with its RFC 9474 SPKI public key.
pub fn verify_public_bearer_signature(
    pubkey_spki: &[u8],
    token: &PublicBearerPass,
) -> Result<(), Error> {
    if token_key_id_from_spki(pubkey_spki) != token.token_key_id {
        return Err(Error::Verify);
    }

    let pk = PublicKeySha384PSSDeterministic::from_spki(pubkey_spki)
        .map_err(|_| Error::InvalidInput("invalid public token key".to_string()))?;
    let msg = build_public_bearer_message(token)?;
    let sig = BlindRsaSignature(token.signature.clone());
    pk.verify(&sig, None, msg).map_err(|_| Error::Verify)
}

pub fn validate_public_bearer_spki(pubkey_spki: &[u8]) -> Result<(), Error> {
    PublicKeySha384PSSDeterministic::from_spki(pubkey_spki)
        .map(|_| ())
        .map_err(|_| Error::InvalidInput("invalid public token key".to_string()))
}

/// Deterministic replay key for V5 public bearer passes.
pub fn nullifier_key_v5(token: &PublicBearerPass) -> Result<String, Error> {
    validate_token_field("issuer_id", &token.issuer_id)?;

    let mut h = Sha256::new();
    h.update(b"freebird:nullifier:v5");
    h.update(token.nonce);
    h.update(token.token_key_id);
    h.update([token.issuer_id.len() as u8]);
    h.update(token.issuer_id.as_bytes());
    h.update(&token.signature);
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
    fn test_v4_redemption_token_roundtrip() {
        let token = RedemptionToken {
            nonce: [0xAA; 32],
            scope_digest: [0xCC; 32],
            kid: "test-key-01".to_string(),
            issuer_id: "issuer-abc".to_string(),
            authenticator: [0xBB; 32],
        };
        let bytes = build_redemption_token(&token).unwrap();
        assert_eq!(bytes[0], REDEMPTION_TOKEN_VERSION_V4); // version byte
        let parsed = parse_redemption_token(&bytes).unwrap();
        assert_eq!(parsed.nonce, token.nonce);
        assert_eq!(parsed.scope_digest, token.scope_digest);
        assert_eq!(parsed.kid, token.kid);
        assert_eq!(parsed.issuer_id, token.issuer_id);
        assert_eq!(parsed.authenticator, token.authenticator);
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
    fn test_v5_public_bearer_pass_roundtrip_and_verify() {
        let mut rng = blind_rsa_signatures::DefaultRng;
        let key_pair =
            blind_rsa_signatures::KeyPairSha384PSSDeterministic::generate(&mut rng, 2048).unwrap();
        let spki = key_pair.pk.to_spki().unwrap();
        let token_key_id = token_key_id_from_spki(&spki);
        let nonce = [0x42; PUBLIC_BEARER_NONCE_LEN];
        let issuer_id = "issuer:test:v5";
        let msg = build_public_bearer_message_from_parts(&nonce, &token_key_id, issuer_id).unwrap();

        let blinding_result = key_pair.pk.blind(&mut rng, msg).unwrap();
        let blind_sig = key_pair
            .sk
            .blind_sign(&blinding_result.blind_message)
            .unwrap();
        let sig = key_pair
            .pk
            .finalize(&blind_sig, &blinding_result, msg)
            .unwrap();

        let token = PublicBearerPass {
            nonce,
            token_key_id,
            issuer_id: issuer_id.to_string(),
            signature: sig.0,
        };
        let bytes = build_public_bearer_pass(&token).unwrap();
        assert_eq!(bytes[0], REDEMPTION_TOKEN_VERSION_V5);
        let parsed = parse_public_bearer_pass(&bytes).unwrap();
        assert_eq!(parsed, token);

        verify_public_bearer_signature(&spki, &parsed).unwrap();

        let mut tampered = parsed.clone();
        tampered.nonce[0] ^= 0x01;
        assert!(verify_public_bearer_signature(&spki, &tampered).is_err());
    }

    #[test]
    fn test_v5_token_key_id_hex_is_strict_lowercase() {
        let token_key_id = [0xAB; PUBLIC_BEARER_TOKEN_KEY_ID_LEN];
        let encoded = encode_token_key_id_hex(&token_key_id);
        assert_eq!(encoded.len(), 64);
        assert_eq!(encoded, "ab".repeat(PUBLIC_BEARER_TOKEN_KEY_ID_LEN));
        assert_eq!(decode_token_key_id_hex(&encoded).unwrap(), token_key_id);
        assert!(decode_token_key_id_hex(&encoded.to_uppercase()).is_err());
        assert!(decode_token_key_id_hex("abc").is_err());
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
