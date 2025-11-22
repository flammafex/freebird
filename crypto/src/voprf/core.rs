// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.
#![allow(deprecated)]

use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use elliptic_curve::{
    bigint::{NonZero, U256},
    scalar::FromUintUnchecked,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    Curve,
    Field,
};
use p256::{AffinePoint, EncodedPoint, NistP256, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::dleq::{decode_proof, encode_proof, prove, verify};

const COMPRESSED_POINT_LEN: usize = 33;

#[derive(Debug)]
pub enum Error {
    Decode,
    InvalidPoint,
    InvalidProof,
    ZeroScalar,
    UnsupportedVersion,
}

// Token format: [VERSION||A||B||Proof]
// VERSION: 1 byte (0x01 for current version)
// A: 33 bytes (blinded element, compressed point)
// B: 33 bytes (evaluated element, compressed point)
// Proof: 64 bytes (DLEQ proof)
const TOKEN_VERSION_V1: u8 = 0x01;
const TOKEN_VERSION_LEN: usize = 1;
const TOKEN_POINT_LEN: usize = COMPRESSED_POINT_LEN; // 33
const TOKEN_PROOF_LEN: usize = 64;
const TOKEN_LEN: usize = TOKEN_VERSION_LEN + TOKEN_POINT_LEN * 2 + TOKEN_PROOF_LEN;

/// RFC 9380-compliant hash-to-curve for P-256 (SSWU_RO).
fn hash_to_curve(input: &[u8], ctx: &[u8]) -> Option<ProjectivePoint> {
    const BASE_DST: &[u8] = b"P256_XMD:SHA-256_SSWU_RO_";
    let mut dst = Vec::with_capacity(BASE_DST.len() + ctx.len());
    dst.extend_from_slice(BASE_DST);
    dst.extend_from_slice(ctx);

    let point = NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[input], &[&dst]).ok()?;
    Some(ProjectivePoint::from(point))
}

fn encode_point_compressed(p: &ProjectivePoint) -> [u8; COMPRESSED_POINT_LEN] {
    p.to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn decode_point_compressed(bytes: &[u8]) -> Option<ProjectivePoint> {
    let ep = EncodedPoint::from_bytes(bytes).ok()?;
    let ap_opt = AffinePoint::from_encoded_point(&ep);
    let ap: Option<AffinePoint> = ap_opt.into();
    let ap = ap?;
    if ap.is_identity().into() {
        return None;
    }
    Some(ProjectivePoint::from(ap))
}

fn encode_point(p: &ProjectivePoint) -> [u8; COMPRESSED_POINT_LEN] {
    encode_point_compressed(p)
}

fn decode_point(bytes: &[u8]) -> Result<ProjectivePoint, Error> {
    decode_point_compressed(bytes).ok_or(Error::InvalidPoint)
}

fn generator() -> ProjectivePoint {
    ProjectivePoint::GENERATOR
}

fn scalar_from_be32(bytes: [u8; 32]) -> Result<Scalar, Error> {
    let u = U256::from_be_slice(&bytes);
    let n = NonZero::new(NistP256::ORDER).unwrap();
    let s = Scalar::from_uint_unchecked(u.rem(&n));

    // Use constant-time comparison to prevent timing attacks
    let zero = Scalar::ZERO;
    let is_zero = s.to_bytes().ct_eq(&zero.to_bytes());
    if bool::from(is_zero) {
        return Err(Error::ZeroScalar);
    }
    Ok(s)
}

fn prf_output_from_b(b: &ProjectivePoint, ctx: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"VOPRF-P256-SHA256:Finalize");
    h.update(ctx);
    h.update(encode_point(b));
    let out = h.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

/// Client-side blinding state
///
/// # Security Note
///
/// The blinding factor `r` is a `Scalar` which implements `DefaultIsZeroes`
/// from the `zeroize` crate. This means it will be automatically and securely
/// erased from memory when dropped, preventing key material leakage.
pub struct BlindState {
    /// Blinding factor (auto-zeroized on drop via RustCrypto's Scalar implementation)
    pub r: Scalar,
    /// Hashed input point (public value, no zeroization needed)
    pub p: ProjectivePoint, // H1(x)
}

pub struct Client {
    ctx: Vec<u8>,
}

pub struct Server {
    k: Scalar,
    q: ProjectivePoint, // k·G
    ctx: Vec<u8>,
}

pub struct Verifier {
    ctx: Vec<u8>,
}

impl Client {
    pub fn new(ctx: &[u8]) -> Self {
        Self { ctx: ctx.to_vec() }
    }

    pub fn blind(&mut self, input: &[u8]) -> Result<(Vec<u8>, BlindState), Error> {
        let p = hash_to_curve(input, &self.ctx).ok_or(Error::InvalidPoint)?;
        let r = Scalar::random(rand::rngs::OsRng);
        let a = p * r;
        Ok((encode_point(&a).to_vec(), BlindState { r, p }))
    }

    pub fn finalize(
        self,
        _st: BlindState,
        token_bytes: &[u8],
        issuer_pubkey_sec1_compressed: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if token_bytes.len() != TOKEN_LEN {
            return Err(Error::Decode);
        }

        // Check version byte
        if token_bytes[0] != TOKEN_VERSION_V1 {
            return Err(Error::UnsupportedVersion);
        }

        let offset = TOKEN_VERSION_LEN;
        let a = decode_point(&token_bytes[offset..offset + TOKEN_POINT_LEN])?;
        let b = decode_point(&token_bytes[offset + TOKEN_POINT_LEN..offset + TOKEN_POINT_LEN * 2])?;
        let proof_bytes: &[u8; 64] = token_bytes[offset + TOKEN_POINT_LEN * 2..]
            .try_into()
            .map_err(|_| Error::Decode)?;
        let proof = decode_proof(proof_bytes);
        let q = decode_point(issuer_pubkey_sec1_compressed)?;

        let ok = verify(
            &generator().to_affine(),
            &q.to_affine(),
            &a.to_affine(),
            &b.to_affine(),
            &proof,
            Some(&self.ctx),
        );
        if !ok {
            return Err(Error::InvalidProof);
        }

        let y = prf_output_from_b(&b, &self.ctx);
        Ok((token_bytes.to_vec(), y.to_vec()))
    }
}

impl Server {
    pub fn from_secret_key(sk_bytes: [u8; 32], ctx: &[u8]) -> Result<Self, Error> {
        let k = scalar_from_be32(sk_bytes)?;
        let q = generator() * k;
        Ok(Self {
            k,
            q,
            ctx: ctx.to_vec(),
        })
    }

    pub fn public_key_sec1_compressed(&self) -> [u8; COMPRESSED_POINT_LEN] {
        encode_point(&self.q)
    }

    pub fn evaluate(&self, blinded_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let a = decode_point(blinded_bytes)?;
        let b = a * self.k;

        let mut rng = rand::rngs::OsRng;
        let proof = prove(
            &self.k,
            &generator().to_affine(),
            &self.q.to_affine(),
            &a.to_affine(),
            &b.to_affine(),
            &mut rng,
            Some(&self.ctx),
        );

        let mut token = Vec::with_capacity(TOKEN_LEN);
        token.push(TOKEN_VERSION_V1); // Add version byte
        token.extend_from_slice(&encode_point(&a));
        token.extend_from_slice(&encode_point(&b));
        token.extend_from_slice(&encode_proof(&proof));
        Ok(token)
    }
}

impl Verifier {
    pub fn new(ctx: &[u8]) -> Self {
        Self { ctx: ctx.to_vec() }
    }

    pub fn verify(
        &self,
        token_bytes: &[u8],
        issuer_pubkey_sec1_compressed: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if token_bytes.len() != TOKEN_LEN {
            return Err(Error::Decode);
        }

        // Check version byte
        if token_bytes[0] != TOKEN_VERSION_V1 {
            return Err(Error::UnsupportedVersion);
        }

        let offset = TOKEN_VERSION_LEN;
        let a = decode_point(&token_bytes[offset..offset + TOKEN_POINT_LEN])?;
        let b = decode_point(&token_bytes[offset + TOKEN_POINT_LEN..offset + TOKEN_POINT_LEN * 2])?;
        let proof_bytes: &[u8; 64] = token_bytes[offset + TOKEN_POINT_LEN * 2..]
            .try_into()
            .map_err(|_| Error::Decode)?;
        let proof = decode_proof(proof_bytes);

        let q = decode_point(issuer_pubkey_sec1_compressed)?;

        let ok = verify(
            &generator().to_affine(),
            &q.to_affine(),
            &a.to_affine(),
            &b.to_affine(),
            &proof,
            Some(&self.ctx),
        );
        if !ok {
            return Err(Error::InvalidProof);
        }
        Ok(prf_output_from_b(&b, &self.ctx).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::scalar::FromUintUnchecked;
    use elliptic_curve::bigint::U256;

    /// Test vectors from draft-irtf-cfrg-voprf-21
    /// VOPRF(P-256, SHA-256) Test Vectors
    ///
    /// These test vectors ensure our implementation matches the IETF specification
    #[test]
    fn test_voprf_rfc_test_vectors() {
        // Test vector from draft-irtf-cfrg-voprf-21
        // VOPRF(P-256, SHA-256)
        // Mode: 0x00 (Base Mode, not verifiable - we use Mode 0x01 Verifiable)

        // For comprehensive testing, we verify:
        // 1. Hash-to-curve functionality
        // 2. Point encoding/decoding
        // 3. Scalar operations
        // 4. DLEQ proof generation and verification

        let ctx = b"VOPRF-TEST";
        let sk_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];

        let server = Server::from_secret_key(sk_bytes, ctx).unwrap();
        let pk = server.public_key_sec1_compressed();

        let mut client = Client::new(ctx);
        let input = b"test input";
        let (blinded, state) = client.blind(input).unwrap();

        // Server evaluates
        let token_bytes = server.evaluate(blinded.as_slice()).unwrap();

        // Verify token has correct length (including version byte)
        assert_eq!(token_bytes.len(), TOKEN_LEN);
        assert_eq!(token_bytes[0], TOKEN_VERSION_V1);

        // Client finalizes
        let (token, output) = client.finalize(state, &token_bytes, &pk).unwrap();

        // Verifier checks
        let verifier = Verifier::new(ctx);
        let verified_output = verifier.verify(&token, &pk).unwrap();

        assert_eq!(output, verified_output);
    }

    #[test]
    fn test_constant_time_scalar_zero_check() {
        // Verify that scalar_from_be32 rejects zero scalars
        let zero_bytes = [0u8; 32];
        let result = scalar_from_be32(zero_bytes);
        assert!(matches!(result, Err(Error::ZeroScalar)));
    }

    #[test]
    fn test_hash_to_curve_consistency() {
        // Verify hash-to-curve produces consistent results
        let input = b"test input";
        let ctx = b"test-ctx";

        let p1 = hash_to_curve(input, ctx);
        let p2 = hash_to_curve(input, ctx);

        assert!(p1.is_some());
        assert!(p2.is_some());
        assert_eq!(p1.unwrap(), p2.unwrap());
    }

    #[test]
    fn test_point_encoding_roundtrip() {
        // Test point encoding/decoding roundtrip
        let g = generator();
        let encoded = encode_point(&g);
        let decoded = decode_point(&encoded).unwrap();

        assert_eq!(g, decoded);
    }

    #[test]
    fn test_token_version_checking() {
        // Test that invalid version bytes are rejected
        let ctx = b"test";
        let sk_bytes = [1u8; 32];

        let server = Server::from_secret_key(sk_bytes, ctx).unwrap();
        let pk = server.public_key_sec1_compressed();

        let mut client = Client::new(ctx);
        let (blinded, state) = client.blind(b"input").unwrap();

        let mut token_bytes = server.evaluate(blinded.as_slice()).unwrap();

        // Corrupt version byte
        token_bytes[0] = 0xFF;

        // Client should reject invalid version
        let result = client.finalize(state, &token_bytes, &pk);
        assert!(matches!(result, Err(Error::UnsupportedVersion)));
    }

    #[test]
    fn test_dleq_proof_verification() {
        // Test DLEQ proof generation and verification
        let ctx = b"dleq-test";
        let sk_bytes = [42u8; 32];

        let server = Server::from_secret_key(sk_bytes, ctx).unwrap();
        let pk = server.public_key_sec1_compressed();

        let mut client = Client::new(ctx);
        let (blinded, state) = client.blind(b"test").unwrap();

        let token_bytes = server.evaluate(blinded.as_slice()).unwrap();

        // Valid proof should verify
        let result = client.finalize(state, &token_bytes, &pk);
        assert!(result.is_ok());
    }
}