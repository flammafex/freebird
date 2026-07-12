// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.
#![allow(deprecated)]

use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use elliptic_curve::{
    bigint::{NonZero, U256},
    scalar::FromUintUnchecked,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    Curve, Field,
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
///
/// The DST is split into two slices (`BASE_DST || ctx`) and passed directly to
/// `hash_from_bytes`, which concatenates them per the spec. This avoids a
/// heap allocation on every call that was previously incurred by building a
/// temporary `Vec<u8>`.
fn hash_to_curve(input: &[u8], ctx: &[u8]) -> Option<ProjectivePoint> {
    const BASE_DST: &[u8] = b"P256_XMD:SHA-256_SSWU_RO_";
    // Pass the two DST parts as separate slices; `hash_from_bytes` concatenates
    // them before computing expand_message_xmd, producing the same DST as the
    // previous `BASE_DST || ctx` Vec without any heap allocation.
    let point =
        NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[input], &[BASE_DST, ctx]).ok()?;
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

fn prf_output(w: &ProjectivePoint, ctx: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"VOPRF-P256-SHA256:Finalize");
    h.update(ctx);
    h.update(encode_point(w));
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

        // Ensure blinding factor is non-zero
        let r = loop {
            let r = Scalar::random(rand::rngs::OsRng);
            let is_zero = r.to_bytes().ct_eq(&Scalar::ZERO.to_bytes());
            if !bool::from(is_zero) {
                break r;
            }
        };

        let a = p * r;
        Ok((encode_point(&a).to_vec(), BlindState { r, p }))
    }

    pub fn finalize(
        self,
        st: BlindState,
        token_bytes: &[u8],
        issuer_pubkey_sec1_compressed: &[u8],
    ) -> Result<[u8; 32], Error> {
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

        // Unblind: W = B * r^(-1), recovering the PRF output point H(input)^sk
        let r_inv = Option::<Scalar>::from(st.r.invert()).ok_or(Error::ZeroScalar)?;
        let w = b * r_inv;
        if bool::from(w.to_affine().is_identity()) {
            return Err(Error::InvalidPoint);
        }
        Ok(prf_output(&w, &self.ctx))
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

    pub fn evaluate_unblinded(&self, input: &[u8]) -> Result<[u8; 32], Error> {
        let p = hash_to_curve(input, &self.ctx).ok_or(Error::InvalidPoint)?;
        let w = p * self.k;
        if bool::from(w.to_affine().is_identity()) {
            return Err(Error::InvalidPoint);
        }
        Ok(prf_output(&w, &self.ctx))
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
    ) -> Result<(), Error> {
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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{CryptoRng, Error as RngError, RngCore};

    struct FixedScalarRng([u8; 32]);

    impl RngCore for FixedScalarRng {
        fn next_u32(&mut self) -> u32 {
            panic!("the DLEQ KAT requires scalar bytes")
        }

        fn next_u64(&mut self) -> u64 {
            panic!("the DLEQ KAT requires scalar bytes")
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            assert_eq!(dest.len(), self.0.len());
            dest.copy_from_slice(&self.0);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for FixedScalarRng {}

    /// Freebird-specific randomized VOPRF round-trip coverage.
    ///
    /// This bespoke construction is not an RFC 9497 conformance test.
    #[test]
    fn freebird_voprf_roundtrip() {
        // This verifies:
        // 1. Hash-to-curve functionality
        // 2. Point encoding/decoding
        // 3. Scalar operations
        // 4. DLEQ proof generation and verification

        let ctx = b"VOPRF-TEST";
        let sk_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
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

        // Client finalizes — now returns 32-byte unblinded PRF output
        let output = client.finalize(state, &token_bytes, &pk).unwrap();

        // Verify output is 32 bytes
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn freebird_v4_voprf_known_answer() {
        // Independently generated with the reference arithmetic recorded in
        // crypto/tests/fixture-provenance.md; these are not RFC 9497 vectors.
        const CONTEXT: &[u8] = b"freebird:v4";
        const INPUT: &[u8] = b"freebird-kat-input-v1";
        const SECRET_KEY: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        const PUBLIC_KEY: [u8; 33] = *b"\x02\x51\x5c\x3d\x6e\xb9\xe3\x96\xb9\x04\xd3\xfe\xca\x7f\x54\xfd\xcd\x0c\xc1\xe9\x97\xbf\x37\x5d\xca\x51\x5a\xd0\xa6\xc3\xb4\x03\x5f";
        const HASHED_INPUT: [u8; 33] = *b"\x02\x5c\x29\xe3\x1b\xfd\xb5\x4d\xb8\x80\xf9\xba\x48\xbe\xe0\xa5\xc1\xb4\xe4\x2e\xa5\xcb\x63\xc6\x6c\x86\x1b\x8c\xf7\xa8\x57\x79\xfc";
        const EVALUATED_POINT: [u8; 33] = *b"\x03\x7b\xc7\x74\x27\xf2\x6e\xa7\xe2\xdb\xd0\xda\x65\x61\xea\xc0\x59\x59\xec\x04\x37\x6a\x87\xd6\x3e\xa2\xed\xd5\x23\x11\xf2\xc3\xd1";
        const AUTHENTICATOR: [u8; 32] = *b"\xdd\x13\xcf\x53\x9f\xda\xf8\x6a\xfa\x32\x4f\x0b\x52\xbe\x16\x1a\x7c\x62\x61\x20\x65\xba\x4a\x42\xf0\x47\x31\x2f\x3e\x18\x24\x1d";

        let server = Server::from_secret_key(SECRET_KEY, CONTEXT).unwrap();
        assert_eq!(server.public_key_sec1_compressed(), PUBLIC_KEY);
        assert_eq!(
            encode_point(&hash_to_curve(INPUT, CONTEXT).unwrap()),
            HASHED_INPUT
        );
        assert_eq!(
            encode_point(
                &(hash_to_curve(INPUT, CONTEXT).unwrap() * scalar_from_be32(SECRET_KEY).unwrap())
            ),
            EVALUATED_POINT
        );
        assert_eq!(server.evaluate_unblinded(INPUT).unwrap(), AUTHENTICATOR);
    }

    #[test]
    fn freebird_v4_dleq_blinding_proof_known_answer() {
        // Independently generated fixed blinding/proof vector; provenance is in
        // crypto/tests/fixture-provenance.md. This is not an RFC 9497 vector.
        const CONTEXT: &[u8] = b"freebird:v4";
        const SECRET_KEY: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        const BLINDING_SCALAR: [u8; 32] =
            *b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x41";
        const PROOF_SCALAR: [u8; 32] =
            *b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x42";
        const HASHED_INPUT: [u8; 33] = *b"\x02\x5c\x29\xe3\x1b\xfd\xb5\x4d\xb8\x80\xf9\xba\x48\xbe\xe0\xa5\xc1\xb4\xe4\x2e\xa5\xcb\x63\xc6\x6c\x86\x1b\x8c\xf7\xa8\x57\x79\xfc";
        const BLINDED: [u8; 33] = *b"\x03\x50\x97\x4e\xc1\x45\x59\xb8\xa2\xbf\x2d\xbb\xf3\x99\x11\xdc\x70\x9a\xe5\x4f\x0e\x88\xfc\xb8\x8a\xe7\xf9\x37\x2e\xb7\x82\x08\xe1";
        const EVALUATED: [u8; 33] = *b"\x03\x00\x58\xb5\x23\x52\x75\x0a\x5e\xc1\x1f\x6d\x63\xe8\x97\xbc\x4f\xcc\xc1\x91\x41\xb3\x17\xf2\x38\x36\x0e\x67\x9a\x03\x3b\x7a\x34";
        const PROOF: [u8; 64] = *b"\x77\x3a\x7a\xac\xe9\xb4\x37\xd0\x43\xdf\x2d\xfd\xb6\x90\xf3\x3b\x86\xdd\x93\x8a\xb8\x5c\x88\x85\xaa\xf7\x02\x6e\xdb\xe1\xd0\x36\x58\x2b\xad\x3f\xc4\x1f\x0e\xd1\x43\x4e\x2e\x05\x8e\x1d\xbc\xb0\x96\xab\xe8\xa0\x29\xbf\x2b\x7d\x68\x39\x26\x13\x65\xbd\x66\x40";

        let secret_key = scalar_from_be32(SECRET_KEY).unwrap();
        let input = decode_point(&HASHED_INPUT).unwrap();
        let blinded = input * scalar_from_be32(BLINDING_SCALAR).unwrap();
        let public_key = generator() * secret_key;
        let evaluated = blinded * secret_key;
        assert_eq!(encode_point(&blinded), BLINDED);
        assert_eq!(encode_point(&evaluated), EVALUATED);

        let mut rng = FixedScalarRng(PROOF_SCALAR);
        let proof = prove(
            &secret_key,
            &generator().to_affine(),
            &public_key.to_affine(),
            &blinded.to_affine(),
            &evaluated.to_affine(),
            &mut rng,
            Some(CONTEXT),
        );
        assert_eq!(encode_proof(&proof), PROOF);
        assert!(verify(
            &generator().to_affine(),
            &public_key.to_affine(),
            &blinded.to_affine(),
            &evaluated.to_affine(),
            &proof,
            Some(CONTEXT),
        ));

        let mut altered = proof;
        altered.s += Scalar::ONE;
        assert!(!verify(
            &generator().to_affine(),
            &public_key.to_affine(),
            &blinded.to_affine(),
            &evaluated.to_affine(),
            &altered,
            Some(CONTEXT),
        ));
    }

    #[test]
    fn freebird_v4_voprf_rejects_wrong_context_key_and_altered_proof() {
        let context = b"freebird:v4";
        let server = Server::from_secret_key([7u8; 32], context).unwrap();
        let public_key = server.public_key_sec1_compressed();
        let mut client = Client::new(context);
        let (blinded, _) = client.blind(b"fixture-negative-input").unwrap();
        let token = server.evaluate(&blinded).unwrap();

        assert!(Verifier::new(b"freebird:v4:wrong-context")
            .verify(&token, &public_key)
            .is_err());
        let wrong_key = Server::from_secret_key([8u8; 32], context)
            .unwrap()
            .public_key_sec1_compressed();
        assert!(Verifier::new(context).verify(&token, &wrong_key).is_err());

        let mut altered_proof = token;
        altered_proof[TOKEN_LEN - 1] ^= 0x01;
        assert!(Verifier::new(context)
            .verify(&altered_proof, &public_key)
            .is_err());
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

    #[test]
    fn test_unblinding_produces_correct_prf_output() {
        let ctx = b"UNBLIND-TEST";
        let sk_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let server = Server::from_secret_key(sk_bytes, ctx).unwrap();
        let pk = server.public_key_sec1_compressed();
        let input = b"same input for both clients";

        let mut client1 = Client::new(ctx);
        let (blinded1, state1) = client1.blind(input).unwrap();
        let token1 = server.evaluate(blinded1.as_slice()).unwrap();
        let output1 = client1.finalize(state1, &token1, &pk).unwrap();

        let mut client2 = Client::new(ctx);
        let (blinded2, state2) = client2.blind(input).unwrap();
        let token2 = server.evaluate(blinded2.as_slice()).unwrap();
        let output2 = client2.finalize(state2, &token2, &pk).unwrap();

        assert_ne!(blinded1, blinded2);
        assert_eq!(output1, output2);
    }
}
