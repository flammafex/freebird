// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.
#![allow(deprecated)]
//./crypto/src/vendor/voprf_p256/oprf.rs
use elliptic_curve::{
    Curve,
    Field,
    bigint::{NonZero, U256},
    scalar::FromUintUnchecked,
    sec1::{ToEncodedPoint, FromEncodedPoint},
    ops::Reduce, // <- we'll use Scalar::reduce_bytes
};
use p256::{ProjectivePoint, FieldBytes, Scalar, NistP256, AffinePoint, EncodedPoint};
use sha2::{Sha256, Digest};
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};

use super::dleq::{encode_proof, decode_proof, prove, verify};

const COMPRESSED_POINT_LEN: usize = 33;

#[derive(Debug)]
pub enum Error {
    Decode,
    InvalidPoint,
    InvalidProof,
    ZeroScalar,
}

const TOKEN_POINT_LEN: usize = COMPRESSED_POINT_LEN; // 33
const TOKEN_PROOF_LEN: usize = 64;
const TOKEN_LEN: usize = TOKEN_POINT_LEN * 2 + TOKEN_PROOF_LEN;

/// RFC 9380-compliant hash-to-curve for P-256 (SSWU_RO).
fn hash_to_curve(input: &[u8], ctx: &[u8]) -> ProjectivePoint {
    // Domain separation tag as per RFC 9380
    const BASE_DST: &[u8] = b"P256_XMD:SHA-256_SSWU_RO_";
    
    // Append context for VOPRF domain separation
    let mut dst = Vec::with_capacity(BASE_DST.len() + ctx.len());
    dst.extend_from_slice(BASE_DST);
    dst.extend_from_slice(ctx);
    
    // Use NistP256::hash_from_bytes (Method 1 - confirmed working!)
    // This returns a generic curve point that we convert to ProjectivePoint
    let point = NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[input],
        &[&dst],
    )
    .expect("hash_to_curve failed");
    
    // Convert to ProjectivePoint
    ProjectivePoint::from(point)
}

/// Compress a projective point (SEC1-encoded, 33 bytes)
fn encode_point_compressed(p: &ProjectivePoint) -> [u8; COMPRESSED_POINT_LEN] {
    p.to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

/// Decompress SEC1 bytes into a projective point
fn decode_point_compressed(bytes: &[u8]) -> Option<ProjectivePoint> {
    let ep = EncodedPoint::from_bytes(bytes).ok()?;
    let ap_opt = AffinePoint::from_encoded_point(&ep);
    let ap: Option<AffinePoint> = ap_opt.into(); // CtOption -> Option
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
    if bool::from(s.is_zero()) {
        return Err(Error::ZeroScalar);
    }
    Ok(s)
}

fn prf_output_from_b(b: &ProjectivePoint, ctx: &[u8]) -> [u8; 32] {
    // Define y = H2(B||ctx) so client and verifier match exactly.
    let mut h = Sha256::new();
    h.update(b"VOPRF-P256-SHA256:Finalize");
    h.update(ctx);
    h.update(encode_point(b));
    let out = h.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

pub struct BlindState {
    pub r: Scalar,
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
        let p = hash_to_curve(input, &self.ctx);
        let r = Scalar::random(rand::rngs::OsRng);
        let a = p * r;
        Ok((encode_point(&a).to_vec(), BlindState { r, p }))
    }

    /// Returns (token_bytes, prf_output[32]).
     pub fn finalize(
        self,
        _st: BlindState, // keep the param to preserve API; not used for hashing
        token_bytes: &[u8],
        issuer_pubkey_sec1_compressed: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if token_bytes.len() != TOKEN_LEN {
            return Err(Error::Decode);
        }

        let a = decode_point(&token_bytes[0..TOKEN_POINT_LEN])?;
        let b = decode_point(&token_bytes[TOKEN_POINT_LEN..TOKEN_POINT_LEN * 2])?;
        let proof_bytes: &[u8; 64] = token_bytes[TOKEN_POINT_LEN * 2..]
            .try_into()
            .map_err(|_| Error::Decode)?;
        let proof = decode_proof(proof_bytes);
        let q = decode_point(issuer_pubkey_sec1_compressed)?;

        // Verify DLEQ on (g,q,a,b) with ctx
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

        // IMPORTANT: Do NOT unblind here. Hash `b` exactly like the verifier.
        let y = prf_output_from_b(&b, &self.ctx);

        Ok((token_bytes.to_vec(), y.to_vec()))
    }
}

impl Server {
    pub fn from_secret_key(sk_bytes: [u8; 32], ctx: &[u8]) -> Result<Self, Error> {
        let k = scalar_from_be32(sk_bytes)?;
        let q = generator() * k;
        Ok(Self { k, q, ctx: ctx.to_vec() })
    }

    pub fn public_key_sec1_compressed(&self) -> [u8; COMPRESSED_POINT_LEN] {
        encode_point(&self.q)
    }

    /// token = A||B||proof  (33 + 33 + 64 = 130 bytes)
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
        let a = decode_point(&token_bytes[0..TOKEN_POINT_LEN])?;
        let b = decode_point(&token_bytes[TOKEN_POINT_LEN..TOKEN_POINT_LEN * 2])?;
        let proof_bytes: &[u8; 64] = token_bytes[TOKEN_POINT_LEN * 2..]
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
