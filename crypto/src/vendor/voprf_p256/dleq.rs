//./crypto/src/vendor/voprf_p256/dleq.rs
//! Discrete Log Equality (DLEQ) proof for P-256
//
// Prove that the same secret `k` links two point pairs:
//   Y = k·G  and  B = k·A
// without revealing `k`.
//
// Proof is a Schnorr-style Sigma protocol made non-interactive via Fiat–Shamir:
//   r ←$ Z_n
//   T1 = r·G,  T2 = r·A
//   c = H(G, Y, A, B, T1, T2, DST)
//   s = r + c·k (mod n)
// Verify:
//   s·G == T1 + c·Y
//   s·A == T2 + c·B
//
// This file is self-contained and targets p256 = "0.13" and elliptic-curve = "0.13".
// No hash-to-curve machinery is used; we only hash bytes to a scalar challenge.

use core::fmt;
use p256::{
    AffinePoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        sec1::ToEncodedPoint,
        Field, // for Scalar::random
        ops::Reduce,
    },
    FieldBytes,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// A DLEQ proof (challenge `c` and response `s`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DleqProof {
    /// Fiat–Shamir challenge scalar.
    pub c: Scalar,
    /// Schnorr response scalar.
    pub s: Scalar,
}

impl fmt::Debug for DleqProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DleqProof {{ c: 0x{}, s: 0x{} }}", hex32(&self.c), hex32(&self.s))
    }
}

/// Domain separation tag for the transcript.
const DLEQ_DST: &[u8] = b"DLEQ-P256-v1";

/// Compute Fiat–Shamir challenge as a scalar: c = H(bytes) mod n.
fn challenge_scalar(
    g: &AffinePoint,
    y: &AffinePoint,
    a: &AffinePoint,
    b: &AffinePoint,
    t1: &AffinePoint,
    t2: &AffinePoint,
    dst: &[u8],
) -> Scalar {
    // Compress points (SEC1 compressed) and hash in a fixed order.
    let mut hasher = Sha256::new();

    // Personalize with DST length and bytes to avoid collisions across protocols.
    hasher.update(u32::try_from(dst.len()).unwrap_or(0).to_be_bytes());
    hasher.update(dst);

    for p in [g, y, a, b, t1, t2] {
        let enc = p.to_encoded_point(true);
        hasher.update(enc.as_bytes());
    }

    let digest = hasher.finalize();
    // Reduce 256-bit digest modulo curve order.
    Scalar::reduce_bytes(FieldBytes::from_slice(&digest))
}

/// Create a DLEQ proof that `y = k·G` and `b = k·a` for the same `k`.
///
/// Inputs:
/// - `k`: secret scalar witness
/// - `g`: generator (affine)
/// - `y`: k·g (affine)
/// - `a`: second base point (affine)
/// - `b`: k·a (affine)
/// - `rng`: CSPRNG
/// - `dst`: optional extra domain separator (in addition to a built-in tag)
pub fn prove<R: RngCore + CryptoRng>(
    k: &Scalar,
    g: &AffinePoint,
    y: &AffinePoint,
    a: &AffinePoint,
    b: &AffinePoint,
    rng: &mut R,
    dst: Option<&[u8]>,
) -> DleqProof {
    let r = Scalar::random(rng);
    let t1 = (ProjectivePoint::from(*g) * r).to_affine();
    let t2 = (ProjectivePoint::from(*a) * r).to_affine();

    let mut full_dst = Vec::with_capacity(DLEQ_DST.len() + dst.map_or(0, |d| d.len()));
    full_dst.extend_from_slice(DLEQ_DST);
    if let Some(extra) = dst { full_dst.extend_from_slice(extra); }

    let c = challenge_scalar(g, y, a, b, &t1, &t2, &full_dst);
    let s = r + c * *k;

    DleqProof { c, s }
}

/// Verify a DLEQ proof.
pub fn verify(
    g: &AffinePoint,
    y: &AffinePoint,
    a: &AffinePoint,
    b: &AffinePoint,
    proof: &DleqProof,
    dst: Option<&[u8]>,
) -> bool {
    let s_g = ProjectivePoint::from(*g) * proof.s;
    let c_y = ProjectivePoint::from(*y) * proof.c;
    let t1_prime = (s_g - c_y).to_affine();

    let s_a = ProjectivePoint::from(*a) * proof.s;
    let c_b = ProjectivePoint::from(*b) * proof.c;
    let t2_prime = (s_a - c_b).to_affine();

    let mut full_dst = Vec::with_capacity(DLEQ_DST.len() + dst.map_or(0, |d| d.len()));
    full_dst.extend_from_slice(DLEQ_DST);
    if let Some(extra) = dst { full_dst.extend_from_slice(extra); }

    let c_check = challenge_scalar(g, y, a, b, &t1_prime, &t2_prime, &full_dst);
    c_check == proof.c
}

/// Serialize proof to 64 bytes.
pub fn encode_proof(proof: &DleqProof) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&proof.c.to_bytes());
    out[32..].copy_from_slice(&proof.s.to_bytes());
    out
}

/// Deserialize proof from bytes.
pub fn decode_proof(bytes: &[u8; 64]) -> DleqProof {
    let c = Scalar::reduce_bytes(FieldBytes::from_slice(&bytes[..32]));
    let s = Scalar::reduce_bytes(FieldBytes::from_slice(&bytes[32..]));
    DleqProof { c, s }
}

fn hex32(x: &Scalar) -> String {
    let b = x.to_bytes();
    b.iter().map(|byte| format!("{:02x}", byte)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{ProjectivePoint, Scalar};
    use rand_core::OsRng;

    #[test]
    fn round_trip_proof() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let g = AffinePoint::GENERATOR;
        let a = (ProjectivePoint::GENERATOR * Scalar::random(&mut rng)).to_affine();
        let y = (ProjectivePoint::from(g) * k).to_affine();
        let b = (ProjectivePoint::from(a) * k).to_affine();

        let proof = prove(&k, &g, &y, &a, &b, &mut rng, Some(b"test-dst"));
        assert!(verify(&g, &y, &a, &b, &proof, Some(b"test-dst")));

        let enc = encode_proof(&proof);
        let dec = decode_proof(&enc);
        assert_eq!(proof, dec);
    }

    #[test]
    fn detect_bad_proof() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let g = AffinePoint::GENERATOR;
        let a = (ProjectivePoint::GENERATOR * Scalar::random(&mut rng)).to_affine();
        let y = (ProjectivePoint::from(g) * k).to_affine();
        let b = (ProjectivePoint::from(a) * k).to_affine();

        let mut proof = prove(&k, &g, &y, &a, &b, &mut rng, None);
        proof.s = proof.s + Scalar::ONE;
        assert!(!verify(&g, &y, &a, &b, &proof, None));
    }
}
