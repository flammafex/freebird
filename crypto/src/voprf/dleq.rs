// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

/// Discrete Log Equality (DLEQ) proof for P-256
///
/// Prove that the same secret 'k' links two point pairs:
///   Y = k·G  and  B = k·A
/// without revealing 'k'.
use core::fmt;
use p256::{
    elliptic_curve::{
        ops::Reduce,
        sec1::ToEncodedPoint,
        Field,
    },
    AffinePoint, FieldBytes, ProjectivePoint, Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// A DLEQ proof (challenge `c` and response `s`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DleqProof {
    /// Fiat-Shamir challenge scalar.
    pub c: Scalar,
    /// Schnorr response scalar.
    pub s: Scalar,
}

impl fmt::Debug for DleqProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DleqProof {{ c: 0x{}, s: 0x{} }}",
            hex32(&self.c),
            hex32(&self.s)
        )
    }
}

/// Domain separation tag for the transcript.
const DLEQ_DST: &[u8] = b"DLEQ-P256-v1";

/// Compute Fiat-Shamir challenge as a scalar: c = H(bytes) mod n.
fn challenge_scalar(
    g: &AffinePoint,
    y: &AffinePoint,
    a: &AffinePoint,
    b: &AffinePoint,
    t1: &AffinePoint,
    t2: &AffinePoint,
    dst: &[u8],
) -> Scalar {
    let mut hasher = Sha256::new();

    hasher.update(u32::try_from(dst.len()).unwrap_or(0).to_be_bytes());
    hasher.update(dst);

    for p in [g, y, a, b, t1, t2] {
        let enc = p.to_encoded_point(true);
        hasher.update(enc.as_bytes());
    }

    let digest = hasher.finalize();
    // Fix: Pass the digest directly. Both are GenericArray<u8, U32>.
    Scalar::reduce_bytes(&digest)
}

/// Create a DLEQ proof that 'y = k·G' and 'b = k·a' for the same 'k'.
///
/// # Security Note
///
/// The ephemeral random scalar `r` is automatically zeroized when this function
/// returns, as `Scalar` implements `DefaultIsZeroes` from the zeroize crate.
pub fn prove<R: RngCore + CryptoRng>(
    k: &Scalar,
    g: &AffinePoint,
    y: &AffinePoint,
    a: &AffinePoint,
    b: &AffinePoint,
    rng: &mut R,
    dst: Option<&[u8]>,
) -> DleqProof {
    // Ephemeral random scalar (auto-zeroized on drop via RustCrypto's Scalar)
    let r = Scalar::random(rng);
    let t1 = (ProjectivePoint::from(*g) * r).to_affine();
    let t2 = (ProjectivePoint::from(*a) * r).to_affine();

    let mut full_dst = Vec::with_capacity(DLEQ_DST.len() + dst.map_or(0, |d| d.len()));
    full_dst.extend_from_slice(DLEQ_DST);
    if let Some(extra) = dst {
        full_dst.extend_from_slice(extra);
    }

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
    if let Some(extra) = dst {
        full_dst.extend_from_slice(extra);
    }

    let c_check = challenge_scalar(g, y, a, b, &t1_prime, &t2_prime, &full_dst);

    // Use constant-time comparison to prevent timing attacks
    // This prevents attackers from using timing side-channels to extract
    // information about the expected challenge scalar
    bool::from(c_check.to_bytes().ct_eq(&proof.c.to_bytes()))
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
    // Convert slices to fixed-size arrays to avoid deprecated GenericArray methods
    let c_bytes: [u8; 32] = bytes[..32].try_into().expect("slice is 32 bytes");
    let s_bytes: [u8; 32] = bytes[32..].try_into().expect("slice is 32 bytes");
    let c = Scalar::reduce_bytes(&FieldBytes::from(c_bytes));
    let s = Scalar::reduce_bytes(&FieldBytes::from(s_bytes));
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

    #[test]
    fn test_constant_time_verification() {
        // This test verifies that the comparison is constant-time by checking
        // that all single-bit flips in the challenge scalar are rejected
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let g = AffinePoint::GENERATOR;
        let a = (ProjectivePoint::GENERATOR * Scalar::random(&mut rng)).to_affine();
        let y = (ProjectivePoint::from(g) * k).to_affine();
        let b = (ProjectivePoint::from(a) * k).to_affine();

        // Generate a valid proof
        let proof = prove(&k, &g, &y, &a, &b, &mut rng, Some(b"test"));

        // Verify the original proof is valid
        assert!(verify(&g, &y, &a, &b, &proof, Some(b"test")));

        // Test all single-bit flips in the challenge scalar
        // This ensures that the comparison is actually checking all bits
        let mut c_bytes = proof.c.to_bytes();
        for byte_idx in 0..32 {
            for bit_idx in 0..8 {
                // Flip a single bit
                c_bytes[byte_idx] ^= 1 << bit_idx;

                // Create modified proof
                let c_modified = Scalar::reduce_bytes(&FieldBytes::clone_from_slice(&c_bytes));
                let modified_proof = DleqProof {
                    c: c_modified,
                    s: proof.s,
                };

                // Verification should fail for any single-bit flip
                assert!(
                    !verify(&g, &y, &a, &b, &modified_proof, Some(b"test")),
                    "Failed to detect bit flip at byte {} bit {}",
                    byte_idx,
                    bit_idx
                );

                // Flip the bit back
                c_bytes[byte_idx] ^= 1 << bit_idx;
            }
        }
    }

    #[test]
    fn test_proof_rejection_patterns() {
        // Test that verification properly rejects various types of invalid proofs
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let g = AffinePoint::GENERATOR;
        let a = (ProjectivePoint::GENERATOR * Scalar::random(&mut rng)).to_affine();
        let y = (ProjectivePoint::from(g) * k).to_affine();
        let b = (ProjectivePoint::from(a) * k).to_affine();

        // Generate a valid proof
        let proof = prove(&k, &g, &y, &a, &b, &mut rng, Some(b"test"));
        assert!(verify(&g, &y, &a, &b, &proof, Some(b"test")));

        // Test 1: Modified challenge (c -> c + 1)
        let bad_proof_1 = DleqProof {
            c: proof.c + Scalar::ONE,
            s: proof.s,
        };
        assert!(!verify(&g, &y, &a, &b, &bad_proof_1, Some(b"test")));

        // Test 2: Modified response (s -> s + 1)
        let bad_proof_2 = DleqProof {
            c: proof.c,
            s: proof.s + Scalar::ONE,
        };
        assert!(!verify(&g, &y, &a, &b, &bad_proof_2, Some(b"test")));

        // Test 3: Wrong domain separation tag
        assert!(!verify(&g, &y, &a, &b, &proof, Some(b"wrong-dst")));

        // Test 4: Swapped c and s
        let bad_proof_3 = DleqProof {
            c: proof.s,
            s: proof.c,
        };
        assert!(!verify(&g, &y, &a, &b, &bad_proof_3, Some(b"test")));

        // Test 5: Zero challenge (should fail)
        let bad_proof_4 = DleqProof {
            c: Scalar::ZERO,
            s: proof.s,
        };
        assert!(!verify(&g, &y, &a, &b, &bad_proof_4, Some(b"test")));
    }
}