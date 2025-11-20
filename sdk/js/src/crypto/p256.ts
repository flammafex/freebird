import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';

// ============================================================================
// Constants & Curve Parameters (P-256)
// ============================================================================
const P = p256.CURVE.p; // Field Size
const N = p256.CURVE.n; // Curve Order
const A = p256.CURVE.a;
const B = p256.CURVE.b;
const Z = BigInt(-10);  // Non-square for P-256 SSWU

// ============================================================================
// 1. RFC 9380: hash_to_curve implementation
// ============================================================================

const VOPRF_DST = 'P256_XMD:SHA-256_SSWU_RO_';

export function hashToCurve(input: Uint8Array, context: Uint8Array): any {
  const dst = new Uint8Array(VOPRF_DST.length + context.length);
  dst.set(new TextEncoder().encode(VOPRF_DST), 0);
  dst.set(context, VOPRF_DST.length);

  const [u0, u1] = hashToField(input, dst, 2);
  const Q0 = mapToCurveSSWU(u0);
  const Q1 = mapToCurveSSWU(u1);

  return Q0.add(Q1);
}

// ============================================================================
// 2. Standard Exports (VOPRF Primitives)
// ============================================================================

/**
 * Generates a random scalar for blinding.
 * Implemented manually to avoid 'p256.utils.normPrivateKeyToScalar' issues.
 */
export function randomScalar(): bigint {
  // 1. Generate 32 random bytes (standard for P-256)
  const randomBytes = p256.utils.randomPrivateKey();
  
  // 2. Convert to integer
  const num = os2ip(randomBytes);
  
  // 3. Reduce modulo curve order N
  return num % N;
}

export function encodePoint(point: any): Uint8Array {
  return point.toRawBytes(true);
}

export function decodePoint(bytes: Uint8Array): any {
  try {
    return p256.ProjectivePoint.fromHex(bytesToHex(bytes));
  } catch (e) {
    throw new Error('Invalid P-256 point encoding');
  }
}

export function multiply(point: any, scalar: bigint): any {
  return point.multiply(scalar);
}

/**
 * Inverts a scalar modulo the curve order N.
 * Used for unblinding (1/r).
 */
export function invertScalar(scalar: bigint): bigint {
  // Calculate inverse using Fermat's Little Theorem: a^(n-2) mod n
  return pow(scalar, N - 2n, N);
}

// ============================================================================
// 3. Internal Math & Hashing (Fully Self-Contained)
// ============================================================================

// Modular Inverse modulo P (Field Size) - Used for SSWU
function invertField(num: bigint): bigint {
  return pow(num, P - 2n, P);
}

function pow(base: bigint, exp: bigint, m: bigint): bigint {
  let res = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp % 2n === 1n) res = mod(res * base, m);
    base = mod(base * base, m);
    exp /= 2n;
  }
  return res;
}

function mod(a: bigint, b: bigint): bigint {
  const result = a % b;
  return result >= 0n ? result : result + b;
}

function os2ip(bytes: Uint8Array): bigint {
  return BigInt('0x' + bytesToHex(bytes));
}

// --- Hash to Field (ExpandMsgXMD) ---

function hashToField(msg: Uint8Array, dst: Uint8Array, count: number): bigint[] {
  const L = 48; // Length for P-256
  const lenInBytes = count * L;
  const pseudoRandomBytes = expandMessageXMD(msg, dst, lenInBytes);

  const u = new Array(count);
  for (let i = 0; i < count; i++) {
    const elmBytes = pseudoRandomBytes.slice(i * L, (i + 1) * L);
    u[i] = mod(os2ip(elmBytes), P);
  }
  return u;
}

function expandMessageXMD(msg: Uint8Array, dst: Uint8Array, lenInBytes: number): Uint8Array {
  const b_in_bytes = 32;
  const r_in_bytes = 64;
  
  if (dst.length > 255) throw new Error('DST too long');
  const dstPrime = concatBytes(dst, new Uint8Array([dst.length]));

  const Z_pad = new Uint8Array(r_in_bytes);
  const l_i_b_str = new Uint8Array(2);
  l_i_b_str[0] = (lenInBytes >> 8) & 0xff;
  l_i_b_str[1] = lenInBytes & 0xff;

  const msgPrime = concatBytes(Z_pad, msg, l_i_b_str, new Uint8Array([0]), dstPrime);
  
  let b_0 = sha256(msgPrime);
  let b_1 = sha256(concatBytes(b_0, new Uint8Array([1]), dstPrime));
  
  const res = new Uint8Array(lenInBytes);
  let offset = 0;
  res.set(b_1.slice(0, Math.min(lenInBytes, b_in_bytes)), 0);
  offset += b_in_bytes;

  let b_i = b_1;
  let i = 2;
  while (offset < lenInBytes) {
    const xorBytes = new Uint8Array(b_0.length);
    for (let j = 0; j < b_0.length; j++) xorBytes[j] = b_0[j] ^ b_i[j];
    
    b_i = sha256(concatBytes(xorBytes, new Uint8Array([i]), dstPrime));
    const len = Math.min(lenInBytes - offset, b_in_bytes);
    res.set(b_i.slice(0, len), offset);
    offset += len;
    i++;
  }
  return res;
}

// --- SSWU Map ---

function mapToCurveSSWU(u: bigint): any {
  const Z_u2 = mod(Z * mod(u * u, P), P);
  const Z_u2_sq = mod(Z_u2 * Z_u2, P);
  
  let tv1 = mod(Z_u2_sq + Z_u2, P);
  tv1 = invertField(tv1); // Use our local invertField
  
  let x1 = mod((mod(-B, P) * invertField(A)) * (BigInt(1) + tv1), P);
  if (x1 < BigInt(0)) x1 += P;

  const gx1 = mod(mod(x1 * x1, P) * x1 + A * x1 + B, P);
  let y1 = sqrt(gx1);
  
  if (y1 !== null) {
    if ((y1 % BigInt(2)) !== (u % BigInt(2))) y1 = mod(-y1, P);
    return new p256.ProjectivePoint(x1, y1, BigInt(1));
  }

  const x2 = mod(Z_u2 * x1, P);
  const gx2 = mod(mod(x2 * x2, P) * x2 + A * x2 + B, P);
  let y2 = sqrt(gx2);
  
  if (y2 === null) throw new Error('SSWU failed to find point');
  
  if ((y2 % BigInt(2)) !== (u % BigInt(2))) y2 = mod(-y2, P);
  return new p256.ProjectivePoint(x2, y2, BigInt(1));
}

function sqrt(x: bigint): bigint | null {
  // P = 3 mod 4, so we can use simplified sqrt
  const root = pow(x, (P + 1n) / 4n, P);
  if (mod(root * root, P) !== x) return null;
  return root;
}