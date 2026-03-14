import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils';
import * as P256 from './p256.js';
import { BlindState } from '../types.js';

// Constants from Rust implementation
const DLEQ_DST_PREFIX = new TextEncoder().encode('DLEQ-P256-v1');
const COMPRESSED_POINT_LEN = 33;
const TOKEN_VERSION_V1 = 0x01;
const TOKEN_VERSION_LEN = 1;
const TOKEN_SIGNATURE_LEN = 64;
const PROOF_LEN = 64; // 32 bytes (c) + 32 bytes (s)
const RAW_TOKEN_LEN_V0 = COMPRESSED_POINT_LEN * 2 + PROOF_LEN; // 130 (legacy, no version byte)
const RAW_TOKEN_LEN_V1 = TOKEN_VERSION_LEN + COMPRESSED_POINT_LEN * 2 + PROOF_LEN; // 131
const TOKEN_LEN_V2 = RAW_TOKEN_LEN_V1 + TOKEN_SIGNATURE_LEN; // 195 (VOPRF + signature)
const REDEMPTION_TOKEN_VERSION_V3 = 0x03;

/**
 * Blinds the input for the VOPRF protocol.
 * Corresponds to Rust: Client::blind
 */
export function blind(
  input: Uint8Array,
  context: Uint8Array
): { blinded: Uint8Array; state: BlindState } {
  // 1. Map input to curve point P = H(input)
  const P = P256.hashToCurve(input, context);

  // 2. Generate random scalar r
  const r = P256.randomScalar();

  // 3. Compute blinded element A = P * r
  const A = P256.multiply(P, r);

  // 4. Return encoded A and state to recover randomness later
  return {
    blinded: P256.encodePoint(A),
    state: { r, p: P }, // We keep P to avoid re-hashing later
  };
}

/**
 * Verifies the issuer's response, unblinds, and returns the 32-byte PRF output.
 * Corresponds to Rust: Client::finalize
 *
 * Returns the unblinded PRF output: SHA-256("VOPRF-P256-SHA256:Finalize" || ctx || W)
 * where W = B * r^(-1) is the unblinded evaluated point.
 */
export function finalize(
  state: BlindState,
  tokenB64: string,
  issuerPubkeyB64: string,
  context: Uint8Array
): Uint8Array {
  // 1. Decode inputs
  const fullTokenBytes = base64UrlToBytes(tokenB64);
  const pubkeyBytes = base64UrlToBytes(issuerPubkeyB64);
  const tokenBytes =
    fullTokenBytes.length === TOKEN_LEN_V2
      ? fullTokenBytes.slice(0, RAW_TOKEN_LEN_V1)
      : fullTokenBytes;

  if (
    tokenBytes.length !== RAW_TOKEN_LEN_V1 &&
    tokenBytes.length !== RAW_TOKEN_LEN_V0
  ) {
    throw new Error(
      `Invalid token length: expected one of ${RAW_TOKEN_LEN_V0}, ${RAW_TOKEN_LEN_V1}, ${TOKEN_LEN_V2}; got ${fullTokenBytes.length}`
    );
  }

  const offset = tokenBytes.length === RAW_TOKEN_LEN_V1 ? TOKEN_VERSION_LEN : 0;
  if (offset === TOKEN_VERSION_LEN && tokenBytes[0] !== TOKEN_VERSION_V1) {
    throw new Error(`Unsupported token version: ${tokenBytes[0]}`);
  }

  // 2. Parse Token Structure: [version? | A (33) | B (33) | Proof (64)]
  const A_bytes = tokenBytes.slice(offset, offset + COMPRESSED_POINT_LEN);
  const B_bytes = tokenBytes.slice(
    offset + COMPRESSED_POINT_LEN,
    offset + COMPRESSED_POINT_LEN * 2
  );
  const proofBytes = tokenBytes.slice(offset + COMPRESSED_POINT_LEN * 2);

  // 3. Decode Points
  const A = P256.decodePoint(A_bytes);
  const B = P256.decodePoint(B_bytes);
  const Q = P256.decodePoint(pubkeyBytes); // Issuer Public Key (Y in DLEQ terms)
  const G = p256.ProjectivePoint.BASE;

  // 4. Verify DLEQ Proof
  // Proves that log_G(Q) == log_A(B) (i.e., Issuer used the same private key)
  const isValid = verifyDleq(G, Q, A, B, proofBytes, context);

  if (!isValid) {
    throw new Error('VOPRF verification failed: Invalid DLEQ proof from issuer');
  }

  // 5. Unblind: W = B * r^(-1)
  const rInv = P256.invertScalar(state.r);
  const W = P256.multiply(B, rInv);

  // 6. Derive PRF output from unblinded point
  const wBytes = P256.encodePoint(W); // SEC1 compressed, 33 bytes
  const finalizeInput = concatBytes(
    new TextEncoder().encode('VOPRF-P256-SHA256:Finalize'),
    context,
    wBytes,
  );
  const output = sha256(finalizeInput); // 32 bytes

  return output;
}

/**
 * Builds a V3 redemption token for wire transmission.
 * Format: [version(1) | output(32) | kid_len(1) | kid(var) | exp(8) | issuer_id_len(1) | issuer_id(var) | sig(64)]
 */
export function buildRedemptionToken(
  output: Uint8Array,  // 32 bytes (PRF output from finalize)
  kid: string,
  exp: bigint,         // i64
  issuerId: string,
  sig: Uint8Array      // 64 bytes
): Uint8Array {
  const kidBytes = new TextEncoder().encode(kid);
  const issuerIdBytes = new TextEncoder().encode(issuerId);
  if (kidBytes.length === 0 || kidBytes.length > 255) throw new Error('kid must be 1-255 bytes');
  if (issuerIdBytes.length === 0 || issuerIdBytes.length > 255) throw new Error('issuer_id must be 1-255 bytes');

  const buf = new Uint8Array(1 + 32 + 1 + kidBytes.length + 8 + 1 + issuerIdBytes.length + 64);
  let pos = 0;
  buf[pos++] = REDEMPTION_TOKEN_VERSION_V3;
  buf.set(output, pos); pos += 32;
  buf[pos++] = kidBytes.length;
  buf.set(kidBytes, pos); pos += kidBytes.length;
  const expView = new DataView(buf.buffer, buf.byteOffset + pos, 8);
  expView.setBigInt64(0, exp);
  pos += 8;
  buf[pos++] = issuerIdBytes.length;
  buf.set(issuerIdBytes, pos); pos += issuerIdBytes.length;
  buf.set(sig, pos);
  return buf;
}

/**
 * Parses a V3 redemption token from wire bytes.
 */
export function parseRedemptionToken(bytes: Uint8Array): {
  output: Uint8Array;
  kid: string;
  exp: bigint;
  issuerId: string;
  sig: Uint8Array;
} {
  if (bytes.length < 109 || bytes.length > 512) throw new Error('invalid token length');
  if (bytes[0] !== REDEMPTION_TOKEN_VERSION_V3) throw new Error('unsupported token version');
  let pos = 1;
  const output = bytes.slice(pos, pos + 32); pos += 32;
  const kidLen = bytes[pos++];
  if (kidLen === 0 || pos + kidLen > bytes.length) throw new Error('invalid kid_len');
  const kid = new TextDecoder().decode(bytes.slice(pos, pos + kidLen)); pos += kidLen;
  if (pos + 8 > bytes.length) throw new Error('truncated');
  const expView = new DataView(bytes.buffer, bytes.byteOffset + pos, 8);
  const exp = expView.getBigInt64(0); pos += 8;
  const issuerIdLen = bytes[pos++];
  if (issuerIdLen === 0 || pos + issuerIdLen > bytes.length) throw new Error('invalid issuer_id_len');
  const issuerId = new TextDecoder().decode(bytes.slice(pos, pos + issuerIdLen)); pos += issuerIdLen;
  if (bytes.length - pos !== 64) throw new Error('invalid sig length');
  const sig = bytes.slice(pos, pos + 64);
  return { output, kid, exp, issuerId, sig };
}

/**
 * Verifies a Chaum-Pedersen DLEQ proof (Fiat-Shamir transformed).
 * Matches Rust: crypto/src/voprf/dleq.rs
 */
function verifyDleq(
  G: any, // Generator
  Y: any, // Public Key
  A: any, // Blinded Point
  B: any, // Evaluated Point
  proofBytes: Uint8Array,
  context: Uint8Array
): boolean {
  // Decode proof scalars (c, s)
  const cBytes = proofBytes.slice(0, 32);
  const sBytes = proofBytes.slice(32, 64);
  const c = bytesToNumber(cBytes);
  const s = bytesToNumber(sBytes);

  // Recompute commitments
  // t1 = G * s - Y * c
  const sG = P256.multiply(G, s);
  const cY = P256.multiply(Y, c);
  const t1 = sG.subtract(cY);

  // t2 = A * s - B * c
  const sA = P256.multiply(A, s);
  const cB = P256.multiply(B, c);
  const t2 = sA.subtract(cB);

  // Recompute Challenge: H(dst_len || dst || G || Y || A || B || t1 || t2)
  const dst = concatBytes(DLEQ_DST_PREFIX, context);
  const dstLenBytes = numberToBytesBE(dst.length, 4); // u32 Big Endian

  const transcript = concatBytes(
    dstLenBytes,
    dst,
    P256.encodePoint(G),
    P256.encodePoint(Y),
    P256.encodePoint(A),
    P256.encodePoint(B),
    P256.encodePoint(t1),
    P256.encodePoint(t2)
  );

  const computedC = hashToScalar(transcript);

  // Check c == computedC
  return c === computedC;
}

// --- Helpers ---

function base64UrlToBytes(base64: string): Uint8Array {
  const binString = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(binString, (m) => m.codePointAt(0)!);
}

function bytesToNumber(bytes: Uint8Array): bigint {
  return BigInt('0x' + bytesToHex(bytes));
}

function numberToBytesBE(num: number, len: number): Uint8Array {
  const hex = num.toString(16).padStart(len * 2, '0');
  return hexToBytes(hex);
}

function hashToScalar(bytes: Uint8Array): bigint {
  const hash = sha256(bytes);
  const num = bytesToNumber(hash);
  // Reduce modulo curve order (Rust: Scalar::reduce_bytes)
  return num % p256.CURVE.n;
}
