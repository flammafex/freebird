import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { sha384 } from '@noble/hashes/sha512';
import { concatBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils';
import * as P256 from './p256.js';
import { BlindState } from '../types.js';
import { base64UrlToBytes } from '../client/wire.js';

// Constants from Rust implementation
const DLEQ_DST_PREFIX = new TextEncoder().encode('DLEQ-P256-v1');
const COMPRESSED_POINT_LEN = 33;
const TOKEN_VERSION_V1 = 0x01;
const TOKEN_VERSION_LEN = 1;
const PROOF_LEN = 64; // 32 bytes (c) + 32 bytes (s)
const RAW_TOKEN_LEN_V1 = TOKEN_VERSION_LEN + COMPRESSED_POINT_LEN * 2 + PROOF_LEN; // 131
const REDEMPTION_TOKEN_VERSION_V4 = 0x04;
const PRIVATE_TOKEN_LEN = 32;

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
  const tokenBytes = base64UrlToBytes(tokenB64);
  const pubkeyBytes = base64UrlToBytes(issuerPubkeyB64);

  if (tokenBytes.length !== RAW_TOKEN_LEN_V1) {
    throw new Error(
      `Invalid token length: expected ${RAW_TOKEN_LEN_V1}; got ${tokenBytes.length}`
    );
  }

  const offset = TOKEN_VERSION_LEN;
  if (tokenBytes[0] !== TOKEN_VERSION_V1) {
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
 * Builds the verifier/audience scope digest clients bind into V4 tokens.
 */
export function buildScopeDigest(verifierId: string, audience: string): Uint8Array {
  const verifierIdBytes = new TextEncoder().encode(verifierId);
  const audienceBytes = new TextEncoder().encode(audience);
  if (verifierIdBytes.length === 0 || verifierIdBytes.length > 255) {
    throw new Error('verifier_id must be 1-255 bytes');
  }
  if (audienceBytes.length === 0 || audienceBytes.length > 255) {
    throw new Error('audience must be 1-255 bytes');
  }

  return sha256(concatBytes(
    new TextEncoder().encode('freebird:scope:v4'),
    new Uint8Array([verifierIdBytes.length]),
    verifierIdBytes,
    new Uint8Array([audienceBytes.length]),
    audienceBytes
  ));
}

/**
 * Builds the public input that is blindly issued and privately re-evaluated.
 */
export function buildPrivateTokenInput(
  issuerId: string,
  kid: string,
  nonce: Uint8Array,
  scopeDigest: Uint8Array
): Uint8Array {
  const issuerIdBytes = new TextEncoder().encode(issuerId);
  const kidBytes = new TextEncoder().encode(kid);
  if (issuerIdBytes.length === 0 || issuerIdBytes.length > 255) {
    throw new Error('issuer_id must be 1-255 bytes');
  }
  if (kidBytes.length === 0 || kidBytes.length > 255) {
    throw new Error('kid must be 1-255 bytes');
  }
  if (nonce.length !== PRIVATE_TOKEN_LEN) throw new Error('nonce must be 32 bytes');
  if (scopeDigest.length !== PRIVATE_TOKEN_LEN) throw new Error('scope_digest must be 32 bytes');

  return concatBytes(
    new TextEncoder().encode('freebird:private-token-input:v4'),
    new Uint8Array([issuerIdBytes.length]),
    issuerIdBytes,
    new Uint8Array([kidBytes.length]),
    kidBytes,
    nonce,
    scopeDigest
  );
}

/**
 * Builds a V4 redemption token for wire transmission.
 * Format: [version(1) | nonce(32) | scope_digest(32) | kid_len(1) | kid(var) | issuer_id_len(1) | issuer_id(var) | authenticator(32)]
 */
export function buildRedemptionToken(
  nonce: Uint8Array,
  scopeDigest: Uint8Array,
  kid: string,
  issuerId: string,
  authenticator: Uint8Array
): Uint8Array {
  const kidBytes = new TextEncoder().encode(kid);
  const issuerIdBytes = new TextEncoder().encode(issuerId);
  if (kidBytes.length === 0 || kidBytes.length > 255) throw new Error('kid must be 1-255 bytes');
  if (issuerIdBytes.length === 0 || issuerIdBytes.length > 255) throw new Error('issuer_id must be 1-255 bytes');
  if (nonce.length !== PRIVATE_TOKEN_LEN) throw new Error('nonce must be 32 bytes');
  if (scopeDigest.length !== PRIVATE_TOKEN_LEN) throw new Error('scope_digest must be 32 bytes');
  if (authenticator.length !== PRIVATE_TOKEN_LEN) throw new Error('authenticator must be 32 bytes');

  const buf = new Uint8Array(1 + 32 + 32 + 1 + kidBytes.length + 1 + issuerIdBytes.length + 32);
  let pos = 0;
  buf[pos++] = REDEMPTION_TOKEN_VERSION_V4;
  buf.set(nonce, pos); pos += 32;
  buf.set(scopeDigest, pos); pos += 32;
  buf[pos++] = kidBytes.length;
  buf.set(kidBytes, pos); pos += kidBytes.length;
  buf[pos++] = issuerIdBytes.length;
  buf.set(issuerIdBytes, pos); pos += issuerIdBytes.length;
  buf.set(authenticator, pos);
  return buf;
}

/**
 * Parses a V4 redemption token from wire bytes.
 */
export function parseRedemptionToken(bytes: Uint8Array): {
  nonce: Uint8Array;
  scopeDigest: Uint8Array;
  kid: string;
  issuerId: string;
  authenticator: Uint8Array;
} {
  if (bytes.length < 101 || bytes.length > 512) throw new Error('invalid token length');
  if (bytes[0] !== REDEMPTION_TOKEN_VERSION_V4) throw new Error('unsupported token version');
  let pos = 1;
  const nonce = bytes.slice(pos, pos + 32); pos += 32;
  const scopeDigest = bytes.slice(pos, pos + 32); pos += 32;
  const kidLen = bytes[pos++];
  if (kidLen === 0 || pos + kidLen > bytes.length) throw new Error('invalid kid_len');
  const kid = new TextDecoder().decode(bytes.slice(pos, pos + kidLen)); pos += kidLen;
  const issuerIdLen = bytes[pos++];
  if (issuerIdLen === 0 || pos + issuerIdLen > bytes.length) throw new Error('invalid issuer_id_len');
  const issuerId = new TextDecoder().decode(bytes.slice(pos, pos + issuerIdLen)); pos += issuerIdLen;
  if (bytes.length - pos !== 32) throw new Error('invalid authenticator length');
  const authenticator = bytes.slice(pos, pos + 32);
  return { nonce, scopeDigest, kid, issuerId, authenticator };
}

/** Verifies a Chaum-Pedersen DLEQ proof (Fiat-Shamir transformed). */
function verifyDleq(
  G: any,
  Y: any,
  A: any,
  B: any,
  proofBytes: Uint8Array,
  context: Uint8Array,
): boolean {
  const c = bytesToNumber(proofBytes.slice(0, 32));
  const s = bytesToNumber(proofBytes.slice(32, 64));
  const t1 = P256.multiply(G, s).subtract(P256.multiply(Y, c));
  const t2 = P256.multiply(A, s).subtract(P256.multiply(B, c));
  const dst = concatBytes(DLEQ_DST_PREFIX, context);
  const transcript = concatBytes(
    numberToBytesBE(dst.length, 4),
    dst,
    P256.encodePoint(G),
    P256.encodePoint(Y),
    P256.encodePoint(A),
    P256.encodePoint(B),
    P256.encodePoint(t1),
    P256.encodePoint(t2),
  );
  return c === hashToScalar(transcript);
}

function bytesToNumber(bytes: Uint8Array): bigint {
  return BigInt(`0x${bytesToHex(bytes)}`);
}

function numberToBytesBE(num: number, len: number): Uint8Array {
  return hexToBytes(num.toString(16).padStart(len * 2, '0'));
}

function hashToScalar(bytes: Uint8Array): bigint {
  return bytesToNumber(sha256(bytes)) % p256.CURVE.n;
}
