// SPDX-License-Identifier: Apache-2.0 OR MIT

import { RSABSSA } from '@cloudflare/blindrsa-ts';
import type { RsaBlindState } from '../types.js';

// RFC 9474 RSABSSA-SHA384-PSS-Deterministic, matching the issuer's V5 public
// bearer suite (salt length 48 for SHA-384).
const suite = RSABSSA.SHA384.PSS.Deterministic();

/**
 * Imports an RSA public key from its SPKI DER bytes for RSA-PSS/SHA-384 use.
 *
 * The issuer publishes a PSS-parameterized SPKI, which WebCrypto rejects for
 * RSA-PSS import. We therefore rebuild a standard rsaEncryption SPKI around
 * the same raw RSA public key before importing (same approach as discovery.ts).
 */
async function importRsaPssPublicKey(spki: Uint8Array): Promise<CryptoKey> {
  const rawOffset = spki[5] + 10;
  if (spki.length <= rawOffset) throw new Error('Invalid RSA public key');
  const raw = spki.slice(rawOffset);
  const standardHeader = new Uint8Array([
    0x30, 0x82, 0, 0, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0, 0,
  ]);
  standardHeader[2] = (raw.length + 19) >>> 8;
  standardHeader[3] = (raw.length + 19) & 0xff;
  standardHeader[21] = raw.length >>> 8;
  standardHeader[22] = raw.length & 0xff;
  const standardSpki = new Uint8Array(standardHeader.length + raw.length);
  standardSpki.set(standardHeader);
  standardSpki.set(raw, standardHeader.length);
  return crypto.subtle.importKey(
    'spki',
    standardSpki.buffer as ArrayBuffer,
    { name: 'RSA-PSS', hash: 'SHA-384' },
    true,
    ['verify'],
  );
}

/**
 * Blinds `msg` for RFC 9474 RSABSSA-SHA384-PSS-Deterministic signing.
 *
 * `publicKey` is the RSA public key as SPKI DER bytes. The returned `state`
 * holds the secret blinding inverse factor and must never be persisted to any
 * store; `@cloudflare/blindrsa-ts` handles zeroization of key material.
 */
export async function rsaBlind(
  publicKey: Uint8Array,
  msg: Uint8Array,
): Promise<{ blinded: Uint8Array; state: RsaBlindState }> {
  const key = await importRsaPssPublicKey(publicKey);
  const prepared = suite.prepare(msg);
  const { blindedMsg, inv } = await suite.blind(key, prepared);
  return { blinded: blindedMsg, state: { inv, prepared, publicKey } };
}

/**
 * Unblinds a blind signature produced by the issuer, returning the final
 * RSA-PSS signature over the original message.
 */
export async function rsaUnblind(
  state: RsaBlindState,
  blindSignature: Uint8Array,
): Promise<Uint8Array> {
  const key = await importRsaPssPublicKey(state.publicKey);
  return suite.finalize(key, state.prepared, blindSignature, state.inv);
}

/**
 * Verifies an RSA-PSS/SHA-384 signature over `msg` using the RSA public key
 * (SPKI DER bytes) via WebCrypto `subtle.verify`. Returns `true` only if the
 * signature is valid.
 */
export async function rsaVerify(
  publicKey: Uint8Array,
  msg: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const key = await importRsaPssPublicKey(publicKey);
  const prepared = suite.prepare(msg);
  return crypto.subtle.verify(
    { name: 'RSA-PSS', saltLength: 48 },
    key,
    signature.buffer as ArrayBuffer,
    prepared.buffer as ArrayBuffer,
  );
}
