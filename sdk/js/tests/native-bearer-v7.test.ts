// SPDX-License-Identifier: Apache-2.0 OR MIT

import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';
import {
  V7_ENVELOPE_VERSION,
  V7_RETIRED_ENVELOPE_VERSION,
  V7_RESERVED_ENVELOPE_VERSION,
  blindV7,
  buildV7Body,
  deriveV7Nullifier,
  finalizeV7,
  parseV7Body,
  parseV7Token,
  serializeV7Token,
  v7ApplicationDigest,
  v7ArtifactDigest,
  v7BodyTranscript,
  verifyV7Token,
} from '../src/crypto/native_bearer_v7.js';
import type { V7DirectBinding, V7Token } from '../src/index.js';

const hex = (value: Uint8Array): string => Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
const bytes = (value: string): Uint8Array => Uint8Array.from(value.match(/../g)!, (pair) => Number.parseInt(pair, 16));

function toPssSpki(standardSpki: Uint8Array): Uint8Array {
  const rawKey = standardSpki.slice(24);
  const algorithm = Uint8Array.from([
    0x30, 0x3d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
    0x30, 0x30, 0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x02, 0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0xa2, 0x03, 0x02, 0x01, 48,
  ]);
  const content = new Uint8Array(1 + rawKey.length);
  content[0] = 0;
  content.set(rawKey, 1);
  const bitString = new Uint8Array(4 + content.length);
  bitString.set([0x03, 0x82, content.length >>> 8, content.length & 0xff]);
  bitString.set(content, 4);
  const body = new Uint8Array(algorithm.length + bitString.length);
  body.set(algorithm);
  body.set(bitString, algorithm.length);
  const result = new Uint8Array(4 + body.length);
  result.set([0x30, 0x82, body.length >>> 8, body.length & 0xff]);
  result.set(body, 4);
  return result;
}

function fixtureBody() {
  return buildV7Body({
    asset_id: 'USD', amount_minor: 42n, issuer_id: 'issuer:v7',
    token_key_id: Uint8Array.from({ length: 32 }, (_, index) => index),
    nonce: Uint8Array.from({ length: 32 }, (_, index) => 32 + index),
    owner_commitment: Uint8Array.from({ length: 32 }, (_, index) => 64 + index),
  });
}

async function fixtureBinding(): Promise<{ binding: V7DirectBinding; privateKey: CryptoKey }> {
  const { publicKey, privateKey } = await RSABSSA.SHA384.PSS.Randomized().generateKey({
    publicExponent: Uint8Array.from([1, 0, 1]), modulusLength: 3072,
  });
  const standard = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
  const spki = toPssSpki(standard);
  const identity = { issuer_id: 'issuer:v7', token_key_id: hex(Uint8Array.from({ length: 32 }, (_, index) => index)), __freebirdV7KeyIdentity: true as const };
  return {
      binding: {
      identity, public_key_spki: spki, spki_fingerprint: hex(sha256(spki)), asset_id: 'USD', amount_minor: 42n,
      valid_from: 1n, valid_until: 9_007_199_254_740_991n, __freebirdV7DirectBinding: true,
    } as unknown as V7DirectBinding,
    privateKey,
  };
}

describe('V7 native bearer crypto', () => {
  it('matches the pinned Rust body, nullifier, and application digest vectors', () => {
    const body = fixtureBody();
    expect(hex(v7BodyTranscript(body))).toBe(
      '000000070000001973636172636974792f6e61746976652d6265617265722f763700000003555344000000000000002a000000096973737565723a7637000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f5ad79fe69329bf927ff4d4fca1527af72354b43bb4c464ae59ab0aab7f99feba404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
    );
    expect(hex(deriveV7Nullifier('issuer:v7', body.nonce, body.owner_commitment))).toBe(
      '5ad79fe69329bf927ff4d4fca1527af72354b43bb4c464ae59ab0aab7f99feba',
    );
    expect(hex(v7ApplicationDigest(body))).toBe(
      '8046535630697e78761ce84ad2f16498e00440cf8622a259fc04f150f8c970efc982f9b19104004a94b58170e19630de',
    );
    expect(parseV7Body(v7BodyTranscript(body))).toEqual(body);
  });

  it('round-trips randomized blind/sign/finalize and verifies policy and identity', async () => {
    const { binding, privateKey } = await fixtureBinding();
    const body = fixtureBody();
    const blinded = await blindV7(binding, body);
    expect(blinded.blinded).toHaveLength(384);
    expect(blinded.randomizer).toHaveLength(32);
    const blindSignature = await RSABSSA.SHA384.PSS.Randomized().blindSign(privateKey, blinded.blinded);
    const token = await finalizeV7(binding, body, blinded.state, blindSignature);
    expect(token.signature).toHaveLength(384);
    expect(await verifyV7Token(binding, token, 42n)).toBe(true);
    expect(parseV7Token(serializeV7Token(token))).toEqual(token);
  });

  it('matches the pinned Rust envelope and artifact digest fixture', () => {
    const body = fixtureBody();
    const token = {
      body,
      message_randomizer: Uint8Array.from({ length: 32 }, (_, index) => 0xa0 + index),
      signature: Uint8Array.from({ length: 384 }, (_, index) => index % 256),
      __freebirdV7Token: true as const,
    } as V7Token;
    const envelope = serializeV7Token(token);
    expect(envelope[0]).toBe(V7_ENVELOPE_VERSION);
    expect(envelope).toHaveLength(606);
    expect(hex(v7ArtifactDigest(token))).toBe('96f5c13eee5bfacda424845de1d032453ea69cb455813799ee27141689c5ea65');
    expect(parseV7Token(envelope)).toEqual(token);
  });

  it('rejects retired/unknown envelopes, malformed UTF-8, nullifiers, trailing bytes, and tampering', async () => {
    const body = fixtureBody();
    const token = {
      body, message_randomizer: new Uint8Array(32), signature: new Uint8Array(384), __freebirdV7Token: true as const,
    } as V7Token;
    const envelope = serializeV7Token(token);
    for (const version of [V7_RETIRED_ENVELOPE_VERSION, V7_RESERVED_ENVELOPE_VERSION, 0x04, 0x99]) {
      const altered = envelope.slice(); altered[0] = version;
      expect(() => parseV7Token(altered)).toThrow();
    }
    expect(() => parseV7Token(Uint8Array.from([...envelope, 0]))).toThrow();
    const badUtf8 = envelope.slice();
    badUtf8[1 + 4 + 4 + 1] = 0xff;
    expect(() => parseV7Token(badUtf8)).toThrow();
    const badNullifier = envelope.slice();
    badNullifier[badNullifier.length - 416 - 32] ^= 1;
    expect(() => parseV7Token(badNullifier)).toThrow();
    const { binding, privateKey } = await fixtureBinding();
    const blinded = await blindV7(binding, body);
    const blindSignature = await RSABSSA.SHA384.PSS.Randomized().blindSign(privateKey, blinded.blinded);
    const wrong = binding.identity.token_key_id.replace(/^../, 'ff');
    await expect(finalizeV7({ ...binding, identity: { ...binding.identity, token_key_id: wrong as V7DirectBinding['identity']['token_key_id'] } }, body, blinded.state, blindSignature)).rejects.toThrow();
  });
});
