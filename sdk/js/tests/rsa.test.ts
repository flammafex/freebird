// SPDX-License-Identifier: Apache-2.0 OR MIT

import { afterEach, describe, expect, it, vi } from 'vitest';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { FreebirdClient, DiscoveryError, crypto as sdkCrypto } from '../src/index.js';
import { rsaBlind, rsaUnblind, rsaVerify } from '../src/crypto/rsa.js';
import * as voprf from '../src/crypto/voprf.js';
import type { PublicKeyInfo } from '../src/index.js';

const suite = RSABSSA.SHA384.PSS.Deterministic();

const fromB64 = (value: string): Uint8Array => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
};
const b64 = (value: Uint8Array): string =>
  btoa(String.fromCharCode(...value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/**
 * Converts a standard rsaEncryption SPKI (as produced by WebCrypto) into the
 * PSS-parameterized SPKI the issuer publishes for RFC 9474
 * RSABSSA-SHA384-PSS-Deterministic (SHA-384, MGF1-SHA384, salt length 48).
 */
function toPssSpki(standardSpki: Uint8Array): Uint8Array {
  // Standard layout: SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { 0x00, raw } }
  // BIT STRING tag at index 19, length at 21-22, unused-bits byte at 23, raw key at 24.
  const rawKey = standardSpki.slice(24);
  const algorithm = Uint8Array.from([
    0x30, 0x3d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
    0x30, 0x30, 0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x02, 0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0xa2, 0x03, 0x02, 0x01, 0x30,
  ]);
  const bitStringContent = new Uint8Array(1 + rawKey.length);
  bitStringContent[0] = 0x00;
  bitStringContent.set(rawKey, 1);
  const bitString = new Uint8Array(4 + bitStringContent.length);
  bitString[0] = 0x03;
  bitString[1] = 0x82;
  bitString[2] = bitStringContent.length >>> 8;
  bitString[3] = bitStringContent.length & 0xff;
  bitString.set(bitStringContent, 4);

  const content = new Uint8Array(algorithm.length + bitString.length);
  content.set(algorithm);
  content.set(bitString, algorithm.length);

  const spki = new Uint8Array(4 + content.length);
  spki[0] = 0x30;
  spki[1] = 0x82;
  spki[2] = content.length >>> 8;
  spki[3] = content.length & 0xff;
  spki.set(content, 4);
  return spki;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
  vi.restoreAllMocks();
});

describe('crypto.rsa* (RFC 9474 RSABSSA-SHA384-PSS-Deterministic)', () => {
  it('round-trips blind -> sign -> unblind -> verify', async () => {
    const { publicKey, privateKey } = await suite.generateKey({
      publicExponent: Uint8Array.from([1, 0, 1]),
      modulusLength: 2048,
    });
    const standardSpki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
    const pssSpki = toPssSpki(standardSpki);

    const msg = new TextEncoder().encode('freebird rsa round-trip');
    const { blinded, state } = await rsaBlind(pssSpki, msg);
    expect(blinded.length).toBeGreaterThan(0);
    expect(state.inv.length).toBeGreaterThan(0);

    const blindSig = await suite.blindSign(privateKey, blinded);
    const signature = await rsaUnblind(state, blindSig);

    expect(await rsaVerify(pssSpki, msg, signature)).toBe(true);
  });

  it('rejects a tampered signature', async () => {
    const { publicKey, privateKey } = await suite.generateKey({
      publicExponent: Uint8Array.from([1, 0, 1]),
      modulusLength: 2048,
    });
    const standardSpki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
    const pssSpki = toPssSpki(standardSpki);

    const msg = new TextEncoder().encode('freebird rsa tamper');
    const { blinded, state } = await rsaBlind(pssSpki, msg);
    const blindSig = await suite.blindSign(privateKey, blinded);
    const signature = await rsaUnblind(state, blindSig);

    const tamperedSig = signature.slice();
    tamperedSig[0] ^= 0x01;
    expect(await rsaVerify(pssSpki, msg, tamperedSig)).toBe(false);
  });

  it('rejects a tampered message', async () => {
    const { publicKey, privateKey } = await suite.generateKey({
      publicExponent: Uint8Array.from([1, 0, 1]),
      modulusLength: 2048,
    });
    const standardSpki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
    const pssSpki = toPssSpki(standardSpki);

    const msg = new TextEncoder().encode('freebird rsa message tamper');
    const { blinded, state } = await rsaBlind(pssSpki, msg);
    const blindSig = await suite.blindSign(privateKey, blinded);
    const signature = await rsaUnblind(state, blindSig);

    const tamperedMsg = msg.slice();
    tamperedMsg[0] ^= 0x01;
    expect(await rsaVerify(pssSpki, tamperedMsg, signature)).toBe(false);
  });
});

describe('FreebirdClient.issuePublicToken', () => {
  it('issues a V5 public bearer pass end-to-end against a mocked issuer', async () => {
    const { publicKey, privateKey } = await suite.generateKey({
      publicExponent: Uint8Array.from([1, 0, 1]),
      modulusLength: 2048,
    });
    const standardSpki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
    const pssSpki = toPssSpki(standardSpki);
    const tokenKeyId = sdkCrypto.tokenKeyIdToHex(sdkCrypto.tokenKeyIdFromSpki(pssSpki));

    const keyInfo: PublicKeyInfo = {
      token_key_id: tokenKeyId,
      token_type: 'public_bearer_pass',
      rfc9474_variant: 'RSABSSA-SHA384-PSS-Deterministic',
      modulus_bits: 2048,
      pubkey_spki_b64: b64(pssSpki),
      issuer_id: 'issuer:test',
      valid_from: 0,
      valid_until: 9999999999,
      spend_policy: 'single_use',
    };

    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === 'https://issuer.example/.well-known/keys') {
        return json({
          issuer_id: 'issuer:test',
          current_epoch: 1,
          valid_epochs: [1],
          epoch_duration_sec: 3600,
          voprf: { suite: 'P256-SHA256', kid: 'kid', pubkey: 'pubkey' },
          public: [keyInfo],
        });
      }
      if (url === 'https://issuer.example/v1/public/issue') {
        const body = JSON.parse(init!.body as string) as { blinded_msg_b64: string };
        const blindedMsg = fromB64(body.blinded_msg_b64);
        const blindSig = await suite.blindSign(privateKey, blindedMsg);
        return json({
          blind_signature_b64: b64(blindSig),
          token_key_id: tokenKeyId,
          issuer_id: 'issuer:test',
        });
      }
      throw new Error(`unexpected fetch url: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const client = new FreebirdClient({ issuerUrl: 'https://issuer.example' });
    const nonce = new Uint8Array(32).fill(0x42);
    const msg = voprf.buildPublicBearerMessage(nonce, sdkCrypto.tokenKeyIdFromHex(tokenKeyId), 'issuer:test');

    const pass = await client.issuePublicToken(msg, {
      nonce,
      tokenKeyId,
      issuerId: 'issuer:test',
    });

    // The returned pass parses back to the expected fields.
    const parsed = voprf.parsePublicBearerPass(pass);
    expect(parsed.nonce).toEqual(nonce);
    expect(parsed.tokenKeyId).toEqual(sdkCrypto.tokenKeyIdFromHex(tokenKeyId));
    expect(parsed.issuerId).toBe('issuer:test');

    // And it verifies locally against the published key.
    expect(await client.verifyPublicBearerPassLocally(pass, keyInfo)).toBe(true);
  });

  it('rejects a message/nonce/key mismatch before POST', async () => {
    const { publicKey } = await suite.generateKey({
      publicExponent: Uint8Array.from([1, 0, 1]),
      modulusLength: 2048,
    });
    const standardSpki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
    const pssSpki = toPssSpki(standardSpki);
    const tokenKeyId = sdkCrypto.tokenKeyIdToHex(sdkCrypto.tokenKeyIdFromSpki(pssSpki));
    const keyInfo: PublicKeyInfo = {
      token_key_id: tokenKeyId,
      token_type: 'public_bearer_pass',
      rfc9474_variant: 'RSABSSA-SHA384-PSS-Deterministic',
      modulus_bits: 2048,
      pubkey_spki_b64: b64(pssSpki),
      issuer_id: 'issuer:test',
      valid_from: 0,
      valid_until: 9999999999,
      spend_policy: 'single_use',
    };
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/.well-known/keys')) {
        return json({
          issuer_id: 'issuer:test', current_epoch: 1, valid_epochs: [1],
          epoch_duration_sec: 3600,
          voprf: { suite: 'P256-SHA256', kid: 'kid', pubkey: 'pubkey' },
          public: [keyInfo],
        });
      }
      throw new Error(`unexpected POST or discovery: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);
    const nonce = new Uint8Array(32).fill(0x42);
    const msg = voprf.buildPublicBearerMessage(
      nonce,
      sdkCrypto.tokenKeyIdFromHex(tokenKeyId),
      'issuer:test',
    );
    msg[0] ^= 1;

    await expect(new FreebirdClient({ issuerUrl: 'https://issuer.example' }).issuePublicToken(msg, {
      nonce, tokenKeyId, issuerId: 'issuer:test',
    })).rejects.toBeInstanceOf(DiscoveryError);
    expect(fetchMock.mock.calls.every(([url]) => !url.endsWith('/v1/public/issue'))).toBe(true);
  });
});

describe('FreebirdClient.verifyPublicBearerPassLocally', () => {
  it('returns true for a valid pass and false for a tampered one', async () => {
    const { publicKey, privateKey } = await suite.generateKey({
      publicExponent: Uint8Array.from([1, 0, 1]),
      modulusLength: 2048,
    });
    const standardSpki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
    const pssSpki = toPssSpki(standardSpki);
    const tokenKeyId = sdkCrypto.tokenKeyIdToHex(sdkCrypto.tokenKeyIdFromSpki(pssSpki));

    const keyInfo: PublicKeyInfo = {
      token_key_id: tokenKeyId,
      token_type: 'public_bearer_pass',
      rfc9474_variant: 'RSABSSA-SHA384-PSS-Deterministic',
      modulus_bits: 2048,
      pubkey_spki_b64: b64(pssSpki),
      issuer_id: 'issuer:test',
      valid_from: 0,
      valid_until: 9999999999,
      spend_policy: 'single_use',
    };

    const nonce = new Uint8Array(32).fill(0x11);
    const msg = voprf.buildPublicBearerMessage(nonce, sdkCrypto.tokenKeyIdFromHex(tokenKeyId), 'issuer:test');
    const { blinded, state } = await rsaBlind(pssSpki, msg);
    const blindSig = await suite.blindSign(privateKey, blinded);
    const signature = await rsaUnblind(state, blindSig);
    const pass = voprf.buildPublicBearerPass(nonce, sdkCrypto.tokenKeyIdFromHex(tokenKeyId), 'issuer:test', signature);

    const client = new FreebirdClient({ issuerUrl: 'https://issuer.example' });
    expect(await client.verifyPublicBearerPassLocally(pass, keyInfo)).toBe(true);

    const tampered = pass.slice();
    tampered[tampered.length - 1] ^= 0x01;
    expect(await client.verifyPublicBearerPassLocally(tampered, keyInfo)).toBe(false);
    expect(await client.verifyPublicBearerPassLocally(pass, {
      ...keyInfo,
      issuer_id: 'issuer:other',
    })).toBe(false);
    expect(await client.verifyPublicBearerPassLocally(pass, {
      ...keyInfo,
      token_key_id: '0'.repeat(64),
    })).toBe(false);
    const tamperedSpki = pssSpki.slice();
    tamperedSpki[tamperedSpki.length - 1] ^= 0x01;
    expect(await client.verifyPublicBearerPassLocally(pass, {
      ...keyInfo,
      pubkey_spki_b64: b64(tamperedSpki),
    })).toBe(false);
  });
});
