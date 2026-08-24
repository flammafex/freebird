// SPDX-License-Identifier: Apache-2.0 OR MIT

import { describe, expect, it } from 'vitest';
import { crypto as sdkCrypto } from '../src/index.js';

const fromB64 = (value: string): Uint8Array => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
};
const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g)!, (byte) => Number.parseInt(byte, 16));
const b64 = (value: Uint8Array): string =>
  btoa(String.fromCharCode(...value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const hex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');

describe('cross-language V4 wire fixtures', () => {
  it('matches the independently generated V4 VOPRF finalization KAT', () => {
    const publicKey = fromHex(
      '02515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f',
    );
    const evaluatedToken = new Uint8Array([
      1,
      ...fromHex('0350974ec14559b8a2bf2dbbf39911dc709ae54f0e88fcb88ae7f9372eb78208e1'),
      ...fromHex('030058b52352750a5ec11f6d63e897bc4fccc19141b317f238360e679a033b7a34'),
      ...fromHex('773a7aace9b437d043df2dfdb690f33b86dd938ab85c8885aaf7026edbe1d036582bad3fc41f0ed1434e2e058e1dbcb096abe8a029bf2b7d6839261365bd6640'),
    ]);

    expect(hex(sdkCrypto.finalize(
      { r: 0x41n, p: {} },
      b64(evaluatedToken),
      b64(publicKey),
      new TextEncoder().encode('freebird:v4'),
    ))).toBe('dd13cf539fdaf86afa324f0b52be161a7c62612065ba4a42f047312f3e18241d');

    const tampered = evaluatedToken.slice();
    tampered[tampered.length - 1] ^= 1;
    expect(() => sdkCrypto.finalize(
      { r: 0x41n, p: {} },
      b64(tampered),
      b64(publicKey),
      new TextEncoder().encode('freebird:v4'),
    )).toThrow('VOPRF verification failed');
  });

  it('matches the independently assembled V4 redemption-token fixture', () => {
    const nonce = Uint8Array.from({ length: 32 }, (_, index) => index);
    const scopeDigest = fromB64('YI6XzRl7YgzzGeGj0HiT5AdAtGOJayzKyfxWP43CRbE');
    const authenticator = Uint8Array.from({ length: 32 }, (_, index) => 0x80 + index);
    const token = sdkCrypto.buildRedemptionToken(
      nonce,
      scopeDigest,
      'kid-fixture-01',
      'issuer:fixture:v4',
      authenticator,
    );

    expect(sdkCrypto.buildScopeDigest('verifier:fixture', 'api/v1')).toEqual(scopeDigest);
    expect(b64(token)).toBe(
      'BAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fYI6XzRl7YgzzGeGj0HiT5AdAtGOJayzKyfxWP43CRbEOa2lkLWZpeHR1cmUtMDERaXNzdWVyOmZpeHR1cmU6djSAgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2enw',
    );
    expect(sdkCrypto.parseRedemptionToken(token)).toEqual({
      nonce,
      scopeDigest,
      kid: 'kid-fixture-01',
      issuerId: 'issuer:fixture:v4',
      authenticator,
    });
  });
});
