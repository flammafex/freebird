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

describe('cross-language V4 and V5 wire fixtures', () => {
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

  it('matches the independently generated V5 public-bearer fixture', () => {
    const spki = fromB64(
      'MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAoxaXGOdxdxj6I3S_lbNJ4T1CQ76A3cVJJUJECn0SiyKwKAA_FFTZQdmKq8gz3JDhrxayLXrhaoFtgTsmeMMlhPsYfyIOOzfe4khh3W-1nKhBqO5Kdr6KbVxgHkgoDWvKLXPCgSOpCG_1BAG1hJveWjd0LUAubxz3e2v5t9J_Vxddhsb9iqKylY0ZWXIsgqyEwPesqShxEb8qoJrIZ_Yi6_27Y9GR3MS6IzK5Ot0rNlEn3PCFW8phxVwofcMlxPgq_ZbdCRH_WJClQl6lWXBmL3DuSN8sMVJH4-rk9psHwrjiDciOpMvIotAEmIg1ZaTO-2DaKGRvV8oPlvXwPBp_gwIDAQAB',
    );
    const signature = fromB64(
      'lR5zKsB-yqyRurEsESMmslQih5gjqVIGhl55yFHpuP40_PX2hG1wCljQcSL8xSYE3k5HeXcvKQsLy4DVz7GiUCHzhEQQqDU1usXI1IPVjZIGwPbWq1R-GyMfUrw0t01IPoAzACChZ267KWuEZ-o7JI9Jk9dS8B67YAl8VZqw2Y0nZU-l0Zbt1DNpYIGX8e9Z-ASJ76WjR2AV7ANNqWIYklRrCJtqySOmDMf3SjkXL6AaYUmIYb98ENizrngKA2voJBSTsHF2FVaXKPNn9GYueYyCZNhfRWsyLQT6gjmvNHnMJWwNQc_ApNwRNKkbNZbkwQfXU-vurMEK-OkuI-C_8Q',
    );
    const tokenKeyId = sdkCrypto.tokenKeyIdFromSpki(spki);
    const nonce = Uint8Array.from({ length: 32 }, (_, index) => 0x20 + index);
    const message = sdkCrypto.buildPublicBearerMessage(nonce, tokenKeyId, 'issuer:fixture:v5');
    const token = sdkCrypto.buildPublicBearerPass(nonce, tokenKeyId, 'issuer:fixture:v5', signature);

    expect(hex(tokenKeyId)).toBe('4257ffa80a19f072ff27b28d60747ed031b4b36c03fdc71252b3df6a5fe982f9');
    expect(hex(message)).toBe('2d1659912a7e91228969587ea710dc0655f4904eaef8c142e989021e15e88c93cf5b56eb0a250dca9134fc0d007c2db5');
    expect(b64(token)).toBe(
      'BSAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_Qlf_qAoZ8HL_J7KNYHR-0DG0s2wD_ccSUrPfal_pgvkRaXNzdWVyOmZpeHR1cmU6djUBAJUecyrAfsqskbqxLBEjJrJUIoeYI6lSBoZeechR6bj-NPz19oRtcApY0HEi_MUmBN5OR3l3LykLC8uA1c-xolAh84REEKg1NbrFyNSD1Y2SBsD21qtUfhsjH1K8NLdNSD6AMwAgoWduuylrhGfqOySPSZPXUvAeu2AJfFWasNmNJ2VPpdGW7dQzaWCBl_HvWfgEie-lo0dgFewDTaliGJJUawibaskjpgzH90o5Fy-gGmFJiGG_fBDYs654CgNr6CQUk7BxdhVWlyjzZ_RmLnmMgmTYX0VrMi0E-oI5rzR5zCVsDUHPwKTcETSpGzWW5MEH11Pr7qzBCvjpLiPgv_E',
    );
    expect(sdkCrypto.parsePublicBearerPass(token)).toEqual({
      nonce,
      tokenKeyId,
      issuerId: 'issuer:fixture:v5',
      signature,
    });
  });

  it('keeps V4 and V5 parser rejection boundaries intact', () => {
    expect(() => sdkCrypto.parseRedemptionToken(new Uint8Array(50))).toThrow();
    expect(() => sdkCrypto.parsePublicBearerPass(new Uint8Array(68))).toThrow();
    expect(() => sdkCrypto.tokenKeyIdFromHex('AB'.repeat(32))).toThrow();
    expect(() => sdkCrypto.buildPublicBearerPass(
      new Uint8Array(32),
      new Uint8Array(32),
      'issuer:test',
      new Uint8Array(0),
    )).toThrow();
  });
});
