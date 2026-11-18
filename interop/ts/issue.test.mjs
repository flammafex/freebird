import assert from 'node:assert/strict';
import test from 'node:test';
import { TokenChallenge, publicVerif } from '@cloudflare/privacypass-ts';
import { decode, loopbackBase, parseChallenge } from './issue.mjs';

test('library challenge and response byte roundtrips without an issuer', () => {
  const challenge = new TokenChallenge(2, 'issuer.test', new Uint8Array(32), ['origin.test']);
  const bytes = challenge.serialize();
  assert.deepEqual(TokenChallenge.deserialize(bytes).serialize(), bytes);
  // Copy into a standalone buffer so that the test reads only the bytes in the Node `Buffer` view.
  const slab = Buffer.concat([Buffer.alloc(13), Buffer.from(bytes), Buffer.alloc(17)]);
  const view = slab.subarray(13, 13 + bytes.length);
  assert.deepEqual(TokenChallenge.deserialize(Uint8Array.from(view)).serialize(), bytes);
  const response = new publicVerif.TokenResponse(new Uint8Array(256).fill(42));
  assert.deepEqual(publicVerif.TokenResponse.deserialize(response.serialize()).serialize(), response.serialize());
});

test('canonical padded base64url preserves original bytes', () => {
  assert.deepEqual(decode('_w=='), Buffer.from([255]));
  for (const bad of ['_w', '/w==', '_x==', 'a', '']) assert.throws(() => decode(bad));
  const parsed = parseChallenge('PrivateToken challenge="_w==", token-key="AA=="');
  assert.deepEqual(parsed.bytes, Buffer.from([255]));
});

test('only explicitly numeric loopback HTTP bases accepted', () => {
  for (const good of ['http://127.0.0.1:1234', 'http://[::1]:1234/', 'http://127.2.3.4']) loopbackBase(good);
  for (const bad of ['https://127.0.0.1', 'http://localhost', 'http://127.1', 'http://2130706433',
    'http://0x7f000001', 'http://127.0.0.1@evil.test', 'http://127.0.0.1/path',
    'http://128.0.0.1', 'http://127.999.0.1', 'http://127.0.0.1?x']) {
    assert.throws(() => loopbackBase(bad));
  }
});
