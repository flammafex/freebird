// The protocol checks use no Privacy Pass library, so these tests run with `node --test` on its own.
import assert from 'node:assert/strict';
import test from 'node:test';
import { decodePaddedBase64url, encodePaddedBase64url } from '../src/encoding.mjs';
import { FreebirdError } from '../src/errors.mjs';
import {
  authorizationHeader, checkChallenge, checkDirectory, isAdmissionCode, issuerBaseURL,
  parsePrivateTokenChallenge, parseRetryAfter,
} from '../src/protocol.mjs';

const key = 'AAECAw==';
const directoryURL = 'https://issuer.example:8443/.well-known/private-token-issuer-directory';
const makeDirectory = () => ({
  'issuer-request-uri': 'https://issuer.example:8443/private-token/issue',
  'token-keys': [{ 'token-type': 2, 'token-key': key }],
});

test('padded base64url: canonical vectors and an independent byte copy', () => {
  for (const [text, bytes] of [
    ['AA==', [0]], ['AAE=', [0, 1]], ['AAEC', [0, 1, 2]], ['-_8=', [251, 255]],
  ]) {
    assert.deepEqual(decodePaddedBase64url(text), Uint8Array.from(bytes));
    assert.equal(encodePaddedBase64url(Uint8Array.from(bytes)), text);
  }
  const bytes = decodePaddedBase64url(key);
  assert.equal(bytes.byteOffset, 0);
  assert.equal(bytes.byteLength, bytes.buffer.byteLength);
});

test('padded base64url: rejects missing/excess padding, base64, whitespace and pad bits', () => {
  for (const value of [
    null, undefined, 23, '', 'A', 'AA', 'AAE', 'AA=', 'AA===', 'AAAA=', 'AA==AA==',
    '+/8=', '-/8=', '-_8=\n', ' AA==', 'AA ==', 'AB==', 'AAF=', '💥',
  ]) {
    assert.throws(() => decodePaddedBase64url(value), /canonical padded base64url/);
  }
});

test('padded base64url: round-trips every byte and nonzero-offset views', () => {
  const bytes = Uint8Array.from({ length: 256 }, (_, index) => index);
  assert.deepEqual(decodePaddedBase64url(encodePaddedBase64url(bytes)), bytes);
  const slice = bytes.subarray(17, 100);
  assert.deepEqual(decodePaddedBase64url(encodePaddedBase64url(slice)), Uint8Array.from(slice));
});

test('WWW-Authenticate: parses the Origin contract', () => {
  const parsed = parsePrivateTokenChallenge(`PrivateToken challenge="AAEC", token-key="${key}"`);
  assert.deepEqual(parsed.bytes, Uint8Array.from([0, 1, 2]));
  assert.deepEqual(parsed.spki, Uint8Array.from([0, 1, 2, 3]));
});

test('WWW-Authenticate: parameter order, horizontal whitespace, case and optional max-age', () => {
  const parsed = parsePrivateTokenChallenge(`  privatetoken\tTOKEN-KEY = "${key}" , max-age=60, CHALLENGE="AA=="  `);
  assert.deepEqual(parsed.bytes, Uint8Array.of(0));
  assert.deepEqual(parsePrivateTokenChallenge(`PrivateToken challenge="AA==", token-key="${key}", max-age="0"`).bytes,
    Uint8Array.of(0));
});

test('WWW-Authenticate: rejects missing, duplicate, unknown, unquoted or folded parameters', () => {
  for (const header of [
    null, '', 'Basic realm="x"', `PrivateToken challenge="AA=="`,
    `PrivateToken token-key="${key}"`, `PrivateToken challenge=1234, token-key="${key}"`,
    `PrivateToken challenge="AA==", token-key=1234`,
    `PrivateToken challenge="AA==", token-key="${key}", token-key="${key}"`,
    `PrivateToken challenge="AA==", CHALLENGE="AA==", token-key="${key}"`,
    `PrivateToken challenge="AA==", token-key="${key}", extra="x"`,
    `PrivateToken challenge="AA==", token-key="${key}", max-age=-1`,
    `PrivateToken challenge="AA==", token-key="${key}", max-age="no"`,
    `PrivateToken challenge="AA==",\r\n token-key="${key}"`,
    `PrivateToken challenge="AA==", token-key="${key}", Basic realm="x"`,
    `PrivateToken challenge="AA==", token-key="${key}",`,
    `PrivateToken challenge="AA", token-key="${key}"`,
    `PrivateToken challenge="AB==", token-key="${key}"`,
  ]) {
    assert.throws(() => parsePrivateTokenChallenge(header), error => {
      assert.ok(error instanceof FreebirdError);
      assert.equal(error.stage, 'challenge');
      assert.equal(error.reason, 'protocol');
      return true;
    });
  }
});

test('Issuer configuration: requires an explicit HTTPS origin', () => {
  assert.equal(issuerBaseURL('https://issuer.example:8443').href, 'https://issuer.example:8443/');
  for (const value of ['', undefined, 'http://issuer.example', 'https://u:p@issuer.example',
    'https://issuer.example/path', 'https://issuer.example/?a=1', 'https://issuer.example/#x',
    'not a url']) {
    assert.throws(() => issuerBaseURL(value), TypeError);
  }
});

test('Issuer configuration: plain HTTP only for 127.0.0.1 and only when explicitly allowed', () => {
  assert.equal(issuerBaseURL('http://127.0.0.1:8081', { allowInsecureLoopback: true }).origin,
    'http://127.0.0.1:8081');
  for (const value of ['http://localhost:8081', 'http://[::1]:8081']) {
    assert.throws(() => issuerBaseURL(value, { allowInsecureLoopback: true }), TypeError);
  }
  assert.throws(() => issuerBaseURL('http://127.0.0.1:8081'), TypeError);
});

test('directory: extracts the request URI, host including port and canonical type-2 keys', () => {
  const checked = checkDirectory(makeDirectory(), directoryURL);
  assert.equal(checked.requestURL.href, 'https://issuer.example:8443/private-token/issue');
  assert.equal(checked.issuerHost, 'issuer.example:8443');
  assert.deepEqual(checked.tokenKeys, [Uint8Array.from([0, 1, 2, 3])]);
});

test('directory: supports rotation and ignores keys for other token types', () => {
  const json = makeDirectory();
  json['token-keys'].push({ 'token-type': 1, 'token-key': 'not applicable' },
    { 'token-type': 2, 'token-key': 'BAUG' });
  const checked = checkDirectory(json, directoryURL);
  checkChallenge({ tokenType: 2, issuerName: checked.issuerHost }, Uint8Array.from([4, 5, 6]), checked);
});

test('directory: rejects a non-HTTPS directory', () => {
  assert.throws(() => checkDirectory(makeDirectory(), 'http://issuer.example/directory'));
});

test('directory: does not send admission to an unconfigured issuer', () => {
  for (const uri of [
    'http://issuer.example:8443/private-token/issue',
    'https://other.example/private-token/issue',
    'https://issuer.example/private-token/issue',
    'https://u:p@issuer.example:8443/private-token/issue',
    'https://issuer.example:8443/private-token/issue#fragment',
    '/private-token/issue',
    '//issuer.example:8443/private-token/issue',
    'not a URL',
  ]) {
    assert.throws(() => checkDirectory({ ...makeDirectory(), 'issuer-request-uri': uri }, directoryURL));
  }
});

test('directory: rejects missing or non-canonical type-2 keys', () => {
  for (const json of [
    null, {}, { ...makeDirectory(), 'issuer-request-uri': 42 },
    { ...makeDirectory(), 'token-keys': null },
    { ...makeDirectory(), 'token-keys': [] },
    { ...makeDirectory(), 'token-keys': [{ 'token-type': '2', 'token-key': key }] },
    { ...makeDirectory(), 'token-keys': [{ 'token-type': 2, 'token-key': 'AA' }] },
    { ...makeDirectory(), 'token-keys': [{ 'token-type': 2, 'token-key': 'AB==' }] },
  ]) {
    assert.throws(() => checkDirectory(json, directoryURL), FreebirdError);
  }
});

test('challenge checks: type-2, exact directory host and advertised key membership', () => {
  const directory = checkDirectory(makeDirectory(), directoryURL);
  const challenge = { tokenType: 2, issuerName: 'issuer.example:8443' };
  const bytes = decodePaddedBase64url(key);
  assert.doesNotThrow(() => checkChallenge(challenge, bytes, directory));
  assert.throws(() => checkChallenge({ ...challenge, tokenType: 1 }, bytes, directory), /type-2/);
  for (const issuerName of ['issuer.example', 'other.example:8443', 'https://issuer.example:8443']) {
    assert.throws(() => checkChallenge({ ...challenge, issuerName }, bytes, directory), /different Issuer/);
  }
  assert.throws(() => checkChallenge(challenge, Uint8Array.of(9), directory), /not in/);
});

test('admission codes: exactly 43 canonical base64url characters for 32 bytes', () => {
  const canonical = 'A'.repeat(42) + 'A';
  assert.equal(isAdmissionCode(canonical), true);
  for (const value of [
    undefined, 42, '', 'A'.repeat(42), 'A'.repeat(44), 'A'.repeat(42) + '+', 'A'.repeat(42) + '=',
    'A'.repeat(42) + 'B', // The final `B` sets a padding bit, so the code is not canonical.
    `${'A'.repeat(42)}/`,
  ]) {
    assert.equal(isAdmissionCode(value), false, String(value));
  }
});

test('authorization header: only canonical 354-byte type-2 tokens', () => {
  const token = encodePaddedBase64url(new Uint8Array(354));
  assert.equal(authorizationHeader(token), `PrivateToken token="${token}"`);
  assert.throws(() => authorizationHeader(encodePaddedBase64url(new Uint8Array(353))), TypeError);
  assert.throws(() => authorizationHeader('A'), TypeError);
  assert.throws(() => authorizationHeader(`${token}"`), TypeError);
});

test('Retry-After: delta seconds and IMF-fixdate; anything else is ignored', () => {
  assert.equal(parseRetryAfter('30'), 30);
  assert.equal(parseRetryAfter(' 0 '), 0);
  assert.equal(parseRetryAfter(null), undefined);
  assert.equal(parseRetryAfter('-1'), undefined);
  assert.equal(parseRetryAfter('soon'), undefined);
  const now = Date.parse('Sun, 06 Nov 1994 08:49:00 GMT');
  assert.equal(parseRetryAfter('Sun, 06 Nov 1994 08:50:30 GMT', now), 90);
  assert.equal(parseRetryAfter('Sun, 06 Nov 1994 08:00:00 GMT', now), 0);
});
