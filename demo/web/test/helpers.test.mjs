import assert from 'node:assert/strict';
import test from 'node:test';
import {
  checkChallenge, checkDirectory, decodePaddedBase64url, encodePaddedBase64url,
  issuerBaseURL, parsePrivateTokenChallenge, statusMessage,
} from '../src/helpers.mjs';

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
    assert.throws(() => parsePrivateTokenChallenge(header));
  }
});

test('Issuer configuration: requires an explicit HTTPS origin', () => {
  assert.equal(issuerBaseURL('https://issuer.example:8443').href, 'https://issuer.example:8443/');
  for (const value of ['', undefined, 'http://issuer.example', 'https://u:p@issuer.example',
    'https://issuer.example/path', 'https://issuer.example/?a=1', 'https://issuer.example/#x']) {
    assert.throws(() => issuerBaseURL(value));
  }
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

test('directory: does not exfiltrate admission to an unconfigured issuer', () => {
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
    assert.throws(() => checkDirectory(json, directoryURL));
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

test('HTTP failures: distinguish rejected proof/admission, key mismatch, busy and spent token', () => {
  assert.match(statusMessage('Admission', 403), /proof.*invalid, expired or already used/);
  assert.match(statusMessage('Issuance', 403), /admission.*invalid, expired or used/);
  assert.match(statusMessage('Issuance', 422), /key changed or does not match/);
  assert.match(statusMessage('Admission', 429), /busy.*429/);
  assert.match(statusMessage('Access', 401), /401.*already spent/);
});
