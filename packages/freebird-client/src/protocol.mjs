// Invalid protocol data produces a `FreebirdError` with a stage. An invalid Issuer setting
// produces a `TypeError`.
// The module does not import the Privacy Pass library, so the checks can run with `node --test`.
import { protocolError } from './errors.mjs';
import { decodePaddedBase64url, equalBytes } from './encoding.mjs';

export const DIRECTORY_PATH = '/.well-known/private-token-issuer-directory';

const ADMISSION_CODE = /^[A-Za-z0-9_-]{43}$/;

// Require HTTPS unless the caller enables plain HTTP on `127.0.0.1` for tests or local development.
export function transportAllowed(url, allowInsecureLoopback = false) {
  if (url.protocol === 'https:') return true;
  return allowInsecureLoopback === true && url.protocol === 'http:' && url.hostname === '127.0.0.1';
}

export function issuerBaseURL(value, { allowInsecureLoopback = false } = {}) {
  let url;
  try {
    url = typeof value === 'string' && value.trim() ? new URL(value) : undefined;
  } catch {
    url = undefined;
  }
  if (!url || !transportAllowed(url, allowInsecureLoopback) || url.username || url.password
      || url.search || url.hash || url.pathname !== '/') {
    throw new TypeError('The Issuer must be an HTTPS origin without a path or credentials.');
  }
  return url;
}

export function parseJSON(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function decodeOr(stage, value, message) {
  try {
    return decodePaddedBase64url(value);
  } catch {
    throw protocolError(stage, message);
  }
}

// Parse one `PrivateToken` challenge so that the token request uses a single set of parameters.
// Parameter names are case-insensitive and may appear in any order.
// Reject duplicates, other schemes, and line breaks.
export function parsePrivateTokenChallenge(header) {
  if (typeof header !== 'string' || /[\r\n]/.test(header)) {
    throw protocolError('challenge', 'Missing or invalid PrivateToken challenge.');
  }
  const scheme = /^PrivateToken[ \t]+(.+)$/i.exec(header.trim());
  if (!scheme) throw protocolError('challenge', 'Expected one PrivateToken challenge.');
  const parameters = new Map();
  for (const part of scheme[1].split(',')) {
    const match = /^[ \t]*([a-z-]+)[ \t]*=[ \t]*(?:"([^"]+)"|([0-9]+))[ \t]*$/i.exec(part);
    if (!match) throw protocolError('challenge', 'Malformed PrivateToken parameter.');
    const name = match[1].toLowerCase();
    if (!['challenge', 'token-key', 'max-age'].includes(name) || parameters.has(name)) {
      throw protocolError('challenge', 'Unknown or duplicate PrivateToken parameter.');
    }
    if (name !== 'max-age' && match[2] === undefined) {
      throw protocolError('challenge', 'PrivateToken binary parameters must be quoted.');
    }
    const value = match[2] ?? match[3];
    if (name === 'max-age' && !/^[0-9]+$/.test(value)) {
      throw protocolError('challenge', 'Invalid PrivateToken max-age.');
    }
    parameters.set(name, value);
  }
  return {
    bytes: decodeOr('challenge', parameters.get('challenge'), 'Malformed PrivateToken challenge.'),
    spki: decodeOr('challenge', parameters.get('token-key'), 'Malformed PrivateToken token key.'),
  };
}

export function checkDirectory(json, directoryURL, { allowInsecureLoopback = false } = {}) {
  const directory = new URL(directoryURL);
  if (!transportAllowed(directory, allowInsecureLoopback) || directory.username || directory.password) {
    throw protocolError('directory', 'The directory must use HTTPS without credentials.');
  }
  if (!json || typeof json !== 'object' || typeof json['issuer-request-uri'] !== 'string') {
    throw protocolError('directory', 'Invalid Issuer directory.');
  }
  // Require an absolute issuance URL on the directory's origin so that the admission code
  // is sent only to the configured Issuer.
  let requestURL;
  try {
    requestURL = new URL(json['issuer-request-uri']);
  } catch {
    throw protocolError('directory', 'The issuance URI must stay on the configured Issuer.');
  }
  if (requestURL.origin !== directory.origin || requestURL.username || requestURL.password
      || requestURL.hash) {
    throw protocolError('directory', 'The issuance URI must stay on the configured Issuer.');
  }
  if (!Array.isArray(json['token-keys'])) {
    throw protocolError('directory', 'Missing directory token keys.');
  }
  const tokenKeys = json['token-keys']
    .filter(key => key && key['token-type'] === 2)
    .map(key => decodeOr('directory', key['token-key'], 'The directory has a malformed token key.'));
  if (!tokenKeys.length) throw protocolError('directory', 'The directory has no type-2 token key.');
  return { requestURL, issuerHost: directory.host, tokenKeys };
}

export function checkChallenge(challenge, spki, directory) {
  if (challenge.tokenType !== 2) {
    throw protocolError('challenge', 'Expected an RFC 9578 type-2 challenge.');
  }
  if (challenge.issuerName !== directory.issuerHost) {
    throw protocolError('challenge', 'The challenge names a different Issuer.');
  }
  if (!directory.tokenKeys.some(key => equalBytes(key, spki))) {
    throw protocolError('challenge', 'The Origin token key is not in the Issuer directory.');
  }
}

// Check that the 43-character unpadded base64url value is the canonical encoding of a 32-byte admission code.
export function isAdmissionCode(value) {
  if (typeof value !== 'string' || !ADMISSION_CODE.test(value)) return false;
  try {
    return decodePaddedBase64url(`${value}=`).length === 32;
  } catch {
    return false;
  }
}

// Format one `PrivateToken` authorization value after checking that the type-2 token decodes to 354 bytes.
export function authorizationHeader(token) {
  let bytes;
  try {
    bytes = decodePaddedBase64url(token);
  } catch {
    throw new TypeError('The token must be canonical padded base64url.');
  }
  if (bytes.length !== 354) throw new TypeError('The token must be a 354-byte type-2 token.');
  return `PrivateToken token="${token}"`;
}

// Parse `Retry-After` as seconds or an IMF-fixdate and return `undefined` for other formats.
export function parseRetryAfter(value, now = Date.now()) {
  if (typeof value !== 'string') return undefined;
  const text = value.trim();
  if (/^[0-9]{1,9}$/.test(text)) return Number(text);
  if (!/^[A-Za-z]{3}, [0-9]{2} [A-Za-z]{3} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT$/.test(text)) {
    return undefined;
  }
  const when = Date.parse(text);
  return Number.isNaN(when) ? undefined : Math.max(0, Math.ceil((when - now) / 1000));
}
