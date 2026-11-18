// These helpers use only browser APIs also available in Node >=20.
export function encodePaddedBase64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_');
}

export function decodePaddedBase64url(value) {
  if (typeof value !== 'string' || value.length === 0
      || !/^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)?$/.test(value)) {
    throw new Error('Expected canonical padded base64url.');
  }
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')),
    character => character.charCodeAt(0));
  // Reject nonzero unused pad bits as well as missing/excess padding.
  if (encodePaddedBase64url(bytes) !== value) {
    throw new Error('Expected canonical padded base64url.');
  }
  return bytes;
}

export function equalBytes(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

// The Origin contract has one PrivateToken challenge, not a list of schemes.
// Parameter names/order are flexible; ambiguity, duplicates and folding are not.
export function parsePrivateTokenChallenge(header) {
  if (typeof header !== 'string' || /[\r\n]/.test(header)) {
    throw new Error('Missing or invalid PrivateToken challenge.');
  }
  const scheme = /^PrivateToken[ \t]+(.+)$/i.exec(header.trim());
  if (!scheme) throw new Error('Expected one PrivateToken challenge.');
  const parameters = new Map();
  for (const part of scheme[1].split(',')) {
    const match = /^[ \t]*([a-z-]+)[ \t]*=[ \t]*(?:"([^"]+)"|([0-9]+))[ \t]*$/i.exec(part);
    if (!match) throw new Error('Malformed PrivateToken parameter.');
    const name = match[1].toLowerCase();
    if (!['challenge', 'token-key', 'max-age'].includes(name) || parameters.has(name)) {
      throw new Error('Unknown or duplicate PrivateToken parameter.');
    }
    if (name !== 'max-age' && match[2] === undefined) {
      throw new Error('PrivateToken binary parameters must be quoted.');
    }
    const value = match[2] ?? match[3];
    if (name === 'max-age' && !/^[0-9]+$/.test(value)) {
      throw new Error('Invalid PrivateToken max-age.');
    }
    parameters.set(name, value);
  }
  return {
    bytes: decodePaddedBase64url(parameters.get('challenge')),
    spki: decodePaddedBase64url(parameters.get('token-key')),
  };
}

export function issuerBaseURL(value) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error('Set the freebird-issuer meta tag to the Issuer HTTPS origin.');
  }
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search
      || url.hash || url.pathname !== '/') {
    throw new Error('The Issuer must be an HTTPS origin without a path or credentials.');
  }
  return url;
}

export function checkDirectory(json, directoryURL) {
  const directory = new URL(directoryURL);
  if (directory.protocol !== 'https:' || directory.username || directory.password) {
    throw new Error('The directory must use HTTPS without credentials.');
  }
  if (!json || typeof json !== 'object' || typeof json['issuer-request-uri'] !== 'string') {
    throw new Error('Invalid Issuer directory.');
  }
  // Do not send the admission to a different host selected by a directory.
  // An absolute HTTPS request URI on this configured Issuer is required.
  const requestURL = new URL(json['issuer-request-uri']);
  if (requestURL.protocol !== 'https:' || requestURL.origin !== directory.origin
      || requestURL.username || requestURL.password || requestURL.hash) {
    throw new Error('The issuance URI must stay on the configured Issuer.');
  }
  if (!Array.isArray(json['token-keys'])) throw new Error('Missing directory token keys.');
  const tokenKeys = json['token-keys']
    .filter(key => key && key['token-type'] === 2)
    .map(key => decodePaddedBase64url(key['token-key']));
  if (!tokenKeys.length) throw new Error('The directory has no type-2 token key.');
  return { requestURL, issuerHost: directory.host, tokenKeys };
}

export function checkChallenge(challenge, spki, directory) {
  if (challenge.tokenType !== 2) throw new Error('Expected an RFC 9578 type-2 challenge.');
  if (challenge.issuerName !== directory.issuerHost) {
    throw new Error('The challenge names a different Issuer.');
  }
  if (!directory.tokenKeys.some(key => equalBytes(key, spki))) {
    throw new Error('The Origin token key is not in the Issuer directory.');
  }
}

export function statusMessage(stage, status) {
  if (status === 403 && stage === 'Admission') {
    return 'Admission refused (403): the proof is invalid, expired or already used. Start again.';
  }
  if (status === 403) return `${stage} refused (403): the admission is invalid, expired or used. Start again.`;
  if (status === 422) return `${stage} refused (422): the Issuer key changed or does not match. Start again.`;
  if (status === 429) return `${stage} busy (429). Wait a moment, then start again.`;
  if (status === 401) return `${stage} refused (401): the token is invalid, expired or already spent. Start again.`;
  return `${stage} failed (HTTP ${status}). Start again.`;
}
