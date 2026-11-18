// Privacy Pass headers and the Issuer directory use canonical padded base64url.
// The encoding and decoding use APIs that are available in browsers and Node.js 16 or later.

const CANONICAL = /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)?$/;

export function encodePaddedBase64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_');
}

export function decodePaddedBase64url(value) {
  if (typeof value !== 'string' || value.length === 0 || !CANONICAL.test(value)) {
    throw new RangeError('Expected canonical padded base64url.');
  }
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')),
    character => character.charCodeAt(0));
  // Re-encoding rejects nonzero padding bits that `atob` accepts.
  if (encodePaddedBase64url(bytes) !== value) {
    throw new RangeError('Expected canonical padded base64url.');
  }
  return bytes;
}

export function equalBytes(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}
