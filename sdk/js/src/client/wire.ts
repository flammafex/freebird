// SPDX-License-Identifier: Apache-2.0 OR MIT

export function concatBytes(...values: Uint8Array[]): Uint8Array {
  const length = values.reduce((sum, value) => sum + value.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

export function base64UrlToBytes(b64: string): Uint8Array {
  const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function isCanonicalBase64Url(
  value: unknown,
  exactBytes?: number,
  maxBytes?: number,
  minBytes = 0,
): boolean {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  if (maxBytes !== undefined && value.length > Math.ceil(maxBytes / 3) * 4) return false;
  try {
    const decoded = base64UrlToBytes(value);
    return bytesToBase64Url(decoded) === value &&
      (exactBytes === undefined || decoded.length === exactBytes) &&
      (maxBytes === undefined || decoded.length <= maxBytes) && decoded.length >= minBytes;
  } catch {
    return false;
  }
}

export function decodeCanonical(
  value: string,
  exactBytes?: number,
  maxBytes?: number,
  minBytes = 0,
): Uint8Array {
  if (!isCanonicalBase64Url(value, exactBytes, maxBytes, minBytes)) {
    throw new Error('Invalid canonical base64url');
  }
  return base64UrlToBytes(value);
}
