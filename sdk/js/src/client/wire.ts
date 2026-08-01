// SPDX-License-Identifier: Apache-2.0 OR MIT

import { sha256 } from '@noble/hashes/sha256';

export function ascii(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

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

export function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function domainHex(domain: string, value: Uint8Array): string {
  return hex(sha256(concatBytes(ascii(domain), value)));
}

export function isLowerHexId(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

export function isSafeUnsigned(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

export function isSafePositive(value: unknown): value is number {
  return isSafeUnsigned(value) && value > 0;
}

export function isBoundedAscii(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 128 &&
    /^[\x00-\x7F]+$/.test(value);
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

export function hasExactKeys(value: unknown, keys: string[]): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const actualKeys = Object.keys(value);
  return actualKeys.length === keys.length && keys.every((key) => actualKeys.includes(key));
}

export function put(output: number[], value: Uint8Array): void {
  pushU32(output, value.length);
  output.push(...value);
}

export function pushU32(output: number[], value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error('Integer is outside the V2 exchange wire range');
  }
  output.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

export function pushU64(output: number[], value: number): void {
  if (!isSafeUnsigned(value)) throw new Error('Invalid V2 exchange integer');
  let integer = BigInt(value);
  const bytes = new Array<number>(8);
  for (let index = 7; index >= 0; index--) {
    bytes[index] = Number(integer & 0xffn);
    integer >>= 8n;
  }
  output.push(...bytes);
}

export function pushI64(output: number[], value: number): void {
  if (!Number.isSafeInteger(value)) throw new Error('Invalid V2 exchange integer');
  let integer = BigInt.asUintN(64, BigInt(value));
  const bytes = new Array<number>(8);
  for (let index = 7; index >= 0; index--) {
    bytes[index] = Number(integer & 0xffn);
    integer >>= 8n;
  }
  output.push(...bytes);
}
