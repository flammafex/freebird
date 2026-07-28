// SPDX-License-Identifier: Apache-2.0 OR MIT

import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';

const HMAC_AUTHORIZATION_DOMAIN = new TextEncoder().encode(
  'freebird graph issuance hmac authorization v2\0'
);

const ascii = (value: string): Uint8Array => new TextEncoder().encode(value);

const concat = (...values: Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
};

const put = (output: number[], value: Uint8Array): void => {
  output.push(
    (value.length >>> 24) & 0xff,
    (value.length >>> 16) & 0xff,
    (value.length >>> 8) & 0xff,
    value.length & 0xff,
    ...value,
  );
};

const toBase64Url = (value: Uint8Array): string => {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const fromBase64Url = (value: string, expectedBytes: number): Uint8Array => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Invalid canonical graph issuance HMAC authorization');
  }
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '=');
  let decoded: Uint8Array;
  try {
    const binary = atob(padded);
    decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new Error('Invalid canonical graph issuance HMAC authorization');
  }
  if (decoded.length !== expectedBytes || toBase64Url(decoded) !== value) {
    throw new Error('Invalid canonical graph issuance HMAC authorization');
  }
  return decoded;
};

const validateFixed = (value: Uint8Array, length: number, name: string): void => {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`${name} must be exactly ${length} bytes`);
  }
};

const validatePolicyId = (policyId: string): void => {
  if (typeof policyId !== 'string' || policyId.length === 0 || policyId.length > 128 ||
      !/^[\x00-\x7F]+$/.test(policyId)) {
    throw new Error('Invalid graph issuance policy ID');
  }
};

/** Build the raw V2 HMAC authorization transcript used by the issuer. */
export function graphIssuanceHmacAuthorizationTranscriptV2(
  nonce: Uint8Array,
  policyId: string,
  authorizationBindingDigest: Uint8Array,
): Uint8Array {
  validateFixed(nonce, 32, 'HMAC nonce');
  validateFixed(authorizationBindingDigest, 32, 'Authorization binding digest');
  validatePolicyId(policyId);
  const framedPolicy: number[] = [];
  put(framedPolicy, ascii(policyId));
  return concat(
    HMAC_AUTHORIZATION_DOMAIN,
    nonce,
    new Uint8Array(framedPolicy),
    authorizationBindingDigest,
  );
}

/** Return the raw V2 HMAC-SHA256 tag. */
export function graphIssuanceHmacAuthorizationTagV2(
  secret: Uint8Array,
  nonce: Uint8Array,
  policyId: string,
  authorizationBindingDigest: Uint8Array,
): Uint8Array {
  if (!(secret instanceof Uint8Array) || secret.length === 0) {
    throw new Error('Invalid HMAC secret');
  }
  return hmac(sha256, secret, graphIssuanceHmacAuthorizationTranscriptV2(
    nonce, policyId, authorizationBindingDigest
  ));
}

/** Construct canonical `nonce_raw || tag_raw` authorization bytes. */
export function buildGraphIssuanceHmacAuthorizationV2(
  secret: Uint8Array,
  nonce: Uint8Array,
  policyId: string,
  authorizationBindingDigest: Uint8Array,
): string {
  const tag = graphIssuanceHmacAuthorizationTagV2(
    secret, nonce, policyId, authorizationBindingDigest
  );
  return toBase64Url(concat(nonce, tag));
}

/** Parse a canonical V2 authorization into its raw nonce and tag. */
export function parseGraphIssuanceHmacAuthorizationV2(
  authorization: string,
): { nonce: Uint8Array; tag: Uint8Array } {
  const bytes = fromBase64Url(authorization, 64);
  return { nonce: bytes.slice(0, 32), tag: bytes.slice(32) };
}

/** Verify a V2 authorization and return its raw nonce. */
export function verifyGraphIssuanceHmacAuthorizationV2(
  secret: Uint8Array,
  policyId: string,
  authorizationBindingDigest: Uint8Array,
  authorization: string,
): Uint8Array {
  const { nonce, tag } = parseGraphIssuanceHmacAuthorizationV2(authorization);
  const expected = graphIssuanceHmacAuthorizationTagV2(
    secret, nonce, policyId, authorizationBindingDigest
  );
  let difference = 0;
  for (let index = 0; index < expected.length; index++) difference |= expected[index] ^ tag[index];
  if (difference !== 0) throw new Error('Invalid graph issuance HMAC authorization');
  return nonce;
}

// Short aliases mirror the common crate utility names for vector consumers.
export const hmacAuthorizationTranscriptV2 = graphIssuanceHmacAuthorizationTranscriptV2;
export const hmacAuthorizationTagV2 = graphIssuanceHmacAuthorizationTagV2;
export const buildHmacAuthorizationV2 = buildGraphIssuanceHmacAuthorizationV2;
export const parseHmacAuthorizationV2 = parseGraphIssuanceHmacAuthorizationV2;
export const verifyHmacAuthorizationV2 = verifyGraphIssuanceHmacAuthorizationV2;
