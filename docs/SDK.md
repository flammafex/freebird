# 📦 Freebird SDK Documentation

The Freebird SDK provides a TypeScript/JavaScript client for issuing and verifying anonymous tokens using the VOPRF protocol.

---

## Installation

```bash
npm install @freebird/sdk
```

**Requirements:**
- Node.js 18+ (for `fetch` and `crypto` API support)
- Modern browsers (Edge, Chrome, Firefox, Safari)

---

## Quick Start

```typescript
import { FreebirdClient } from '@freebird/sdk';

// 1. Configure
const client = new FreebirdClient({
  issuerUrl: 'https://issuer.example.com',
  verifierUrl: 'https://verifier.example.com' // Optional, for verification
});

async function main() {
  // 2. Initialize (fetches server public key)
  await client.init();

  // 3. Issue an anonymous token
  try {
    const token = await client.issueToken();
    console.log('Got token:', token.tokenValue);
    console.log('Expires at:', new Date(token.expiration * 1000));

    // 4. Verify (optional client-side check)
    const isValid = await client.verifyToken(token);
    console.log('Token valid:', isValid);

  } catch (e) {
    console.error('Issuance failed:', e);
  }
}

main();
```

---

## API Reference

### `FreebirdClient`

The main entry point for the SDK.

#### `constructor(config: ClientConfig)`

Creates a new client instance.

| Option | Type | Description |
|--------|------|-------------|
| `issuerUrl` | `string` | (Required) Base URL of the Freebird Issuer service. |
| `verifierUrl` | `string` | (Optional) Base URL of the Freebird Verifier service. Required only if you call `verifyToken()`. |

```typescript
const client = new FreebirdClient({
  issuerUrl: 'http://localhost:8081',
  verifierUrl: 'http://localhost:8082'
});
```

#### `init(): Promise<void>`

Fetches the issuer's metadata (public key, key ID, supported cipher suites) from `/.well-known/issuer`.

**Note:** You must await `init()` before issuing tokens. If you call `issueToken()` without initializing, it will attempt to auto-initialize, but explicit initialization is best practice.

#### `issueToken(proof?: SybilProof): Promise<FreebirdToken>`

Performs the full VOPRF issuance flow:
1. Generates random input and blinds it.
2. Sends blinded input (+ optional Sybil proof) to Issuer.
3. Verifies the DLEQ proof (confirms issuer honesty).
4. Unblinds the evaluation to obtain the PRF output.
5. Builds a self-contained V3 redemption token from the output + metadata + ECDSA signature.
6. Returns the usable token.

**Parameters:**
- `proof` (Optional): A `SybilProof` object if the issuer requires it (e.g. Invitation code, PoW, WebAuthn).

**Returns:**
- A `FreebirdToken` object ready for use.

**Throws:**
- Error if the issuer rejects the request (400/401/403).
- Error if the cryptographic verification (DLEQ) fails.

#### `verifyToken(token: FreebirdToken): Promise<boolean>`

Sends the V3 redemption token to the configured Verifier. The token is self-contained — the verifier extracts all needed fields (expiration, issuer ID, ECDSA signature) from the token itself.

**Returns:**
- `true` if valid and fresh.
- `false` if expired, invalid ECDSA signature, or already spent.

---

## Types

### `FreebirdToken`

The standard token object used by applications.

```typescript
interface FreebirdToken {
  /** Base64url-encoded V3 redemption token (self-contained) */
  tokenValue: string;

  /** Unix timestamp (seconds) when this token expires (extracted for convenience) */
  expiration: number;

  /** The ID of the issuer that signed this token (extracted for convenience) */
  issuerId: string;
}
```

The `tokenValue` is a self-contained V3 redemption token containing the unblinded PRF output, key ID, expiration, issuer ID, and ECDSA signature. It can be sent directly to the verifier without any additional fields.

### `SybilProof`

A union type representing the different proofs you can provide to the issuer.

#### 1. Invitation
Used for invite-only communities.

```typescript
const proof = {
  type: 'invitation',
  code: 'Abc123XyZ...',       // The invitation code
  signature: '304502...'      // The cryptographic signature provided with the code
};
```

#### 2. WebAuthn (Passkey)
Used for hardware-backed "Proof of Humanity".

```typescript
const proof = {
  type: 'webauthn',
  username: 'alice',
  auth_proof: 'base64...',    // Returned from /webauthn/authenticate/finish
  timestamp: 1699454445       // Authentication timestamp
};
```

#### 3. Proof of Work
Used for permissionless spam prevention.

```typescript
const proof = {
  type: 'proof_of_work',
  nonce: 12345,
  input: 'challenge_string',
  timestamp: 1699454445
};
```

#### 4. Rate Limit
Used for IP/Fingerprint throttling.

```typescript
const proof = {
  type: 'rate_limit',
  client_id: 'hashed_id',
  timestamp: 1699454445
};
```

#### 5. Registered User
Used for users already in the system (e.g., instance owner). Bypasses the invitation requirement for existing database users.

```typescript
const proof = {
  type: 'registered_user',
  user_id: 'alice'
};
```

#### 6. Progressive Trust
Used for time-based reputation building.

```typescript
const proof = {
  type: 'progressive_trust',
  user_id_hash: 'blake3-hash',   // Blake3(username + salt)
  first_seen: 1699000000,
  tokens_issued: 10,
  last_issuance: 1699454445,
  hmac_proof: 'base64url...'
};
```

#### 7. Multi-Party Vouching
Used when multiple users must vouch for the requester.

```typescript
const proof = {
  type: 'multi_party_vouching',
  vouchee_id_hash: 'blake3-hash',
  vouches: [
    {
      voucher_id: 'alice',
      vouchee_id: 'bob',
      timestamp: 1699454445,
      signature: 'base64url...',
      voucher_pubkey_b64: 'base64url...'
    }
  ],
  hmac_proof: 'base64url...',
  timestamp: 1699454445
};
```

---

## Error Handling

All SDK methods throw standard `Error` objects on failure. The error message contains a human-readable description.

```typescript
try {
  const token = await client.issueToken(proof);
} catch (e: unknown) {
  if (e instanceof Error) {
    // Issuer rejected the request (HTTP 400/401/403)
    if (e.message.includes('403')) {
      console.error('Sybil proof rejected');
    }
    // DLEQ proof verification failure (issuer misbehavior)
    if (e.message.includes('DLEQ')) {
      console.error('Issuer cheated: DLEQ proof invalid');
    }
  }
}
```

**Common errors:**

| Condition | Typical message |
|-----------|----------------|
| Invalid sybil proof | `"Issuer returned 403: Sybil resistance proof failed"` |
| No sybil proof provided when required | `"Issuer returned 403: Sybil resistance proof required"` |
| DLEQ verification fails | `"DLEQ proof verification failed"` |
| Network error | `"fetch failed"` or `"NetworkError"` |
| Token already spent | `"Verifier returned 401: token already spent"` |
| Token expired | `"Verifier returned 401: token expired"` |

---

## Low-Level Crypto API

The SDK exports low-level cryptographic primitives for advanced use cases. These are available as `crypto.*` from the package root.

```typescript
import { crypto } from '@freebird/sdk';
```

### `crypto.blind(input, context)`

Blinds a byte array for the VOPRF protocol. Returns the blinded element and a `BlindState` needed for finalization.

```typescript
const { blinded, state } = crypto.blind(
  new TextEncoder().encode('my-secret-input'),
  new TextEncoder().encode('freebird-voprf-v1')
);
// blinded: Uint8Array — 33-byte SEC1 compressed P-256 point
// state: BlindState — contains scalar r and point P for finalization
```

### `crypto.finalize(state, evaluationB64, kid, exp, issuerId)`

Finalizes the VOPRF by unblinding the server's evaluation and building the V3 redemption token.

```typescript
const token = await crypto.finalize(
  state,
  serverEvaluationBase64,  // from IssueResp.token
  kid,                     // from IssueResp.kid
  exp,                     // from IssueResp.exp
  issuerId                 // from IssueResp.issuer_id
);
```

### `crypto.buildRedemptionToken(output, kid, exp, issuerId, sig)`

Assembles a V3 redemption token from its components. Used after unblinding.

```typescript
const tokenBytes = crypto.buildRedemptionToken(output, kid, exp, issuerId, sig);
```

### `crypto.parseRedemptionToken(bytes)`

Parses a V3 redemption token binary back into its components.

```typescript
const { output, kid, exp, issuerId, sig } = crypto.parseRedemptionToken(tokenBytes);
```

---

## Browser vs. Node.js Differences

The SDK uses `@noble/curves` and `@noble/hashes` for all elliptic curve and hash operations. These are pure-JavaScript implementations with no native dependencies and work identically in both environments.

**Fetch:** The SDK uses the global `fetch` API, available in:
- Node.js 18+ (built-in)
- All modern browsers (Chrome, Firefox, Safari, Edge)
- For older Node.js: use `node-fetch` as a polyfill

**Random scalar generation:** Uses `crypto.getRandomValues()` (Web Crypto API) — available in Node.js 15+ and all modern browsers.

**Module format:** The package ships both ESM and CJS bundles (via `tsup`). Import style:

```typescript
// ESM (recommended)
import { FreebirdClient } from '@freebird/sdk';

// CommonJS
const { FreebirdClient } = require('@freebird/sdk');
```

**WASM/native:** No WASM or native bindings are used. The SDK is pure TypeScript/JavaScript.