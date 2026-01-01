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
  issuerUrl: '[https://issuer.example.com](https://issuer.example.com)',
  verifierUrl: '[https://verifier.example.com](https://verifier.example.com)' // Optional, for verification
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
1. Generates random input.
2. Blinds the input.
3. Sends blinded input (+ optional Sybil proof) to Issuer.
4. Unblinds the response using the DLEQ proof.
5. Returns the usable token.

**Parameters:**
- `proof` (Optional): A `SybilProof` object if the issuer requires it (e.g. Invitation code, PoW, WebAuthn).

**Returns:**
- A `FreebirdToken` object ready for use.

**Throws:**
- Error if the issuer rejects the request (400/401/403).
- Error if the cryptographic verification (DLEQ) fails.

#### `verifyToken(token: FreebirdToken): Promise<boolean>`

Sends the token to the configured Verifier to check validity and replay status.

**Returns:**
- `true` if valid and fresh.
- `false` if expired, invalid signature, or already spent.

---

## Types

### `FreebirdToken`

The standard token object used by applications.

```typescript
interface FreebirdToken {
  /** The unblinded, base64url-encoded VOPRF output string */
  tokenValue: string;
  
  /** Unix timestamp (seconds) when this token expires */
  expiration: number;
  
  /** The ID of the issuer that signed this token */
  issuerId: string;
}
```

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