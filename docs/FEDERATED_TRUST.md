# Federated Trust Sybil Resistance

## Overview

Federated Trust is a cross-issuer Sybil resistance mechanism that allows users who already possess valid tokens from **trusted federated issuers** to request new tokens from your issuer. This creates an ecosystem where trust relationships between issuers enable users to move freely across the federation without needing to re-establish their identity with each issuer.

### Key Characteristics

- **Cross-Issuer Interoperability**: Users with tokens from trusted issuers can obtain tokens from your issuer
- **Trust Graph Based**: Leverages existing federation vouches to determine issuer trust
- **Zero User Friction**: No additional user action required beyond presenting their existing token
- **Cryptographically Verifiable**: Trust relationships are established through ECDSA-signed vouches
- **Configurable Trust Policy**: Fine-grained control over trust depth, paths, and requirements
- **Anti-Replay Protection**: Token age limits prevent replay attacks

## How It Works

### Trust Establishment

Federated Trust builds on the existing issuer-to-issuer federation infrastructure:

1. **Federation Vouches**: Issuers vouch for other issuers by creating ECDSA-signed vouches
2. **Trust Graph**: Vouches form a directed graph of trust relationships
3. **Trust Policy**: Each issuer configures how they traverse the trust graph
4. **Trust Levels**: Optional numerical trust levels (0-100) for fine-grained control

### Token Verification Flow

When a user presents a Federated Trust proof:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. User obtains token from Source Issuer (Issuer A)        │
│    Token: { user_hash, exp, signature_A }                   │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. User presents token to Target Issuer (Issuer B)         │
│    Proof: {                                                  │
│      source_issuer_id: "issuer-a.example.com",              │
│      source_token_b64: "eyJ...",                             │
│      token_exp: 1735689600,                                  │
│      trust_path: ["issuer-a", "issuer-b"]                   │
│    }                                                         │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Issuer B verifies:                                       │
│    ✓ Token hasn't expired                                   │
│    ✓ Token isn't too old (anti-replay)                      │
│    ✓ Token structure is valid                               │
│    ✓ Issuer A is in B's trust graph                         │
│    ✓ Trust path is valid (if provided)                      │
│    ✓ Trust path doesn't exceed max depth                    │
│    ✓ Issuer A is not blocked                                │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Issuer B issues new token to user                        │
└─────────────────────────────────────────────────────────────┘
```

### Trust Graph Traversal

Federated Trust supports both **direct** and **indirect** trust:

**Direct Trust**: Issuer B directly vouches for Issuer A
```
Issuer A → [vouch] → Issuer B
```

**Indirect Trust** (future): Trust through intermediaries
```
Issuer A → [vouch] → Issuer C → [vouch] → Issuer B
```

Current implementation supports direct trust only. Indirect trust graph traversal is planned.

## Configuration

### Basic Configuration

```bash
# Sybil resistance mode
SYBIL_MODE=federated_trust

# Enable federated trust
SYBIL_FEDERATED_TRUST_ENABLED=true

# Maximum trust graph depth (1 = direct trust only)
SYBIL_FEDERATED_TRUST_MAX_DEPTH=2

# Minimum number of trust paths required (future)
SYBIL_FEDERATED_TRUST_MIN_PATHS=1

# Require direct trust (ignore indirect paths)
SYBIL_FEDERATED_TRUST_REQUIRE_DIRECT=false

# Minimum trust level required (0-100)
SYBIL_FEDERATED_TRUST_MIN_TRUST_LEVEL=50

# Cache TTL for remote metadata (seconds)
SYBIL_FEDERATED_TRUST_CACHE_TTL_SECS=3600

# Maximum acceptable token age (seconds)
SYBIL_FEDERATED_TRUST_MAX_TOKEN_AGE_SECS=600

# Trusted root issuers (comma-separated)
SYBIL_FEDERATED_TRUST_TRUSTED_ROOTS=issuer:root:v1,issuer:authority:v2

# Blocked issuers (comma-separated)
SYBIL_FEDERATED_TRUST_BLOCKED_ISSUERS=issuer:untrusted:v1
```

### Configuration Profiles

#### Strict Trust (High Security)

Only accept tokens from directly vouched issuers with high trust levels:

```bash
SYBIL_MODE=federated_trust
SYBIL_FEDERATED_TRUST_ENABLED=true
SYBIL_FEDERATED_TRUST_MAX_DEPTH=1           # Direct trust only
SYBIL_FEDERATED_TRUST_REQUIRE_DIRECT=true   # No indirect paths
SYBIL_FEDERATED_TRUST_MIN_TRUST_LEVEL=80    # High trust required
SYBIL_FEDERATED_TRUST_MAX_TOKEN_AGE_SECS=300  # 5 minute window
SYBIL_FEDERATED_TRUST_TRUSTED_ROOTS=issuer:known:v1
```

**Best for**: High-security applications, financial services, sensitive data access

#### Moderate Trust (Balanced)

Accept tokens from trusted issuers with moderate trust depth:

```bash
SYBIL_MODE=federated_trust
SYBIL_FEDERATED_TRUST_ENABLED=true
SYBIL_FEDERATED_TRUST_MAX_DEPTH=2           # One intermediary allowed
SYBIL_FEDERATED_TRUST_REQUIRE_DIRECT=false  # Allow indirect paths
SYBIL_FEDERATED_TRUST_MIN_TRUST_LEVEL=50    # Moderate trust
SYBIL_FEDERATED_TRUST_MAX_TOKEN_AGE_SECS=600  # 10 minute window
SYBIL_FEDERATED_TRUST_TRUSTED_ROOTS=issuer:root:v1,issuer:partner:v1
```

**Best for**: General-purpose applications, content platforms, community services

#### Permissive Trust (Maximum Interoperability)

Maximize federation reach with deeper trust graph traversal:

```bash
SYBIL_MODE=federated_trust
SYBIL_FEDERATED_TRUST_ENABLED=true
SYBIL_FEDERATED_TRUST_MAX_DEPTH=3           # Two intermediaries allowed
SYBIL_FEDERATED_TRUST_REQUIRE_DIRECT=false  # Allow indirect paths
SYBIL_FEDERATED_TRUST_MIN_TRUST_LEVEL=30    # Lower threshold
SYBIL_FEDERATED_TRUST_MAX_TOKEN_AGE_SECS=1800  # 30 minute window
SYBIL_FEDERATED_TRUST_TRUSTED_ROOTS=issuer:root:v1
SYBIL_FEDERATED_TRUST_BLOCKED_ISSUERS=issuer:known-bad:v1
```

**Best for**: Open platforms, public services, maximum user reach

## API Integration

### Client-Side: Presenting a Federated Trust Proof

```typescript
import { FreebirdClient } from '@freebird/sdk';

// User has a token from Issuer A
const sourceToken = {
  tokenValue: "eyJhbGciOiJFUzI1NiJ9...",
  expiration: 1735689600,
  issuerId: "issuer-a.example.com"
};

// Create Federated Trust proof
const proof = {
  type: 'federated_trust' as const,
  source_issuer_id: sourceToken.issuerId,
  source_token_b64: sourceToken.tokenValue,
  token_exp: sourceToken.expiration,
  trust_path: [] // Optional: leave empty for automatic discovery
};

// Request token from Issuer B using Federated Trust
const client = new FreebirdClient({
  issuerUrl: 'https://issuer-b.example.com'
});

const newToken = await client.issueToken({
  input: "user-id-hash",
  sybilProof: proof
});
```

### Server-Side: Creating Federation Vouches

Use the admin API to vouch for other issuers:

```bash
# Vouch for Issuer A
curl -X POST https://your-issuer.example.com/admin/federation/vouch \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vouched_issuer_id": "issuer-a.example.com",
    "vouched_pubkey": "BMw1...",
    "expires_at": 1767225600,
    "trust_level": 80
  }'

# List your current vouches
curl https://your-issuer.example.com/.well-known/federation \
  | jq '.vouches'

# Revoke a vouch
curl -X POST https://your-issuer.example.com/admin/federation/revoke \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vouched_issuer_id": "issuer-a.example.com",
    "reason": "Trust policy changed"
  }'
```

## Trust Graph Concepts

### Trust Roots

**Trusted roots** are issuers you unconditionally trust, regardless of vouches:

```bash
SYBIL_FEDERATED_TRUST_TRUSTED_ROOTS=issuer:root:v1,issuer:authority:v2
```

Typical use cases:
- **Root Certificate Authorities**: Well-known, highly trusted issuers
- **Partner Organizations**: Organizations you have formal agreements with
- **Self**: Your own issuer ID (for multi-instance deployments)

### Blocked Issuers

**Blocked issuers** are explicitly distrusted and rejected:

```bash
SYBIL_FEDERATED_TRUST_BLOCKED_ISSUERS=issuer:malicious:v1,issuer:compromised:v2
```

Use for:
- Known compromised issuers
- Issuers that violated trust policies
- Regulatory compliance requirements

### Trust Levels

Trust levels (0-100) provide fine-grained trust control:

- **0-30**: Low trust - testing, experimental issuers
- **31-60**: Moderate trust - community issuers, known but not vetted
- **61-80**: High trust - partner issuers, established organizations
- **81-100**: Maximum trust - root authorities, critical partners

Configure minimum required level:

```bash
SYBIL_FEDERATED_TRUST_MIN_TRUST_LEVEL=50
```

### Trust Depth

Trust depth controls how many "hops" are allowed in the trust graph:

- **Depth 1**: Direct trust only (A → B)
- **Depth 2**: One intermediary (A → C → B)
- **Depth 3**: Two intermediaries (A → D → C → B)

```bash
SYBIL_FEDERATED_TRUST_MAX_DEPTH=2
```

Higher depth increases user reach but dilutes trust. Start with depth 1 and increase carefully.

## Security Analysis

### Threat Model

Federated Trust protects against:

✅ **Sybil Attacks from Untrusted Sources**: Only tokens from trusted issuers are accepted
✅ **Token Replay**: Token age limits prevent old tokens from being reused
✅ **Unauthorized Issuers**: Blocked issuer list prevents known bad actors
✅ **Trust Dilution**: Max depth and min trust level limit trust graph traversal
✅ **Compromised Intermediaries**: Trust path validation ensures path integrity

### Attack Vectors

⚠️ **Compromised Trusted Issuer**: If a trusted issuer is compromised, attacker can generate unlimited tokens
- **Mitigation**: Regularly audit trusted roots, use revocation, monitor for anomalies

⚠️ **Trust Graph Manipulation**: Attacker creates complex trust paths to gain access
- **Mitigation**: Require direct trust, limit max depth, maintain blocked issuer list

⚠️ **Token Theft**: Stolen tokens can be used to obtain new tokens
- **Mitigation**: Short token age limits, rate limiting, anomaly detection

⚠️ **Vouch Spam**: Malicious issuer creates many vouches to appear trusted
- **Mitigation**: Use trusted roots, require minimum trust level, manual vetting

### Best Practices

1. **Start Conservative**: Begin with `REQUIRE_DIRECT=true` and `MAX_DEPTH=1`
2. **Vet Trusted Roots**: Only add issuers you have verified out-of-band
3. **Monitor Vouches**: Regularly review your vouches via `/.well-known/federation`
4. **Use Trust Levels**: Assign appropriate trust levels based on relationship strength
5. **Revoke Quickly**: Immediately revoke vouches for compromised issuers
6. **Combine Mechanisms**: Use Federated Trust WITH other Sybil resistance (defense-in-depth)
7. **Audit Regularly**: Review trusted roots and vouches quarterly
8. **Set Age Limits**: Use short `MAX_TOKEN_AGE_SECS` for sensitive applications

## Use Cases

### 1. Academic Consortium

Universities form a federation where students can access resources across institutions:

```
Stanford vouches for MIT (trust_level: 90)
MIT vouches for Harvard (trust_level: 90)
Harvard vouches for Princeton (trust_level: 85)

Student at Stanford can access:
- MIT resources (direct vouch, depth 1)
- Harvard resources (indirect through MIT, depth 2)
- Princeton resources (indirect through MIT→Harvard, depth 3)
```

Configuration:
```bash
SYBIL_FEDERATED_TRUST_MAX_DEPTH=3
SYBIL_FEDERATED_TRUST_MIN_TRUST_LEVEL=80
SYBIL_FEDERATED_TRUST_TRUSTED_ROOTS=stanford.edu,mit.edu
```

### 2. Healthcare Network

Medical providers federate to enable patient access across facilities:

```
Hospital A vouches for Clinic B (trust_level: 95)
Clinic B vouches for Lab C (trust_level: 90)

Patient with token from Hospital A can:
- Access Clinic B (direct trust)
- Access Lab C (indirect trust via Clinic B)
```

Configuration (strict security):
```bash
SYBIL_FEDERATED_TRUST_MAX_DEPTH=2
SYBIL_FEDERATED_TRUST_MIN_TRUST_LEVEL=90
SYBIL_FEDERATED_TRUST_REQUIRE_DIRECT=false
SYBIL_FEDERATED_TRUST_MAX_TOKEN_AGE_SECS=300
```

### 3. Open Source Community

Projects federate to enable contributor access across codebases:

```
Rust Foundation vouches for various project issuers
Each project issues tokens to active contributors
Contributors can access tools/resources across federation
```

Configuration (permissive):
```bash
SYBIL_FEDERATED_TRUST_MAX_DEPTH=2
SYBIL_FEDERATED_TRUST_MIN_TRUST_LEVEL=50
SYBIL_FEDERATED_TRUST_TRUSTED_ROOTS=rust-foundation.org
```

### 4. Enterprise Multi-Cloud

Enterprises federate across cloud providers for unified access:

```
AWS GovCloud vouches for Azure Government (trust_level: 95)
Both vouch for internal corporate issuer (trust_level: 100)

Employees can access:
- AWS resources (via corp issuer)
- Azure resources (via corp issuer)
- Cross-cloud tools (via any trusted issuer)
```

Configuration:
```bash
SYBIL_FEDERATED_TRUST_MAX_DEPTH=2
SYBIL_FEDERATED_TRUST_REQUIRE_DIRECT=true
SYBIL_FEDERATED_TRUST_MIN_TRUST_LEVEL=95
SYBIL_FEDERATED_TRUST_TRUSTED_ROOTS=corp.example.com
```

## Combining with Other Mechanisms

Federated Trust works well with other Sybil resistance mechanisms for defense-in-depth:

### Federated Trust + Rate Limiting

Accept federated tokens but limit issuance rate:

```bash
SYBIL_MODE=combined

# Accept both federated trust and rate limiting
# Federated users still subject to rate limits
```

Use for: Public services that trust federation but need DoS protection

### Federated Trust + Progressive Trust

Federated tokens establish initial trust, then progressive trust takes over:

```bash
# User presents federated token → gets initial token (trust level 1)
# After time/usage → trust level increases → higher limits
```

Use for: Platforms where federated users start with limited access

### Federated Trust + WebAuthn

Federated token + hardware key = high-assurance authentication:

```bash
SYBIL_MODE=combined
# Require BOTH federated token AND WebAuthn proof
```

Use for: Maximum security applications, zero-trust architectures

### Federated Trust + Multi-Party Vouching

Federated token establishes identity, vouches establish reputation:

```bash
# User from federated issuer can participate immediately
# But needs vouches to unlock premium features
```

Use for: Social platforms, community-driven services

## Data Formats

### Federated Trust Proof

```typescript
interface FederatedTrustProof {
  type: 'federated_trust';

  // Source issuer that issued the original token
  source_issuer_id: string;

  // Base64url-encoded token from source issuer
  source_token_b64: string;

  // Expiration timestamp of source token (Unix seconds)
  token_exp: number;

  // Trust path from source to target (optional)
  // Example: ["issuer-a.com", "issuer-b.com", "issuer-c.com"]
  trust_path: string[];
}
```

### Federation Vouch

```rust
pub struct Vouch {
    // Issuer creating the vouch
    pub voucher_issuer_id: String,

    // Issuer being vouched for
    pub vouched_issuer_id: String,

    // Public key of vouched issuer (for verification)
    pub vouched_pubkey: Vec<u8>,

    // Vouch expiration (Unix timestamp)
    pub expires_at: i64,

    // Vouch creation time
    pub created_at: i64,

    // Optional trust level (0-100)
    pub trust_level: Option<u8>,

    // ECDSA P-256 signature
    pub signature: [u8; 64],
}
```

### Federation Metadata

Available at `/.well-known/federation`:

```json
{
  "issuer_id": "issuer-a.example.com",
  "vouches": [
    {
      "voucher_issuer_id": "issuer-a.example.com",
      "vouched_issuer_id": "issuer-b.example.com",
      "vouched_pubkey": "BMw1aKNx...",
      "expires_at": 1767225600,
      "created_at": 1735689600,
      "trust_level": 80,
      "signature": "MEUCIQDXq..."
    }
  ],
  "revocations": [],
  "updated_at": 1735689600,
  "cache_ttl_secs": 3600
}
```

## Comparison to Other Mechanisms

| Feature | Federated Trust | Invitation | Multi-Party Vouching |
|---------|----------------|------------|---------------------|
| **User Friction** | None | Low | None (after vouches) |
| **Cross-Issuer** | ✅ Yes | ❌ No | ❌ No |
| **Sybil Resistance** | Medium | High | Very High |
| **Setup Complexity** | Medium | Low | Medium |
| **Trust Model** | Issuer-based | User-based | Social consensus |
| **Scalability** | Excellent | Good | Good |
| **Privacy** | High | High | High |

**When to use Federated Trust:**
- ✅ Building a federation of related services
- ✅ Users already have tokens from trusted issuers
- ✅ Want zero friction for federated users
- ✅ Have established trust relationships with other issuers
- ✅ Need cross-organizational interoperability

**When NOT to use Federated Trust:**
- ❌ No trusted issuers exist yet (bootstrap problem)
- ❌ Need maximum Sybil resistance (use Multi-Party Vouching instead)
- ❌ Cannot establish out-of-band trust with other issuers
- ❌ Standalone application with no federation needs

## Monitoring and Observability

### Key Metrics to Track

1. **Federated Token Requests**: Count of requests with federated trust proofs
2. **Trust Path Lengths**: Distribution of trust path depths
3. **Source Issuer Distribution**: Which issuers are most common sources
4. **Rejection Reasons**: Why federated proofs are rejected
5. **Vouch Expiration**: Upcoming vouch expirations
6. **Trust Level Distribution**: Distribution of trust levels in accepted proofs

### Logging

Enable detailed logging for Federated Trust:

```rust
// Logs emitted at startup
info!("✅ Sybil resistance: Federated Trust");

// Logs during verification
debug!("Verifying federated trust proof from issuer: {}", source_issuer_id);
debug!("Trust path: {:?}", trust_path);
warn!("Rejected federated proof: {}", reason);
```

### Alerting

Set up alerts for:
- **Vouch expiration warnings** (7 days before expiry)
- **Unusual source issuer** (new issuer ID appearing)
- **High rejection rate** (>10% federated proofs rejected)
- **Blocked issuer attempts** (tokens from blocked issuers)

## Future Enhancements

### Trust Graph Traversal

Current implementation supports direct trust only. Future versions will support:

- **Multi-hop trust paths**: A → C → B
- **Multiple path requirements**: Require N independent paths
- **Path weight calculation**: Score paths by trust levels
- **Cycle detection**: Prevent circular trust relationships

### Token Cryptographic Verification

Currently only validates token structure. Future versions will:

- **Verify token signatures**: Cryptographically verify source issuer signature
- **Validate DLEQ proofs**: Ensure tokens are valid VOPRF outputs
- **Check revocation**: Query source issuer revocation lists

### Remote Metadata Caching

Future versions will cache remote issuer metadata:

- **HTTP fetching**: Fetch `/.well-known/federation` from source issuers
- **TTL management**: Respect cache TTL from remote issuers
- **Background refresh**: Automatically refresh expiring metadata

### Trust Scores

Compute aggregate trust scores:

- **Path diversity**: More paths = higher score
- **Trust level aggregation**: Combine trust levels across paths
- **Issuer reputation**: Historical behavior influences score

## Conclusion

Federated Trust enables seamless cross-issuer interoperability by leveraging existing trust relationships. It provides:

- **Zero friction** for users with federated tokens
- **Configurable trust policies** for fine-grained control
- **Cryptographically verifiable** trust relationships
- **Defense-in-depth** when combined with other mechanisms

Start with strict configuration (direct trust, high trust levels) and gradually expand your federation as you build trust relationships with other issuers.

For questions or issues, see the [Freebird documentation](https://github.com/flammafex/freebird) or open an issue.
