# Security Model

Freebird provides anonymous authorization, not network anonymity. It lets a verifier decide "this bearer is authorized" without learning who the bearer is.

---

## Security Goals

### Unlinkability

The issuer should not be able to link an issuance request to a later redemption by looking at token cryptography.

- V4 uses P-256 VOPRF blinding.
- V5 uses RFC 9474 blind RSA signatures.

### Unforgeability

An attacker should not be able to create a valid token without issuer signing authority.

- V4 relies on the issuer VOPRF secret key and verifier recomputation.
- V5 relies on the issuer RSA blind-signature secret key and public signature verification.

### Single Use

A token should be accepted once.

- The verifier stores deterministic nullifiers.
- Redis is recommended for production.
- In-memory replay storage is only for local testing.

### Issuer Trust

The verifier should accept tokens only from configured issuers.

- V4 requires trusted issuer metadata plus private verification key material.
- V5 requires trusted issuer metadata plus strict public key metadata policy.

## Token Modes

### V4 Private Option

V4 is verifier-bound and privacy-maximal.

Security properties:

- clients verify issuer honesty with DLEQ during issuance;
- token scope includes verifier ID and audience;
- verifiers recompute authenticators locally;
- verifiers do not phone home to issuers at redemption time;
- replay records do not expire while the verifier accepts the key.

Main operational risk:

- the verifier must hold VOPRF private verification key material. Protect it like issuer signing authority.

### V5 Public Option

V5 is a public bearer pass.

Security properties:

- issuance uses RFC 9474 blind RSA signatures;
- `token_key_id = SHA-256(pubkey_spki)`;
- verifiers validate public key metadata before accepting tokens;
- optional issuer metadata `audience` can restrict tokens to a verifier audience;
- replay records expire at public key `valid_until`.

Main operational risk:

- because verification is public, any verifier that trusts the issuer metadata can validate V5 tokens. Use `PUBLIC_BEARER_AUDIENCE` when public tokens should be audience-specific.

## Threat Model

We assume attackers can:

- observe network traffic;
- request tokens if they satisfy the Sybil policy;
- steal bearer tokens in transit or from client storage;
- replay spent tokens;
- run malicious clients;
- compromise one trusted issuer if operational controls fail.

We assume attackers cannot:

- break P-256 discrete log;
- forge RFC 9474 RSA-PSS signatures;
- find useful SHA-256 or SHA-384 preimages;
- bypass a correctly configured replay store;
- extract keys from properly managed secret storage or HSMs.

## Attacks and Mitigations

### Token Theft

Tokens are bearer credentials. Anyone who obtains a token can spend it first.

Mitigations:

- use HTTPS everywhere;
- avoid logging token bodies;
- keep tokens short-lived operationally;
- spend tokens promptly;
- protect browser, mobile, or server-side token storage.

### Replay

Reusing the same token should fail.

Mitigations:

- use Redis or durable replay storage in production;
- monitor replay failures;
- treat replay store loss as an incident.

### Timing Correlation

An issuer and verifier can compare logs and timing to guess which issuance became which redemption.

Mitigations:

- run issuer and verifier as separate services;
- minimize logs and avoid token material in logs;
- use batching, delay, Tor, VPNs, or other network privacy controls when needed;
- keep administrative access separate.

### Malicious Issuer Tagging

A malicious issuer might try to tag users by issuing malformed or key-specific outputs.

Mitigations:

- V4 clients verify DLEQ proofs before unblinding;
- clients should fetch fresh issuer metadata;
- verifiers should trust only configured issuers;
- communities should rotate and distrust issuers that violate policy.

### Issuer Key Compromise

If an issuer key is compromised, tokens for that key are no longer trustworthy.

Mitigations:

- rotate compromised keys immediately;
- remove compromised V4 key IDs from verifier keyrings;
- rotate V5 public bearer key and metadata;
- use secret managers or HSM-backed storage;
- monitor unusual issuance rates.

### V5 Metadata Misconfiguration

V5 key metadata is part of the trust decision.

Mitigations:

- rotate keys rather than editing immutable metadata;
- keep `spend_policy = "single_use"`;
- use `PUBLIC_BEARER_AUDIENCE` for audience-specific deployments;
- keep validity windows short enough for operational recovery.

## Cryptographic Assumptions

| Component | Algorithm | Role |
|-----------|-----------|------|
| V4 VOPRF | P-256, SHA-256, DLEQ | Blind private issuance and client verifiability |
| V4 nullifier | SHA-256 | Replay detection |
| V5 blind signatures | RFC 9474 RSABSSA-SHA384-PSS-Deterministic | Blind public bearer issuance |
| V5 message digest | SHA-384 | Protocol message binding |
| V5 token key ID | SHA-256 | Public key identity |
| Invitation signing | P-256 ECDSA | Invitation authenticity |

Freebird is not post-quantum. P-256 and RSA are vulnerable to large future quantum computers.

## Operational Requirements

- Use TLS in production.
- Use Redis for verifier replay storage.
- Keep issuer and verifier secrets out of Git.
- Store V4 private verification keys as secrets.
- Store V5 RSA private keys as secrets.
- Back up Sybil-resistance state.
- Keep issuer and verifier clocks synchronized.
- Avoid putting token bodies, blinded messages, signatures, or private keys in logs.

## Privacy Boundaries

Freebird hides authorization identity. It does not automatically hide:

- IP addresses;
- browser fingerprints;
- request timing;
- traffic volume;
- who is allowed to request tokens under the Sybil policy.

Choose Sybil mechanisms carefully. Stronger Sybil resistance often collects more operational data.

## Audit Status

Freebird is a prototype and has not had an independent cryptographic audit. Treat production deployments accordingly.

Recommended review focus:

- V4 VOPRF implementation and DLEQ verification;
- V4 verifier private-key handling;
- V5 RFC 9474 usage and metadata validation;
- replay-store durability;
- Sybil-resistance state machines;
- log hygiene.
