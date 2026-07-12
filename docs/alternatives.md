# Alternatives & Landscape Comparison

How Freebird compares to other privacy-preserving access-token, challenge-bypass,
and anonymous-credential systems. Focus is on self-hostable, open-source options,
since that is the filter Freebird itself satisfies.

## TL;DR

Freebird occupies a narrow niche: **self-hostable, open-source,
VOPRF-like/blind-RSA anonymous access tokens with built-in composable Sybil
resistance.** Its V4 P-256 construction is Freebird-specific and bespoke, not
RFC 9497 interoperable. No single other project fills all four of those slots.

- **Privacy Pass** provides related standardized token protocols, but Freebird
  V4 is not the same cryptographic protocol and does not interoperate with it.
- **PoW captchas** (mCaptcha, Anubis, ALTCHA) give you anti-abuse gates but no
  cryptographic unlinkability.
- **Semaphore** gives you both anonymity and Sybil resistance but is on-chain
  (Ethereum), not an HTTP service you run.
- **Anonymous-credentials** stack (AnonCreds, Idemix, BBS+) is richer but
  heavier, multi-use, and lacks built-in Sybil gating.

```
                 Sybil-resistant
                       │
        Semaphore ─────┼──── Freebird ──── (nothing)
        World ID       │    (VOPRF+gates,
                       │     self-hosted)
  ─────────────────────┼──────────────────────
   rich credentials    │   lightweight tokens
                       │
  AnonCreds/BBS+ ─────┼──── Privacy Pass ──── poprf-ristretto
  Idemix              │    (no gates)          (lib only)
                       │
                       │   mCaptcha / Anubis / ALTCHA
                       │   (PoW, linkable)
```

---

## Tier 1 — Related token primitives (closest functional analogs)

These use related VOPRF, POPRF, or blind-RSA primitives but are not necessarily
wire- or protocol-compatible with Freebird. In particular, Freebird V4 is a
bespoke P-256 construction, not RFC 9497 VOPRF or a Privacy Pass VOPRF suite.
Freebird's distinguishing value is the service layer (issuer + verifier HTTP
services, key rotation, nullifier/double-spend storage, admin UI, audit
logging) and the composable Sybil gates on top.

### Privacy Pass (original)

- **Self-hostable:** Yes (server)
- **Open source:** Yes — BSD-3-Clause (server/extension), Apache-2.0 (TS lib),
  MIT (Rust lib)
- **Crypto:** VOPRF (P-256, Ristretto255) + Blind RSA (RFC 9474)
- **Relying party receives:** Anonymous boolean (valid/invalid)
- **Token model:** Single-use
- **Sybil resistance:** No (attestation is external)
- **Integration:** HTTP API + browser extension + library
- **Maintained:** Fragmented — original Go server dormant (last push Mar 2024);
  IETF specs active; Cloudflare fork (`pp-browser-extension`, `privacypass-ts`)
  is the active lineage
- **Language:** Go (server), TypeScript, Rust

Privacy Pass is a related standardized single-use token model, not a V4
interoperability target. It has no built-in Sybil gates or complete Freebird
service layer; the original server is dormant.

### Brave `poprf-ristretto`

- **Self-hostable:** Yes (library)
- **Open source:** Yes — Apache-2.0
- **Crypto:** POPRF over Ristretto255-SHA512 (RFC 9497)
- **Relying party receives:** Anonymous boolean
- **Token model:** Single-use
- **Sybil resistance:** No
- **Integration:** Rust library + FFI (C ABI) + WASM bindings
- **Maintained:** Yes (pending audit)
- **Language:** Rust

The partially-oblivious PRF mode enables attribute-bound rate limiting via the
`info` tag — architecturally the closest to Freebird's VOPRF + Sybil-gate
design. But library-only: no issuer/verifier services, no nullifier storage,
no admin.

### Brave `challenge-bypass-ristretto`

- **Self-hostable:** Yes (library)
- **Open source:** Yes — MPL-2.0
- **Crypto:** VOPRF over Ristretto255
- **Relying party receives:** Anonymous boolean
- **Token model:** Single-use
- **Sybil resistance:** No
- **Integration:** Rust library + FFI + WASM
- **Maintained:** Yes (v2.0.4 Dec 2025)
- **Language:** Rust

Active. No service layer.

### raphaelrobert/privacypass

- **Self-hostable:** Yes (library)
- **Open source:** Yes — MIT
- **Crypto:** VOPRF (P-384, Ristretto255) + Blind RSA (RFC 9578) + batch VOPRF
- **Relying party receives:** Anonymous boolean
- **Token model:** Single-use
- **Sybil resistance:** No
- **Integration:** Rust library (async API) with HTTP auth header
  construction/parsing
- **Maintained:** Moderate (65 stars; implements draft-06, not final RFC 9578)
- **Language:** Rust

Closest pure-Rust library analog to Freebird's `crypto` crate. But: no service
layer, no Sybil gates, no key rotation, implements an older draft.

---

## Tier 2 — Self-hostable, open-source, different paradigm

### mCaptcha

- **Self-hostable:** Yes
- **Open source:** Yes — AGPL-3.0
- **Crypto:** SHA-256 Proof-of-Work
- **Relying party receives:** Anonymous boolean (PoW valid/invalid)
- **Token model:** Single-use (PoW config expires in ~30s)
- **Sybil resistance:** Partial (PoW rate-limiting is itself anti-Sybil; no
  identity-based Sybil resistance)
- **Integration:** HTTP API + Rust library (`libmcaptcha`) + WASM frontend
- **Maintained:** Low activity (last crate release Oct 2023; NLnet-funded)
- **Language:** Rust

No cryptographic unlinkability between issuance and redemption — the PoW
solution is the credential, trivially linkable.

### Anubis

- **Self-hostable:** Yes
- **Open source:** Yes — MIT
- **Crypto:** SHA-256 Proof-of-Work
- **Relying party receives:** Pseudonymous session (JWT cookie, EdDSA-signed)
- **Token model:** Multi-use (cookie valid for tunable period)
- **Sybil resistance:** Partial (PoW cost is the Sybil deterrent; no identity
  verification)
- **Integration:** Reverse proxy (Docker)
- **Maintained:** Yes (v1.25.0, Feb 2026; 19K stars)
- **Language:** Go + JavaScript

Very active, designed for AI-scraper defense. Issues a pseudonymous JWT
cookie, not an unlinkable token.

### ALTCHA

- **Self-hostable:** Yes
- **Open source:** Yes — MIT (core)
- **Crypto:** SHA-256 Proof-of-Work (v2 protocol)
- **Relying party receives:** Anonymous boolean (PoW valid/invalid)
- **Token model:** Single-use
- **Sybil resistance:** Partial (PoW is the Sybil deterrent; "Sentinel" adds ML)
- **Integration:** JS npm package + web component + server-side verification;
  Rust library (`altcha-lib-rs`)
- **Maintained:** Yes (v3.1.0, Jun 2026; 2.5K stars)
- **Language:** TypeScript + Svelte

Same linkability caveat as mCaptcha/Anubis.

### Semaphore

- **Self-hostable:** Yes (on-chain, no central server)
- **Open source:** Yes — MIT
- **Crypto:** ZK-SNARKs (Circom circuits) + EdDSA (Baby Jubjub) + Poseidon hash
  + Merkle trees
- **Relying party receives:** Pseudonymous nullifier (per-scope, per-user) +
  anonymous group membership proof
- **Token model:** Single-use per nullifier/scope (multi-use with different
  scopes)
- **Sybil resistance:** Yes (group membership is the Sybil gate; on-chain
  identity commitments)
- **Integration:** JS/TS libraries + Solidity contracts + CLI
- **Maintained:** Yes (V4, trusted setup Jul 2024; PSE-supported)
- **Language:** TypeScript, Circom, Solidity

Has Sybil resistance + anonymity but uses ZK-SNARKs on Ethereum — completely
different deployment model, not HTTP-based.

### Hyperledger Indy / Aries + BBS+

- **Self-hostable:** Yes
- **Open source:** Yes — Apache-2.0
- **Crypto:** BBS+ signatures (BLS12-381) + CL Signatures (Indy/AnonCreds v1)
  + ZK proofs
- **Relying party receives:** Selective-disclosure credentials (pseudonymous,
  unlinkable presentations)
- **Token model:** Multi-use (credentials are reusable; presentations are
  unlinkable)
- **Sybil resistance:** No (identity issuance is application-defined)
- **Integration:** Agent framework (HTTP/DIDComm) + Rust libraries
  (`anoncreds-rs`, `aries-askar`) + ACA-Py (Python)
- **Maintained:** Yes (Indy graduated, stable; AnonCreds v2 in active
  development)
- **Language:** Rust, Python, Go

Richer than Freebird — selective disclosure, predicate proofs, multi-use
credentials. But: no built-in Sybil resistance, no single-use double-spend
model, heavier framework rather than lightweight access-token service.

### Hyperledger AnonCreds v2 (`anoncreds-v2-rs`)

- **Self-hostable:** Yes
- **Open source:** Yes — Apache-2.0
- **Crypto:** BBS+ signatures + PS Signatures (pluggable ZKP signature suites)
- **Relying party receives:** Selective-disclosure ZK proof (pseudonymous,
  unlinkable)
- **Token model:** Multi-use
- **Sybil resistance:** No
- **Integration:** Rust library
- **Maintained:** Yes (in active development)
- **Language:** Rust

Most mature Rust-ecosystem anonymous-credentials library. Complementary to
Freebird rather than a direct competitor.

### IBM Idemix

- **Self-hostable:** Yes (reference implementation)
- **Open source:** Yes — Apache-2.0
- **Crypto:** CL Signatures (Camenisch-Lysyanskaya) + ZK proofs + pseudonyms
- **Relying party receives:** Selective-disclosure credentials (pseudonymous,
  unlinkable)
- **Token model:** Multi-use
- **Sybil resistance:** No (issuance policy is application-defined)
- **Integration:** Go library (blockchain-oriented)
- **Maintained:** No (dormant; superseded by Hyperledger AnonCreds/Ursa)
- **Language:** Go

---

## Tier 3 — Not self-hostable or not open source

Included for completeness; these fail the key filters.

### hCaptcha

- **Self-hostable:** No (SaaS only; "first-party hosting" is a proxy, not
  self-hosting)
- **Open source:** No (proprietary)
- **Crypto:** Proprietary ML + behavioral analysis (not cryptographic tokens)
- **Sybil resistance:** Yes (built-in bot detection)

### Cloudflare Turnstile

- **Self-hostable:** No (SaaS only)
- **Open source:** No (proprietary)
- **Crypto:** PoW + proof-of-space + JS challenges + Privacy Pass/PATs (Blind
  RSA, RFC 9474)
- **Sybil resistance:** Yes (built-in challenge platform)

Uses Privacy Pass/PATs internally but the challenge platform is Cloudflare's
infrastructure.

### World ID / Worldcoin

- **Self-hostable:** Partial (protocol is open; Orb hardware + AMPC network are
  not self-hostable by third parties)
- **Open source:** Yes (protocol/contracts) — MIT
- **Crypto:** ZK proofs (Semaphore-based) + OPRF (blinded) + AMPC
  (multi-party computation) + iris biometrics
- **Sybil resistance:** Yes (iris uniqueness is the core Sybil resistance)
- **Integration:** JS SDK (`@worldcoin/idkit`) + on-chain verification + Rust
  crates
- **Maintained:** Yes (World ID 4.0 specs; active development)
- **Language:** Rust, Circom, Solidity, TypeScript

The protocol is open source, but practical deployment requires the Orb hardware
(closed biometric device) and the AMPC node network. You cannot self-host the
core Sybil-resistance mechanism.

---

## One to watch

### Mozilla PACT (Private Access Control Tokens)

- **Self-hostable:** TBD (architecture in design phase)
- **Open source:** Draft specs at
  [github.com/Moderation-of-unLinkable-Endorsements](https://github.com/Moderation-of-unLinkable-Endorsements);
  no reference implementation yet
- **Crypto:** Privacy Pass protocol + Anonymous Credit Tokens (ACT, stateful
  credentials with counters) + Issuer blinding (ZK proofs) + MPC (Prio)
- **Relying party receives:** Single bit (credential valid / below rate limit);
  no identity, no counter value, no linkability
- **Token model:** Multi-use (stateful credentials, mutated on each
  presentation)
- **Sybil resistance:** Yes — the entire architecture is a Sybil-resistance
  mechanism (scarcity signals anchor rate limits)
- **Integration:** WebAPI (W3C) + crypto protocols (IETF)
- **Maintained:** Early design phase (blog post Jun 2026; "many details still
  need to be worked out")
- **Language:** N/A (no implementation yet)

Conceptually the closest analog to Freebird's design philosophy — combining
anonymous tokens with Sybil-resistance gating — but it's a proposal, not a
deployable system.

---

## What makes Freebird unique

Freebird is the only project in the upper-right quadrant of the landscape:
**lightweight single-use tokens with Privacy-Pass-related primitives + built-in
composable Sybil resistance + self-hostable service layer + open source.**

1. **A bespoke V4 P-256 VOPRF-like construction plus V5 Blind RSA tokens** —
   V4 is not RFC 9497 or Privacy Pass interoperable; V5 uses a separate public
   bearer path. Both are provided with a complete service layer (issuer +
   verifier HTTP services, key rotation, admin UI, nullifier storage).
2. **Built-in Sybil resistance** with multiple composable gates (`invitation`,
   `pow`, `rate_limit`, `progressive_trust`, `proof_of_diversity`,
   `multi_party_vouching`, `webauthn`, `social_graph`) and combiners
   (`CombinedOr`, `CombinedAnd`, `CombinedThreshold`). No other VOPRF-based
   system has this.
3. **Self-hostable and open-source** (MIT/Apache-2.0), in Rust, with production
   deployment assets (Docker, K8s, TLS enforcement, audit logging).

If you want what Freebird does specifically, there isn't a drop-in alternative.
The closest alternative would combine a standardized Privacy Pass or POPRF
library with a Sybil gate and service layer. That would be a separate design,
not a drop-in implementation of Freebird V4.
