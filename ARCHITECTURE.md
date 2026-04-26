# Freebird Architecture

Freebird is an anonymous authorization system with two token modes:

- **V4 private option:** verifier-bound VOPRF tokens. The issuer cannot see the verifier scope at redemption time, and the verifier recomputes the authenticator locally with issuer-approved private verification key material.
- **V5 public option:** public bearer passes using RFC 9474 blind RSA signatures. Verifiers use issuer-published public keys, accept only immutable `single_use` key metadata, and do not need VOPRF private verification key material.

Both modes share the same operational model: an issuer gates issuance with a Sybil-resistance policy, a client blinds the issuance message, and a verifier spends a bearer token exactly once with a nullifier store.

---

## Workspace

```text
freebird/
├── crypto/             freebird-crypto: VOPRF, V4/V5 codecs, nullifiers, providers
├── common/             freebird-common: shared API types, logging, duration parsing
├── issuer/             freebird-issuer: HTTP issuer, metadata, Sybil gates, admin API
├── verifier/           freebird-verifier: HTTP verifier, issuer trust, replay store
├── interface/          freebird-interface: CLI test client
├── sdk/js/             TypeScript SDK
└── integration_tests/  protocol and service tests
```

## Services

### Issuer

The issuer exposes:

- `GET /.well-known/issuer`: issuer summary metadata.
- `GET /.well-known/keys`: VOPRF metadata and V5 public bearer key metadata.
- `POST /v1/oprf/issue`: V4 VOPRF evaluation.
- `POST /v1/oprf/issue/batch`: batch V4 VOPRF evaluation.
- `POST /v1/public/issue`: V5 blind RSA signature.
- `POST /v1/public/issue/batch`: batch V5 blind RSA signatures.
- `/admin/*`: issuer administration when `ADMIN_API_KEY` is configured.

The issuer owns the issuance policy. It may require invitation proofs, proof of work, rate limits, progressive trust, proof of diversity, multi-party vouching, WebAuthn, or combined mechanisms before signing.

### Verifier

The verifier exposes:

- `GET /.well-known/verifier`: verifier scope metadata for V4 clients.
- `POST /v1/verify`: consuming verification for V4 or V5 tokens.
- `POST /v1/verify/batch`: consuming batch verification for V4 or V5 tokens.
- `POST /v1/check`: non-consuming validation for V4 or V5 tokens.
- `/admin/*`: verifier administration when `ADMIN_API_KEY` is configured.

The verifier is configured with trusted issuer metadata URLs via `ISSUER_URL` or `ISSUER_URLS`. For each issuer, it refreshes `/.well-known/issuer` and `/.well-known/keys`.

## V4 Private Option

V4 is verifier-bound private verification.

```text
Client                         Issuer                         Verifier
  |                              |                              |
  | GET /.well-known/verifier    |                              |
  |<------------------------------------------------------------|
  | build nonce + scope_digest   |                              |
  | blind V4 token input         |                              |
  | POST /v1/oprf/issue          |                              |
  |----------------------------->| verify Sybil proof           |
  |                              | evaluate blinded element     |
  |<-----------------------------| token = VOPRF eval + DLEQ    |
  | verify DLEQ, unblind         |                              |
  | build V4 redemption token    |                              |
  | POST /v1/verify {token_b64}  |                              |
  |------------------------------------------------------------>|
  |                              |                              | parse token
  |                              |                              | check scope
  |                              |                              | recompute authenticator
  |                              |                              | mark V4 nullifier spent
```

V4 wire format:

```text
[VERSION=0x04]
[nonce(32)]
[scope_digest(32)]
[kid_len(1) | kid]
[issuer_id_len(1) | issuer_id]
[authenticator(32)]
```

The authenticator is the unblinded VOPRF output over:

```text
freebird:private-token-input:v4
issuer_id_len | issuer_id
kid_len | kid
nonce
scope_digest
```

Verifier requirements for V4:

- trusted issuer metadata URL;
- verifier scope configured with `VERIFIER_ID` and `VERIFIER_AUDIENCE`;
- matching private verification key material through `VERIFIER_SK_B64`, `VERIFIER_SK_PATH`, or `VERIFIER_KEYRING_B64`;
- durable replay storage for production.

## V5 Public Option

V5 is a public bearer pass.

```text
Client                         Issuer                         Verifier
  | GET /.well-known/keys        |                              |
  |<-----------------------------|                              |
  | choose public token key      |                              |
  | build nonce + token_key_id   |                              |
  | build V5 message digest      |                              |
  | blind digest with RFC 9474   |                              |
  | POST /v1/public/issue        |                              |
  |----------------------------->| verify Sybil proof           |
  |                              | blind-sign message           |
  |<-----------------------------| blind_signature              |
  | finalize blind signature     |                              |
  | build V5 public bearer pass  |                              |
  | POST /v1/verify {token_b64}  |                              |
  |------------------------------------------------------------>|
  |                              |                              | parse token
  |                              |                              | find public key
  |                              |                              | check metadata policy
  |                              |                              | verify RSA signature
  |                              |                              | mark V5 nullifier spent
```

V5 wire format:

```text
[VERSION=0x05]
[nonce(32)]
[token_key_id(32)]
[issuer_id_len(1) | issuer_id]
[sig_len(2, big endian) | signature]
```

The V5 message passed to the RFC 9474 library is:

```text
SHA-384(
  "freebird:public-bearer-pass:v5" ||
  0x00 ||
  0x05 ||
  nonce ||
  token_key_id ||
  issuer_id_len ||
  issuer_id
)
```

`token_key_id` is `SHA-256(pubkey_spki)` and is encoded in JSON as strict lowercase 64-character hex.

Verifier requirements for V5:

- trusted issuer metadata URL;
- valid public key metadata from `/.well-known/keys`;
- `token_type = "public_bearer_pass"`;
- `rfc9474_variant = "RSABSSA-SHA384-PSS-Deterministic"`;
- `spend_policy = "single_use"`;
- `token_key_id` must match `SHA-256(pubkey_spki)`;
- optional `audience` must match the verifier audience;
- durable replay storage for production.

## Nullifiers

V4 nullifiers include verifier scope, issuer ID, key ID, nonce, scope digest, and authenticator. This makes V4 replay keys verifier-scoped.

V5 nullifiers include nonce, token key ID, issuer ID, and finalized signature. V5 public tokens are bearer instruments, so replay protection is the verifier's spend database.

Use Redis in production. In-memory replay storage is for local testing because restart loses spend state.

## Issuer Trust

Freebird uses explicit issuer trust rather than global federation. A verifier trusts only configured issuer URLs. V4 adds private verification key authority; V5 uses issuer-published public keys with strict metadata policy.

This is "minimal federation": verifiers can accept more than one issuer, but there is no transitive trust graph, no token forwarding between issuers, and no verifier phone-home to the issuer during redemption.

## Deployment

```text
issuer.example.com
  /.well-known/issuer
  /.well-known/keys
  /v1/oprf/issue
  /v1/public/issue
  /admin/*

verifier.example.com
  /.well-known/verifier
  /v1/verify
  /v1/check
  /admin/*
```

Run issuer and verifier as separate services in production. TLS is required for bearer tokens. Keep issuer logs, verifier logs, and replay stores operationally separate when privacy against timing correlation matters.
