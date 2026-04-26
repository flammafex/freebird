# How Freebird Works

Freebird separates authorization from identity. A user proves they are allowed to do something by presenting a bearer token, without presenting an account, email address, wallet, phone number, or other identity handle.

Freebird has two token modes:

- **V4 private option:** maximal verifier privacy. Tokens are bound to a verifier scope and verified with private VOPRF key authority held by the verifier.
- **V5 public option:** public bearer passes. Tokens are verified with issuer-published RFC 9474 public keys, so verifiers do not need VOPRF private verification key material.

Both modes are blind issuance protocols: the issuer can decide whether to issue, but does not see the final token that will later be spent.

---

## Roles

- **Client:** asks for a token and later redeems it.
- **Issuer:** applies the issuance policy, such as invitation, proof of work, or WebAuthn, and signs blinded client input.
- **Verifier:** accepts tokens from explicitly configured issuers and prevents double spending with a nullifier store.

The issuer and verifier can be operated by the same community, but they should be separate services in production when timing correlation matters.

## V4 Private Option

V4 is the privacy-maximal Freebird mode.

1. The client fetches verifier metadata from `/.well-known/verifier`.
2. The client computes a verifier scope digest from `VERIFIER_ID` and `VERIFIER_AUDIENCE`.
3. The client builds a V4 token input from issuer ID, key ID, nonce, and scope digest.
4. The client blinds that input with the P-256 VOPRF protocol.
5. The issuer verifies the Sybil proof and evaluates the blinded element.
6. The issuer returns a VOPRF evaluation and DLEQ proof.
7. The client verifies the DLEQ proof and unblinds the result.
8. The client builds a V4 redemption token.
9. The verifier parses the V4 token, checks the scope digest, recomputes the authenticator with its authorized VOPRF key material, and marks the nullifier spent.

V4 token:

```text
[0x04]
[nonce(32)]
[scope_digest(32)]
[kid_len | kid]
[issuer_id_len | issuer_id]
[authenticator(32)]
```

Privacy properties:

- The issuer does not see the verifier scope during issuance unless the client reveals it out of band.
- The verifier does not call the issuer at redemption time.
- A V4 token minted for one verifier scope is rejected by other verifier scopes.
- The nullifier is scoped to the verifier ID and audience.

Operational requirement:

- The verifier must have private verification key authority for the issuer key it trusts. Configure this with `VERIFIER_SK_B64`, `VERIFIER_SK_PATH`, or `VERIFIER_KEYRING_B64`.

## V5 Public Option

V5 is Freebird's public bearer pass mode.

1. The client fetches issuer key metadata from `/.well-known/keys`.
2. The client selects a `public_bearer_pass` key whose policy is `single_use`.
3. The client chooses a nonce and builds the V5 message digest:

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

4. The client blinds that digest with an RFC 9474 `RSABSSA-SHA384-PSS-Deterministic` public key.
5. The issuer verifies the Sybil proof and returns a blind RSA signature.
6. The client finalizes the signature locally.
7. The client builds a V5 public bearer pass.
8. The verifier checks issuer trust, public key metadata, signature validity, optional audience, and replay state.

V5 token:

```text
[0x05]
[nonce(32)]
[token_key_id(32)]
[issuer_id_len | issuer_id]
[sig_len(2, big endian) | signature]
```

`token_key_id` is `SHA-256(pubkey_spki)`. In JSON metadata and API responses it is encoded as strict lowercase hex.

Privacy and deployment tradeoff:

- V5 is easier for independent verifiers because verification is public-key based.
- V5 tokens are not verifier-bound unless the issuer key metadata includes an `audience`.
- V5 replay records expire at the public key metadata `valid_until`.
- V5 is a bearer pass, not an economic token with demurrage semantics.

## Issuer Trust

Freebird uses explicit issuer trust.

```text
ISSUER_URL=https://issuer.example.com/.well-known/issuer
```

The verifier refreshes issuer metadata and key metadata from that URL. It does not discover issuers from a global network and does not accept transitive trust paths.

V4 trust means:

- the issuer metadata URL is configured; and
- the verifier has matching private verification key material.

V5 trust means:

- the issuer metadata URL is configured; and
- the issuer publishes valid `single_use` public bearer key metadata.

This is minimal federation: a verifier can trust more than one issuer, but every issuer is explicitly configured.

## Replay Protection

Freebird tokens are single-use. The verifier stores a nullifier for every consumed token.

- V4 nullifiers are verifier-scoped and do not expire while the verifier accepts the issuer key.
- V5 nullifiers are public-token nullifiers and use the V5 public key validity window as their replay TTL.

Use Redis in production. In-memory replay storage is only appropriate for development and tests.

## What Freebird Hides

Freebird hides identity from the authorization check:

- the issuer does not learn the final token;
- the verifier does not learn the user's identity;
- the verifier does not need to ask the issuer who spent a token;
- double-spend checks reveal only that the same bearer token was reused.

Freebird does not hide network metadata. IP addresses, timing, and traffic volume still require operational controls such as TLS, separate infrastructure, log minimization, Tor, VPNs, batching, or delayed redemption.

## Comparison

| System | Main Shape | Freebird Difference |
|--------|------------|---------------------|
| Privacy Pass | Blind-token authorization standard | Freebird packages issuer trust, Sybil gates, self-hosted issuer/verifier services, and both V4 private and V5 public modes for communities. |
| OAuth/session cookies | Identity-bearing authorization | Freebird bearer tokens do not identify the user. |
| API keys | Stable user or app identifier | Freebird tokens are unlinkable and single-use. |
| Anonymous cash protocols | Spendable economic tokens | Freebird V5 is an authorization pass, not a currency ledger. |

## Related Docs

- [Architecture](../ARCHITECTURE.md)
- [API Reference](API.md)
- [Issuer Trust](FEDERATION.md)
- [Security Model](SECURITY.md)
- [SDK](SDK.md)
