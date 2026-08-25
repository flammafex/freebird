# Security Threat Model

This is a conservative engineering threat model for the current Freebird
implementation. It is not a formal proof, external audit, or production
approval. Freebird is pre-1.0; public deployments are experimental.

The current issuance API is transitional. Profile names and stronger future
claims must not be inferred from the current routes. See the repository's
profile and claim matrix for that distinction.

## Security objectives

Freebird is intended to provide, within the stated assumptions:

1. token-layer unlinkability between a blinded issuance request and a later
   redemption;
2. integrity checks for issued tokens; and
3. rejection of a second use of a token when replay state is durable and
   correctly configured.

Issuer admission controls additionally decide whether a client may receive an
issuance response. They are local policy mechanisms, not universal bot or
humanity detection.

## Actors

| Actor | Relevant capability or position |
| --- | --- |
| **Issuer** | Evaluates blinded requests, applies the configured Sybil gate, holds issuance keys, and operates admin/state storage. An honest issuer follows its policy; a malicious issuer may issue outside policy or retain identifying data. |
| **Verifier** | Validates tokens and records nullifiers/replay state. An honest verifier enforces the configured token and scope rules; a malicious verifier may log requests, attempt linkage, or accept an invalid implementation-specific input. |
| **User** | Creates blinded requests, presents admission proofs where required, finalizes tokens, and redeems them. A user may be honest, may reuse a token accidentally, or may farm/share credentials. |
| **Network observer** | Sees traffic, timing, packet sizes, addresses, and other metadata when positioned on a network path or at a proxy/hosting provider. Modification is also possible if transport and proxy controls are wrong. |
| **Malicious redeemer** | Obtains a token or its surrounding application context and attempts forgery, alteration, theft, double spend, or replay. This actor may also operate an application around the verifier. |
| **Malicious issuer** | Controls issuance policy, issuer infrastructure, keys, logs, or admission state. It can deliberately issue many tokens, correlate its own observations, or compromise the intended trust boundary. Token cryptography does not make a malicious operator honest. |
| **Colluding issuer/verifier** | Controls both service sides and can join issuance and redemption observations, including timing, IP, User-Agent, account, proxy, and application logs. Token-layer unlinkability is not a claim against this actor. |

Administrative attackers and storage/hosting operators are within the practical
capability of the issuer or verifier threat boundary when they obtain admin
credentials, service keys, Redis state, local state, or logs.

## Assets

The principal assets are:

| Asset | Security interest |
| --- | --- |
| **Identity** | User identifiers, account relationships, credential identifiers, IP/User-Agent data, and admin identities should not be exposed or joined unnecessarily. |
| **Eligibility** | Admission evidence and policy decisions should not be forged, replayed, or silently widened. Eligibility is local to the configured mechanism and is not proof of a unique human. |
| **Token unlinkability** | A verifier should not learn which blinded issuance request produced a valid token from the token flow alone. This does not cover surrounding metadata or colluding operators. |
| **Redemption integrity** | Only valid, correctly scoped, non-tampered tokens should be accepted by the applicable verifier implementation. |
| **Replay prevention** | A consumed token, and where configured a consumed Sybil proof, should not be accepted again within the lifetime and scope of the configured replay store. |

Other sensitive assets include issuer and verifier keys, Redis nullifiers,
Sybil state and secrets, WebAuthn credential data, admin keys/session cookies,
and audit exports.

## Threats and controls

| Threat | Current treatment and limitation |
| --- | --- |
| **Replay** | Verifier nullifier storage is intended to reject a second token use. Redis is the production path. In-memory verifier storage loses state on restart. PoW, WebAuthn, vouching, and social-graph proof replay protection defaults to process-local memory; Redis is required for restart-safe or multi-instance behavior. |
| **Issuer/verifier collusion** | The token flow separates issuance from redemption, but a party controlling both services can correlate timing, network metadata, proxy logs, application identifiers, and its own records. No current profile claims anonymity against this. |
| **Timing correlation** | Blinding does not hide request and redemption times from an observer who sees both sides. Padding, batching, relays, and deployment discipline are not current guarantees of the transitional API. |
| **Metadata leakage** | IP addresses, User-Agent data, browser fingerprints, request timing, account identifiers, operation identifiers, proxy logs, hosting logs, and audit data can create linkage. TLS protects traffic in transit; it does not erase endpoint or operator metadata. |
| **Browser fingerprinting** | Freebird does not prevent a browser, proxy, verifier, issuer, or surrounding application from collecting a fingerprint. WebAuthn attestation may identify authenticator characteristics and is not a unique-human proof. |
| **Sybil attacks** | Configured gates can raise cost or require local credentials, but PoW can be defeated by cheap compute/botnets, rate limits by identity rotation, invitations by farming/social attack, WebAuthn by multiple devices, progressive trust by fresh-account farming, and social/diversity signals by patient or coordinated farming. Combined `or` mode is only as strong as its easiest mechanism. |
| **Compromised issuer keys** | Key custody and protected persistent storage are operator responsibilities. A compromised issuer key can undermine token issuance or verification assumptions. Existing documentation does not turn file-backed keys or current rotation into HSM-backed protection; `HSM_ENABLE=true` is not implemented. |
| **Malicious verifier logging** | A verifier can retain redemption requests, IPs, User-Agent data, account IDs, timing, and application context. Audit and reverse-proxy records can create linkage. Operators must define retention and access controls; the token layer cannot force an untrusted verifier to delete logs. |
| Forgery or tampering | V4 and V7 verification use their respective implementation-specific cryptographic checks. This depends on the cryptographic assumptions in [Cryptographic assumptions](cryptographic-assumptions.md), correct key/discovery configuration, and uncompromised keys. |
| Admin or storage compromise | Admin API keys/session cookies, Redis, local state, audit exports, and service hosts are sensitive trust boundaries. TLS and admin network isolation are deployment requirements, not automatic properties of a running process. |

## Assumptions

The intended security boundary assumes that:

- public traffic uses HTTPS with `REQUIRE_TLS=true` and trusted proxy settings;
- forwarded headers are supplied only by a correctly isolated trusted proxy;
- admin routes are protected by a strong `ADMIN_API_KEY`, session controls, and
  network policy;
- issuer and verifier keys, Sybil state, and Redis are protected and backed up
  according to the operator's policy;
- public verifiers use Redis for nullifier/replay state;
- public issuers use `SYBIL_REPLAY_STORE=redis` when restart-safe or multi-node
  proof replay protection is required; and
- operators choose a Sybil mode deliberately and document what it does not
  resist.

Breaking these assumptions does not merely reduce convenience; it can invalidate
the associated security claim.

## Explicit non-goals

Freebird does **not** currently claim:

- global bot detection;
- proof that a user is a unique human;
- protection against all farms of real devices or real invited accounts;
- anonymity against an operator controlling both issuer and verifier and
  correlating timing, network metadata, logs, or application behavior;
- tamper-evident audit logging;
- restart-safe or multi-instance Sybil-proof replay protection when the issuer
  uses its process-local memory store;
- production readiness, certification, or an external audit finding;
- RFC 9497 interoperability for the bespoke V4 construction; or
- protection against a malicious issuer, malicious verifier, compromised host,
  or colluding service operator.

These are boundaries on claims, not promises that the corresponding future work
will be delivered.

## Future work boundary

The repository identifies durable admission state, clearer deployment examples,
operator workflows, WebAuthn/combined-mode guidance, and documented log
retention as gaps. Any future privacy profile would need explicit relay,
logging, timing, admission, and non-collusion requirements. It must not be
described as a retroactive property of the current transitional API.
