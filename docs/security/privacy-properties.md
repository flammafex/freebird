# Privacy Properties

This page states the narrow privacy property supported by the current design.
It is not a claim of general anonymity. Freebird is pre-1.0, experimental for
public deployment, and has not received an external security audit.

## Token-layer property

The client sends a blinded issuance request. The issuer evaluates that request
without needing to know where the eventual token will be redeemed. The client
then unblinds/finalizes the result and presents the token to a verifier. The
intended token-layer property is that the verifier cannot identify the original
issuance request from the finalized token flow alone.

This is a separation property, not an unconditional anonymity guarantee. It
depends on the applicable cryptographic assumptions, correct implementation,
fresh client randomness, protected keys, and the issuer and verifier not using
extra observations to correlate users.

## What remains visible

The token flow does not hide all surrounding data. A deployment can expose or
retain:

- client IP address and network path;
- User-Agent and browser-fingerprint data;
- request and redemption timing, sizes, and frequency;
- application account identifiers and behavior;
- reverse-proxy, hosting-provider, service, and audit logs;
- configured admission identifiers, credential metadata, or social-graph
  evidence at their respective trust boundaries; and
- public discovery and operational metadata.

TLS protects traffic in transit when correctly deployed. It does not stop an
issuer, verifier, proxy, relay, hosting provider, or application from observing
its own endpoint metadata.

## V4 and V7 scope

V4 is a Freebird-specific bespoke P-256 VOPRF-like construction. It is not RFC
9497 interoperable, and this page makes no Privacy Pass or standards-conformance
claim. V7 uses randomized RSA blind signatures and issuer-published discovery
metadata. Their privacy properties must be read as implementation-specific
claims, not as a transfer of guarantees from a named standard.

## Operational limits

The issuer's Sybil layer runs before blinded issuance. It can use server-observed
request context and configured credentials. This may be useful for admission
policy, but it can also create linkable operational state. In particular,
rate-limiting, invitations, WebAuthn, progressive trust, diversity scoring,
vouching, and social-graph admission have distinct data and trust boundaries.
None establishes global human uniqueness.

Audit logs are operational records, not tamper-evident security logs. They may
contain user IDs, invite data, admin identifiers, and details. Treat exports and
proxy logs as sensitive, set a deployment-specific retention policy, and do not
assume that removing token fields removes surrounding linkage.

## Not provided

Current Freebird does not provide anonymity against a colluding issuer and
verifier, timing-resistant issuance and redemption, browser-fingerprint
resistance, or a guarantee that a malicious verifier will not log. A future
privacy profile would require independently operated transport and admission
components, minimized logs, and explicit non-collusion assumptions; those are
future work, not current behavior.
