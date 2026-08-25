# Engineering Roadmap

This is a bounded planning document, not a capability announcement. Freebird
remains pre-1.0, public deployments remain experimental, and no external audit
has been completed. A roadmap item does not create a security property or a
named profile in the current source tree.

## Priorities

### 1. Keep claims and compatibility explicit

- Preserve the distinction between current transitional issuance and planned
  profiles.
- Keep V4 described as bespoke and non-RFC-9497-interoperable.
- Maintain regression and negative coverage for token encoding, scope, and
  nullifier behavior before protocol changes.
- Require every public security or privacy claim to identify its assumptions and
  deployment boundary.

**Bounded outcome:** reviewers can map each claim to current behavior or a
clearly labeled future requirement.

### 2. Make admission and replay state durable

- Specify atomic admission decisions, quantities, retries, and failure behavior.
- Use shared Redis state where restart-safe or multi-instance replay protection is
  claimed.
- Keep in-memory verifier and Sybil replay stores explicitly development-only.
- Add integration coverage for restart, concurrent use, and partial failure.

**Bounded outcome:** no limited-production claim rests on process-local replay
state or an undocumented retry effect.

### 3. Improve key and metadata lifecycle controls

- Define reviewed activation, retention, rotation, and rollback behavior.
- Keep issuer keys and verifier state on protected persistent storage.
- Test discovery freshness, key transitions, and failure behavior.
- Do not imply HSM-backed operation where it is not implemented.

**Bounded outcome:** operators can state which keys and tokens remain valid and
which recovery assumptions apply.

### 4. Harden deployment and operator boundaries

- Keep public traffic behind TLS and correctly configured trusted proxies.
- Keep admin routes behind network controls in addition to authentication.
- Document Redis, persistence, backups, readiness, and log retention.
- Treat audit logs as sensitive operational records, not tamper-evident evidence.

**Bounded outcome:** the documented baseline is testable without silently
weakening transport, replay, or admin controls.

### 5. Review Sybil mechanisms conservatively

- Test each supported gate and each combiner, including duplicate-proof and
  replay cases.
- Measure false positives, false negatives, cost, state, and privacy impact for
  the intended deployment rather than claiming universal humanity detection.
- Keep experimental diversity, progressive-trust, and social-graph behavior
  bounded by explicit operator policy.

**Bounded outcome:** each admission mode has a documented resistance claim and a
  documented failure mode.

### 6. Evaluate future privacy transport only after the core is stable

- Design any admission-ticket or relay/gateway work as a separate, reviewed
  protocol and deployment profile.
- Specify timing, padding, logging, forwarded-header, and non-collusion
  assumptions before implementation.
- Do not turn a relay or ticket alone into an anonymity claim.

**Bounded outcome:** a future privacy profile can be reviewed independently of
  current transitional issuance and cannot be enabled through a weaker bypass.

## Sequencing and stop conditions

Durable admission/replay and lifecycle work precede any broader deployment
claim. Future privacy work depends on that foundation and independent design
review. External audit is a prerequisite for any claim broader than the current
experimental, implementation-specific boundary.

Work should stop for security review when it changes cryptographic primitives,
wire formats, nullifier derivation, Sybil semantics, admin authentication, or
TLS trust behavior. No roadmap item authorizes those changes by itself.
