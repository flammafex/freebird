# Grant Work Packages

This proposal is deliberately bounded. It funds engineering, review, tests,
documentation, and low-stakes demonstrations; it does not fund a claim that
Freebird is production-ready, audited, anonymous against colluding operators,
or a proof of unique humanity. The project is pre-1.0 and public deployments are
experimental.

The grant is organized into exactly eight work packages. Packages 1–6 are
engineering and assurance work. Packages 7–8 are low-stakes demonstrations,
not products or high-value deployments.

## WP1 — Security scope and cryptographic assurance

**Purpose:** turn the current implementation-specific security boundary into a
reviewable baseline.

**Activities:** maintain the threat model and claim matrix; preserve V4/V7
compatibility fixtures and negative tests; document V4's bespoke,
non-RFC-9497-interoperable construction; prepare an independent cryptographic
design review target.

**Deliverables:** reviewed security/claim documentation, fixture provenance,
negative-case coverage, and a written list of assumptions and unresolved risks.

**Boundary:** this package is not an external audit and does not authorize a new
cryptographic primitive or a production claim.

## WP2 — Durable admission and replay controls

**Purpose:** reduce replay and partial-failure risk in issuance and redemption.

**Activities:** specify atomic admission decisions, quantities, reservations,
exact retries, and failure handling; use Redis-backed shared state where
restart-safe or multi-instance behavior is required; test restart, concurrency,
and partial failure.

**Deliverables:** versioned state and failure specification, integration tests,
operator configuration guidance, and a bounded acceptance checklist.

**Boundary:** process-local memory remains unsuitable for restart-safe public
claims; this package does not make Sybil mechanisms proof-of-personhood systems.

## WP3 — Key, verifier, and discovery lifecycle

**Purpose:** make key and metadata transitions reviewable and recoverable.

**Activities:** define activation, retention, rotation, freshness, rollback, and
backup expectations; test V4/V7 lifecycle behavior and verifier discovery;
document protected storage requirements.

**Deliverables:** lifecycle design, failure/recovery tests, operator runbook, and
explicit key-validity boundaries.

**Boundary:** file-backed operation is not HSM-backed security, and compromised
issuer keys remain outside the current trust claim.

## WP4 — Deployment and operator safety baseline

**Purpose:** make the documented deployment boundary enforceable and legible.

**Activities:** validate TLS and trusted-proxy assumptions; isolate admin routes;
document Redis/persistence requirements, backups, readiness, and sensitive-log
retention; reconcile examples with actual configuration.

**Deliverables:** deployment validation checks, operator checklist, backup/restore
criteria, and a privacy-aware logging policy template.

**Boundary:** operational records are not tamper-evident security logs, and a
working local demo is not production evidence.

## WP5 — Sybil-mode evaluation and admission governance

**Purpose:** evaluate configurable admission mechanisms without overstating what
they prove.

**Activities:** add coverage for each supported mode and combiner; document
replay and persistence limits; record cost, privacy, and farming failure modes;
define operator review and escalation guidance for experimental social/diversity
signals.

**Deliverables:** mode-by-mode evaluation report, combiner/replay tests, and
deployment guidance that explicitly rejects global-human-uniqueness claims.

**Boundary:** no mode becomes a universal bot detector or unique-human proof.

## WP6 — Future privacy transport and admission design

**Purpose:** establish a separate, reviewable path for stronger future privacy
properties.

**Activities:** design (without assuming implementation) separately operated
relay/gateway and admission-ticket requirements; specify timing, padding,
logging, forwarded-header, application-identity, and non-collusion assumptions;
obtain independent design review before protocol implementation.

**Deliverables:** threat-model extension, protocol/deployment requirements, and
go/no-go criteria for a future privacy profile.

**Boundary:** a relay, ticket, or transport change alone does not provide
anonymity against colluding issuer/verifier operators.

## WP7 — Low-stakes access-flow demonstration

**Purpose:** demonstrate the bounded token issuance, verification, and replay
behavior in a non-sensitive setting.

**Activities:** build a disposable test scenario with low-value access tokens;
show one-time redemption, documented replay rejection, configured admission, and
operator-visible limitations; publish reproducible test instructions.

**Deliverables:** a demo harness, test report, and risk/limitations notice.

**Boundary:** no real identity, financial, health, civic, or other high-consequence
decision; no production service; no claim of anonymity or unique humanity.
Possible future integrations with Witness may be explored only as optional demo
inputs, not as a Freebird product or dependency.

## WP8 — Low-stakes community/eligibility demonstration

**Purpose:** demonstrate coarse, policy-scoped eligibility and community review
without turning reputation into a universal identity product.

**Activities:** use synthetic or volunteer test data; show coarse admission
levels, explicit policy, expiry/replay handling, and privacy/logging review;
compare the observed behavior with the threat model.

**Deliverables:** a bounded demo, evaluation report, and operator/user consent
and data-retention notes.

**Boundary:** no high-stakes voting, benefits, employment, access control, or
proof-of-personhood deployment. Prestige may be considered later as a possible
future integration or demo context only; it is not a Freebird product and is not
part of the current implementation.

## Cross-package acceptance

All packages must preserve the pre-1.0 notice, identify assumptions, avoid
crypto overclaims, and report Redis and Sybil replay limitations. Deliverables
are review artifacts and bounded demonstrations until independent review and
maintainer acceptance support any further step.
