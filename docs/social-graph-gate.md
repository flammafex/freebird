# Social Graph Sybil Gate — Design Blueprint

> Status: **Design phase, not implemented.** This document is the blueprint
> for a future Freebird Sybil gate. It was produced by parallel research
> (Freebird architecture, app signal survey, Sybil detection literature)
> followed by architectural design review.

## 1. Overview

The `social_graph` Sybil gate admits users based on reputation in an
external social/trust graph, primarily [Clout](https://git.carpocratian.org/sibyl/clout).
Its purpose is to raise the cost of fake-account farming beyond what a
single invitation code, proof-of-work nonce, or rate-limit identity can
provide.

### What problems this addresses

Freebird's current Sybil gates (`invitation`, `pow`, `rate_limit`,
`webauthn`, `multi_party_vouching`, `progressive_trust`) are all
point-in-time admission checks. None establish that a participant has
sustained, real-world social trust. A farmer who obtains one invitation
or solves one PoW challenge can request a token.

The `social_graph` gate consumes **organic trust signals** —
relationships that emerge from real social interaction, economic
activity, and civic participation over time. These signals are harder
to farm because they require sustained participation that decays if
neglected.

### Core principle

> Freebird's issuer verifies "this requester has a valid Cred
> presentation containing a social-graph eligibility attestation," not
> "this Clout identity has these graph edges."

The issuer must not ingest raw trust edges, invitation chains, wallet
histories, ballot histories, or rendezvous participation data. Graph
analysis happens in a separate Social Graph Attester service, and the
attestation is held and presented by [Cred](https://git.carpocratian.org/sibyl/cred)
(the user-owned proof agent). The issuer receives only a Cred
presentation containing a signed attestation.

### What it is not

- Not proof-of-personhood (graph reputation is gameable with patience)
- Not universal bot detection (no continuous behavioral analysis)
- Not a replacement for existing gates (it composes with them via
  `combined` mode)

It is a **higher-cost admission layer** that raises the farming bar by
requiring real, aged, multi-signal social participation.

---

## 2. Architecture

### Cred-mediated attestation flow

Graph analysis happens in a **separate Social Graph Attester service**,
and the attestation is held and presented by **Cred** (the user-owned
proof agent). This creates two privacy boundaries: attester → Cred, and
Cred → Freebird issuer.

```
Client      Cred (user agent)    Social Graph Attester    Freebird Issuer
  │               │                       │                      │
  │── 1. request ─→│                       │                      │
  │   issuance     │                       │                      │
  │               │── 2. get request binding ──────────────────→│
  │               │←── request_binding ─────────────────────────│
  │               │                       │                      │
  │── 3. ask Cred │                       │                      │
  │   for social  │                       │                      │
  │   graph proof │                       │                      │
  │               │── 4. request attestation ─────────────────→│
  │               │    (Cred controller key,                     │
  │               │     Clout trust evidence)                     │
  │               │                       │                      │
  │               │                  5. evaluate graph           │
  │               │                  (SybilRank/heuristic)       │
  │               │                       │                      │
  │               │←── 6. signed attestation ──────────────────│
  │               │    (NOT request-bound;                      │
  │               │     bound to Cred controller key)            │
  │               │                       │                      │
  │               │── 7. store as cred.artifact_record           │
  │               │                       │                      │
  │               │── 8. create cred.presentation                │
  │               │    bound to Freebird app_id + request_id     │
  │               │    (request_binding_hash embedded here)     │
  │               │                       │                      │
  │←── 9. Cred presentation ─│             │                      │
  │               │                       │                      │
  │── 10. submit as SybilProof::SocialGraph ─────────────────→│
  │               │                       │                      │
  │               │                  11. issuer verifies:       │
  │               │                     - attester signature     │
  │               │                     - policy/version         │
  │               │                     - expiry                 │
  │               │                     - Cred presentation sig │
  │               │                     - request binding match  │
  │               │                     - eligibility threshold  │
  │               │                     - replay store (jti)     │
  │               │                       │                      │
  │←── 12. VOPRF evaluation (token issued) ──────────────────│
```

### Why Cred in the middle?

Cred is the [user-owned proof agent](https://git.carpocratian.org/sibyl/cred)
that holds keys, credentials, attestations, and app permissions locally.
It already has adapters for Freebird (check/verify), Witness
(attestations), and Matchlock (commitments/nullifiers), following a
canonical `sophia/v1` contract with `cred.permission_grant`,
`cred.action_request`, and `cred.presentation` artifacts.

Routing the social graph attestation through Cred provides three
privacy properties that direct client → attester → issuer does not:

1. **The attester doesn't know which Freebird instance the user is
   targeting.** The attester issues a general-purpose eligibility
   attestation bound to Cred's controller key. Cred later binds the
   presentation to a specific Freebird issuer's `request_id` at
   presentation time. The attester never sees the request binding.

2. **Permission grants enforce the presentation boundary.** Cred's
   `cred.permission_grant` system constrains which apps can request
   which artifacts, with `allowed_audiences`, `max_uses`, `expires_at`,
   and `human_approval: "per_use"`. A social graph grant would
   constrain presentation to specific Freebird issuers with single-use
   enforcement.

3. **The attestation is a canonical Sophia artifact.** It follows the
   `sophia/v1` contract with `contract_version`, `artifact_type`, and
   canonical JSON serialization. This makes it testable via SophiaDOS
   conformance checks and smoke harnesses.

### Why not issuer-side graph analysis?

Issuer-side analysis would require the issuer to see Clout public
keys, trust edges, invitation chains, or browser-local graph snapshots.
This breaks Clout's "Dark Social Graph" property and creates a strong
issuance-time identity record that could later be correlated.

### The Clout browser-local graph problem

Clout's strongest trust graph lives in the browser (IndexedDB), not on
a server. The attester cannot simply query a Clout API for a user's
full graph. Options considered:

| Option | Approach | Verdict |
|---|---|---|
| A. Client submits graph snapshot to Freebird issuer | Client sends trust edges directly | **Rejected** — breaks Dark Social Graph, issuer sees raw graph |
| B. Clout exposes server-side attestation API | Clout server computes score, issues attestation | **Preferred long-term** — requires Clout API work |
| C. Separate graph indexer service | Indexer aggregates Clout signals, computes scores | **Preferred Phase 2** — sensitive infrastructure |
| D. Cred submits verifiable evidence to attester | Cred presents signed trust edges to attester on behalf of user | **Phase 1 approach** — requires Clout edges to be signed |

**Phase 1 approach (Option D):** Cred submits cryptographically signed
Clout trust evidence (signed trust edges, signed invitation chain,
timestamps) to the attester on behalf of the user. The attester
validates the evidence, runs the scoring heuristic, and issues an
attestation to Cred's controller key. Cred stores it as a
`cred.artifact_record` and later presents it to Freebird.

**Prerequisite:** Clout trust records must be cryptographically
self-authenticating (signed edges, signed invitations, verifiable
timestamps). If they are not currently signed, that is a prerequisite
before Phase 1 can ship.

---

## 3. Trait Integration

### New `SybilProof` variant

```rust
pub enum SybilProof {
    // ... existing variants ...
    SocialGraph {
        /// Compact signed attestation from a trusted Social Graph Attester
        attestation: String,
        /// Proof that the requester controls the holder secret/key
        /// bound to the attestation
        presentation: String,
    },
    // ...
}
```

### Signed attestation payload

The attestation is a signed payload issued to Cred's controller key.
It is **not request-bound** at issuance time — Cred binds it to a
specific Freebird request at presentation time.

| Field | Purpose |
|---|---|
| `contract_version` | `"sophia/v1"` (canonical Sophia artifact) |
| `artifact_type` | `"social_graph.attestation"` |
| `version` | Attestation schema version |
| `attester_id` | Which attester issued this |
| `kid` | Key ID used to sign |
| `policy_id` | Which scoring policy was applied |
| `issued_at` | When the attestation was created |
| `expires_at` | When it expires (short-lived) |
| `eligibility_level` | Coarse score bucket (not exact score) |
| `quota_nullifier` | Optional epoch-scoped nullifier for quota |
| `jti` | Unique attestation ID (for replay prevention) |
| `holder_commitment` | Commitment to Cred controller's public key |
| `signature` | Attester's Ed25519 signature over all fields |

**Must not contain:** Clout public key, raw trust edges, invitation
path, exact SybilRank score, wallet address, ballot/rendezvous
identifiers, any stable user identifier, or any Freebird-specific
request binding. The attestation is general-purpose; Cred makes it
request-bound at presentation time.

### Cred presentation

When presenting to Freebird, Cred creates a `cred.presentation`
artifact containing:

- The signed attestation (embedded or referenced)
- `app_id`: the Freebird issuer identifier
- `request_id`: the Freebird issuance request ID
- `request_binding_hash`: hash of the Freebird request binding
- Cred controller's signature over the presentation

This presentation is what the client submits as
`SybilProof::SocialGraph.attestation`. The `presentation` field of
the proof contains the Cred presentation signature.

### Config struct

Environment variables:

| Variable | Purpose | Default |
|---|---|---|
| `SOCIAL_GRAPH_ATTESTERS_PATH` | Path to trusted attester key config | none (required) |
| `SOCIAL_GRAPH_JWKS_URL` | Optional JWKS URL for key refresh | none |
| `SOCIAL_GRAPH_KEY_REFRESH_INTERVAL` | How often to refresh attester keys | `1h` |
| `SOCIAL_GRAPH_MIN_LEVEL` | Minimum eligibility level to accept | `1` |
| `SOCIAL_GRAPH_ACCEPTED_POLICY_IDS` | Comma-separated accepted policy IDs | none (required) |
| `SOCIAL_GRAPH_ATTESTATION_MAX_AGE` | Maximum age of accepted attestations | `5m` |
| `SOCIAL_GRAPH_CLOCK_SKEW_SECS` | Allowed clock skew | `30` |
| `SOCIAL_GRAPH_REQUIRE_REQUEST_BINDING` | Require request binding match | `true` |
| `SOCIAL_GRAPH_REQUIRE_QUOTA_NULLIFIER` | Require epoch-scoped quota | `false` |
| `SOCIAL_GRAPH_REPLAY_TTL` | Replay store TTL | `10m` |
| `SOCIAL_GRAPH_STATE_PATH` | Persistent state path | `social_graph_state.json` |
| `SOCIAL_GRAPH_FAIL_CLOSED` | Reject if attester keys unavailable | `true` |

### State struct

The issuer persists only verifier-side state:

- Trusted attester metadata and public keys
- Accepted policy versions
- Key refresh timestamps
- Optional revoked attestation IDs or revoked key IDs
- Local metrics/counters

It does **not** persist graph records, Clout identities, score
histories, or edge snapshots.

### `verify_with_context` flow

1. Require `SybilProof::SocialGraph`
2. Parse the Cred presentation (contains the signed attestation +
   presentation metadata)
3. Verify Cred controller's signature over the presentation
4. Verify attester identity and key ID
5. Verify attester's Ed25519 signature over the attestation
6. Check `policy_id` is in accepted list
7. Check `issued_at`, `expires_at`, and max age
8. Check eligibility level >= `SOCIAL_GRAPH_MIN_LEVEL`
9. Require `ctx.request_binding` when configured
10. Compare `hash(ctx.request_binding)` to the presentation's
    `request_binding_hash`
11. Verify `holder_commitment` matches the Cred controller key that
    signed the presentation
12. Use replay store: `mark_once("social_graph:jti", jti, ttl)`

### Combined mode

The gate composes with existing gates via `combined` mode:

| Mode | Use case | Security note |
|---|---|---|
| `combined_or` | `social_graph OR invitation` | Only as strong as easiest mechanism |
| `combined_and` | `social_graph AND pow` | Both must pass — stronger |
| `combined_threshold` | 2 of 3 mechanisms | Flexible middle ground |

**Recommended production posture:**

- Low-value onboarding: `invitation OR social_graph`
- Higher-value issuance: `social_graph AND pow` or threshold mode
- Never treat `invitation` alone as equivalent to a strong social graph pass

### Replay store

Replay keys:
- `social_graph:jti:<attester_id>:<jti>` (always)
- `social_graph:quota:<attester_id>:<quota_nullifier>` (if quota enabled)

TTL should not exceed the attestation expiry. Redis-backed replay store
is required for clustered deployments.

---

## 4. Signal Sources

### Clout (primary signal)

Clout's trust graph is the strongest available signal. It is
structurally similar to BrightID's social graph, but emerges from real
social interaction rather than dedicated verification rituals.

**Usable signals:**
- Signed trust edges (who trusts whom, weight, timestamp)
- Signed invitation chain (inviter → invitee)
- Edge age and temporal decay
- Edge weight (0.1–1.0)
- Independent endorsers
- Seed-rooted paths
- Fanout behavior (how many people does each node trust?)
- Day Pass delegation history

**Privacy cost:** High if raw edges leave the browser. Raw Clout graph
data goes only to the dedicated attester, never to the Freebird issuer.

### Scarcity (weak secondary signal)

**Usable signals (coarse attestations only):**
- Wallet age bucket (e.g., "exists for >30 days")
- Activity count bucket (e.g., "participated in >5 transfers")
- "Has ongoing economic activity" boolean

**Must not expose:** Raw transfer history, token graph, nullifier
gossip, balances, or wallet addresses to Freebird.

### Prestige (excluded)

Per-person ballot participation breaks coercion resistance and
unlinkability. **Do not consume.**

### Rendezvous (excluded)

Cross-pool correlation breaks the core privacy model. Pseudonym
rotation makes cross-pool linkage intentionally impossible. **Do not
consume.**

---

## 5. Privacy Analysis

### Does this preserve issuance-redemption unlinkability?

**Yes**, if implemented as designed.

The issuer learns that a requester had a valid social-graph attestation
at issuance time. Redemption remains unlinkable because the redemption
token carries no graph identity or attestation metadata.

### What the issuer learns

- A trusted attester approved this request
- Coarse eligibility level (bucket, not exact score)
- Policy version
- Attestation expiry
- Request binding match
- Optional epoch-scoped quota nullifier

### What the issuer must not learn

- Clout public key
- Browser-local graph contents
- Trust edges or invitation path
- Exact graph score
- Wallet address or transfer history
- Ballot or rendezvous participation
- Stable cross-epoch social identity

### Attester trust boundary

With Cred in the middle, the attester's knowledge is significantly
reduced compared to direct client → attester → issuer flow:

**What the attester learns (Phase 1):**
- Cred controller public key (not Clout identity directly, though
  Clout evidence is submitted on the user's behalf)
- That the user is seeking social-graph eligibility
- The graph evidence submitted (signed Clout trust edges)

**What the attester does NOT learn:**
- Which Freebird issuer the user will present to
- When the attestation will be used
- The Freebird request binding
- Whether the attestation was ever used at all

This is a stronger privacy property than direct attester → issuer flow.
The attester issues a general-purpose eligibility attestation; Cred
makes it request-bound at presentation time.

**Stronger long-term design (Phase 3):**
- Blind signatures or BBS+ anonymous credentials (attester cannot link
  issuance to presentation even with Cred)
- Privacy Pass-style issuance
- Per-issuer/per-epoch unlinkable nullifiers
- Multiple independent attesters

Full privacy-preserving graph analytics remains an open research
problem. The practical design is **separation of duties plus anonymous
attestations**, not ZK proof of global graph position.

---

## 6. Threat Model

### Fake trust edges

Attackers create many fake Clout identities and mutually endorse them.

**Countermeasures:**
- Require seed-rooted paths
- Cap edge weight
- Apply fanout penalties (high-outdegree nodes are less trustworthy)
- Require minimum edge age
- Require independent roots
- Ignore fresh dense subgraphs

### Collusion rings

A group of real or fake users create a dense endorsement cluster.

**Countermeasures:**
- SybilRank-style propagation from trusted seeds
- Community diversity requirements
- Outbound trust budget per node
- Anomaly detection for dense new clusters

### Purchased invitations / bridge farming

Attackers buy endorsements from honest users or compromise weak bridges
into the honest region.

**Countermeasures:**
- Require multiple independent paths
- Decay or penalize high-fanout endorsers
- Delay the effect of new trust edges
- Slash or downgrade endorsers linked to abuse
- Cap blast radius per trusted node

### Eclipse attacks

An attacker surrounds a victim or feeds the attester only
attacker-controlled graph evidence.

**Countermeasures:**
- Cross-check against known roots/indexes where possible
- Reject isolated client-only snapshots
- Require independent corroboration
- Use key transparency or append-only logs for trust records

### Whaling

Attackers compromise high-trust Clout nodes and use them to vouch many
Sybils.

**Countermeasures:**
- Per-voucher issuance caps
- Anomaly detection on endorsement spikes
- Delayed trust activation
- Revocation
- Hardware-backed protection for high-trust accounts
- Blast-radius limits

### Temporal decay

Decay helps because instant farming is less valuable. Older, stable
relationships carry more weight.

**Limits:**
- Patient attackers can farm aged accounts
- Compromised aged accounts remain dangerous
- Purchased aged accounts bypass freshness checks

### Operator warning signs

Operators should monitor for:
- Sudden increase in accepted social-graph attestations
- One attester dominating eligibility
- One seed or voucher creating many accepted users
- Sharp score distribution shifts
- High rejection due to stale keys or replay failures
- Attestation API outages
- Repeated quota-nullifier collisions
- Privacy-sensitive fields appearing in logs

### Comparison to existing `invitation` gate

| Property | `invitation` | `social_graph` |
|---|---|---|
| Farming cost | Low (one invite code) | Higher (requires aged, diverse trust) |
| Complexity | Simple | Complex (external attester, graph analysis) |
| Privacy risk | Low (issuer sees invite code) | Medium (attester sees graph evidence) |
| Bootstrapping | Built-in | Requires invitation fallback |
| Operational burden | Low | Higher (attester service, key management) |

---

## 7. Bootstrapping

New users with no Clout trust history need a path in.

### Recommended model

1. **Entry:** Use existing `invitation` gate as the bootstrap mechanism
2. **Probation:** New users get low initial privileges
3. **Accumulation:** Users build Clout trust history over time
4. **Promotion:** After enough aged, independent signals exist,
   promote to social-graph eligibility

A single invitation should **not** equal high-trust social-graph
eligibility.

### Minimum viable admission

One of:
- Trusted invitation plus waiting period
- Two independent aged trust edges
- Seed-rooted path within limited depth
- Low-risk progressive-trust history
- Threshold combination of invitation + proof-of-work + time

### Cold-start resolution

The cold-start problem is solved by separating concerns:

| Stage | Mechanism | Privilege level |
|---|---|---|
| Entry | Invitation or community bootstrap | Minimal |
| Promotion | Social graph reputation accumulated | Standard |
| High-value | Stronger threshold requiring graph maturity | Elevated |

---

## 8. Implementation Phases

### Pre-Phase 1: Research and prototyping

Before implementation:

- [ ] Define attestation schema (fields, encoding, signature format)
- [ ] Define Cred `social_graph` adapter contract (import + present)
- [ ] Define SophiaDOS `schemas/social-graph-attestation.schema.json`
- [ ] Decide signing format: JWS, COSE, or canonical JSON signature
- [ ] Confirm Clout trust records are signed and independently verifiable
- [ ] Prototype Cred presentation with request binding
- [ ] Prototype replay/quota handling
- [ ] Choose initial thresholds
- [ ] Test false positives/false negatives on sample graphs
- [ ] Define attester key rotation and revocation
- [ ] Document privacy boundary and logging rules

**If Clout cannot produce verifiable trust evidence, Phase 1 should not
ship.**

> **Update:** Investigation confirmed Clout trust edges ARE signed with
> Ed25519 and are independently verifiable by a third party. The Phase 1
> prerequisite is met. See resolved open question #1 below.

### Phase 1: MVP

**Build (Freebird):**
- `SybilProof::SocialGraph` variant
- Issuer-side verifier gate (verifies Cred presentation + attester sig)
- Trusted attester key config (JWKS)
- Replay-store integration
- Coarse eligibility levels

**Build (Cred):**
- `social_graph` adapter: `import-attestation` + `present-attestation`
- Permission grant type: `social_graph.present`
- Presentation binding to Freebird `app_id` + `request_id` +
  `request_binding_hash`

**Build (Social Graph Attester):**
- New service: accepts Clout trust evidence from Cred
- Validates Ed25519 signatures on trust edges
- Runs scoring heuristic
- Issues signed attestation to Cred controller key
- JWKS key publication endpoint
- Key rotation support

**Build (SophiaDOS):**
- `schemas/social-graph-attestation.schema.json`
- `scripts/run-social-graph-live-seam.sh` smoke test

**Signals:**
- Clout signed trust edges
- Edge age
- Edge weight
- Independent endorsers

**Algorithm:**
- Simple heuristic, not full SybilRank
- Seed-rooted trust score
- Temporal decay
- Fanout caps
- Minimum independent endorsements

**Privacy:**
- Freebird issuer sees only Cred presentation + eligibility level
- Attester sees Cred controller key + Clout evidence, but NOT which
  Freebird instance the user will present to
- Cred enforces per-use human approval before presentation

**Limitations:**
- Attester is trusted (sees graph evidence)
- No full privacy-preserving graph analytics
- Collusion and bridge farming remain possible
- Heuristic thresholds require tuning

### Phase 2: Stronger graph scoring

**Build:**
- Opt-in graph indexer or Clout-hosted attestation API
- Periodic SybilRank / personalized PageRank computation
- Community diversity scoring
- Abuse feedback loop
- Attester revocation and policy versioning
- Optional coarse Scarcity participation attestations

**Signals:**
- Larger Clout graph
- Signed trust edges
- Invitation roots
- Edge age/decay
- Coarse wallet activity attestations

**Privacy:**
- Issuer still sees only attestations
- Attester/indexer sees more graph data (preferably opt-in and minimized)

**Limitations:**
- Seed bias
- Governance complexity
- Graph indexer becomes sensitive infrastructure

### Phase 3: Full vision

**Build:**
- Anonymous credential issuance (BBS+ or similar)
- Blind attestations
- Per-issuer/per-epoch unlinkable nullifiers
- Multiple independent attesters
- Audited policy engine
- Robust revocation
- Community-local scoring
- Optional stake/time/activity hybrid model

**Signals:**
- Clout primary
- Scarcity only as coarse privacy-preserving attestations
- No raw Prestige or Rendezvous signals

**Privacy:**
- Issuer cannot identify graph participant
- Attester ideally cannot link credential issuance to Freebird presentation
- Redemption remains unlinkable

**Limitations:**
- Fully private global Sybil detection is still an open research problem
- Practical system still depends on trusted seeds, governance, and monitoring

---

## 9. Open Questions

1. ~~Are Clout trust edges currently signed and independently verifiable?~~
   **Resolved: Yes.** Clout trust edges are signed with Ed25519 over a
   canonical payload hash (truster, trustee, weight, timestamp, revoked).
   Both plaintext and encrypted trust signals carry signatures. Timestamps
   are bound into the signature and backed by Witness attestations. A
   third-party attester can independently verify trust edges without Clout
   being present. Invitation codes are NOT currently signed by the inviter
   — this is a non-blocking gap that could be addressed in a future Clout
   change to strengthen the invitation chain signal. See
   `clout/src/trust/plaintext-signal.ts:18-52` and
   `clout/src/crypto.ts:614-744`.
2. ~~Who operates the Social Graph Attester?~~
   **Confirmed: Same operator as the Freebird issuer for Phase 1.** This
   is simplest, keeps trust concentrated in one party the deployer
   already trusts, and avoids multi-party attester governance complexity.
   Phase 3 targets multiple independent attesters for stronger trust
   distribution.
3. ~~Is the attester allowed to know the user is requesting Freebird
   eligibility?~~
   **Resolved (technical): Yes, in Phase 1.** The attester issues a
   request-bound attestation (`request_binding_hash` field), so it
   inherently knows the user is seeking Freebird eligibility. The attester
   learns: Clout identity + that the user wants Freebird eligibility +
   the request binding hash. It does NOT learn: what the token will be
   used for, when redemption happens, or who the verifier is. Phase 3
   targets blind attestations to close this gap.
4. ~~Should quota be enforced by the attester only, or also via
   issuer-visible epoch nullifiers?~~
   **Resolved (technical): Both layers.** The attester enforces
   per-Clout-identity quota (how many attestations per identity per
   epoch) — this is the primary quota. The issuer also checks the
   `quota_nullifier` via replay store (`mark_once("social_graph:quota",
   nullifier, ttl)`) to prevent attestation reuse across issuers or
   attesters — this is the secondary defense. Controlled by
   `SOCIAL_GRAPH_REQUIRE_QUOTA_NULLIFIER` config flag.
5. ~~What is the minimum acceptable eligibility threshold for Phase 1?~~
   **Confirmed: Conservative starting values:**
   - At least 2 independent trust edges from distinct Clout identities
   - Edge age > 7 days (prevents instant farming)
   - Minimum weighted trust score of 0.3 (on Clout's 0.1–1.0 scale)
   - At least 1 seed-rooted path (connected to the invitation tree root)
   - Fanout cap: endorsers with >20 outbound trust edges get discounted

   These are deliberately conservative — they'll reject most farmers
   while accepting genuine community members. They'll need tuning with
   real graph data during Pre-Phase 1 prototyping.
6. ~~How are attester keys rotated and revoked?~~
   **Resolved (technical): Standard JWKS pattern.**
   - Attester generates Ed25519 keypair, publishes public key at a
     well-known URL (JWKS format)
   - Issuer fetches and caches keys, refreshes on
     `SOCIAL_GRAPH_KEY_REFRESH_INTERVAL` (default 1h)
   - Rotation: attester generates new keypair, publishes new JWKS, signs
     new attestations with new key. Old key remains valid for a grace
     period (controlled by `SOCIAL_GRAPH_ATTESTATION_MAX_AGE`).
   - Revocation: attester publishes a key revocation list (revoked `kid`
     values). Issuer checks on each verification. Short key TTL (e.g.,
     24h) means revoked keys expire quickly.
   - Emergency revocation: issuer operator can manually add a `kid` to
     a local revocation list in `SOCIAL_GRAPH_STATE_PATH`.
7. ~~What abuse feedback can Freebird safely send back without
   deanonymizing redeemers?~~
   **Resolved (technical): Very little, by design.**
   - The issuer can publish **aggregate** statistics: attestation
     acceptance/rejection counts, attester ID distribution, policy ID
     distribution. These are safe because they don't link to individual
     users.
   - The issuer must NOT send per-user feedback to the attester. Any
     feedback channel from issuer to attester about specific
     attestations (jti, holder commitment, request binding) would
     create a correlation path between Freebird issuance and the
     attester's Clout identity records.
   - The attester should detect abuse through its own graph analysis
     (dense new clusters, endorsement spikes, etc.), not through issuer
     feedback.
   - If abuse is detected (e.g., a farmed cluster), the attester
     revokes eligibility for those Clout identities at the attester
     level. The issuer doesn't need to know why.
8. ~~What fields are safe to log?~~
   **Resolved (technical): Different rules for issuer vs. attester.**

   **Issuer-side (safe at INFO level):**
   - `attester_id`, `policy_id`, `eligibility_level` (bucket)
   - `jti` (for replay debugging — rotate logs frequently)
   - `request_binding_hash` (not the binding itself)
   - timestamp, accept/reject decision
   - reject reason (generic: "expired", "bad signature", "replay",
     "below threshold")

   **Issuer-side (must NOT log):**
   - Clout public key
   - Graph data (edges, scores, invitation chains)
   - Exact SybilRank score
   - Holder commitment (unless DEBUG level with short retention)
   - Full attestation payload

   **Attester-side (safe to log, but more sensitive):**
   - Clout identity, evidence submitted, score computed, attestation
     issued (jti, expiry)
   - These logs need their own retention policy and access controls.
9. ~~Should different Freebird issuance classes require different
   social-graph levels?~~
   **Confirmed: Yes.** The gate supports this via `SOCIAL_GRAPH_MIN_LEVEL`
   config. Starting classes:
   - Low-value onboarding (e.g., basic Clout posting): level >= 1
   - Standard issuance (e.g., Scarcity transfers): level >= 2
   - High-value issuance (e.g., Prestige ballot creation): level >= 3

   Different Freebird instances can be configured with different
   thresholds. The specific classes and levels are the operator's
   policy decision.
10. ~~What is the governance process for trusted seeds and policy
    changes?~~
    **Confirmed: Phased approach.**
    - Phase 1: Single operator decides. The operator configures trusted
      seeds and policy IDs via environment variables. Changes require
      restarting the issuer with new config.
    - Phase 2: Community vote via Prestige (uses existing infrastructure
      in the ecosystem).
    - Phase 3: Multi-party threshold approval (most robust, most
      complex).

---

## Research basis

This blueprint was produced by three parallel research lanes, followed
by architectural design review, followed by Cred/SophiaDOS integration:

1. **Freebird architecture review** — `SybilResistance` trait, existing
   gates, combiners, replay store, persistence patterns, startup wiring
2. **App signal survey** — Clout, Scarcity, Prestige, Rendezvous trust
   signals, data structures, queryability, privacy costs
3. **Sybil detection literature** — SybilGuard, SybilLimit, SumUp,
   SybilInfer, SybilRank, BrightID/Aura, privacy-preserving graph
   analysis, attack taxonomy, bootstrapping strategies
4. **Cred + SophiaDOS review** — user agent custody/presentation model,
   `sophia/v1` canonical contract, permission grants, existing adapter
   pattern (Freebird/Witness/Matchlock), smoke harness integration

Key findings that shaped the design:

- **SybilRank** is the practical baseline for seed-based trust
  propagation, but pure graph topology is insufficient. Multi-signal
  scoring (graph + temporal + economic) is stronger.
- **Privacy-preserving full-graph Sybil detection is an open research
  problem.** The practical resolution is separation of duties: graph
  analysis at a dedicated attester, anonymous attestation to the issuer,
  unlinkable redemption.
- **Clout is the only viable primary signal source.** Its trust graph
  is structurally similar to BrightID's, but emerges from real social
  interaction. Scarcity can contribute weak secondary signals.
  Prestige and Rendezvous cannot be consumed without breaking their
  own privacy models.
- **The attester pattern** follows Freebird's existing architecture:
  the issuer verifies a proof, it does not perform the underlying
  computation. Just as the issuer verifies a PoW nonce without mining
  it, the issuer verifies a social-graph attestation without computing
  the graph score.
- **Cred mediation** strengthens the privacy boundary: the attester
  issues a general-purpose eligibility attestation to Cred's controller
  key without knowing which Freebird instance the user will present to.
  Cred binds the presentation to a specific Freebird request at
  presentation time, enforcing per-use human approval and permission
  grant constraints.
- **SophiaDOS** provides the canonical contract layer: the attestation
  is a `sophia/v1` artifact with a JSON Schema, conformance checks, and
  a smoke harness seam that validates the full attester → Cred →
  Freebird flow end-to-end.
