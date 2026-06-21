# Social Graph Gate Test Methodology

> Status: Pre-Phase 1 test-design document.
>
> Scope: attester-side scoring tests for the Phase 1 `social_graph`
> heuristic. The Freebird issuer must still receive only signed Cred
> presentations and social-graph attestations, never raw graph evidence.

## 1. Purpose

This document defines sample Clout trust graphs and a scoring-test
methodology for validating the Phase 1 `social_graph` Sybil gate heuristic.

The heuristic under test:

- At least 2 independent trust edges from distinct Clout identities
- Edge age > 7 days
- Minimum weighted trust score of 0.3 on Clout's 0.1-1.0 scale
- At least 1 seed-rooted path connected to the invitation tree root
- Fanout cap: endorsers with >20 outbound trust edges are discounted

Clout trust edges are assumed to be Ed25519-signed over canonical payloads:

```text
truster, trustee, weight, timestamp, revoked
```

These tests validate the attester's graph scoring policy. They do not replace
issuer-side tests for attestation signature verification, request binding,
expiry, replay, or Cred presentation verification.

---

## 2. Scoring model for tests

For deterministic Phase 1 tests, use this concrete interpretation.

### Constants

```text
MIN_INDEPENDENT_EDGES = 2
MIN_EDGE_AGE_DAYS = 7       # strict: age must be > 7
MIN_WEIGHTED_SCORE = 0.3
FANOUT_CAP = 20
```

### Edge eligibility

A trust edge is eligible for scoring if:

1. The Ed25519 signature verifies.
2. `revoked == false`.
3. `0.1 <= weight <= 1.0`.
4. `trustee == subject`.
5. `age_days > 7`.

### Fanout discount

For each eligible inbound edge:

```text
fanout_factor = min(1.0, FANOUT_CAP / active_out_degree(truster))
effective_weight = raw_weight * fanout_factor
```

Where `active_out_degree(truster)` is the number of non-revoked outbound trust
edges known to the attester for that truster.

Important: fanout cannot be safely computed from only user-submitted inbound
edges. Tests that exercise fanout must include the endorser's outbound inventory
or an attester-known outdegree source. Otherwise a client could omit edges and
evade the cap.

### Weighted score

Use the average effective weight across the subject's independent eligible
endorsers:

```text
weighted_score = mean(best_effective_weight_per_distinct_truster)
```

The "minimum viable" case with weights `0.4` and `0.3` therefore scores `0.35`
and passes barely.

### Seed-rooted path

A subject is seed-rooted if there is at least one directed path:

```text
trusted_seed_root -> ... -> subject
```

using valid, non-revoked, age-qualified edges.

For Phase 1 tests, no SybilRank/PageRank is used. The root check is only a
reachability check over the supplied/known signed graph evidence.

---

## 3. Sample graph structures

Public keys are placeholders. `R0` is the trusted invitation-tree seed root.

### 3.1 Healthy community — should PASS

A realistic small community with organic trust relationships.

#### Nodes

```text
R0                  seed root
A_alice             established member
B_bob               established member
C_carol             established member
D_dana              established member
T_healthy           candidate
```

#### Edges

```text
R0       -> A_alice     weight 0.9 age 365d
R0       -> B_bob       weight 0.8 age 300d
A_alice  -> C_carol     weight 0.7 age 180d
B_bob    -> D_dana      weight 0.6 age 120d

A_alice  -> T_healthy   weight 0.8 age 90d
B_bob    -> T_healthy   weight 0.6 age 45d
C_carol  -> T_healthy   weight 0.4 age 20d
```

#### Expected result

```text
PASS
```

#### Why

- Independent endorsers: 3
- All candidate inbound edges are older than 7 days
- Weighted score: `(0.8 + 0.6 + 0.4) / 3 = 0.6`
- Seed-rooted path exists: `R0 -> A_alice -> T_healthy`

---

### 3.2 New user, cold start — should FAIL

A legitimate-looking new user with insufficient trust history.

#### Nodes

```text
R0
E_erin
T_cold_start
```

#### Edges

```text
R0      -> E_erin         weight 0.8 age 100d
E_erin  -> T_cold_start   weight 0.7 age 2d
```

#### Expected result

```text
FAIL
primary reason: insufficient_independent_edges
additional reason: edge_too_young
```

#### Why

- Only 1 inbound trust edge
- Candidate edge age is only 2 days
- This is a deliberate false negative risk for legitimate new users

---

### 3.3 New user, minimum viable — should PASS barely

A user with exactly the minimum acceptable trust evidence.

#### Nodes

```text
R0
M_mia
N_noah
T_minimum_viable
```

#### Edges

```text
R0      -> M_mia              weight 0.8 age 120d
R0      -> N_noah             weight 0.8 age 120d

M_mia   -> T_minimum_viable   weight 0.4 age 8d
N_noah  -> T_minimum_viable   weight 0.3 age 8d
```

#### Expected result

```text
PASS
```

#### Why

- Independent endorsers: 2
- Candidate edges are older than 7 days
- Weighted score: `(0.4 + 0.3) / 2 = 0.35`
- Seed-rooted path exists

This case should remain close to the threshold and is useful for catching
off-by-one age bugs and score-computation drift.

---

### 3.4 Collusion ring — should FAIL

Ten fake identities mutually trust each other with high weights, but the cluster
is new and disconnected from the seed root.

#### Nodes

```text
F_fake_01
F_fake_02
F_fake_03
F_fake_04
F_fake_05
F_fake_06
F_fake_07
F_fake_08
F_fake_09
F_fake_10
```

Subject under test:

```text
F_fake_01
```

#### Edges

For every ordered pair `i != j`:

```text
F_fake_i -> F_fake_j weight 0.9 age 1d
```

No edge from `R0` or any rooted honest member reaches the fake cluster.

#### Expected result

```text
FAIL
primary reason: no_seed_rooted_path
additional reason: edge_too_young
```

#### Why

- Dense trust is not enough
- All edges are too young
- No seed-rooted path exists

This should catch implementations that only count inbound endorsements and
ignore graph rootedness.

---

### 3.5 Bridge farming — should FAIL

A farmer bought three endorsements from honest users, but the edges are fresh.

#### Nodes

```text
R0
H_honest_01
H_honest_02
H_honest_03
T_bridge_farmer
```

#### Edges

```text
R0           -> H_honest_01       weight 0.9 age 300d
R0           -> H_honest_02       weight 0.9 age 300d
R0           -> H_honest_03       weight 0.9 age 300d

H_honest_01  -> T_bridge_farmer   weight 0.8 age 2d
H_honest_02  -> T_bridge_farmer   weight 0.7 age 2d
H_honest_03  -> T_bridge_farmer   weight 0.6 age 2d
```

#### Expected result

```text
FAIL
primary reason: edge_too_young
```

#### Why

- 3 independent endorsers exist
- Seed-rooted paths exist
- Raw score would be high
- But all candidate endorsements are only 2 days old

This validates the anti-instant-farming delay.

---

### 3.6 Aged farmer — should PASS, known false negative

A patient farmer cultivated or bought trust edges and waited 30 days.

#### Nodes

```text
R0
H_honest_04
H_honest_05
H_honest_06
T_aged_farmer
```

#### Edges

```text
R0           -> H_honest_04     weight 0.9 age 300d
R0           -> H_honest_05     weight 0.9 age 300d
R0           -> H_honest_06     weight 0.9 age 300d

H_honest_04  -> T_aged_farmer   weight 0.5 age 30d
H_honest_05  -> T_aged_farmer   weight 0.4 age 30d
H_honest_06  -> T_aged_farmer   weight 0.4 age 30d
```

#### Expected result

```text
PASS
```

#### Why

- Independent endorsers: 3
- Edges are older than 7 days
- Weighted score: `(0.5 + 0.4 + 0.4) / 3 = 0.433`
- Seed-rooted paths exist

#### Security interpretation

This is a known false negative: the Phase 1 heuristic cannot reliably detect
patient bridge farming. Mitigations require Phase 2 signals such as abuse
feedback, voucher reputation, community diversity, per-voucher quotas, or
SybilRank-like propagation.

---

### 3.7 Whaling victim — should FAIL

A high-trust account suddenly endorses many new identities. The test isolates
the fanout cap by giving each new identity two independent edges that would pass
without discounting.

#### Nodes

```text
R0
W_whale
L_low_weight_helper
S_whale_01
S_whale_02
...
S_whale_15
Legacy_01
...
Legacy_35
```

#### Edges

Rooting edges:

```text
R0 -> W_whale             weight 1.0 age 365d
R0 -> L_low_weight_helper weight 0.8 age 365d
```

Whale's existing outbound inventory:

```text
W_whale -> Legacy_01  weight 0.6 age 100d
...
W_whale -> Legacy_35  weight 0.6 age 100d
```

New burst:

```text
W_whale             -> S_whale_01 weight 1.0 age 10d
L_low_weight_helper -> S_whale_01 weight 0.1 age 10d

W_whale             -> S_whale_02 weight 1.0 age 10d
L_low_weight_helper -> S_whale_02 weight 0.1 age 10d

...

W_whale             -> S_whale_15 weight 1.0 age 10d
L_low_weight_helper -> S_whale_15 weight 0.1 age 10d
```

Each `S_whale_N` is evaluated independently as the subject.

#### Expected result

```text
FAIL
primary reason: weighted_score_below_threshold_after_fanout
```

#### Why

For each new identity:

```text
active_out_degree(W_whale) = 35 legacy + 15 new = 50
fanout_factor(W_whale) = 20 / 50 = 0.4
effective whale edge = 1.0 * 0.4 = 0.4
helper edge = 0.1
weighted_score = (0.4 + 0.1) / 2 = 0.25
```

Without fanout discounting:

```text
score = (1.0 + 0.1) / 2 = 0.55
```

So this case specifically validates that high-fanout endorsers do not retain
unbounded endorsement power.

---

## 4. Scoring algorithm pseudocode

```text
function evaluate_social_graph(subject, signed_edges, trusted_roots, now):
    reasons = []

    valid_edges = []

    for edge in signed_edges:
        payload = canonical_json({
            "truster": edge.truster,
            "trustee": edge.trustee,
            "weight": edge.weight,
            "timestamp": edge.timestamp,
            "revoked": edge.revoked
        })

        if !ed25519_verify(edge.truster, payload, edge.signature):
            return Fail(["bad_signature"])

        if edge.weight < 0.1 or edge.weight > 1.0:
            return Fail(["invalid_weight"])

        if edge.revoked:
            continue

        valid_edges.append(edge)

    active_out_degree = map default 0

    for edge in valid_edges:
        active_out_degree[edge.truster] += 1

    age_qualified_edges = []

    for edge in valid_edges:
        if age_days(edge.timestamp, now) > 7:
            age_qualified_edges.append(edge)

    # Seed-rooted reachability over age-qualified active graph.
    if !has_path_from_any_root(trusted_roots, subject, age_qualified_edges):
        reasons.append("no_seed_rooted_path")

    inbound_to_subject = []

    for edge in valid_edges:
        if edge.trustee == subject:
            inbound_to_subject.append(edge)

    if inbound_to_subject.length == 0:
        reasons.append("no_inbound_trust_edges")

    eligible_by_age = []

    for edge in inbound_to_subject:
        if age_days(edge.timestamp, now) > 7:
            eligible_by_age.append(edge)

    if eligible_by_age.length < inbound_to_subject.length:
        reasons.append("edge_too_young")

    # Deduplicate by truster. If multiple edges exist from same truster to
    # subject, keep only the highest effective contribution.
    best_by_truster = map truster -> effective_weight

    for edge in eligible_by_age:
        out_degree = active_out_degree[edge.truster]

        if out_degree == 0:
            continue

        fanout_factor = min(1.0, FANOUT_CAP / out_degree)
        effective_weight = edge.weight * fanout_factor

        current = best_by_truster.get(edge.truster)
        if current is missing or effective_weight > current:
            best_by_truster[edge.truster] = effective_weight

    independent_count = best_by_truster.length

    if independent_count < MIN_INDEPENDENT_EDGES:
        reasons.append("insufficient_independent_edges")

    if independent_count > 0:
        weighted_score = mean(best_by_truster.values)
    else:
        weighted_score = 0.0

    if weighted_score < MIN_WEIGHTED_SCORE:
        reasons.append("weighted_score_below_threshold")

    if reasons is empty:
        return Pass({
            "weighted_score": weighted_score,
            "independent_edges": independent_count
        })
    else:
        return Fail(reasons)


function has_path_from_any_root(roots, subject, edges):
    adjacency = map truster -> list trustee

    for edge in edges:
        adjacency[edge.truster].push(edge.trustee)

    visited = set()
    queue = roots

    while queue not empty:
        node = queue.pop_front()

        if node == subject:
            return true

        if node in visited:
            continue

        visited.add(node)

        for next in adjacency[node]:
            if next not in visited:
                queue.push(next)

    return false
```

Implementation note: return all failure reasons, not only the first. Tests can
assert that the expected primary reason is present without making reason order
brittle.

---

## 5. False positive / false negative analysis

### Healthy community

Expected heuristic result: pass.

False positives:

- None in this fixture.

False negatives:

- Possible if organic communities have naturally high-fanout organizers and
  the fanout cap discounts them too aggressively.

Tuning:

- Track score distribution on real data before raising thresholds.
- Consider community-specific seed roots in Phase 2.

---

### New user, cold start

Expected heuristic result: fail.

False positives:

- None.

False negatives:

- Legitimate new users fail until they accumulate a second aged trust edge.

Tuning:

- Use invitation or progressive-trust gates for bootstrapping.
- Keep social graph eligibility for promotion, not first contact.

---

### New user, minimum viable

Expected heuristic result: pass.

False positives:

- A minimally coordinated attacker with two aged rooted endorsements can pass.

False negatives:

- Legitimate users with one strong endorsement still fail.

Tuning:

- If abuse is high, increase `MIN_INDEPENDENT_EDGES` to 3.
- If onboarding is too strict, allow `social_graph AND invitation` threshold
  combinations for lower privilege.

---

### Collusion ring

Expected heuristic result: fail.

False positives:

- A collusion ring that obtains one or more aged rooted bridge edges can pass
  this simple test.

False negatives:

- A real new subcommunity disconnected from the configured seed root also fails.

Tuning:

- Add independent-root requirements.
- Add community diversity scoring.
- Add dense-new-cluster anomaly detection in Phase 2.

---

### Bridge farming

Expected heuristic result: fail.

False positives:

- Farmers who wait past the age threshold can pass.

False negatives:

- Legitimate users receiving several recent endorsements fail for at least
  7 days.

Tuning:

- Increase the edge age threshold for higher-value issuance.
- Apply probation instead of outright rejection for fresh but otherwise strong
  evidence.

---

### Aged farmer

Expected heuristic result: pass.

False positives:

- This is the main known false negative: patient attackers can farm trust over
  time and pass.

False negatives:

- None in this fixture.

Tuning:

- Voucher reputation.
- Per-voucher issuance caps.
- Abuse-linked downgrades.
- Community diversity.
- Longer edge age for higher issuance levels.
- Phase 2 SybilRank/PageRank-style propagation.

---

### Whaling victim

Expected heuristic result: fail.

False positives:

- If the attester cannot see the whale's full outbound inventory, the attacker
  may evade fanout discounting by submitting only the target endorsements.

False negatives:

- Legitimate high-trust organizers who endorse many real users may be
  over-discounted.

Tuning:

- Require attester-known outbound inventory for fanout enforcement.
- Add per-voucher burst detection.
- Use time-windowed fanout, not only total outdegree.
- Consider different caps for verified high-trust institutional accounts, but
  only with explicit governance.

---

## 6. JSON test data format

Automated tests should use a fixture format like:

```json
{
  "schema_version": "social_graph_test/v1",
  "policy": {
    "policy_id": "clout-trust-v1",
    "now_unix": 1760000000,
    "min_independent_edges": 2,
    "min_edge_age_days_exclusive": 7,
    "min_weighted_score": 0.3,
    "fanout_cap": 20,
    "trusted_seed_roots": ["R0"]
  },
  "cases": [
    {
      "case_id": "minimum_viable",
      "description": "Two independent aged edges, score 0.35.",
      "subject": "T_minimum_viable",
      "nodes": [
        { "id": "R0", "kind": "seed" },
        { "id": "M_mia", "kind": "honest" },
        { "id": "N_noah", "kind": "honest" },
        { "id": "T_minimum_viable", "kind": "candidate" }
      ],
      "edges": [
        {
          "truster": "R0",
          "trustee": "M_mia",
          "weight": 0.8,
          "age_days": 120,
          "revoked": false,
          "signature": "fake-ed25519:minimum_viable:edge:1",
          "signature_valid": true
        },
        {
          "truster": "R0",
          "trustee": "N_noah",
          "weight": 0.8,
          "age_days": 120,
          "revoked": false,
          "signature": "fake-ed25519:minimum_viable:edge:2",
          "signature_valid": true
        },
        {
          "truster": "M_mia",
          "trustee": "T_minimum_viable",
          "weight": 0.4,
          "age_days": 8,
          "revoked": false,
          "signature": "fake-ed25519:minimum_viable:edge:3",
          "signature_valid": true
        },
        {
          "truster": "N_noah",
          "trustee": "T_minimum_viable",
          "weight": 0.3,
          "age_days": 8,
          "revoked": false,
          "signature": "fake-ed25519:minimum_viable:edge:3",
          "signature_valid": true
        }
      ],
      "expected": {
        "pass": true,
        "weighted_score": 0.35,
        "independent_edges": 2,
        "failure_reasons": []
      }
    }
  ]
}
```

### Field notes

- `age_days` is fixture sugar. Test loaders should convert it to a deterministic
  `timestamp = now_unix - age_days * 86400`.
- `signature` may be fake for pure scoring tests if the signature verifier is
  mocked.
- Separate signature-verification tests should use real generated Ed25519 test
  vectors.
- `signature_valid` is test-only metadata and must not exist in production
  evidence.
- Fanout tests must include enough outbound edges for endorsers to compute
  `active_out_degree`.
- Expected failures should assert that `failure_reasons` contains the intended
  reason, not that it is the only reason, unless the test is designed to isolate
  a single rule.

Recommended failure reason strings:

```text
bad_signature
invalid_weight
no_inbound_trust_edges
insufficient_independent_edges
edge_too_young
weighted_score_below_threshold
no_seed_rooted_path
```

---

## 7. Minimum automated test suite

The Phase 1 prototype should include at least these tests:

1. `healthy_community_passes`
2. `cold_start_fails`
3. `minimum_viable_passes`
4. `collusion_ring_fails_without_seed_root`
5. `bridge_farming_fails_when_edges_too_young`
6. `aged_farmer_passes_known_false_negative`
7. `whaling_fails_due_to_fanout_discount`
8. `revoked_edges_are_ignored`
9. `bad_signature_rejects_evidence`
10. `duplicate_edges_from_same_truster_count_once`

The last three are not sample graph scenarios, but they are essential for
security regression coverage.
