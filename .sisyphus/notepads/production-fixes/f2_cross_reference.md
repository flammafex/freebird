# F2: Cross-Reference Integrity Check

**Date:** 2026-04-28
**Scope:** docs/ directory, root markdown files, docker-compose.yaml
**Checks:** Stale references + broken cross-references

---

## Stale References Checked

| Pattern | Files Searched | Matches |
|---------|----------------|---------|
| `ADMIN_API_KEY` described as "optional" | All `*.md` | 0 |
| `WEBAUTHN_PROOF_SECRET` described as "recommended" | All `*.md` | 0 |
| `grace_period_secs: 0` | All `*.md` | 0 |
| `rayon` for batch issuance | docs/, README.md, CONTRIBUTING.md | 0 |
| `x86_64` for Docker images | CONTRIBUTING.md | 0 |
| `/.well-known/issuer` used as healthcheck | docker-compose.yaml | 0 |

**Result:** No stale references remain.

---

## Broken Cross-References

**1 found:**

- `docs/SYBIL_RESISTANCE.md:134`
  - Link: `[Configuration Reference](CONFIGURATION.md#invitation-system)`
  - Issue: Target heading in `CONFIGURATION.md` is `### Invitation` (line 156), which generates anchor `#invitation`. The link uses `#invitation-system`, which does not exist.
  - Fix: Change link to `CONFIGURATION.md#invitation`.

All other relative file links and cross-file anchors were verified and resolve correctly.

---

## Verdict

**REJECT**

1 broken cross-reference found between docs. Stale reference sweep is clean, but the broken anchor in `SYBIL_RESISTANCE.md` must be fixed before approval.
