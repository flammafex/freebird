# Docker Compose backup and restore

`scripts/backup-restore.sh` is the only supported Freebird backup mechanism for Docker Compose. It is **not** a Kubernetes backup tool. Kubernetes persistence must be handled by a separately reviewed native procedure.

## Prerequisites and custody

The operator host needs Docker Compose v2, `age`, `minisign`, Python 3, and `curl`. Fixture commands run with a bounded, fixed-argv runner: GNU `timeout` is preferred, then Homebrew's `gtimeout`, with a Python standard-library subprocess fallback. `BACKUP_HELPER_TIMEOUT` is seconds (or a numeric value suffixed with `s`, `m`, `h`, or `d`). Install or build the `freebird-interface` binary and make it available as `freebird-interface` (or set `FREEBIRD_INTERFACE_BIN`). Redis must be the Compose container and use a resolved named volume; bind mounts and unknown authoritative paths fail closed. Copy `.env.example` to `.env` first. `scripts/backup_archive.py` owns archive/state parsing and uses only the Python standard library.

Keep these controls outside the archive and under separate access control:

* `BACKUP_AGE_RECIPIENTS` encrypts archives; `BACKUP_AGE_IDENTITY` is required for both `verify` and `restore`/`recover`.
* `BACKUP_MINISIGN_SECRET_KEY` signs manifests; `BACKUP_MINISIGN_PUBLIC_KEY` is an externally pinned verification key and is required for verification and recovery.
* `BACKUP_STATE_DIR` contains filesystem-protected, canonical JSON high-water/accepted/rollback records. It is not cryptographically authenticated by this tool. Do not place it in a volume being restored.

Initialize operator state explicitly once, before any backup or restore:

```sh
scripts/backup-restore.sh init
```

The post-mutation recovery command is `scripts/backup-restore.sh recover ARCHIVE`; it requires the exact confirmation and reason printed by the failed operation and is usable while Compose services are stopped.

Missing, partial, or corrupt state is rejected; the script never silently
reinitializes it. The fixed interface contract is:
`freebird-interface backup-fixture create --output PATH` and
`freebird-interface backup-fixture validate-replay --input PATH`. No arbitrary
operator command is accepted. The fixture is mandatory: deployments must have
a Sybil policy permitting this controlled V4 issue/check/spend flow, or backup
fails closed rather than omitting replay evidence.

Backups quiesce services, synchronously save Redis (including AOF-aware state), capture complete resolved issuer and Redis volumes, and stream tar directly into age. No plaintext tar is created. Restore rejects legacy plaintext archives, unsafe entries, links, duplicates, undeclared files, bad signatures, and archives ahead of the protected generation high-water mark. The high-water generation is allocation history, distinct from the currently accepted restore; every archive at or below it requires its exact digest plus a non-empty rollback reason. It creates a signed/encrypted recovery archive in the same format before changing volumes. Acceptance requires bounded volume identity, readiness, and spent-fixture replay checks.

When public bearer exchange is enabled, treat these as one recovery unit:

* the authoritative Redis AOF operation ledger and shared V5 spend keys;
* active and retained target profiles and RSA private keys;
* active and retained Ed25519 receipt seeds; and
* `PUBLIC_BEARER_EXCHANGE_PUBLIC_HISTORY_PATH`.

For V2 graph issuance, the same Redis capture must include the permanent
replay-authority container:

* `freebird:v4-replay-authority:v1:id`;
* `freebird:v4-replay-authority:v1:scope-tombstones`;
* graph-issuance operations, budgets, probe challenges/acknowledgements, and
  the shared `freebird:spent:v4:` markers.

The authority identity and scope tombstones are append-only security state, not
cache entries. Never delete them, flush their logical database, or restore a
different Redis database merely because a URL or host name changed. The
issuer, graph configuration, and every participating verifier must be restored
against the same logical Redis database; the verifier's 30-second probe is the
post-restore proof, not URL string equality.

Never snapshot or restore only one side. Before backup, require Redis to be the
standalone writable master with AOF active, `appendfsync always`, healthy last
write status, and `maxmemory-policy noeviction`. Quiesce writers before the
synchronous Redis save and volume capture. Keep operation IDs out of commands,
filenames, normal logs, and manifests: they are private 16-byte capabilities.
Any operation IDs retained for recovery probes belong in separately encrypted,
access-controlled operator evidence.

Private historical target and receipt keys remain configured until readiness
confirms that their pending-reference counts are zero. Public history has a
different lifetime: copy canonical public keysets, target descriptors, and
receipt verification keys into it before private-key removal, then retain and
back it up until all corresponding artifacts and receipts expire.

After restore, before admitting traffic:

1. confirm Redis still reports master role, non-cluster mode, no eviction,
   active healthy AOF, and `appendfsync always`;
2. require issuer and verifier readiness;
3. wait for a fresh replay-authority probe when graph issuance is configured;
4. compare discovered target descriptor/keyset IDs, replay authority ID,
   retained scope tombstones, and receipt key IDs/public
   keys with the protected pre-backup inventory;
5. retry a protected committed operation through the fixed status endpoint and
   require the pre-backup response bytes exactly; and
6. confirm spent fixtures remain rejected.

Restoring response bytes without their target and Ed25519 verification metadata
is incomplete. A missing committed response, accepted spent artifact, changed
receipt key, or Redis/AOF rollback is a security failure: stop services and use
the exact generated `recover` procedure rather than accepting partial state.

The replay fixture is always forced to the locally discovered Compose-published issuer and verifier endpoints, which are also used for readiness and metadata checks. Fixture validation re-fetches both discovery documents and rejects metadata or endpoint binding changes before replay. Before quiescence, the verifier's effective `REDIS_URL` must target the Compose `redis` service and its captured local volume; external Redis is rejected. Restored files are checked against the signed manifest for exact content and modes before ownership is applied. Archive ownership is never trusted: the issuer volume is explicitly assigned `1000:1000`, and the Redis volume `999:1000`. Volume identity covers captured files only; HSM-backed keys, environment-only keys, and keys outside the captured volume are intentionally excluded and must be recovered separately.

If post-mutation validation fails, services remain stopped and the output prints the exact recovery archive digest and command. Run that exact `recover` command (not `restore`); recovery does not create another fixture or snapshot, discovers volumes from stopped Compose containers, restores and verifies both volumes, starts services, checks readiness, and confirms fixture replay rejection. Recovery archives are never overwritten.

### Operator-state recovery and stale locks

Back up `BACKUP_STATE_DIR` externally as a protected filesystem directory, including `counter.json`, `accepted.json`, and `rollback.json`; retain ownership `operator:operator` (the invoking UID), directory mode `0700`, and record mode `0600`. Copy it atomically to protected custody and periodically verify canonical JSON and expected schema before relying on it. After host loss, restore this directory from the last verified external copy before using any archive. Never run `init` to repair missing state or bypass the high-water check. A stale `${BACKUP_STATE_DIR}/operator.lock.d` may be removed only after confirming no backup, restore, or recover process is running; preserve the state files and then retry. If that cannot be established, escalate rather than deleting the lock.
