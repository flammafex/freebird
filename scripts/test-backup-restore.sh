#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bash -n "$root/scripts/backup-restore.sh"
python3 -m py_compile "$root/scripts/backup_archive.py"
grep -Fq 'ISSUER_UID_GID=1000:1000' "$root/scripts/backup-restore.sh"
grep -Fq 'REDIS_UID_GID=999:1000' "$root/scripts/backup-restore.sh"
grep -Fq 'BACKUP_ROLLBACK_CONFIRM=%s' "$root/scripts/backup-restore.sh"
grep -Fq 'recover_archive "$2"' "$root/scripts/backup-restore.sh"
grep -Fq '&& !MUTATED' "$root/scripts/backup-restore.sh"
grep -Fq 'REDIS_URL must target the Compose redis service' "$root/scripts/backup-restore.sh"
grep -Fq 'FIXTURE_ISSUER_URL/readyz' "$root/scripts/backup-restore.sh"
grep -Fq '8#$mode & 8#77' "$root/scripts/backup-restore.sh"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
secret="$tmp/secret"; : >"$secret"; chmod 600 "$secret"
BACKUP_RESTORE_TEST_SECURE_KEY=1 "$root/scripts/backup-restore.sh" test "$secret"
chmod 644 "$secret"
if BACKUP_RESTORE_TEST_SECURE_KEY=1 "$root/scripts/backup-restore.sh" test "$secret" 2>/dev/null; then exit 1; fi
BACKUP_RESTORE_TEST_REDIS_URL=1 "$root/scripts/backup-restore.sh" test redis://redis:6379/0
if BACKUP_RESTORE_TEST_REDIS_URL=1 "$root/scripts/backup-restore.sh" test redis://external.example:6379 2>/dev/null; then exit 1; fi
grep -Fq 'recover_archive "$2"' "$root/scripts/backup-restore.sh"
grep -Fq 'check_mounts_stopped' "$root/scripts/backup-restore.sh"
grep -Fq 'compose_endpoint issuer 8081' "$root/scripts/backup-restore.sh"
if grep -Fq 'create --no-start' "$root/scripts/backup-restore.sh"; then exit 1; fi
grep -Fq '"${COMPOSE[@]}" create "$service"' "$root/scripts/backup-restore.sh"
grep -Fq '"${COMPOSE[@]}" create verifier' "$root/scripts/backup-restore.sh"
stub="$root/scripts/backup-fixture-stub.sh"
"$stub" create --output "$tmp/fixture.json"
[[ -s "$tmp/fixture.json" ]]
"$stub" validate-replay --input "$tmp/fixture.json"
if "$stub" validate-replay --input "$tmp/missing"; then exit 1; fi
python3 "$root/scripts/test-backup-archive.py"
state="$tmp/state"; BACKUP_STATE_DIR="$state" "$root/scripts/backup-restore.sh" init
if BACKUP_STATE_DIR="$state" "$root/scripts/backup-restore.sh" init; then exit 1; fi

# Exercise the portable runner without Docker.  Verify GNU timeout is preferred
# to gtimeout, then verify fixed argv, timeout status, and child cleanup in the
# Python fallback.
runner="$tmp/runner"; args="$tmp/args"
cat >"$runner" <<'SH'
#!/bin/sh
printf '%s\n' "$@" >"$1.args"
exit 7
SH
chmod 700 "$runner"
tools="$tmp/tools"; mkdir "$tools"
for timer in timeout gtimeout; do
  cat >"$tools/$timer" <<'SH'
#!/bin/sh
: "${BOUND_TIMER_MARKER:?}"
printf '%s\n' "$0" >"$BOUND_TIMER_MARKER"
shift 2
exec "$@"
SH
  chmod 700 "$tools/$timer"
done
if BOUND_TIMER_MARKER="$tmp/timer" PATH="$tools:/usr/bin:/bin" BACKUP_RESTORE_TEST_RUN_BOUNDED=1 \
  "$root/scripts/backup-restore.sh" "$runner" "$args" ok; then exit 1; else [[ $? == 7 ]]; fi
[[ $(basename "$(cat "$tmp/timer")") == timeout ]]
rm "$tools/timeout"
if BOUND_TIMER_MARKER="$tmp/timer" PATH="$tools:/usr/bin:/bin" BACKUP_RESTORE_TEST_RUN_BOUNDED=1 \
  "$root/scripts/backup-restore.sh" "$runner" "$args" ok; then exit 1; else [[ $? == 7 ]]; fi
[[ $(basename "$(cat "$tmp/timer")") == gtimeout ]]
PATH="/usr/bin:/bin" BACKUP_RESTORE_TEST_RUN_BOUNDED=1 \
  "$root/scripts/backup-restore.sh" "$runner" "$args" 'literal;not-shell' || [[ $? == 7 ]]
[[ $(wc -l <"$args.args") == 2 ]] && [[ $(sed -n '2p' "$args.args") == 'literal;not-shell' ]]
sleepy="$tmp/sleepy"; printf '#!/bin/sh\nsleep 30\n' >"$sleepy"; chmod 700 "$sleepy"
if PATH="/usr/bin:/bin" BACKUP_RESTORE_TEST_RUN_BOUNDED=1 BACKUP_HELPER_TIMEOUT=0.1 \
  "$root/scripts/backup-restore.sh" "$sleepy"; then exit 1; else [[ $? == 124 ]]; fi
printf 'backup behavioural tests passed\n'
