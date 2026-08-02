#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
bash -n "$root/scripts/backup-restore.sh"
PYTHONPYCACHEPREFIX="$tmp/pycache" python3 -m py_compile "$root/scripts/backup_archive.py"
grep -Fq 'ISSUER_UID_GID=1000:1000' "$root/scripts/backup-restore.sh"
grep -Fq 'REDIS_UID_GID=999:1000' "$root/scripts/backup-restore.sh"
grep -Fq 'BACKUP_ROLLBACK_CONFIRM=%s' "$root/scripts/backup-restore.sh"
grep -Fq 'recover_archive "$2"' "$root/scripts/backup-restore.sh"
grep -Fq '&& !MUTATED' "$root/scripts/backup-restore.sh"
grep -Fq 'REDIS_URL must target the Compose redis service' "$root/scripts/backup-restore.sh"
grep -Fq 'FIXTURE_ISSUER_URL/readyz' "$root/scripts/backup-restore.sh"
grep -Fq '8#$mode & 8#77' "$root/scripts/backup-restore.sh"
secret="$tmp/secret"; : >"$secret"; chmod 600 "$secret"
# A same-UID 0600 key is accepted.
BACKUP_RESTORE_TEST_SECURE_KEY=1 "$root/scripts/backup-restore.sh" test "$secret"
chmod 644 "$secret"
# A same-UID key with group/world write access is rejected.
if BACKUP_RESTORE_TEST_SECURE_KEY=1 "$root/scripts/backup-restore.sh" test "$secret" 2>/dev/null; then exit 1; fi

# Exercise the GNU/Linux stat path even when the host running this test is BSD/macOS.
linux_tools="$tmp/linux-tools"; mkdir "$linux_tools"
cat >"$linux_tools/uname" <<'SH'
#!/bin/sh
printf '%s\n' Linux
SH
cat >"$linux_tools/stat" <<'SH'
#!/bin/sh
: "${STAT_ARGS:?}"
printf '%s %s\n' "$1" "$2" >>"$STAT_ARGS"
case "$1:$2" in
  -c:%u) id -u ;;
  -c:%a) printf '600\n' ;;
  *) exit 2 ;;
esac
SH
chmod 700 "$linux_tools/uname" "$linux_tools/stat"
linux_secret="$tmp/linux-secret"; : >"$linux_secret"; chmod 600 "$linux_secret"
STAT_ARGS="$tmp/stat-args" PATH="$linux_tools:/usr/bin:/bin" BACKUP_RESTORE_TEST_SECURE_KEY=1 \
  "$root/scripts/backup-restore.sh" test "$linux_secret"
grep -Fxq -- '-c %u' "$tmp/stat-args"
grep -Fxq -- '-c %a' "$tmp/stat-args"

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
PYTHONPYCACHEPREFIX="$tmp/pycache" python3 "$root/scripts/test-backup-archive.py"
state="$tmp/state"; BACKUP_STATE_DIR="$state" "$root/scripts/backup-restore.sh" init
if BACKUP_STATE_DIR="$state" "$root/scripts/backup-restore.sh" init; then exit 1; fi

# Exercise the portable runner without Docker.  Verify timeout is preferred to
# gtimeout, then exercise the Python fallback for fixed argv, timeout status,
# and child cleanup.  Each bounded run uses a sandboxed PATH so the results do
# not depend on which timer binaries the host ships (Linux coreutils timeout vs
# macOS, where only Homebrew gtimeout exists).
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
# A system GNU timeout (coreutils, /usr/bin/timeout on Linux) shadows the
# gtimeout stub once the stub is removed, so run this preference check in a
# PATH exposing only the stubs and the minimal tools the script needs to boot.
ln -s "$(command -v bash)" "$tools/bash"
ln -s "$(command -v dirname)" "$tools/dirname"
if BOUND_TIMER_MARKER="$tmp/timer" PATH="$tools" BACKUP_RESTORE_TEST_RUN_BOUNDED=1 \
  "$root/scripts/backup-restore.sh" "$runner" "$args" ok; then exit 1; else [[ $? == 7 ]]; fi
[[ $(basename "$(cat "$tmp/timer")") == gtimeout ]]
# Force the Python fallback deterministically: a PATH containing python3 (and
# the minimal boot tools plus a real sleep) but no timeout/gtimeout. On Linux
# /usr/bin/timeout would otherwise shadow the fallback and return 128+signal
# on kill instead of the fallback's 124.
mkdir "$tmp/fallback"
ln -s "$(command -v bash)" "$tmp/fallback/bash"
ln -s "$(command -v dirname)" "$tmp/fallback/dirname"
ln -s "$(command -v python3)" "$tmp/fallback/python3"
ln -s "$(command -v sleep)" "$tmp/fallback/sleep"
if PATH="$tmp/fallback" BACKUP_RESTORE_TEST_RUN_BOUNDED=1 \
  "$root/scripts/backup-restore.sh" "$runner" "$args" 'literal;not-shell'; then exit 1; else [[ $? == 7 ]]; fi
[[ $(wc -l <"$args.args") == 2 ]] && [[ $(sed -n '2p' "$args.args") == 'literal;not-shell' ]]
# The sleepy child must be able to find sleep, otherwise it exits 127 instead
# of being killed by the timeout (dash reports this on Linux; macOS bash is
# slow enough to mask it). With sleep available the kill path is deterministic.
sleepy="$tmp/sleepy"; printf '#!/bin/sh\nsleep 30\n' >"$sleepy"; chmod 700 "$sleepy"
if PATH="$tmp/fallback" BACKUP_RESTORE_TEST_RUN_BOUNDED=1 BACKUP_HELPER_TIMEOUT=0.1 \
  "$root/scripts/backup-restore.sh" "$sleepy"; then exit 1; else [[ $? == 124 ]]; fi
printf 'backup behavioural tests passed\n'
