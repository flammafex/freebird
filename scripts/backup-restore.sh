#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Docker Compose backup/restore.  This deliberately does not support the old
# plaintext tar format.
set -Eeuo pipefail
IFS=$'\n\t'

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
HELPER=${BACKUP_ARCHIVE_HELPER:-$ROOT/scripts/backup_archive.py}
COMPOSE=(docker compose --project-directory "$ROOT" --env-file "${COMPOSE_ENV_FILE:-$ROOT/.env}")
BACKUP_DIR=${BACKUP_DIR:-$ROOT/backups}
STATE_DIR=${BACKUP_STATE_DIR:-$ROOT/.backup-state}
LOCK=${BACKUP_LOCK_FILE:-$STATE_DIR/operator.lock}
COUNTER=${BACKUP_GENERATION_FILE:-$STATE_DIR/generation}
ACCEPTED=${BACKUP_ACCEPTED_GENERATION_FILE:-$STATE_DIR/accepted-generation}
JOURNAL=${BACKUP_ROLLBACK_JOURNAL:-$STATE_DIR/rollback-journal}
RECIPIENTS=${BACKUP_AGE_RECIPIENTS:-}
SIGNING_KEY=${BACKUP_MINISIGN_SECRET_KEY:-}
VERIFY_KEY=${BACKUP_MINISIGN_PUBLIC_KEY:-}
IDENTITY=${BACKUP_AGE_IDENTITY:-}
INTERFACE=${FREEBIRD_INTERFACE_BIN:-freebird-interface}
SERVICES=(issuer verifier redis)
RUNNING_SERVICES=()
FIXTURE_ISSUER_URL=; FIXTURE_VERIFIER_URL=; ENDPOINTS_DISCOVERED=0; OPERATION=
STAGE=; RECOVERY_STAGE=; OUTPUT_TMP=; ARCHIVE_COPY=; LOCK_HELD=; MUTATED=0; RESTART_ON_FAILURE=0; RECOVERY_ARCHIVE=; RECOVERY_DIGEST=; RECOVERY_GENERATION=
ISSUER_UID_GID=1000:1000
REDIS_UID_GID=999:1000
cleanup() {
  local rc=$?
  [[ -n $OUTPUT_TMP ]] && rm -f -- "$OUTPUT_TMP"
  [[ -n $ARCHIVE_COPY ]] && rm -f -- "$ARCHIVE_COPY"
  [[ -n $STAGE ]] && rm -rf -- "$STAGE"
  [[ -n $RECOVERY_STAGE ]] && rm -rf -- "$RECOVERY_STAGE"
  [[ -n $LOCK_HELD ]] && rmdir -- "$LOCK_HELD" 2>/dev/null || true
  if (( MUTATED && rc != 0 )); then "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true; recovery || true; fi
  if (( RESTART_ON_FAILURE && rc != 0 && !MUTATED )); then start_services || true; fi
  if [[ $OPERATION == restore && $rc != 0 && ! $MUTATED ]]; then printf '\nPRE-MUTATION FAILURE: volumes were not intentionally mutated. Verify service state before retrying; protected operator state was not reinitialized.\n' >&2; fi
  exit "$rc"
}
trap cleanup EXIT

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command unavailable: $1"; }
helper() { python3 "$HELPER" "$@"; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
check_ciphertext_limit() { [[ $(wc -c <"$1") -le ${BACKUP_MAX_CIPHERTEXT_BYTES:-4294967296} ]] || die 'encrypted archive ciphertext limit exceeded'; }
secure_key() { local p=$1 label=$2 policy=$3 mode; [[ -f $p ]] || die "$label is not a regular file"; [[ $(stat -f '%u' "$p" 2>/dev/null || stat -c '%u' "$p") == "$(id -u)" ]] || die "$label ownership is unsafe"; mode=$(stat -f '%Lp' "$p" 2>/dev/null || stat -c '%a' "$p"); [[ $mode =~ ^[0-7]+$ ]] || die "$label mode is unsafe"; if [[ $policy == secret ]]; then (( (8#$mode & 8#77) == 0 )) || die "$label mode is unsafe"; else (( (8#$mode & 8#22) == 0 )) || die "$label mode is unsafe"; fi; }
publish_no_replace() { python3 - "$1" "$2" <<'PY'
import os, sys
source, target = sys.argv[1:]
try:
    os.link(source, target)
except FileExistsError:
    raise SystemExit("destination already exists; refusing recovery archive overwrite")
os.unlink(source)
directory = os.path.dirname(os.path.abspath(target))
fd = os.open(directory, os.O_RDONLY); os.fsync(fd); os.close(fd)
PY
}
sync_file() { python3 - "$1" <<'PY'
import os,sys
p=sys.argv[1]; f=os.open(p,os.O_RDONLY); os.fsync(f); os.close(f)
d=os.path.dirname(os.path.abspath(p)); f=os.open(d,os.O_RDONLY); os.fsync(f); os.close(f)
PY
}
atomic_write() { local p=$1; local d; d=$(dirname "$p"); mkdir -p "$d"; local t; t=$(mktemp "$d/.tmp.XXXXXX"); chmod 600 "$t"; printf '%s\n' "$2" >"$t"; sync_file "$t"; mv -f "$t" "$p"; sync_file "$d"; }
resolve() { [[ -f $1 ]] && printf '%s' "$1" || printf '%s/%s' "$BACKUP_DIR" "$1"; }
run_bounded() {
  local bin=$1; shift
  [[ -x $bin ]] || die "bounded helper is not executable: $bin"
  local duration=${BACKUP_HELPER_TIMEOUT:-30} timer
  # Prefer the platform's GNU timeout when it is available.  Homebrew names
  # the same utility gtimeout; neither invocation uses a shell or eval.
  if timer=$(command -v timeout 2>/dev/null); then
    "$timer" --preserve-status "$duration" "$bin" "$@"
  elif timer=$(command -v gtimeout 2>/dev/null); then
    "$timer" --preserve-status "$duration" "$bin" "$@"
  else
    # Keep the fallback dependency-free beyond Python 3, which is already a
    # prerequisite.  Pass the complete argv as Python argv, never as code.
    python3 - "$duration" "$bin" "$@" <<'PY'
import os
import signal
import subprocess
import sys

def seconds(value):
    suffixes = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    suffix = value[-1:].lower()
    if suffix in suffixes:
        return float(value[:-1]) * suffixes[suffix]
    return float(value)

try:
    process = subprocess.Popen(
        sys.argv[2:],
        start_new_session=(os.name == "posix"),
    )
    try:
        process.communicate(timeout=seconds(sys.argv[1]))
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        process.wait()
        sys.exit(124)
    status = process.returncode
    sys.exit(128 + -status if status < 0 else status)
except (OSError, ValueError) as error:
    print("bounded helper failed: %s" % error, file=sys.stderr)
    sys.exit(127)
PY
  fi
}
compose_endpoint() { local service=$1 port=$2 published; published=$("${COMPOSE[@]}" port "$service" "$port") || die "unable to discover Compose endpoint for $service"; published=${published##*:}; printf 'http://127.0.0.1:%s' "$published"; }
fixture_endpoints() { if (( ! ENDPOINTS_DISCOVERED )); then FIXTURE_ISSUER_URL=$(compose_endpoint issuer 8081); FIXTURE_VERIFIER_URL=$(compose_endpoint verifier 8082); ENDPOINTS_DISCOVERED=1; fi; }
run_fixture_create() { command -v "$INTERFACE" >/dev/null 2>&1 || die 'freebird-interface is required'; fixture_endpoints; run_bounded "$(command -v "$INTERFACE")" backup-fixture create --output "$1" --issuer-url "$FIXTURE_ISSUER_URL" --verifier-url "$FIXTURE_VERIFIER_URL"; }
run_fixture_replay() { command -v "$INTERFACE" >/dev/null 2>&1 || die 'freebird-interface is required'; fixture_endpoints; run_bounded "$(command -v "$INTERFACE")" backup-fixture validate-replay --input "$1" --issuer-url "$FIXTURE_ISSUER_URL" --verifier-url "$FIXTURE_VERIFIER_URL"; }
init_state() {
  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"; lock
  helper state init --state "$STATE_DIR"
  printf 'Initialized protected backup state in %s\n' "$STATE_DIR"
}

prereqs() {
  need docker; need age; need minisign; need python3; need curl
  case $1 in
    backup) [[ -n $RECIPIENTS ]] || die 'BACKUP_AGE_RECIPIENTS is required'; [[ -n $SIGNING_KEY ]] || die 'BACKUP_MINISIGN_SECRET_KEY is required'; secure_key "$SIGNING_KEY" BACKUP_MINISIGN_SECRET_KEY secret ;;
    verify) [[ -n $IDENTITY ]] || die 'BACKUP_AGE_IDENTITY is required'; secure_key "$IDENTITY" BACKUP_AGE_IDENTITY secret ;;
    restore) [[ -n $RECIPIENTS ]] || die 'BACKUP_AGE_RECIPIENTS is required'; [[ -n $SIGNING_KEY ]] || die 'BACKUP_MINISIGN_SECRET_KEY is required'; [[ -n $IDENTITY ]] || die 'BACKUP_AGE_IDENTITY is required'; secure_key "$SIGNING_KEY" BACKUP_MINISIGN_SECRET_KEY secret; secure_key "$IDENTITY" BACKUP_AGE_IDENTITY secret ;;
    recover) [[ -n $IDENTITY ]] || die 'BACKUP_AGE_IDENTITY is required'; secure_key "$IDENTITY" BACKUP_AGE_IDENTITY secret ;;
  esac
  if [[ $1 == verify || $1 == restore || $1 == recover ]]; then [[ -n $VERIFY_KEY && -f $VERIFY_KEY ]] || die 'BACKUP_MINISIGN_PUBLIC_KEY must be an external pinned file'; secure_key "$VERIFY_KEY" BACKUP_MINISIGN_PUBLIC_KEY public; fi
  docker compose version >/dev/null 2>&1 || die 'Docker Compose v2 is required'
  "${COMPOSE[@]}" config --quiet >/dev/null || die 'Compose configuration is invalid'
  mkdir -p "$BACKUP_DIR" "$STATE_DIR"; chmod 700 "$BACKUP_DIR" "$STATE_DIR"
  helper state check --state "$STATE_DIR" >/dev/null
}
lock() { local l="${LOCK}.d"; mkdir -p "$(dirname "$l")"; mkdir "$l" 2>/dev/null || die 'another backup/restore operator is running'; chmod 700 "$l"; LOCK_HELD=$l; }
next_generation() { helper state next --state "$STATE_DIR"; }

mount_source() {
  local service=$1 dest=$2 id; id=$("${COMPOSE[@]}" ps -q "$service") || return 1
  [[ -n $id ]] || die "$service is not running; start Compose before backup"
  local row; row=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "'$dest'"}}{{.Type}}|{{.Name}}|{{.Source}}{{end}}{{end}}' "$id")
  [[ -n $row ]] || die "no resolved $dest mount for $service"
  [[ $row != bind\|* ]] || die "bind mount for $service:$dest is outside the authoritative captured volume"
  [[ $row == volume\|* ]] || die "unsupported mount for $service:$dest"
  printf '%s' "${row#*|}" | cut -d'|' -f1
}
mount_source_stopped() {
  local service=$1 dest=$2 id row
  id=$("${COMPOSE[@]}" ps -aq "$service")
  if [[ -z $id ]]; then "${COMPOSE[@]}" create "$service" >/dev/null || die "unable to create stopped $service container for volume discovery"; id=$("${COMPOSE[@]}" ps -aq "$service"); fi
  [[ -n $id ]] || die "no stopped container for $service"
  row=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "'$dest'"}}{{.Type}}|{{.Name}}|{{.Source}}{{end}}{{end}}' "$id")
  [[ -n $row && $row != bind\|* && $row == volume\|* ]] || die "unsafe resolved $dest mount for stopped $service"
  printf '%s' "${row#*|}" | cut -d'|' -f1
}
record_running_services() {
  RUNNING_SERVICES=(); for service in "${SERVICES[@]}"; do [[ -n $("${COMPOSE[@]}" ps -q "$service") ]] || die "required service is not initially running: $service"; RUNNING_SERVICES+=("$service"); done
}
check_mounts() {
  ISSUER_VOL=$(mount_source issuer /data); REDIS_VOL=$(mount_source redis /data); [[ -n $ISSUER_VOL && -n $REDIS_VOL ]]
  local vid; vid=$("${COMPOSE[@]}" ps -q verifier); [[ -n $vid ]] || die 'verifier is not running'
  local verifier_vol; verifier_vol=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/issuer-data"}}{{.Type}}|{{.Name}}{{end}}{{end}}' "$vid")
  [[ $verifier_vol == volume\|"$ISSUER_VOL" ]] || die 'verifier authoritative mount does not match issuer volume'
  for service in issuer verifier redis; do
    local id bind_paths; id=$("${COMPOSE[@]}" ps -q "$service"); bind_paths=$(docker inspect -f '{{range .Mounts}}{{if eq .Type "bind"}}{{.Destination}}{{end}}{{end}}' "$id"); [[ -z $bind_paths ]] || die "unaccounted bind mount: $service:$bind_paths"
  done
  check_verifier_redis
}
check_verifier_redis() {
  local vid envline redis_url; vid=$("${COMPOSE[@]}" ps -q verifier); envline=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$vid"); redis_url=$(printf '%s\n' "$envline" | awk -F= '$1 == "REDIS_URL" {print substr($0, index($0,"=")+1)}'); redis_url_allowed "$redis_url" || die 'verifier REDIS_URL must target the Compose redis service'; [[ -n $REDIS_VOL ]] || die 'captured local Redis volume is unavailable';
}
redis_url_allowed() { [[ $1 =~ ^redis://redis(:6379)?(/.*)?$ ]]; }
check_mounts_stopped() {
  ISSUER_VOL=$(mount_source_stopped issuer /data); REDIS_VOL=$(mount_source_stopped redis /data)
  local vid verifier_vol; vid=$("${COMPOSE[@]}" ps -aq verifier); if [[ -z $vid ]]; then "${COMPOSE[@]}" create verifier >/dev/null || die 'unable to create stopped verifier container for volume discovery'; vid=$("${COMPOSE[@]}" ps -aq verifier); fi; [[ -n $vid ]] || die 'verifier stopped container is unavailable'
  verifier_vol=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/issuer-data"}}{{.Type}}|{{.Name}}{{end}}{{end}}' "$vid")
  [[ $verifier_vol == volume\|"$ISSUER_VOL" ]] || die 'verifier authoritative mount does not match issuer volume'
  local envline redis_url; envline=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$vid"); redis_url=$(printf '%s\n' "$envline" | awk -F= '$1 == "REDIS_URL" {print substr($0, index($0,"=")+1)}'); redis_url_allowed "$redis_url" || die 'verifier REDIS_URL must target the Compose redis service'
}

stop_quiesced() {
  "${COMPOSE[@]}" stop --timeout "${BACKUP_STOP_TIMEOUT:-30}" issuer verifier || die 'application quiescing failed'
  local redis_id; redis_id=$("${COMPOSE[@]}" ps -q redis); [[ -n $redis_id ]] || die 'Redis is not running'
  docker exec "$redis_id" redis-cli SAVE >/dev/null || die 'synchronous Redis SAVE failed'
  REDIS_LASTSAVE=$(docker exec "$redis_id" redis-cli LASTSAVE) || die 'Redis persistence evidence unavailable'
  [[ $REDIS_LASTSAVE =~ ^[0-9]+$ ]] || die 'invalid Redis LASTSAVE evidence'
  REDIS_PERSISTENCE=$(docker exec "$redis_id" redis-cli INFO persistence) || die 'Redis persistence evidence unavailable'
  [[ $REDIS_PERSISTENCE == *aof_enabled:1* || $REDIS_PERSISTENCE == *rdb_bgsave_in_progress:0* ]] || die 'Redis persistence evidence is incomplete'
  "${COMPOSE[@]}" stop --timeout "${BACKUP_STOP_TIMEOUT:-30}" redis || die 'Redis quiescing failed'
}
start_services() { "${COMPOSE[@]}" up -d "${RUNNING_SERVICES[@]}"; }
readiness() {
  fixture_endpoints; local deadline=$(( $(date +%s) + ${BACKUP_READY_DEADLINE:-60} )); local issuer_ready="$FIXTURE_ISSUER_URL/readyz" issuer_meta="$FIXTURE_ISSUER_URL/.well-known/issuer" verifier_ready="$FIXTURE_VERIFIER_URL/ready"; while (( $(date +%s) < deadline )); do curl --fail --silent --show-error --max-time "${BACKUP_READY_TIMEOUT:-5}" "$issuer_ready" >/dev/null && curl --fail --silent --show-error --max-time "${BACKUP_READY_TIMEOUT:-5}" "$issuer_meta" >/dev/null && curl --fail --silent --show-error --max-time "${BACKUP_READY_TIMEOUT:-5}" "$verifier_ready" >/dev/null && return 0; sleep 1; done; die 'service readiness deadline exceeded'
}
recovery() {
  printf '\nRECOVERY: services are stopped after a state mutation. Recovery archive: %s\nRecovery archive SHA-256: %s\nKeep volumes untouched; inspect logs, then recover this archive with:\n  BACKUP_ROLLBACK_CONFIRM=%s BACKUP_ROLLBACK_REASON=%q %q recover %q\n' \
    "${RECOVERY_ARCHIVE:-unknown}" "${RECOVERY_DIGEST:-unknown}" \
    "${RECOVERY_GENERATION:-unknown}:${RECOVERY_DIGEST:-unknown}" \
    'restore failed after volume mutation' "$0" "${RECOVERY_ARCHIVE:-unknown}" >&2
}

verify_volume_tree() {
  local volume=$1 manifest_path=$2 label=$3 parent out
  parent=$(dirname "$manifest_path"); out=$(mktemp -d "$parent/.verify-$label.XXXXXX")
  docker run --rm -v "$volume:/data:ro" alpine:3.20 \
    sh -c 'tar -cf - -C /data .' | tar -xf - -C "$out" || { rm -rf -- "$out"; die "$label restored tree capture failed"; }
  helper verify-tree --root "$out" --manifest "$manifest_path" --prefix "$label" || { rm -rf -- "$out"; die "$label restored content/mode verification failed"; }
  rm -rf -- "$out"
}
restore_volume() {
  local volume=$1 label=$2
  docker run --rm -v "$volume:/data" -v "$STAGE/payload/$label:/in:ro" alpine:3.20 sh -c 'rm -rf /data/* /data/.[!.]* /data/..?* 2>/dev/null || true; cp -a /in/. /data/' || die "$label restore failed"
  verify_volume_tree "$volume" "$STAGE/MANIFEST.json" "$label"
  if [[ $label == issuer ]]; then docker run --rm -v "$volume:/data" alpine:3.20 chown -R "$ISSUER_UID_GID" /data || die 'issuer destination ownership policy failed'; else docker run --rm -v "$volume:/data" alpine:3.20 chown -R "$REDIS_UID_GID" /data || die 'Redis destination ownership policy failed'; fi
}

# Private test hook; it does not form part of the operator interface.
if [[ ${BACKUP_RESTORE_TEST_RUN_BOUNDED:-} == 1 ]]; then
  run_bounded "$@"
  exit $?
fi
if [[ ${BACKUP_RESTORE_TEST_SECURE_KEY:-} == 1 ]]; then secure_key "$2" test secret; exit 0; fi
if [[ ${BACKUP_RESTORE_TEST_REDIS_URL:-} == 1 ]]; then redis_url_allowed "$2" || exit 1; exit 0; fi

manifest() {
  helper manifest --root "$1" --generation "$2" --created "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --issuer-key-id "$ISSUER_IDENTITY" --redis-volume "$REDIS_VOL" --redis-lastsave "${REDIS_LASTSAVE:-0}"
  minisign -Sm "$1/MANIFEST.json" -s "$SIGNING_KEY" -x "$1/MANIFEST.json.minisig" >/dev/null
}

backup() {
  OPERATION=backup; prereqs backup; lock; record_running_services; check_mounts; local gen; gen=$(next_generation); STAGE=$(mktemp -d "$BACKUP_DIR/.stage.XXXXXX"); chmod 700 "$STAGE"; umask 077; RESTART_ON_FAILURE=1
  # The fixture command must issue and spend a controlled token, writing only
  # its opaque token/proof evidence under payload/fixture.
  mkdir -p "$STAGE/payload/issuer" "$STAGE/payload/redis" "$STAGE/payload/fixture"
  run_fixture_create "$STAGE/payload/fixture/token.json"; [[ -s $STAGE/payload/fixture/token.json ]] || die 'fixture evidence missing'
  check_mounts; stop_quiesced
  docker cp "$(${COMPOSE[@]} ps -aq issuer):/data/." "$STAGE/payload/issuer/" || die 'complete issuer capture failed'
  docker run --rm -v "$REDIS_VOL:/data:ro" -v "$STAGE/payload/redis:/out" alpine:3.20 sh -c 'cp -a /data/. /out/' || die 'complete Redis capture failed'
  ISSUER_IDENTITY=$(helper identity --root "$STAGE/payload/issuer"); manifest "$STAGE" "$gen"; local name="freebird-backup-g${gen}-$(date -u +%Y%m%dT%H%M%SZ).age"; OUTPUT_TMP="$BACKUP_DIR/.${gen}.age.tmp"
  helper pack --root "$STAGE" | age -R "$RECIPIENTS" -o "$OUTPUT_TMP" - || die 'encrypted archive creation failed'
  sync_file "$OUTPUT_TMP"; mv -f "$OUTPUT_TMP" "$BACKUP_DIR/$name"; OUTPUT_TMP=; sync_file "$BACKUP_DIR"; start_services; RESTART_ON_FAILURE=0
  printf 'Backup created: %s (generation %s)\n' "$BACKUP_DIR/$name" "$gen"
}

verify() { OPERATION=verify; prereqs verify; lock; local a; a=$(resolve "$1"); [[ $a == *.age ]] || die 'legacy plaintext archives are rejected'; local parent; parent=$(mktemp -d); chmod 700 "$parent"; STAGE="$parent/archive"; ARCHIVE_COPY="$parent/archive.age"; cp "$a" "$ARCHIVE_COPY"; chmod 600 "$ARCHIVE_COPY"; check_ciphertext_limit "$ARCHIVE_COPY"; local digest; digest=$(sha "$ARCHIVE_COPY"); [[ $digest == "$(sha "$ARCHIVE_COPY")" ]] || die 'archive changed during capture'; age -d -i "$IDENTITY" "$ARCHIVE_COPY" | helper extract --dest "$STAGE"; minisign -Vm "$STAGE/MANIFEST.json" -p "$VERIFY_KEY" -x "$STAGE/MANIFEST.json.minisig"; local identity; identity=$(helper identity --root "$STAGE/payload/issuer"); helper check --root "$STAGE" --expected-issuer-key-id "$identity" >/dev/null; printf 'Archive verified: %s (sha256 %s)\n' "$a" "$digest"; }
restore() {
  OPERATION=restore; prereqs restore; lock; record_running_services; RESTART_ON_FAILURE=1; local a; a=$(resolve "$1"); [[ $a == *.age ]] || die 'legacy plaintext archives are rejected'; local parent; parent=$(mktemp -d); chmod 700 "$parent"; STAGE="$parent/archive"
  ARCHIVE_COPY="$parent/archive.age"; cp "$a" "$ARCHIVE_COPY"; chmod 600 "$ARCHIVE_COPY"; check_ciphertext_limit "$ARCHIVE_COPY"; local digest; digest=$(sha "$ARCHIVE_COPY"); [[ $digest == "$(sha "$ARCHIVE_COPY")" ]] || die 'archive changed during capture'; age -d -i "$IDENTITY" "$ARCHIVE_COPY" | helper extract --dest "$STAGE"; minisign -Vm "$STAGE/MANIFEST.json" -p "$VERIFY_KEY" -x "$STAGE/MANIFEST.json.minisig"; local identity; identity=$(helper identity --root "$STAGE/payload/issuer"); local gen; gen=$(helper check --root "$STAGE" --expected-issuer-key-id "$identity"); local hwm; hwm=$(helper state high-water --state "$STATE_DIR");
  (( gen <= hwm )) || die 'archive generation is ahead of protected high-water state'
  check_mounts
  if (( gen <= hwm )); then
    [[ ${BACKUP_ROLLBACK_CONFIRM:-} == "$gen:$digest" && -n ${BACKUP_ROLLBACK_REASON:-} ]] || die 'archive generation is at or below high-water; exact BACKUP_ROLLBACK_CONFIRM and non-empty reason required'
    [[ $BACKUP_ROLLBACK_REASON != *$'\n'* && $BACKUP_ROLLBACK_REASON != *$'\r'* ]] || die 'rollback reason contains controls'
    helper state rollback --state "$STATE_DIR" --generation "$gen" --digest "$digest" --reason "$BACKUP_ROLLBACK_REASON"
  fi
  # A recovery snapshot is mandatory and encrypted before mutation.
  local recovery=${BACKUP_RECOVERY_SNAPSHOT:-$BACKUP_DIR/pre-restore-$(date -u +%Y%m%dT%H%M%SZ).age}; [[ ! -e $recovery ]] || die 'recovery archive already exists; refusing overwrite'
  RECOVERY_STAGE=$(mktemp -d "$STATE_DIR/.recovery.XXXXXX"); chmod 700 "$RECOVERY_STAGE"; mkdir -p "$RECOVERY_STAGE/payload/issuer" "$RECOVERY_STAGE/payload/redis" "$RECOVERY_STAGE/payload/fixture"
  # Issue and spend the recovery fixture while the verifier is still live;
  # the volume snapshot itself is taken only after quiescing.
  run_fixture_create "$RECOVERY_STAGE/payload/fixture/token.json"
  local recovery_gen; recovery_gen=$(next_generation)
  stop_quiesced
  docker cp "$(${COMPOSE[@]} ps -aq issuer):/data/." "$RECOVERY_STAGE/payload/issuer" || die 'pre-restore issuer snapshot failed'
  docker run --rm -v "$REDIS_VOL:/data:ro" -v "$RECOVERY_STAGE/payload/redis:/out" alpine:3.20 sh -c 'cp -a /data/. /out/' || die 'pre-restore Redis snapshot failed'
  ISSUER_IDENTITY=$(helper identity --root "$RECOVERY_STAGE/payload/issuer"); manifest "$RECOVERY_STAGE" "$recovery_gen"; OUTPUT_TMP="$recovery.tmp"
  helper pack --root "$RECOVERY_STAGE" | age -R "$RECIPIENTS" -o "$OUTPUT_TMP" - || die 'pre-restore recovery encryption failed'; sync_file "$OUTPUT_TMP"; publish_no_replace "$OUTPUT_TMP" "$recovery"; OUTPUT_TMP=; RECOVERY_ARCHIVE=$recovery; RECOVERY_GENERATION=$recovery_gen; RECOVERY_DIGEST=$(sha "$recovery")
  # Replace, rather than overlay, authoritative volumes.  Services remain down
  # on every failure after this point; the trap prints deterministic recovery.
  "${COMPOSE[@]}" down --remove-orphans >/dev/null; MUTATED=1
  restore_volume "$ISSUER_VOL" issuer
  restore_volume "$REDIS_VOL" redis
  "${COMPOSE[@]}" up -d redis; "${COMPOSE[@]}" up -d issuer verifier
  "${COMPOSE[@]}" ps --all
  for service in "${RUNNING_SERVICES[@]}"; do [[ -n $("${COMPOSE[@]}" ps -q "$service") ]] || die "service readiness failed: $service"; done
  readiness
  run_fixture_replay "$STAGE/payload/fixture/token.json" || die 'spent fixture replay was accepted'
  helper state accept --state "$STATE_DIR" --generation "$gen" --digest "$digest"; MUTATED=0
  RESTART_ON_FAILURE=0; printf 'Restore accepted: generation %s\nRecovery artifact: %s\nRecovery artifact SHA-256: %s\nRecovery command: BACKUP_ROLLBACK_CONFIRM=%q BACKUP_ROLLBACK_REASON=%q %q recover %q\n' "$gen" "$RECOVERY_ARCHIVE" "$RECOVERY_DIGEST" "$RECOVERY_GENERATION:$RECOVERY_DIGEST" "pre-restore recovery" "$0" "$RECOVERY_ARCHIVE"
}
recover_archive() {
  OPERATION=recover; prereqs recover; lock; local a=$1; a=$(resolve "$a"); [[ $a == *.age ]] || die 'legacy plaintext archives are rejected'; local parent; parent=$(mktemp -d); chmod 700 "$parent"; STAGE="$parent/archive"; ARCHIVE_COPY="$parent/archive.age"; cp "$a" "$ARCHIVE_COPY"; chmod 600 "$ARCHIVE_COPY"; check_ciphertext_limit "$ARCHIVE_COPY"; local digest; digest=$(sha "$ARCHIVE_COPY"); age -d -i "$IDENTITY" "$ARCHIVE_COPY" | helper extract --dest "$STAGE"; minisign -Vm "$STAGE/MANIFEST.json" -p "$VERIFY_KEY" -x "$STAGE/MANIFEST.json.minisig"; local identity; identity=$(helper identity --root "$STAGE/payload/issuer"); local gen; gen=$(helper check --root "$STAGE" --expected-issuer-key-id "$identity"); local hwm; hwm=$(helper state high-water --state "$STATE_DIR"); (( gen <= hwm )) || die 'recovery archive is ahead of protected high-water state'; [[ ${BACKUP_ROLLBACK_CONFIRM:-} == "$gen:$digest" && -n ${BACKUP_ROLLBACK_REASON:-} ]] || die 'recovery requires exact BACKUP_ROLLBACK_CONFIRM and non-empty reason'; [[ $BACKUP_ROLLBACK_REASON != *$'\n'* && $BACKUP_ROLLBACK_REASON != *$'\r'* ]] || die 'rollback reason contains controls'; RECOVERY_ARCHIVE=$a; RECOVERY_DIGEST=$digest; RECOVERY_GENERATION=$gen; helper state rollback --state "$STATE_DIR" --generation "$gen" --digest "$digest" --reason "$BACKUP_ROLLBACK_REASON"; check_mounts_stopped; MUTATED=1; restore_volume "$ISSUER_VOL" issuer; restore_volume "$REDIS_VOL" redis; RUNNING_SERVICES=(issuer verifier redis); "${COMPOSE[@]}" up -d redis issuer verifier; readiness; run_fixture_replay "$STAGE/payload/fixture/token.json" || die 'recovery fixture replay was accepted'; helper state accept --state "$STATE_DIR" --generation "$gen" --digest "$digest"; MUTATED=0; printf 'Recovery accepted: generation %s\nArchive SHA-256: %s\n' "$gen" "$digest"
}
list() { prereqs verify; find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.age' -print | sort; }
case ${1:-} in init) init_state;; backup) backup;; verify) [[ ${2:-} ]] || die 'verify requires an archive'; verify "$2";; restore) [[ ${2:-} ]] || die 'restore requires an archive'; restore "$2";; recover) [[ ${2:-} ]] || die 'recover requires an archive'; recover_archive "$2";; list) list;; *) printf 'Usage: %s {init|backup|verify|restore|recover|list} [encrypted-age-archive]\n' "$0"; exit 2;; esac
