# Stop both services to back up or recover state.

Stop both services before copying or restoring their state. Restarting from a
provider snapshot, SQLite main file, or copied state directory can reopen
used invitations and tokens. This experimental procedure applies to the
[single-host Ubuntu deployment](deployment.md) and does not provide automatic
failover. Run the commands as root with the reviewed service binary and a
matching source checkout for `scripts/recovery-catalog.py`.

Copy whole state directories while both processes are stopped. Include any
`-wal`, `-shm`, and `.lock` files. The WAL files may contain committed changes
that have not reached the main SQLite files. Preserve ownership and modes:
0700 for directories and 0600 for state files. Do not unlink a lock file that
a process might hold.

The state directories contain three SQLite stores: `issuer/admission.sqlite`,
`issuer/issuer-keys.sqlite`, and `origin/origin.sqlite`. The Issuer stores a
`generation` file. Its optional features add `pow-key`, `pow.sqlite`, and
`app-clients.sqlite`. The Origin stores a `context` file. A backup may omit
`control.sock` or leave it as a stale node. The Issuer replaces this runtime
socket at startup.

## The catalog checks both key histories.

Check both roles against the external catalog to avoid restoring a retired
signing key or losing a key tombstone. The check compares complete public key
histories. It covers IDs, SPKI hashes, activation hours, the presence of
private keys on the Issuer, and retirement flags on the Origin. This record
does not reconstruct lost keys or make arbitrary old rotation snapshots safe
to restore. It does not detect rollback automatically and is not
cryptographically authenticated.

Keep the latest catalog outside the VPS instance, provider snapshots, and
application state that you might restore. Separate storage that you control
can keep it outside the restore scope. Update the catalog after every key
staging, activation, rescheduling, or retirement, before you resume serving.
If the catalog is missing, outdated, or mismatched, keep both services stopped
and investigate. Do not replace the authoritative record with restored state.

Pass the database file paths to the script so that it can record and check
the catalog. Do not pass the paths to their parent directories:

```sh
repo=/path/to/reviewed/freebird
issuer=/var/lib/freebird-issuer/state
origin=/var/lib/freebird-origin/state
catalog=/path/on/separate-storage/freebird-key-history.json
python3 "$repo/scripts/recovery-catalog.py" record \
  "$issuer/issuer-keys.sqlite" "$origin/origin.sqlite" "$catalog"
# A new catalog filename is required; record never overwrites an existing one.
python3 "$repo/scripts/recovery-catalog.py" check \
  "$issuer/issuer-keys.sqlite" "$origin/origin.sqlite" "$catalog"
```

Keep a copy of the catalog and the record of which backup and catalog are
current outside any whole-VPS snapshot that you might restore. Do not keep
the only copies under `/var/lib`, `/root`, or another directory in that
snapshot.

## Disable starts and stop both services before copying state.

Remove `/etc/freebird/serving-enabled` to block systemd from starting either
service. Keep that permission file outside the restored application state.
Removing the file does not stop running processes. Disable starts and stop
both units before every backup, restore, and update to the key catalog:

```sh
rm -f /etc/freebird/serving-enabled
sync -f /etc/freebird
systemctl stop freebird-issuer.service freebird-origin.service
systemctl show freebird-issuer.service freebird-origin.service \
  -p Id -p ActiveState -p SubState -p MainPID
```

Verify that both units report inactive/dead with `MainPID=0` and that no
maintenance command holds their locks. A `systemctl start` that skips a unit
because its condition is unmet can exit 0. Check the unit status to verify
that it started. Do not recreate the permission file in a boot script or
cleanup trap. Keep it absent on every failure.

## Copy both stopped services to private storage.

After confirming that both units are stopped and cannot start, create a
private backup directory on storage that you control. The backup contains
signing keys and the generation values for bearer secrets:

```sh
umask 077
backup=/path/to/new/private-backup
install -d -o root -g root -m 0700 "$backup"
cp -a -- "$issuer" "$backup/issuer-state"
cp -a -- "$origin" "$backup/origin-state"
sync
python3 "$repo/scripts/recovery-catalog.py" check \
  "$backup/issuer-state/issuer-keys.sqlite" \
  "$backup/origin-state/origin.sqlite" "$catalog"
```

If a copy or check fails, inspect and discard the incomplete backup. Leave
the live state intact. Keep the external catalog and backup separate because
the backup alone cannot prevent rollback. Back up again after any change to
the keys and retain a compatible binary.

For a backup that does not involve a restore, resume serving only after the
live key history matches the catalog:

```sh
python3 "$repo/scripts/recovery-catalog.py" check \
  "$issuer/issuer-keys.sqlite" "$origin/origin.sqlite" "$catalog"
install -o root -g root -m 0644 /dev/null /etc/freebird/serving-enabled
sync -f /etc/freebird
systemctl reset-failed freebird-issuer.service freebird-origin.service
systemctl start freebird-issuer.service freebird-origin.service
systemctl is-active freebird-issuer.service freebird-origin.service
```

## Check and invalidate staged state before restoring it.

Disable starts and stop both units before staging a restore. Confirm that
the clock is synchronized with `timedatectl status`. Leave the live
directories intact until the replacements have passed their checks. Stage
both copies in fresh sibling directories on the same filesystem. Stop if
either staging name already exists:

```sh
test ! -e /var/lib/freebird-issuer/state.recovering
test ! -e /var/lib/freebird-origin/state.recovering
cp -a -- "$backup/issuer-state" /var/lib/freebird-issuer/state.recovering
cp -a -- "$backup/origin-state" /var/lib/freebird-origin/state.recovering
next_issuer=/var/lib/freebird-issuer/state.recovering
next_origin=/var/lib/freebird-origin/state.recovering
python3 "$repo/scripts/recovery-catalog.py" check \
  "$next_issuer/issuer-keys.sqlite" "$next_origin/origin.sqlite" "$catalog"
```

Require a successful catalog check before invalidating credentials. A backup
that predates a rotation or retirement is incompatible. Do not run `init-*`,
reinstall a retired key, or change the catalog to make the check pass. Find a
compatible backup or consider a separate deployment with a separate trust
epoch.

Invalidate credentials in both staged directories before you let either unit
serve. Run each maintenance command as its service user while both units are
stopped:

```sh
bin=/usr/local/bin/freebird-privacy-pass-service
runuser -u freebird-issuer -- "$bin" recover-issuer-admission "$next_issuer"
runuser -u freebird-origin -- "$bin" recover-origin-context "$next_origin"
python3 "$repo/scripts/recovery-catalog.py" check \
  "$next_issuer/issuer-keys.sqlite" "$next_origin/origin.sqlite" "$catalog"
runuser -u freebird-issuer -- "$bin" issuer-key-status "$next_issuer"
runuser -u freebird-origin -- "$bin" origin-key-status "$next_origin"
```

`recover-issuer-admission` changes the invitation generation and removes
every restored invitation. If proof-of-work is enabled, it also rotates
`pow-key` and clears the table of spent challenges. If app admission is
enabled, it revokes every application key. Run `app-add` for each application
after recovery to give it a replacement key.

`recover-origin-context` replaces the context secret and clears all restored
challenges and spent rows in one transaction. It preserves the key history,
retired key records, pinned names, and minimum clock time. If recovery stops
between publication of the secret and the database commit, a hash mismatch
blocks normal startup. Stage both copies again from the intact backup and
repeat the procedure. Do not edit a hash or reuse the secret.

Complete both commands before either unit serves. This invalidates all old
invitations and old-context tokens, including those that were unused at
snapshot time. Provision replacement invitations offline after recovery.

When all checks pass, move the old live directories into private quarantine
and put the staged directories in their expected locations. Keep both units
stopped and prevent starts while you move the directories:

```sh
test ! -e /var/lib/freebird-issuer/state.pre-restore
test ! -e /var/lib/freebird-origin/state.pre-restore
mv -T -- "$issuer" /var/lib/freebird-issuer/state.pre-restore
mv -T -- "$origin" /var/lib/freebird-origin/state.pre-restore
mv -T -- "$next_issuer" "$issuer"
mv -T -- "$next_origin" "$origin"
sync
python3 "$repo/scripts/recovery-catalog.py" check \
  "$issuer/issuer-keys.sqlite" "$origin/origin.sqlite" "$catalog"
```

Keep the serving permission absent if a move is incomplete or a status check
fails. Inspect and repair the staged and quarantined directories while both
units are stopped. Do not retry automatically with a different key history.
Run the `install … serving-enabled` and `systemctl start` sequence only
after the recovered states pass their checks and the names, key IDs, and
activation times agree. Through nginx, verify the directory, a fresh 401
challenge, one fresh issuance and redemption, and a 401 on replay.

If only one store was damaged, preserve the healthy stores by copying their
complete live directories into staging while both services are stopped.
Replace only the damaged store's database and its matching secret and WAL
sidecars from the cold backup. Do not combine a main database file and WAL
files from different copies. Check key history and run both invalidation
commands on the staged pair. The automated restore drill tests recovery of
admission state, Origin state, Issuer keys, and the full bundle.

The local software cannot detect a machine-image rollback that also restores
the serving permission and the external catalog. The procedure does not
guarantee recovery after power loss or support arbitrary historical restores.
It does not provide automatic failover or replace independent cryptographic
review.
