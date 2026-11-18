# Stopped backup and recovery

**Experimental single-host procedure.** Read the
[deployment guide](deployment.md) first. Never restore a provider snapshot,
SQLite main file, or copied state directory and simply restart: an older copy
can reopen used invitations and tokens. These commands require root on the
supported Ubuntu host, the reviewed service binary, and the matching source
checkout for `scripts/recovery-catalog.py`. They are not automatic failover.

The three SQLite stores are `issuer/admission.sqlite`,
`issuer/issuer-keys.sqlite`, and `origin/origin.sqlite`. The Issuer also has a
`generation` file and the Origin a `context` file. SQLite WAL files may contain
committed changes not yet copied into the main files. **Copy whole state
directories only while both processes are stopped**, including any `-wal`,
`-shm`, and `.lock` files. Do not unlink a lock file while a process might
hold it. Keep ownership and mode 0700 directories / mode 0600 state files.
The Issuer's `control.sock` is a runtime socket, not state: a backup may omit
it or copy it as a stale node; the Issuer replaces it at startup.

## The independent key-history record

The restore check compares complete public key histories for both roles:
IDs, SPKI hashes, activation hours, whether the Issuer still has each private
key, and Origin retirement flags. This prevents an older backup from
silently restoring a retired signing key or forgetting a key tombstone. It
cannot reconstruct lost keys or safely recover an arbitrary old rotation
snapshot. Keep the **newest** catalog outside the VPS/provider-snapshot and
application-state restore scope (for example, on separate operator-controlled
storage). Update it after **every** key staging, activation, rescheduling, or
retirement, before serving again. A lost, older, or mismatching catalog is a
reason to stay stopped and investigate, not to record the restored state as
the new authority. The catalog is an operational record, **not** an automatic
or cryptographically authenticated rollback detector.

The script's arguments are the **database files**, not their parent directories:

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

Do not place the catalog only under `/var/lib`, `/root`, or another directory
included in a whole-VPS snapshot you might restore. The same restriction
applies to the operator's record of which backup/catalog is current.

## Hold serving before touching state

The shipped systemd units require
`/etc/freebird/serving-enabled`. Keep that permission file **outside the
restored application state**. Removal prevents later systemd starts; it does
*not* stop processes already running. Therefore every backup, restore, and
key-history catalog update begins:

```sh
rm -f /etc/freebird/serving-enabled
sync -f /etc/freebird
systemctl stop freebird-issuer.service freebird-origin.service
systemctl show freebird-issuer.service freebird-origin.service \
  -p Id -p ActiveState -p SubState -p MainPID
```

Require **both** units inactive/dead with `MainPID=0`, and verify no other
maintenance command holds their locks. A condition-skipped `systemctl start`
can itself exit 0; do not interpret that exit code as a running service.
Do not put this positive permission file in an auto-recreating boot script or
restore it in a cleanup trap. Keep it absent on every failure.

## Make a cold backup

With the hold above confirmed, use a new private directory on storage you
control. The backup contains signing keys and bearer-secret generations:

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

If any copy or check fails, discard the incomplete **new backup** after
inspection, not the live state. Keep the backup and external catalog
separately; do not claim that a backup alone will prevent rollback.
Back up again after any key lifecycle change, and retain a compatible binary.

For a routine backup with no restore, release the hold only after checking
the current live key history against the catalog:

```sh
python3 "$repo/scripts/recovery-catalog.py" check \
  "$issuer/issuer-keys.sqlite" "$origin/origin.sqlite" "$catalog"
install -o root -g root -m 0644 /dev/null /etc/freebird/serving-enabled
sync -f /etc/freebird
systemctl reset-failed freebird-issuer.service freebird-origin.service
systemctl start freebird-issuer.service freebird-origin.service
systemctl is-active freebird-issuer.service freebird-origin.service
```

## Restore a compatible cold backup

Enter the hold again, check synchronized time (`timedatectl status`), and
leave the existing live directories intact until the replacement is
validated. Stage **both** copies in fresh sibling directories on the same
filesystem; refuse existing staging names:

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

The check **must pass before invalidation**. A backup from before a later
rotation or retirement is incompatible; do not use `init-*`, reinstall a
retired key, or change the catalog to make it pass. Recover a newer compatible
backup or handle a new deployment/trust epoch as a separate decision.

Run each explicit maintenance command as its service user on the **staged**
state, while both units remain stopped:

```sh
bin=/usr/local/bin/freebird-privacy-pass-service
runuser -u freebird-issuer -- "$bin" recover-issuer-admission "$next_issuer"
runuser -u freebird-origin -- "$bin" recover-origin-context "$next_origin"
python3 "$repo/scripts/recovery-catalog.py" check \
  "$next_issuer/issuer-keys.sqlite" "$next_origin/origin.sqlite" "$catalog"
runuser -u freebird-issuer -- "$bin" issuer-key-status "$next_issuer"
runuser -u freebird-origin -- "$bin" origin-key-status "$next_origin"
```

The Issuer command publishes a new invitation generation and removes every
restored invitation. The Origin command publishes a new context secret and
atomically clears **all** restored challenges and spent rows while keeping
the full key/tombstone history, pinned names, and clock floor. If interrupted
between secret publication and database commit, the hash mismatch refuses
normal startup; **restage from the intact backup and repeat**, never manually
edit a hash or reuse the secret. Both commands must finish before either
unit can serve. Old invitations and old-context tokens, whether used or
unused at snapshot time, are invalid. New invitations must be provisioned
offline after recovery.

Only when all checks pass, retain the old live state in private quarantine and
swap the staged directories into their expected locations while still held:

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

Any partial move or failed status check leaves the serving permission
**absent**. Inspect and repair the staged/quarantined directories under the
hold; never automatically retry with a different key history. Release the
hold with the `install … serving-enabled` and `systemctl start` sequence
above only after the recovered states pass their checks and the two names,
key IDs, and activation times agree. Verify the directory, a fresh 401
challenge, one fresh issuance/redemption, and replay 401 through nginx.

If only one store was damaged, preserve the healthy stores rather than rolling
them back: copy their current complete directories into staging, then replace
only the damaged store's database **and its matching secret and WAL sidecars**
from the cold backup while stopped. Check key history and run **both**
invalidation commands on the staged pair as above. Never combine a database
main file with WAL from a different copy. The automated restore drill tests
admission-only, Origin-only, Issuer-key-only, and full-bundle cases.

An entire machine-image rollback that also restores the serving permission
and external catalog is **not detectable by this local software**. Do not
describe this procedure as power-loss proof, arbitrary historical restore,
automatic failover, or independent cryptographic review.
