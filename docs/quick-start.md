# Run one Issuer and one Origin on loopback.

Use the experimental runner for local development with one process per role
and fresh, private state directories. It supports offline key staging,
activation for rotation, and retirement. The binary does not provide TLS,
automatic failover, multi-instance operation, or backup restoration. The
experimental [single-host deployment](deployment.md) uses nginx for TLS.

Build the runner, create Issuer state, and provision the first invitation:

```sh
cargo build --locked -p freebird-privacy-pass-service
bin=target/debug/freebird-privacy-pass-service
$bin init-issuer /path/to/new-issuer-state
$bin provision /path/to/new-issuer-state
$bin issuer-key-status /path/to/new-issuer-state
```

`init-issuer` creates `admission.sqlite`, the invitation generation file, and
`issuer-keys.sqlite`. The genesis key is active from hour 0. A failed or
partial initialization is not reset automatically.

Capture the output of `provision` privately because the command prints the
code only once. The code expires in 24 hours and can be used once. Keep it
out of logs, shell history, and public issue reports. Stop the Issuer before
running `provision`. While the Issuer serves, run
`$bin provision-live <issuer-state-dir>` as the Issuer's user.

`issuer-key-status` prints a fixed format with a `now` line, a `high-water`
line, and one row per key. Each row uses
`<state> <key-id-hex> <activation-secs|-> <issuance-end-secs|-> <acceptance-deadline-secs|->`.
Issuer states are `staged`, `scheduled`, `active`, `retired-for-issuance`, and
`retired`. Times are in Unix seconds. The value `-` means that a time does
not apply.

## Initialize the Origin from the public genesis key.

Export the active public key by its ID and use that exact ID to create the
Origin state. Do not transfer the Issuer's `issuer-keys.sqlite` to the Origin:

```sh
key_id="$($bin issuer-key-status /path/to/new-issuer-state | awk '$1=="active"{print $2}')"
$bin export-issuer-spki /path/to/new-issuer-state "$key_id" /path/to/genesis-spki.der
$bin init-origin /path/to/new-origin-state /path/to/genesis-spki.der "$key_id"
$bin origin-key-status /path/to/new-origin-state
```

`init-origin` requires a fresh directory and a public key file whose SHA-256
hash matches the key ID. `export-issuer-spki` creates a mode-0600 file and
synchronizes it and its parent directory. It does not overwrite a file.

## Serve the directory and challenge over loopback HTTP.

Start the Issuer and Origin on separate loopback HTTP addresses. The HTTPS
request URL identifies the Issuer externally. It does not change where the
runner listens.

Start the Issuer and check its directory:

```sh
$bin serve-issuer /path/to/new-issuer-state issuer.example \
  https://issuer.example/private-token/issue 127.0.0.1:8081
curl -fsS http://127.0.0.1:8081/.well-known/private-token-issuer-directory
```

Start the Origin and check its protected route:

```sh
$bin serve-origin /path/to/new-origin-state issuer.example origin.example 127.0.0.1:8082
curl -i http://127.0.0.1:8082/private-token/protected
```

`serve-origin` loads keys from the Origin store. It does not accept a public
key argument such as `<spki.der>` in
`serve-origin <dir> <issuer> <origin> <spki.der> <bind>`. Startup is refused
if the clock is behind the high-water mark or if there is no key to advertise
at startup.

The protected route returns an RFC 9577 `PrivateToken` challenge. Run the
reference client tests in `privacy_pass_service/tests/` to exercise the
complete flow through Axum routers and live loopback TCP:

```sh
cargo test --locked -p freebird-privacy-pass-service --tests
```

## Stop each role before changing its keys.

Stop the Issuer before Issuer key commands and the Origin before Origin key
commands. Every offline key command needs the lifetime lock for the state.
If a process is serving that state, the command fails with `already owned`.

Choose an activation time in the future and after every existing activation.
It must be a whole UTC hour, expressed as Unix seconds divisible by 3600.
Commands use the system clock and do not accept a clock override.

Install the successor's public key on the Origin before scheduling it on the
Issuer. The Origin must be able to issue challenges for the key and verify
its tokens before the Issuer signs with it:

```sh
# 1. Stop the Issuer. Stage its next candidate key (refused while one is staged or scheduled).
$bin stage-issuer-key /path/to/new-issuer-state
$bin issuer-key-status /path/to/new-issuer-state        # new row: staged <NEW-ID> - - -
# Replace NEW-ID with the staged row's key ID in every command below.
$bin export-issuer-spki /path/to/new-issuer-state NEW-ID /path/to/next-spki.der

# 2. Stop the Origin. Install the new public key FIRST, activating at S.
S=$(( ($(date +%s) / 3600 + 2) * 3600 ))               # an hour boundary, two hours ahead
$bin install-origin-key /path/to/new-origin-state /path/to/next-spki.der NEW-ID "$S"

# 3. Schedule the Issuer for the same S (activation of the staged key).
$bin activate-issuer-key /path/to/new-issuer-state NEW-ID "$S"

# 4. Compare the two statuses. Columns 2-3 (key ID, activation) must match.
$bin issuer-key-status /path/to/new-issuer-state
$bin origin-key-status /path/to/new-origin-state

# 5. Start both roles again before S.
```

An offline command fails and leaves state unchanged if you run it while the
role is serving. Other refusals include a past `S`, an `S` that is not a whole
hour, a mismatched key ID, and a second staging request. The ID must match
the SPKI file or the Issuer's staged or scheduled key, as applicable.

Repeating the same `S` for the same key succeeds without changing state.
Before `S` arrives, you can reschedule the same key to a different future
hour. Run `install-origin-key` on the Origin and `activate-issuer-key` on the
Issuer with the same replacement time. Do not reinstall a retired key ID.

### Matching statuses confirm the rotation schedule.

Compare key IDs and activation times across both roles in step 4. The active
key is `active` on the Issuer and `advertising` on the Origin. Its successor
is `scheduled` on the Issuer and `installed` on the Origin.

Check the `issuance-end` and `acceptance-deadline` values for the key that is
being replaced. Issuance ends when its successor activates. The acceptance
deadline is 300 seconds later and matches on both roles.

At the successor's activation hour, the old key becomes
`retired-for-issuance` on the Issuer and `verifying` on the Origin. The
Issuer stops signing with the old key at that hour. Its private material
remains in `issuer-keys.sqlite` until you retire it.

### Finish a partial rotation to restore issuance.

If a rotation is incomplete, use the scheduled time if it is still in the
future. Otherwise, pick a future time for any role that has yet to activate
the key.

- **Schedule the Issuer before `S`** if the Origin has installed the
  successor but the Issuer has not scheduled it. Neither role changes keys
  before `S`. From `S`, the Origin challenges with the successor. If the
  Issuer cannot sign with it, issuance requests fail until the Issuer
  activates that key. Tokens signed with the old key can still be redeemed
  until its acceptance deadline.
- **Install the key on the Origin before `S`** if the Issuer has scheduled
  it but Origin installation failed or did not run. From `S`, the Issuer
  signs with the successor. If the Origin cannot verify those tokens,
  requests fail rather than bypassing token checks. The Origin refuses an
  installation at a past hour.
- **Choose a future whole hour `S'`** if `S` has passed on either role that
  has yet to activate the key. Stop both roles and choose an hour that is
  in the future on both clocks. Install or schedule the same `NEW-ID` at
  `S'` wherever the key has not activated, Origin first. For an absent or
  still installed Origin key, run `install-origin-key <dir> <spki> NEW-ID S'`.
  For a staged or still scheduled Issuer key, run
  `activate-issuer-key <dir> NEW-ID S'`. Do not leave a pending activation at
  the old `S`. A key that is already advertising on the Origin or active on
  the Issuer cannot be rescheduled. Leave its activation time unchanged and
  check both statuses before restarting. Requests fail until the lagging
  role activates at `S'`. Token checks are not bypassed. Do not backdate a
  schedule or roll either clock back.

A process crash releases the lifetime lock automatically. Do not edit
SQLite files, delete a `.lock` file, or copy an Issuer key store to the
Origin.

## Retire a key after its role stops using it.

Stop each role before retiring its key. Retirement uses the same offline
lifetime locks as activation. Take `OLD-ID` from the status output for the
old public key. Use `S` for the successor's activation time, not the old
key's activation time:

```sh
# 6. Once now >= S, stop the Issuer and retire its old private key.
$bin retire-issuer-key /path/to/new-issuer-state OLD-ID
$bin issuer-key-status /path/to/new-issuer-state       # old row: retired
# Restart the Issuer; it signs only with the successor.

# 7. Once now >= S+420, stop the Origin and retire the same old key ID.
$bin retire-origin-key /path/to/new-origin-state OLD-ID
$bin origin-key-status /path/to/new-origin-state       # old row: retired
# Restart the Origin after retirement. Use the same procedure for the next rotation.
```

Retire the old key on the Issuer only once its successor is active,
when `now >= S`. The Origin requires `now >= S+420`, which is the last
challenge deadline `S+300` plus a 120-second safety margin. Commands that
run too early are refused, not queued. Retirement also fails for unknown
or malformed IDs, retired keys, keys with no active successor, and clocks
behind the high-water mark.

Issuer retirement removes the old private material by setting `pkcs8=NULL`
and advances the high-water mark in one transaction. Origin retirement
removes the key's challenge and spent rows, marks it retired, and advances
the high-water mark in one transaction. Both roles retain the public key
record. The status row retains the key's activation, issuance-end, and
acceptance-deadline values. Retired IDs cannot be reinstalled, reset, or reused.

SQLite uses `secure_delete=ON`. After committing retirement, the Issuer
attempts `wal_checkpoint(TRUNCATE)` to clean up SQLite data. A failed or busy
checkpoint does not undo retirement or make the command fail. Cleanup does
not guarantee destruction of private material. It does not cover journal
copies, backups, snapshots, or process memory. It does not guarantee
zeroization or forensic erasure. Use the
[backup and recovery procedure](recovery.md) to restore state, not retirement.

## The runner advertises one key at a time.

The Issuer directory advertises exactly one key at a time. It does not
provide multiple keys with a not-before field. The runner does not provide
HSM support, an online rotation API, multi-instance operation, failover, or
zeroization of memory that holds superseded keys. Release requires
independent cryptographic review.

## Unsupported schemas require a fresh state directory.

Initialize a fresh state directory if startup refuses an unsupported schema.
Older experimental state such as the Issuer's `signing.pk8` or schema-v1 key
or Origin stores is refused. The error states that migration is unavailable
and that you must initialize fresh state. The existing file is not changed
or reset.

## Test issuance, redemption, and replay on loopback.

Use the experimental loopback client for local tests only. It is not a
production or remote client, and it is not a general RFC 9577 parser. It
accepts only the Origin's three-parameter challenge layout. It checks the
challenge against the HTTPS identity in the directory. In HTTP mode it sends
requests only to the specified numeric loopback base addresses. It disables
proxies and redirects, limits response sizes, and does not print the
invitation or token.

In terminal 1, create fresh state and an invitation, then start the Issuer:

```sh
cargo build --locked -p freebird-privacy-pass-service
bin="$PWD/target/debug/freebird-privacy-pass-service"
umask 077
demo="$(mktemp -d)"
printf 'Demo directory for terminal 2: %s\n' "$demo"
$bin init-issuer "$demo/issuer"
$bin provision "$demo/issuer" > "$demo/invitation"
key_id="$($bin issuer-key-status "$demo/issuer" | awk '$1=="active"{print $2}')"
$bin export-issuer-spki "$demo/issuer" "$key_id" "$demo/genesis-spki.der"
$bin init-origin "$demo/origin" "$demo/genesis-spki.der" "$key_id"
$bin serve-issuer "$demo/issuer" issuer.example \
  https://issuer.example/private-token/issue 127.0.0.1:8081
```

In terminal 2, use the same repository directory and set `demo` to the
path printed in terminal 1. Start the Origin and wait for its listening
message before running the client:

```sh
umask 077
demo="/path/printed/by/terminal-1"
bin="$PWD/target/debug/freebird-privacy-pass-service"
"$bin" serve-origin "$demo/origin" issuer.example origin.example 127.0.0.1:8082 &
origin_pid=$!
cargo run --locked -p freebird-privacy-pass-service --example loopback_client -- \
  http://127.0.0.1:8081 http://127.0.0.1:8082 < "$demo/invitation"
kill "$origin_pid"
rm "$demo/invitation"
```

Check for `issuance: 200; redemption: 200; replay: 401; invitation retry: 403`.
The invitation is spent even if a later step fails. Before retrying, start
with fresh state or stop the Issuer and provision another invitation.

Redirect a protected file to standard input to keep the invitation out of
command-line arguments. Interactive input requires one line followed by EOF.
Disable terminal echo if you enter the invitation interactively. Keep the
temporary state directory private and remove it after the test when both
servers are stopped.

Use the opt-in HTTPS mode with a pinned CA to test the
[local TLS proxy](deployment.md). The
[protocol contract](protocol/privacy-pass-phase1.md) specifies the binary
formats, admission policy, challenge windows, and release requirements.
