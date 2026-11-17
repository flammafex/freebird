# Local experimental runner

This is a **loopback-only development probe**. For the experimental nginx/TLS
topology, see the [single-host deployment guide](deployment.md).
The binary does not provide TLS, automatic failover, multi-instance operation,
or backup restoration. It does provide offline key staging, **activation**
(rotation), and **retirement** for one local instance per role, described below.
Run one process per role with fresh, private state directories.

```sh
cargo build --locked -p freebird-privacy-pass-service
bin=target/debug/freebird-privacy-pass-service
$bin init-issuer /path/to/new-issuer-state
$bin provision /path/to/new-issuer-state
$bin issuer-key-status /path/to/new-issuer-state
```

`init-issuer` creates `admission.sqlite`, the invitation generation file, and
`issuer-keys.sqlite` (a genesis key active from hour 0). `provision` prints a
24-hour, one-use admission code **once**. Capture it privately; never put a
code in logs, shell history, or public issue reports. Stop the Issuer before
provisioning. A failed or partial initialization is never reset automatically.

`issuer-key-status` prints a frozen format: a `now` line, a `high-water` line,
then one row per key. Each row is
`<state> <key-id-hex> <activation-secs|-> <issuance-end-secs|-> <acceptance-deadline-secs|->`.
Issuer states are `staged`, `scheduled`, `active`, `retired-for-issuance`, and
`retired`. Times are Unix seconds. `-` means not applicable.

## Initialize the Origin from the genesis key

The Origin is initialized from the Issuer's **public** genesis key. It never
receives `issuer-keys.sqlite`. Export the active key by its public ID, then
create the Origin state with that exact key ID:

```sh
key_id="$($bin issuer-key-status /path/to/new-issuer-state | awk '$1=="active"{print $2}')"
$bin export-issuer-spki /path/to/new-issuer-state "$key_id" /path/to/genesis-spki.der
$bin init-origin /path/to/new-origin-state /path/to/genesis-spki.der "$key_id"
$bin origin-key-status /path/to/new-origin-state
```

`init-origin` refuses if the file's SHA-256 does not equal the key ID, and it
requires a fresh directory. `export-issuer-spki` writes a **new** mode-0600
file, synchronizes it and its parent directory, and never overwrites output.

## Serving

Start the Issuer and the Origin. Their HTTPS request URL describes an external
identity; the runner itself listens **only on loopback HTTP**:

```sh
$bin serve-issuer /path/to/new-issuer-state issuer.example \
  https://issuer.example/private-token/issue 127.0.0.1:8081
curl -fsS http://127.0.0.1:8081/.well-known/private-token-issuer-directory
```

```sh
$bin serve-origin /path/to/new-origin-state issuer.example origin.example 127.0.0.1:8082
curl -i http://127.0.0.1:8082/private-token/protected
```

`serve-origin` takes **no public-key argument**. Its keys come from the Origin
store. This replaces the former `serve-origin <dir> <issuer> <origin> <spki.der> <bind>`
form. `serve-origin` refuses a clock behind its high-water mark or when no key
is advertising at the current time.

The response to the protected resource is an RFC 9577 `PrivateToken`
challenge. The reference client tests in `privacy_pass_service/tests/` exercise
the complete flow through Axum routers and live loopback TCP:

```sh
cargo test --locked -p freebird-privacy-pass-service --tests
```

## Offline key maintenance

Every offline key command takes the state's lifetime lock. It **refuses while a
process serves that state**, with an `already owned` message. Stop the Issuer
before issuer key commands and the Origin before origin key commands. Times are
whole UTC hours, so each activation instant is Unix seconds divisible by 3600.
Commands never read a clock override; they use the system clock. Activation
must be in the future and after every existing activation.

Rotation order is **Origin first**. The Origin must be able to challenge with
and verify the new key before any Issuer signs with it.

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

Each refusal leaves state unchanged. Expected refusals include a non-aligned
`S`, a past `S`, a key ID that does not match the SPKI file or the Issuer's
staged/scheduled candidate, a second stage,
and any offline command run while the role is serving. Repeating the same `S`
for the same key is a successful no-op. Before `S` arrives, the operator may
reschedule the same key to a new future hour by running the install (Origin)
and activate (Issuer) commands again with the new value. Do this on both roles.
A retired key ID is never reinstalled.

### Reading the status diff

After step 4 the Issuer shows the current key `active` and the new key
`scheduled`. The Origin shows the current key `advertising` and the new key
`installed`. Both key rows have the same ID and activation values. The Issuer's
`issuance-end` (its successor's activation) and `acceptance-deadline` (that
plus 300 seconds) describe the last issuance window of the old key. The
Origin's `acceptance-deadline` matches it. Once the new key's activation hour
arrives, the old key becomes `retired-for-issuance` on the Issuer and
`verifying` on the Origin. The superseded key is never used for signing after
its successor's activation hour; its private material remains in
`issuer-keys.sqlite` until the operator retires it.

### Half-done rotation recovery

- **Origin installed, Issuer not yet scheduled.** The Origin advertises the new
  key only from `S`. Until then no key changes. Schedule the Issuer with the
  same `S` before it arrives. If `S` has passed, the Origin challenges with a
  key the Issuer cannot yet sign with, so new requests fail until the Issuer's
  new activation (see below). Tokens already issued under the old key
  keep redeeming until its acceptance deadline.
- **Issuer scheduled, Origin install refused or not run.** The Issuer signs
  with the new key from `S`, but the Origin cannot verify it: an outage, not an
  acceptance bypass. Install the Origin key with the same `S` before `S`.
  If `S` has already passed on the lagging Origin, use the recovery below;
  installing at a past hour is refused.
- **`S` passed on either lagging side.** Stop both roles and choose a new
  whole-hour `S'` in the future on **both** clocks. Schedule/install the same
  `NEW-ID` at `S'` on **both sides as needed**, Origin first: an absent or still
  installed Origin key uses `install-origin-key <dir> <spki> NEW-ID S'`, and a
  staged or still scheduled Issuer key uses
  `activate-issuer-key <dir> NEW-ID S'`. Do not leave a still-pending side at the
  old `S`. A key already advertising on the Origin or active on the Issuer
  cannot be rescheduled; leave that side at its existing activation and bring
  only the lagging side forward at `S'`. Check both statuses before restarting.
  There is an outage until the lagging side activates at `S'`, not an acceptance
  bypass; do not backdate a schedule or roll either clock back.

Never edit the SQLite files, delete a `.lock` sidecar, or copy an Issuer key
store to the Origin. A process crash releases the lifetime lock automatically.

## Retire the superseded key

Retirement is offline, under the same lifetime locks as activation. Keep the
old public key ID (`OLD-ID` below) from the status output. These times refer to
the **successor's** activation `S`, not the old key's activation:

```sh
# 6. Once now >= S, stop the Issuer and retire its old private key.
$bin retire-issuer-key /path/to/new-issuer-state OLD-ID
$bin issuer-key-status /path/to/new-issuer-state       # old row: retired
# Restart the Issuer; it signs only with the successor.

# 7. Once now >= S+420, stop the Origin and retire the same old key ID.
$bin retire-origin-key /path/to/new-origin-state OLD-ID
$bin origin-key-status /path/to/new-origin-state       # old row: retired
# Restart the Origin. A new rotation can now follow the same runbook.
```

The Issuer refuses retirement until a successor is active (`now >= S`). The
Origin refuses until `now >= S+420`: the last challenge deadline `S+300` plus
a 120-second safety margin. Retirement before that boundary is refused, not
queued. Unknown IDs, malformed IDs, an already retired key, the current key
without an active successor, and a clock behind high-water are also refused.

Issuer retirement atomically removes the old private material (`pkcs8=NULL`)
and advances high-water. Origin retirement atomically removes that key's
challenge and spent rows, marks the key retired, and advances high-water.
Both retain the public key record. **Retired IDs can never be reinstalled**;
retirement is not a way to reset or reuse an old key. The old status row keeps
its original activation, issuance-end, and acceptance-deadline values.

SQLite uses `secure_delete=ON`, and Issuer retirement attempts a
`wal_checkpoint(TRUNCATE)` after committing. This is **best-effort cleanup,
not a destruction guarantee**. Checkpoint failure or a busy result does not
undo committed retirement or make the command fail. Journal copies, backups,
snapshots, and process memory are outside this guarantee; no zeroization or
forensic erasure is claimed. Never use retirement as a substitute for the
documented backup/recovery procedure.

## Unsupported

No HSM, no online rotation API, no multi-instance or failover, no zeroization
of superseded key memory, and no multi-key directory with a not-before field.
The Issuer advertises exactly one key at a time.
Release remains blocked by independent cryptographic review and operational
backup/recovery tests.

## Upgrading older state

State created by earlier experimental builds is refused explicitly. Both
`signing.pk8` (legacy Issuer state) and schema-v1 key or Origin stores fail
with a message saying there is no migration and to initialize fresh state. The
file is left untouched, with no reset. Initialize fresh state in a new
directory.

## Experimental loopback client

This example is **local-only**, not a production client or general RFC 9577
parser. It accepts only this Origin's current three-parameter challenge layout.
The directory's advertised HTTPS identity is compared with the challenge;
network requests still go only to the explicitly supplied numeric loopback
HTTP bases. Proxies and redirects are disabled, responses are bounded, and the
invitation and token are never printed by the client.

For a fresh run, in terminal 1:

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

In terminal 2, from the same repository directory, set `demo` to the path
printed in terminal 1 and start the Origin:

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

Wait for the Origin's listening message before invoking the client. Expected
output is `issuance: 200; redemption: 200; replay: 401; invitation retry: 403`.
The invitation is spent even if a later step fails; use fresh state or stop
the Issuer and provision another invitation before retrying. Never pass an
invitation as a command-line argument. Prefer the protected-file stdin
redirection above; interactive stdin requires one line followed by EOF (and
may echo in your terminal, so disable echo or avoid it). Keep the temporary
state directory private; remove it after stopping both servers and completing
the experiment.

The example also has an opt-in, CA-pinned HTTPS mode for a local TLS proxy;
see the [deployment guide](deployment.md). It is not a remote or general client.
See the [protocol contract](protocol/privacy-pass-phase1.md) for the exact
binary formats, admission policy, challenge windows, and release blockers.
