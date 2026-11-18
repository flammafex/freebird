# Single-host deployment (experimental)

**Not approved for production authorization.** This is the one supported
*network topology* for testing Freebird: one Ubuntu 24.04 host, nginx terminating
HTTPS, and one loopback-only Issuer and one loopback-only Origin under systemd.
The [remaining release gates](https://github.com/flammafex/freebird/blob/main/SECURITY.md)
still apply. No replicas, failover, containers, CDN, or load balancer are
supported. The host must be single-tenant: other local accounts can connect
directly to the loopback HTTP ports.

```text
client ── HTTPS ── nginx ── 127.0.0.1:8081 ── Issuer (private key, invitations)
                    └───── 127.0.0.1:8082 ── Origin (public key, spent tokens)
```

The services do not read `Host`, forwarding headers, or client addresses. They
take their public identities from the operator's configuration. nginx must
restrict hostnames and routes, carry admission and authorization headers
unchanged, never cache or retry requests, and never log those headers or
bodies. Its warning/error log can still contain client IP addresses. The
operator of both roles can correlate issuance and redemption using network
metadata; blind signing alone does not prevent that.

## Prepare the host

Use local storage (not NFS) for `/var/lib`; the state relies on exclusive
process locks and SQLite durability. Synchronize the system clock before
starting the services (`timedatectl status`); a clock behind durable state is
refused. Install nginx, systemd, a compiler toolchain to build the checked-out
source, and certificates for **two distinct lowercase DNS names**. The examples
below use `issuer.example.org` and `origin.example.org`; replace both in the
nginx template and in the environment file. Names must have no trailing dot or
port. Configure DNS to point to this host.

The nginx template expects certificates at
`/etc/letsencrypt/live/<name>/fullchain.pem` and `privkey.pem`. Obtain them
using your ACME provider before enabling the TLS server blocks (a temporary
HTTP-only ACME configuration may be needed); install a renewal hook that runs
`nginx -t && systemctl reload nginx`. Never log invitation or token headers in
your existing nginx configuration; do not enable nginx debug logging.

From a reviewed checkout, as root:

```sh
cargo build --release --locked -p freebird-privacy-pass-service \
  --bin freebird-privacy-pass-service --example loopback_client
install -o root -g root -m 0755 target/release/freebird-privacy-pass-service \
  /usr/local/bin/freebird-privacy-pass-service
useradd --system --user-group --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin freebird-issuer
useradd --system --user-group --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin freebird-origin
install -d -o root -g root -m 0755 /etc/freebird
install -o root -g root -m 0644 deploy/systemd/freebird.env.example \
  /etc/freebird/freebird.env
# Edit the two public names; do not put invitations or private keys in this file.
install -d -o freebird-issuer -g freebird-issuer -m 0700 /var/lib/freebird-issuer
install -d -o freebird-origin -g freebird-origin -m 0700 /var/lib/freebird-origin
```

The service binary must be readable by the two role users. Confirm that
`FREEBIRD_ISSUER_NAME` and `FREEBIRD_ORIGIN_NAME` in the environment file
exactly match the two nginx `server_name` directives and the certificate DNS
names. **Check before initializing the Origin:** its two names are pinned in
its database at first open; changing them later is refused. The Issuer's
directory must advertise exactly
`https://<FREEBIRD_ISSUER_NAME>/private-token/issue`, not a loopback URL.
No proxy-supplied header changes these identities.

## Initialize and provision

All maintenance commands, including status and provisioning, take exclusive
locks and **must run as the role user with its unit stopped**. A root-run command
can leave root-owned SQLite or lock files and prevent the service from starting.
Never delete `.lock` files. Before the first start, initialize fresh
`state` subdirectories; initialization refuses an existing state directory:

```sh
bin=/usr/local/bin/freebird-privacy-pass-service
issuer=/var/lib/freebird-issuer/state
origin=/var/lib/freebird-origin/state
runuser -u freebird-issuer -- "$bin" init-issuer "$issuer"
key_id="$(runuser -u freebird-issuer -- "$bin" issuer-key-status "$issuer" |
  awk '$1=="active"{print $2}')"
# Verify the result is exactly one 64-character hexadecimal key ID.
test "${#key_id}" -eq 64
install -d -o freebird-issuer -g freebird-issuer -m 0700 /var/lib/freebird-issuer/transfer
runuser -u freebird-issuer -- "$bin" export-issuer-spki "$issuer" "$key_id" \
  /var/lib/freebird-issuer/transfer/genesis.der
# Copy public data into a fresh Origin-owned transfer directory, not its key store.
install -d -o freebird-origin -g freebird-origin -m 0700 /var/lib/freebird-origin/transfer
install -o freebird-origin -g freebird-origin -m 0600 \
  /var/lib/freebird-issuer/transfer/genesis.der /var/lib/freebird-origin/transfer/genesis.der
runuser -u freebird-origin -- "$bin" init-origin "$origin" \
  /var/lib/freebird-origin/transfer/genesis.der "$key_id"
runuser -u freebird-origin -- "$bin" origin-key-status "$origin"
rm /var/lib/freebird-issuer/transfer/genesis.der /var/lib/freebird-origin/transfer/genesis.der
```

The root-operated copy above transfers only the **public** SPKI, never the
Issuer's database. Verify that the Origin status shows the same key ID as the
Issuer's active key. Keep the original transfer directories private, and do
not overwrite a failed/partial initialization.

Create one invitation in a private file, not in the journal or a shell
argument:

```sh
(umask 077; runuser -u freebird-issuer -- "$bin" provision "$issuer") \
  > /root/freebird-invitation
```

An invitation is single-use and expires in 24 hours. Treat the output file as
a bearer secret. If output fails after provisioning, the invitation may be
irretrievable; do not infer that a retry is safe.

## Start and verify

Install the two units from
[`deploy/systemd/`](https://github.com/flammafex/freebird/tree/main/deploy/systemd)
under `/etc/systemd/system/`. Put the edited
[`deploy/nginx/freebird.conf`](https://github.com/flammafex/freebird/blob/main/deploy/nginx/freebird.conf)
in `/etc/nginx/conf.d/` (included within nginx's `http` context). Keep an
existing default vhost; Freebird blocks are intentionally **not** default
servers. Check certificate paths, two names, and ports before activation:

```sh
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/freebird-{issuer,origin}.service
nginx -t
# Only after both roles are initialized, names/keys agree, and checks pass:
# Record the external key-history catalog and a cold backup first (recovery guide).
install -o root -g root -m 0644 /dev/null /etc/freebird/serving-enabled
sync -f /etc/freebird
systemctl enable --now freebird-issuer.service freebird-origin.service
systemctl is-active freebird-issuer.service freebird-origin.service
systemctl reload nginx
curl --fail --silent --show-error \
  https://issuer.example.org/.well-known/private-token-issuer-directory
curl -i https://origin.example.org/private-token/protected
```

The directory's `issuer-request-uri` must be
`https://issuer.example.org/private-token/issue`; the protected route returns
401 with one `WWW-Authenticate` header. Unknown paths return nginx 404. HTTP
port 80 redirects normal requests to HTTPS; it never proxies to Freebird.
Both systemd units require `/etc/freebird/serving-enabled`; if it is absent,
even a manual start is skipped. A skipped start can exit successfully, so
check `is-active` and the listener rather than trusting the start exit code.
Removing the file does not stop an already running process.
Follow the [recovery guide](recovery.md#the-independent-key-history-record)
to create the external catalog and first cold backup before enabling serving.
Test end-to-end with a single fresh invitation (this **consumes** it):

```sh
target/release/examples/loopback_client --tls-ca /path/to/trusted-ca.pem \
  --connect 127.0.0.1 https://issuer.example.org/ \
  https://origin.example.org/ < /root/freebird-invitation
```

The pinned CA must validate both DNS names. The client prints only status
codes: `issuance: 200; redemption: 200; replay: 401; invitation retry: 403`.
Its original numeric-loopback HTTP mode remains available for local tests.
This example cannot connect to a remote host and is not a general-purpose SDK.

## Operation and limits

To provision more invitations while the Issuer serves, use its local control
socket (`control.sock` in the private state directory) as the service user:

```sh
(umask 077; runuser -u freebird-issuer -- "$bin" provision-live "$issuer") \
  > /root/freebird-invitation
```

Only a peer with the Issuer's own UID may connect; root and other users are
refused. Each successful call durably creates one 24-hour, one-use code before
replying. If the reply is lost, that code is orphaned until it expires; it is
never refunded or resent. Offline `provision` still works while the Issuer is
stopped. The socket path is `<state-dir>/control.sock`; Unix socket paths are
limited to about 100 bytes, so keep the state directory path short (the
default `/var/lib/freebird-issuer/state` is fine), or the Issuer refuses to start.
To offer open admission through a browser puzzle, see the
[browser demo and PoW guide](demo.md); to let your own application servers
request codes for their users, see
[admission for application servers](app-admission.md). Key staging, activation, and
retirement follow the [offline rotation runbook](quick-start.md#offline-key-maintenance):
enter the [two-role serving hold](recovery.md#hold-serving-before-touching-state),
run each command as **its** role user, compare statuses and activation times,
update the external key-history catalog and cold backup, then release the
hold. The Origin installs the new public key first. Status commands also
require the role to be stopped. A deliberate state/configuration refusal exits
1 and does not auto-restart; inspect `journalctl -u freebird-issuer -u
freebird-origin`, fix the cause, then `systemctl reset-failed` and start.
Never edit SQLite files or roll back the clock.

**Do not restore a provider snapshot, disk image, or database copy and then
start the services.** A rollback can reopen spent tokens and invitations. Use
the explicit [stopped backup and recovery procedure](recovery.md), which
refuses incompatible key history and invalidates old credentials before
reopening. It is not automatic failover. An upgrade must retain state and the old binary until validated;
older experimental schema is refused, not silently migrated.

Live invitations, admission for application servers, and an optional browser
PoW demo are available; WebAuthn,
vouching, and multi-instance operation are not. PoW raises cost, not
uniqueness. Nothing here waives the independent cryptographic review.
