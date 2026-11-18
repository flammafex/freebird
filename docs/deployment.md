# One Ubuntu host runs both experimental services.

Run Freebird for testing only on one Ubuntu 24.04 host. This is the only
supported network topology. nginx terminates HTTPS, and systemd runs one Issuer
and one Origin that listen only on loopback. Use a single-tenant host because
other local accounts can connect directly to the loopback HTTP ports.

Do not use this deployment for production authorization. It does not support
replicas, failover, containers, a CDN, or a load balancer. The
[release gates](https://github.com/flammafex/freebird/blob/main/SECURITY.md)
apply, including independent cryptographic review.

```text
client ── HTTPS ── nginx ── 127.0.0.1:8081 ── Issuer (private key, invitations)
                    └───── 127.0.0.1:8082 ── Origin (public key, spent tokens)
```

Set public identities in the service configuration. The services do not read
`Host`, forwarding headers, or client addresses. Restrict hostnames and
routes in nginx, and pass admission and authorization headers unchanged.
Disable request caching and retries. Keep those headers and request bodies
out of logs, although warnings and errors can contain client IP addresses.

An operator who runs both roles can correlate issuance and redemption by using
network metadata. Blind signing does not prevent that correlation.

## Prepare the host for local state and HTTPS.

Put `/var/lib` on local storage to support exclusive process locks and durable
SQLite writes. Do not use NFS. Synchronize the system clock and check it
with `timedatectl status` before starting either service. Startup is refused
if the clock is behind the time recorded in durable state.

Install nginx, systemd, and a compiler toolchain that can build the checked-out
source. Configure two distinct lowercase DNS names that point to this host.
Names cannot include a trailing dot or a port. Replace `issuer.example.org`
and `origin.example.org` in the nginx template and the environment file.

Obtain certificates for both names from your ACME provider before enabling
the TLS server blocks. You may need a temporary HTTP-only configuration for
ACME. The nginx template uses `/etc/letsencrypt/live/<name>/fullchain.pem` and
`privkey.pem`. Install a renewal hook that runs
`nginx -t && systemctl reload nginx`. Keep invitation and token headers out of
your nginx logs, and leave debug logging disabled.

Build and install the binary from a reviewed checkout as root. Create separate
service accounts and state directories for the two roles:

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

Make the service binary readable by both role users. Before initializing the
Origin, confirm that `FREEBIRD_ISSUER_NAME` and `FREEBIRD_ORIGIN_NAME` exactly
match the nginx `server_name` directives and the certificate DNS names. The
database pins the Origin's two names when it is first opened. A later change
is refused. Configure the Issuer directory to advertise exactly
`https://<FREEBIRD_ISSUER_NAME>/private-token/issue`, not a loopback URL. Proxy
headers cannot change these identities.

## Initialize both roles and create the first invitation.

Run offline maintenance commands, including status and provisioning, as the
role user with its unit stopped. Each command takes an exclusive lock.
Running it as root can leave root-owned SQLite or lock files that prevent
startup. Do not delete `.lock` files. Before the first start, initialize
fresh `state` subdirectories. Initialization refuses a directory that already
exists:

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

Transfer only the public SPKI as root. Do not transfer the Issuer's database.
Verify that the Origin status shows the same key ID as the Issuer's active key.
Keep the original transfer directories private. Preserve a failed or partial
initialization for inspection rather than overwriting it.

Create one invitation and capture it in a private file so that it does not
appear in the journal or in shell arguments:

```sh
(umask 077; runuser -u freebird-issuer -- "$bin" provision "$issuer") \
  > /root/freebird-invitation
```

Protect the output file as a bearer secret. An invitation expires in 24 hours
and can be used once. If output fails after provisioning, the invitation may
be irretrievable. Do not assume that it is safe to retry.

## Start both services and verify access through nginx.

Install the two units from
[`deploy/systemd/`](https://github.com/flammafex/freebird/tree/main/deploy/systemd)
in `/etc/systemd/system/` so that systemd can start the services. Put the edited
[`deploy/nginx/freebird.conf`](https://github.com/flammafex/freebird/blob/main/deploy/nginx/freebird.conf)
in `/etc/nginx/conf.d/`, which is included in nginx's `http` context. Keep an
existing default virtual host because the Freebird blocks are not default
servers.

Create the [external key catalog](recovery.md#the-catalog-checks-both-key-histories)
and first cold backup before enabling serving. Confirm that both roles are
initialized and their names and keys agree. Check the certificate paths, names,
and ports before activation:

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

Verify that the directory's `issuer-request-uri` is
`https://issuer.example.org/private-token/issue`. The protected route returns
401 with one `WWW-Authenticate` header. nginx returns 404 for unknown paths.
Port 80 redirects normal requests to HTTPS and does not proxy them to Freebird.

Keep `/etc/freebird/serving-enabled` present to allow systemd starts for both
roles. If the file is absent, even a manual start is skipped. Check `is-active`
and the listener because a skipped start can exit successfully. Removing the
file does not stop running processes.

Run the end-to-end test with one fresh invitation. The test consumes it:

```sh
target/release/examples/loopback_client --tls-ca /path/to/trusted-ca.pem \
  --connect 127.0.0.1 https://issuer.example.org/ \
  https://origin.example.org/ < /root/freebird-invitation
```

Use a pinned CA that can validate both DNS names. The client prints only status
codes: `issuance: 200; redemption: 200; replay: 401; invitation retry: 403`.
For local tests, the client also accepts numeric loopback HTTP addresses. It
cannot connect to a remote host and is not a general-purpose SDK.

## Provision invitations without stopping the Issuer.

Run `provision-live` as the Issuer's service user to create invitations while
the Issuer serves. The command uses the local control socket:

```sh
(umask 077; runuser -u freebird-issuer -- "$bin" provision-live "$issuer") \
  > /root/freebird-invitation
```

Connect as the Issuer's UID. Connections from root and other users are refused.
Each successful call durably creates one single-use code before sending the
reply. The code expires in 24 hours. If the reply is lost, the code remains
unclaimed until it expires. It is not refunded or resent. Use offline
`provision` while the Issuer is stopped.

Keep `<state-dir>/control.sock` within the Unix socket path limit of about
100 bytes to allow Issuer startup. The default state path,
`/var/lib/freebird-issuer/state`, fits.

Use the optional [browser puzzle](demo.md) for open admission or
[app admission](app-admission.md) to let application servers request codes for
their users. Proof-of-work raises the cost of collecting tokens. It does not
prove that each visitor is unique. WebAuthn, vouching, and multi-instance
operation are unsupported.

## Stop both roles to rotate keys or restore state.

Use the [offline rotation procedure](quick-start.md#stop-each-role-before-changing-its-keys)
to stage, activate, or retire keys. [Stop both services](recovery.md#disable-starts-and-stop-both-services-before-copying-state)
and run each command as its role user. Install the successor's public key on
the Origin first. Compare statuses and activation times, then update the
external key catalog and cold backup before releasing the hold. Status
commands also require the role to be stopped.

Check `journalctl -u freebird-issuer -u freebird-origin` if a unit refuses to
start. A state or configuration refusal exits with status 1 and does not
trigger an automatic restart. Correct the cause, then run
`systemctl reset-failed` and start the unit. Do not edit SQLite files or roll
back the clock.

Use [stopped recovery](recovery.md) because a provider snapshot, disk image, or
database copy can reopen spent tokens and invitations if you restart without
invalidating them. The procedure checks key history for compatibility and
invalidates old credentials before you restart. It is not automatic failover.
Retain the state and the old binary until you validate an upgrade. Startup
rejects older experimental schemas and does not migrate them.
