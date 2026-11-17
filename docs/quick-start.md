# Local experimental runner

This is a **loopback-only development probe**, not deployment guidance.
The binary does not provide TLS, key rotation, automatic failover, or backup
restoration. Run one process per role with fresh, private state directories.

```sh
cargo build --locked -p freebird-privacy-pass-service
bin=target/debug/freebird-privacy-pass-service
$bin init-issuer /path/to/new-issuer-state
$bin init-origin /path/to/new-origin-state
$bin provision /path/to/new-issuer-state
```

`provision` prints a 24-hour, one-use admission code **once**. Capture it
privately. Stop the Issuer before provisioning; its lifetime lock prevents
concurrent access. Never put a code in logs, shell history, or public issue
reports. A failed or partial initialization is not automatically reset.

The Issuer's HTTPS request URL describes an external identity; the runner
itself listens **only on loopback HTTP**. To inspect its standard directory:

```sh
$bin serve-issuer /path/to/new-issuer-state issuer.example \
  https://issuer.example/private-token/issue 127.0.0.1:8081
curl -fsS http://127.0.0.1:8081/.well-known/private-token-issuer-directory
```

The Origin requires the **DER SPKI public key** from that directory,
base64url-decoded into a file. Do not copy the Issuer's `signing.pk8` to the
Origin. With a separately obtained `issuer-public-spki.der`:

```sh
$bin serve-origin /path/to/new-origin-state issuer.example origin.example \
  issuer-public-spki.der 127.0.0.1:8082
curl -i http://127.0.0.1:8082/private-token/protected
```

The response is an RFC 9577 `PrivateToken` challenge. Reference client tests
in `privacy_pass_service/tests/roundtrip.rs` and `network_roundtrip.rs`
exercise the complete flow through Axum routers and live loopback TCP:

```sh
cargo test --locked -p freebird-privacy-pass-service --tests
```

## Experimental loopback client

This example is **local-only**, not a production client or general RFC 9577
parser. It accepts only this Origin's current three-parameter challenge layout.
The directory's advertised HTTPS identity is compared with the challenge;
network requests still go only to the explicitly supplied numeric loopback
HTTP bases. Proxies and redirects are disabled, responses are bounded, and
the invitation and token are never printed by the client.

For a fresh run, in terminal 1:

```sh
cargo build --locked -p freebird-privacy-pass-service
bin="$PWD/target/debug/freebird-privacy-pass-service"
umask 077
demo="$(mktemp -d)"
printf 'Demo directory for terminal 2: %s\n' "$demo"
$bin init-issuer "$demo/issuer"
$bin init-origin "$demo/origin"
$bin provision "$demo/issuer" > "$demo/invitation"
$bin serve-issuer "$demo/issuer" issuer.example \
  https://issuer.example/private-token/issue 127.0.0.1:8081
```

In terminal 2, from the same repository directory, set `demo` to the path
printed in terminal 1, obtain only the public key, and start the Origin:

```sh
umask 077
demo="/path/printed/by/terminal-1"
curl --noproxy '*' -fsS --max-time 10 \
  http://127.0.0.1:8081/.well-known/private-token-issuer-directory \
  | python3 -c 'import sys,json,base64; d=json.load(sys.stdin); sys.stdout.buffer.write(base64.urlsafe_b64decode(d["token-keys"][0]["token-key"]))' \
  > "$demo/issuer-public-spki.der"
target/debug/freebird-privacy-pass-service serve-origin \
  "$demo/origin" issuer.example origin.example \
  "$demo/issuer-public-spki.der" 127.0.0.1:8082 &
origin_pid=$!
cargo run --locked -p freebird-privacy-pass-service --example loopback_client -- \
  http://127.0.0.1:8081 http://127.0.0.1:8082 < "$demo/invitation"
kill "$origin_pid"
rm "$demo/invitation"
```

Wait for the Origin's listening message before invoking the client. Expected
output is `issuance: 200; redemption: 200; replay: 401; invitation retry: 403`.
The invitation is spent even if a later step fails; use fresh state or stop
the Issuer and provision another invitation before retrying.
Never pass an invitation as a command-line argument. Prefer the protected-file
stdin redirection above; interactive stdin requires one line followed by EOF
(and may echo in your terminal, so disable echo or avoid it).
Keep the temporary state directory private; remove it after stopping both
servers and completing the experiment.

There is no supported production network client or deployment recipe yet.
See the [protocol contract](protocol/privacy-pass-phase1.md) for the exact
binary formats, admission policy, challenge windows, and release blockers.
