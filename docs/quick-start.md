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

There is no supported network client or production deployment recipe yet.
See the [protocol contract](protocol/privacy-pass-phase1.md) for the exact
binary formats, admission policy, challenge windows, and release blockers.
