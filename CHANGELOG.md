# Freebird changes by release

## Freebird has no production release

Independent cryptographic review blocks release publishing. The unreleased implementation includes these changes and tests:

- **Publicly verifiable Privacy Pass tokens** use the experimental RFC 9578 profile with one-use admission and durable redemption on a single instance.
- **Independent RFC vectors** check protocol values, and round-trip tests exercise the routers and loopback HTTP.
- **Offline key staging** prepares Issuer candidates and exports public SPKI without overwriting files.
- **Offline rotation** installs the Origin key first and schedules the Issuer at the same hour for one instance per role. Compare key status to confirm that the roles agree.
- **Offline retirement** removes superseded Issuer private material and Origin challenge and spend rows after the applicable safety boundaries. Permanent public-key tombstones prevent retired IDs from being reinstalled. Best-effort SQLite cleanup does not guarantee destruction or zeroization.
- **The RFC 9474 compatibility fork** pins stable RustCrypto RSA 0.10.0. `cargo audit` does not report the RSA release-candidate advisory against this pin. The fork and integration have not been independently reviewed.
- **Seven parser fuzz targets** completed their first campaign without failures. Bounded pruning removes expired replay state at the Origin, and an interoperability plan covers tests with independent implementations.
- **The single-host template** deploys nginx with TLS and systemd. A local HTTPS client mode pins the CA, and an end-to-end test exercises the proxy.
- **Bidirectional tests** use pinned TypeScript and Go implementations to exercise independent verification, redemption, replay, and negative cases.
- **Stopped recovery** invalidates credentials and rejects stale key histories. Cold-restore drills and commit and crash tests exercise the recovery rules.
- **Online provisioning** through `provision-live` lets the running Issuer create one-use invitations over a UID-restricted local control socket without downtime.
- **Optional ALTCHA admission** uses `init-issuer-pow` and the six-argument `serve-issuer` command. A durable spend record limits each solved, signed challenge to one invitation. CORS allows one origin, and recovery rotates proof-of-work state.
- **The self-hosted browser demo** in `demo/web/` has an end-to-end TLS test in headless Chrome. The nginx template serves the demo with a strict CSP and rate-limits proof-of-work.
- **Application admission** uses a server-only endpoint, a daily cap per application, and application secrets that are stored as hashes. Operators manage keys over the control socket, and recovery revokes all keys.
- **The integration kit** uses nginx `auth_request` and the Origin to protect any application route. An optional scope that nginx sets binds tokens to one resource. The browser and server packages are unpublished.
