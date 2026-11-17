# Parser fuzz targets

Coverage-guided robustness tests for Freebird's wire and key parsers. Each
target asserts that arbitrary input returns an error rather than panicking, and
that successful parses re-encode to identical bytes.

| Target | Function under test |
|---|---|
| `token_request` | `TokenRequest::from_bytes` / `to_bytes` |
| `token_response` | `TokenResponse::from_bytes` |
| `token` | `Token::from_bytes` / `to_bytes` |
| `token_challenge` | `TokenChallenge::parse` / `serialize`, digest determinism |
| `authorization_header` | `parse_authorization_header` / `build_authorization_header` |
| `public_key_spki` | `PublicKey::from_spki` (canonical bytes only) |
| `secret_key_pkcs8` | `SecretKey::from_pkcs8` (canonical bytes only) |

This crate is excluded from the workspace and has its own lockfile. Seeds in
`corpus/` are regenerated from the RFC fixtures by `python3 seed_corpus.py`.
The stable property tests in `common/src/privacy_pass/tests.rs` cover the codec
targets in ordinary CI; these targets need a nightly toolchain and
`cargo install cargo-fuzz`.

```sh
cargo +nightly fuzz build -s none
cargo +nightly fuzz run -s none token_request /tmp/new-corpus corpus/token_request \
  -- -max_total_time=120
```

Pass a scratch directory first so discovered inputs do not grow the checked-in
seeds.

**Why `-s none`:** on current macOS, the AddressSanitizer runtime that
`cargo fuzz` enables by default hangs during process startup (inside
`__asan::InitializeShadowMemory`), before libFuzzer prints anything. The
targets exercise safe Rust, so running libFuzzer's coverage guidance without
AddressSanitizer is appropriate. On Linux the default sanitizer may be used.
Always confirm that libFuzzer prints `INITED` and `stat::` lines; a run with no
output did not fuzz anything.
