# Fuzz tests check that Freebird parsers handle arbitrary input

The coverage-guided fuzz tests check that Freebird's wire and key parsers
return errors for invalid input and do not panic. They also check that
successful parses re-encode to identical bytes.

| Target | Function under test |
|---|---|
| `token_request` | `TokenRequest::from_bytes` and `to_bytes` |
| `token_response` | `TokenResponse::from_bytes` |
| `token` | `Token::from_bytes` and `to_bytes` |
| `token_challenge` | `TokenChallenge::parse`, `serialize`, and the check that the digest is deterministic |
| `authorization_header` | `parse_authorization_header` and `build_authorization_header` |
| `public_key_spki` | `PublicKey::from_spki` with canonical bytes only |
| `secret_key_pkcs8` | `SecretKey::from_pkcs8` with canonical bytes only |

## A nightly toolchain builds and runs the fuzz targets

Use a nightly toolchain and run `cargo install cargo-fuzz` to run the fuzz
targets. The crate has its own lockfile and is excluded from the workspace.
The stable property tests in `common/src/privacy_pass/tests.rs` cover the
codec targets in ordinary CI.

Run `python3 seed_corpus.py` to regenerate the seeds in `corpus/` from the
RFC fixtures. Pass the scratch directory before the checked-in corpus so
that discovered inputs are kept separate from the seeds.

```sh
cargo +nightly fuzz build -s none
cargo +nightly fuzz run -s none token_request /tmp/new-corpus corpus/token_request \
  -- -max_total_time=120
```

## Disabling AddressSanitizer avoids a startup hang on macOS

Use `-s none` on macOS because the AddressSanitizer runtime that `cargo fuzz`
enables by default hangs in `__asan::InitializeShadowMemory` during startup.
The hang occurs before libFuzzer prints output. The targets exercise safe
Rust, so libFuzzer can run coverage-guided tests without AddressSanitizer.
On Linux, you can use the default sanitizer.

Confirm that libFuzzer prints `INITED` and `stat::` lines. A run with no
output did not fuzz any inputs.
