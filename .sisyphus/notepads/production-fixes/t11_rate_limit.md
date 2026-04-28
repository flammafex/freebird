# T11: IP-Based Rate Limiting

## Implementation
Created `common/src/rate_limit.rs` with a Tower `PublicRateLimitLayer`:
- IP extraction from `ConnectInfo<SocketAddr>` first, then `X-Forwarded-For`
- 30 req/sec per IP over a 1-second window
- Lazy cleanup of entries older than 2 seconds
- Returns HTTP 429 with `Retry-After: 1` and JSON body when exceeded

## Integration
- Added to issuer public routes (`/v1/oprf/issue`, `/v1/public/issue`, etc.) in `issuer/src/startup.rs`
- Added to verifier public routes (`/v1/verify`, `/v1/check`, etc.) in `verifier/src/main.rs`
- Admin routes are NOT affected because the layer is applied before `.with_state()` on the public router, and admin routers are nested afterward.

## Key Decision
Used `std::sync::Mutex` instead of `tokio::sync::RwLock` to avoid adding tokio as a direct dependency of `freebird-common`. The critical section is tiny (hashmap retain + vec push), so a synchronous mutex is fine. Had to scope the guard inside a block to avoid the `Send` issue across await points.

## Verification
- `cargo check` passes for common, issuer, verifier
- All unit tests pass (common: 15, issuer: 92, verifier: 8)
- All integration tests pass (27 tests)
