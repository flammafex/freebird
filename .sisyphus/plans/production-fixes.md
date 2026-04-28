# Production Readiness Fixes

## TL;DR

> Fix all 22 production-blocking issues identified in the security/correctness/infra audit.

## Progress

### Completed (23/27)

- [x] 0. Verify Existing Test Baseline
- [x] 1. Remove Default Admin Key from docker-compose + Fail on Missing Key
- [x] 2. Derive HMAC Comparison Key from ADMIN_API_KEY
- [x] 3. Fail Startup on Insecure Default Salts + Generate Random Fallbacks
- [x] 4. Add Minimum Grace Period Enforcement for Key Rotation
- [x] 5. Fix Invitation Tree Ban to Use Recursive BFS with Depth Cap
- [x] 6. Convert 4 Non-Atomic State Writes to Temp-File-Then-Rename Pattern
- [x] 7. Require HTTPS for Verifier Issuer Metadata Refresh + Add Public Key Pinning
- [x] 8. Fail WebAuthn Startup if PROOF_SECRET Not Set + Remove Insecure Fallback
- [x] 9. Enforce ADMIN_API_KEY Minimum Length as Startup Error
- [x] 10. Replace rayon+block_on with tokio JoinSet for Batch Operations
- [x] 11. Add IP-Based Rate Limiting on Public Token Endpoints
- [x] 12. Add LRU Eviction + Periodic Cleanup to Unbounded HashMaps
- [x] 13. Enforce REQUIRE_TLS at HTTP Layer + Add X-Forwarded-Proto Middleware
- [x] 14. Add CORS Headers for Public Endpoints
- [x] 15. Add Graceful Shutdown with Connection Drain Period
- [x] 16. Add Redis Connection Pooling to Verifier Store
- [x] 17. Add GitHub Actions CI Workflow
- [x] 18. Fix Verifier Health Check Endpoint + Add Docker HEALTHCHECK
- [x] 19. Make RedisStore::build() Return Result Instead of Panic
- [x] 20. Add Periodic Cleanup Task for Admin Rate Limiter
- [x] 21. Add Prometheus Request Latency + Error Metrics
- [x] 22. Add curl to Verifier Docker Image + Add .env Validation Script

### Final Verification

- [x] F1. Plan Compliance Audit
- [x] F2. Code Quality Review
- [x] F3. Real Manual QA
- [x] F4. Scope Fidelity Check

## Verification Commands

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt -- --check
```
