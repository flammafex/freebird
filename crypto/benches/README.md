# Freebird Cryptographic Benchmarks

This directory contains comprehensive performance benchmarks for Freebird's core cryptographic operations using [Criterion](https://github.com/bheisler/criterion.rs).

## Overview

These benchmarks measure the performance of the cryptographic primitives that form the foundation of Freebird's privacy-preserving authorization system. The results back up the performance claims made in the main README.

## Benchmark Suites

### 1. VOPRF Operations (`voprf.rs`)

Measures the performance of core VOPRF operations using P-256 elliptic curve cryptography:

- **`voprf/blind`**: Client-side blinding operation with various input sizes (16-256 bytes)
- **`voprf/evaluate`**: Server-side evaluation of blinded elements (includes DLEQ proof generation)
- **`voprf/finalize`**: Client-side finalization and token generation
- **`voprf/verify`**: Verifier-side token verification
- **`voprf/end_to_end`**: Complete flow from blinding through verification
- **`voprf/batch_evaluate`**: Sequential batch evaluation (10-1000 tokens)
- **`voprf/batch_evaluate_parallel`**: Parallel batch evaluation using Rayon (10-1000 tokens)

**Key Performance Insight**: P-256 scalar multiplication is the primary CPU bottleneck, as stated in the README. The evaluate operation (which performs the VOPRF evaluation and generates DLEQ proofs) is the most expensive operation at ~540-570µs per token.

### 2. MAC and Key Derivation (`mac.rs`)

Measures the performance of token authentication and key management:

- **`mac/compute`**: HMAC-SHA256 computation with various token sizes (32-512 bytes)
- **`mac/verify`**: Constant-time MAC verification (both valid and invalid MACs)
- **`mac/derive_key`**: Legacy HKDF-based MAC key derivation
- **`mac/derive_key_v2`**: Enhanced HKDF-based MAC key derivation with domain separation
- **`mac/throughput`**: Batch MAC computation and verification (10-1000 tokens)

**Key Performance Insight**: MAC operations are significantly faster than VOPRF operations, taking only a few microseconds per token.

## Running Benchmarks

### Quick Test (Verify benchmarks compile and run)

```bash
cargo bench --package crypto --bench voprf -- --test
cargo bench --package crypto --bench mac -- --test
```

### Run All Benchmarks

```bash
cargo bench --package crypto
```

### Run Specific Benchmark Suite

```bash
# VOPRF benchmarks only
cargo bench --package crypto --bench voprf

# MAC benchmarks only
cargo bench --package crypto --bench mac
```

### Run Specific Benchmark

```bash
# Single operation benchmark
cargo bench --package crypto --bench voprf "voprf/evaluate/single"

# End-to-end flow
cargo bench --package crypto --bench voprf "end_to_end"

# Batch evaluation benchmarks
cargo bench --package crypto --bench voprf "batch_evaluate"
cargo bench --package crypto --bench voprf "batch_evaluate_parallel"
```

### Quick Benchmarks (Shorter Duration)

Use the `--quick` flag for faster results with less statistical rigor:

```bash
cargo bench --package crypto --bench voprf -- --quick
```

## Understanding Results

### Sample Output

```
voprf/evaluate/single   time:   [541.42 µs 564.16 µs 569.84 µs]
                        ┌──────────────┬──────────────┬──────────────┐
                        │  Lower bound │  Estimate    │  Upper bound │
                        └──────────────┴──────────────┴──────────────┘
```

- **Lower bound**: 95% confidence interval lower bound
- **Estimate**: Best estimate of the mean time
- **Upper bound**: 95% confidence interval upper bound

### Throughput Interpretation

For deployment sizing, use these approximate figures from the benchmarks:

- **Single token issuance**: ~540µs (VOPRF evaluate + DLEQ proof)
- **End-to-end flow**: ~2.1ms (blind + evaluate + finalize + verify)
- **Sequential batch (100 tokens)**: ~54ms (540µs × 100)
- **Parallel batch (100 tokens)**: Scales with available CPU cores

**Example Capacity Estimates**:
- 2 vCPU server: ~1,850 tokens/second (single-threaded) → 3,700 tokens/second (parallel)
- 4 vCPU server: ~1,850 tokens/second (single-threaded) → 7,400 tokens/second (parallel)
- 8 vCPU server: ~1,850 tokens/second (single-threaded) → 14,800 tokens/second (parallel)

These are theoretical maximums. Real-world throughput depends on:
- Network latency
- Sybil resistance mechanism overhead (PoW, WebAuthn, etc.)
- Redis/storage backend performance
- HTTP server overhead

## Benchmark Reports

Criterion generates detailed HTML reports in `target/criterion/`. Open `target/criterion/report/index.html` in a browser to view:

- Statistical analysis of results
- Performance trends over time (if running benchmarks repeatedly)
- Comparison between benchmark runs
- Violin plots showing result distributions

## Continuous Performance Monitoring

To track performance regressions over time:

1. **Baseline**: Establish a baseline before making changes
   ```bash
   cargo bench --package crypto --bench voprf -- --save-baseline main
   ```

2. **Compare**: After making changes, compare against the baseline
   ```bash
   cargo bench --package crypto --bench voprf -- --baseline main
   ```

3. **Review**: Check if there are significant performance changes
   - Criterion will report performance differences as percentages
   - Look for "Performance has regressed" or "Performance has improved" messages

## Architecture-Specific Notes

### Intel/AMD (x86_64)
- Benchmarks will utilize AES-NI and other CPU extensions automatically
- P-256 operations benefit from modern CPU features

### ARM (aarch64)
- Cryptographic operations may be slower on ARM without specialized instructions
- Consider using hardware with cryptographic extensions for production

### Optimization Level

Benchmarks run with the `--release` profile (optimization level 3). To verify:

```bash
cargo bench --package crypto --verbose
```

## Contributing

When adding new cryptographic primitives:

1. Add corresponding benchmarks to measure performance impact
2. Run benchmarks before and after changes to detect regressions
3. Document expected performance characteristics
4. Update this README with new benchmark descriptions

## References

- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/book/)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [P-256 ECDH Performance](https://www.bearssl.org/speed.html)
