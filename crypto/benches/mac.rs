// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Benchmarks for MAC computation and key derivation
//!
//! These benchmarks measure the performance of:
//! - HMAC-SHA256 computation for token authentication
//! - HKDF key derivation for MAC keys
//! - Constant-time MAC verification
//!
//! Run with: cargo bench --bench mac

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use freebird_crypto::{compute_token_mac, derive_mac_key, derive_mac_key_v2, verify_token_mac};

fn bench_compute_mac(c: &mut Criterion) {
    let mut group = c.benchmark_group("mac/compute");
    let mac_key = [42u8; 32];
    let kid = "test-kid-001";
    let exp = 1234567890i64;
    let issuer_id = "test-issuer";

    // Benchmark with different token sizes
    for size in [32, 64, 128, 256, 512].iter() {
        let token = vec![0xABu8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(compute_token_mac(
                    black_box(&mac_key),
                    black_box(&token),
                    black_box(kid),
                    black_box(exp),
                    black_box(issuer_id),
                ))
            });
        });
    }
    group.finish();
}

fn bench_verify_mac(c: &mut Criterion) {
    let mut group = c.benchmark_group("mac/verify");
    let mac_key = [42u8; 32];
    let token = vec![0xABu8; 128];
    let kid = "test-kid-001";
    let exp = 1234567890i64;
    let issuer_id = "test-issuer";

    let mac = compute_token_mac(&mac_key, &token, kid, exp, issuer_id);

    group.bench_function("valid_mac", |b| {
        b.iter(|| {
            black_box(verify_token_mac(
                black_box(&mac_key),
                black_box(&token),
                black_box(&mac),
                black_box(kid),
                black_box(exp),
                black_box(issuer_id),
            ))
        });
    });

    // Benchmark with invalid MAC (should still be constant-time)
    let invalid_mac = [0u8; 32];
    group.bench_function("invalid_mac", |b| {
        b.iter(|| {
            black_box(verify_token_mac(
                black_box(&mac_key),
                black_box(&token),
                black_box(&invalid_mac),
                black_box(kid),
                black_box(exp),
                black_box(issuer_id),
            ))
        });
    });

    group.finish();
}

fn bench_derive_mac_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("mac/derive_key");
    let sk = [7u8; 32];
    let info = b"freebird:mac:v1";

    group.bench_function("legacy", |b| {
        b.iter(|| black_box(derive_mac_key(black_box(&sk), black_box(info))))
    });

    group.finish();
}

fn bench_derive_mac_key_v2(c: &mut Criterion) {
    let mut group = c.benchmark_group("mac/derive_key_v2");
    let sk = [7u8; 32];
    let issuer_id = "test-issuer";
    let kid = "key-001";
    let epoch = 0u32;

    group.bench_function("v2", |b| {
        b.iter(|| {
            black_box(derive_mac_key_v2(
                black_box(&sk),
                black_box(issuer_id),
                black_box(kid),
                black_box(epoch),
            ))
        })
    });

    group.finish();
}

fn bench_mac_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("mac/throughput");
    let mac_key = [42u8; 32];
    let token = vec![0xABu8; 131]; // Typical token size (VERSION + 2*33 + 64)
    let kid = "test-kid-001";
    let exp = 1234567890i64;
    let issuer_id = "test-issuer";

    // Pre-compute MAC
    let mac = compute_token_mac(&mac_key, &token, kid, exp, issuer_id);

    // Benchmark batch MAC operations (simulating high-throughput verification)
    for batch_size in [10, 50, 100, 500, 1000].iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("compute", batch_size),
            batch_size,
            |b, batch_size| {
                b.iter(|| {
                    for _ in 0..*batch_size {
                        black_box(compute_token_mac(&mac_key, &token, kid, exp, issuer_id));
                    }
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("verify", batch_size),
            batch_size,
            |b, batch_size| {
                b.iter(|| {
                    for _ in 0..*batch_size {
                        black_box(verify_token_mac(&mac_key, &token, &mac, kid, exp, issuer_id));
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_compute_mac,
    bench_verify_mac,
    bench_derive_mac_key,
    bench_derive_mac_key_v2,
    bench_mac_throughput
);
criterion_main!(benches);
