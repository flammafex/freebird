// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Benchmarks for key derivation
//!
//! These benchmarks measure the performance of:
//! - HKDF key derivation for MAC keys
//!
//! Run with: cargo bench --bench mac

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use freebird_crypto::derive_mac_key;

fn bench_derive_mac_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("mac/derive_key");
    let sk = [7u8; 32];
    let info = b"freebird:mac:v1";

    group.bench_function("legacy", |b| {
        b.iter(|| black_box(derive_mac_key(black_box(&sk), black_box(info))))
    });

    group.finish();
}

criterion_group!(benches, bench_derive_mac_key);
criterion_main!(benches);
