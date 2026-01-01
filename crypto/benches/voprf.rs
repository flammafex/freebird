// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Benchmarks for core VOPRF operations
//!
//! These benchmarks measure the performance of cryptographic primitives
//! that form the bottleneck of Freebird's authorization system:
//! - P-256 elliptic curve operations (hash-to-curve, scalar multiplication)
//! - DLEQ proof generation and verification
//! - Token blinding, evaluation, finalization, and verification
//!
//! Run with: cargo bench --bench voprf

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use freebird_crypto::{Client, Server, Verifier};

fn bench_blind(c: &mut Criterion) {
    let mut group = c.benchmark_group("voprf/blind");
    let ctx = b"freebird-v1";

    // Benchmark different input sizes
    for size in [16, 32, 64, 128, 256].iter() {
        let input = vec![0xABu8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let mut client = Client::new(ctx);
                black_box(client.blind(&input).unwrap())
            });
        });
    }
    group.finish();
}

fn bench_evaluate(c: &mut Criterion) {
    let mut group = c.benchmark_group("voprf/evaluate");
    let ctx = b"freebird-v1";
    let sk = [7u8; 32];

    let server = Server::from_secret_key(sk, ctx).unwrap();

    // Pre-generate blinded values
    let mut client = Client::new(ctx);
    let (blinded_b64, _state) = client.blind(b"test input").unwrap();

    group.bench_function("single", |b| {
        b.iter(|| {
            black_box(server.evaluate_with_proof(black_box(&blinded_b64)).unwrap())
        });
    });

    group.finish();
}

fn bench_finalize(c: &mut Criterion) {
    let mut group = c.benchmark_group("voprf/finalize");
    let ctx = b"freebird-v1";
    let sk = [7u8; 32];

    let server = Server::from_secret_key(sk, ctx).unwrap();
    let pk = server.public_key_sec1_compressed();

    // Pre-generate evaluation
    let mut client = Client::new(ctx);
    let (blinded_b64, state) = client.blind(b"test input").unwrap();
    let eval_b64 = server.evaluate_with_proof(&blinded_b64).unwrap();

    group.bench_function("single", |b| {
        b.iter(|| {
            // Need to recreate client and state for each iteration
            let mut client = Client::new(ctx);
            let (blinded_b64, state) = client.blind(b"test input").unwrap();
            let eval_b64 = server.evaluate_with_proof(&blinded_b64).unwrap();
            black_box(client.finalize(state, &eval_b64, &pk).unwrap())
        });
    });

    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("voprf/verify");
    let ctx = b"freebird-v1";
    let sk = [7u8; 32];

    let server = Server::from_secret_key(sk, ctx).unwrap();
    let pk = server.public_key_sec1_compressed();
    let verifier = Verifier::new(ctx);

    // Pre-generate a token
    let mut client = Client::new(ctx);
    let (blinded_b64, state) = client.blind(b"test input").unwrap();
    let eval_b64 = server.evaluate_with_proof(&blinded_b64).unwrap();
    let (token_b64, _out) = client.finalize(state, &eval_b64, &pk).unwrap();

    group.bench_function("single", |b| {
        b.iter(|| {
            black_box(verifier.verify(black_box(&token_b64), black_box(&pk)).unwrap())
        });
    });

    group.finish();
}

fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("voprf/end_to_end");
    let ctx = b"freebird-v1";
    let sk = [7u8; 32];

    let server = Server::from_secret_key(sk, ctx).unwrap();
    let pk = server.public_key_sec1_compressed();
    let verifier = Verifier::new(ctx);

    group.bench_function("full_flow", |b| {
        b.iter(|| {
            // Full flow: blind -> evaluate -> finalize -> verify
            let mut client = Client::new(ctx);
            let (blinded_b64, state) = client.blind(black_box(b"test input")).unwrap();
            let eval_b64 = server.evaluate_with_proof(&blinded_b64).unwrap();
            let (token_b64, _out_cli) = client.finalize(state, &eval_b64, &pk).unwrap();
            let _out_ver = verifier.verify(&token_b64, &pk).unwrap();
            black_box(_out_ver)
        });
    });

    group.finish();
}

fn bench_batch_evaluate(c: &mut Criterion) {
    let mut group = c.benchmark_group("voprf/batch_evaluate");
    let ctx = b"freebird-v1";
    let sk = [7u8; 32];

    let server = Server::from_secret_key(sk, ctx).unwrap();

    // Benchmark different batch sizes
    for batch_size in [10, 50, 100, 500, 1000].iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));

        // Pre-generate blinded values
        let blinded_values: Vec<_> = (0..*batch_size)
            .map(|i| {
                let mut client = Client::new(ctx);
                let input = format!("input-{}", i);
                let (blinded_b64, _) = client.blind(input.as_bytes()).unwrap();
                blinded_b64
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    let results: Vec<_> = blinded_values
                        .iter()
                        .map(|blinded| server.evaluate_with_proof(blinded).unwrap())
                        .collect();
                    black_box(results)
                });
            },
        );
    }
    group.finish();
}

fn bench_batch_evaluate_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("voprf/batch_evaluate_parallel");
    let ctx = b"freebird-v1";
    let sk = [7u8; 32];

    let server = Server::from_secret_key(sk, ctx).unwrap();

    // Benchmark different batch sizes with parallel evaluation
    for batch_size in [10, 50, 100, 500, 1000].iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));

        // Pre-generate blinded values
        let blinded_values: Vec<_> = (0..*batch_size)
            .map(|i| {
                let mut client = Client::new(ctx);
                let input = format!("input-{}", i);
                let (blinded_b64, _) = client.blind(input.as_bytes()).unwrap();
                blinded_b64
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    use rayon::prelude::*;
                    let results: Vec<_> = blinded_values
                        .par_iter()
                        .map(|blinded| server.evaluate_with_proof(blinded).unwrap())
                        .collect();
                    black_box(results)
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_blind,
    bench_evaluate,
    bench_finalize,
    bench_verify,
    bench_end_to_end,
    bench_batch_evaluate,
    bench_batch_evaluate_parallel
);
criterion_main!(benches);
