//! Cryptographic benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use r_squared_rust::ecc::{PrivateKey, hash};

fn benchmark_key_generation(c: &mut Criterion) {
    c.bench_function("private_key_generation", |b| {
        b.iter(|| {
            let _key = black_box(PrivateKey::generate().unwrap());
        })
    });
}

fn benchmark_hashing(c: &mut Criterion) {
    let data = vec![0u8; 1024];
    
    c.bench_function("sha256_1kb", |b| {
        b.iter(|| {
            let _hash = black_box(hash::sha256(&data));
        })
    });
}

criterion_group!(benches, benchmark_key_generation, benchmark_hashing);
criterion_main!(benches);