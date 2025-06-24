//! Serialization benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use r_squared_rust::serializer::Serializer;

fn benchmark_serialization(c: &mut Criterion) {
    let data = vec![0u8; 1024];
    
    c.bench_function("serialize_1kb", |b| {
        b.iter(|| {
            let _result = black_box(Serializer::serialize(&data));
        })
    });
}

criterion_group!(benches, benchmark_serialization);
criterion_main!(benches);