//! Benchmarks for [`CilObject`] loading with and without metadata validation.

extern crate dotscope;

use criterion::{criterion_group, criterion_main, Criterion};
use dotscope::{metadata::cilobject::CilObject, ValidationConfig};
use std::path::PathBuf;

/// Benchmark loading a `CilObject` with and without metadata validation.
pub fn criterion_benchmark(c: &mut Criterion) {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/mono_4.8/mscorlib.dll");
    c.bench_function("bench_cilobject", |b| {
        b.iter(|| {
            let _ = CilObject::from_path_with_validation(&path, ValidationConfig::disabled());
        });
    });

    c.bench_function("bench_cilobject_validation", |b| {
        b.iter(|| {
            let _ = CilObject::from_path_with_validation(&path, ValidationConfig::strict());
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
