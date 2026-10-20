//! Benchmarks for [`CilAssemblyView`] loading with and without metadata validation.

extern crate dotscope;

use criterion::{criterion_group, criterion_main, Criterion};
use dotscope::{testkit::fixture, CilAssemblyView, ValidationConfig};

/// Benchmark loading a `CilAssemblyView` with and without metadata validation.
pub fn criterion_benchmark(c: &mut Criterion) {
    let path = fixture("WindowsBase.dll");
    c.bench_function("bench_cilassemblyview", |b| {
        b.iter(|| {
            let _ = CilAssemblyView::from_path(&path);
        });
    });

    c.bench_function("bench_cilassemblyview_validation", |b| {
        b.iter(|| {
            let _ = CilAssemblyView::from_path_with_validation(&path, ValidationConfig::strict());
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
