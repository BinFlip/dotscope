//! Benchmarks for COR20 (CLI) header parsing.
//!
//! The CLI header is a fixed 72-byte structure that contains essential
//! metadata about .NET assemblies including runtime version, metadata
//! location, and runtime flags.

extern crate dotscope;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use dotscope::metadata::cor20header::Cor20Header;
use std::{fs, hint::black_box, path::PathBuf};

/// Benchmark parsing the CLI header from a real assembly.
///
/// The CLI header is exactly 72 bytes and is parsed frequently during
/// assembly loading. This benchmark measures the parsing overhead.
fn bench_cor20_header_parse(c: &mut Criterion) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WB_COR20_HEADER.bin");

    let data = fs::read(&path).expect("Failed to read COR20 header file");
    let file_size = data.len();

    assert_eq!(file_size, 72, "COR20 header must be exactly 72 bytes");

    let mut group = c.benchmark_group("cor20_header");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            let header = Cor20Header::read(black_box(&data)).unwrap();
            black_box(header)
        });
    });
    group.finish();
}
criterion_group!(benches, bench_cor20_header_parse,);
criterion_main!(benches);
